#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

project_root() {
    cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
    pwd -P
}

die() {
    printf 'pocket_vm: %s\n' "$*" >&2
    exit 1
}

# The single build timestamp every packed archive must use. Reading it from the
# lock keeps probe and release archives on one value and makes both reproducible.
pocket_source_date_epoch() {
    local root lock
    root=$(project_root)
    lock="$root/config/sources.lock.toml"
    local -a matches=()
    mapfile -t matches < <(
        awk '
            /^\[linux\]$/ { inside = 1; next }
            /^\[/ { if (inside) exit }
            inside && /^source_date_epoch = [0-9]+$/ { print $3; count++ }
            END { if (count != 1) exit 3 }
        ' "$lock"
    ) || die "missing or duplicate linux.source_date_epoch in $lock"
    [[ ${#matches[@]} -eq 1 && ${matches[0]} =~ ^[0-9]+$ ]] || \
        die "linux.source_date_epoch is not a plain integer"
    printf '%s\n' "${matches[0]}"
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

# The widest any build lane will accept. It is a typo guard, not a resource
# promise: -j is a hint to the scheduler, and a request past what the tree can
# use simply leaves make holding tokens nobody takes.
POCKET_MAX_BUILD_JOBS=256

# How wide to build. POCKET_BUILD_JOBS is the knob for every lane that has one;
# unset means "ask the host", bounded by the ceiling the caller passes, because
# the kernel pays for every core it is given while the small static tool chains
# stop paying well before that.
#
# The accepted range and the message live here so five callers cannot drift
# into five different contracts, which is exactly what they had done: one lane
# accepted 1..=256, two accepted 1..=64, one accepted any positive integer, and
# one validated nothing at all and handed the raw string to make.
pocket_build_jobs() {
    local default_ceiling=${1:-0} jobs

    if [[ -n ${POCKET_BUILD_JOBS:-} ]]; then
        jobs=$POCKET_BUILD_JOBS
        # An out-of-range request is a mistake worth refusing, and the message
        # can name the variable because the operator set it.
        [[ $jobs =~ ^[1-9][0-9]*$ && $jobs -le $POCKET_MAX_BUILD_JOBS ]] || \
            die "POCKET_BUILD_JOBS must be an integer in 1..=$POCKET_MAX_BUILD_JOBS, found: $jobs"
    else
        jobs=$(getconf _NPROCESSORS_ONLN) || die "cannot read the online CPU count"
        [[ $jobs =~ ^[1-9][0-9]*$ ]] || \
            die "getconf returned an invalid online CPU count: $jobs"
        # A host with more cores than the ceiling is not a typo, so clamp it
        # rather than refuse. Refusing would fail a 384-thread machine over a
        # variable nobody set.
        if (( default_ceiling > 0 && jobs > default_ceiling )); then
            jobs=$default_ceiling
        fi
        if (( jobs > POCKET_MAX_BUILD_JOBS )); then
            jobs=$POCKET_MAX_BUILD_JOBS
        fi
    fi

    printf '%s\n' "$jobs"
}

# True when $1 is at least $2. sort -V puts the lower first, so the wanted
# version leading its own comparison means nothing outranks it. Handles a
# two-component minimum against a three-component version, and 1.100 > 1.9.
pocket_version_at_least() {
    [[ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n 1)" == "$2" ]]
}

# Apply the width to the tools that take it from the environment instead of a
# flag. make and ninja get -j and go gets -p at the call site, but cargo reads
# CARGO_BUILD_JOBS and the Go compiler schedules over GOMAXPROCS, so without
# this POCKET_BUILD_JOBS bounds only part of a build.
pocket_export_build_jobs() {
    local jobs=$1
    [[ $jobs =~ ^[1-9][0-9]*$ ]] || die "refusing to export an invalid job count: $jobs"
    export CARGO_BUILD_JOBS="$jobs"
    export GOMAXPROCS="$jobs"
}

# One locked scalar from config/sources.lock.toml, by section and key.
#
# This exists because the scripts that needed to read a locked version did not
# all have a reader: development_tools.rust sat in the lock with nothing
# consulting it, and the version the build actually enforced was spelled out as
# a literal in two shell scripts, so editing the lock moved nothing. Callers
# without their own reader use this one.
#
# Four scripts still carry a byte-identical private `lock_value`, predating
# this. They are not wrong, only duplicated; replacing them touches four
# verified release builds for no behavioural gain, so it is left as its own
# change.
pocket_lock_value() {
    local section=$1 key=$2 root lock value
    root=$(project_root)
    lock="$root/config/sources.lock.toml"
    [[ -f "$lock" ]] || die "source lock file not found: $lock"
    value=$(
        awk -v expected_section="[$section]" -v expected_key="$key" '
            $0 == expected_section { in_section = 1; next }
            /^\[/ { in_section = 0 }
            in_section {
                equals = index($0, "=")
                if (equals == 0) next
                candidate = substr($0, 1, equals - 1)
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", candidate)
                if (candidate != expected_key) next
                value = substr($0, equals + 1)
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
                if (value ~ /^".*"$/) value = substr(value, 2, length(value) - 2)
                print value
                found++
            }
            END { if (found != 1) exit 42 }
        ' "$lock"
    ) || die "$section.$key is missing or duplicated in $lock"
    printf '%s\n' "$value"
}

# Whether a difference from what the lock records stops the build.
#
# By default it does not. A mismatch means this host's toolchain produced
# different bytes than the reference release did, which is worth saying and is
# not by itself a reason to refuse someone a working local build. The source is
# authenticated separately -- GPG-verified tarball, recorded patched-tree hash,
# post-build source audit -- and none of that depends on the output digest.
#
# Set POCKET_STRICT_TOOLCHAIN=1 for the one job that genuinely needs equality:
# reproducing a release built on some other machine.
pocket_strict_toolchain() {
    case ${POCKET_STRICT_TOOLCHAIN:-} in
        '' | 0 | false | no) return 1 ;;
        *) return 0 ;;
    esac
}

pocket_match_recorded() {
    local description=$1 actual=$2 expected=$3
    [[ "$actual" != "$expected" ]] || return 0
    if pocket_strict_toolchain; then
        die "$description is $actual, but the lock records $expected"
    fi
    printf 'note: %s is %s, recorded as %s; not byte-identical to the reference release\n' \
        "$description" "$actual" "$expected" >&2
}

# Hold an observed value to what the lock records, and say both numbers when it
# does not match. A message that names only the expectation sends the reader to
# grep for what they actually have.
pocket_assert_lock() {
    local section=$1 key=$2 actual=$3 description=$4 expected
    expected=$(pocket_lock_value "$section" "$key")
    [[ "$actual" == "$expected" ]] || die \
        "$description is $actual, but config/sources.lock.toml records $expected"
}

# Resolve the busybox that will actually be packed, and require only that it is
# a plain, static executable. Which build of busybox it is is the host's
# business.
pocket_resolve_busybox() {
    local resolved
    resolved=$(command -v busybox 2>/dev/null || true)
    [[ -n "$resolved" ]] || die "busybox is required"
    resolved=$(readlink -f -- "$resolved") || die "cannot resolve the busybox path"
    [[ -f "$resolved" && -x "$resolved" && ! -L "$resolved" ]] || \
        die "busybox is not a plain executable file: $resolved"
    # file(1) says "static-pie linked" for a static PIE and "statically linked"
    # otherwise, and the wording has moved between releases. Accept both rather
    # than reject a perfectly static busybox for how it was phrased.
    file -- "$resolved" | grep -Eq 'static-pie linked|statically linked' || \
        die "busybox must be statically linked: $resolved"
    printf '%s\n' "$resolved"
}

safe_managed_root() {
    local path=$1
    [[ "$path" = /* ]] || die "managed path must be absolute: $path"
    [[ "$path" != *[[:space:],:]* ]] || die "managed path contains UML-reserved whitespace, comma, or colon: $path"
    [[ "$path" != / && "$path" != /home && "$path" != /tmp ]] || die "refusing broad managed path: $path"
}

# UML's null line channel is backed by /dev/null. Linux rejects /dev/null in
# epoll with EPERM, so using ssl=null produces a scary-but-benign boot message.
# Probe launches instead inherit pollable FIFOs: separate input endpoints that
# are never written and an output endpoint drained by tee. Product launches
# use full-duplex socketpairs for the same reason.
open_pollable_serial_sink() {
    local run_dir=$1
    local console_input_fifo="$run_dir/console-sink.in"
    local input_fifo="$run_dir/serial-sink.in"
    local output_fifo="$run_dir/serial-sink.out"

    mkfifo -m 0600 "$console_input_fifo" "$input_fifo" "$output_fifo"
    tee < "$output_fifo" >/dev/null &
    POCKET_SERIAL_SINK_PID=$!
    exec {POCKET_SERIAL_OUTPUT_FD}>"$output_fifo"
    exec {POCKET_SERIAL_INPUT_FD}<>"$input_fifo"
    exec {POCKET_CONSOLE_INPUT_FD}<>"$console_input_fifo"
}

close_pollable_serial_fds() {
    if [[ -n ${POCKET_SERIAL_INPUT_FD:-} ]]; then
        exec {POCKET_SERIAL_INPUT_FD}>&-
    fi
    if [[ -n ${POCKET_SERIAL_OUTPUT_FD:-} ]]; then
        exec {POCKET_SERIAL_OUTPUT_FD}>&-
    fi
    if [[ -n ${POCKET_CONSOLE_INPUT_FD:-} ]]; then
        exec {POCKET_CONSOLE_INPUT_FD}>&-
    fi
}

wait_pollable_serial_sink() {
    local status=0

    close_pollable_serial_fds
    if [[ -n ${POCKET_SERIAL_SINK_PID:-} ]]; then
        wait "$POCKET_SERIAL_SINK_PID" || status=$?
        POCKET_SERIAL_SINK_PID=
    fi
    return "$status"
}

stop_pollable_serial_sink() {
    close_pollable_serial_fds
    if [[ -n ${POCKET_SERIAL_SINK_PID:-} ]] && kill -0 "$POCKET_SERIAL_SINK_PID" 2>/dev/null; then
        kill -TERM "$POCKET_SERIAL_SINK_PID" 2>/dev/null || true
        wait "$POCKET_SERIAL_SINK_PID" 2>/dev/null || true
    fi
    POCKET_SERIAL_SINK_PID=
}

assert_clean_uml_log() {
    local log=$1
    local context=$2
    # Guest-kernel reports that must never appear in a passing probe. The
    # scheduler-from-idle and RCU-stall entries matter in particular: they are
    # the signature of the free_irq()-from-signal-handler defect that patches
    # 0003-0005 fix, and a pattern without them would let that exact regression
    # through a green probe.
    local pattern='epollctl (add|mod) err|BUG:|WARNING:|Oops|Kernel panic|panic - not syncing'
    pattern+='|soft lockup|hard LOCKUP|bad: scheduling|rcu:.*(stall|starved)'
    pattern+='|detected stalls on CPU|self-detected stall|Segfault|INFO: task .* blocked'
    pattern+='|possible circular locking|INCONSISTENT LOCK STATE|suspicious RCU usage'
    pattern+='|held lock freed|ODEBUG:|list_(add|del) corruption|Unexpectedly lost MM child'

    # Fail closed on a log that is missing or empty. grep exits 2 for a file it
    # cannot read, which reads as "found nothing", so an absent log would pass
    # this assertion having proved nothing whatsoever.
    [[ -f "$log" && ! -L "$log" && -s "$log" ]] || \
        die "$context produced no UML log to check: $log"
    if grep -Eq "$pattern" "$log"; then
        grep -En "$pattern" "$log" >&2 || true
        die "$context emitted an unexpected UML diagnostic"
    fi
}
