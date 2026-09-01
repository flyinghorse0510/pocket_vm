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

# One locked SHA-256 from config/sources.lock.toml, by exact key.
pocket_locked_sha256() {
    local key=$1 root lock
    root=$(project_root)
    lock="$root/config/sources.lock.toml"
    local -a matches=()
    mapfile -t matches < <(
        awk -v key="$key" '
            /^\[development_artifacts\]$/ { inside = 1; next }
            /^\[/ { if (inside) exit }
            inside && $1 == key && $2 == "=" {
                gsub(/"/, "", $3); print $3; count++
            }
            END { if (count != 1) exit 3 }
        ' "$lock"
    ) || true
    [[ ${#matches[@]} -eq 1 && ${matches[0]} =~ ^[0-9a-f]{64}$ ]] || die \
        "development_artifacts.$key is missing, duplicated, or not a SHA-256 digest in $lock"
    printf '%s\n' "${matches[0]}"
}

# Resolve the busybox that will actually be packed, and authenticate exactly
# that file against the lock.
#
# Checking a hardcoded path while packing whatever PATH resolves first
# authenticates a different binary than the one that ships, which is no check at
# all. Set POCKET_BUSYBOX_SHA256 to pin a different host's build; the failure
# message names the digest to pin.
pocket_resolve_busybox() {
    local resolved expected actual
    resolved=$(command -v busybox 2>/dev/null || true)
    [[ -n "$resolved" ]] || die "busybox is required"
    resolved=$(readlink -f -- "$resolved") || die "cannot resolve the busybox path"
    [[ -f "$resolved" && -x "$resolved" && ! -L "$resolved" ]] || \
        die "busybox is not a plain executable file: $resolved"
    file -- "$resolved" | grep -q 'statically linked' || \
        die "busybox must be statically linked: $resolved"
    expected=${POCKET_BUSYBOX_SHA256:-$(pocket_locked_sha256 busybox_sha256)}
    actual=$(sha256sum -- "$resolved" | awk '{print $1}')
    [[ "$actual" == "$expected" ]] || die \
        "busybox digest mismatch: $resolved is $actual; set POCKET_BUSYBOX_SHA256=$actual to pin this host's build"
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
