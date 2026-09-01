#!/usr/bin/env bash

# Repeated fresh full-lifecycle launches at a fixed vCPU count, plus optional
# concurrent waves. This is the harness behind the repeated-lifecycle release
# gate: the counts a document claims must be reproducible by running this.
#
# Guest programs are single-quoted so the host shell cannot expand them.
# shellcheck disable=SC2016

# shellcheck source=scripts/lib.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"

export LC_ALL=C

ROOT=$(project_root)
BUILD_ROOT=${POCKET_BUILD_ROOT:-"$ROOT/build"}
POCKET_BIN=${POCKET_BIN:-"$ROOT/target/release/pocket"}

PROFILE_BUNDLE=${POCKET_PROFILE_BUNDLE:-}
STORE=${POCKET_SOAK_STORE:-}
GENERATION=${POCKET_SOAK_GENERATION:-}
CPUS=${POCKET_SOAK_CPUS:-4}
ITERATIONS=${POCKET_SOAK_ITERATIONS:-100}
WAVES=${POCKET_SOAK_WAVES:-0}
WAVE_WIDTH=${POCKET_SOAK_WAVE_WIDTH:-8}

usage() {
    cat >&2 <<'USAGE'
usage: POCKET_PROFILE_BUNDLE=... POCKET_SOAK_STORE=... POCKET_SOAK_GENERATION=... \
       [POCKET_SOAK_CPUS=4] [POCKET_SOAK_ITERATIONS=100] \
       [POCKET_SOAK_WAVES=0] [POCKET_SOAK_WAVE_WIDTH=8] \
       scripts/run-lifecycle-soak.sh

Every launch is a fresh workload lifecycle against the same immutable base.
A launch counts as a pass only when it exits zero AND prints exactly the
online CPU count, so a silently degraded guest fails the lane.
USAGE
    exit 2
}

for command in awk find mkdir mktemp seq; do
    require_command "$command"
done
[[ -n "$PROFILE_BUNDLE" && -d "$PROFILE_BUNDLE" ]] || usage
[[ -n "$STORE" && -d "$STORE" ]] || usage
[[ -n "$GENERATION" ]] || usage
[[ -x "$POCKET_BIN" && ! -L "$POCKET_BIN" ]] || die "pocket executable is missing: $POCKET_BIN"
[[ "$CPUS" =~ ^[1-9][0-9]*$ ]] || die "POCKET_SOAK_CPUS must be a positive integer"
[[ "$ITERATIONS" =~ ^[1-9][0-9]*$ ]] || die "POCKET_SOAK_ITERATIONS must be a positive integer"
[[ "$WAVES" =~ ^[0-9]+$ ]] || die "POCKET_SOAK_WAVES must be a nonnegative integer"
[[ "$WAVE_WIDTH" =~ ^[1-9][0-9]*$ ]] || die "POCKET_SOAK_WAVE_WIDTH must be a positive integer"
safe_managed_root "$BUILD_ROOT"

mkdir -p -- "$BUILD_ROOT/soak"
WORK_ROOT=$(mktemp -d "$BUILD_ROOT/soak/run.XXXXXXXX")
RUNTIME_ROOT="$WORK_ROOT/runtime"
LOG_ROOT="$WORK_ROOT/logs"
mkdir -m 0700 -- "$RUNTIME_ROOT" "$LOG_ROOT"

printf 'soak_work_root=%s\n' "$WORK_ROOT"
printf 'profile_bundle=%s\n' "$PROFILE_BUNDLE"
printf 'generation=%s\n' "$GENERATION"
printf 'cpus=%s iterations=%s waves=%s wave_width=%s\n' \
    "$CPUS" "$ITERATIONS" "$WAVES" "$WAVE_WIDTH"

launch() {
    local label=$1
    "$POCKET_BIN" run \
        --profile-bundle "$PROFILE_BUNDLE" \
        --store "$STORE" \
        --runtime-root "$RUNTIME_ROOT" \
        --platform linux/amd64 \
        --cpus "$CPUS" \
        --timeout 180s \
        "$GENERATION" -- \
        /bin/sh -c 'exec nproc' \
        >"$LOG_ROOT/$label.stdout" 2>"$LOG_ROOT/$label.stderr"
}

passed=0
failed=0
for index in $(seq 1 "$ITERATIONS"); do
    if launch "seq-$index" && [[ $(cat "$LOG_ROOT/seq-$index.stdout") == "$CPUS" ]]; then
        passed=$((passed + 1))
        rm -f -- "$LOG_ROOT/seq-$index.stdout" "$LOG_ROOT/seq-$index.stderr"
    else
        failed=$((failed + 1))
        printf 'FAIL sequential %s\n' "$index" >&2
        sed -n '1,80p' "$LOG_ROOT/seq-$index.stderr" >&2
    fi
done
printf 'sequential cpus=%s passed=%s failed=%s\n' "$CPUS" "$passed" "$failed"

wave_failures=0
for wave in $(seq 1 "$WAVES"); do
    pids=()
    for slot in $(seq 1 "$WAVE_WIDTH"); do
        launch "wave-$wave-$slot" &
        pids+=("$!")
    done
    for pid in "${pids[@]}"; do
        wait "$pid" || wave_failures=$((wave_failures + 1))
    done
    for slot in $(seq 1 "$WAVE_WIDTH"); do
        if [[ $(cat "$LOG_ROOT/wave-$wave-$slot.stdout" 2>/dev/null) == "$CPUS" ]]; then
            rm -f -- "$LOG_ROOT/wave-$wave-$slot.stdout" "$LOG_ROOT/wave-$wave-$slot.stderr"
        else
            wave_failures=$((wave_failures + 1))
            printf 'FAIL wave %s slot %s\n' "$wave" "$slot" >&2
        fi
    done
done
(( WAVES == 0 )) || printf 'concurrent waves=%s width=%s failures=%s\n' \
    "$WAVES" "$WAVE_WIDTH" "$wave_failures"

# .sweep.lock is the runtime root's orphan-reclamation lock, created once and
# kept by design; it is not an operation directory.
leaked=$(find "$RUNTIME_ROOT" -mindepth 1 ! -name .sweep.lock | wc -l)
printf 'leaked_runtime_entries=%s\n' "$leaked"

(( failed == 0 )) || die "sequential lane failed $failed of $ITERATIONS launches"
(( wave_failures == 0 )) || die "concurrent lane recorded $wave_failures failures"
(( leaked == 0 )) || die "runtime operation directories leaked"
find "$WORK_ROOT" -depth -delete 2>/dev/null || true
printf 'POCKET_LIFECYCLE_SOAK_OK\n'
