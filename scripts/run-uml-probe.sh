#!/usr/bin/env bash

source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"

ROOT=$(project_root)
BUILD_ROOT=${POCKET_BUILD_ROOT:-"$ROOT/build"}
KERNEL="$BUILD_ROOT/kernel/x86_64-smp-p4k/linux"
INITRAMFS="$BUILD_ROOT/initramfs/probe.cpio"
DISK="$BUILD_ROOT/disks/probe.ext4"
GUARD=${POCKET_GUARD:-"$ROOT/target/release/pocket-guard"}
CPUS=${POCKET_CPUS:-2}
MEMORY=${POCKET_MEMORY:-256M}
TIMEOUT=${POCKET_BOOT_TIMEOUT:-30}
RUNTIME_ROOT=${POCKET_RUNTIME_ROOT:-"/tmp/pocket-vm-$(id -u)"}

[[ -x "$KERNEL" ]] || die "UML kernel is missing: $KERNEL"
[[ -x "$GUARD" ]] || die "process guard is missing: $GUARD (run: cargo build --release -p pocket-guard)"
[[ -f "$INITRAMFS" ]] || die "probe initramfs is missing: $INITRAMFS"
[[ -f "$DISK" ]] || die "probe ext4 disk is missing: $DISK"
[[ "$CPUS" =~ ^[1-9][0-9]*$ ]] || die "CPU count must be a positive integer"
(( CPUS <= 16 )) || die "CPU count exceeds profile maximum 16"
if [[ "$MEMORY" =~ ^([1-9][0-9]*)([KMG])$ ]]; then
    MEMORY_NUMBER=${BASH_REMATCH[1]}
    case ${BASH_REMATCH[2]} in
        K) MEMORY_MULTIPLIER=1024 ;;
        M) MEMORY_MULTIPLIER=$((1024 * 1024)) ;;
        G) MEMORY_MULTIPLIER=$((1024 * 1024 * 1024)) ;;
    esac
elif [[ "$MEMORY" =~ ^[1-9][0-9]*$ ]]; then
    MEMORY_NUMBER=$MEMORY
    MEMORY_MULTIPLIER=1
else
    die "memory must be a positive integer with optional K, M, or G binary suffix"
fi
(( MEMORY_NUMBER <= 9223372036854775807 / MEMORY_MULTIPLIER )) || die "memory byte count overflows"
MEMORY_BYTES=$((MEMORY_NUMBER * MEMORY_MULTIPLIER))
(( MEMORY_BYTES % 4096 == 0 )) || die "memory byte count must be 4096-byte aligned"
safe_managed_root "$BUILD_ROOT"
safe_managed_root "$RUNTIME_ROOT"

mkdir -p -- "$RUNTIME_ROOT" "$BUILD_ROOT/logs"
chmod 0700 "$RUNTIME_ROOT"
RUN_DIR=$(mktemp -d "$RUNTIME_ROOT/probe.XXXXXXXX")
mkdir -m 0700 -- "$RUN_DIR/uml" "$RUN_DIR/tmp"
LOG="$RUN_DIR/console.log"
FIFO="$RUN_DIR/console.pipe"
EVIDENCE_LOG="$BUILD_ROOT/logs/probe-ncpus-$CPUS-mem-$MEMORY_BYTES.log"
install -m 0600 /dev/null "$LOG"
mkfifo -m 0600 "$FIFO"
open_pollable_serial_sink "$RUN_DIR"

cleanup() {
    local status=$?
    if [[ -n ${GUARD_PID:-} ]] && kill -0 "$GUARD_PID" 2>/dev/null; then
        kill -TERM "$GUARD_PID" 2>/dev/null || true
        wait "$GUARD_PID" 2>/dev/null || true
    fi
    if [[ -n ${LOGGER_PID:-} ]] && kill -0 "$LOGGER_PID" 2>/dev/null; then
        kill -TERM "$LOGGER_PID" 2>/dev/null || true
        wait "$LOGGER_PID" 2>/dev/null || true
    fi
    stop_pollable_serial_sink
    if [[ -n ${RUN_DIR:-} && -d "$RUN_DIR" ]]; then
        find "$RUN_DIR" -depth -delete 2>/dev/null || true
    fi
    return "$status"
}
trap cleanup EXIT INT TERM

tee "$LOG" < "$FIFO" >/dev/null &
LOGGER_PID=$!

SUPERVISOR_PID=$BASHPID
"$GUARD" \
    --supervisor-pid "$SUPERVISOR_PID" \
    --inherit-fd "$POCKET_CONSOLE_INPUT_FD" \
    --inherit-fd "$POCKET_SERIAL_INPUT_FD" \
    --inherit-fd "$POCKET_SERIAL_OUTPUT_FD" \
    --uml-personality \
    -- \
    env -i PATH=/usr/bin:/bin TMPDIR="$RUN_DIR/tmp" \
    "$KERNEL" \
    "mem=$MEMORY" \
    "ncpus=$CPUS" \
    seccomp=on \
    "pocket.expected_cpus=$CPUS" \
    "pocket.expected_memory_bytes=$MEMORY_BYTES" \
    "umid=probe-${RUN_DIR##*.}" \
    "uml_dir=$RUN_DIR/uml" \
    "initrd=$INITRAMFS" \
    rdinit=/init \
    rootfstype=ramfs \
    "ubd0r=$DISK" \
    con=null \
    "con0=fd:$POCKET_CONSOLE_INPUT_FD,fd:1" \
    "ssl=fd:$POCKET_SERIAL_INPUT_FD,fd:$POCKET_SERIAL_OUTPUT_FD" \
    noreboot \
    panic=1 \
    </dev/null >"$FIFO" 2>&1 &
GUARD_PID=$!
close_pollable_serial_fds

DEADLINE=$((SECONDS + TIMEOUT))
while kill -0 "$GUARD_PID" 2>/dev/null; do
    if grep -Fq POCKET_PROBE_OK "$LOG"; then
        break
    fi
    (( SECONDS < DEADLINE )) || die "UML probe timed out; log: $LOG"
    sleep 0.05
done

if wait "$GUARD_PID"; then
    UML_STATUS=0
else
    UML_STATUS=$?
fi
GUARD_PID=
wait "$LOGGER_PID"
LOGGER_PID=
wait_pollable_serial_sink || die "serial sink failed"
if [[ "$UML_STATUS" != 0 ]]; then
    cat "$LOG" >&2
    die "guarded UML exited with status $UML_STATUS; log: $LOG"
fi
grep -Fq 'Checking that seccomp filters can be installed...OK' "$LOG" || \
    die "cooperative seccomp backend was not positively identified"
grep -Fq "cpu_count=$CPUS" "$LOG" || die "guest CPU count did not match request"
grep -Fq "accepted_physmem_bytes=$MEMORY_BYTES" "$LOG" || \
    die "UML accepted physical memory did not exactly match request"
GUEST_CMDLINE=$(sed -n 's/^guest_cmdline=//p' "$LOG")
[[ -n "$GUEST_CMDLINE" ]] || die "guest /proc/cmdline was not reported"
[[ " $GUEST_CMDLINE " == *" pocket.expected_cpus=$CPUS "* ]] || \
    die "guest-visible expected CPU alias is missing"
[[ " $GUEST_CMDLINE " == *" pocket.expected_memory_bytes=$MEMORY_BYTES "* ]] || \
    die "guest-visible expected memory alias is missing"
[[ " $GUEST_CMDLINE " != *" ncpus="* ]] || die "UML ncpus option leaked into /proc/cmdline"
[[ " $GUEST_CMDLINE " != *" mem="* ]] || die "UML mem option leaked into /proc/cmdline"
grep -Fq 'ubd_marker=ext4-ubd-ok' "$LOG" || die "UBD/ext4 probe did not match"
grep -Fq POCKET_PROBE_OK "$LOG" || die "guest probe did not complete"
assert_clean_uml_log "$LOG" "UML probe"

cat "$LOG"
mv -- "$LOG" "$EVIDENCE_LOG"
printf 'probe_log=%s\n' "$EVIDENCE_LOG"
