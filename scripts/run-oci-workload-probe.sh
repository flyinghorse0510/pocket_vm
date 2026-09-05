#!/usr/bin/env bash

source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"
# shellcheck source=scripts/linux-source-lib.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/linux-source-lib.sh"

ROOT=$(project_root)
BUILD_ROOT=${POCKET_BUILD_ROOT:-"$ROOT/build"}
VERSION=${1:-24.04}
BASE="$BUILD_ROOT/disks/ubuntu-$VERSION/base.ext4"
INITRAMFS="$BUILD_ROOT/initramfs/workload-probe.cpio"
KERNEL="$BUILD_ROOT/kernel/x86_64-smp-p4k$LINUX_OUTPUT_SUFFIX/linux"
GUARD=${POCKET_GUARD:-"$ROOT/target/release/pocket-guard"}
CPUS=${POCKET_CPUS:-2}
RUNTIME_ROOT=${POCKET_RUNTIME_ROOT:-"/tmp/pocket-vm-$(id -u)"}

[[ -f "$BASE" && -f "$INITRAMFS" && -x "$KERNEL" ]] || die "build OCI rootfs and workload initramfs first"
[[ -x "$GUARD" ]] || die "process guard is missing: $GUARD (run: cargo build --release -p pocket-guard)"
if [[ ! "$CPUS" =~ ^[1-9][0-9]*$ ]] || (( CPUS > 16 )); then
    die "invalid CPU count"
fi
safe_managed_root "$BUILD_ROOT"
safe_managed_root "$RUNTIME_ROOT"
mkdir -p -- "$RUNTIME_ROOT" "$BUILD_ROOT/logs"
chmod 0700 "$RUNTIME_ROOT"
BASE_HASH_BEFORE=$(sha256sum "$BASE" | awk '{print $1}')

RUN_DIR=$(mktemp -d "$RUNTIME_ROOT/workload.XXXXXXXX")
mkdir -m 0700 -- "$RUN_DIR/uml" "$RUN_DIR/tmp"
COW="$RUN_DIR/root.cow"
LOG="$RUN_DIR/console.log"
FIFO="$RUN_DIR/console.pipe"
install -m 0600 /dev/null "$LOG"
mkfifo -m 0600 "$FIFO"
open_pollable_serial_sink "$RUN_DIR"
[[ ! -e "$COW" ]] || die "COW leaf must not exist before UML"

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
    find "$RUN_DIR" -depth -delete 2>/dev/null || true
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
    "$KERNEL" mem=512M "ncpus=$CPUS" seccomp=on \
    "umid=workload-${RUN_DIR##*.}" "uml_dir=$RUN_DIR/uml" \
    "initrd=$INITRAMFS" rdinit=/init rootfstype=ramfs \
    "ubd0=$COW,$BASE" \
    con=null "con0=fd:$POCKET_CONSOLE_INPUT_FD,fd:1" \
    "ssl=fd:$POCKET_SERIAL_INPUT_FD,fd:$POCKET_SERIAL_OUTPUT_FD" noreboot panic=1 \
    </dev/null >"$FIFO" 2>&1 &
GUARD_PID=$!
close_pollable_serial_fds

if wait "$GUARD_PID"; then UML_STATUS=0; else UML_STATUS=$?; fi
GUARD_PID=
wait "$LOGGER_PID"
LOGGER_PID=
wait_pollable_serial_sink || die "serial sink failed"
[[ "$UML_STATUS" == 0 ]] || die "workload UML exited with status $UML_STATUS"
grep -Fq 'Checking that seccomp filters can be installed...OK' "$LOG" || die "workload did not use cooperative seccomp"
grep -Fq 'POCKET_WORKLOAD_STATUS=0' "$LOG" || die "Ubuntu workload failed"
grep -Fq 'uts_machine=x86_64' "$LOG" || die "Ubuntu workload architecture mismatch"
grep -Fq "guest_cpu_count=$CPUS" "$LOG" || die "Ubuntu workload CPU count mismatch"
grep -Fq "ubuntu_version=\"$VERSION\"" "$LOG" || die "Ubuntu version mismatch"
assert_clean_uml_log "$LOG" "Ubuntu workload"
[[ -s "$COW" ]] || die "UML did not create a COW overlay"
BASE_HASH_AFTER=$(sha256sum "$BASE" | awk '{print $1}')
[[ "$BASE_HASH_AFTER" == "$BASE_HASH_BEFORE" ]] || die "immutable base changed"

cat "$LOG"
mv -- "$LOG" "$BUILD_ROOT/logs/workload-ubuntu-$VERSION-ncpus-$CPUS.log"
printf 'base_sha256=%s\n' "$BASE_HASH_AFTER"
