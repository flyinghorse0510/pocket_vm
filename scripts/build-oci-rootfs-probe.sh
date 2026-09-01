#!/usr/bin/env bash

source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"

ROOT=$(project_root)
BUILD_ROOT=${POCKET_BUILD_ROOT:-"$ROOT/build"}
VERSION=${1:-24.04}

case "$VERSION" in
    24.04)
        PAYLOAD_UUID=84630be9-4cd9-5f5c-8a74-b41c7b309f57
        ROOT_UUID=d88696d0-1aca-5ceb-8e65-d17b2b5edae4
        ;;
    26.04)
        PAYLOAD_UUID=7a75e20a-fd0e-5217-b8de-a0212fd2e59c
        ROOT_UUID=bdaca769-0027-52bb-93a5-80e0ec91aa68
        ;;
    *) die "supported Ubuntu fixture versions are 24.04 and 26.04" ;;
esac

OCI_DIR="$BUILD_ROOT/oci/ubuntu-$VERSION"
DISK_DIR="$BUILD_ROOT/disks/ubuntu-$VERSION"
PAYLOAD="$DISK_DIR/payload.ext4"
TARGET="$DISK_DIR/base.ext4"
INITRAMFS="$BUILD_ROOT/initramfs/builder-probe.cpio"
KERNEL="$BUILD_ROOT/kernel/x86_64-smp-p4k/linux"
GUARD=${POCKET_GUARD:-"$ROOT/target/release/pocket-guard"}
RUNTIME_ROOT=${POCKET_RUNTIME_ROOT:-"/tmp/pocket-vm-$(id -u)"}

for command in mke2fs e2fsck truncate tee sync; do require_command "$command"; done
[[ -f "$OCI_DIR/index.json" ]] || die "pull the Ubuntu fixture first"
[[ -x "$KERNEL" && -f "$INITRAMFS" ]] || die "build kernel and builder initramfs first"
[[ -x "$GUARD" ]] || die "process guard is missing: $GUARD (run: cargo build --release -p pocket-guard)"
safe_managed_root "$BUILD_ROOT"
safe_managed_root "$RUNTIME_ROOT"
mkdir -p -- "$DISK_DIR" "$RUNTIME_ROOT" "$BUILD_ROOT/logs"
chmod 0700 "$RUNTIME_ROOT"

RUN_DIR=
PAYLOAD_STAGE=
TARGET_STAGE=

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
    if [[ -n ${PAYLOAD_STAGE:-} ]]; then
        rm -f -- "$PAYLOAD_STAGE"
    fi
    if [[ -n ${TARGET_STAGE:-} ]]; then
        rm -f -- "$TARGET_STAGE"
    fi
    return "$status"
}
trap cleanup EXIT INT TERM

if [[ ! -f "$PAYLOAD" ]]; then
    PAYLOAD_STAGE=$(mktemp "$DISK_DIR/.payload.XXXXXXXX.ext4")
    truncate -s 256M "$PAYLOAD_STAGE"
    E2FSPROGS_FAKE_TIME=1786940622 mke2fs -q -t ext4 -b 4096 -I 256 -m 0 \
        -U "$PAYLOAD_UUID" -L pocket-payload -O ^has_journal,^orphan_file \
        -E lazy_itable_init=0,lazy_journal_init=0 -d "$OCI_DIR" "$PAYLOAD_STAGE"
    e2fsck -fn "$PAYLOAD_STAGE"
    mv -- "$PAYLOAD_STAGE" "$PAYLOAD"
    PAYLOAD_STAGE=
    chmod 0400 "$PAYLOAD"
fi

TARGET_STAGE=$(mktemp "$DISK_DIR/.base.XXXXXXXX.ext4")
truncate -s 768M "$TARGET_STAGE"
E2FSPROGS_FAKE_TIME=1786940622 mke2fs -q -t ext4 -b 4096 -I 256 -m 0 \
    -N 65536 -U "$ROOT_UUID" -L pocket-root -O ^has_journal,^orphan_file \
    -E lazy_itable_init=0,lazy_journal_init=0 "$TARGET_STAGE"

RUN_DIR=$(mktemp -d "$RUNTIME_ROOT/builder.XXXXXXXX")
mkdir -m 0700 -- "$RUN_DIR/uml" "$RUN_DIR/tmp"
LOG="$RUN_DIR/console.log"
FIFO="$RUN_DIR/console.pipe"
install -m 0600 /dev/null "$LOG"
mkfifo -m 0600 "$FIFO"
open_pollable_serial_sink "$RUN_DIR"

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
    "$KERNEL" mem=512M ncpus=1 seccomp=on \
    "umid=builder-${RUN_DIR##*.}" "uml_dir=$RUN_DIR/uml" \
    "initrd=$INITRAMFS" rdinit=/init rootfstype=ramfs \
    "ubd0r=$PAYLOAD" "ubd1=$TARGET_STAGE" \
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
[[ "$UML_STATUS" == 0 ]] || die "builder UML exited with status $UML_STATUS"
grep -Fq 'Checking that seccomp filters can be installed...OK' "$LOG" || die "builder did not use cooperative seccomp"
grep -Fq POCKET_BUILD_OK "$LOG" || die "builder did not complete successfully"
! grep -Fq POCKET_BUILD_ERROR "$LOG" || die "builder reported an error"
assert_clean_uml_log "$LOG" "builder UML"

e2fsck -fn "$TARGET_STAGE"
sync -f "$TARGET_STAGE"
mv -- "$TARGET_STAGE" "$TARGET"
TARGET_STAGE=
chmod 0400 "$TARGET"
sha256sum "$PAYLOAD" "$TARGET" > "$DISK_DIR/SHA256SUMS"
sync -f "$DISK_DIR"
mv -- "$LOG" "$BUILD_ROOT/logs/builder-ubuntu-$VERSION.log"
cat "$DISK_DIR/SHA256SUMS"
