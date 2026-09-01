#!/usr/bin/env bash

source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"

ROOT=$(project_root)
BUILD_ROOT=${POCKET_BUILD_ROOT:-"$ROOT/build"}
KERNEL_OUTPUT="$BUILD_ROOT/kernel/x86_64-smp-p4k"
GEN_INIT_CPIO="$KERNEL_OUTPUT/usr/gen_init_cpio"
TEMPLATE="$ROOT/config/initramfs/lifecycle-probe.list.in"
OUTPUT_DIR="$BUILD_ROOT/initramfs"
SPEC="$OUTPUT_DIR/lifecycle-probe.list"
OUTPUT="$OUTPUT_DIR/lifecycle-probe.cpio"
PANIC_PROBE="$OUTPUT_DIR/lifecycle-panic"
[[ -x "$GEN_INIT_CPIO" ]] || die "build the UML kernel before the lifecycle probe initramfs"
BUSYBOX=$(pocket_resolve_busybox)
require_command musl-gcc

mkdir -p -- "$OUTPUT_DIR"
musl-gcc -std=c17 -static -Os -s -Wall -Wextra -Werror \
    -o "$PANIC_PROBE.tmp" "$ROOT/guest/lifecycle-probe/panic.c"
mv -- "$PANIC_PROBE.tmp" "$PANIC_PROBE"
file "$PANIC_PROBE" | grep -q 'statically linked' || die "panic probe must be statically linked"
sed -e "s|@BUSYBOX@|$BUSYBOX|g" \
    -e "s|@PANIC_PROBE@|$PANIC_PROBE|g" \
    -e "s|@PROJECT_ROOT@|$ROOT|g" \
    "$TEMPLATE" > "$SPEC"
SOURCE_DATE_EPOCH=$(pocket_source_date_epoch)
"$GEN_INIT_CPIO" -t "$SOURCE_DATE_EPOCH" "$SPEC" > "$OUTPUT.tmp"
mv -- "$OUTPUT.tmp" "$OUTPUT"
sha256sum "$OUTPUT" > "$OUTPUT.sha256"
cat "$OUTPUT.sha256"
