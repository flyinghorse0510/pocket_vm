#!/usr/bin/env bash

source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"

ROOT=$(project_root)
BUILD_ROOT=${POCKET_BUILD_ROOT:-"$ROOT/build"}
KERNEL_OUTPUT="$BUILD_ROOT/kernel/x86_64-smp-p4k"
GEN_INIT_CPIO="$KERNEL_OUTPUT/usr/gen_init_cpio"
TEMPLATE="$ROOT/config/initramfs/probe.list.in"
OUTPUT_DIR="$BUILD_ROOT/initramfs"
SPEC="$OUTPUT_DIR/probe.list"
OUTPUT="$OUTPUT_DIR/probe.cpio"
[[ -x "$GEN_INIT_CPIO" ]] || die "build the UML kernel before the probe initramfs"
BUSYBOX=$(pocket_resolve_busybox)

mkdir -p -- "$OUTPUT_DIR"
sed -e "s|@BUSYBOX@|$BUSYBOX|g" -e "s|@PROJECT_ROOT@|$ROOT|g" \
    "$TEMPLATE" > "$SPEC"
SOURCE_DATE_EPOCH=$(pocket_source_date_epoch)
"$GEN_INIT_CPIO" -t "$SOURCE_DATE_EPOCH" "$SPEC" > "$OUTPUT.tmp"
mv -- "$OUTPUT.tmp" "$OUTPUT"
sha256sum "$OUTPUT" > "$OUTPUT.sha256"
cat "$OUTPUT.sha256"

