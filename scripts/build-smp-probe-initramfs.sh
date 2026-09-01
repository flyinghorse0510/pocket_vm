#!/usr/bin/env bash

source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"

ROOT=$(project_root)
BUILD_ROOT=${POCKET_BUILD_ROOT:-"$ROOT/build"}
GEN_INIT_CPIO="$BUILD_ROOT/kernel/x86_64-smp-p4k/usr/gen_init_cpio"
TEMPLATE="$ROOT/config/initramfs/smp-probe.list.in"
OUTPUT_DIR="$BUILD_ROOT/initramfs"
BINARY="$OUTPUT_DIR/smp-probe"
SPEC="$OUTPUT_DIR/smp-probe.list"
OUTPUT="$OUTPUT_DIR/smp-probe.cpio"

for command in musl-gcc readelf file; do require_command "$command"; done
[[ -x "$GEN_INIT_CPIO" ]] || die "build the UML kernel first"
mkdir -p -- "$OUTPUT_DIR"

musl-gcc -std=c11 -O2 -pipe -static -Wall -Wextra -Werror \
    -fno-ident -Wl,--build-id=none \
    -o "$BINARY.tmp" "$ROOT/guest/smp-probe/main.c"
mv -- "$BINARY.tmp" "$BINARY"
[[ "$(file -b "$BINARY")" == *'ELF 64-bit LSB executable, x86-64'* ]] || \
    die "SMP probe has the wrong ELF ABI"
! readelf -l "$BINARY" | grep -q INTERP || die "SMP probe is dynamically linked"

sed "s|@SMP_PROBE@|$BINARY|g" "$TEMPLATE" > "$SPEC"
SOURCE_DATE_EPOCH=$(pocket_source_date_epoch)
"$GEN_INIT_CPIO" -t "$SOURCE_DATE_EPOCH" "$SPEC" > "$OUTPUT.tmp"
mv -- "$OUTPUT.tmp" "$OUTPUT"
sha256sum "$BINARY" "$OUTPUT" > "$OUTPUT.sha256"
cat "$OUTPUT.sha256"
