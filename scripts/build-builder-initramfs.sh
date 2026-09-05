#!/usr/bin/env bash

source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"
# shellcheck source=scripts/linux-source-lib.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/linux-source-lib.sh"

ROOT=$(project_root)
BUILD_ROOT=${POCKET_BUILD_ROOT:-"$ROOT/build"}
GEN_INIT_CPIO="$BUILD_ROOT/kernel/x86_64-smp-p4k$LINUX_OUTPUT_SUFFIX/usr/gen_init_cpio"
TEMPLATE="$ROOT/config/initramfs/builder-probe.list.in"
OUTPUT_DIR="$BUILD_ROOT/initramfs"
SPEC="$OUTPUT_DIR/builder-probe.list"
OUTPUT="$OUTPUT_DIR/builder-probe.cpio"
UMOCI=$(command -v umoci || true)
LIBC=/usr/lib/x86_64-linux-gnu/libc.so.6
LOADER=/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2

[[ -x "$GEN_INIT_CPIO" ]] || die "build the UML kernel first"
# One resolver authenticates the busybox that is actually packed, so its pinned
# digest lives in exactly one place.
BUSYBOX=$(pocket_resolve_busybox)
[[ -n "$UMOCI" && -x "$UMOCI" ]] || die "umoci is required"
[[ -f "$LIBC" && -f "$LOADER" ]] || die "pinned glibc runtime files are missing"

# The pinned digests live in config/sources.lock.toml, not here: two copies of
# one constant is one copy that can drift.
printf '%s  %s\n' \
    "$(pocket_locked_sha256 umoci_sha256)" "$UMOCI" \
    "$(pocket_locked_sha256 glibc_sha256)" "$LIBC" \
    "$(pocket_locked_sha256 glibc_loader_sha256)" "$LOADER" \
    | sha256sum --check --status - || die "builder runtime artifact digest mismatch"

mkdir -p -- "$OUTPUT_DIR"
sed -e "s|@BUSYBOX@|$BUSYBOX|g" \
    -e "s|@UMOCI@|$UMOCI|g" \
    -e "s|@LIBC@|$LIBC|g" \
    -e "s|@LOADER@|$LOADER|g" \
    -e "s|@PROJECT_ROOT@|$ROOT|g" \
    "$TEMPLATE" > "$SPEC"
SOURCE_DATE_EPOCH=$(pocket_source_date_epoch)
"$GEN_INIT_CPIO" -t "$SOURCE_DATE_EPOCH" "$SPEC" > "$OUTPUT.tmp"
mv -- "$OUTPUT.tmp" "$OUTPUT"
sha256sum "$OUTPUT" > "$OUTPUT.sha256"
cat "$OUTPUT.sha256"

