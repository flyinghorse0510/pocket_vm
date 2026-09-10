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
UMOCI=${POCKET_UMOCI:-$(command -v umoci || true)}
# Resolved from umoci's own closure below. These were fixed at
# /usr/lib/x86_64-linux-gnu/..., which is Debian's multiarch layout and does not
# exist on most other distributions.
LIBC=${POCKET_BUILDER_LIBC:-}
LOADER=${POCKET_BUILDER_LOADER:-}

for command in awk file ldd readelf sed sha256sum; do
    require_command "$command"
done
[[ -x "$GEN_INIT_CPIO" ]] || die "build the UML kernel first"
# One resolver authenticates the busybox that is actually packed, so its pinned
# digest lives in exactly one place.
BUSYBOX=$(pocket_resolve_busybox)
[[ -n "$UMOCI" && -x "$UMOCI" ]] || die \
    "umoci is required (Debian/Ubuntu: apt install umoci); or set POCKET_UMOCI"
if [[ -z "$LOADER" ]]; then
    LOADER=$(readelf -lW "$UMOCI" |
        sed -n 's/.*Requesting program interpreter: \([^]]*\)].*/\1/p')
fi
if [[ -z "$LIBC" ]]; then
    LIBC=$(LC_ALL=C ldd "$UMOCI" | awk '$1 == "libc.so.6" && $3 ~ /^\// { print $3 }')
fi
[[ -f "$LIBC" && -f "$LOADER" ]] || die "cannot resolve umoci's glibc closure"

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

