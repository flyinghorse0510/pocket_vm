#!/usr/bin/env bash

# Build a diagnostic UML kernel from the same authenticated, patched source as
# the release kernel, with the lock/RCU/atomic-sleep validators enabled.
#
# The output is deliberately NOT locked and NOT publishable: its digest depends
# on debug options that no release profile carries. What it is for is proving
# that the release source runs the full lifecycle without the kernel's own
# validators complaining -- above all CONFIG_DEBUG_ATOMIC_SLEEP, which reports
# the exact class of defect that patches 0003-0005 fix.

# shellcheck source=scripts/lib.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"
# shellcheck source=scripts/linux-source-lib.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/linux-source-lib.sh"

export LC_ALL=C

ROOT=$(project_root)
BUILD_ROOT=${POCKET_BUILD_ROOT:-"$ROOT/build"}
SOURCE_DIR="$BUILD_ROOT/src/$LINUX_SOURCE_NAME"
FRAGMENT="$ROOT/config/kernel/x86_64-uml.fragment"
DIAGNOSTIC_FRAGMENT="$ROOT/config/kernel/x86_64-uml-diagnostic.fragment"
# Suffixed like every other kernel output. The source directory above already
# follows the variant, so sharing one output directory would let a variant
# build replace the default's diagnostic kernel with one built from different
# source, under a name that says nothing about it.
OUTPUT_DIR="$BUILD_ROOT/diagnostic-kernel$LINUX_OUTPUT_SUFFIX"
JOBS=${POCKET_BUILD_JOBS:-$(getconf _NPROCESSORS_ONLN)}

for command in awk bc bison file flex g++ gcc getconf ld make mkdir python3 sha256sum; do
    require_command "$command"
done
safe_managed_root "$BUILD_ROOT"
load_linux_source_locks "$ROOT"

[[ -d "$SOURCE_DIR" && ! -L "$SOURCE_DIR" ]] || \
    die "authenticated Linux source is missing; run: make kernel"
[[ -f "$DIAGNOSTIC_FRAGMENT" ]] || die "diagnostic fragment is missing"

# The diagnostic kernel is only meaningful if it is the release source. Prove
# that before spending a build on it.
"$ROOT/scripts/audit-linux-source.sh" "$SOURCE_DIR" >/dev/null

rm -rf -- "$OUTPUT_DIR"
mkdir -p -- "$OUTPUT_DIR/home" "$OUTPUT_DIR/out"

run_build_command() {
    env -i \
        HOME="$OUTPUT_DIR/home" \
        PATH="$PATH" \
        LC_ALL=C \
        TZ=UTC0 \
        ARCH=um \
        SUBARCH=x86_64 \
        CC=gcc \
        HOSTCC=gcc \
        HOSTCXX=g++ \
        LD=ld \
        KBUILD_BUILD_USER=pocket \
        KBUILD_BUILD_HOST=diagnostic \
        "$@"
}

run_build_command make -C "$SOURCE_DIR" O="$OUTPUT_DIR/out" x86_64_defconfig >/dev/null
run_build_command "$SOURCE_DIR/scripts/kconfig/merge_config.sh" -m -O "$OUTPUT_DIR/out" \
    "$OUTPUT_DIR/out/.config" "$FRAGMENT" "$DIAGNOSTIC_FRAGMENT" >/dev/null
run_build_command make -C "$SOURCE_DIR" O="$OUTPUT_DIR/out" olddefconfig >/dev/null
run_build_command make -C "$SOURCE_DIR" O="$OUTPUT_DIR/out" -j "$JOBS" linux >/dev/null

# Every requested validator must actually be present. A silently dropped option
# would turn this whole lane into a kernel that proves nothing.
missing=0
while read -r line; do
    [[ "$line" == CONFIG_* ]] || continue
    if ! grep -Fxq "$line" "$OUTPUT_DIR/out/.config"; then
        printf 'diagnostic option was not honoured: %s\n' "$line" >&2
        missing=$((missing + 1))
    fi
done < "$DIAGNOSTIC_FRAGMENT"
(( missing == 0 )) || die "$missing diagnostic kernel options were not enabled"

# The whole point of the lane is this one option.
grep -Fxq 'CONFIG_DEBUG_ATOMIC_SLEEP=y' "$OUTPUT_DIR/out/.config" || \
    die "CONFIG_DEBUG_ATOMIC_SLEEP is not enabled"
# And it must be the corrected source, not a prototype.
grep -Fq 'free_chan_irqs_locked' "$SOURCE_DIR/arch/um/drivers/chan_kern.c" || \
    die "source does not carry the locked channel-IRQ correction"

{
    printf 'pocket-diagnostic-kernel-v1\n'
    printf 'variant=%s\n' "${LINUX_VARIANT:-none}"
    printf 'source_tree_sha1=%s\n' "$LINUX_PATCHED_TREE"
    printf 'source_manifest_sha256=%s\n' "$LINUX_PATCHED_MANIFEST"
    printf 'patch_series_sha256=%s\n' "$LINUX_PATCH_SERIES_SHA256"
    printf 'linux_sha256=%s\n' "$(sha256sum "$OUTPUT_DIR/out/linux" | awk '{print $1}')"
    printf 'config_sha256=%s\n' "$(sha256sum "$OUTPUT_DIR/out/.config" | awk '{print $1}')"
} > "$OUTPUT_DIR/BUILD-METADATA"

cat "$OUTPUT_DIR/BUILD-METADATA"
printf 'diagnostic_kernel=%s\n' "$OUTPUT_DIR/out/linux"
