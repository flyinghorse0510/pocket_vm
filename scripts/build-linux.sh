#!/usr/bin/env bash

# shellcheck source=scripts/lib.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"
# shellcheck source=scripts/linux-source-lib.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/linux-source-lib.sh"

ROOT=$(project_root)
BUILD_ROOT=${POCKET_BUILD_ROOT:-"$ROOT/build"}
SOURCE_DIR="$BUILD_ROOT/src/$LINUX_SOURCE_NAME"
KERNEL_PARENT="$BUILD_ROOT/kernel"
PROFILE_ID="x86_64-smp-p4k$LINUX_OUTPUT_SUFFIX"
OUTPUT_DIR="$KERNEL_PARENT/$PROFILE_ID"
BUILD_STAGING="$KERNEL_PARENT/.$PROFILE_ID.building"
BUILD_HOME="$KERNEL_PARENT/.linux-build-home"
RECOVERY_DIR="$KERNEL_PARENT/replaced"
FRAGMENT="$ROOT/config/kernel/x86_64-uml.fragment"
JOBS=${POCKET_BUILD_JOBS:-$(getconf _NPROCESSORS_ONLN)}

for command in awk bc bison date file find flex flock g++ gcc getconf git ld make mktemp mv \
    python3 rsync sha256sum tar; do
    require_command "$command"
done
safe_managed_root "$BUILD_ROOT"
[[ $JOBS =~ ^[1-9][0-9]*$ && $JOBS -le 256 ]] || die "POCKET_BUILD_JOBS must be in 1..=256"
load_linux_source_locks "$ROOT"
if [[ -n $LINUX_VARIANT ]]; then
    printf 'building the EXPERIMENTAL %s kernel variant\n' "$LINUX_VARIANT" >&2
    printf 'source: %s\n' "$SOURCE_DIR" >&2
    printf 'output: %s\n' "$OUTPUT_DIR" >&2
    printf 'the default kernel at %s/x86_64-smp-p4k is not touched by this build\n' \
        "$KERNEL_PARENT" >&2
fi
acquire_linux_pipeline_lock "$BUILD_ROOT"
mkdir -p -- "$KERNEL_PARENT"

# This call always starts from the authenticated archive and publishes a new
# fully verified source tree. The inherited lock prevents any concurrent
# prepare/audit process from replacing SOURCE_DIR during this build.
prepared_source=$("$ROOT/scripts/apply-linux-patches.sh")
[[ $prepared_source == "$SOURCE_DIR" ]] || die "source preparation returned the wrong fixed path"
"$ROOT/scripts/audit-linux-source.sh" "$SOURCE_DIR"

preserve_generated_tree "$BUILD_STAGING" "$RECOVERY_DIR" "$PROFILE_ID.interrupted-build"
preserve_generated_tree "$BUILD_HOME" "$RECOVERY_DIR" linux-build-home.interrupted
mkdir -p -- "$BUILD_STAGING" "$BUILD_HOME" "$BUILD_HOME/tmp"
BUILD_PUBLISHED=0
preserve_failed_build() {
    if [[ $BUILD_PUBLISHED -eq 0 && ( -e $BUILD_STAGING || -L $BUILD_STAGING ) ]]; then
        preserve_generated_tree "$BUILD_STAGING" "$RECOVERY_DIR" "$PROFILE_ID.failed-build" || true
    fi
    if [[ -e $BUILD_HOME || -L $BUILD_HOME ]]; then
        cleanup_linux_staging "$BUILD_HOME" "$KERNEL_PARENT" .linux-build-home
    fi
}
trap preserve_failed_build EXIT

BUILD_TIMESTAMP=$(date --utc --date="@$LINUX_SOURCE_DATE_EPOCH" '+%a %b %d %H:%M:%S UTC %Y')
BUILD_PATH=$PATH
# TMPDIR is set deliberately. A parallel kernel build writes a great deal
# through the compiler's temporary directory, and left to default to /tmp it
# competes with whatever else the host keeps there; a full or quota-limited
# /tmp then fails the build with an error from inside gcc that reads as a
# source problem. The path is derived from the build root, so the environment
# stays as deterministic as `env -i` makes it, and it is removed with the rest
# of the build home.
run_build_command() {
    env -i \
        HOME="$BUILD_HOME" \
        PATH="$BUILD_PATH" \
        TMPDIR="$BUILD_HOME/tmp" \
        LC_ALL=C \
        TZ=UTC0 \
        ARCH=um \
        SUBARCH=x86_64 \
        CC=gcc \
        HOSTCC=gcc \
        HOSTCXX=g++ \
        LD=ld \
        KBUILD_BUILD_USER=pocket \
        KBUILD_BUILD_HOST=reproducible \
        KBUILD_BUILD_TIMESTAMP="$BUILD_TIMESTAMP" \
        KBUILD_BUILD_VERSION=1 \
        KCONFIG_NOTIMESTAMP=1 \
        SOURCE_DATE_EPOCH="$LINUX_SOURCE_DATE_EPOCH" \
        "$@"
}

run_build_command make -C "$SOURCE_DIR" O="$BUILD_STAGING" x86_64_defconfig
run_build_command "$SOURCE_DIR/scripts/kconfig/merge_config.sh" -m -O "$BUILD_STAGING" \
    "$BUILD_STAGING/.config" "$FRAGMENT"
run_build_command make -C "$SOURCE_DIR" O="$BUILD_STAGING" olddefconfig
POCKET_KERNEL_CONFIG="$BUILD_STAGING/.config" "$ROOT/scripts/verify-kernel-config.sh"
run_build_command make -C "$SOURCE_DIR" O="$BUILD_STAGING" -j "$JOBS" linux

# Out-of-tree compilation is not permitted to alter even an otherwise
# unobserved source file, mode, symlink, or directory.
"$ROOT/scripts/audit-linux-source.sh" "$SOURCE_DIR"

(
    cd -- "$BUILD_STAGING" || exit
    sha256sum linux .config > SHA256SUMS
)
linux_sha=$(sha256sum "$BUILD_STAGING/linux" | awk '{print $1}')
config_sha=$(sha256sum "$BUILD_STAGING/.config" | awk '{print $1}')
# A variant produces different bytes -- different patches, and a different
# reference toolchain -- so it carries its own artifact locks. Reading them
# from the variant's section means a variant build can never be waved through
# by the default build's digests, or the other way round.
ARTIFACT_SECTION=development_artifacts
[[ -z $LINUX_VARIANT ]] || ARTIFACT_SECTION="linux.variant.$LINUX_VARIANT"
locked_linux_sha=$(linux_lock_value "$LINUX_SOURCE_LOCK" linux_uml_sha256 "$ARTIFACT_SECTION")
locked_config_sha=$(linux_lock_value "$LINUX_SOURCE_LOCK" linux_uml_config_sha256 "$ARTIFACT_SECTION")
require_hex "$locked_linux_sha" 64 "$ARTIFACT_SECTION.linux_uml_sha256"
require_hex "$locked_config_sha" 64 "$ARTIFACT_SECTION.linux_uml_config_sha256"
[[ $linux_sha == "$locked_linux_sha" ]] || die "rebuilt UML kernel differs from the locked artifact SHA-256"
[[ $config_sha == "$locked_config_sha" ]] || die "rebuilt UML config differs from the locked artifact SHA-256"

{
    printf 'pocket-linux-build-v1\n'
    printf 'variant=%s\n' "${LINUX_VARIANT:-none}"
    printf 'source_tree_sha1=%s\n' "$LINUX_PATCHED_TREE"
    printf 'source_manifest_sha256=%s\n' "$LINUX_PATCHED_MANIFEST"
    printf 'patch_series_sha256=%s\n' "$LINUX_PATCH_SERIES_SHA256"
    [[ -z $LINUX_VARIANT ]] || \
        printf 'variant_series_sha256=%s\n' "$(sha256sum "$LINUX_OVERLAY_LOCK" | awk '{print $1}')"
    printf 'source_date_epoch=%s\n' "$LINUX_SOURCE_DATE_EPOCH"
    printf 'gcc=%s\n' "$(gcc -dumpfullversion -dumpversion)"
    printf 'ld=%s\n' "$(ld --version | awk 'NR == 1')"
    printf 'make=%s\n' "$(make --version | awk 'NR == 1')"
    printf 'python3=%s\n' "$(python3 --version 2>&1)"
    printf 'linux_sha256=%s\n' "$linux_sha"
    printf 'config_sha256=%s\n' "$config_sha"
} > "$BUILD_STAGING/BUILD-METADATA"
chmod 0444 "$BUILD_STAGING/BUILD-METADATA" "$BUILD_STAGING/SHA256SUMS"

preserve_generated_tree "$OUTPUT_DIR" "$RECOVERY_DIR" "$PROFILE_ID"
if ! mv -- "$BUILD_STAGING" "$OUTPUT_DIR"; then
    if [[ -n ${PRESERVED_GENERATED_TREE:-} && ! -e $OUTPUT_DIR && ! -L $OUTPUT_DIR ]]; then
        mv -- "$PRESERVED_GENERATED_TREE" "$OUTPUT_DIR" || true
    fi
    die "failed to atomically publish rebuilt UML kernel output"
fi
BUILD_PUBLISHED=1
cleanup_linux_staging "$BUILD_HOME" "$KERNEL_PARENT" .linux-build-home

file "$OUTPUT_DIR/linux"
cat "$OUTPUT_DIR/SHA256SUMS"
