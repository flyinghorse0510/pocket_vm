#!/usr/bin/env bash

source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"
# shellcheck source=scripts/linux-source-lib.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/linux-source-lib.sh"

ROOT=$(project_root)
BUILD_ROOT=${POCKET_BUILD_ROOT:-"$ROOT/build"}
KERNEL="$BUILD_ROOT/kernel/x86_64-smp-p4k$LINUX_OUTPUT_SUFFIX/linux"
INITRAMFS="$BUILD_ROOT/initramfs/probe.cpio"

[[ -x "$KERNEL" ]] || die "missing UML kernel"
# The probe initramfs is not a variant artifact: it is built once from the
# release source and comes out byte-identical whichever kernel built
# gen_init_cpio. Building it needs busybox, which the default lane's host has
# and an EL7 host does not, so a variant run says plainly that it did not check
# one rather than either demanding an artifact its lane cannot build or
# skipping in silence. Absent from a default run it is still an error.
CHECK_INITRAMFS=1
if [[ ! -f "$INITRAMFS" ]]; then
    [[ -n $LINUX_VARIANT ]] || die "missing probe initramfs"
    CHECK_INITRAMFS=0
fi

KERNEL_FILE=$(file -b "$KERNEL")
[[ "$KERNEL_FILE" == *'ELF 64-bit LSB executable, x86-64'* ]] || \
    die "unexpected UML ELF identity: $KERNEL_FILE"
[[ "$KERNEL_FILE" == *'statically linked'* ]] || die "UML kernel is not statically linked"

if readelf -l "$KERNEL" | grep -q INTERP; then
    die "static UML kernel unexpectedly contains PT_INTERP"
fi

if (( CHECK_INITRAMFS == 1 )); then
    sha256sum "$KERNEL" "$INITRAMFS"
else
    sha256sum "$KERNEL"
fi

# Printing a digest is not verification. Both artifacts are locked, so compare
# them and fail closed on any difference.
locked_artifact() {
    local key=$1
    local section=${2:-development_artifacts}
    local -a matches=()
    mapfile -t matches < <(
        awk -v wanted="$key" -v heading="[$section]" '
            $0 == heading { inside = 1; next }
            /^\[/ { if (inside) exit }
            inside && $0 ~ "^" wanted " = \"" { print; count++ }
            END { if (count != 1) exit 3 }
        ' "$ROOT/config/sources.lock.toml"
    ) || die "missing or duplicate $section.$key"
    # mapfile reports its own status, not awk's, so the count is what actually
    # rejects a missing or duplicated key.
    [[ ${#matches[@]} -eq 1 ]] || die "missing or duplicate $section.$key"
    local value=${matches[0]#*= }
    [[ $value =~ ^\"([0-9a-f]{64})\"$ ]] || die "$section.$key is not a SHA-256"
    printf '%s\n' "${BASH_REMATCH[1]}"
}

compare_artifact() {
    local label=$1 path=$2 key=$3 section=${4:-development_artifacts}
    local observed expected
    observed=$(sha256sum "$path" | awk '{print $1}')
    expected=$(locked_artifact "$key" "$section")
    [[ "$observed" == "$expected" ]] || \
        die "$label digest $observed does not match locked $expected"
}

# A variant's kernel is locked under its own section, so verifying one against
# the default's digest would fail every time and mean nothing when it passed.
# The probe initramfs is not variant specific: it is built from the release
# source and comes out byte-identical whichever kernel built gen_init_cpio.
KERNEL_SECTION=development_artifacts
[[ -z $LINUX_VARIANT ]] || KERNEL_SECTION="linux.variant.$LINUX_VARIANT"

compare_artifact "UML kernel" "$KERNEL" linux_uml_sha256 "$KERNEL_SECTION"
if (( CHECK_INITRAMFS == 1 )); then
    compare_artifact "probe initramfs" "$INITRAMFS" probe_initramfs_sha256
    printf 'verified artifact ABI, linkage, and locked digests\n'
else
    printf 'verified the %s kernel; no probe initramfs on this host to check\n' \
        "$LINUX_VARIANT"
fi

