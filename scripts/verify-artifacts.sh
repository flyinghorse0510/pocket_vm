#!/usr/bin/env bash

source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"

ROOT=$(project_root)
BUILD_ROOT=${POCKET_BUILD_ROOT:-"$ROOT/build"}
KERNEL="$BUILD_ROOT/kernel/x86_64-smp-p4k/linux"
INITRAMFS="$BUILD_ROOT/initramfs/probe.cpio"

[[ -x "$KERNEL" ]] || die "missing UML kernel"
[[ -f "$INITRAMFS" ]] || die "missing probe initramfs"

KERNEL_FILE=$(file -b "$KERNEL")
[[ "$KERNEL_FILE" == *'ELF 64-bit LSB executable, x86-64'* ]] || \
    die "unexpected UML ELF identity: $KERNEL_FILE"
[[ "$KERNEL_FILE" == *'statically linked'* ]] || die "UML kernel is not statically linked"

if readelf -l "$KERNEL" | grep -q INTERP; then
    die "static UML kernel unexpectedly contains PT_INTERP"
fi

sha256sum "$KERNEL" "$INITRAMFS"

# Printing a digest is not verification. Both artifacts are locked, so compare
# them and fail closed on any difference.
locked_artifact() {
    local key=$1
    local -a matches=()
    mapfile -t matches < <(
        awk -v wanted="$key" '
            /^\[development_artifacts\]$/ { inside = 1; next }
            /^\[/ { if (inside) exit }
            inside && $0 ~ "^" wanted " = \"" { print; count++ }
            END { if (count != 1) exit 3 }
        ' "$ROOT/config/sources.lock.toml"
    ) || die "missing or duplicate development_artifacts.$key"
    # mapfile reports its own status, not awk's, so the count is what actually
    # rejects a missing or duplicated key.
    [[ ${#matches[@]} -eq 1 ]] || die "missing or duplicate development_artifacts.$key"
    local value=${matches[0]#*= }
    [[ $value =~ ^\"([0-9a-f]{64})\"$ ]] || die "development_artifacts.$key is not a SHA-256"
    printf '%s\n' "${BASH_REMATCH[1]}"
}

compare_artifact() {
    local label=$1 path=$2 key=$3
    local observed expected
    observed=$(sha256sum "$path" | awk '{print $1}')
    expected=$(locked_artifact "$key")
    [[ "$observed" == "$expected" ]] || \
        die "$label digest $observed does not match locked $expected"
}

compare_artifact "UML kernel" "$KERNEL" linux_uml_sha256
compare_artifact "probe initramfs" "$INITRAMFS" probe_initramfs_sha256
printf 'verified artifact ABI, linkage, and locked digests\n'

