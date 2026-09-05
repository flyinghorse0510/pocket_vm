#!/usr/bin/env bash

# shellcheck source=scripts/lib.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"
# shellcheck source=scripts/linux-source-lib.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/linux-source-lib.sh"

ROOT=$(project_root)
BUILD_ROOT=${POCKET_BUILD_ROOT:-"$ROOT/build"}
CONFIG=${POCKET_KERNEL_CONFIG:-"$BUILD_ROOT/kernel/x86_64-smp-p4k$LINUX_OUTPUT_SUFFIX/.config"}
REQUIRED="$ROOT/config/kernel/x86_64-uml.required"

[[ $CONFIG = /* ]] || die "kernel configuration path must be absolute"
[[ -f "$CONFIG" ]] || die "kernel configuration has not been generated: $CONFIG"

while IFS= read -r expected; do
    [[ -z "$expected" || "$expected" == \#\ Exact* ]] && continue
    grep -Fqx -- "$expected" "$CONFIG" || die "kernel config assertion failed: $expected"
done < "$REQUIRED"

printf 'verified kernel config: %s\n' "$CONFIG"
