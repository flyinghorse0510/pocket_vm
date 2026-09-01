#!/usr/bin/env bash

source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"

ROOT=$(project_root)
BUILD_ROOT=${POCKET_BUILD_ROOT:-"$ROOT/build"}
PROFILE_ROOT="$BUILD_ROOT/release/x86_64-smp-p4k"
TARGET=x86_64-unknown-linux-gnu
RUST_TARGET_DIR=${POCKET_RELEASE_CARGO_TARGET_DIR:-"$BUILD_ROOT/rust/$TARGET-static-pie"}
SOURCE_DATE_EPOCH=1786940622
export LC_ALL=C
export TZ=UTC

for command in ar awk cargo cut file gcc grep install mktemp readelf sed sha256sum; do
    require_command "$command"
done
safe_managed_root "$BUILD_ROOT"
safe_managed_root "$PROFILE_ROOT"
safe_managed_root "$RUST_TARGET_DIR"
umask 0022

RUST_RELEASE=$(rustc --version | awk '{print $2}')
[[ "$RUST_RELEASE" == 1.93.1 ]] || \
    die "release artifacts require rustc 1.93.1, found $RUST_RELEASE"
RUST_HOST=$(rustc -vV | sed -n 's/^host: //p')
[[ "$RUST_HOST" == "$TARGET" ]] || \
    die "release artifacts require a $TARGET Rust host, found $RUST_HOST"
GCC_MAJOR=$(gcc -dumpfullversion | cut -d. -f1)
[[ "$GCC_MAJOR" == 15 ]] || \
    die "release artifacts require GCC major 15, found $(gcc -dumpfullversion)"
[[ -d "$(rustc --print target-libdir --target "$TARGET")" ]] || \
    die "Rust target $TARGET is not installed"

POCKET_CARGO_HOME_PATH=${CARGO_HOME:-"${HOME:?HOME is required}/.cargo"}
[[ "$POCKET_CARGO_HOME_PATH" = /* ]] || \
    die "Cargo home must be absolute: $POCKET_CARGO_HOME_PATH"
[[ "$POCKET_CARGO_HOME_PATH" != *[[:space:]]* ]] || \
    die "Cargo home containing whitespace cannot be remapped reproducibly"

# The GNU target plus target-scoped +crt-static produces a static PIE while
# retaining glibc ABI compatibility with the pinned x86_64 release profile.
# Remap both first-party and registry source paths so the host account and
# checkout location cannot enter panic diagnostics in the stripped binaries.
export CARGO_TARGET_DIR="$RUST_TARGET_DIR"
export CARGO_INCREMENTAL=0
export SOURCE_DATE_EPOCH
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS="-Ctarget-feature=+crt-static --remap-path-prefix=$ROOT=/usr/src/pocket_vm --remap-path-prefix=$POCKET_CARGO_HOME_PATH=/usr/src/cargo"
export CC_x86_64_unknown_linux_gnu=gcc
export AR_x86_64_unknown_linux_gnu=ar
export CFLAGS_x86_64_unknown_linux_gnu="-ffile-prefix-map=$ROOT=/usr/src/pocket_vm -fdebug-prefix-map=$ROOT=/usr/src/pocket_vm"
unset RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER
unset POCKET_GUEST_CONTRACT_ID POCKET_INIT_BUILD_ID POCKET_KERNEL_BUILD_ID
unset POCKET_CPU_STATE_HWCAP_POLICY POCKET_GUEST_CAPABILITY_POLICY
unset POCKET_BUILDER_GUEST_CONTRACT_ID POCKET_BUILDER_INIT_BUILD_ID
unset POCKET_BUILDER_KERNEL_BUILD_ID POCKET_BUILDER_CPU_STATE_HWCAP_POLICY
unset POCKET_VALIDATOR_GUEST_CONTRACT_ID POCKET_VALIDATOR_INIT_BUILD_ID
unset POCKET_VALIDATOR_KERNEL_BUILD_ID POCKET_VALIDATOR_CPU_STATE_HWCAP_POLICY

cargo build --locked --release --target "$TARGET" \
    -p pocket -p pocket-init -p pocket-builder-init -p pocket-validator-init -p pocket-guard

verify_static_pie() {
    local binary=$1
    local description=$2
    local elf_type elf_machine

    [[ -s "$binary" ]] || die "$description was not built: $binary"
    elf_type=$(readelf -h "$binary" | sed -n 's/^[[:space:]]*Type:[[:space:]]*\([^[:space:]]*\).*/\1/p')
    elf_machine=$(readelf -h "$binary" | sed -n 's/^[[:space:]]*Machine:[[:space:]]*//p')
    [[ "$elf_type" == DYN ]] || die "$description is not an ELF static PIE (type=$elf_type)"
    [[ "$elf_machine" == "Advanced Micro Devices X86-64" ]] || \
        die "$description has the wrong ELF machine: $elf_machine"
    if readelf -lW "$binary" | grep -q ' INTERP '; then
        die "$description unexpectedly has a program interpreter"
    fi
    if readelf -dW "$binary" | grep -q '(NEEDED)'; then
        die "$description unexpectedly needs a shared library"
    fi
    file -b "$binary" | grep -Eq 'static-pie linked|statically linked' || \
        die "$description is not reported as statically linked"
}

atomic_install() {
    local source=$1
    local destination=$2
    local mode=$3
    local directory temporary

    directory=$(dirname -- "$destination")
    mkdir -p -- "$directory"
    chmod 0755 "$PROFILE_ROOT" "$directory"
    temporary=$(mktemp "$directory/.${destination##*/}.tmp.XXXXXXXX")
    install -m "$mode" "$source" "$temporary"
    mv -f -- "$temporary" "$destination"
}

atomic_sha256_sidecar() {
    local artifact=$1
    local directory basename temporary

    directory=$(dirname -- "$artifact")
    basename=${artifact##*/}
    temporary=$(mktemp "$directory/.${basename}.sha256.tmp.XXXXXXXX")
    (cd -- "$directory" && sha256sum "$basename") > "$temporary"
    chmod 0444 "$temporary"
    mv -f -- "$temporary" "$artifact.sha256"
}

RUST_OUTPUT="$RUST_TARGET_DIR/$TARGET/release"
for name in pocket pocket-init pocket-builder-init pocket-validator-init pocket-guard; do
    verify_static_pie "$RUST_OUTPUT/$name" "$name"
done

atomic_install "$RUST_OUTPUT/pocket" "$PROFILE_ROOT/host/pocket" 0555
atomic_install "$RUST_OUTPUT/pocket-init" "$PROFILE_ROOT/guest/pocket-init" 0555
atomic_install "$RUST_OUTPUT/pocket-builder-init" \
    "$PROFILE_ROOT/guest/pocket-builder-init" 0555
atomic_install "$RUST_OUTPUT/pocket-validator-init" \
    "$PROFILE_ROOT/guest/pocket-validator-init" 0555
atomic_install "$RUST_OUTPUT/pocket-guard" "$PROFILE_ROOT/host/pocket-guard" 0555

for artifact in \
    "$PROFILE_ROOT/host/pocket" \
    "$PROFILE_ROOT/guest/pocket-init" \
    "$PROFILE_ROOT/guest/pocket-builder-init" \
    "$PROFILE_ROOT/guest/pocket-validator-init" \
    "$PROFILE_ROOT/host/pocket-guard"
do
    verify_static_pie "$artifact" "${artifact##*/} release artifact"
    atomic_sha256_sidecar "$artifact"
    sha256sum "$artifact"
done
