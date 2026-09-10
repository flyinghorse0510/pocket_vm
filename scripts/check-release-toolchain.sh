#!/usr/bin/env bash

# What a release build actually needs from the host toolchain, checked before
# any of the long builds start.
#
# Two different kinds of requirement live here, and conflating them is what
# produced the rule this replaces.
#
# GCC is load-bearing. The kernel, e2fsprogs and Skopeo each compare their own
# output against a SHA-256 recorded in config/sources.lock.toml and refuse to
# publish a mismatch. A different GCC major therefore does not yield a different
# release; it yields no release at all, most of an hour later. Checking it here
# turns a guaranteed late failure into an immediate one, which is the opposite
# of over-verification.
#
# Rust is not load-bearing, and used to be pinned to one patch release anyway.
# No Rust-built artifact has a locked digest anywhere in this tree: not the five
# binaries, not the three initramfs images, not the archive. Their `.sha256`
# sidecars are generated from the same build that produced them, and
# scripts/verify-artifacts.sh compares only the kernel and the probe initramfs.
# So nothing downstream constrains which rustc built them, and refusing to
# build on 1.94 bought exactly nothing.
#
# `make reproduce-release` does not need it either: scripts/reproduce-release.sh
# runs the second build on the same host, so both halves share whichever rustc
# is installed. Matching a release built on some *other* machine is a real
# question, but the answer to it is the version this reports, not a refusal to
# build here. Set POCKET_STRICT_TOOLCHAIN=1 when that is what you are doing.

# shellcheck source=scripts/lib.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"

ROOT=$(project_root)
TARGET=x86_64-unknown-linux-gnu

for command in awk cargo cut gcc rustc sed sort; do
    require_command "$command"
done

# The floor the workspace itself declares. Cargo enforces this on every build
# path already; naming it here only makes the failure legible and early.
RUST_FLOOR=$(
    awk -F'"' '/^rust-version[[:space:]]*=/ { print $2; found++ }
               END { if (found != 1) exit 42 }' "$ROOT/Cargo.toml"
) || die "Cargo.toml does not declare exactly one workspace rust-version"

RUST_RECORDED=$(pocket_lock_value development_tools rust)
RUST_ACTUAL=$(rustc --version | awk '{print $2}')
CARGO_ACTUAL=$(cargo --version | awk '{print $2}')

pocket_version_at_least "$RUST_ACTUAL" "$RUST_FLOOR" || die \
    "release builds need rustc $RUST_FLOOR or newer, found $RUST_ACTUAL"
pocket_version_at_least "$CARGO_ACTUAL" "$RUST_FLOOR" || die \
    "release builds need cargo $RUST_FLOOR or newer, found $CARGO_ACTUAL"

# Exactness on request, for the one job that wants it: comparing your bytes
# against a release somebody else built.
if pocket_strict_toolchain; then
    [[ "$RUST_ACTUAL" == "$RUST_RECORDED" ]] || die \
        "POCKET_STRICT_TOOLCHAIN is set and rustc is $RUST_ACTUAL, but config/sources.lock.toml records $RUST_RECORDED"
    [[ "$CARGO_ACTUAL" == "$RUST_RECORDED" ]] || die \
        "POCKET_STRICT_TOOLCHAIN is set and cargo is $CARGO_ACTUAL, but config/sources.lock.toml records $RUST_RECORDED"
fi

# A genuine build requirement rather than a preference: the release artifacts
# are static PIEs for this triple, and cargo cannot produce them without it.
RUST_HOST=$(rustc -vV | sed -n 's/^host: //p')
[[ "$RUST_HOST" == "$TARGET" ]] || die \
    "release artifacts require a $TARGET Rust host, found $RUST_HOST"
TARGET_LIBDIR=$(rustc --print target-libdir --target "$TARGET" 2>/dev/null) || \
    die "Rust target $TARGET is not installed (rustup target add $TARGET)"
[[ -d "$TARGET_LIBDIR" ]] || \
    die "Rust target $TARGET is not installed (rustup target add $TARGET)"

# -dumpfullversion arrived in GCC 7; fall back so an older host gets the note
# rather than an empty version and a confusing one.
GCC_VERSION=$(gcc -dumpfullversion 2>/dev/null || gcc -dumpversion)
GCC_MAJOR=${GCC_VERSION%%.*}
pocket_match_recorded "the GCC major version" "$GCC_MAJOR" \
    "$(pocket_lock_value development_tools cc_major)"

printf 'release toolchain: rustc %s, cargo %s, host %s, gcc %s\n' \
    "$RUST_ACTUAL" "$CARGO_ACTUAL" "$RUST_HOST" "$GCC_VERSION"
if [[ "$RUST_ACTUAL" != "$RUST_RECORDED" ]]; then
    printf 'note: the reference release was built with rustc %s; these artifacts will not be byte-identical to it\n' \
        "$RUST_RECORDED" >&2
fi
