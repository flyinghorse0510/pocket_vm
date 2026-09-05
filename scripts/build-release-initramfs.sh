#!/usr/bin/env bash

source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"
# shellcheck source=scripts/linux-source-lib.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/linux-source-lib.sh"

ROOT=$(project_root)
BUILD_ROOT=${POCKET_BUILD_ROOT:-"$ROOT/build"}
PROFILE_ROOT="$BUILD_ROOT/release/x86_64-smp-p4k"
GUEST_DIR="$PROFILE_ROOT/guest"
GEN_INIT_CPIO=${POCKET_GEN_INIT_CPIO:-"$BUILD_ROOT/kernel/x86_64-smp-p4k$LINUX_OUTPUT_SUFFIX/usr/gen_init_cpio"}
WORKLOAD_TEMPLATE="$ROOT/config/initramfs/workload-release.list.in"
BUILDER_TEMPLATE="$ROOT/config/initramfs/builder-release.list.in"
VALIDATOR_TEMPLATE="$ROOT/config/initramfs/validator-release.list.in"
SOURCE_LOCK="$ROOT/config/sources.lock.toml"
SOURCE_DATE_EPOCH=$(pocket_source_date_epoch)
export LC_ALL=C
export TZ=UTC
POCKET_INIT="$GUEST_DIR/pocket-init"
POCKET_BUILDER_INIT="$GUEST_DIR/pocket-builder-init"
POCKET_VALIDATOR_INIT="$GUEST_DIR/pocket-validator-init"
UMOCI=${POCKET_UMOCI:-/usr/bin/umoci}
LIBC=${POCKET_BUILDER_LIBC:-/usr/lib/x86_64-linux-gnu/libc.so.6}
LOADER=${POCKET_BUILDER_LOADER:-/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2}

for command in awk cmp cpio diff env grep install ldd mktemp objdump readelf sed sha256sum; do
    require_command "$command"
done
safe_managed_root "$BUILD_ROOT"
safe_managed_root "$PROFILE_ROOT"
[[ -x "$GEN_INIT_CPIO" ]] || die "build the pinned UML kernel first: $GEN_INIT_CPIO"
[[ -x "$POCKET_INIT" && -x "$POCKET_BUILDER_INIT" && -x "$POCKET_VALIDATOR_INIT" ]] || \
    die "build release Rust artifacts first"
[[ -x "$UMOCI" && -f "$LIBC" && -f "$LOADER" ]] || \
    die "pinned umoci loader/libc closure is missing"
umask 0022

lock_digest() {
    local key=$1
    local value

    value=$(sed -n "s/^${key} = \"\([0-9a-f]\{64\}\)\"$/\\1/p" "$SOURCE_LOCK")
    [[ ${#value} == 64 ]] || die "missing or duplicate $key in source lock"
    printf '%s\n' "$value"
}

verify_digest() {
    local artifact=$1
    local expected=$2
    local actual

    actual=$(sha256sum "$artifact" | awk '{print $1}')
    [[ "$actual" == "$expected" ]] || \
        die "artifact digest mismatch for $artifact: expected $expected, found $actual"
}

UMOCI_DIGEST=$(lock_digest umoci_sha256)
LIBC_DIGEST=$(lock_digest glibc_sha256)
LOADER_DIGEST=$(lock_digest glibc_loader_sha256)
verify_digest "$UMOCI" "$UMOCI_DIGEST"
verify_digest "$LIBC" "$LIBC_DIGEST"
verify_digest "$LOADER" "$LOADER_DIGEST"

UMOCI_VERSION=$(env -i "$UMOCI" --version)
[[ "$UMOCI_VERSION" == "umoci version 0.4.7+ds-4" ]] || \
    die "unexpected pinned umoci version output: $UMOCI_VERSION"
UMOCI_MACHINE=$(readelf -h "$UMOCI" | sed -n 's/^[[:space:]]*Machine:[[:space:]]*//p')
[[ "$UMOCI_MACHINE" == "Advanced Micro Devices X86-64" ]] || \
    die "pinned umoci is not x86-64: $UMOCI_MACHINE"
UMOCI_INTERPRETER=$(readelf -lW "$UMOCI" | \
    sed -n 's/.*Requesting program interpreter: \([^]]*\)].*/\1/p')
[[ "$UMOCI_INTERPRETER" == /lib64/ld-linux-x86-64.so.2 ]] || \
    die "unexpected umoci interpreter: $UMOCI_INTERPRETER"
mapfile -t UMOCI_NEEDED < <(objdump -p "$UMOCI" | awk '$1 == "NEEDED" { print $2 }')
[[ ${#UMOCI_NEEDED[@]} == 1 && ${UMOCI_NEEDED[0]} == libc.so.6 ]] || \
    die "umoci shared-library closure is not exactly libc.so.6 plus its loader"
LDD_OUTPUT=$(LC_ALL=C ldd "$UMOCI")
[[ "$LDD_OUTPUT" != *"not found"* ]] || die "umoci has an unresolved shared library"
mapfile -t UMOCI_CLOSURE < <(
    awk '$2 == "=>" && $3 ~ /^\// { print $3 }
         $1 ~ /^\// { print $1 }' <<< "$LDD_OUTPUT"
)
[[ ${#UMOCI_CLOSURE[@]} == 2 ]] || \
    die "umoci loader/library closure contains an unexpected file"
[[ ${UMOCI_CLOSURE[0]} == "$LIBC" && \
   ${UMOCI_CLOSURE[1]} == /lib64/ld-linux-x86-64.so.2 ]] || \
    die "umoci resolves outside the pinned loader/libc closure"

escape_sed_replacement() {
    sed 's/[&|\\]/\\&/g' <<< "$1"
}

STAGING_DIR=$(mktemp -d "$BUILD_ROOT/.release-initramfs.XXXXXXXX")
[[ "$STAGING_DIR" == "$BUILD_ROOT/.release-initramfs."* ]] || \
    die "unexpected release-initramfs staging directory: $STAGING_DIR"
cleanup() {
    if [[ -n ${STAGING_DIR:-} && -d "$STAGING_DIR" && \
          "$STAGING_DIR" == "$BUILD_ROOT/.release-initramfs."* ]]; then
        find "$STAGING_DIR" -depth -delete
    fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

WORKLOAD_SPEC="$STAGING_DIR/workload.list"
BUILDER_SPEC="$STAGING_DIR/builder.list"
VALIDATOR_SPEC="$STAGING_DIR/validator.list"
sed "s|@POCKET_INIT@|$(escape_sed_replacement "$POCKET_INIT")|g" \
    "$WORKLOAD_TEMPLATE" > "$WORKLOAD_SPEC"
sed \
    -e "s|@POCKET_BUILDER_INIT@|$(escape_sed_replacement "$POCKET_BUILDER_INIT")|g" \
    -e "s|@UMOCI@|$(escape_sed_replacement "$UMOCI")|g" \
    -e "s|@LIBC@|$(escape_sed_replacement "$LIBC")|g" \
    -e "s|@LOADER@|$(escape_sed_replacement "$LOADER")|g" \
    "$BUILDER_TEMPLATE" > "$BUILDER_SPEC"
sed "s|@POCKET_VALIDATOR_INIT@|$(escape_sed_replacement "$POCKET_VALIDATOR_INIT")|g" \
    "$VALIDATOR_TEMPLATE" > "$VALIDATOR_SPEC"

build_twice_and_compare() {
    local spec=$1
    local description=$2
    local first="$STAGING_DIR/$description.first.cpio"
    local second="$STAGING_DIR/$description.second.cpio"

    "$GEN_INIT_CPIO" -t "$SOURCE_DATE_EPOCH" -o "$first" "$spec"
    "$GEN_INIT_CPIO" -t "$SOURCE_DATE_EPOCH" -o "$second" "$spec"
    cmp -s "$first" "$second" || \
        die "$description initramfs was not reproducible across two independent pack operations"
    printf '%s\n' "$first"
}

WORKLOAD_CPIO=$(build_twice_and_compare "$WORKLOAD_SPEC" workload)
BUILDER_CPIO=$(build_twice_and_compare "$BUILDER_SPEC" builder)
VALIDATOR_CPIO=$(build_twice_and_compare "$VALIDATOR_SPEC" validator)

verify_archive_names() {
    local archive=$1
    local expected=$2
    local description=$3
    local actual="$STAGING_DIR/$description.names"

    cpio -it --quiet < "$archive" > "$actual"
    diff -u "$expected" "$actual" || die "$description initramfs contents differ from contract"
    if LC_ALL=C TZ=UTC cpio --numeric-uid-gid -itv --quiet < "$archive" | \
        awk '$3 != 0 || $4 != 0 { bad = 1 } END { exit bad }'
    then
        :
    else
        die "$description initramfs contains a non-root owner or group"
    fi
}

printf '%s\n' \
    dev \
    dev/console \
    proc \
    sys \
    run \
    tmp \
    volume \
    newroot \
    init \
    > "$STAGING_DIR/workload.expected"
printf '%s\n' \
    dev \
    dev/console \
    proc \
    sys \
    run \
    tmp \
    input \
    target \
    usr \
    usr/bin \
    usr/bin/umoci \
    lib \
    lib/x86_64-linux-gnu \
    lib/x86_64-linux-gnu/libc.so.6 \
    lib64 \
    lib64/ld-linux-x86-64.so.2 \
    init \
    > "$STAGING_DIR/builder.expected"
verify_archive_names "$WORKLOAD_CPIO" "$STAGING_DIR/workload.expected" workload
verify_archive_names "$BUILDER_CPIO" "$STAGING_DIR/builder.expected" builder
printf '%s\n' \
    dev \
    dev/console \
    proc \
    sys \
    candidate \
    init \
    > "$STAGING_DIR/validator.expected"
verify_archive_names "$VALIDATOR_CPIO" "$STAGING_DIR/validator.expected" validator

atomic_install() {
    local source=$1
    local destination=$2
    local directory temporary

    directory=$(dirname -- "$destination")
    mkdir -p -- "$directory"
    chmod 0755 "$PROFILE_ROOT" "$directory"
    temporary=$(mktemp "$directory/.${destination##*/}.tmp.XXXXXXXX")
    install -m 0444 "$source" "$temporary"
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

atomic_install "$WORKLOAD_CPIO" "$GUEST_DIR/workload.cpio"
atomic_install "$BUILDER_CPIO" "$GUEST_DIR/builder.cpio"
atomic_install "$VALIDATOR_CPIO" "$GUEST_DIR/validator.cpio"
for artifact in \
    "$GUEST_DIR/workload.cpio" \
    "$GUEST_DIR/builder.cpio" \
    "$GUEST_DIR/validator.cpio"
do
    atomic_sha256_sidecar "$artifact"
    sha256sum "$artifact"
done
printf 'builder_umoci_version=%s\n' "$UMOCI_VERSION"
printf 'builder_umoci_sha256=%s\n' "$UMOCI_DIGEST"
printf 'builder_libc_sha256=%s\n' "$LIBC_DIGEST"
printf 'builder_loader_sha256=%s\n' "$LOADER_DIGEST"
printf 'source_date_epoch=%s\n' "$SOURCE_DATE_EPOCH"
