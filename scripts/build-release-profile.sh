#!/usr/bin/env bash

source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"

ROOT=$(project_root)
BUILD_ROOT=${POCKET_BUILD_ROOT:-"$ROOT/build"}
LOCK_FILE="$ROOT/config/sources.lock.toml"
TEMPLATE="$ROOT/config/profile/x86_64-smp-p4k.template.json"
MKE2FS_CONFIG="$ROOT/config/profile/mke2fs.conf"
E2FSCK_CONFIG="$ROOT/config/profile/e2fsck.conf"
KERNEL_DIR="$BUILD_ROOT/kernel/x86_64-smp-p4k"
RELEASE_DIR="$BUILD_ROOT/release/x86_64-smp-p4k"
E2FS_DIR="$BUILD_ROOT/tools/e2fsprogs-1.47.2"
SKOPEO_DIR="$BUILD_ROOT/tools/skopeo-1.23.0"
OUTPUT_PARENT="$BUILD_ROOT/profiles"
SEALER_TARGET_DIR="$BUILD_ROOT/profile-sealer-target"
UMOCI=${POCKET_UMOCI:-/usr/bin/umoci}
export LC_ALL=C
export TZ=UTC

for command in awk cargo chmod env find mkdir mktemp rustc sha256sum stat truncate; do
    require_command "$command"
done
safe_managed_root "$BUILD_ROOT"
safe_managed_root "$OUTPUT_PARENT"
safe_managed_root "$SEALER_TARGET_DIR"
[[ -f "$LOCK_FILE" ]] || die "source lock file not found: $LOCK_FILE"
umask 0022

lock_value() {
    local section=$1
    local key=$2

    awk -v expected_section="[$section]" -v expected_key="$key" '
        $0 == expected_section { in_section = 1; next }
        /^\[/ { in_section = 0 }
        in_section {
            equals = index($0, "=")
            if (equals == 0) next
            candidate = substr($0, 1, equals - 1)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", candidate)
            if (candidate != expected_key) next
            value = substr($0, equals + 1)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
            if (value ~ /^".*"$/) value = substr(value, 2, length(value) - 2)
            print value
            found++
        }
        END { if (found != 1) exit 42 }
    ' "$LOCK_FILE"
}

verify_digest() {
    local artifact=$1
    local expected=$2
    local actual

    [[ -f "$artifact" && ! -L "$artifact" ]] || die "release input is missing or a symlink: $artifact"
    actual=$(sha256sum "$artifact" | awk '{print $1}')
    [[ "$actual" == "$expected" ]] || \
        die "release input digest mismatch for $artifact: expected $expected, found $actual"
}

verify_sidecar() {
    local artifact=$1
    local sidecar="$artifact.sha256"
    local expected_name=${artifact##*/}
    local expected actual name fields

    [[ -f "$sidecar" && ! -L "$sidecar" ]] || die "release digest sidecar is missing: $sidecar"
    fields=$(awk 'NR == 1 { print NF } NR > 1 { extra = 1 } END { if (extra) exit 42 }' "$sidecar")
    expected=$(awk 'NR == 1 { print $1 }' "$sidecar")
    name=$(awk 'NR == 1 { print $2 }' "$sidecar")
    [[ "$fields" == 2 && "$name" == "$expected_name" && ${#expected} == 64 ]] || \
        die "malformed release digest sidecar: $sidecar"
    actual=$(sha256sum "$artifact" | awk '{print $1}')
    [[ "$actual" == "$expected" ]] || die "release digest sidecar mismatch: $artifact"
}

RUST_RELEASE=$(rustc --version | awk '{print $2}')
[[ "$RUST_RELEASE" == 1.93.1 ]] || \
    die "release profile sealing requires rustc 1.93.1, found $RUST_RELEASE"

verify_digest "$TEMPLATE" "$(lock_value development_artifacts profile_template_sha256)"
verify_digest "$MKE2FS_CONFIG" "$(lock_value development_artifacts mke2fs_config_sha256)"
verify_digest "$E2FSCK_CONFIG" "$(lock_value development_artifacts e2fsck_config_sha256)"
verify_digest "$KERNEL_DIR/linux" "$(lock_value development_artifacts linux_uml_sha256)"
verify_digest "$KERNEL_DIR/.config" "$(lock_value development_artifacts linux_uml_config_sha256)"
verify_digest "$E2FS_DIR/mke2fs" "$(lock_value development_artifacts mke2fs_sha256)"
verify_digest "$E2FS_DIR/e2fsck" "$(lock_value development_artifacts e2fsck_sha256)"
verify_digest "$SKOPEO_DIR/skopeo" "$(lock_value development_artifacts skopeo_sha256)"
verify_digest "$SKOPEO_DIR/registry-ca.pem" \
    "$(lock_value development_artifacts registry_ca_sha256)"
verify_sidecar "$RELEASE_DIR/host/pocket-guard"
verify_sidecar "$RELEASE_DIR/guest/workload.cpio"
verify_sidecar "$RELEASE_DIR/guest/builder.cpio"
verify_sidecar "$RELEASE_DIR/guest/validator.cpio"

SMOKE_DIR=$(mktemp -d "$BUILD_ROOT/.release-profile-smoke.XXXXXXXX")
[[ "$SMOKE_DIR" == "$BUILD_ROOT/.release-profile-smoke."* ]] || \
    die "unexpected release-profile smoke directory: $SMOKE_DIR"
cleanup() {
    if [[ -n ${SMOKE_DIR:-} && -d "$SMOKE_DIR" && \
          "$SMOKE_DIR" == "$BUILD_ROOT/.release-profile-smoke."* ]]; then
        find "$SMOKE_DIR" -depth -delete
    fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
SMOKE_IMAGE="$SMOKE_DIR/filesystem.ext4"
SMOKE_MKE2FS_LOG="$SMOKE_DIR/mke2fs.log"
SMOKE_BLKID_FILE="$SMOKE_DIR/blkid.tab"
truncate -s 0 "$SMOKE_BLKID_FILE"
chmod 0600 "$SMOKE_BLKID_FILE"
truncate -s 32M "$SMOKE_IMAGE"
if ! env -i \
    MKE2FS_CONFIG="$MKE2FS_CONFIG" \
    BLKID_FILE="$SMOKE_BLKID_FILE" \
    E2FSPROGS_FAKE_TIME=1786940622 \
    "$E2FS_DIR/mke2fs" \
    -F -q -t ext4 -b 4096 -I 256 -i 16384 -m 0 \
    -L pocket-smoke -U 11111111-2222-5333-8444-555555555555 \
    -O has_journal,ext_attr,resize_inode,dir_index,filetype,extent,64bit,flex_bg,metadata_csum_seed,sparse_super,large_file,huge_file,dir_nlink,extra_isize,metadata_csum \
    -E lazy_itable_init=0,lazy_journal_init=0,root_owner=0:0 \
    "$SMOKE_IMAGE" > "$SMOKE_MKE2FS_LOG" 2>&1
then
    awk '{ print "mke2fs: " $0 }' "$SMOKE_MKE2FS_LOG" >&2
    die "frozen mke2fs policy failed its exact-argv smoke test"
fi
if [[ -s "$SMOKE_MKE2FS_LOG" ]]; then
    awk '{ print "mke2fs: " $0 }' "$SMOKE_MKE2FS_LOG" >&2
    die "frozen mke2fs policy emitted an unexpected diagnostic"
fi
env -i \
    E2FSCK_CONFIG="$E2FSCK_CONFIG" \
    BLKID_FILE="$SMOKE_BLKID_FILE" \
    E2FSPROGS_FAKE_TIME=1786940622 \
    "$E2FS_DIR/e2fsck" -fn "$SMOKE_IMAGE" >/dev/null

UMOCI_SHA256=$(sha256sum "$UMOCI" | awk '{print $1}')
[[ "$UMOCI_SHA256" == "$(lock_value development_artifacts umoci_sha256)" ]] || \
    die "umoci bytes no longer match the builder initramfs input lock"
UMOCI_VERSION=$(env -i "$UMOCI" --version)
[[ "$UMOCI_VERSION" == "umoci version 0.4.7+ds-4" ]] || \
    die "unexpected umoci version output: $UMOCI_VERSION"

mkdir -p -- "$OUTPUT_PARENT"
chmod 0755 "$OUTPUT_PARENT"
[[ $(stat -c '%a' "$OUTPUT_PARENT") == 755 ]] || \
    die "profile output parent has an unsafe mode"

CARGO_TARGET_DIR="$SEALER_TARGET_DIR" cargo build --locked --release -p pocket
POCKET="$SEALER_TARGET_DIR/release/pocket"
[[ -x "$POCKET" ]] || die "pocket profile sealer was not built"

"$POCKET" profile seal \
    --template "$TEMPLATE" \
    --output-parent "$OUTPUT_PARENT" \
    --guard "$RELEASE_DIR/host/pocket-guard" \
    --uml "$KERNEL_DIR/linux" \
    --skopeo "$SKOPEO_DIR/skopeo" \
    --registry-ca-bundle "$SKOPEO_DIR/registry-ca.pem" \
    --workload-initramfs "$RELEASE_DIR/guest/workload.cpio" \
    --builder-initramfs "$RELEASE_DIR/guest/builder.cpio" \
    --validator-initramfs "$RELEASE_DIR/guest/validator.cpio" \
    --mke2fs "$E2FS_DIR/mke2fs" \
    --e2fsck "$E2FS_DIR/e2fsck" \
    --mke2fs-config "$MKE2FS_CONFIG" \
    --e2fsck-config "$E2FSCK_CONFIG" \
    --kernel-config "$KERNEL_DIR/.config" \
    --umoci-sha256 "$UMOCI_SHA256" \
    --umoci-version "$UMOCI_VERSION" \
    --json
