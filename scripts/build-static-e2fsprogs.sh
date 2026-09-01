#!/usr/bin/env bash

source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"

ROOT=$(project_root)
BUILD_ROOT=${POCKET_BUILD_ROOT:-"$ROOT/build"}
LOCK_FILE="$ROOT/config/sources.lock.toml"
MKE2FS_CONFIG="$ROOT/config/profile/mke2fs.conf"
E2FSCK_CONFIG="$ROOT/config/profile/e2fsck.conf"
VERSION=1.47.2
SOURCE_DATE_EPOCH=1735716385
SOURCE_NAME="e2fsprogs-$VERSION"
SOURCE_URL="https://cdn.kernel.org/pub/linux/kernel/people/tytso/e2fsprogs/v$VERSION/$SOURCE_NAME.tar.xz"
CHECKSUMS_URL="https://cdn.kernel.org/pub/linux/kernel/people/tytso/e2fsprogs/v$VERSION/sha256sums.asc"
EXPECTED_SOURCE_SHA256=08242e64ca0e8194d9c1caad49762b19209a06318199b63ce74ae4ef2d74e63c
EXPECTED_CHECKSUMS_SHA256=cbfc602aa3efc08502352f28a573b72df1690d0663cab832763ad269595d2c12
EXPECTED_SIGNER_FINGERPRINT=B8868C80BA62A1FFFAF5FDA9632D3A06589DA6B1
DOWNLOAD_DIR="$BUILD_ROOT/downloads"
TARBALL="$DOWNLOAD_DIR/$SOURCE_NAME.tar.xz"
CHECKSUMS="$DOWNLOAD_DIR/$SOURCE_NAME.sha256sums.asc"
GNUPG_HOME="$BUILD_ROOT/gnupg/$SOURCE_NAME"
OUTPUT_DIR="$BUILD_ROOT/tools/$SOURCE_NAME"
ONLINE_CPU_COUNT=$(getconf _NPROCESSORS_ONLN)
[[ "$ONLINE_CPU_COUNT" =~ ^[1-9][0-9]*$ ]] || \
    die "getconf returned an invalid online CPU count"
if ((ONLINE_CPU_COUNT > 16)); then
    ONLINE_CPU_COUNT=16
fi
JOBS=${POCKET_BUILD_JOBS:-$ONLINE_CPU_COUNT}

for command in awk basename chmod cmp curl dirname file find gcc getconf gpg grep \
    install ln make mkdir mktemp mv readelf sha256sum strings strip tar timeout \
    touch truncate uname xz; do
    require_command "$command"
done
safe_managed_root "$BUILD_ROOT"
safe_managed_root "$OUTPUT_DIR"
[[ -f "$LOCK_FILE" ]] || die "source lock file not found: $LOCK_FILE"
[[ $(uname -m) == x86_64 ]] || die "the release e2fsprogs build requires an x86_64 host"
[[ "$JOBS" =~ ^[1-9][0-9]*$ ]] || die "POCKET_BUILD_JOBS must be a positive integer"
((JOBS <= 64)) || die "POCKET_BUILD_JOBS exceeds the bounded maximum of 64"
umask 022

mkdir -p -- "$BUILD_ROOT" "$DOWNLOAD_DIR" "$GNUPG_HOME"
chmod 0700 "$GNUPG_HOME"
WORK_ROOT=$(mktemp -d "$BUILD_ROOT/.${SOURCE_NAME}.build.XXXXXX")
[[ "$WORK_ROOT" == "$BUILD_ROOT/.${SOURCE_NAME}.build."* ]] || \
    die "unexpected e2fsprogs work directory: $WORK_ROOT"

cleanup() {
    if [[ -n ${WORK_ROOT:-} && -d "$WORK_ROOT" && \
          "$WORK_ROOT" == "$BUILD_ROOT/.${SOURCE_NAME}.build."* ]]; then
        find "$WORK_ROOT" -depth -delete
    fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

download() {
    local url=$1
    local output=$2
    local staging

    staging="$WORK_ROOT/$(basename -- "$output").download"

    if [[ ! -f "$output" ]]; then
        curl --proto '=https' --tlsv1.2 --fail --location \
            --retry 3 --retry-all-errors --connect-timeout 15 --max-time 300 \
            --output "$staging" "$url"
        mv -- "$staging" "$output"
    fi
}

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

[[ $(lock_value e2fsprogs release) == "$VERSION" ]] || \
    die "e2fsprogs release does not match sources.lock.toml"
[[ $(lock_value e2fsprogs tarball_url) == "$SOURCE_URL" ]] || \
    die "e2fsprogs source URL does not match sources.lock.toml"
[[ $(lock_value e2fsprogs signed_checksums_url) == "$CHECKSUMS_URL" ]] || \
    die "e2fsprogs signed-checksum URL does not match sources.lock.toml"
[[ -f "$MKE2FS_CONFIG" && ! -L "$MKE2FS_CONFIG" ]] || \
    die "frozen mke2fs policy is missing or a symlink"
[[ -f "$E2FSCK_CONFIG" && ! -L "$E2FSCK_CONFIG" ]] || \
    die "empty e2fsck policy is missing or a symlink"
[[ $(sha256sum "$MKE2FS_CONFIG" | awk '{print $1}') == \
    "$(lock_value development_artifacts mke2fs_config_sha256)" ]] || \
    die "frozen mke2fs policy does not match sources.lock.toml"
[[ $(sha256sum "$E2FSCK_CONFIG" | awk '{print $1}') == \
    "$(lock_value development_artifacts e2fsck_config_sha256)" ]] || \
    die "empty e2fsck policy does not match sources.lock.toml"
[[ $(lock_value e2fsprogs tarball_sha256) == "$EXPECTED_SOURCE_SHA256" ]] || \
    die "e2fsprogs source SHA-256 does not match sources.lock.toml"
[[ $(lock_value e2fsprogs signed_checksums_sha256) == "$EXPECTED_CHECKSUMS_SHA256" ]] || \
    die "e2fsprogs signed-checksum SHA-256 does not match sources.lock.toml"
[[ $(lock_value e2fsprogs checksum_signer_fingerprint) == "$EXPECTED_SIGNER_FINGERPRINT" ]] || \
    die "e2fsprogs checksum signer does not match sources.lock.toml"
[[ $(lock_value e2fsprogs source_date_epoch) == "$SOURCE_DATE_EPOCH" ]] || \
    die "e2fsprogs SOURCE_DATE_EPOCH does not match sources.lock.toml"
GCC_VERSION=$(gcc -dumpversion)
[[ ${GCC_VERSION%%.*} == "$(lock_value development_tools cc_major)" ]] || \
    die "GCC major version does not match sources.lock.toml"

download "$SOURCE_URL" "$TARBALL"
download "$CHECKSUMS_URL" "$CHECKSUMS"

ACTUAL_SOURCE_SHA256=$(sha256sum "$TARBALL" | awk '{print $1}')
[[ "$ACTUAL_SOURCE_SHA256" == "$EXPECTED_SOURCE_SHA256" ]] || \
    die "e2fsprogs tarball SHA-256 mismatch"
ACTUAL_CHECKSUMS_SHA256=$(sha256sum "$CHECKSUMS" | awk '{print $1}')
[[ "$ACTUAL_CHECKSUMS_SHA256" == "$EXPECTED_CHECKSUMS_SHA256" ]] || \
    die "e2fsprogs signed-checksum file SHA-256 mismatch"

if ! gpg --batch --homedir "$GNUPG_HOME" \
    --list-keys "$EXPECTED_SIGNER_FINGERPRINT" >/dev/null 2>&1; then
    timeout --signal=TERM --kill-after=10s 60s \
        gpg --batch --homedir "$GNUPG_HOME" \
        --keyserver hkps://keyserver.ubuntu.com \
        --keyserver-options timeout=15 \
        --recv-keys "$EXPECTED_SIGNER_FINGERPRINT"
fi

PRIMARY_FINGERPRINT=$(gpg --batch --homedir "$GNUPG_HOME" --with-colons \
    --fingerprint "$EXPECTED_SIGNER_FINGERPRINT" | \
    awk -F: '$1 == "fpr" { print $10; exit }')
[[ "$PRIMARY_FINGERPRINT" == "$EXPECTED_SIGNER_FINGERPRINT" ]] || \
    die "unexpected e2fsprogs checksum-signing key fingerprint: $PRIMARY_FINGERPRINT"

CHECKSUM_PLAINTEXT="$WORK_ROOT/sha256sums"
GPG_STATUS="$WORK_ROOT/gpg.status"
gpg --batch --homedir "$GNUPG_HOME" --status-fd=3 \
    --output "$CHECKSUM_PLAINTEXT" --decrypt "$CHECKSUMS" 3>"$GPG_STATUS"
mapfile -t VALID_FINGERPRINTS < <(
    awk '$1 == "[GNUPG:]" && $2 == "VALIDSIG" { print $3 }' "$GPG_STATUS"
)
((${#VALID_FINGERPRINTS[@]} == 1)) || \
    die "expected exactly one valid signature on the e2fsprogs checksum file"
[[ "${VALID_FINGERPRINTS[0]}" == "$EXPECTED_SIGNER_FINGERPRINT" ]] || \
    die "e2fsprogs checksum signature was made by an unexpected key"

SIGNED_SOURCE_COUNT=$(awk -v name="$SOURCE_NAME.tar.xz" \
    '$2 == name { count++ } END { print count + 0 }' "$CHECKSUM_PLAINTEXT")
[[ "$SIGNED_SOURCE_COUNT" == 1 ]] || \
    die "signed checksum file does not contain exactly one e2fsprogs tarball entry"
SIGNED_SOURCE_SHA256=$(awk -v name="$SOURCE_NAME.tar.xz" \
    '$2 == name { print $1 }' "$CHECKSUM_PLAINTEXT")
[[ "$SIGNED_SOURCE_SHA256" == "$EXPECTED_SOURCE_SHA256" ]] || \
    die "signed e2fsprogs tarball SHA-256 does not match the release lock"

if ! tar -tf "$TARBALL" | awk -v prefix="$SOURCE_NAME/" '
    $0 ~ /^\// || $0 ~ /(^|\/)\.\.(\/|$)/ { exit 1 }
    $0 != substr(prefix, 1, length(prefix) - 1) && index($0, prefix) != 1 { exit 1 }
'; then
    die "e2fsprogs tarball contains an unsafe or unexpected path"
fi

build_once() {
    local label=$1
    local instance="$WORK_ROOT/$label"
    local source_dir="$instance/source"
    local build_dir="$instance/build"
    local result_dir="$instance/result"
    local canonical_source=/usr/src/e2fsprogs-1.47.2
    local cflags
    local -a build_environment

    mkdir -p -- "$source_dir" "$build_dir" "$result_dir" "$instance/tmp"
    tar -C "$source_dir" --strip-components=1 --no-same-owner \
        --no-same-permissions -xf "$TARBALL"
    [[ -x "$source_dir/configure" ]] || die "extracted e2fsprogs configure script is missing"

    cflags="-O2 -g0 -fno-ident -fno-record-gcc-switches"
    cflags+=" -ffile-prefix-map=$instance=$canonical_source"
    cflags+=" -fdebug-prefix-map=$instance=$canonical_source"
    cflags+=" -fmacro-prefix-map=$instance=$canonical_source"
    cflags+=" -Wdate-time -Werror=date-time"
    build_environment=(
        env -i
        PATH=/usr/bin:/bin
        LC_ALL=C
        LANG=C
        TZ=UTC
        SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH"
        ZERO_AR_DATE=1
        TMPDIR="$instance/tmp"
        CONFIG_SITE=/dev/null
        CC=gcc
        BUILD_CC=gcc
        PKG_CONFIG=/bin/false
        CFLAGS="$cflags"
        CPPFLAGS=
        LDFLAGS="-Wl,--build-id=none"
        ac_cv_lib_magic_magic_file=no
        ac_cv_header_magic_h=no
    )

    (
        cd -- "$build_dir" || exit 1
        timeout --signal=TERM --kill-after=30s 300s "${build_environment[@]}" \
            "$source_dir/configure" \
            --build=x86_64-pc-linux-gnu \
            --host=x86_64-pc-linux-gnu \
            --srcdir="$source_dir" \
            --prefix=/usr \
            --with-root-prefix= \
            --disable-elf-shlibs \
            --disable-profile \
            --disable-gcov \
            --enable-hardening \
            --disable-jbd-debug \
            --disable-blkid-debug \
            --disable-testio-debug \
            --disable-developer-features \
            --enable-libuuid \
            --enable-libblkid \
            --disable-backtrace \
            --disable-debugfs \
            --disable-imager \
            --disable-resizer \
            --disable-defrag \
            --disable-fsck \
            --disable-e2initrd-helper \
            --disable-uuidd \
            --disable-nls \
            --disable-rpath \
            --disable-fuse2fs \
            --disable-lto \
            --disable-ubsan \
            --disable-addrsan \
            --disable-threadsan \
            --disable-fuzzing \
            --without-libarchive \
            --without-crond-dir \
            --without-systemd-unit-dir \
            --without-udev-rules-dir
    )

    timeout --signal=TERM --kill-after=30s 600s "${build_environment[@]}" \
        make -C "$build_dir" -j "$JOBS" libs
    timeout --signal=TERM --kill-after=30s 600s "${build_environment[@]}" \
        make -C "$build_dir/e2fsck" -j "$JOBS" e2fsck.static
    timeout --signal=TERM --kill-after=30s 600s "${build_environment[@]}" \
        make -C "$build_dir/misc" -j "$JOBS" mke2fs.static

    install -m 0755 "$build_dir/misc/mke2fs.static" "$result_dir/mke2fs"
    install -m 0755 "$build_dir/e2fsck/e2fsck.static" "$result_dir/e2fsck"
    strip --strip-all --remove-section=.comment "$result_dir/mke2fs" "$result_dir/e2fsck"
}

build_once first
build_once second
FIRST_RESULT="$WORK_ROOT/first/result"
SECOND_RESULT="$WORK_ROOT/second/result"
cmp --silent "$FIRST_RESULT/mke2fs" "$SECOND_RESULT/mke2fs" || \
    die "independent mke2fs builds are not byte-for-byte reproducible"
cmp --silent "$FIRST_RESULT/e2fsck" "$SECOND_RESULT/e2fsck" || \
    die "independent e2fsck builds are not byte-for-byte reproducible"

verify_static_binary() {
    local binary=$1
    local name=$2
    local description

    description=$(file "$binary")
    [[ "$description" == *"ELF 64-bit LSB executable, x86-64"* ]] || \
        die "$name is not an x86-64 ELF executable"
    [[ "$description" == *"statically linked"* ]] || \
        die "$name is not statically linked"
    if readelf -lW "$binary" | grep -Eq '(^|[[:space:]])(INTERP|DYNAMIC)([[:space:]]|$)'; then
        die "$name contains a dynamic-loader program header"
    fi
    if readelf -dW "$binary" 2>&1 | grep -q '(NEEDED)'; then
        die "$name declares a dynamic-library dependency"
    fi
    if strings "$binary" | grep -Fq "$WORK_ROOT"; then
        die "$name embeds its temporary build path"
    fi
}

verify_static_binary "$FIRST_RESULT/mke2fs" mke2fs
verify_static_binary "$FIRST_RESULT/e2fsck" e2fsck

MKE2FS_VERSION=$("$FIRST_RESULT/mke2fs" -V 2>&1 || true)
E2FSCK_VERSION=$("$FIRST_RESULT/e2fsck" -V 2>&1 || true)
[[ "$MKE2FS_VERSION" == *"mke2fs 1.47.2 (1-Jan-2025)"* ]] || \
    die "unexpected mke2fs version output"
[[ "$E2FSCK_VERSION" == *"e2fsck 1.47.2 (1-Jan-2025)"* ]] || \
    die "unexpected e2fsck version output"

SMOKE_ROOT="$WORK_ROOT/smoke-root"
SMOKE_IMAGE="$WORK_ROOT/smoke.ext4"
SMOKE_BLKID_FILE="$WORK_ROOT/smoke.blkid.tab"
mkdir -p -- "$SMOKE_ROOT/etc"
printf '%s\n' pocket-static-e2fsprogs-smoke > "$SMOKE_ROOT/etc/pocket-release"
ln -s pocket-release "$SMOKE_ROOT/etc/release-link"
touch -d "@$SOURCE_DATE_EPOCH" "$SMOKE_ROOT" "$SMOKE_ROOT/etc" \
    "$SMOKE_ROOT/etc/pocket-release"
touch -h -d "@$SOURCE_DATE_EPOCH" "$SMOKE_ROOT/etc/release-link"
truncate -s 33554432 "$SMOKE_IMAGE"
truncate -s 0 "$SMOKE_BLKID_FILE"
chmod 0600 "$SMOKE_BLKID_FILE"
timeout --signal=TERM --kill-after=5s 30s env -i \
    MKE2FS_CONFIG="$MKE2FS_CONFIG" \
    BLKID_FILE="$SMOKE_BLKID_FILE" \
    E2FSPROGS_FAKE_TIME=$SOURCE_DATE_EPOCH \
    "$FIRST_RESULT/mke2fs" -q -F -t ext4 -b 4096 -I 256 -m 0 \
    -U 69562479-1350-4e52-a503-44d69e5d01c7 \
    -E lazy_itable_init=0,lazy_journal_init=0 \
    -d "$SMOKE_ROOT" "$SMOKE_IMAGE"
timeout --signal=TERM --kill-after=5s 30s env -i \
    E2FSCK_CONFIG="$E2FSCK_CONFIG" \
    BLKID_FILE="$SMOKE_BLKID_FILE" \
    E2FSPROGS_FAKE_TIME=$SOURCE_DATE_EPOCH \
    "$FIRST_RESULT/e2fsck" -fn "$SMOKE_IMAGE"

MKE2FS_SHA256=$(sha256sum "$FIRST_RESULT/mke2fs" | awk '{print $1}')
E2FSCK_SHA256=$(sha256sum "$FIRST_RESULT/e2fsck" | awk '{print $1}')
printf 'mke2fs_sha256=%s\n' "$MKE2FS_SHA256"
printf 'e2fsck_sha256=%s\n' "$E2FSCK_SHA256"
[[ "$MKE2FS_SHA256" == "$(lock_value development_artifacts mke2fs_sha256)" ]] || \
    die "mke2fs SHA-256 does not match sources.lock.toml"
[[ "$E2FSCK_SHA256" == "$(lock_value development_artifacts e2fsck_sha256)" ]] || \
    die "e2fsck SHA-256 does not match sources.lock.toml"

PUBLISH_DIR="$WORK_ROOT/publish"
mkdir -p -- "$PUBLISH_DIR"
install -m 0755 "$FIRST_RESULT/mke2fs" "$PUBLISH_DIR/mke2fs"
install -m 0755 "$FIRST_RESULT/e2fsck" "$PUBLISH_DIR/e2fsck"
(
    cd -- "$PUBLISH_DIR" || exit 1
    sha256sum mke2fs e2fsck > SHA256SUMS
)
printf '%s\n' \
    'schema=pocket-static-e2fsprogs-v1' \
    "version=$VERSION" \
    "source_sha256=$EXPECTED_SOURCE_SHA256" \
    "signed_checksums_sha256=$EXPECTED_CHECKSUMS_SHA256" \
    "checksum_signer_fingerprint=$EXPECTED_SIGNER_FINGERPRINT" \
    "source_date_epoch=$SOURCE_DATE_EPOCH" \
    'target=x86_64-pc-linux-gnu' \
    'linkage=static' > "$PUBLISH_DIR/BUILD-METADATA"
touch -d "@$SOURCE_DATE_EPOCH" "$PUBLISH_DIR/mke2fs" "$PUBLISH_DIR/e2fsck" \
    "$PUBLISH_DIR/SHA256SUMS" "$PUBLISH_DIR/BUILD-METADATA"

mkdir -p -- "$(dirname -- "$OUTPUT_DIR")"
if [[ -e "$OUTPUT_DIR" || -L "$OUTPUT_DIR" ]]; then
    [[ -d "$OUTPUT_DIR" && ! -L "$OUTPUT_DIR" ]] || \
        die "refusing to replace non-directory output: $OUTPUT_DIR"
    [[ "$OUTPUT_DIR" == "$BUILD_ROOT/tools/$SOURCE_NAME" ]] || \
        die "refusing to clear unexpected output directory: $OUTPUT_DIR"
    find "$OUTPUT_DIR" -depth -delete
fi
mv -- "$PUBLISH_DIR" "$OUTPUT_DIR"
printf '%s\n' "$OUTPUT_DIR"
