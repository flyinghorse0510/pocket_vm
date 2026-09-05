#!/usr/bin/env bash

# shellcheck source=scripts/lib.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"
# shellcheck source=scripts/linux-source-lib.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/linux-source-lib.sh"

ROOT=$(project_root)
BUILD_ROOT=${POCKET_BUILD_ROOT:-"$ROOT/build"}
DOWNLOAD_DIR="$BUILD_ROOT/downloads"
GNUPG_HOME="$BUILD_ROOT/gnupg-linux-release"
TARBALL="$DOWNLOAD_DIR/$LINUX_ARCHIVE_NAME.tar.xz"
SIGNATURE="$DOWNLOAD_DIR/$LINUX_ARCHIVE_NAME.tar.sign"
DOWNLOAD_LOCK="$BUILD_ROOT/locks/linux-download.lock"

for command in awk curl find flock gpg sha256sum xz; do
    require_command "$command"
done
safe_managed_root "$BUILD_ROOT"
load_linux_source_locks "$ROOT"

mkdir -p -- "$DOWNLOAD_DIR" "$GNUPG_HOME" "$BUILD_ROOT/locks"
chmod 0700 "$GNUPG_HOME"
exec {DOWNLOAD_LOCK_FD}>"$DOWNLOAD_LOCK"
flock -x "$DOWNLOAD_LOCK_FD"

PART_FILES=()
cleanup_download_parts() {
    local part
    for part in "${PART_FILES[@]}"; do
        [[ $part == "$DOWNLOAD_DIR/.linux-download."* ]] || \
            die "refusing to clean unexpected download path: $part"
        if [[ -e $part || -L $part ]]; then
            unlink -- "$part"
        fi
    done
}
trap cleanup_download_parts EXIT

download_once() {
    local url=$1 output=$2
    [[ ! -L $output ]] || die "refusing symlinked Linux download: $output"
    if [[ -f $output ]]; then
        return
    fi
    [[ ! -e $output ]] || die "Linux download target is not a regular file: $output"
    local part
    part=$(mktemp "$DOWNLOAD_DIR/.linux-download.XXXXXX")
    PART_FILES+=("$part")
    curl --fail --location --proto '=https' --tlsv1.2 --retry 3 \
        --output "$part" "$url"
    chmod 0600 "$part"
    mv -- "$part" "$output"
}

download_once "$LINUX_TARBALL_URL" "$TARBALL"
download_once "$LINUX_SIGNATURE_URL" "$SIGNATURE"

actual_tarball_sha=$(sha256sum "$TARBALL" | awk '{print $1}')
[[ $actual_tarball_sha == "$LINUX_TARBALL_SHA256" ]] || die "Linux tarball SHA-256 mismatch"
actual_signature_sha=$(sha256sum "$SIGNATURE" | awk '{print $1}')
[[ $actual_signature_sha == "$LINUX_SIGNATURE_SHA256" ]] || die "Linux signature SHA-256 mismatch"
xz --test -- "$TARBALL"
actual_signed_tar_sha=$(xz -cd -- "$TARBALL" | sha256sum | awk '{print $1}')
[[ $actual_signed_tar_sha == "$LINUX_SIGNED_TAR_SHA256" ]] || \
    die "uncompressed signed Linux tar stream SHA-256 mismatch"

if ! gpg --no-options --batch --homedir "$GNUPG_HOME" \
    --list-keys "$LINUX_SIGNER_FINGERPRINT" >/dev/null 2>&1; then
    # gpg learned Web Key Directory lookups in 2.1.12; an older one rejects the
    # mechanism list outright. Fetch the signer's WKD entry directly in that
    # case -- the same URL and the same bytes gpg would have retrieved. The
    # retrieval path is not trusted either way: the fingerprint check below
    # accepts only the locked key, and the signature must then produce exactly
    # one VALIDSIG from it.
    if ! gpg --no-options --batch --homedir "$GNUPG_HOME" --auto-key-locate clear,wkd \
        --locate-keys "$LINUX_SIGNER_EMAIL" >/dev/null 2>&1; then
        key_file=$(mktemp "$DOWNLOAD_DIR/.linux-download.XXXXXX")
        PART_FILES+=("$key_file")
        curl --fail --location --proto '=https' --tlsv1.2 --retry 3 \
            --output "$key_file" "$LINUX_SIGNER_KEY_URL"
        gpg --no-options --batch --homedir "$GNUPG_HOME" --import "$key_file" >/dev/null 2>&1
    fi
fi
actual_fingerprint=$(
    gpg --no-options --batch --homedir "$GNUPG_HOME" --with-colons \
        --fingerprint "$LINUX_SIGNER_FINGERPRINT" |
        awk -F: '$1 == "fpr" { print $10; exit }'
)
[[ $actual_fingerprint == "$LINUX_SIGNER_FINGERPRINT" ]] || \
    die "unexpected Linux release signer fingerprint: $actual_fingerprint"

status_file=$(mktemp "$DOWNLOAD_DIR/.linux-download.XXXXXX")
PART_FILES+=("$status_file")
# kernel.org signs the exact uncompressed .tar stream, not the .tar.xz bytes.
xz -cd -- "$TARBALL" | gpg --no-options --batch --homedir "$GNUPG_HOME" \
    --status-fd=3 --verify "$SIGNATURE" - 3>"$status_file"
valid_signature_count=$(
    awk -v fingerprint="$LINUX_SIGNER_FINGERPRINT" \
        '$1 == "[GNUPG:]" && $2 == "VALIDSIG" && $3 == fingerprint { count++ }
         END { print count + 0 }' "$status_file"
)
[[ $valid_signature_count -eq 1 ]] || \
    die "Linux signature did not produce exactly one VALIDSIG from the locked fingerprint"

printf '%s\n' "$TARBALL"
