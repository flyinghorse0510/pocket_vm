#!/usr/bin/env bash

source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"

ROOT=$(project_root)
BUILD_ROOT=${POCKET_BUILD_ROOT:-"$ROOT/build"}
VERSION=${1:-24.04}

case "$VERSION" in
    24.04) DIGEST=sha256:33ceb71981b602c1a7443a53469e4dba065f7503eab3078a2d7a57a2ab987517 ;;
    26.04) DIGEST=sha256:2260313b31c8c011cd2eebe728008efac1b3982be73eb71348ea2648d2c0e09b ;;
    *) die "supported Ubuntu fixture versions are 24.04 and 26.04" ;;
esac

require_command skopeo
safe_managed_root "$BUILD_ROOT"
OCI_PARENT="$BUILD_ROOT/oci"
OCI_DIR="$OCI_PARENT/ubuntu-$VERSION"

if [[ ! -f "$OCI_DIR/index.json" ]]; then
    mkdir -p -- "$OCI_PARENT"
    STAGING=$(mktemp -d "$OCI_PARENT/.ubuntu-$VERSION.XXXXXXXX")
    skopeo copy --override-os linux --override-arch amd64 --retry-times 3 \
        "docker://docker.io/library/ubuntu@$DIGEST" "oci:$STAGING:root"
    mv -- "$STAGING" "$OCI_DIR"
fi

[[ "$(jq -r '.schemaVersion' "$OCI_DIR/index.json")" == 2 ]] || die "invalid staged OCI index"
printf 'oci_layout=%s\n' "$OCI_DIR"

