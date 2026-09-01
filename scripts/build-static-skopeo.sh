#!/usr/bin/env bash

source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"

ROOT=$(project_root)
BUILD_ROOT=${POCKET_BUILD_ROOT:-"$ROOT/build"}
LOCK_FILE="$ROOT/config/sources.lock.toml"

VERSION=1.23.0
MODULE=go.podman.io/skopeo
TAG=v1.23.0
REPOSITORY_URL=https://github.com/containers/skopeo.git
TAG_OBJECT=0215995053b78878f5491980d44311c2eb4bd3ed
COMMIT=9645b282ca2d8792235db5a3e142ea9ae2f0c63b
TREE=5f7437a8b441c632b2f42a780f4481699e3f0280
SOURCE_DATE_EPOCH=1779821906
MODULE_SUM='h1:JnzawQosV0o2A2fwMG16YkffZvI0AU1Kp3wepuv9Eww='
MODULE_MOD_SUM='h1:1FUlKYS8NwKOUGLBKlxOubc5ZM9oyO9VKwt0P1FqtDw='
MODULE_ZIP_SHA256=8e21e25ea5f2df9fef991388bec50c300af41700244c342f9a7110402310801a
MODULE_MOD_SHA256=125f484e43e6333124082733656e136fafda3db60a20eae577be2d1d5230d058

GO_VERSION=1.25.6
GO_ARCHIVE=go1.25.6.linux-amd64.tar.gz
GO_URL="https://go.dev/dl/$GO_ARCHIVE"
GO_SHA256=f022b6aad78e362bcba9b0b94d09ad58c5a70c6ba3b7582905fababf5fe0181a
GO_SIZE=59768880

CA_REVISION=2026-08-13
CA_CERTIFICATE_COUNT=121
CA_NAME="cacert-$CA_REVISION.pem"
CA_CHECKSUM_NAME="$CA_NAME.sha256"
CA_URL="https://curl.se/ca/$CA_NAME"
CA_CHECKSUM_URL="https://curl.se/ca/$CA_CHECKSUM_NAME"
CA_SHA256=f66dff1bdf8f96060b8177976f8b7d9254bc89bc4db933d769f7384d28480bc9
CA_CHECKSUM_SHA256=2d55c7d3d1f3ed1989e4ad5f4e8124df16eb42ae8a88715385dd4348b2efc986
CA_SIZE=188900
CA_CHECKSUM_SIZE=88

BUILD_TAGS='exclude_graphdriver_btrfs containers_image_openpgp'
EXPECTED_SKOPEO_SHA256=c602dfb345db1ea8e9e709857fc5e17d936af64e676964c1a873b0b849885780
DOWNLOAD_DIR="$BUILD_ROOT/downloads"
GO_TARBALL="$DOWNLOAD_DIR/$GO_ARCHIVE"
CA_BUNDLE="$DOWNLOAD_DIR/$CA_NAME"
CA_CHECKSUM="$DOWNLOAD_DIR/$CA_CHECKSUM_NAME"
CACHE_ROOT="$BUILD_ROOT/cache/skopeo-$VERSION-go$GO_VERSION"
MODULE_CACHE="$CACHE_ROOT/mod"
OUTPUT_DIR="$BUILD_ROOT/tools/skopeo-$VERSION"

for command in awk basename bwrap chmod cmp cp curl dirname file find getconf \
    git grep install jq mkdir mktemp mv openssl readelf realpath sha256sum stat strings \
    tar timeout touch uname wc; do
    require_command "$command"
done
safe_managed_root "$BUILD_ROOT"
safe_managed_root "$CACHE_ROOT"
safe_managed_root "$OUTPUT_DIR"
[[ -f "$LOCK_FILE" ]] || die "source lock file not found: $LOCK_FILE"
[[ $(uname -m) == x86_64 ]] || die "the release Skopeo build requires an x86_64 host"
umask 022

ONLINE_CPU_COUNT=$(getconf _NPROCESSORS_ONLN)
[[ "$ONLINE_CPU_COUNT" =~ ^[1-9][0-9]*$ ]] || \
    die "getconf returned an invalid online CPU count"
if ((ONLINE_CPU_COUNT > 16)); then
    ONLINE_CPU_COUNT=16
fi
JOBS=${POCKET_BUILD_JOBS:-$ONLINE_CPU_COUNT}
[[ "$JOBS" =~ ^[1-9][0-9]*$ ]] || die "POCKET_BUILD_JOBS must be a positive integer"
((JOBS <= 64)) || die "POCKET_BUILD_JOBS exceeds the bounded maximum of 64"

mkdir -p -- "$BUILD_ROOT" "$DOWNLOAD_DIR" "$CACHE_ROOT" "$MODULE_CACHE"
WORK_ROOT=$(mktemp -d "$BUILD_ROOT/.skopeo-$VERSION.build.XXXXXX")
[[ "$WORK_ROOT" == "$BUILD_ROOT/.skopeo-$VERSION.build."* ]] || \
    die "unexpected Skopeo work directory: $WORK_ROOT"

cleanup() {
    if [[ -n ${WORK_ROOT:-} && -d "$WORK_ROOT" && \
          "$WORK_ROOT" == "$BUILD_ROOT/.skopeo-$VERSION.build."* ]]; then
        # Go module-cache content is deliberately read-only. The work tree may
        # nevertheless contain copied cache files after a failed invocation.
        chmod -R u+w "$WORK_ROOT" 2>/dev/null || true
        find "$WORK_ROOT" -depth -delete
    fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

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

assert_lock() {
    local section=$1
    local key=$2
    local expected=$3
    local description=$4

    [[ $(lock_value "$section" "$key") == "$expected" ]] || \
        die "$description does not match sources.lock.toml"
}

assert_lock skopeo release "$VERSION" "Skopeo release"
assert_lock skopeo module "$MODULE" "Skopeo module"
assert_lock skopeo tag "$TAG" "Skopeo tag"
assert_lock skopeo repository_url "$REPOSITORY_URL" "Skopeo repository URL"
assert_lock skopeo tag_object "$TAG_OBJECT" "Skopeo tag object"
assert_lock skopeo commit "$COMMIT" "Skopeo commit"
assert_lock skopeo tree "$TREE" "Skopeo tree"
assert_lock skopeo module_sum "$MODULE_SUM" "Skopeo module sum"
assert_lock skopeo module_mod_sum "$MODULE_MOD_SUM" "Skopeo go.mod sum"
assert_lock skopeo module_zip_sha256 "$MODULE_ZIP_SHA256" "Skopeo module zip SHA-256"
assert_lock skopeo module_mod_sha256 "$MODULE_MOD_SHA256" "Skopeo go.mod SHA-256"
assert_lock skopeo source_date_epoch "$SOURCE_DATE_EPOCH" "Skopeo SOURCE_DATE_EPOCH"
assert_lock go_toolchain release "$GO_VERSION" "Go toolchain release"
assert_lock go_toolchain archive_url "$GO_URL" "Go toolchain URL"
assert_lock go_toolchain archive_sha256 "$GO_SHA256" "Go toolchain SHA-256"
assert_lock go_toolchain archive_size "$GO_SIZE" "Go toolchain archive size"
assert_lock registry_ca revision "$CA_REVISION" "registry CA revision"
assert_lock registry_ca bundle_url "$CA_URL" "registry CA bundle URL"
assert_lock registry_ca checksum_url "$CA_CHECKSUM_URL" "registry CA checksum URL"
assert_lock registry_ca bundle_sha256 "$CA_SHA256" "registry CA bundle SHA-256"
assert_lock registry_ca checksum_sha256 "$CA_CHECKSUM_SHA256" \
    "registry CA checksum-file SHA-256"
assert_lock registry_ca bundle_size "$CA_SIZE" "registry CA bundle size"
assert_lock registry_ca checksum_size "$CA_CHECKSUM_SIZE" "registry CA checksum-file size"
assert_lock registry_ca certificate_count "$CA_CERTIFICATE_COUNT" \
    "registry CA certificate count"
assert_lock development_tools go "$GO_VERSION" "development Go version"
assert_lock development_tools skopeo "$VERSION" "development Skopeo version"
assert_lock development_artifacts skopeo_sha256 "$EXPECTED_SKOPEO_SHA256" \
    "Skopeo artifact SHA-256"

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

download "$GO_URL" "$GO_TARBALL"
download "$CA_URL" "$CA_BUNDLE"
download "$CA_CHECKSUM_URL" "$CA_CHECKSUM"
[[ $(sha256sum "$GO_TARBALL" | awk '{print $1}') == "$GO_SHA256" ]] || \
    die "Go toolchain archive SHA-256 mismatch"
[[ $(stat -c %s "$GO_TARBALL") == "$GO_SIZE" ]] || \
    die "Go toolchain archive size mismatch"
[[ $(sha256sum "$CA_BUNDLE" | awk '{print $1}') == "$CA_SHA256" ]] || \
    die "registry CA bundle SHA-256 mismatch"
[[ $(sha256sum "$CA_CHECKSUM" | awk '{print $1}') == "$CA_CHECKSUM_SHA256" ]] || \
    die "registry CA checksum-file SHA-256 mismatch"
[[ $(stat -c %s "$CA_BUNDLE") == "$CA_SIZE" ]] || die "registry CA bundle size mismatch"
[[ $(stat -c %s "$CA_CHECKSUM") == "$CA_CHECKSUM_SIZE" ]] || \
    die "registry CA checksum-file size mismatch"
EXPECTED_CA_CHECKSUM_LINE="$CA_SHA256  $CA_NAME"
[[ $(wc -l < "$CA_CHECKSUM") == 1 && \
   $(< "$CA_CHECKSUM") == "$EXPECTED_CA_CHECKSUM_LINE" ]] || \
    die "registry CA checksum file does not contain the exact locked checksum line"
BEGIN_CERTIFICATE_COUNT=$(grep -c '^-----BEGIN CERTIFICATE-----$' "$CA_BUNDLE")
END_CERTIFICATE_COUNT=$(grep -c '^-----END CERTIFICATE-----$' "$CA_BUNDLE")
[[ "$BEGIN_CERTIFICATE_COUNT" == "$CA_CERTIFICATE_COUNT" && \
   "$END_CERTIFICATE_COUNT" == "$CA_CERTIFICATE_COUNT" ]] || \
    die "registry CA bundle does not contain exactly $CA_CERTIFICATE_COUNT certificates"
grep -Fq 'Certificate data from Mozilla as of: Thu Aug 13 03:12:01 2026 GMT' \
    "$CA_BUNDLE" || die "registry CA bundle has an unexpected Mozilla source date"

CA_CERTIFICATE_DIR="$WORK_ROOT/registry-ca-certificates"
mkdir -p -- "$CA_CERTIFICATE_DIR"
awk -v destination="$CA_CERTIFICATE_DIR" -v expected="$CA_CERTIFICATE_COUNT" '
    /^-----BEGIN CERTIFICATE-----$/ {
        number++
        output = sprintf("%s/cert-%03d.pem", destination, number)
    }
    output != "" { print > output }
    /^-----END CERTIFICATE-----$/ { close(output); output = "" }
    END { if (number != expected || output != "") exit 42 }
' "$CA_BUNDLE" || die "registry CA bundle has malformed PEM boundaries"
PARSED_CERTIFICATE_COUNT=0
for certificate in "$CA_CERTIFICATE_DIR"/*.pem; do
    openssl x509 -in "$certificate" -noout || die "registry CA certificate is not valid X.509"
    openssl verify -no_check_time -check_ss_sig -no-CAfile -no-CApath \
        -trusted "$certificate" "$certificate" >/dev/null || \
        die "registry CA certificate has an invalid self-signature"
    PARSED_CERTIFICATE_COUNT=$((PARSED_CERTIFICATE_COUNT + 1))
done
[[ "$PARSED_CERTIFICATE_COUNT" == "$CA_CERTIFICATE_COUNT" ]] || \
    die "registry CA PEM parser did not validate every certificate"
if ! tar -tzf "$GO_TARBALL" | awk '
    $0 ~ /^\// || $0 ~ /(^|\/)\.\.(\/|$)/ { exit 1 }
    $0 != "go" && index($0, "go/") != 1 { exit 1 }
'; then
    die "Go toolchain archive contains an unsafe or unexpected path"
fi

TOOLCHAIN_ROOT="$WORK_ROOT/toolchain"
mkdir -p -- "$TOOLCHAIN_ROOT"
tar -C "$TOOLCHAIN_ROOT" --no-same-owner --no-same-permissions -xzf "$GO_TARBALL"
GO="$TOOLCHAIN_ROOT/go/bin/go"
[[ -x "$GO" ]] || die "Go executable is missing from the toolchain archive"
[[ $(env -i PATH="$TOOLCHAIN_ROOT/go/bin:/usr/bin:/bin" HOME="$WORK_ROOT" \
    GOENV=off GOTOOLCHAIN=local "$GO" version) == \
    "go version go$GO_VERSION linux/amd64" ]] || die "unexpected Go toolchain version"

# Bind the source version to the canonical upstream Git object graph. Skopeo's
# v1.23.0 annotated tag and release commit are not signed; the authenticated
# source-content check below therefore comes from the Go checksum database.
TAG_REPOSITORY="$WORK_ROOT/tag-repository"
git -C "$WORK_ROOT" init -q tag-repository
git -C "$TAG_REPOSITORY" remote add origin "$REPOSITORY_URL"
timeout --signal=TERM --kill-after=15s 180s \
    git -C "$TAG_REPOSITORY" -c protocol.version=2 fetch --quiet --no-tags --depth=1 \
    origin "refs/tags/$TAG:refs/tags/$TAG"
[[ $(git -C "$TAG_REPOSITORY" cat-file -t "refs/tags/$TAG") == tag ]] || \
    die "Skopeo release ref is not the expected annotated tag"
[[ $(git -C "$TAG_REPOSITORY" rev-parse "refs/tags/$TAG") == "$TAG_OBJECT" ]] || \
    die "Skopeo tag object mismatch"
[[ $(git -C "$TAG_REPOSITORY" rev-parse "refs/tags/$TAG^{commit}") == "$COMMIT" ]] || \
    die "Skopeo release commit mismatch"
[[ $(git -C "$TAG_REPOSITORY" rev-parse "refs/tags/$TAG^{tree}") == "$TREE" ]] || \
    die "Skopeo release tree mismatch"
if git -C "$TAG_REPOSITORY" cat-file -p "refs/tags/$TAG" | \
    grep -q '^-----BEGIN PGP SIGNATURE-----$'; then
    die "the locked unsigned Skopeo tag unexpectedly contains a PGP signature"
fi

GO_HOME="$WORK_ROOT/home"
GO_TMP="$WORK_ROOT/go-tmp"
DOWNLOAD_CACHE="$WORK_ROOT/download-build-cache"
mkdir -p -- "$GO_HOME" "$GO_TMP" "$DOWNLOAD_CACHE"
MODULE_JSON="$WORK_ROOT/module.json"

# `go mod download` verifies the module h1 against sum.golang.org using the
# checksum-database public key embedded by the official Go toolchain. The
# module proxy also reports the canonical VCS origin and release commit.
timeout --signal=TERM --kill-after=30s 600s env -i \
    PATH="$TOOLCHAIN_ROOT/go/bin:/usr/bin:/bin" \
    HOME="$GO_HOME" TMPDIR="$GO_TMP" LC_ALL=C LANG=C TZ=UTC \
    SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
    GOPATH="$CACHE_ROOT/gopath" GOMODCACHE="$MODULE_CACHE" GOCACHE="$DOWNLOAD_CACHE" \
    GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org \
    GOPRIVATE= GONOPROXY= GONOSUMDB= GOENV=off GOTOOLCHAIN=local \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 \
    "$GO" mod download -json "$MODULE@$TAG" > "$MODULE_JSON"

jq -e '.Error == null' "$MODULE_JSON" >/dev/null || \
    die "the Go toolchain reported an error acquiring Skopeo"
[[ $(jq -r '.Path' "$MODULE_JSON") == "$MODULE" ]] || die "unexpected Skopeo module path"
[[ $(jq -r '.Version' "$MODULE_JSON") == "$TAG" ]] || die "unexpected Skopeo module version"
[[ $(jq -r '.Sum' "$MODULE_JSON") == "$MODULE_SUM" ]] || \
    die "Skopeo checksum-database module sum mismatch"
[[ $(jq -r '.GoModSum' "$MODULE_JSON") == "$MODULE_MOD_SUM" ]] || \
    die "Skopeo checksum-database go.mod sum mismatch"
[[ $(jq -r '.Origin.VCS' "$MODULE_JSON") == git ]] || die "unexpected Skopeo source VCS"
[[ $(jq -r '.Origin.URL' "$MODULE_JSON") == "$REPOSITORY_URL" ]] || \
    die "unexpected Skopeo source repository"
[[ $(jq -r '.Origin.Hash' "$MODULE_JSON") == "$COMMIT" ]] || \
    die "unexpected Skopeo module origin commit"
[[ $(jq -r '.Origin.Ref' "$MODULE_JSON") == "refs/tags/$TAG" ]] || \
    die "unexpected Skopeo module origin ref"

SOURCE_DIR=$(jq -r '.Dir' "$MODULE_JSON")
MODULE_ZIP=$(jq -r '.Zip' "$MODULE_JSON")
[[ -d "$SOURCE_DIR" && -f "$MODULE_ZIP" ]] || die "Go did not publish the Skopeo source"
SOURCE_DIR=$(realpath -e -- "$SOURCE_DIR")
MODULE_ZIP=$(realpath -e -- "$MODULE_ZIP")
MODULE_CACHE_REAL=$(realpath -e -- "$MODULE_CACHE")
[[ "$SOURCE_DIR" == "$MODULE_CACHE_REAL/"* ]] || die "Skopeo source escaped the module cache"
[[ "$MODULE_ZIP" == "$MODULE_CACHE_REAL/"* ]] || die "Skopeo zip escaped the module cache"
[[ $(sha256sum "$MODULE_ZIP" | awk '{print $1}') == "$MODULE_ZIP_SHA256" ]] || \
    die "Skopeo module zip SHA-256 mismatch"
[[ $(sha256sum "$SOURCE_DIR/go.mod" | awk '{print $1}') == "$MODULE_MOD_SHA256" ]] || \
    die "Skopeo go.mod SHA-256 mismatch"
grep -Fxq "go $GO_VERSION" "$SOURCE_DIR/go.mod" || \
    die "Skopeo no longer requires the locked Go toolchain"

DEPENDENCY_LIST="$WORK_ROOT/dependency-list"
timeout --signal=TERM --kill-after=30s 900s env -i \
    PATH="$TOOLCHAIN_ROOT/go/bin:/usr/bin:/bin" \
    HOME="$GO_HOME" TMPDIR="$GO_TMP" LC_ALL=C LANG=C TZ=UTC \
    SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
    GOPATH="$CACHE_ROOT/gopath" GOMODCACHE="$MODULE_CACHE" GOCACHE="$DOWNLOAD_CACHE" \
    GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org \
    GOPRIVATE= GONOPROXY= GONOSUMDB= GOENV=off GOTOOLCHAIN=local \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 \
    "$GO" -C "$SOURCE_DIR" list -mod=readonly -deps -tags "$BUILD_TAGS" \
    ./cmd/skopeo > "$DEPENDENCY_LIST"
grep -Fxq go.podman.io/skopeo/cmd/skopeo "$DEPENDENCY_LIST" || \
    die "Skopeo dependency closure does not contain its main package"

# `go mod verify` checks every module in the build list, which is a superset of
# the tag-filtered dependency closure resolved above. Acquire the remainder
# through the same authenticated proxy/checksum-database pair first, so a clean
# build root does not fail the offline verification below.
timeout --signal=TERM --kill-after=30s 900s env -i \
    PATH="$TOOLCHAIN_ROOT/go/bin:/usr/bin:/bin" \
    HOME="$GO_HOME" TMPDIR="$GO_TMP" LC_ALL=C LANG=C TZ=UTC \
    SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
    GOPATH="$CACHE_ROOT/gopath" GOMODCACHE="$MODULE_CACHE" GOCACHE="$DOWNLOAD_CACHE" \
    GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org \
    GOPRIVATE= GONOPROXY= GONOSUMDB= GOENV=off GOTOOLCHAIN=local \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 \
    "$GO" -C "$SOURCE_DIR" mod download

timeout --signal=TERM --kill-after=30s 600s env -i \
    PATH="$TOOLCHAIN_ROOT/go/bin:/usr/bin:/bin" \
    HOME="$GO_HOME" TMPDIR="$GO_TMP" LC_ALL=C LANG=C TZ=UTC \
    GOPATH="$CACHE_ROOT/gopath" GOMODCACHE="$MODULE_CACHE" GOCACHE="$DOWNLOAD_CACHE" \
    GOPROXY=off GOSUMDB=sum.golang.org GOENV=off GOTOOLCHAIN=local \
    "$GO" -C "$SOURCE_DIR" mod verify

build_once() {
    local label=$1
    local instance="$WORK_ROOT/$label"
    local output="$instance/skopeo"

    mkdir -p -- "$instance/home" "$instance/tmp" "$instance/gocache"
    timeout --signal=TERM --kill-after=30s 1200s env -i \
        PATH="$TOOLCHAIN_ROOT/go/bin:/usr/bin:/bin" \
        HOME="$instance/home" TMPDIR="$instance/tmp" LC_ALL=C LANG=C TZ=UTC \
        SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
        GOPATH="$CACHE_ROOT/gopath" GOMODCACHE="$MODULE_CACHE" GOCACHE="$instance/gocache" \
        GOPROXY=off GOSUMDB=sum.golang.org \
        GOPRIVATE= GONOPROXY= GONOSUMDB= GOENV=off GOTOOLCHAIN=local \
        GOFLAGS= GOEXPERIMENT= CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 \
        "$GO" -C "$SOURCE_DIR" build -mod=readonly -trimpath -buildvcs=false \
        -p "$JOBS" -tags "$BUILD_TAGS" -ldflags '-buildid= -s -w' \
        -o "$output" ./cmd/skopeo
}

build_once first
build_once second
FIRST_BINARY="$WORK_ROOT/first/skopeo"
SECOND_BINARY="$WORK_ROOT/second/skopeo"
cmp --silent "$FIRST_BINARY" "$SECOND_BINARY" || \
    die "independent Skopeo builds are not byte-for-byte reproducible"

verify_static_binary() {
    local binary=$1
    local description

    description=$(file "$binary")
    [[ "$description" == *"ELF 64-bit LSB executable, x86-64"* ]] || \
        die "Skopeo is not an x86-64 ELF executable"
    [[ "$description" == *"statically linked"* ]] || die "Skopeo is not statically linked"
    if readelf -lW "$binary" | grep -Eq \
        '(^|[[:space:]])(INTERP|DYNAMIC)([[:space:]]|$)'; then
        die "Skopeo contains a dynamic-loader program header"
    fi
    if readelf -SW "$binary" | grep -Eq '(^|[[:space:]])\.dynamic([[:space:]]|$)'; then
        die "Skopeo contains a dynamic section"
    fi
    if readelf -dW "$binary" 2>&1 | grep -q '(NEEDED)'; then
        die "Skopeo declares a dynamic-library dependency"
    fi
    if strings "$binary" | grep -Fq "$WORK_ROOT"; then
        die "Skopeo embeds its temporary build path"
    fi
    if strings "$binary" | grep -Fq "$MODULE_CACHE_REAL"; then
        die "Skopeo embeds its module-cache path"
    fi
}

verify_static_binary "$FIRST_BINARY"
[[ $("$FIRST_BINARY" --version) == "skopeo version $VERSION" ]] || \
    die "unexpected Skopeo version output"
GO_BUILD_INFO=$("$GO" version -m "$FIRST_BINARY")
grep -Fq $'\tCGO_ENABLED=0' <<< "$GO_BUILD_INFO" || die "Skopeo build info does not disable cgo"
grep -Fq $'\tGOARCH=amd64' <<< "$GO_BUILD_INFO" || die "unexpected Skopeo GOARCH"
grep -Fq $'\tGOOS=linux' <<< "$GO_BUILD_INFO" || die "unexpected Skopeo GOOS"
grep -Fq $'\tGOAMD64=v1' <<< "$GO_BUILD_INFO" || die "unexpected Skopeo GOAMD64 baseline"
grep -Fq $'\t-tags=exclude_graphdriver_btrfs,containers_image_openpgp' \
    <<< "$GO_BUILD_INFO" || die "unexpected Skopeo build tags"

# Construct the smallest useful OCI image locally, then copy it to a second OCI
# layout while bubblewrap has removed the network namespace. This exercises the
# real transport/copy path without contacting a registry.
SMOKE_ROOT="$WORK_ROOT/smoke"
SMOKE_SOURCE="$SMOKE_ROOT/source"
SMOKE_DESTINATION="$SMOKE_ROOT/destination"
SMOKE_HOME="$SMOKE_ROOT/home"
SMOKE_RUNTIME="$SMOKE_ROOT/runtime"
SMOKE_TMP="$SMOKE_ROOT/tmp"
POLICY="$SMOKE_ROOT/policy.json"
mkdir -p -- "$SMOKE_SOURCE/blobs/sha256" "$SMOKE_HOME" "$SMOKE_RUNTIME" "$SMOKE_TMP"
chmod 0700 "$SMOKE_HOME" "$SMOKE_RUNTIME" "$SMOKE_TMP"
printf '%s' '{"default":[{"type":"insecureAcceptAnything"}]}' > "$POLICY"
printf '%s' '{"imageLayoutVersion":"1.0.0"}' > "$SMOKE_SOURCE/oci-layout"

CONFIG_FILE="$SMOKE_ROOT/config.json"
printf '%s' \
    '{"architecture":"amd64","config":{"Cmd":["/bin/true"]},"created":"1970-01-01T00:00:00Z","os":"linux","rootfs":{"diff_ids":[],"type":"layers"}}' \
    > "$CONFIG_FILE"
CONFIG_DIGEST=$(sha256sum "$CONFIG_FILE" | awk '{print $1}')
CONFIG_SIZE=$(wc -c < "$CONFIG_FILE")
install -m 0644 "$CONFIG_FILE" "$SMOKE_SOURCE/blobs/sha256/$CONFIG_DIGEST"

MANIFEST_FILE="$SMOKE_ROOT/manifest.json"
printf '%s' \
    "{\"schemaVersion\":2,\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\",\"config\":{\"mediaType\":\"application/vnd.oci.image.config.v1+json\",\"digest\":\"sha256:$CONFIG_DIGEST\",\"size\":$CONFIG_SIZE},\"layers\":[]}" \
    > "$MANIFEST_FILE"
MANIFEST_DIGEST=$(sha256sum "$MANIFEST_FILE" | awk '{print $1}')
MANIFEST_SIZE=$(wc -c < "$MANIFEST_FILE")
install -m 0644 "$MANIFEST_FILE" "$SMOKE_SOURCE/blobs/sha256/$MANIFEST_DIGEST"
printf '%s' \
    "{\"schemaVersion\":2,\"mediaType\":\"application/vnd.oci.image.index.v1+json\",\"manifests\":[{\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\",\"digest\":\"sha256:$MANIFEST_DIGEST\",\"size\":$MANIFEST_SIZE,\"annotations\":{\"org.opencontainers.image.ref.name\":\"source\"}}]}" \
    > "$SMOKE_SOURCE/index.json"

run_without_network() {
    timeout --signal=TERM --kill-after=5s 30s env -i PATH=/usr/bin:/bin LC_ALL=C LANG=C TZ=UTC \
        bwrap --unshare-net --die-with-parent --ro-bind / / --dev-bind /dev /dev \
        --proc /proc --tmpfs /tmp --bind "$SMOKE_ROOT" "$SMOKE_ROOT" --clearenv \
        --setenv PATH /usr/bin:/bin --setenv HOME "$SMOKE_HOME" \
        --setenv XDG_RUNTIME_DIR "$SMOKE_RUNTIME" --setenv TMPDIR "$SMOKE_TMP" \
        --setenv LC_ALL C --setenv LANG C --setenv TZ UTC -- "$@"
}

run_without_network "$FIRST_BINARY" --policy "$POLICY" --tmpdir "$SMOKE_TMP" copy \
    --preserve-digests -- "oci:$SMOKE_SOURCE:source" "oci:$SMOKE_DESTINATION:copy"
[[ -f "$SMOKE_DESTINATION/index.json" && -f "$SMOKE_DESTINATION/oci-layout" ]] || \
    die "Skopeo did not create the destination OCI layout"
DESTINATION_DIGEST=$(jq -er '.manifests[] | select(.annotations["org.opencontainers.image.ref.name"] == "copy") | .digest' \
    "$SMOKE_DESTINATION/index.json")
[[ "$DESTINATION_DIGEST" == "sha256:$MANIFEST_DIGEST" ]] || \
    die "Skopeo local copy did not preserve the manifest digest"
cmp --silent "$MANIFEST_FILE" "$SMOKE_DESTINATION/blobs/sha256/$MANIFEST_DIGEST" || \
    die "Skopeo local copy changed the manifest bytes"
run_without_network "$FIRST_BINARY" --policy "$POLICY" --tmpdir "$SMOKE_TMP" \
    inspect --raw "oci:$SMOKE_DESTINATION:copy" > "$SMOKE_ROOT/inspected-manifest.json"
cmp --silent "$MANIFEST_FILE" "$SMOKE_ROOT/inspected-manifest.json" || \
    die "Skopeo could not inspect the copied OCI manifest"

# Also ensure that the docker transport is registered. The isolated network
# namespace makes a successful registry connection impossible by construction.
DOCKER_PROBE_LOG="$SMOKE_ROOT/docker-probe.log"
set +e
run_without_network "$FIRST_BINARY" --policy "$POLICY" --tmpdir "$SMOKE_TMP" \
    inspect --tls-verify=false docker://127.0.0.1:9/pocket/probe:latest \
    > "$DOCKER_PROBE_LOG" 2>&1
DOCKER_PROBE_STATUS=$?
set -e
[[ "$DOCKER_PROBE_STATUS" != 0 && "$DOCKER_PROBE_STATUS" != 124 && \
   "$DOCKER_PROBE_STATUS" != 137 ]] || die "docker transport isolation probe did not fail promptly"
if grep -Eqi 'unknown transport|invalid image name.*transport' "$DOCKER_PROBE_LOG"; then
    die "Skopeo was built without docker transport support"
fi

SKOPEO_SHA256=$(sha256sum "$FIRST_BINARY" | awk '{print $1}')
printf 'skopeo_sha256=%s\n' "$SKOPEO_SHA256"
[[ "$SKOPEO_SHA256" == "$EXPECTED_SKOPEO_SHA256" ]] || \
    die "Skopeo SHA-256 does not match sources.lock.toml"

PUBLISH_DIR="$WORK_ROOT/publish"
mkdir -p -- "$PUBLISH_DIR"
install -m 0755 "$FIRST_BINARY" "$PUBLISH_DIR/skopeo"
install -m 0644 "$CA_BUNDLE" "$PUBLISH_DIR/registry-ca.pem"
printf '%s  %s\n' "$SKOPEO_SHA256" skopeo > "$PUBLISH_DIR/SHA256SUMS"
printf '%s  %s\n' "$CA_SHA256" registry-ca.pem >> "$PUBLISH_DIR/SHA256SUMS"
printf '%s\n' \
    'schema=pocket-static-skopeo-v1' \
    "version=$VERSION" \
    "module=$MODULE" \
    "tag=$TAG" \
    "tag_object=$TAG_OBJECT" \
    "commit=$COMMIT" \
    "tree=$TREE" \
    'upstream_tag_signature=absent' \
    "module_sum=$MODULE_SUM" \
    "module_mod_sum=$MODULE_MOD_SUM" \
    "module_zip_sha256=$MODULE_ZIP_SHA256" \
    'module_authentication=sum.golang.org' \
    "go_version=$GO_VERSION" \
    "go_archive_sha256=$GO_SHA256" \
    "registry_ca_revision=$CA_REVISION" \
    "registry_ca_sha256=$CA_SHA256" \
    "registry_ca_source_checksum_sha256=$CA_CHECKSUM_SHA256" \
    "registry_ca_certificate_count=$CA_CERTIFICATE_COUNT" \
    "source_date_epoch=$SOURCE_DATE_EPOCH" \
    'target=linux/amd64/v1' \
    'cgo_enabled=0' \
    "build_tags=$BUILD_TAGS" \
    'linkage=static' \
    'docker_transport=enabled' > "$PUBLISH_DIR/BUILD-METADATA"
touch -d "@$SOURCE_DATE_EPOCH" "$PUBLISH_DIR/skopeo" "$PUBLISH_DIR/registry-ca.pem" \
    "$PUBLISH_DIR/SHA256SUMS" "$PUBLISH_DIR/BUILD-METADATA"

mkdir -p -- "$(dirname -- "$OUTPUT_DIR")"
if [[ -e "$OUTPUT_DIR" || -L "$OUTPUT_DIR" ]]; then
    [[ -d "$OUTPUT_DIR" && ! -L "$OUTPUT_DIR" ]] || \
        die "refusing to replace non-directory output: $OUTPUT_DIR"
    [[ "$OUTPUT_DIR" == "$BUILD_ROOT/tools/skopeo-$VERSION" ]] || \
        die "refusing to clear unexpected output directory: $OUTPUT_DIR"
    chmod -R u+w "$OUTPUT_DIR" 2>/dev/null || true
    find "$OUTPUT_DIR" -depth -delete
fi
mv -- "$PUBLISH_DIR" "$OUTPUT_DIR"
printf '%s\n' "$OUTPUT_DIR"
