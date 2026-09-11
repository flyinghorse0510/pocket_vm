#!/usr/bin/env bash

# Build a statically linked slirp4netns from pinned source.
#
# This is what gives a guest network access without any host privilege: UML's
# vector driver connects to an AF_UNIX socket through its bess transport, and
# slirp4netns serves that socket and performs the NAT in userspace. No TUN
# device, no CAP_NET_ADMIN, no host configuration.
#
# It is linked statically because a sealed profile artifact may not depend on
# the host's libraries. glib is libslirp's own mandatory dependency, and glib
# in turn requires pcre2, libffi and zlib, so all five are built here rather
# than taken from the host.

source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"

ROOT=$(project_root)
BUILD_ROOT=${POCKET_BUILD_ROOT:-"$ROOT/build"}
LOCK_FILE="$ROOT/config/sources.lock.toml"
SOURCE_DATE_EPOCH=$(pocket_source_date_epoch)

ZLIB_VERSION=1.3.1
LIBFFI_VERSION=3.5.2
PCRE2_VERSION=10.47
# The newest glib whose meson floor the oldest supported distribution still
# clears: 2.78 wants meson 0.60, and Ubuntu 22.04 packages 0.61.2. Every later
# series raises it -- 2.80 to 1.2.0, 2.84 to 1.4.0 -- which would put the build
# out of reach of both current LTS releases. libslirp declares no glib version
# constraint at all, so nothing here needs a newer one.
GLIB_VERSION=2.78.6
MESON_MINIMUM=0.60.0
LIBSLIRP_VERSION=4.9.4
SLIRP4NETNS_VERSION=1.3.5
SLIRP4NETNS_COMMIT=7132ff3ba66cf0eebd8c9a83b9f23838bc84c518

DOWNLOAD_DIR="$BUILD_ROOT/downloads"
OUTPUT_DIR="$BUILD_ROOT/tools/slirp4netns-$SLIRP4NETNS_VERSION"

for command in autoreconf awk basename chmod cmp curl cut file find gcc getconf grep \
    head make meson mkdir mktemp mv ninja pkg-config readelf sha256sum sort tail tar \
    touch; do
    require_command "$command"
done
safe_managed_root "$BUILD_ROOT"
safe_managed_root "$OUTPUT_DIR"
[[ -f "$LOCK_FILE" ]] || die "source lock file not found: $LOCK_FILE"
[[ $(uname -m) == x86_64 ]] || die "the release slirp4netns build requires an x86_64 host"
# Reaches both make -j and ninja -j across the whole GLib chain. This lane
# accepted any positive integer before, with no ceiling of its own.
JOBS=$(pocket_build_jobs)

WORK_ROOT=$(mktemp -d "$BUILD_ROOT/.slirp4netns-build.XXXXXXXX")
cleanup() {
    # Keep the tree when POCKET_KEEP_BUILD is set: the logs are the only
    # way to diagnose a failure in a chain this deep.
    [[ -n ${POCKET_KEEP_BUILD:-} ]] && return 0
    [[ -n ${WORK_ROOT:-} && -d "$WORK_ROOT" ]] && rm -rf -- "$WORK_ROOT"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# The exit trap removes WORK_ROOT, so an error that names a log inside it names
# a path that is already gone by the time anyone reads the message. Print the
# log that failed and keep the tree.
die_with_logs() {
    local logs=$1 message=$2 newest
    newest=$(find "$logs" -maxdepth 1 -name '*.log' -printf '%T@ %p\n' 2>/dev/null |
        sort -rn | head -n 1 | cut -d' ' -f2-)
    if [[ -n "$newest" && -s "$newest" ]]; then
        printf '\n--- %s (last 40 lines) ---\n' "${newest##*/}" >&2
        tail -n 40 -- "$newest" >&2
        printf -- '---\n\n' >&2
    elif [[ -n "$newest" ]]; then
        printf '\n%s is empty; the step failed before it wrote anything\n\n' \
            "${newest##*/}" >&2
    fi
    POCKET_KEEP_BUILD=1
    die "$message; logs kept in $logs"
}

lock_value() {
    local section=$1 key=$2
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
    [[ $(lock_value "$1" "$2") == "$3" ]] || die "$4 does not match sources.lock.toml"
}

assert_lock zlib version "$ZLIB_VERSION" "zlib version"
assert_lock libffi version "$LIBFFI_VERSION" "libffi version"
assert_lock pcre2 version "$PCRE2_VERSION" "pcre2 version"
assert_lock glib version "$GLIB_VERSION" "glib version"

# GLib is the fourth link in this chain, so an unusable meson otherwise
# announces itself only after zlib, libffi and pcre2 have already been built.
MESON_VERSION=$(meson --version)
pocket_version_at_least "$MESON_VERSION" "$MESON_MINIMUM" || die \
    "glib $GLIB_VERSION needs meson $MESON_MINIMUM or newer, found $MESON_VERSION (pipx install meson)"
# slirp4netns is the last of six components, and its configure requires both of
# these from the host, so a machine without them finds out at the very end.
for module in libcap libseccomp; do
    pkg-config --exists "$module" || \
        die "slirp4netns needs the $module development package (Debian: ${module}-dev)"
done
assert_lock libslirp version "$LIBSLIRP_VERSION" "libslirp version"
assert_lock slirp4netns version "$SLIRP4NETNS_VERSION" "slirp4netns version"
assert_lock slirp4netns commit "$SLIRP4NETNS_COMMIT" "slirp4netns commit"

mkdir -p -- "$DOWNLOAD_DIR"

# Every source is fetched over TLS and checked against the lock before it is
# unpacked. An archive that does not match is never opened.
fetch() {
    local section=$1 file=$2 url expected observed staging
    url=$(lock_value "$section" tarball_url) || die "no tarball_url for $section"
    expected=$(lock_value "$section" tarball_sha256) || die "no tarball_sha256 for $section"
    local output="$DOWNLOAD_DIR/$file"
    if [[ ! -f "$output" ]]; then
        staging="$WORK_ROOT/$file.download"
        curl --proto '=https' --tlsv1.2 --fail --location \
            --retry 3 --retry-all-errors --connect-timeout 15 --max-time 600 \
            --output "$staging" "$url" || die "download failed: $url"
        mv -- "$staging" "$output"
    fi
    observed=$(sha256sum "$output" | awk '{print $1}')
    [[ "$observed" == "$expected" ]] || \
        die "$section archive SHA-256 mismatch: expected $expected, observed $observed"
}

fetch zlib "zlib-$ZLIB_VERSION.tar.gz"
fetch libffi "libffi-$LIBFFI_VERSION.tar.gz"
fetch pcre2 "pcre2-$PCRE2_VERSION.tar.bz2"
fetch glib "glib-$GLIB_VERSION.tar.xz"
fetch libslirp "libslirp-v$LIBSLIRP_VERSION.tar.gz"
fetch slirp4netns "slirp4netns-$SLIRP4NETNS_VERSION.tar.gz"

# The artifact must not depend on where it was built: glib compiles its own
# prefix in as a string (GLIB_LOCALE_DIR), and glib's g_return_if_fail macros
# embed __FILE__, which for a header resolves to the absolute include path. A
# build root therefore leaks straight into the binary, and `make
# reproduce-release` builds in a different root on purpose.
#
# So the whole chain is configured for one fixed logical prefix and installed
# through DESTDIR into a per-pass staging tree. pkg-config is told about the
# staging root separately, and the two remaining absolute paths -- the staging
# tree and the unpacked sources -- are mapped back to fixed names for the
# compiler. Nothing that reaches the binary then names a real directory.
LOGICAL_PREFIX=/pocket-slirp

build_once() {
    local pass=$1
    local base="$WORK_ROOT/$pass"
    local stage="$base/stage" src="$base/src"
    local staged="$stage$LOGICAL_PREFIX"
    mkdir -p -- "$stage" "$src" "$base/logs"
    local logs="$base/logs"

    local common="-O2 -fPIC -g0"
    common+=" -ffile-prefix-map=$src=/pocket-source"
    common+=" -ffile-prefix-map=$stage="
    export CFLAGS="$common"
    export CXXFLAGS="$common"
    export SOURCE_DATE_EPOCH
    export PKG_CONFIG_PATH="$staged/lib/pkgconfig"
    export LDFLAGS="-L$staged/lib"

    # Each component is configured for the fixed logical prefix but installed
    # through DESTDIR, so its .pc files advertise a directory that does not
    # exist. Point them at the staging tree instead. PKG_CONFIG_SYSROOT_DIR
    # would do this too, but it rewrites the host's .pc files as well and
    # emits -I$stage/usr/include, which glib rejects under
    # -Werror=missing-include-dirs.
    restage_pkgconfig() {
        local file
        for file in "$staged"/lib/pkgconfig/*.pc; do
            [[ -f "$file" ]] || continue
            sed -i "s|^prefix=$LOGICAL_PREFIX\$|prefix=$staged|" "$file"
        done
    }

    cd "$src" || die "cannot enter the build source directory"
    tar -xf "$DOWNLOAD_DIR/zlib-$ZLIB_VERSION.tar.gz"
    (cd "zlib-$ZLIB_VERSION" && ./configure --static --prefix="$LOGICAL_PREFIX" >/dev/null \
        && make -j"$JOBS" >/dev/null && make install DESTDIR="$stage" >/dev/null) \
        || die "zlib build failed"
    restage_pkgconfig

    tar -xf "$DOWNLOAD_DIR/libffi-$LIBFFI_VERSION.tar.gz"
    (cd "libffi-$LIBFFI_VERSION" && ./configure --enable-static --disable-shared \
        --disable-docs --prefix="$LOGICAL_PREFIX" >/dev/null \
        && make -j"$JOBS" >/dev/null && make install DESTDIR="$stage" >/dev/null) \
        || die "libffi build failed"
    restage_pkgconfig

    tar -xf "$DOWNLOAD_DIR/pcre2-$PCRE2_VERSION.tar.bz2"
    (cd "pcre2-$PCRE2_VERSION" && ./configure --enable-static --disable-shared \
        --prefix="$LOGICAL_PREFIX" >/dev/null \
        && make -j"$JOBS" >/dev/null && make install DESTDIR="$stage" >/dev/null) \
        || die "pcre2 build failed"
    restage_pkgconfig

    tar -xf "$DOWNLOAD_DIR/glib-$GLIB_VERSION.tar.xz"
    (cd "glib-$GLIB_VERSION" && meson setup _b --prefix="$LOGICAL_PREFIX" --libdir=lib \
        --default-library=static --buildtype=release \
        -Dtests=false -Dglib_debug=disabled -Dman=false -Dnls=disabled \
        -Dselinux=disabled -Dlibmount=disabled -Dsysprof=disabled \
        -Ddtrace=false -Dsystemtap=false >"$logs/glib-setup.log" 2>&1 \
        && ninja -C _b -j"$JOBS" >"$logs/glib-build.log" 2>&1 \
        && DESTDIR="$stage" ninja -C _b install >"$logs/glib-install.log" 2>&1) \
        || die_with_logs "$logs" "glib build failed"
    restage_pkgconfig

    tar -xf "$DOWNLOAD_DIR/libslirp-v$LIBSLIRP_VERSION.tar.gz"
    (cd "libslirp-v$LIBSLIRP_VERSION" && meson setup _b --prefix="$LOGICAL_PREFIX" --libdir=lib \
        --default-library=static --buildtype=release >"$logs/libslirp-setup.log" 2>&1 \
        && ninja -C _b -j"$JOBS" >"$logs/libslirp-build.log" 2>&1 \
        && DESTDIR="$stage" ninja -C _b install >"$logs/libslirp-install.log" 2>&1) \
        || die_with_logs "$logs" "libslirp build failed"
    restage_pkgconfig

    tar -xf "$DOWNLOAD_DIR/slirp4netns-$SLIRP4NETNS_VERSION.tar.gz"
    # slirp4netns has no --disable-seccomp or --disable-libcap: its configure.ac
    # requires both through PKG_CHECK_MODULES unconditionally, and autoconf
    # discarded the two flags that used to be passed here with nothing but a
    # warning. libseccomp is linked in statically; libcap supplies only a header.
    (cd "slirp4netns-$SLIRP4NETNS_VERSION" && ./autogen.sh >"$logs/slirp4netns-autogen.log" 2>&1 \
        && LDFLAGS="-static -L$staged/lib" ./configure --prefix="$LOGICAL_PREFIX" \
            >"$logs/slirp4netns-configure.log" 2>&1 \
        && make -j"$JOBS" >"$logs/slirp4netns-build.log" 2>&1) || die_with_logs "$logs" "slirp4netns build failed"

    mkdir -p -- "$base/result"
    cp -- "$src/slirp4netns-$SLIRP4NETNS_VERSION/slirp4netns" "$base/result/slirp4netns"
}

build_once only
BINARY="$WORK_ROOT/only/result/slirp4netns"

file "$BINARY" | grep -q 'statically linked' || \
    die "slirp4netns is not statically linked"
readelf -d "$BINARY" 2>/dev/null | grep -q NEEDED && \
    die "slirp4netns declares a dynamic dependency"

mkdir -p -- "$OUTPUT_DIR"
install -m 0555 -- "$BINARY" "$OUTPUT_DIR/slirp4netns"
touch -d "@$SOURCE_DATE_EPOCH" "$OUTPUT_DIR/slirp4netns"

printf 'slirp4netns=%s\n' "$OUTPUT_DIR/slirp4netns"
sha256sum "$OUTPUT_DIR/slirp4netns"
