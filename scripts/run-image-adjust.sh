#!/usr/bin/env bash

# Resize one converted image in both directions and boot each result.
#
# The claim `image adjust` makes is not that resize2fs works, but that the
# image still runs afterwards and still holds what it held: a resized base
# carries a generation marker that has to be rewritten, and a filesystem that
# passes e2fsck can still fail to boot.

source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"

ROOT=$(project_root)
BUILD_ROOT=${POCKET_BUILD_ROOT:-"$ROOT/build"}
PROFILE_BUNDLE=${POCKET_PROFILE_BUNDLE:-}
POCKET_BIN="$ROOT/target/release/pocket"
ADJUST_IMAGE=${POCKET_ADJUST_IMAGE:-docker://docker.io/library/alpine:3.22}

for command in cargo grep mkdir mktemp; do
    require_command "$command"
done
if [[ -z "$PROFILE_BUNDLE" ]]; then
    [[ -f "$BUILD_ROOT/profiles/latest" ]] || \
        die "set POCKET_PROFILE_BUNDLE, or run make release-profile first"
    PROFILE_BUNDLE=$(cat "$BUILD_ROOT/profiles/latest")
fi
[[ -d "$PROFILE_BUNDLE" ]] || die "profile bundle is not a directory: $PROFILE_BUNDLE"
[[ "$PROFILE_BUNDLE" = /* ]] || die "POCKET_PROFILE_BUNDLE must be absolute"
safe_managed_root "$BUILD_ROOT"

cargo build --locked --release -p pocket >/dev/null
[[ -x "$POCKET_BIN" ]] || die "pocket was not built"

WORK_ROOT=$(mktemp -d "$BUILD_ROOT/adjust.XXXXXXXX")
STORE="$WORK_ROOT/store"
RUNTIME_ROOT=$(mktemp -d "${XDG_RUNTIME_DIR:-/tmp}/pkadj.XXXXXX")
cleanup() {
    [[ -d "$RUNTIME_ROOT" ]] && rm -rf -- "$RUNTIME_ROOT"
    if [[ -d "$WORK_ROOT" ]]; then
        find "$WORK_ROOT" -depth -type d -exec chmod u+rwx -- {} + 2>/dev/null || true
        find "$WORK_ROOT" -depth -type f -exec chmod u+w -- {} + 2>/dev/null || true
        rm -rf -- "$WORK_ROOT"
    fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir -m 0700 -- "$STORE"
export POCKET_CONFIG=/nonexistent

common=(--profile-bundle "$PROFILE_BUNDLE" --store "$STORE" --runtime-root "$RUNTIME_ROOT")

printf 'adjust_work_root=%s\n' "$WORK_ROOT"
printf 'profile_bundle=%s\n' "$PROFILE_BUNDLE"

"$POCKET_BIN" image pull "${common[@]}" --reference base:latest --platform linux/amd64 \
    "$ADJUST_IMAGE" >"$WORK_ROOT/pull.json" 2>"$WORK_ROOT/pull.stderr" || {
        sed -n '1,40p' "$WORK_ROOT/pull.stderr" >&2
        die "could not acquire the image to adjust"
    }

# Report the size the default floor produced, then both adjusted sizes. Each
# is read from a running guest, because that is the number an operator gets.
size_of() {
    # shellcheck disable=SC2016  # the guest shell expands this, not this one
    "$POCKET_BIN" run "${common[@]}" --timeout 600s "$1" -- \
        /bin/sh -c 'df -k / | awk "NR==2 {print \$2}"' 2>"$WORK_ROOT/$2.stderr"
}

default_kb=$(size_of base:latest default) || {
    sed -n '1,40p' "$WORK_ROOT/default.stderr" >&2
    die "the freshly converted image did not run"
}
printf 'default_kb=%s\n' "$default_kb"

"$POCKET_BIN" image adjust "${common[@]}" --size 32G --reference base:big base:latest \
    >"$WORK_ROOT/grow.json" 2>"$WORK_ROOT/grow.stderr" || {
        sed -n '1,40p' "$WORK_ROOT/grow.stderr" >&2
        die "growing the image failed"
    }
grown_kb=$(size_of base:big grown) || {
    sed -n '1,40p' "$WORK_ROOT/grown.stderr" >&2
    die "the grown image did not run"
}
printf 'grown_kb=%s\n' "$grown_kb"

"$POCKET_BIN" image adjust "${common[@]}" --size 2G --reference base:small base:latest \
    >"$WORK_ROOT/shrink.json" 2>"$WORK_ROOT/shrink.stderr" || {
        sed -n '1,40p' "$WORK_ROOT/shrink.stderr" >&2
        die "shrinking the image failed"
    }
shrunk_kb=$(size_of base:small shrunk) || {
    sed -n '1,40p' "$WORK_ROOT/shrunk.stderr" >&2
    die "the shrunk image did not run"
}
printf 'shrunk_kb=%s\n' "$shrunk_kb"

release=$("$POCKET_BIN" run "${common[@]}" --timeout 600s base:big -- \
    /bin/sh -c 'cat /etc/alpine-release' 2>/dev/null | tr -d '\r\n')
printf 'grown_release=%s\n' "$release"
after_kb=$(size_of base:latest after) || die "the source image stopped running"
printf 'source_kb_after=%s\n' "$after_kb"

# The default floor, both directions, contents preserved, and a source that
# was not touched. Each is asserted separately.
(( default_kb > 7000000 )) || die "the default filesystem is below the 8 GiB floor"
(( grown_kb > 30000000 )) || die "growing did not produce a larger filesystem"
(( shrunk_kb < 2200000 && shrunk_kb > 1500000 )) || die "shrinking did not produce a 2 GiB filesystem"
[[ -n "$release" ]] || die "the grown image lost its contents"
(( after_kb == default_kb )) || die "adjusting modified the source image"

if find "$RUNTIME_ROOT" -mindepth 1 ! -name .sweep.lock -print -quit | grep -q .; then
    die "an adjust run leaked a runtime directory"
fi

printf 'POCKET_IMAGE_ADJUST_OK\n'
