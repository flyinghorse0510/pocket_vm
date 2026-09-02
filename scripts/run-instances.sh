#!/usr/bin/env bash

# Keep runs, list them, commit one into an image, and remove them.
#
# The commit assertion is the point: a merged overlay that passes e2fsck can
# still be missing every change the run made, because the COW bitmap does not
# begin where the header ends. Nothing but reading the committed image back
# catches that, so this runs the committed image and looks for what the run
# put there.

source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"

ROOT=$(project_root)
BUILD_ROOT=${POCKET_BUILD_ROOT:-"$ROOT/build"}
PROFILE_BUNDLE=${POCKET_PROFILE_BUNDLE:-}
POCKET_BIN="$ROOT/target/release/pocket"
INSTANCE_IMAGE=${POCKET_INSTANCE_IMAGE:-docker://docker.io/library/alpine:3.22}

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

WORK_ROOT=$(mktemp -d "$BUILD_ROOT/instances.XXXXXXXX")
STORE="$WORK_ROOT/store"
RUNTIME_ROOT=$(mktemp -d "${XDG_RUNTIME_DIR:-/tmp}/pkinst.XXXXXX")
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

printf 'instances_work_root=%s\n' "$WORK_ROOT"
printf 'profile_bundle=%s\n' "$PROFILE_BUNDLE"

"$POCKET_BIN" image pull "${common[@]}" --reference base:latest --platform linux/amd64 \
    "$INSTANCE_IMAGE" >"$WORK_ROOT/pull.json" 2>"$WORK_ROOT/pull.stderr" || {
        sed -n '1,40p' "$WORK_ROOT/pull.stderr" >&2
        die "could not acquire the image"
    }

# One kept run that changes the filesystem, one discarded run.
# shellcheck disable=SC2016  # the guest shell expands this, not this one
"$POCKET_BIN" run "${common[@]}" --name kept --timeout 600s base:latest -- /bin/sh -c \
    'echo POCKET_COMMIT_MARKER > /provenance.txt; mkdir -p /added;
     adduser -D -u 1000 committed_user; addgroup -g 1500 committed_group;
     adduser committed_user committed_group; sync' \
    >"$WORK_ROOT/kept.out" 2>"$WORK_ROOT/kept.err" || {
        sed -n '1,40p' "$WORK_ROOT/kept.err" >&2
        die "the kept run failed"
    }
"$POCKET_BIN" run "${common[@]}" --rm --timeout 600s base:latest -- /bin/true \
    >/dev/null 2>"$WORK_ROOT/discarded.err" || {
        sed -n '1,40p' "$WORK_ROOT/discarded.err" >&2
        die "the discarded run failed"
    }

"$POCKET_BIN" ps "${common[@]:2:2}" --runtime-root "$RUNTIME_ROOT" -a \
    >"$WORK_ROOT/ps.out" 2>"$WORK_ROOT/ps.err" || {
        sed -n '1,20p' "$WORK_ROOT/ps.err" >&2
        die "ps -a failed"
    }
cat "$WORK_ROOT/ps.out"
kept_rows=$(grep -c '^name=' "$WORK_ROOT/ps.out" || true)
printf 'kept_rows=%s\n' "$kept_rows"

"$POCKET_BIN" commit "${common[@]}" kept base:committed \
    >"$WORK_ROOT/commit.out" 2>"$WORK_ROOT/commit.err" || {
        sed -n '1,40p' "$WORK_ROOT/commit.err" >&2
        die "committing the kept run failed"
    }
cat "$WORK_ROOT/commit.out"

# The committed image must actually contain what the run produced, and the
# source must not.
committed=$("$POCKET_BIN" run "${common[@]}" --rm --timeout 600s base:committed -- \
    /bin/sh -c 'cat /provenance.txt; test -d /added && echo DIR_PRESENT' 2>/dev/null | tr -d '\r')
printf 'committed_contents=%s\n' "$(printf '%s' "$committed" | tr '\n' ',')"
source_has=$("$POCKET_BIN" run "${common[@]}" --rm --timeout 600s base:latest -- \
    /bin/sh -c 'cat /provenance.txt 2>/dev/null || echo SOURCE_CLEAN' 2>/dev/null | tr -d '\r\n')
printf 'source_after_commit=%s\n' "$source_has"

# An account the run created must be selectable by name on the committed
# image. The account database is a host-readable index of the guest's
# /etc/passwd, so carrying the source's across would leave this unresolvable
# while the account plainly exists inside the image.
committed_user=$("$POCKET_BIN" run "${common[@]}" --rm --timeout 600s \
    --user committed_user:committed_group base:committed -- /bin/sh -c 'id' 2>&1 | tail -1)
printf 'committed_user=%s\n' "$committed_user"

"$POCKET_BIN" rm --store "$STORE" kept >"$WORK_ROOT/rm.out" 2>&1 || die "rm failed"
remaining=$("$POCKET_BIN" ps --store "$STORE" --runtime-root "$RUNTIME_ROOT" -a 2>/dev/null | grep -c '^name=' || true)
printf 'remaining_after_rm=%s\n' "$remaining"

(( kept_rows == 1 )) || die "expected exactly one kept run, saw $kept_rows"
grep -q 'POCKET_COMMIT_MARKER' <<<"$committed" || \
    die "the committed image does not contain what the run wrote"
grep -q 'DIR_PRESENT' <<<"$committed" || \
    die "the committed image is missing a directory the run created"
[[ "$source_has" == SOURCE_CLEAN ]] || die "committing modified the source image"
grep -q 'uid=1000(committed_user)' <<<"$committed_user" || \
    die "an account the run created does not resolve by name on the committed image"
grep -q 'gid=1500(committed_group)' <<<"$committed_user" || \
    die "a group the run created does not resolve by name on the committed image"
(( remaining == 0 )) || die "rm left $remaining kept runs behind"

if find "$RUNTIME_ROOT" -mindepth 1 ! -name .sweep.lock -print -quit | grep -q .; then
    die "a run leaked a runtime directory"
fi

printf 'POCKET_INSTANCES_OK\n'
