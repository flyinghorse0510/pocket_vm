#!/usr/bin/env bash

# shellcheck source=scripts/lib.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"
# shellcheck source=scripts/linux-source-lib.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/linux-source-lib.sh"

# Every permission bit in this tree is bound into the locked manifest, and the
# operator's umask reaches all three ways files get created here: tar
# extraction, `git apply`, and mkdir. Left to the environment, a correct and
# signature-verified tarball fails its identity check on any host that does not
# happen to use 0022. Fix it for the pipeline rather than record the umask of
# whoever produced the lock.
umask 0022

ROOT=$(project_root)
BUILD_ROOT=${POCKET_BUILD_ROOT:-"$ROOT/build"}
SOURCE_PARENT="$BUILD_ROOT/src"
SOURCE_DIR="$SOURCE_PARENT/$LINUX_SOURCE_NAME"
RECOVERY_DIR="$SOURCE_PARENT/replaced"
TMP_PARENT="$BUILD_ROOT/tmp"

for command in awk find flock git make mktemp mv python3 sha256sum tar; do
    require_command "$command"
done
safe_managed_root "$BUILD_ROOT"
load_linux_source_locks "$ROOT"
acquire_linux_pipeline_lock "$BUILD_ROOT"
mkdir -p -- "$SOURCE_PARENT" "$TMP_PARENT"

TARBALL=$("$ROOT/scripts/fetch-linux.sh")
[[ $TARBALL == "$BUILD_ROOT/downloads/$LINUX_ARCHIVE_NAME.tar.xz" ]] || \
    die "fetch-linux returned an unexpected tarball path"

STAGING=$(mktemp -d "$TMP_PARENT/linux-source-prepare.XXXXXX")
STAGED_TREE="$STAGING/$LINUX_ARCHIVE_NAME"
METADATA="$STAGING/identity"
cleanup_staging() {
    cleanup_linux_staging "$STAGING" "$TMP_PARENT" linux-source-prepare.
}
trap cleanup_staging EXIT

archive_entries=0
while IFS= read -r member; do
    ((archive_entries += 1))
    normalized=${member%/}
    [[ $normalized == "$LINUX_ARCHIVE_NAME" || $normalized == "$LINUX_ARCHIVE_NAME/"* ]] || \
        die "Linux archive member escapes its one locked top-level directory: $member"
    relative=${normalized#"$LINUX_ARCHIVE_NAME"}
    relative=${relative#/}
    if [[ -n $relative ]]; then
        [[ $relative != /* && $relative != ../* && $relative != */../* && $relative != */.. ]] || \
            die "Linux archive member contains path traversal: $member"
        [[ $relative != .git && $relative != .git/* ]] || \
            die "Linux archive unexpectedly contains Git metadata"
        [[ $relative != *.orig && $relative != *.rej ]] || \
            die "Linux archive unexpectedly contains patch backup/reject artifacts"
    fi
done < <(LC_ALL=C tar -tf "$TARBALL")
[[ $archive_entries -gt 1000 ]] || die "Linux archive member list is implausibly small"

# The umask fixed above is what makes this deterministic. Restoring the
# archive's own modes instead would be wrong here: upstream ships 0664 and
# 0775 members, and a verified source tree should not be group-writable.
tar --extract --file "$TARBALL" --directory "$STAGING" \
    --no-same-owner --delay-directory-restore
[[ -d $STAGED_TREE && ! -L $STAGED_TREE ]] || die "Linux archive did not extract its locked root"
verify_source_identity "$ROOT" "$STAGED_TREE" "$METADATA" \
    "$LINUX_UPSTREAM_TREE" "$LINUX_UPSTREAM_MANIFEST" "authenticated upstream Linux"

apply_locked_patch_series "$STAGED_TREE" "$METADATA"
verify_source_tree_hygiene "$STAGED_TREE"
patched_manifest=$(source_manifest_sha256 "$ROOT" "$STAGED_TREE")
[[ $patched_manifest == "$LINUX_PATCHED_MANIFEST" ]] || \
    die "patched Linux filesystem manifest mismatch: observed $patched_manifest"
patched_tree=$(isolated_git "$STAGED_TREE" "$METADATA" write-tree)
[[ $patched_tree == "$LINUX_PATCHED_TREE" ]] || \
    die "patched Linux Git tree mismatch immediately before publication"
isolated_git "$STAGED_TREE" "$METADATA" diff-files --quiet || \
    die "patched Linux worktree differs from its verified index"
version=$(make -s -C "$STAGED_TREE" kernelversion)
[[ $version == 7.2.0 ]] || die "unexpected authenticated Linux version: $version"

preserve_generated_tree "$SOURCE_DIR" "$RECOVERY_DIR" "$LINUX_SOURCE_NAME"
if ! mv -- "$STAGED_TREE" "$SOURCE_DIR"; then
    if [[ -n ${PRESERVED_GENERATED_TREE:-} && ! -e $SOURCE_DIR && ! -L $SOURCE_DIR ]]; then
        mv -- "$PRESERVED_GENERATED_TREE" "$SOURCE_DIR" || true
    fi
    die "failed to atomically publish authenticated Linux source tree"
fi

identity_tmp="$STAGING/source.identity"
{
    printf 'pocket-linux-source-v1\n'
    printf 'release=%s\n' "$LINUX_RELEASE"
    printf 'tag_object=%s\n' "$LINUX_TAG_OBJECT"
    printf 'commit=%s\n' "$LINUX_COMMIT"
    printf 'upstream_tree_sha1=%s\n' "$LINUX_UPSTREAM_TREE"
    printf 'upstream_manifest_sha256=%s\n' "$LINUX_UPSTREAM_MANIFEST"
    printf 'patch_series_sha256=%s\n' "$LINUX_PATCH_SERIES_SHA256"
    printf 'patched_tree_sha1=%s\n' "$LINUX_PATCHED_TREE"
    printf 'patched_manifest_sha256=%s\n' "$LINUX_PATCHED_MANIFEST"
    printf 'variant=%s\n' "${LINUX_VARIANT:-none}"
    [[ -z ${LINUX_VARIANT:-} ]] || \
        printf 'variant_series_sha256=%s\n' "$(sha256sum "$LINUX_OVERLAY_LOCK" | awk '{print $1}')"
} > "$identity_tmp"
chmod 0444 "$identity_tmp"
mv --no-target-directory -- "$identity_tmp" "$SOURCE_PARENT/$LINUX_SOURCE_NAME.identity"

printf '%s\n' "$SOURCE_DIR"
