#!/usr/bin/env bash

# shellcheck source=scripts/lib.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"
# shellcheck source=scripts/linux-source-lib.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/linux-source-lib.sh"

ROOT=$(project_root)
BUILD_ROOT=${POCKET_BUILD_ROOT:-"$ROOT/build"}
SOURCE_DIR=${1:-"$BUILD_ROOT/src/$LINUX_SOURCE_NAME"}
EXPECTED_SOURCE_DIR="$BUILD_ROOT/src/$LINUX_SOURCE_NAME"
TMP_PARENT="$BUILD_ROOT/tmp"

for command in awk find flock git mktemp python3 sha256sum; do
    require_command "$command"
done
safe_managed_root "$BUILD_ROOT"
[[ $SOURCE_DIR == "$EXPECTED_SOURCE_DIR" ]] || \
    die "Linux source audit accepts only the fixed managed source path"
load_linux_source_locks "$ROOT"
acquire_linux_pipeline_lock "$BUILD_ROOT"
mkdir -p -- "$TMP_PARENT"

AUDIT_ROOT=$(mktemp -d "$TMP_PARENT/linux-source-audit.XXXXXX")
cleanup_audit() {
    cleanup_linux_staging "$AUDIT_ROOT" "$TMP_PARENT" linux-source-audit.
}
trap cleanup_audit EXIT

verify_source_identity "$ROOT" "$SOURCE_DIR" "$AUDIT_ROOT/identity" \
    "$LINUX_PATCHED_TREE" "$LINUX_PATCHED_MANIFEST" "published patched Linux"
audit_patch_series_reverse_forward "$SOURCE_DIR" "$AUDIT_ROOT/identity"
isolated_git "$SOURCE_DIR" "$AUDIT_ROOT/identity" update-index -q --refresh
isolated_git "$SOURCE_DIR" "$AUDIT_ROOT/identity" diff-files --quiet || \
    die "patch audit changed or diverged from the published source worktree"
verify_source_tree_hygiene "$SOURCE_DIR"
final_manifest=$(source_manifest_sha256 "$ROOT" "$SOURCE_DIR")
[[ $final_manifest == "$LINUX_PATCHED_MANIFEST" ]] || \
    die "published Linux manifest changed during audit"

printf 'verified Linux source: %s\n' "$SOURCE_DIR"
printf 'upstream tree: %s\n' "$LINUX_UPSTREAM_TREE"
printf 'patch series: %s\n' "$LINUX_PATCH_SERIES_SHA256"
printf 'patched tree: %s\n' "$LINUX_PATCHED_TREE"
printf 'patched manifest: %s\n' "$LINUX_PATCHED_MANIFEST"
