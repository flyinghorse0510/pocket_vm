#!/usr/bin/env bash

# shellcheck source=scripts/lib.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"
# shellcheck source=scripts/linux-source-lib.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/linux-source-lib.sh"

ROOT=$(project_root)
BUILD_ROOT=${POCKET_BUILD_ROOT:-"$ROOT/build"}
TMP_PARENT="$BUILD_ROOT/tmp"

for command in chmod find ln mkdir mktemp python3 sha256sum; do
    require_command "$command"
done
safe_managed_root "$BUILD_ROOT"
load_linux_source_locks "$ROOT"
mkdir -p -- "$TMP_PARENT"

TEST_ROOT=$(mktemp -d "$TMP_PARENT/linux-source-test.XXXXXX")
cleanup_test() {
    cleanup_linux_staging "$TEST_ROOT" "$TMP_PARENT" linux-source-test.
}
trap cleanup_test EXIT

FIXTURE="$TEST_ROOT/tree"
mkdir -p -- "$FIXTURE/dir"
printf 'locked content\n' > "$FIXTURE/dir/file"
ln -s dir/file "$FIXTURE/link"
chmod 0644 "$FIXTURE/dir/file"
baseline=$(source_manifest_sha256 "$ROOT" "$FIXTURE")
chmod 0600 "$FIXTURE/dir/file"
mode_changed=$(source_manifest_sha256 "$ROOT" "$FIXTURE")
[[ $mode_changed != "$baseline" ]] || die "source manifest failed to bind file mode"
chmod 0644 "$FIXTURE/dir/file"
printf 'changed content\n' > "$FIXTURE/dir/file"
content_changed=$(source_manifest_sha256 "$ROOT" "$FIXTURE")
[[ $content_changed != "$baseline" ]] || die "source manifest failed to bind file content"
printf 'locked content\n' > "$FIXTURE/dir/file"
[[ $(source_manifest_sha256 "$ROOT" "$FIXTURE") == "$baseline" ]] || \
    die "source manifest is not deterministic after fixture restoration"

printf 'reject\n' > "$FIXTURE/file.orig"
if (verify_source_tree_hygiene "$FIXTURE" >/dev/null 2>&1); then
    die "source hygiene accepted a .orig artifact"
fi
unlink "$FIXTURE/file.orig"
mkdir "$FIXTURE/empty"
if (verify_source_tree_hygiene "$FIXTURE" >/dev/null 2>&1); then
    die "source hygiene accepted an untracked empty directory"
fi
rmdir "$FIXTURE/empty"
verify_source_tree_hygiene "$FIXTURE"

"$ROOT/scripts/audit-linux-source.sh"
printf 'verified Linux source-pipeline regression checks\n'
