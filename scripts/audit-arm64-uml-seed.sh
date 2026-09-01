#!/usr/bin/env bash

source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"

ROOT=$(project_root)
AUDIT_ROOT="$ROOT/build/source-audit"
REPOSITORY="$AUDIT_ROOT/linux-um-arm64-seed.git"
SOURCE_URL=https://github.com/zalexdev/linux-um-arm64.git

BASE_COMMIT=1590cf0329716306e948a8fc29f1d3ee87d3989f
HEAD_COMMIT=8897487c52233cd00cf2850008ca068892f1ae91
SMP_COMMIT=03c57e1808f9fc3df91a770e42ce0ff7ac466269
BENCHMARK_COMMIT=1532f4aee863d3a580d13cc99685599c46caf3e1
EXPECTED_RANGE_COUNT=54
FETCH_DEPTH=64

export GIT_CONFIG_NOSYSTEM=1
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_TERMINAL_PROMPT=0
export LC_ALL=C
export TZ=UTC
umask 0077

require_command git
require_command grep
safe_managed_root "$AUDIT_ROOT"

for path in "$ROOT/build" "$AUDIT_ROOT" "$REPOSITORY"; do
    [[ ! -L "$path" ]] || die "refusing symlinked ARM64 audit path: $path"
done
[[ ! -e "$ROOT/build" || -d "$ROOT/build" ]] || \
    die "build path is not a directory: $ROOT/build"
[[ ! -e "$AUDIT_ROOT" || -d "$AUDIT_ROOT" ]] || \
    die "audit path is not a directory: $AUDIT_ROOT"
[[ ! -e "$REPOSITORY" || -d "$REPOSITORY" ]] || \
    die "audit repository path is not a directory: $REPOSITORY"

mkdir -p -- "$AUDIT_ROOT"
if [[ ! -e "$REPOSITORY/HEAD" ]]; then
    [[ ! -e "$REPOSITORY" || -z "$(ls -A -- "$REPOSITORY")" ]] || \
        die "audit repository path is nonempty but is not a Git repository"
    git -c init.defaultBranch=audit -c core.hooksPath=/dev/null \
        init --bare --quiet --template= "$REPOSITORY"
fi

git_audit() {
    git -c core.hooksPath=/dev/null -C "$REPOSITORY" "$@"
}

[[ "$(git_audit rev-parse --is-bare-repository)" == true ]] || \
    die "ARM64 audit object store is not a bare Git repository"

# Fetch only the pinned objects and a bounded slice of their ancestry. Trees
# and blobs stay omitted until one of the small, explicitly audited paths is
# inspected below. No worktree is created and no repository code is executed.
git_audit fetch --quiet --no-tags --force --depth="$FETCH_DEPTH" --filter=tree:0 \
    "$SOURCE_URL" \
    "$BASE_COMMIT:refs/pocket-audit/base" \
    "$HEAD_COMMIT:refs/pocket-audit/head" \
    "$SMP_COMMIT:refs/pocket-audit/smp" \
    "$BENCHMARK_COMMIT:refs/pocket-audit/benchmark"

assert_commit_object() {
    local commit=$1
    local label=$2
    local object_type resolved

    if ! object_type=$(git_audit cat-file -t "$commit"); then
        die "$label object is missing: $commit"
    fi
    [[ "$object_type" == commit ]] || \
        die "$label is not a commit object: $commit ($object_type)"
    if ! resolved=$(git_audit rev-parse --verify "$commit^{commit}"); then
        die "$label commit cannot be resolved: $commit"
    fi
    [[ "$resolved" == "$commit" ]] || \
        die "$label commit resolved unexpectedly: expected $commit, found $resolved"
}

assert_ref() {
    local reference=$1
    local expected=$2
    local resolved

    if ! resolved=$(git_audit rev-parse --verify "$reference^{commit}"); then
        die "pinned audit reference cannot be resolved: $reference"
    fi
    [[ "$resolved" == "$expected" ]] || \
        die "pinned audit reference mismatch: $reference is $resolved, expected $expected"
}

assert_blob_at_head() {
    local path=$1
    local object_type

    if ! object_type=$(git_audit cat-file -t "$HEAD_COMMIT:$path"); then
        die "ARM64 UML glue is missing at pinned head: $path"
    fi
    [[ "$object_type" == blob ]] || \
        die "ARM64 UML glue is not a regular Git blob at pinned head: $path"
}

assert_commit_object "$BASE_COMMIT" "base"
assert_commit_object "$HEAD_COMMIT" "head"
assert_commit_object "$SMP_COMMIT" "SMP"
assert_commit_object "$BENCHMARK_COMMIT" "benchmark"
assert_ref refs/pocket-audit/base "$BASE_COMMIT"
assert_ref refs/pocket-audit/head "$HEAD_COMMIT"
assert_ref refs/pocket-audit/smp "$SMP_COMMIT"
assert_ref refs/pocket-audit/benchmark "$BENCHMARK_COMMIT"

if ! MERGE_BASE=$(git_audit merge-base --all "$BASE_COMMIT" "$HEAD_COMMIT"); then
    die "pinned base and head have no merge base"
fi
[[ "$MERGE_BASE" == "$BASE_COMMIT" ]] || \
    die "unexpected merge base: expected only $BASE_COMMIT, found ${MERGE_BASE//$'\n'/,}"

if ! RANGE_COMMITS=$(git_audit rev-list "$BASE_COMMIT..$HEAD_COMMIT"); then
    die "cannot enumerate the pinned base-to-head commit range"
fi
# A shallow boundary inside the range would make its history incomplete. A
# boundary at the base or earlier is harmless because base..head excludes it.
if [[ -s "$REPOSITORY/shallow" ]] && \
    grep -Fxf "$REPOSITORY/shallow" <<< "$RANGE_COMMITS" >/dev/null; then
    die "bounded fetch left a shallow boundary inside the pinned commit range"
fi
if ! RANGE_COUNT=$(git_audit rev-list --count "$BASE_COMMIT..$HEAD_COMMIT"); then
    die "cannot count the pinned base-to-head commit range"
fi
[[ "$RANGE_COUNT" == "$EXPECTED_RANGE_COUNT" ]] || \
    die "unexpected base-to-head commit count: expected $EXPECTED_RANGE_COUNT, found $RANGE_COUNT"

for commit in "$SMP_COMMIT" "$BENCHMARK_COMMIT"; do
    git_audit merge-base --is-ancestor "$BASE_COMMIT" "$commit" || \
        die "required commit is not descended from the pinned base: $commit"
    git_audit merge-base --is-ancestor "$commit" "$HEAD_COMMIT" || \
        die "required commit is not an ancestor of the pinned head: $commit"
    grep -Fxq -- "$commit" <<< "$RANGE_COMMITS" || \
        die "required commit is absent from the pinned base-to-head range: $commit"
done

if ! UML_TREE_TYPE=$(git_audit cat-file -t "$HEAD_COMMIT:arch/arm64/um"); then
    die "pinned head does not contain the ARM64 UML source tree"
fi
[[ "$UML_TREE_TYPE" == tree ]] || \
    die "arch/arm64/um is not a Git tree at the pinned head"

GLUE_PATHS=(
    arch/arm64/Makefile.um
    arch/arm64/um/Kconfig
    arch/arm64/um/Makefile
    arch/arm64/um/os-Linux/registers.c
    arch/arm64/um/setjmp_aarch64.S
    arch/arm64/um/shared/sysdep/ptrace.h
    arch/um/configs/arm64_defconfig
)
for path in "${GLUE_PATHS[@]}"; do
    assert_blob_at_head "$path"
done

if ! ARM64_UML_KCONFIG=$(git_audit cat-file blob \
    "$HEAD_COMMIT:arch/arm64/um/Kconfig"); then
    die "cannot read the ARM64 UML Kconfig at the pinned head"
fi
grep -Eq \
    '^[[:space:]]*select[[:space:]]+UML_SUBARCH_SUPPORTS_SMP[[:space:]]*$' \
    <<< "$ARM64_UML_KCONFIG" || \
    die "ARM64 UML Kconfig does not select UML_SUBARCH_SUPPORTS_SMP"

printf '%s\n' \
    'ARM64_UML_SEED_AUDIT_OK' \
    "source_url=$SOURCE_URL" \
    "base_commit=$BASE_COMMIT" \
    "head_commit=$HEAD_COMMIT" \
    "merge_base=$MERGE_BASE" \
    "base_to_head_commit_count=$RANGE_COUNT" \
    "smp_commit=$SMP_COMMIT" \
    'smp_commit_in_base_to_head=yes' \
    "benchmark_commit=$BENCHMARK_COMMIT" \
    'benchmark_commit_in_base_to_head=yes' \
    'arm64_uml_glue_at_head=yes' \
    'kconfig_selects_UML_SUBARCH_SUPPORTS_SMP=yes' \
    "fetch_depth=$FETCH_DEPTH" \
    'fetch_filter=tree:0' \
    'checkout_performed=no'
