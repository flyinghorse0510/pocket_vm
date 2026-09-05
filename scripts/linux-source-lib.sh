#!/usr/bin/env bash

# Shared fail-closed Linux source identity helpers. Callers must source lib.sh
# first so `die`, `require_command`, and `safe_managed_root` are available.

# These globals are the deliberate interface exported to sourcing scripts.
# shellcheck disable=SC2034
LINUX_RELEASE=7.2
# The archive's own top-level directory, fixed by the upstream tarball.
# shellcheck disable=SC2034
LINUX_ARCHIVE_NAME=linux-7.2

# Optional, experimental kernel variants.
#
# A variant applies one additional locked patch overlay on top of the default
# series and publishes to its own source and output paths, so selecting one
# can neither disturb the default build nor be mistaken for it. Nothing here
# happens unless the operator names a variant: POCKET_KERNEL_VARIANT is empty
# by default, and an unknown value is refused rather than ignored.
#
# The set is a fixed allow-list, not whatever directories happen to exist, so
# a stray directory under kernel/patches cannot become a buildable variant.
LINUX_SUPPORTED_VARIANTS=(el7)
LINUX_VARIANT=${POCKET_KERNEL_VARIANT:-}
if [[ -n $LINUX_VARIANT ]]; then
    linux_variant_known=0
    for linux_variant_candidate in "${LINUX_SUPPORTED_VARIANTS[@]}"; do
        [[ $linux_variant_candidate == "$LINUX_VARIANT" ]] && linux_variant_known=1
    done
    [[ $linux_variant_known -eq 1 ]] || \
        die "POCKET_KERNEL_VARIANT is not a supported kernel variant: $LINUX_VARIANT"
    unset linux_variant_known linux_variant_candidate
    # shellcheck disable=SC2034
    LINUX_SOURCE_NAME=$LINUX_ARCHIVE_NAME-$LINUX_VARIANT
    # shellcheck disable=SC2034
    LINUX_OUTPUT_SUFFIX=-$LINUX_VARIANT
else
    # shellcheck disable=SC2034
    LINUX_SOURCE_NAME=$LINUX_ARCHIVE_NAME
    # shellcheck disable=SC2034
    LINUX_OUTPUT_SUFFIX=
fi

linux_lock_value() {
    local lock_file=$1 key=$2 section=${3:-linux}
    local -a matches=()
    mapfile -t matches < <(
        awk -v wanted="$key" -v heading="[$section]" '
            $0 == heading { inside = 1; next }
            /^\[/ { if (inside) exit }
            inside && $0 ~ "^" wanted " = " { print; count++ }
            END { if (count != 1) exit 3 }
        ' "$lock_file"
    ) || die "missing or duplicate $section.$key in $lock_file"
    [[ ${#matches[@]} -eq 1 ]] || die "missing or duplicate $section.$key in $lock_file"

    local value=${matches[0]#*= }
    if [[ $value =~ ^\"([^\"]*)\"$ ]]; then
        printf '%s\n' "${BASH_REMATCH[1]}"
    elif [[ $value =~ ^[0-9]+$ ]]; then
        printf '%s\n' "$value"
    else
        die "$section.$key has an unsupported lock-file value"
    fi
}

require_hex() {
    local value=$1 length=$2 description=$3
    [[ $value =~ ^[0-9a-f]+$ && ${#value} -eq $length ]] || \
        die "$description is not a lowercase $length-character hexadecimal value"
}

load_linux_source_locks() {
    local root=$1
    LINUX_SOURCE_LOCK="$root/config/sources.lock.toml"
    LINUX_PATCH_DIR="$root/kernel/patches/$LINUX_RELEASE"
    LINUX_SERIES_LOCK="$LINUX_PATCH_DIR/series.lock"
    [[ -f $LINUX_SOURCE_LOCK && ! -L $LINUX_SOURCE_LOCK ]] || \
        die "Linux source lock is missing or not a regular file: $LINUX_SOURCE_LOCK"
    [[ -f $LINUX_SERIES_LOCK && ! -L $LINUX_SERIES_LOCK ]] || \
        die "Linux patch-series lock is missing or not a regular file: $LINUX_SERIES_LOCK"

    LINUX_LOCKED_RELEASE=$(linux_lock_value "$LINUX_SOURCE_LOCK" release)
    LINUX_TAG=$(linux_lock_value "$LINUX_SOURCE_LOCK" tag)
    LINUX_TAG_OBJECT=$(linux_lock_value "$LINUX_SOURCE_LOCK" tag_object)
    LINUX_COMMIT=$(linux_lock_value "$LINUX_SOURCE_LOCK" commit)
    LINUX_TARBALL_URL=$(linux_lock_value "$LINUX_SOURCE_LOCK" tarball_url)
    LINUX_SIGNATURE_URL=$(linux_lock_value "$LINUX_SOURCE_LOCK" signature_url)
    LINUX_TARBALL_SHA256=$(linux_lock_value "$LINUX_SOURCE_LOCK" tarball_sha256)
    LINUX_SIGNATURE_SHA256=$(linux_lock_value "$LINUX_SOURCE_LOCK" signature_sha256)
    LINUX_SIGNED_TAR_SHA256=$(linux_lock_value "$LINUX_SOURCE_LOCK" signed_tar_sha256)
    LINUX_SIGNER_EMAIL=$(linux_lock_value "$LINUX_SOURCE_LOCK" signer_email)
    LINUX_SIGNER_FINGERPRINT=$(linux_lock_value "$LINUX_SOURCE_LOCK" signer_fingerprint)
    LINUX_SIGNER_KEY_URL=$(linux_lock_value "$LINUX_SOURCE_LOCK" signer_key_url)
    LINUX_UPSTREAM_TREE=$(linux_lock_value "$LINUX_SOURCE_LOCK" upstream_tree_sha1)
    LINUX_UPSTREAM_MANIFEST=$(linux_lock_value "$LINUX_SOURCE_LOCK" upstream_manifest_sha256)
    LINUX_PATCH_SERIES_SHA256=$(linux_lock_value "$LINUX_SOURCE_LOCK" patch_series_sha256)
    LINUX_PATCHED_TREE=$(linux_lock_value "$LINUX_SOURCE_LOCK" patched_tree_sha1)
    LINUX_PATCHED_MANIFEST=$(linux_lock_value "$LINUX_SOURCE_LOCK" patched_manifest_sha256)
    LINUX_SOURCE_DATE_EPOCH=$(linux_lock_value "$LINUX_SOURCE_LOCK" source_date_epoch)

    [[ $LINUX_LOCKED_RELEASE == "$LINUX_RELEASE" ]] || die "Linux release lock is not $LINUX_RELEASE"
    [[ $LINUX_TAG == "v$LINUX_RELEASE" ]] || die "Linux tag lock is not v$LINUX_RELEASE"
    [[ $LINUX_TARBALL_URL == "https://cdn.kernel.org/pub/linux/kernel/v7.x/linux-$LINUX_RELEASE.tar.xz" ]] || \
        die "Linux tarball URL is outside the pinned kernel.org location"
    [[ $LINUX_SIGNATURE_URL == "https://cdn.kernel.org/pub/linux/kernel/v7.x/linux-$LINUX_RELEASE.tar.sign" ]] || \
        die "Linux signature URL is outside the pinned kernel.org location"
    [[ $LINUX_SIGNER_EMAIL == gregkh@kernel.org ]] || die "unexpected Linux signer email lock"
    [[ $LINUX_SIGNER_KEY_URL == "https://kernel.org/.well-known/openpgpkey/hu/"* ]] || \
        die "Linux signer key URL is outside the signer's own Web Key Directory"
    [[ $LINUX_SOURCE_DATE_EPOCH == 1786940622 ]] || die "unexpected Linux source date epoch"

    require_hex "$LINUX_TAG_OBJECT" 40 "Linux tag object"
    require_hex "$LINUX_COMMIT" 40 "Linux commit"
    require_hex "$LINUX_TARBALL_SHA256" 64 "Linux tarball SHA-256"
    require_hex "$LINUX_SIGNATURE_SHA256" 64 "Linux signature SHA-256"
    require_hex "$LINUX_SIGNED_TAR_SHA256" 64 "Linux signed-tar SHA-256"
    [[ $LINUX_SIGNER_FINGERPRINT =~ ^[0-9A-F]{40}$ ]] || \
        die "Linux signer fingerprint is not an uppercase 40-character hexadecimal value"
    require_hex "$LINUX_UPSTREAM_TREE" 40 "Linux upstream tree"
    require_hex "$LINUX_UPSTREAM_MANIFEST" 64 "Linux upstream manifest"
    require_hex "$LINUX_PATCH_SERIES_SHA256" 64 "Linux patch-series SHA-256"
    require_hex "$LINUX_PATCHED_TREE" 40 "Linux patched tree"
    require_hex "$LINUX_PATCHED_MANIFEST" 64 "Linux patched manifest"

    local actual_series_sha
    actual_series_sha=$(sha256sum "$LINUX_SERIES_LOCK" | awk '{print $1}')
    [[ $actual_series_sha == "$LINUX_PATCH_SERIES_SHA256" ]] || \
        die "Linux patch-series lock SHA-256 mismatch"

    load_linux_patch_series
    load_linux_variant_overlay
}

load_linux_patch_series() {
    LINUX_PATCH_FILES=()
    LINUX_PATCH_DIRS=()
    LINUX_PATCH_HASHES=()
    LINUX_PATCH_PATHS=()
    LINUX_PATCH_MODES=()
    LINUX_PATCH_PRE_BLOBS=()
    LINUX_PATCH_POST_BLOBS=()

    linux_load_series_file "$LINUX_SERIES_LOCK" "$LINUX_PATCH_DIR" \
        pocket-linux-patch-series-v1 upstream \
        "$LINUX_UPSTREAM_TREE" "$LINUX_UPSTREAM_MANIFEST" \
        "$LINUX_PATCHED_TREE" "$LINUX_PATCHED_MANIFEST"
}

# Read one series file: its schema line, the tree it starts from, its ordered
# patches, and the tree it produces. Records append to the shared patch arrays
# so a variant overlay can be loaded straight after the default series and the
# two applied as one ordered run. Everything is checked here; nothing
# downstream reads the file again.
linux_load_series_file() {
    local lock_file=$1 patch_dir=$2 schema=$3 start_kind=$4
    local expect_start_tree=$5 expect_start_manifest=$6
    local expect_end_tree=$7 expect_end_manifest=$8
    local line_number=0 kind first second third fourth fifth sixth extra
    local series_start_tree='' series_start_manifest=''
    local series_end_tree='' series_end_manifest=''
    local -a series_files=() series_hashes=()
    local -A seen_files=() seen_paths=()

    [[ -f $lock_file && ! -L $lock_file ]] || \
        die "Linux patch-series lock is missing or not a regular file: $lock_file"
    [[ -d $patch_dir && ! -L $patch_dir ]] || \
        die "Linux patch directory is missing or not a directory: $patch_dir"

    while IFS=$'\t' read -r kind first second third fourth fifth sixth extra || [[ -n $kind ]]; do
        ((line_number += 1))
        if ((line_number == 1)); then
            [[ $kind == "$schema" && -z ${first:-} ]] || \
                die "unsupported Linux patch-series schema: $lock_file"
            continue
        fi
        case "$kind" in
            "$start_kind-tree")
                [[ -z $second && -z $extra && -z $series_start_tree ]] || die "malformed $start_kind-tree record"
                series_start_tree=$first
                ;;
            "$start_kind-manifest")
                [[ -z $second && -z $extra && -z $series_start_manifest ]] || die "malformed $start_kind-manifest record"
                series_start_manifest=$first
                ;;
            patched-tree)
                [[ -z $second && -z $extra && -z $series_end_tree ]] || die "malformed patched-tree record"
                series_end_tree=$first
                ;;
            patched-manifest)
                [[ -z $second && -z $extra && -z $series_end_manifest ]] || die "malformed patched-manifest record"
                series_end_manifest=$first
                ;;
            patch)
                [[ -z ${extra:-} && -n $sixth ]] || die "malformed patch record at line $line_number"
                [[ $first =~ ^[0-9]{4}-[A-Za-z0-9._-]+\.patch$ ]] || die "invalid locked patch filename: $first"
                [[ $third != /* && $third != *..* && $third != *$'\n'* && $third != *$'\t'* ]] || \
                    die "invalid locked patch path: $third"
                [[ $fourth == 100644 || $fourth == 100755 ]] || die "invalid locked patch mode: $fourth"
                require_hex "$second" 64 "patch $first SHA-256"
                require_hex "$fifth" 40 "patch $first preimage blob"
                require_hex "$sixth" 40 "patch $first postimage blob"
                [[ -z ${seen_files[$first]+present} ]] || die "duplicate locked patch filename: $first"
                [[ -z ${seen_paths[$third]+present} ]] || die "multiple locked patches modify $third"
                seen_files[$first]=1
                seen_paths[$third]=1
                series_files+=("$first")
                series_hashes+=("$second")
                LINUX_PATCH_FILES+=("$first")
                LINUX_PATCH_DIRS+=("$patch_dir")
                LINUX_PATCH_HASHES+=("$second")
                LINUX_PATCH_PATHS+=("$third")
                LINUX_PATCH_MODES+=("$fourth")
                LINUX_PATCH_PRE_BLOBS+=("$fifth")
                LINUX_PATCH_POST_BLOBS+=("$sixth")
                ;;
            '') die "blank line in Linux patch-series lock: $lock_file" ;;
            *) die "unknown Linux patch-series record at line $line_number: $kind" ;;
        esac
    done < "$lock_file"

    [[ ${#series_files[@]} -gt 0 ]] || die "Linux patch-series lock contains no patches: $lock_file"
    [[ $series_start_tree == "$expect_start_tree" ]] || die "patch lock $start_kind tree mismatch: $lock_file"
    [[ $series_start_manifest == "$expect_start_manifest" ]] || die "patch lock $start_kind manifest mismatch: $lock_file"
    [[ $series_end_tree == "$expect_end_tree" ]] || die "patch lock patched tree mismatch: $lock_file"
    [[ $series_end_manifest == "$expect_end_manifest" ]] || die "patch lock patched manifest mismatch: $lock_file"

    # The directory must hold exactly the locked patches and nothing else, so
    # an unlocked file dropped beside them is a failure rather than a no-op.
    local -a disk_patches=()
    mapfile -t disk_patches < <(find "$patch_dir" -maxdepth 1 -type f -name '*.patch' -printf '%f\n' | LC_ALL=C sort)
    [[ ${#disk_patches[@]} -eq ${#series_files[@]} ]] || die "unlocked or missing Linux patch file in $patch_dir"
    local index patch_sha
    for index in "${!series_files[@]}"; do
        [[ ${disk_patches[$index]} == "${series_files[$index]}" ]] || die "Linux patch order/file set differs from $lock_file"
        patch_sha=$(sha256sum "$patch_dir/${series_files[$index]}" | awk '{print $1}')
        [[ $patch_sha == "${series_hashes[$index]}" ]] || \
            die "Linux patch SHA-256 mismatch: ${series_files[$index]}"
    done
}

# Load the selected variant's overlay on top of the default series. The
# overlay declares the tree it starts from, which must be exactly the tree the
# default series produces, so the two locks are chained rather than merely
# adjacent. With no variant selected this does nothing at all.
load_linux_variant_overlay() {
    [[ -n $LINUX_VARIANT ]] || return 0

    LINUX_BASE_PATCH_COUNT=${#LINUX_PATCH_FILES[@]}
    LINUX_BASE_PATCHED_TREE=$LINUX_PATCHED_TREE
    LINUX_BASE_PATCHED_MANIFEST=$LINUX_PATCHED_MANIFEST
    LINUX_OVERLAY_DIR="$LINUX_PATCH_DIR/$LINUX_VARIANT"
    LINUX_OVERLAY_LOCK="$LINUX_OVERLAY_DIR/series.lock"
    LINUX_VARIANT_SECTION="linux.variant.$LINUX_VARIANT"

    local overlay_series_sha overlay_tree overlay_manifest observed
    local overlay_base_tree overlay_base_manifest
    overlay_series_sha=$(linux_lock_value "$LINUX_SOURCE_LOCK" patch_series_sha256 "$LINUX_VARIANT_SECTION")
    overlay_base_tree=$(linux_lock_value "$LINUX_SOURCE_LOCK" base_tree_sha1 "$LINUX_VARIANT_SECTION")
    overlay_base_manifest=$(linux_lock_value "$LINUX_SOURCE_LOCK" base_manifest_sha256 "$LINUX_VARIANT_SECTION")
    overlay_tree=$(linux_lock_value "$LINUX_SOURCE_LOCK" patched_tree_sha1 "$LINUX_VARIANT_SECTION")
    overlay_manifest=$(linux_lock_value "$LINUX_SOURCE_LOCK" patched_manifest_sha256 "$LINUX_VARIANT_SECTION")
    require_hex "$overlay_series_sha" 64 "$LINUX_VARIANT overlay patch-series SHA-256"
    require_hex "$overlay_base_tree" 40 "$LINUX_VARIANT overlay base tree"
    require_hex "$overlay_base_manifest" 64 "$LINUX_VARIANT overlay base manifest"
    require_hex "$overlay_tree" 40 "$LINUX_VARIANT overlay patched tree"
    require_hex "$overlay_manifest" 64 "$LINUX_VARIANT overlay patched manifest"

    # The variant declares the tree it builds on, in the same file as the
    # default series' result. They have to be the same tree, or the overlay is
    # describing a base this build does not produce.
    [[ $overlay_base_tree == "$LINUX_BASE_PATCHED_TREE" ]] || \
        die "$LINUX_VARIANT overlay names a base tree the default series does not produce"
    [[ $overlay_base_manifest == "$LINUX_BASE_PATCHED_MANIFEST" ]] || \
        die "$LINUX_VARIANT overlay names a base manifest the default series does not produce"

    [[ -f $LINUX_OVERLAY_LOCK && ! -L $LINUX_OVERLAY_LOCK ]] || \
        die "$LINUX_VARIANT overlay lock is missing or not a regular file: $LINUX_OVERLAY_LOCK"
    observed=$(sha256sum "$LINUX_OVERLAY_LOCK" | awk '{print $1}')
    [[ $observed == "$overlay_series_sha" ]] || \
        die "$LINUX_VARIANT overlay patch-series lock SHA-256 mismatch"

    linux_load_series_file "$LINUX_OVERLAY_LOCK" "$LINUX_OVERLAY_DIR" \
        pocket-linux-patch-overlay-v1 base \
        "$LINUX_BASE_PATCHED_TREE" "$LINUX_BASE_PATCHED_MANIFEST" \
        "$overlay_tree" "$overlay_manifest"

    # From here on the published tree is the variant's, so every downstream
    # identity check compares against what this build will actually produce.
    LINUX_PATCHED_TREE=$overlay_tree
    LINUX_PATCHED_MANIFEST=$overlay_manifest
}

acquire_linux_pipeline_lock() {
    local build_root=$1
    local lock_dir="$build_root/locks" lock_path="$build_root/locks/linux-pipeline.lock"
    mkdir -p -- "$lock_dir"
    if [[ -n ${POCKET_LINUX_PIPELINE_LOCK_FD:-} ]]; then
        [[ $POCKET_LINUX_PIPELINE_LOCK_FD =~ ^[0-9]+$ ]] || die "invalid inherited Linux pipeline lock descriptor"
        local inherited_target
        inherited_target=$(readlink "/proc/$$/fd/$POCKET_LINUX_PIPELINE_LOCK_FD") || die "inherited Linux pipeline lock descriptor is closed"
        [[ $inherited_target == "$lock_path" ]] || die "inherited Linux pipeline lock targets the wrong file"
        flock -n "$POCKET_LINUX_PIPELINE_LOCK_FD" || die "inherited Linux pipeline lock is not held"
        return
    fi
    exec {POCKET_LINUX_PIPELINE_LOCK_FD}>"$lock_path"
    flock -x "$POCKET_LINUX_PIPELINE_LOCK_FD"
    export POCKET_LINUX_PIPELINE_LOCK_FD
}

isolated_git() {
    local tree=$1 metadata=$2
    shift 2
    env \
        HOME="$metadata/home" \
        XDG_CONFIG_HOME="$metadata/xdg" \
        GIT_CONFIG_NOSYSTEM=1 \
        GIT_ATTR_NOSYSTEM=1 \
        LC_ALL=C \
        TZ=UTC0 \
        git -C "$tree" --git-dir="$metadata/repository/.git" "$@"
}

initialize_source_index() {
    local tree=$1 metadata=$2 description=$3
    mkdir -p -- "$metadata/home" "$metadata/xdg" "$metadata/template"
    env HOME="$metadata/home" XDG_CONFIG_HOME="$metadata/xdg" GIT_CONFIG_NOSYSTEM=1 \
        git init --quiet --template="$metadata/template" "$metadata/repository"
    isolated_git "$tree" "$metadata" config core.autocrlf false
    isolated_git "$tree" "$metadata" config core.filemode true
    # Importing a kernel tree creates far more loose objects than the default
    # threshold, so the commit below would kick off a detached repack. This
    # repository is a throwaway used only to compute identities: there is
    # nothing to reclaim, and a background process still writing into it races
    # the staging directory's removal. Newer Git is more eager about this than
    # older, so it shows up as a build that fails on one host and not another.
    isolated_git "$tree" "$metadata" config gc.auto 0
    isolated_git "$tree" "$metadata" config maintenance.auto false
    isolated_git "$tree" "$metadata" add --all --force
    local tree_id
    tree_id=$(isolated_git "$tree" "$metadata" write-tree)
    env \
        GIT_AUTHOR_NAME=pocket-source-audit \
        GIT_AUTHOR_EMAIL=pocket-source-audit@invalid \
        GIT_COMMITTER_NAME=pocket-source-audit \
        GIT_COMMITTER_EMAIL=pocket-source-audit@invalid \
        GIT_AUTHOR_DATE="@$LINUX_SOURCE_DATE_EPOCH +0000" \
        GIT_COMMITTER_DATE="@$LINUX_SOURCE_DATE_EPOCH +0000" \
        HOME="$metadata/home" \
        XDG_CONFIG_HOME="$metadata/xdg" \
        GIT_CONFIG_NOSYSTEM=1 \
        GIT_ATTR_NOSYSTEM=1 \
        LC_ALL=C \
        TZ=UTC0 \
        git -C "$tree" --git-dir="$metadata/repository/.git" \
            -c commit.gpgSign=false commit --quiet --no-gpg-sign -m "$description"
    isolated_git "$tree" "$metadata" diff-index --quiet HEAD -- || \
        die "source worktree differs from its authenticated index immediately after import"
    printf '%s\n' "$tree_id"
}

source_blob_record() {
    local tree=$1 metadata=$2 path=$3
    local record
    record=$(isolated_git "$tree" "$metadata" ls-files --stage -- "$path")
    [[ $record =~ ^([0-9]{6})[[:space:]]([0-9a-f]{40})[[:space:]]0$'\t'(.+)$ ]] || \
        die "cannot resolve exact source blob for $path"
    [[ ${BASH_REMATCH[3]} == "$path" ]] || die "source blob path mismatch for $path"
    printf '%s %s\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
}

verify_source_blob() {
    local tree=$1 metadata=$2 path=$3 expected_mode=$4 expected_blob=$5 context=$6
    local observed
    observed=$(source_blob_record "$tree" "$metadata" "$path")
    [[ $observed == "$expected_mode $expected_blob" ]] || \
        die "$context blob mismatch for $path: observed $observed"
}

verify_source_tree_hygiene() {
    local tree=$1
    [[ -d $tree && ! -L $tree ]] || die "Linux source tree is missing or is a symlink: $tree"
    local forbidden
    forbidden=$(find "$tree" \( -name .git -o -name '*.orig' -o -name '*.rej' \) -print -quit)
    [[ -z $forbidden ]] || die "forbidden generated source entry: $forbidden"
    forbidden=$(find "$tree" ! -type f ! -type d ! -type l -print -quit)
    [[ -z $forbidden ]] || die "unsupported special source-tree entry: $forbidden"
    forbidden=$(find "$tree" -type d -empty -print -quit)
    [[ -z $forbidden ]] || die "unexpected empty source directory outside Git tree identity: $forbidden"
}

source_manifest_sha256() {
    local root=$1 tree=$2
    python3 "$root/scripts/hash-source-tree.py" "$tree"
}

verify_source_identity() {
    local root=$1 tree=$2 metadata=$3 expected_tree=$4 expected_manifest=$5 description=$6
    verify_source_tree_hygiene "$tree"
    local observed_tree observed_manifest
    observed_tree=$(initialize_source_index "$tree" "$metadata" "$description")
    [[ $observed_tree == "$expected_tree" ]] || \
        die "$description Git tree mismatch: observed $observed_tree"
    observed_manifest=$(source_manifest_sha256 "$root" "$tree")
    [[ $observed_manifest == "$expected_manifest" ]] || \
        die "$description filesystem manifest mismatch: observed $observed_manifest"
}

apply_locked_patch_series() {
    local tree=$1 metadata=$2
    local index patch_file path before_tree after_tree observed_tree
    local -a changed_paths=()
    for index in "${!LINUX_PATCH_FILES[@]}"; do
        patch_file="${LINUX_PATCH_DIRS[$index]}/${LINUX_PATCH_FILES[$index]}"
        path=${LINUX_PATCH_PATHS[$index]}
        verify_source_blob "$tree" "$metadata" "$path" \
            "${LINUX_PATCH_MODES[$index]}" "${LINUX_PATCH_PRE_BLOBS[$index]}" \
            "pre-patch ${LINUX_PATCH_FILES[$index]}"
        before_tree=$(isolated_git "$tree" "$metadata" write-tree)
        isolated_git "$tree" "$metadata" apply --check --index --whitespace=error-all "$patch_file"
        isolated_git "$tree" "$metadata" apply --index --whitespace=error-all "$patch_file"
        isolated_git "$tree" "$metadata" diff-files --quiet || \
            die "patch application left worktree and index inconsistent: ${LINUX_PATCH_FILES[$index]}"
        after_tree=$(isolated_git "$tree" "$metadata" write-tree)
        mapfile -t changed_paths < <(
            isolated_git "$tree" "$metadata" diff-tree --no-commit-id --name-only -r "$before_tree" "$after_tree"
        )
        [[ ${#changed_paths[@]} -eq 1 && ${changed_paths[0]} == "$path" ]] || \
            die "patch changed paths outside its lock: ${LINUX_PATCH_FILES[$index]}"
        verify_source_blob "$tree" "$metadata" "$path" \
            "${LINUX_PATCH_MODES[$index]}" "${LINUX_PATCH_POST_BLOBS[$index]}" \
            "post-patch ${LINUX_PATCH_FILES[$index]}"
        isolated_git "$tree" "$metadata" apply --check --reverse --index --whitespace=error-all "$patch_file"
        # With a variant selected, the default series still has to land on the
        # exact tree the overlay declares as its base, so the two locks are
        # verified as a chain rather than only at the end.
        if [[ -n ${LINUX_BASE_PATCH_COUNT:-} ]] && ((index + 1 == LINUX_BASE_PATCH_COUNT)); then
            observed_tree=$(isolated_git "$tree" "$metadata" write-tree)
            [[ $observed_tree == "$LINUX_BASE_PATCHED_TREE" ]] || \
                die "default patch series did not reproduce the tree $LINUX_VARIANT builds on: observed $observed_tree"
        fi
    done
    observed_tree=$(isolated_git "$tree" "$metadata" write-tree)
    [[ $observed_tree == "$LINUX_PATCHED_TREE" ]] || \
        die "patched Linux Git tree mismatch: observed $observed_tree"
}

audit_patch_series_reverse_forward() {
    local tree=$1 metadata=$2
    local index patch_file path observed_tree
    for ((index = ${#LINUX_PATCH_FILES[@]} - 1; index >= 0; index--)); do
        patch_file="${LINUX_PATCH_DIRS[$index]}/${LINUX_PATCH_FILES[$index]}"
        path=${LINUX_PATCH_PATHS[$index]}
        verify_source_blob "$tree" "$metadata" "$path" \
            "${LINUX_PATCH_MODES[$index]}" "${LINUX_PATCH_POST_BLOBS[$index]}" \
            "reverse-audit postimage ${LINUX_PATCH_FILES[$index]}"
        isolated_git "$tree" "$metadata" apply --check --cached --reverse --whitespace=error-all "$patch_file"
        isolated_git "$tree" "$metadata" apply --cached --reverse --whitespace=error-all "$patch_file"
        verify_source_blob "$tree" "$metadata" "$path" \
            "${LINUX_PATCH_MODES[$index]}" "${LINUX_PATCH_PRE_BLOBS[$index]}" \
            "reverse-audit preimage ${LINUX_PATCH_FILES[$index]}"
    done
    observed_tree=$(isolated_git "$tree" "$metadata" write-tree)
    [[ $observed_tree == "$LINUX_UPSTREAM_TREE" ]] || \
        die "reverse patch audit did not reproduce the upstream Git tree"

    for index in "${!LINUX_PATCH_FILES[@]}"; do
        patch_file="${LINUX_PATCH_DIRS[$index]}/${LINUX_PATCH_FILES[$index]}"
        path=${LINUX_PATCH_PATHS[$index]}
        isolated_git "$tree" "$metadata" apply --check --cached --whitespace=error-all "$patch_file"
        isolated_git "$tree" "$metadata" apply --cached --whitespace=error-all "$patch_file"
        verify_source_blob "$tree" "$metadata" "$path" \
            "${LINUX_PATCH_MODES[$index]}" "${LINUX_PATCH_POST_BLOBS[$index]}" \
            "forward-audit postimage ${LINUX_PATCH_FILES[$index]}"
    done
    observed_tree=$(isolated_git "$tree" "$metadata" write-tree)
    [[ $observed_tree == "$LINUX_PATCHED_TREE" ]] || \
        die "forward patch audit did not reproduce the patched Git tree"
}

cleanup_linux_staging() {
    local path=$1 expected_parent=$2 expected_prefix=$3
    [[ -n $path && $path == "$expected_parent/$expected_prefix"* && $path != "$expected_parent" ]] || \
        die "refusing to clean unexpected Linux staging path: $path"
    if [[ -e $path || -L $path ]]; then
        chmod -R u+w "$path" 2>/dev/null || true
        find "$path" -depth -delete
    fi
}

preserve_generated_tree() {
    local path=$1 recovery_dir=$2 label=$3
    PRESERVED_GENERATED_TREE=
    [[ -e $path || -L $path ]] || return 0
    mkdir -p -- "$recovery_dir"
    local timestamp destination
    timestamp=$(date -u +%Y%m%dT%H%M%SZ)
    destination="$recovery_dir/$label.replaced.$timestamp.$$"
    [[ ! -e $destination && ! -L $destination ]] || die "recovery destination already exists: $destination"
    mv -- "$path" "$destination"
    # shellcheck disable=SC2034
    PRESERVED_GENERATED_TREE=$destination
    printf 'preserved replaced generated tree: %s\n' "$destination" >&2
}
