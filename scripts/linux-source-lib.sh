#!/usr/bin/env bash

# Shared fail-closed Linux source identity helpers. Callers must source lib.sh
# first so `die`, `require_command`, and `safe_managed_root` are available.

# These globals are the deliberate interface exported to sourcing scripts.
# shellcheck disable=SC2034
LINUX_RELEASE=7.2
# shellcheck disable=SC2034
LINUX_SOURCE_NAME=linux-7.2

linux_lock_value() {
    local lock_file=$1 key=$2
    local -a matches=()
    mapfile -t matches < <(
        awk -v wanted="$key" '
            /^\[linux\]$/ { inside = 1; next }
            /^\[/ { if (inside) exit }
            inside && $0 ~ "^" wanted " = " { print; count++ }
            END { if (count != 1) exit 3 }
        ' "$lock_file"
    ) || die "missing or duplicate linux.$key in $lock_file"
    [[ ${#matches[@]} -eq 1 ]] || die "missing or duplicate linux.$key in $lock_file"

    local value=${matches[0]#*= }
    if [[ $value =~ ^\"([^\"]*)\"$ ]]; then
        printf '%s\n' "${BASH_REMATCH[1]}"
    elif [[ $value =~ ^[0-9]+$ ]]; then
        printf '%s\n' "$value"
    else
        die "linux.$key has an unsupported lock-file value"
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
}

load_linux_patch_series() {
    LINUX_PATCH_FILES=()
    LINUX_PATCH_HASHES=()
    LINUX_PATCH_PATHS=()
    LINUX_PATCH_MODES=()
    LINUX_PATCH_PRE_BLOBS=()
    LINUX_PATCH_POST_BLOBS=()
    local line_number=0 kind first second third fourth fifth sixth extra
    local series_upstream_tree='' series_upstream_manifest=''
    local series_patched_tree='' series_patched_manifest=''
    local -A seen_files=() seen_paths=()

    while IFS=$'\t' read -r kind first second third fourth fifth sixth extra || [[ -n $kind ]]; do
        ((line_number += 1))
        if ((line_number == 1)); then
            [[ $kind == pocket-linux-patch-series-v1 && -z ${first:-} ]] || \
                die "unsupported Linux patch-series schema"
            continue
        fi
        case "$kind" in
            upstream-tree)
                [[ -z $second && -z $extra && -z $series_upstream_tree ]] || die "malformed upstream-tree record"
                series_upstream_tree=$first
                ;;
            upstream-manifest)
                [[ -z $second && -z $extra && -z $series_upstream_manifest ]] || die "malformed upstream-manifest record"
                series_upstream_manifest=$first
                ;;
            patched-tree)
                [[ -z $second && -z $extra && -z $series_patched_tree ]] || die "malformed patched-tree record"
                series_patched_tree=$first
                ;;
            patched-manifest)
                [[ -z $second && -z $extra && -z $series_patched_manifest ]] || die "malformed patched-manifest record"
                series_patched_manifest=$first
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
                LINUX_PATCH_FILES+=("$first")
                LINUX_PATCH_HASHES+=("$second")
                LINUX_PATCH_PATHS+=("$third")
                LINUX_PATCH_MODES+=("$fourth")
                LINUX_PATCH_PRE_BLOBS+=("$fifth")
                LINUX_PATCH_POST_BLOBS+=("$sixth")
                ;;
            '') die "blank line in Linux patch-series lock" ;;
            *) die "unknown Linux patch-series record at line $line_number: $kind" ;;
        esac
    done < "$LINUX_SERIES_LOCK"

    [[ ${#LINUX_PATCH_FILES[@]} -gt 0 ]] || die "Linux patch-series lock contains no patches"
    [[ $series_upstream_tree == "$LINUX_UPSTREAM_TREE" ]] || die "patch lock upstream tree mismatch"
    [[ $series_upstream_manifest == "$LINUX_UPSTREAM_MANIFEST" ]] || die "patch lock upstream manifest mismatch"
    [[ $series_patched_tree == "$LINUX_PATCHED_TREE" ]] || die "patch lock patched tree mismatch"
    [[ $series_patched_manifest == "$LINUX_PATCHED_MANIFEST" ]] || die "patch lock patched manifest mismatch"

    local -a disk_patches=()
    mapfile -t disk_patches < <(find "$LINUX_PATCH_DIR" -maxdepth 1 -type f -name '*.patch' -printf '%f\n' | LC_ALL=C sort)
    [[ ${#disk_patches[@]} -eq ${#LINUX_PATCH_FILES[@]} ]] || die "unlocked or missing Linux patch file"
    local index patch_sha
    for index in "${!LINUX_PATCH_FILES[@]}"; do
        [[ ${disk_patches[$index]} == "${LINUX_PATCH_FILES[$index]}" ]] || die "Linux patch order/file set differs from series.lock"
        patch_sha=$(sha256sum "$LINUX_PATCH_DIR/${LINUX_PATCH_FILES[$index]}" | awk '{print $1}')
        [[ $patch_sha == "${LINUX_PATCH_HASHES[$index]}" ]] || die "Linux patch SHA-256 mismatch: ${LINUX_PATCH_FILES[$index]}"
    done
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
        patch_file="$LINUX_PATCH_DIR/${LINUX_PATCH_FILES[$index]}"
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
    done
    observed_tree=$(isolated_git "$tree" "$metadata" write-tree)
    [[ $observed_tree == "$LINUX_PATCHED_TREE" ]] || \
        die "patched Linux Git tree mismatch: observed $observed_tree"
}

audit_patch_series_reverse_forward() {
    local tree=$1 metadata=$2
    local index patch_file path observed_tree
    for ((index = ${#LINUX_PATCH_FILES[@]} - 1; index >= 0; index--)); do
        patch_file="$LINUX_PATCH_DIR/${LINUX_PATCH_FILES[$index]}"
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
        patch_file="$LINUX_PATCH_DIR/${LINUX_PATCH_FILES[$index]}"
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
