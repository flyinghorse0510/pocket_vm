#!/usr/bin/env bash

# Guest-shell programs are deliberately single-quoted so the host shell cannot
# expand their variables or command substitutions.
# shellcheck disable=SC2016

# shellcheck source=scripts/lib.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"

export LC_ALL=C

ROOT=$(project_root)
BUILD_ROOT=${POCKET_BUILD_ROOT:-"$ROOT/build"}
PROFILE_INPUT=${1:-${POCKET_PROFILE_BUNDLE:-}}
if [[ -n ${POCKET_BIN:-} ]]; then
    BUILD_POCKET=0
else
    POCKET_BIN="$ROOT/target/release/pocket"
    BUILD_POCKET=1
fi

[[ -n "$PROFILE_INPUT" ]] || \
    die "usage: scripts/run-rust-release-e2e.sh ABSOLUTE_PROFILE_BUNDLE"

for command in awk cargo cmp find grep jq mkdir mktemp readlink sed sha256sum stat tr; do
    require_command "$command"
done

PROFILE_BUNDLE=$(readlink -e -- "$PROFILE_INPUT")
[[ -n "$PROFILE_BUNDLE" && -d "$PROFILE_BUNDLE" ]] || \
    die "profile bundle does not exist: $PROFILE_INPUT"
[[ "$PROFILE_BUNDLE" == "$PROFILE_INPUT" ]] || \
    die "profile bundle must be an absolute canonical path: $PROFILE_INPUT"
safe_managed_root "$BUILD_ROOT"
safe_managed_root "$PROFILE_BUNDLE"

if (( BUILD_POCKET == 1 )); then
    cargo build --locked --release -p pocket --manifest-path "$ROOT/Cargo.toml"
fi
[[ -x "$POCKET_BIN" && ! -L "$POCKET_BIN" ]] || \
    die "Pocket release executable is missing or a symlink: $POCKET_BIN"

if [[ -n ${POCKET_E2E_WORK_ROOT:-} ]]; then
    WORK_ROOT=$POCKET_E2E_WORK_ROOT
    safe_managed_root "$WORK_ROOT"
    [[ ! -e "$WORK_ROOT" ]] || die "explicit E2E work root already exists: $WORK_ROOT"
    mkdir -m 0700 -- "$WORK_ROOT"
else
    mkdir -p -- "$BUILD_ROOT/e2e"
    # The product deliberately gives UML an operation-local directory rather
    # than falling back to ~/.uml.  Keep the generated test prefix short enough
    # that the later build-<32 hex>/uml and run-<32 hex>/uml paths still fit the
    # sealed profile's AF_UNIX boundary.
    WORK_ROOT=$(mktemp -d "$BUILD_ROOT/e2e/e.XXXXXXXX")
fi

STORE="$WORK_ROOT/store"
RUNTIME_ROOT="$WORK_ROOT/runtime"
LOG_ROOT="$WORK_ROOT/logs"

MAX_UNIX_PATH_BYTES=$(jq -er \
    '.launch.max_unix_path_bytes |
     select(type == "number" and floor == . and . >= 1)' \
    "$PROFILE_BUNDLE/profile.json") || \
    die "profile has no valid launch.max_unix_path_bytes"
WORST_OPERATION_UML_DIR="$RUNTIME_ROOT/build-00000000000000000000000000000000/uml"
if (( ${#WORST_OPERATION_UML_DIR} > MAX_UNIX_PATH_BYTES )); then
    die "E2E runtime root cannot fit a generated UML operation path: $RUNTIME_ROOT"
fi
mkdir -m 0700 -- "$RUNTIME_ROOT" "$LOG_ROOT"

printf 'e2e_work_root=%s\n' "$WORK_ROOT"
printf 'profile_bundle=%s\n' "$PROFILE_BUNDLE"
printf 'pocket_sha256=%s\n' "$(sha256sum "$POCKET_BIN" | awk '{print $1}')"

assert_exact_output() {
    local file=$1
    local expected=$2

    if ! cmp -s -- "$file" <(printf '%s' "$expected"); then
        printf 'expected output:\n%s' "$expected" >&2
        printf 'observed output from %s:\n' "$file" >&2
        sed -n '1,160p' "$file" >&2
        die "unexpected workload output"
    fi
}

run_guest() {
    local version=$1
    local generation=$2
    local label=$3
    local expected_status=$4
    shift 4
    local -a options=()
    local -a command=()
    local user=0:0
    local execution_timeout=180s

    while (( $# > 0 )) && [[ $1 != -- ]]; do
        if [[ $1 == --user ]]; then
            (( $# >= 2 )) || die "internal E2E error: missing --user value for $label"
            user=$2
            shift 2
        elif [[ $1 == --timeout ]]; then
            (( $# >= 2 )) || die "internal E2E error: missing --timeout value for $label"
            execution_timeout=$2
            shift 2
        else
            options+=("$1")
            shift
        fi
    done
    [[ ${1:-} == -- ]] || die "internal E2E error: missing command separator for $label"
    shift
    command=("$@")
    (( ${#command[@]} > 0 )) || die "internal E2E error: empty command for $label"

    local stdout="$LOG_ROOT/$version-$label.stdout"
    local stderr="$LOG_ROOT/$version-$label.stderr"
    local status
    if "$POCKET_BIN" run \
        --profile-bundle "$PROFILE_BUNDLE" \
        --store "$STORE" \
        --runtime-root "$RUNTIME_ROOT" \
        --platform linux/amd64 \
        --user "$user" \
        --timeout "$execution_timeout" \
        "${options[@]}" \
        "$generation" -- "${command[@]}" \
        >"$stdout" 2>"$stderr"
    then
        status=0
    else
        status=$?
    fi
    if (( status != expected_status )); then
        printf 'stdout (%s):\n' "$stdout" >&2
        sed -n '1,200p' "$stdout" >&2
        printf 'stderr (%s):\n' "$stderr" >&2
        sed -n '1,240p' "$stderr" >&2
        die "$version $label returned $status, expected $expected_status"
    fi
}

# Feed an exact payload on standard input and check the workload's output.
# `label` keeps each case's transcript, and `guest_program` decides whether the
# case needs end-of-file: a case that only reads one line proves nothing about
# the exact-length contract, because dash's `read` returns on the newline.
run_stdin_case() {
    local version=$1
    local generation=$2
    local label=$3
    local payload_file=$4
    local guest_program=$5
    local expected=$6
    local stdout="$LOG_ROOT/$version-$label.stdout"
    local stderr="$LOG_ROOT/$version-$label.stderr"
    local status

    if "$POCKET_BIN" run \
        --profile-bundle "$PROFILE_BUNDLE" \
        --store "$STORE" \
        --runtime-root "$RUNTIME_ROOT" \
        --platform linux/amd64 \
        --user 0:0 \
        --timeout 180s \
        -i \
        "$generation" -- \
        /bin/sh -c "$guest_program" \
        <"$payload_file" >"$stdout" 2>"$stderr"
    then
        status=0
    else
        status=$?
    fi
    if (( status != 0 )); then
        sed -n '1,200p' "$stderr" >&2
        die "$version $label stdin transport returned $status"
    fi
    assert_exact_output "$stdout" "$expected"
}

# Every assertion below fails if the guest stops ending standard input after
# exactly the announced byte count, or truncates/duplicates the payload.
assert_exact_stdin_contract() {
    local version=$1
    local generation=$2
    local work="$WORK_ROOT/stdin"
    local digest

    [[ -d "$work" ]] || mkdir -m 0700 -- "$work"

    # Empty: the workload must observe an immediate end-of-file, not a hang.
    : >"$work/empty"
    run_stdin_case "$version" "$generation" stdin-empty "$work/empty" \
        'wc -c' $'0\n'

    # No trailing newline: the terminator is the announced count, not a line.
    printf 'no-trailing-newline' >"$work/partial-line"
    run_stdin_case "$version" "$generation" stdin-partial-line "$work/partial-line" \
        'cat; printf "|%s\n" "$(wc -c </dev/null)"' 'no-trailing-newline|0'$'\n'

    # Multi-megabyte payload: read to end-of-file and compare a digest computed
    # inside the guest, so truncation or duplication cannot pass.
    head -c 3000000 /dev/urandom >"$work/bulk"
    digest=$(sha256sum "$work/bulk" | awk '{print $1}')
    run_stdin_case "$version" "$generation" stdin-bulk "$work/bulk" \
        'sha256sum | cut -d" " -f1' "$digest"$'\n'

    # A workload that never reads must not stall the host's bounded write.
    run_stdin_case "$version" "$generation" stdin-unread "$work/bulk" \
        'exec true' ''
}

# Run with no command at all, so Entrypoint and Cmd must come from the image's
# own authenticated config rather than from the command line.
run_image_defaults() {
    local version=$1
    local generation=$2
    local stdout="$LOG_ROOT/$version-image-defaults.stdout"
    local stderr="$LOG_ROOT/$version-image-defaults.stderr"
    local status

    if "$POCKET_BIN" run \
        --profile-bundle "$PROFILE_BUNDLE" \
        --store "$STORE" \
        --runtime-root "$RUNTIME_ROOT" \
        --platform linux/amd64 \
        --timeout 180s \
        "$generation" \
        >"$stdout" 2>"$stderr"
    then
        status=0
    else
        status=$?
    fi
    if (( status != 0 )); then
        sed -n '1,200p' "$stderr" >&2
        die "$version image defaults returned $status"
    fi
    # Ubuntu's Cmd is an interactive shell; with no input it exits cleanly and
    # silently. An unresolved Cmd would instead fail before launch.
    assert_exact_output "$stdout" ''
}

run_stdin_guest() {
    local version=$1
    local generation=$2
    local input=$3
    local stdout="$LOG_ROOT/$version-stdin.stdout"
    local stderr="$LOG_ROOT/$version-stdin.stderr"
    local status

    if printf '%s' "$input" | "$POCKET_BIN" run \
        --profile-bundle "$PROFILE_BUNDLE" \
        --store "$STORE" \
        --runtime-root "$RUNTIME_ROOT" \
        --platform linux/amd64 \
        --user 0:0 \
        --timeout 180s \
        -i \
        "$generation" -- \
        /bin/sh -c 'IFS= read -r line; printf "stdin=%s\n" "$line"' \
        >"$stdout" 2>"$stderr"
    then
        status=0
    else
        status=$?
    fi
    if (( status != 0 )); then
        sed -n '1,200p' "$stderr" >&2
        die "$version stdin transport returned $status"
    fi
    assert_exact_output "$stdout" "stdin=$input"
}

import_image() {
    local version=$1
    local layout="$BUILD_ROOT/oci/ubuntu-$version"
    local output="$LOG_ROOT/$version-import.json"
    local stderr="$LOG_ROOT/$version-import.stderr"

    [[ -d "$layout" && ! -L "$layout" ]] || \
        die "canonical Ubuntu $version OCI layout is missing: $layout"
    "$POCKET_BIN" image import \
        --profile-bundle "$PROFILE_BUNDLE" \
        --store "$STORE" \
        --runtime-root "$RUNTIME_ROOT" \
        --reference "ubuntu:$version" \
        --platform linux/amd64 \
        --oci "$layout" \
        --json >"$output" 2>"$stderr" || {
            sed -n '1,240p' "$stderr" >&2
            die "Ubuntu $version import failed"
        }

    jq -er '.generation_id | select(test("^pkvm-gen-v1-[0-9a-f]{64}$"))' "$output"
}

assert_cache_hit() {
    local version=$1
    local expected_generation=$2
    local layout="$BUILD_ROOT/oci/ubuntu-$version"
    local output="$LOG_ROOT/$version-cache-hit.json"
    local stderr="$LOG_ROOT/$version-cache-hit.stderr"

    "$POCKET_BIN" image import \
        --profile-bundle "$PROFILE_BUNDLE" \
        --store "$STORE" \
        --runtime-root "$RUNTIME_ROOT" \
        --reference "ubuntu:$version" \
        --platform linux/amd64 \
        --oci "$layout" \
        --json >"$output" 2>"$stderr" || {
            sed -n '1,200p' "$stderr" >&2
            die "Ubuntu $version cache-hit import failed"
        }
    jq -e --arg generation "$expected_generation" \
        '.cache_hit == true and .generation_id == $generation' "$output" >/dev/null || \
        die "Ubuntu $version repeated import was not an exact cache hit"
}

assert_concurrent_cow_isolation() {
    local generation=$1
    local a_out="$LOG_ROOT/24.04-concurrent-a.stdout"
    local a_err="$LOG_ROOT/24.04-concurrent-a.stderr"
    local b_out="$LOG_ROOT/24.04-concurrent-b.stdout"
    local b_err="$LOG_ROOT/24.04-concurrent-b.stderr"
    local a_pid b_pid a_status b_status
    local -a common=(
        run
        --profile-bundle "$PROFILE_BUNDLE"
        --store "$STORE"
        --runtime-root "$RUNTIME_ROOT"
        --platform linux/amd64
        --user 0:0
        --timeout 180s
        "$generation"
        --
        /bin/sh -c
    )

    # Each run writes its own marker and then requires both that its own
    # survived and that the other's never appeared. Every step is chained with
    # && so a failed step decides the exit status: a bare `test` in a `;` list
    # is discarded by the command after it, which silently threw away the only
    # check that actually proves isolation. Distinct filenames and a check at
    # the end of both runs make the absence assertion hold at any boot skew,
    # rather than depending on which guest reaches its first command first.
    "$POCKET_BIN" "${common[@]}" \
        'printf "A\n" > /pocket-concurrent-a &&
         sleep 3 &&
         grep -qx A /pocket-concurrent-a &&
         test ! -e /pocket-concurrent-b' \
        >"$a_out" 2>"$a_err" &
    a_pid=$!
    "$POCKET_BIN" "${common[@]}" \
        'printf "B\n" > /pocket-concurrent-b &&
         sleep 3 &&
         grep -qx B /pocket-concurrent-b &&
         test ! -e /pocket-concurrent-a' \
        >"$b_out" 2>"$b_err" &
    b_pid=$!

    if wait "$a_pid"; then a_status=0; else a_status=$?; fi
    if wait "$b_pid"; then b_status=0; else b_status=$?; fi
    if (( a_status != 0 || b_status != 0 )); then
        sed -n '1,200p' "$a_err" >&2
        sed -n '1,200p' "$b_err" >&2
        die "concurrent COW isolation failed: run-a=$a_status run-b=$b_status"
    fi
}

assert_archive_normalization() {
    local version=$1
    local canonical_generation=$2
    local layout="$BUILD_ROOT/oci/ubuntu-$version"
    local archives="$WORK_ROOT/archives"
    local oci_archive="$archives/ubuntu-$version.oci.tar"
    local docker_archive="$archives/ubuntu-$version.docker.tar"
    local output stderr generation

    [[ -d "$archives" ]] || mkdir -m 0700 -- "$archives"
    # Local layout-to-archive copies must not consult the ambient host trust
    # policy or temporary directory: the product's own acquisition path passes
    # --insecure-policy for exactly the same reason.
    [[ -d "$archives/tmp" ]] || mkdir -m 0700 -- "$archives/tmp"
    for transport in "oci-archive:$oci_archive" \
                     "docker-archive:$docker_archive:pocket/ubuntu:$version"; do
        env -i PATH=/usr/bin:/bin TMPDIR="$archives/tmp" LC_ALL=C \
            "$PROFILE_BUNDLE/host/skopeo" --insecure-policy copy \
            "oci:$layout:root" "$transport" \
            >"$LOG_ROOT/$version-archive-copy.stdout" \
            2>"$LOG_ROOT/$version-archive-copy.stderr" || {
                sed -n '1,120p' "$LOG_ROOT/$version-archive-copy.stderr" >&2
                die "could not produce $transport for Ubuntu $version"
            }
    done

    # A single-image OCI archive is the same authenticated content as the
    # canonical layout, so it must normalize to the identical generation and
    # reuse it rather than rebuild.
    output="$LOG_ROOT/$version-oci-archive-import.json"
    stderr="$LOG_ROOT/$version-oci-archive-import.stderr"
    "$POCKET_BIN" image import \
        --profile-bundle "$PROFILE_BUNDLE" \
        --store "$STORE" \
        --runtime-root "$RUNTIME_ROOT" \
        --reference "ubuntu-oci-archive:$version" \
        --platform linux/amd64 \
        --oci-archive "$oci_archive" \
        --json >"$output" 2>"$stderr" || {
            sed -n '1,240p' "$stderr" >&2
            die "Ubuntu $version OCI-archive import failed"
        }
    jq -e --arg generation "$canonical_generation" \
        '.generation_id == $generation and .cache_hit == true' \
        "$output" >/dev/null || \
        die "Ubuntu $version OCI archive did not reuse the canonical generation"

    # A Docker save archive carries a different manifest schema, so it is a
    # distinct authenticated input that must build and run on its own.
    output="$LOG_ROOT/$version-docker-archive-import.json"
    stderr="$LOG_ROOT/$version-docker-archive-import.stderr"
    "$POCKET_BIN" image import \
        --profile-bundle "$PROFILE_BUNDLE" \
        --store "$STORE" \
        --runtime-root "$RUNTIME_ROOT" \
        --reference "ubuntu-docker-archive:$version" \
        --platform linux/amd64 \
        --docker-archive "$docker_archive" \
        --json >"$output" 2>"$stderr" || {
            sed -n '1,240p' "$stderr" >&2
            die "Ubuntu $version Docker-archive import failed"
        }
    generation=$(jq -er '.generation_id | select(test("^pkvm-gen-v1-[0-9a-f]{64}$"))' "$output")
    run_guest "$version" "$generation" docker-archive-run 0 -- \
        /bin/sh -c '. /etc/os-release; printf "%s\n" "$VERSION_ID"'
    assert_exact_output "$LOG_ROOT/$version-docker-archive-run.stdout" "$version"$'\n'

    # `tar -cf archive.tar -C layout .` is how an oci-archive gets built by
    # hand, and it names every member `./index.json`. That is the same archive
    # skopeo reads, so it must normalize to the same canonical generation.
    local dot_archive="$archives/ubuntu-$version.dot.oci.tar"
    local dot_layout="$archives/ubuntu-$version.dot.d"
    rm -rf -- "$dot_archive" "$dot_layout"
    mkdir -m 0700 -- "$dot_layout"
    tar -xf "$oci_archive" -C "$dot_layout"
    # tar's own default format, exactly as a person would type it.
    tar --sort=name --numeric-owner --owner=0 --group=0 \
        --mtime="@$(pocket_source_date_epoch)" -cf "$dot_archive" -C "$dot_layout" .
    tar -tf "$dot_archive" | grep -qx './index.json' || \
        die "the ./-prefixed fixture does not actually carry ./-prefixed members"
    output="$LOG_ROOT/$version-dot-archive-import.json"
    stderr="$LOG_ROOT/$version-dot-archive-import.stderr"
    "$POCKET_BIN" image import \
        --profile-bundle "$PROFILE_BUNDLE" \
        --store "$STORE" \
        --runtime-root "$RUNTIME_ROOT" \
        --reference "ubuntu-dot-archive:$version" \
        --platform linux/amd64 \
        --oci-archive "$dot_archive" \
        --json >"$output" 2>"$stderr" || {
            sed -n '1,240p' "$stderr" >&2
            die "Ubuntu $version ./-prefixed OCI-archive import failed"
        }
    jq -e --arg generation "$canonical_generation" \
        '.generation_id == $generation and .cache_hit == true' \
        "$output" >/dev/null || \
        die "Ubuntu $version ./-prefixed archive did not reuse the canonical generation"
}

# Two conversions of one image must agree on everything the system
# authenticates. The guest clock keeps running during a conversion, so the raw
# ext4 bytes still differ in inode ctime/crtime and journal records and the
# generation IDs differ with them -- but nothing the manifest, the account
# database or the image config records may depend on when the conversion ran.
# A published generation is sealed: mode 0500 directories holding mode 0400
# files. Removing one needs write permission on the directories that hold the
# entries, so restore that first rather than let `rm` fail entry by entry.
remove_sealed_tree() {
    local tree=$1

    [[ -e "$tree" ]] || return 0
    find "$tree" -type d -exec chmod u+rwx -- {} + 2>/dev/null || true
    find "$tree" -type f -exec chmod u+w -- {} + 2>/dev/null || true
    rm -rf -- "$tree"
}

assert_conversion_metadata_is_deterministic() {
    local version=$1
    local first=$2
    local layout="$BUILD_ROOT/oci/ubuntu-$version"
    local second_store="$WORK_ROOT/store-repeat"
    local output="$LOG_ROOT/$version-repeat-import.json"
    local stderr="$LOG_ROOT/$version-repeat-import.stderr"
    local second sidecar

    remove_sealed_tree "$second_store"
    "$POCKET_BIN" image import \
        --profile-bundle "$PROFILE_BUNDLE" \
        --store "$second_store" \
        --runtime-root "$RUNTIME_ROOT" \
        --reference "ubuntu:$version" \
        --platform linux/amd64 \
        --oci "$layout" \
        --json >"$output" 2>"$stderr" || {
            sed -n '1,240p' "$stderr" >&2
            die "Ubuntu $version repeat conversion failed"
        }
    second=$(jq -er '.generation_id' "$output")
    for sidecar in metadata.manifest accounts.cbor image-config.json; do
        cmp -s -- "$STORE/generations/$first/$sidecar" \
                  "$second_store/generations/$second/$sidecar" || \
            die "Ubuntu $version repeat conversion changed $sidecar"
    done
    remove_sealed_tree "$second_store"
}

# An alias is the only thing that roots a generation, it outlives the profile
# that created it, and reconstructing its key needs that bundle. Without a way
# to see and drop one by its own ID, a resealed profile's aliases root their
# generations permanently and collection can never reclaim the space.
assert_alias_roots_can_be_released() {
    local doomed_generation=$1
    local doomed_reference=$2
    local alias_id output

    output="$LOG_ROOT/cache-roots.json"
    "$POCKET_BIN" cache roots --store "$STORE" --json >"$output" || \
        die "cache roots failed"
    alias_id=$(jq -er --arg reference "$doomed_reference" \
        '.roots[] | select(.reference == $reference) | .alias_id' "$output") || \
        die "cache roots does not list the alias for $doomed_reference"
    jq -e --arg generation "$doomed_generation" --arg alias "$alias_id" \
        '[.roots[] | select(.alias_id == $alias)] |
         length == 1 and .[0].generation_id == $generation and
         .[0].profile_id == "x86_64-smp-p4k" and .[0].platform == "linux/amd64"' \
        "$output" >/dev/null || die "cache roots misreports the alias for $doomed_reference"

    # Rooted, so a collection must leave it exactly where it is.
    "$POCKET_BIN" cache gc --store "$STORE" --apply --json \
        >"$LOG_ROOT/cache-gc-rooted.json" || die "rooted collection failed"
    jq -e --arg generation "$doomed_generation" \
        '(.collected | index($generation) | not) and (.rooted | index($generation))' \
        "$LOG_ROOT/cache-gc-rooted.json" >/dev/null || \
        die "a rooted generation was not protected"

    "$POCKET_BIN" cache forget --store "$STORE" --alias "$alias_id" \
        >"$LOG_ROOT/cache-forget.txt" || die "cache forget failed"
    grep -Fqx "alias=$alias_id removed=true" "$LOG_ROOT/cache-forget.txt" || \
        die "cache forget did not report the removal"
    # Forgetting again is not an error, and says so.
    "$POCKET_BIN" cache forget --store "$STORE" --alias "$alias_id" \
        >"$LOG_ROOT/cache-forget-again.txt" || die "repeated cache forget failed"
    grep -Fqx "alias=$alias_id removed=false" "$LOG_ROOT/cache-forget-again.txt" || \
        die "repeated cache forget did not report an absent alias"

    "$POCKET_BIN" cache gc --store "$STORE" --apply --json \
        >"$LOG_ROOT/cache-gc-unrooted.json" || die "unrooted collection failed"
    jq -e --arg generation "$doomed_generation" '.collected | index($generation)' \
        "$LOG_ROOT/cache-gc-unrooted.json" >/dev/null || \
        die "the unrooted generation was not reclaimed"
    [[ ! -e "$STORE/generations/$doomed_generation" ]] || \
        die "the reclaimed generation is still on disk"
}

# A signal-killed pocket never runs its cleanup, so the operation directory it
# owned has to be reclaimed by the next one rather than accumulate forever.
assert_signal_killed_runs_are_reclaimed() {
    local generation=$1
    local victim_root="$WORK_ROOT/reclaim-runtime"
    local before after

    rm -rf -- "$victim_root"
    mkdir -m 0700 -- "$victim_root"
    "$POCKET_BIN" run \
        --profile-bundle "$PROFILE_BUNDLE" --store "$STORE" \
        --runtime-root "$victim_root" --timeout 120s \
        "$generation" -- /bin/sh -c 'printf "ready\n"; sleep 60' \
        >"$LOG_ROOT/reclaim-victim.stdout" 2>"$LOG_ROOT/reclaim-victim.stderr" &
    local victim=$!
    # Stop waiting the moment the victim dies. Spinning the full 60 s and then
    # blaming directory creation would hide the real cause, which is sitting in
    # the stderr this harness captured and would otherwise never print.
    local waited=0
    while (( waited < 600 )) &&
          ! find "$victim_root" -mindepth 1 -maxdepth 1 -name 'run-*' -print -quit | grep -q .
    do
        if ! kill -0 "$victim" 2>/dev/null; then
            wait "$victim" 2>/dev/null || true
            sed -n '1,80p' "$LOG_ROOT/reclaim-victim.stderr" >&2
            die "the victim run exited before it created an operation directory"
        fi
        waited=$((waited + 1))
        sleep 0.1
    done
    before=$(find "$victim_root" -mindepth 1 -maxdepth 1 -name 'run-*' | wc -l)
    (( before == 1 )) || {
        sed -n '1,80p' "$LOG_ROOT/reclaim-victim.stderr" >&2
        die "the victim run did not create exactly one operation directory"
    }
    kill -KILL "$victim" 2>/dev/null || true
    wait "$victim" 2>/dev/null || true
    # SIGKILL leaves it behind by construction: nothing can run on the way out.
    (( $(find "$victim_root" -mindepth 1 -maxdepth 1 -name 'run-*' | wc -l) == 1 )) || \
        die "the killed run's directory disappeared without a sweep"

    "$POCKET_BIN" run \
        --profile-bundle "$PROFILE_BUNDLE" --store "$STORE" \
        --runtime-root "$victim_root" --timeout 120s \
        "$generation" -- /bin/true \
        >"$LOG_ROOT/reclaim-sweeper.stdout" 2>"$LOG_ROOT/reclaim-sweeper.stderr" || {
            sed -n '1,120p' "$LOG_ROOT/reclaim-sweeper.stderr" >&2
            die "the sweeping run failed"
        }
    after=$(find "$victim_root" -mindepth 1 -maxdepth 1 -name 'run-*' | wc -l)
    (( after == 0 )) || {
        find "$victim_root" -mindepth 1 -maxdepth 2 -printf '%M %p\n' >&2
        die "an abandoned run directory survived the next run"
    }
    rm -rf -- "$victim_root"
}

assert_no_live_operation_process() {
    local cmdline command_text

    for cmdline in /proc/[0-9]*/cmdline; do
        [[ -r "$cmdline" ]] || continue
        command_text=$(tr '\0' ' ' <"$cmdline" 2>/dev/null || true)
        if [[ "$command_text" == *"$WORK_ROOT"* ]]; then
            printf 'live process still references E2E root: %s: %s\n' \
                "$cmdline" "$command_text" >&2
            return 1
        fi
    done
}

declare -A GENERATIONS=()
declare -A BASE_HASHES=()

for version in 24.04 26.04; do
    generation=$(import_image "$version")
    GENERATIONS[$version]=$generation
    generation_dir="$STORE/generations/$generation"
    base="$generation_dir/base.ext4"
    [[ -f "$base" && ! -L "$base" ]] || die "missing immutable base for $generation"
    [[ $(stat -c '%a' "$generation_dir") == 500 ]] || \
        die "generation is not sealed mode 0500: $generation_dir"
    BASE_HASHES[$version]=$(sha256sum "$base" | awk '{print $1}')
    build_record="$generation_dir/build-record.json"
    validation_evidence="$generation_dir/validation-evidence.cbor"
    [[ -f "$build_record" && ! -L "$build_record" ]] || \
        die "Ubuntu $version generation lacks its immutable build record"
    [[ -f "$validation_evidence" && ! -L "$validation_evidence" ]] || \
        die "Ubuntu $version generation lacks independent validator evidence"
    [[ $(stat -c '%a' "$build_record") == 400 && \
       $(stat -c '%a' "$validation_evidence") == 400 ]] || \
        die "Ubuntu $version validation evidence is not sealed mode 0400"
    jq -e \
        --arg digest "sha256:${BASE_HASHES[$version]}" \
        --argjson bytes "$(stat -c '%s' "$base")" \
        '.schema == "pocket-build-record-v4" and
         .base_sha256 == $digest and
         .base_size == $bytes and
         .validation.protocol == "fresh-read-only-uml-challenge-evidence-v1" and
         .validation.filesystem_bytes == $bytes and
         .validation.clean_before_mount == true and
         .validation.block_device_read_only == true and
         .validation.mounted_read_only == true and
         .validation.unmounted == true and
         .validation.clean_after_unmount == true' \
        "$build_record" >/dev/null || \
        die "Ubuntu $version independent validation evidence is incomplete or inconsistent"

    run_guest "$version" "$generation" version 0 -- \
        /bin/sh -c '. /etc/os-release; printf "%s\n" "$VERSION_ID"'
    assert_exact_output "$LOG_ROOT/$version-version.stdout" "$version"$'\n'

    run_guest "$version" "$generation" streams 0 -- \
        /bin/sh -c 'printf "stdout\n"; printf "stderr\n" >&2'
    assert_exact_output "$LOG_ROOT/$version-streams.stdout" $'stdout\n'
    assert_exact_output "$LOG_ROOT/$version-streams.stderr" $'stderr\n'

    run_stdin_guest "$version" "$generation" "ubuntu-$version"$'\n'
    assert_exact_output "$LOG_ROOT/$version-stdin.stdout" "stdin=ubuntu-$version"$'\n'
    assert_exact_stdin_contract "$version" "$generation"

    run_image_defaults "$version" "$generation"
    # The default working directory also comes from the image config.
    run_guest "$version" "$generation" default-workdir 0 --entrypoint /bin/sh -- -c 'pwd'
    assert_exact_output "$LOG_ROOT/$version-default-workdir.stdout" $'/\n'

    # Guest physical memory is exercised through the complete workload, not just
    # a boot probe: the workload itself reports what the kernel accepted.
    for memory in 64M:67108864 256M:268435456 4G:4294967296; do
        run_guest "$version" "$generation" "memory-${memory%%:*}" 0 \
            --memory "${memory%%:*}" -- /bin/cat /proc/uml_physmem_bytes
        assert_exact_output "$LOG_ROOT/$version-memory-${memory%%:*}.stdout" \
            "${memory##*:}"$'\n'
    done

    run_guest "$version" "$generation" cpus-one 0 --cpus 1 -- /usr/bin/nproc
    assert_exact_output "$LOG_ROOT/$version-cpus-one.stdout" $'1\n'
    run_guest "$version" "$generation" cpus-four 0 --cpus 4 -- /usr/bin/nproc
    assert_exact_output "$LOG_ROOT/$version-cpus-four.stdout" $'4\n'

    run_guest "$version" "$generation" nonroot 0 --user 65534:65534 -- /usr/bin/id -u
    assert_exact_output "$LOG_ROOT/$version-nonroot.stdout" $'65534\n'

    # mknod() subtracts the process umask, so the curated device nodes have to
    # be given their exact modes afterwards. A 0644 /dev/null makes every
    # non-root workload that redirects to it fail.
    run_guest "$version" "$generation" dev-modes 0 -- \
        /bin/sh -c 'stat -c "%n %A" /dev/null /dev/zero /dev/full /dev/random /dev/urandom /dev/tty'
    assert_exact_output "$LOG_ROOT/$version-dev-modes.stdout" \
"/dev/null crw-rw-rw-
/dev/zero crw-rw-rw-
/dev/full crw-rw-rw-
/dev/random crw-rw-rw-
/dev/urandom crw-rw-rw-
/dev/tty crw-rw-rw-
"
    run_guest "$version" "$generation" dev-nonroot-write 0 --user 65534:65534 -- \
        /bin/sh -c 'echo discarded > /dev/null && printf "wrote\n"'
    assert_exact_output "$LOG_ROOT/$version-dev-nonroot-write.stdout" $'wrote\n'

    # A requested console transcript has to exist, be owner-only, and hold the
    # kernel's own boot output. A flag that quietly writes nothing is worse
    # than no flag: the evidence is missing exactly when it is wanted.
    console_log="$LOG_ROOT/$version-console.log"
    rm -f -- "$console_log"
    run_guest "$version" "$generation" console-log 0 --console-log "$console_log" -- \
        /bin/sh -c 'printf "pocket-e2e-stdout-token\n"'
    assert_exact_output "$LOG_ROOT/$version-console-log.stdout" $'pocket-e2e-stdout-token\n'
    [[ -f "$console_log" && ! -L "$console_log" ]] || \
        die "Ubuntu $version --console-log wrote no transcript"
    [[ $(stat -c '%a' "$console_log") == 600 ]] || \
        die "Ubuntu $version console transcript is not owner-only"
    grep -q 'Linux version' "$console_log" || {
        sed -n '1,40p' "$console_log" >&2
        die "Ubuntu $version console transcript does not carry the guest kernel console"
    }
    if grep -q 'pocket-e2e-stdout-token' "$console_log"; then
        die "the console transcript must not carry workload output"
    fi
    # An existing path is never overwritten, and the run still delivers its
    # result with the reason reported.
    run_guest "$version" "$generation" console-log-exists 0 --console-log "$console_log" -- \
        /bin/sh -c 'printf "second\n"'
    assert_exact_output "$LOG_ROOT/$version-console-log-exists.stdout" $'second\n'
    grep -q 'console log not written' "$LOG_ROOT/$version-console-log-exists.stderr" || {
        sed -n '1,40p' "$LOG_ROOT/$version-console-log-exists.stderr" >&2
        die "a refused console transcript was not reported"
    }

    # The working directory is resolved inside the guest root, so a merged-usr
    # image's symlinked directories are ordinary working directories.
    run_guest "$version" "$generation" workdir-symlink 0 --workdir /var/run -- /bin/pwd
    assert_exact_output "$LOG_ROOT/$version-workdir-symlink.stdout" $'/run\n'
    run_guest "$version" "$generation" workdir-merged-usr 0 --workdir /lib -- /bin/pwd
    assert_exact_output "$LOG_ROOT/$version-workdir-merged-usr.stdout" $'/usr/lib\n'

    # Named identities come only from the immutable account sidecar.
    run_guest "$version" "$generation" named-user 0 --user ubuntu -- /usr/bin/id -u
    assert_exact_output "$LOG_ROOT/$version-named-user.stdout" $'1000\n'
    run_guest "$version" "$generation" named-group 0 --user ubuntu:ubuntu -- /usr/bin/id -gn
    assert_exact_output "$LOG_ROOT/$version-named-group.stdout" $'ubuntu\n'

    # Docker-compatible process overrides.
    run_guest "$version" "$generation" entrypoint 0 --entrypoint /bin/echo -- pocket entrypoint
    assert_exact_output "$LOG_ROOT/$version-entrypoint.stdout" $'pocket entrypoint\n'
    run_guest "$version" "$generation" exact-argv 0 --exact-argv -- /bin/echo exact argv
    assert_exact_output "$LOG_ROOT/$version-exact-argv.stdout" $'exact argv\n'
    run_guest "$version" "$generation" stop-signal-name 61 \
        --stop-signal SIGUSR1 --timeout 5s -- \
        /bin/sh -c 'trap "exit 61" USR1; while :; do sleep 1; done'

    run_guest "$version" "$generation" config 0 \
        --workdir /tmp --env POCKET_E2E=present --hostname pocket-e2e --umask 027 -- \
        /bin/sh -c \
        'test "$PWD" = /tmp; test "$POCKET_E2E" = present; test "$(cat /proc/sys/kernel/hostname)" = pocket-e2e; : > mode; test "$(stat -c %a mode)" = 640'

    run_guest "$version" "$generation" exit-37 37 -- /bin/sh -c 'exit 37'

    # The workload is PID 1 of its own namespace, so Linux discards a
    # default-disposition signal it sends to itself. Docker behaves the same
    # way, and it is why an ignored stop request has to escalate to SIGKILL.
    run_guest "$version" "$generation" self-signal-ignored 0 -- \
        /bin/sh -c 'kill -15 $$; kill -9 $$; printf "alive\n"'
    assert_exact_output "$LOG_ROOT/$version-self-signal-ignored.stdout" $'alive\n'

    # A descendant is signalable, so 128+n reaches the workload exit status.
    run_guest "$version" "$generation" signal-term 143 -- \
        /bin/sh -c '/bin/sh -c "kill -15 \$\$"; exit $?'
    run_guest "$version" "$generation" signal-rt-35 163 -- \
        /bin/sh -c '/bin/sh -c "kill -35 \$\$"; exit $?'

    # An ignored stop signal escalates to SIGKILL after the execution timeout,
    # which is the path that reports a signal-terminated workload.
    run_guest "$version" "$generation" stop-escalation 137 --timeout 5s -- \
        /bin/sh -c 'trap "" TERM; while :; do sleep 1; done'
    # A cooperative workload observes the stop signal and exits by itself.
    run_guest "$version" "$generation" stop-cooperative 55 --timeout 5s -- \
        /bin/sh -c 'trap "exit 55" TERM; while :; do sleep 1; done'

    run_guest "$version" "$generation" cow-write 0 -- \
        /bin/sh -c 'printf "private\n" > /pocket-cow-marker'
    run_guest "$version" "$generation" cow-fresh 0 -- \
        /bin/sh -c 'test ! -e /pocket-cow-marker'

    run_guest "$version" "$generation" readonly 1 --root-readonly -- \
        /bin/sh -c 'touch /usr/pocket-readonly-must-fail'
    run_guest "$version" "$generation" readonly-fresh 0 -- \
        /bin/sh -c 'test ! -e /usr/pocket-readonly-must-fail'

    assert_cache_hit "$version" "$generation"
    [[ $(sha256sum "$base" | awk '{print $1}') == "${BASE_HASHES[$version]}" ]] || \
        die "Ubuntu $version immutable base changed across runs"
done

assert_archive_normalization 24.04 "${GENERATIONS[24.04]}"
assert_concurrent_cow_isolation "${GENERATIONS[24.04]}"
assert_conversion_metadata_is_deterministic 24.04 "${GENERATIONS[24.04]}"
assert_signal_killed_runs_are_reclaimed "${GENERATIONS[24.04]}"
# The Docker-save archive built its own generation under its own alias, so it is
# the one input this suite can release without losing anything it still checks.
assert_alias_roots_can_be_released \
    "$(jq -er '.generation_id' "$LOG_ROOT/24.04-docker-archive-import.json")" \
    "ubuntu-docker-archive:24.04"

# .sweep.lock is the runtime root's own orphan-reclamation lock, not an
# operation directory: it is created once and outlives every run by design.
if find "$RUNTIME_ROOT" -mindepth 1 ! -name .sweep.lock -print -quit | grep -q .; then
    find "$RUNTIME_ROOT" -mindepth 1 ! -name .sweep.lock -maxdepth 3 -printf '%M %p\n' >&2
    die "runtime operation directories leaked"
fi
assert_no_live_operation_process || die "a guarded operation process leaked"

for version in 24.04 26.04; do
    printf 'ubuntu_%s_generation=%s\n' "${version//./_}" "${GENERATIONS[$version]}"
    printf 'ubuntu_%s_base_sha256=%s\n' "${version//./_}" "${BASE_HASHES[$version]}"
done
printf 'POCKET_RUST_RELEASE_E2E_OK\n'
