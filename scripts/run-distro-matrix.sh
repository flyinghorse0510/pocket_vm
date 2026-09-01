#!/usr/bin/env bash

# Pull and run a set of unrelated base images to show that nothing in the
# runtime is specific to the Ubuntu fixtures: different libc, different
# userland, different package manager, and images with no shell or no /etc at
# all. Requires anonymous network access to the named registries.
#
# Guest programs are single-quoted so the host shell cannot expand them.
# shellcheck disable=SC2016

# shellcheck source=scripts/lib.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"

export LC_ALL=C

ROOT=$(project_root)
BUILD_ROOT=${POCKET_BUILD_ROOT:-"$ROOT/build"}
POCKET_BIN=${POCKET_BIN:-"$ROOT/target/release/pocket"}
PROFILE_BUNDLE=${POCKET_PROFILE_BUNDLE:-}

for command in awk mkdir mktemp python3; do
    require_command "$command"
done
[[ -n "$PROFILE_BUNDLE" && -d "$PROFILE_BUNDLE" ]] || \
    die "set POCKET_PROFILE_BUNDLE to an exact sealed profile directory"
[[ -x "$POCKET_BIN" && ! -L "$POCKET_BIN" ]] || die "pocket executable is missing: $POCKET_BIN"
safe_managed_root "$BUILD_ROOT"

require_command jq
MAX_UNIX_PATH_BYTES=$(jq -er \
    '.launch.max_unix_path_bytes |
     select(type == "number" and floor == . and . >= 1)' \
    "$PROFILE_BUNDLE/profile.json") || die "profile has no valid launch.max_unix_path_bytes"

# Operation directories are named build-<32 hex>/uml, so keep the generated
# prefix short enough that the longest one still fits the AF_UNIX boundary.
mkdir -p -- "$BUILD_ROOT/dm"
WORK_ROOT=$(mktemp -d "$BUILD_ROOT/dm/m.XXXXXXXX")
STORE="$WORK_ROOT/store"
RUNTIME_ROOT="$WORK_ROOT/runtime"
LOG_ROOT="$WORK_ROOT/logs"
WORST_OPERATION_UML_DIR="$RUNTIME_ROOT/build-00000000000000000000000000000000/uml"
if (( ${#WORST_OPERATION_UML_DIR} > MAX_UNIX_PATH_BYTES )); then
    die "distro-matrix runtime root cannot fit a generated UML operation path: $RUNTIME_ROOT"
fi
mkdir -m 0700 -- "$RUNTIME_ROOT" "$LOG_ROOT"
printf 'distro_matrix_work_root=%s\n' "$WORK_ROOT"

# alias|source|probe program|expected stdout
#
# debian is present deliberately: its official manifest inlines a copy of the
# config blob in the descriptor's optional `data` field, which the layout
# verifier must check rather than refuse.
CASES=(
    'debian|docker://docker.io/library/debian:13|. /etc/os-release; printf "%s\n" "$ID"|debian'
    'alpine|docker://docker.io/library/alpine:3.22|. /etc/os-release; printf "%s\n" "$ID"|alpine'
    'archlinux|docker://docker.io/library/archlinux:latest|. /etc/os-release; printf "%s\n" "$ID"|arch'
    'fedora|docker://docker.io/library/fedora:latest|. /etc/os-release; printf "%s\n" "$ID"|fedora'
    'busybox|docker://docker.io/library/busybox:stable|printf "%s\n" "$(id -u)"|0'
)

failures=0
for entry in "${CASES[@]}"; do
    IFS='|' read -r alias source program expected <<<"$entry"
    printf '=== %s ===\n' "$alias"
    if ! "$POCKET_BIN" image pull \
        --profile-bundle "$PROFILE_BUNDLE" --store "$STORE" --runtime-root "$RUNTIME_ROOT" \
        --reference "x86_64-smp-p4k/$alias" --platform linux/amd64 --json "$source" \
        >"$LOG_ROOT/$alias-pull.json" 2>"$LOG_ROOT/$alias-pull.stderr"
    then
        sed -n '1,20p' "$LOG_ROOT/$alias-pull.stderr" >&2
        printf 'FAIL pull %s\n' "$alias" >&2
        failures=$((failures + 1))
        continue
    fi
    generation=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["generation_id"])' \
        "$LOG_ROOT/$alias-pull.json")
    if ! "$POCKET_BIN" run \
        --profile-bundle "$PROFILE_BUNDLE" --store "$STORE" --runtime-root "$RUNTIME_ROOT" \
        --cpus 4 --timeout 300s "$generation" -- /bin/sh -c "$program" \
        >"$LOG_ROOT/$alias-run.stdout" 2>"$LOG_ROOT/$alias-run.stderr"
    then
        sed -n '1,20p' "$LOG_ROOT/$alias-run.stderr" >&2
        printf 'FAIL run %s\n' "$alias" >&2
        failures=$((failures + 1))
        continue
    fi
    observed=$(cat "$LOG_ROOT/$alias-run.stdout")
    if [[ "$observed" != "$expected" ]]; then
        printf 'FAIL %s: expected %q, observed %q\n' "$alias" "$expected" "$observed" >&2
        failures=$((failures + 1))
        continue
    fi
    printf '%s ok (%s)\n' "$alias" "$generation"
done

# An image with no shell, no libc and no /etc still runs its own default Cmd.
printf '=== scratch (hello-world) ===\n'
if "$POCKET_BIN" image pull \
    --profile-bundle "$PROFILE_BUNDLE" --store "$STORE" --runtime-root "$RUNTIME_ROOT" \
    --reference "x86_64-smp-p4k/scratch" --platform linux/amd64 --json \
    "docker://docker.io/library/hello-world:latest" \
    >"$LOG_ROOT/scratch-pull.json" 2>"$LOG_ROOT/scratch-pull.stderr"
then
    generation=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["generation_id"])' \
        "$LOG_ROOT/scratch-pull.json")
    if "$POCKET_BIN" run \
        --profile-bundle "$PROFILE_BUNDLE" --store "$STORE" --runtime-root "$RUNTIME_ROOT" \
        --timeout 300s "$generation" >"$LOG_ROOT/scratch-run.stdout" 2>"$LOG_ROOT/scratch-run.stderr"
    then
        grep -Fq 'Hello from Docker!' "$LOG_ROOT/scratch-run.stdout" || {
            printf 'FAIL scratch image default command\n' >&2
            failures=$((failures + 1))
        }
        printf 'scratch ok (%s)\n' "$generation"
    else
        sed -n '1,20p' "$LOG_ROOT/scratch-run.stderr" >&2
        printf 'FAIL run scratch\n' >&2
        failures=$((failures + 1))
    fi
else
    sed -n '1,20p' "$LOG_ROOT/scratch-pull.stderr" >&2
    printf 'FAIL pull scratch\n' >&2
    failures=$((failures + 1))
fi

(( failures == 0 )) || die "distro matrix recorded $failures failures; logs under $LOG_ROOT"
printf 'POCKET_DISTRO_MATRIX_OK\n'
