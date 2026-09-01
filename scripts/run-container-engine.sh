#!/usr/bin/env bash

# Run a real container engine inside the guest, and a container inside that.
#
# The prerequisites are asserted by the end-to-end suite without pulling a
# daemon; this is the claim itself. It is a separate target because the image
# is large and the run is slow, not because it is optional evidence.

source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"

ROOT=$(project_root)
BUILD_ROOT=${POCKET_BUILD_ROOT:-"$ROOT/build"}
PROFILE_BUNDLE=${POCKET_PROFILE_BUNDLE:-}
POCKET_BIN="$ROOT/target/release/pocket"
ENGINE_IMAGE=${POCKET_ENGINE_IMAGE:-docker://docker.io/library/docker:27-dind}

for command in cargo find mkdir mktemp; do
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

WORK_ROOT=$(mktemp -d "$BUILD_ROOT/engine.XXXXXXXX")
STORE="$WORK_ROOT/store"
# Short by necessity: a run's sockets live under the runtime root.
RUNTIME_ROOT=$(mktemp -d "${XDG_RUNTIME_DIR:-/tmp}/pkeng.XXXXXX")
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

printf 'engine_work_root=%s\n' "$WORK_ROOT"
printf 'profile_bundle=%s\n' "$PROFILE_BUNDLE"

"$POCKET_BIN" image pull --profile-bundle "$PROFILE_BUNDLE" --store "$STORE" \
    --runtime-root "$RUNTIME_ROOT" --reference engine:latest --platform linux/amd64 \
    "$ENGINE_IMAGE" >"$WORK_ROOT/pull.json" 2>"$WORK_ROOT/pull.stderr" || {
        sed -n '1,40p' "$WORK_ROOT/pull.stderr" >&2
        die "could not acquire the container-engine image"
    }

# shellcheck disable=SC2016  # the guest expands these, not this shell
# DOCKER_HOST is overridden because the image presets a TCP endpoint for its
# own daemon-in-a-sibling-container arrangement, which is not this one.
"$POCKET_BIN" run --profile-bundle "$PROFILE_BUNDLE" --store "$STORE" \
    --runtime-root "$RUNTIME_ROOT" --privileged --cpus 4 --memory 2G \
    --timeout 600s -e DOCKER_HOST=unix:///var/run/docker.sock \
    engine:latest -- /bin/sh -c '
        dockerd --host=unix:///var/run/docker.sock >/tmp/dockerd.log 2>&1 &
        for _ in $(seq 1 120); do docker info >/dev/null 2>&1 && break; sleep 1; done
        docker info --format "engine={{.ServerVersion}} storage={{.Driver}} cgroup=v{{.CgroupVersion}} kernel={{.KernelVersion}}" || {
            tail -20 /tmp/dockerd.log >&2; exit 1; }
        docker run --rm hello-world
        docker run --rm alpine:3.22 sh -c "nproc; cat /etc/alpine-release"
    ' >"$WORK_ROOT/engine.stdout" 2>"$WORK_ROOT/engine.stderr" || {
        sed -n '1,40p' "$WORK_ROOT/engine.stderr" >&2
        sed -n '1,40p' "$WORK_ROOT/engine.stdout" >&2
        die "the container engine did not complete"
    }

cat "$WORK_ROOT/engine.stdout"

# The engine must have started, pulled over the guest's own network, and run a
# container to completion. Each is asserted separately so a partial success
# cannot read as a pass.
grep -q '^engine=' "$WORK_ROOT/engine.stdout" || die "the engine never reported itself"
grep -q 'storage=overlay2' "$WORK_ROOT/engine.stdout" || die "the engine did not use overlay2"
grep -q 'cgroup=v2' "$WORK_ROOT/engine.stdout" || die "the engine did not use cgroup v2"
grep -q 'Hello from Docker' "$WORK_ROOT/engine.stdout" || die "no container ran to completion"
grep -qx '3.22.5' "$WORK_ROOT/engine.stdout" || die "the second container did not report its release"

# Nothing may be left running, and the runtime root must be empty again.
if find "$RUNTIME_ROOT" -mindepth 1 ! -name .sweep.lock -print -quit | grep -q .; then
    die "the engine run leaked a runtime directory"
fi

printf 'POCKET_CONTAINER_ENGINE_OK\n'
