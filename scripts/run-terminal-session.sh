#!/usr/bin/env bash

# Drive one interactive terminal session and assert what an operator gets.
#
# `-t` cannot be exercised from a pipe by construction, so this allocates a
# real PTY, types into it, and checks the answers. Every claim the terminal
# documentation makes is asserted here rather than described.

source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"

ROOT=$(project_root)
BUILD_ROOT=${POCKET_BUILD_ROOT:-"$ROOT/build"}
PROFILE_BUNDLE=${POCKET_PROFILE_BUNDLE:-}
POCKET_BIN="$ROOT/target/release/pocket"
SESSION_IMAGE=${POCKET_SESSION_IMAGE:-docker://docker.io/library/alpine:3.22}

for command in cargo mkdir mktemp python3; do
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

WORK_ROOT=$(mktemp -d "$BUILD_ROOT/terminal.XXXXXXXX")
STORE="$WORK_ROOT/store"
# Short by necessity: a run's sockets live under the runtime root.
RUNTIME_ROOT=$(mktemp -d "${XDG_RUNTIME_DIR:-/tmp}/pkterm.XXXXXX")
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

printf 'terminal_work_root=%s\n' "$WORK_ROOT"
printf 'profile_bundle=%s\n' "$PROFILE_BUNDLE"

"$POCKET_BIN" image pull --profile-bundle "$PROFILE_BUNDLE" --store "$STORE" \
    --runtime-root "$RUNTIME_ROOT" --reference session:latest --platform linux/amd64 \
    "$SESSION_IMAGE" >"$WORK_ROOT/pull.json" 2>"$WORK_ROOT/pull.stderr" || {
        sed -n '1,40p' "$WORK_ROOT/pull.stderr" >&2
        die "could not acquire the session image"
    }

# A pipe cannot stand in for a terminal here: `-t` requires one on both
# descriptors, which is itself one of the assertions below.
POCKET_BIN="$POCKET_BIN" PROFILE_BUNDLE="$PROFILE_BUNDLE" STORE="$STORE" \
    RUNTIME_ROOT="$RUNTIME_ROOT" WORK_ROOT="$WORK_ROOT" \
    python3 "$ROOT/scripts/terminal_session.py" >"$WORK_ROOT/session.out" 2>"$WORK_ROOT/session.err" || {
        sed -n '1,60p' "$WORK_ROOT/session.err" >&2
        sed -n '1,60p' "$WORK_ROOT/session.out" >&2
        die "the terminal session did not complete"
    }

cat "$WORK_ROOT/session.out"

# Each property is asserted separately so a partial success cannot read as a
# pass. Together they are the difference between a PTY and a pipe.
grep -qx 'isatty=1' "$WORK_ROOT/session.out" || die "stdin was not a terminal in the guest"
grep -qx 'size=40 132' "$WORK_ROOT/session.out" || \
    die "the guest did not start at the size the operator's terminal had"
grep -qx 'resized=24 100' "$WORK_ROOT/session.out" || \
    die "a window resize did not reach the guest"
grep -qx 'ttyname=/dev/pts/0' "$WORK_ROOT/session.out" || \
    die "the terminal has no resolvable name in the guest"
grep -qx 'term=xterm-256color' "$WORK_ROOT/session.out" || \
    die "TERM was not carried into the guest"
grep -qx 'ctrl_c=interrupted' "$WORK_ROOT/session.out" || \
    die "an interrupt key did not reach the guest's line discipline"
grep -qx 'exit=7' "$WORK_ROOT/session.out" || \
    die "the session's exit status was not the workload's"
grep -qx 'no_terminal_refused=1' "$WORK_ROOT/session.out" || \
    die "--tty from a pipe was not refused"

# Extra serial lines are the other half of the terminal story: the session
# above is the workload's own, these are additional lines an operator attaches
# to while it runs. A line that exists is not a line that works, so this uses
# one rather than inspecting it.
POCKET_BIN="$POCKET_BIN" PROFILE_BUNDLE="$PROFILE_BUNDLE" STORE="$STORE" \
    RUNTIME_ROOT="$RUNTIME_ROOT" CONSOLE_ALIAS=session:latest \
    python3 "$ROOT/scripts/extra_consoles.py" >"$WORK_ROOT/consoles.out" 2>"$WORK_ROOT/consoles.err" || {
        sed -n '1,40p' "$WORK_ROOT/consoles.err" >&2
        sed -n '1,40p' "$WORK_ROOT/consoles.out" >&2
        die "the extra-console session did not complete"
    }
cat "$WORK_ROOT/consoles.out"

grep -qx 'published_lines=2' "$WORK_ROOT/consoles.out" || \
    die "both extra serial lines were not published"
grep -qx 'path_present=1' "$WORK_ROOT/consoles.out" || \
    die "an extra line's pseudo-terminal did not outlive the launch"
grep -qx 'nodes_present=1' "$WORK_ROOT/consoles.out" || \
    die "the guest has no device nodes for its extra serial lines"
grep -qx 'second_shell=1' "$WORK_ROOT/consoles.out" || \
    die "no shell was waiting on an extra line for an attached operator"
grep -qx 'shell_is_root=1' "$WORK_ROOT/consoles.out" || \
    die "the shell on the extra line does not have the workload's identity"
grep -qx 'second_line=1' "$WORK_ROOT/consoles.out" || \
    die "the second extra line is not independently usable"
grep -qx 'guest_hostname=1' "$WORK_ROOT/consoles.out" || \
    die "the shell on the extra line is not inside the guest"
grep -qx 'main_workload=1' "$WORK_ROOT/consoles.out" || \
    die "the main workload did not finish alongside the extra line"

# Nothing may be left running, and the runtime root must be empty again.
# .sweep.lock is the runtime root's orphan-reclamation lock, created once and
# kept by design; it is not an operation directory.
if find "$RUNTIME_ROOT" -mindepth 1 ! -name .sweep.lock -print -quit | grep -q .; then
    die "the session leaked a runtime directory"
fi

printf 'POCKET_TERMINAL_SESSION_OK\n'
