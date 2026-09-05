#!/usr/bin/env bash

source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"
# shellcheck source=scripts/linux-source-lib.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/linux-source-lib.sh"

ROOT=$(project_root)
BUILD_ROOT=${POCKET_BUILD_ROOT:-"$ROOT/build"}
KERNEL="$BUILD_ROOT/kernel/x86_64-smp-p4k$LINUX_OUTPUT_SUFFIX/linux"
INITRAMFS="$BUILD_ROOT/initramfs/lifecycle-probe.cpio"
DISK="$BUILD_ROOT/disks/probe.ext4"
GUARD=${POCKET_GUARD:-"$ROOT/target/release/pocket-guard"}
RUNTIME_ROOT=${POCKET_RUNTIME_ROOT:-"/tmp/pocket-vm-$(id -u)"}
TIMEOUT=${POCKET_LIFECYCLE_TIMEOUT:-15}

[[ -x "$KERNEL" && -f "$INITRAMFS" && -f "$DISK" ]] || \
    die "build the kernel, lifecycle probe initramfs, and probe disk first"
[[ -x "$GUARD" ]] || die "process guard is missing: $GUARD (run: cargo build --release -p pocket-guard)"
[[ "$TIMEOUT" =~ ^[1-9][0-9]*$ ]] || die "lifecycle timeout must be a positive integer"
for command in ps find grep mkfifo tee awk tr; do require_command "$command"; done
safe_managed_root "$BUILD_ROOT"
safe_managed_root "$RUNTIME_ROOT"
mkdir -p -- "$RUNTIME_ROOT" "$BUILD_ROOT/logs"
chmod 0700 "$RUNTIME_ROOT"

RUN_DIR=
GUARD_PID=
UML_PID=
SUPERVISOR_WORKER_PID=
LOGGER_PID=

pid_is_live() {
    local pid=$1
    local state
    [[ -r "/proc/$pid/stat" ]] || return 1
    state=$(awk '{print $3}' "/proc/$pid/stat" 2>/dev/null) || return 1
    [[ "$state" != Z ]]
}

wait_for_pid_absence() {
    local pid=$1
    local description=$2
    local deadline=$((SECONDS + TIMEOUT))

    while [[ -e "/proc/$pid" ]]; do
        (( SECONDS < deadline )) || die "$description process $pid survived lifecycle cleanup"
        sleep 0.05
    done
}

wait_for_group_absence() {
    local pgid=$1
    local description=$2
    local deadline=$((SECONDS + TIMEOUT))

    while ps -eo pgid= | awk -v target="$pgid" '$1 == target { found = 1 } END { exit !found }'; do
        (( SECONDS < deadline )) || die "$description process group $pgid survived lifecycle cleanup"
        sleep 0.05
    done
}

assert_no_owned_uml_process() {
    local uml_dir=$1
    local proc cmdline

    for proc in /proc/[0-9]*/cmdline; do
        [[ -r "$proc" ]] || continue
        cmdline=$(tr '\0' ' ' < "$proc" 2>/dev/null || true)
        if [[ "$cmdline" == *"uml_dir=$uml_dir"* ]]; then
            printf 'surviving_process=%s command=%s\n' "${proc#/proc/}" "$cmdline" >&2
            return 1
        fi
    done
}

close_launch_fds() {
    if [[ -n ${CONSOLE_INPUT_FD:-} ]]; then exec {CONSOLE_INPUT_FD}>&-; fi
    if [[ -n ${SERIAL_FD:-} ]]; then exec {SERIAL_FD}>&-; fi
}

start_guarded_uml() {
    local run_dir=$1
    local log=$2
    local lifecycle_option=${3:-}
    local supervisor_pid=$BASHPID
    local deadline children
    local -a lifecycle_args=()

    if [[ -n "$lifecycle_option" ]]; then
        lifecycle_args+=("$lifecycle_option")
    fi

    mkfifo -m 0600 "$run_dir/console.in" "$run_dir/serial" "$run_dir/console.out"
    exec {CONSOLE_INPUT_FD}<>"$run_dir/console.in"
    exec {SERIAL_FD}<>"$run_dir/serial"
    tee "$log" < "$run_dir/console.out" >/dev/null &
    LOGGER_PID=$!

    "$GUARD" \
        --supervisor-pid "$supervisor_pid" \
        --inherit-fd "$CONSOLE_INPUT_FD" \
        --inherit-fd "$SERIAL_FD" \
        --uml-personality \
        -- \
        env -i PATH=/usr/bin:/bin TMPDIR="$run_dir/tmp" \
        "$KERNEL" mem=256M ncpus=2 seccomp=on \
        "umid=lifecycle-${run_dir##*.}" "uml_dir=$run_dir/uml" \
        "initrd=$INITRAMFS" rdinit=/init rootfstype=ramfs \
        "ubd0r=$DISK" \
        con=null "con0=fd:$CONSOLE_INPUT_FD,fd:1" \
        "ssl=fd:$SERIAL_FD,fd:$SERIAL_FD" noreboot panic=1 \
        "${lifecycle_args[@]}" \
        </dev/null >"$run_dir/console.out" 2>&1 &
    GUARD_PID=$!
    close_launch_fds

    deadline=$((SECONDS + TIMEOUT))
    until grep -Fq POCKET_LIFECYCLE_READY "$log"; do
        pid_is_live "$GUARD_PID" || {
            cat "$log" >&2
            die "guard exited before the lifecycle guest became ready"
        }
        (( SECONDS < deadline )) || die "lifecycle guest readiness timed out"
        sleep 0.05
    done

    children=$(cat -- "/proc/$GUARD_PID/task/$GUARD_PID/children")
    IFS=' ' read -r UML_PID _ <<< "$children"
    if [[ ! "$UML_PID" =~ ^[1-9][0-9]*$ ]]; then
        ps -eo pid=,ppid=,pgid=,sid=,stat=,comm= --forest >&2
        cat "$log" >&2
        die "guard has no observable direct UML child"
    fi
}

record_and_verify_relationships() {
    local evidence=$1
    local observed_pid observed_ppid observed_pgid observed_sid
    local guard_pid guard_ppid guard_pgid guard_sid

    IFS=' ' read -r observed_pid observed_ppid observed_pgid observed_sid < <(
        ps -o pid=,ppid=,pgid=,sid= -p "$UML_PID"
    )
    IFS=' ' read -r guard_pid guard_ppid guard_pgid guard_sid < <(
        ps -o pid=,ppid=,pgid=,sid= -p "$GUARD_PID"
    )

    [[ "$observed_pid" == "$UML_PID" ]] || die "observed the wrong UML PID"
    [[ "$observed_ppid" == "$GUARD_PID" ]] || die "UML is not a direct child of its guard"
    [[ "$observed_pgid" == "$UML_PID" ]] || die "UML escaped its pre-exec process group"
    [[ "$observed_sid" == "$guard_sid" ]] || die "UML escaped into a new session"
    [[ "$observed_sid" != "$UML_PID" ]] || die "UML setsid unexpectedly succeeded"

    printf 'guard_pid=%s guard_ppid=%s guard_pgid=%s guard_sid=%s\n' \
        "$guard_pid" "$guard_ppid" "$guard_pgid" "$guard_sid" >> "$evidence"
    printf 'uml_pid=%s uml_ppid=%s uml_pgid=%s uml_sid=%s\n' \
        "$observed_pid" "$observed_ppid" "$observed_pgid" "$observed_sid" >> "$evidence"
}

make_run_dir() {
    RUN_DIR=$(mktemp -d "$RUNTIME_ROOT/lifecycle.XXXXXXXX")
    mkdir -m 0700 -- "$RUN_DIR/uml" "$RUN_DIR/tmp"
    install -m 0600 /dev/null "$RUN_DIR/console.log"
}

cleanup() {
    local status=$?
    close_launch_fds
    if [[ -n ${SUPERVISOR_WORKER_PID:-} ]] && pid_is_live "$SUPERVISOR_WORKER_PID"; then
        kill -KILL "$SUPERVISOR_WORKER_PID" 2>/dev/null || true
        wait "$SUPERVISOR_WORKER_PID" 2>/dev/null || true
    fi
    if [[ -n ${GUARD_PID:-} ]] && pid_is_live "$GUARD_PID"; then
        kill -TERM "$GUARD_PID" 2>/dev/null || true
        wait "$GUARD_PID" 2>/dev/null || true
    fi
    if [[ -n ${LOGGER_PID:-} ]] && pid_is_live "$LOGGER_PID"; then
        kill -TERM "$LOGGER_PID" 2>/dev/null || true
        wait "$LOGGER_PID" 2>/dev/null || true
    fi
    if [[ -n ${RUN_DIR:-} && -d "$RUN_DIR" ]]; then
        find "$RUN_DIR" -depth -delete 2>/dev/null || true
    fi
    return "$status"
}
trap cleanup EXIT INT TERM

# A signal to the guard must reach the guard-owned UML process group, and the
# guard must reap the complete tree before returning.
make_run_dir
LOG="$RUN_DIR/console.log"
EVIDENCE="$RUN_DIR/relationships.log"
start_guarded_uml "$RUN_DIR" "$LOG"
record_and_verify_relationships "$EVIDENCE"
FIRST_UML_PID=$UML_PID
FIRST_UML_DIR="$RUN_DIR/uml"
kill -TERM "$GUARD_PID"
if wait "$GUARD_PID"; then GUARDED_STATUS=0; else GUARDED_STATUS=$?; fi
GUARD_PID=
wait "$LOGGER_PID"
LOGGER_PID=
wait_for_pid_absence "$FIRST_UML_PID" "normally terminated UML"
wait_for_group_absence "$FIRST_UML_PID" "normally terminated UML"
assert_no_owned_uml_process "$FIRST_UML_DIR" || die "normal guard termination leaked a UML process"
assert_clean_uml_log "$LOG" "guard lifecycle normal-stop probe"
printf 'guard_signal_exit_status=%s\n' "$GUARDED_STATUS" >> "$EVIDENCE"
cat "$EVIDENCE"
mv -- "$LOG" "$BUILD_ROOT/logs/guard-lifecycle-normal.log"
mv -- "$EVIDENCE" "$BUILD_ROOT/logs/guard-lifecycle-relationships.log"
find "$RUN_DIR" -depth -delete
RUN_DIR=

# SIGKILL cannot run guard cleanup; the child-side parent-death contract must
# still kill the UML process and its patched helper/stub descendants.
make_run_dir
LOG="$RUN_DIR/console.log"
start_guarded_uml "$RUN_DIR" "$LOG"
record_and_verify_relationships /dev/null
KILLED_GUARD_PID=$GUARD_PID
KILLED_UML_PID=$UML_PID
KILLED_UML_DIR="$RUN_DIR/uml"
kill -KILL "$KILLED_GUARD_PID"
if wait "$KILLED_GUARD_PID" 2>/dev/null; then KILLED_STATUS=0; else KILLED_STATUS=$?; fi
GUARD_PID=
wait "$LOGGER_PID"
LOGGER_PID=
wait_for_pid_absence "$KILLED_UML_PID" "parent-death-killed UML"
wait_for_group_absence "$KILLED_UML_PID" "parent-death-killed UML"
assert_no_owned_uml_process "$KILLED_UML_DIR" || die "guard SIGKILL leaked a UML process"
printf 'guard_sigkill_status=%s uml_pid=%s result=gone\n' \
    "$KILLED_STATUS" "$KILLED_UML_PID"
mv -- "$LOG" "$BUILD_ROOT/logs/guard-lifecycle-sigkill.log"
find "$RUN_DIR" -depth -delete
RUN_DIR=

# A supervisor which disappears without cleanup must trigger the guard's own
# parent-death signal. The guard's death must in turn terminate the UML tree.
supervisor_worker() {
    local worker_run_dir=$1
    local worker_log="$worker_run_dir/console.log"
    local state_tmp="$worker_run_dir/supervisor.state.tmp"

    start_guarded_uml "$worker_run_dir" "$worker_log"
    record_and_verify_relationships /dev/null
    printf '%s %s %s\n' "$GUARD_PID" "$UML_PID" "$LOGGER_PID" > "$state_tmp"
    mv -- "$state_tmp" "$worker_run_dir/supervisor.state"
    wait "$GUARD_PID"
}

make_run_dir
LOG="$RUN_DIR/console.log"
supervisor_worker "$RUN_DIR" &
SUPERVISOR_WORKER_PID=$!
STATE="$RUN_DIR/supervisor.state"
DEADLINE=$((SECONDS + TIMEOUT))
until [[ -f "$STATE" ]]; do
    pid_is_live "$SUPERVISOR_WORKER_PID" || die "lifecycle supervisor worker exited before readiness"
    (( SECONDS < DEADLINE )) || die "lifecycle supervisor worker readiness timed out"
    sleep 0.05
done
IFS=' ' read -r ORPHAN_GUARD_PID ORPHAN_UML_PID ORPHAN_LOGGER_PID < "$STATE"
ORPHAN_UML_DIR="$RUN_DIR/uml"
kill -KILL "$SUPERVISOR_WORKER_PID"
if wait "$SUPERVISOR_WORKER_PID" 2>/dev/null; then SUPERVISOR_STATUS=0; else SUPERVISOR_STATUS=$?; fi
SUPERVISOR_WORKER_PID=
wait_for_pid_absence "$ORPHAN_GUARD_PID" "parent-death-killed guard"
wait_for_pid_absence "$ORPHAN_UML_PID" "supervisor-orphaned UML"
wait_for_group_absence "$ORPHAN_UML_PID" "supervisor-orphaned UML"
wait_for_pid_absence "$ORPHAN_LOGGER_PID" "supervisor-orphaned logger"
assert_no_owned_uml_process "$ORPHAN_UML_DIR" || die "supervisor SIGKILL leaked a UML process"
assert_clean_uml_log "$LOG" "guard lifecycle supervisor-death probe"
printf 'supervisor_sigkill_status=%s guard_pid=%s uml_pid=%s result=gone\n' \
    "$SUPERVISOR_STATUS" "$ORPHAN_GUARD_PID" "$ORPHAN_UML_PID"
mv -- "$LOG" "$BUILD_ROOT/logs/guard-lifecycle-supervisor-sigkill.log"
find "$RUN_DIR" -depth -delete
RUN_DIR=

# UML normally handles a guest reboot by execing itself. The supported launch
# contract passes noreboot, so a real guest restart syscall must instead end the
# one guarded launch without creating a replacement process.
make_run_dir
LOG="$RUN_DIR/console.log"
EVIDENCE="$RUN_DIR/restart-relationships.log"
start_guarded_uml "$RUN_DIR" "$LOG" pocket.lifecycle=reboot
record_and_verify_relationships "$EVIDENCE"
RESTART_UML_PID=$UML_PID
RESTART_UML_DIR="$RUN_DIR/uml"
DEADLINE=$((SECONDS + TIMEOUT))
while pid_is_live "$GUARD_PID"; do
    (( SECONDS < DEADLINE )) || die "noreboot guest restart did not end the guarded launch"
    sleep 0.05
done
if wait "$GUARD_PID"; then RESTART_STATUS=0; else RESTART_STATUS=$?; fi
GUARD_PID=
wait "$LOGGER_PID"
LOGGER_PID=
READY_COUNT=$(grep -Fc POCKET_LIFECYCLE_READY "$LOG" || true)
REQUEST_COUNT=$(grep -Fc POCKET_RESTART_REQUESTED "$LOG" || true)
[[ "$READY_COUNT" == 1 ]] || die "restart gate observed $READY_COUNT boots instead of exactly one"
[[ "$REQUEST_COUNT" == 1 ]] || die "restart gate did not observe exactly one guest restart request"
! grep -Fq POCKET_RESTART_FAILED "$LOG" || die "guest restart syscall unexpectedly returned"
wait_for_pid_absence "$RESTART_UML_PID" "noreboot-restarted UML"
wait_for_group_absence "$RESTART_UML_PID" "noreboot-restarted UML"
assert_no_owned_uml_process "$RESTART_UML_DIR" || die "noreboot restart leaked a UML process"
assert_clean_uml_log "$LOG" "guard lifecycle noreboot probe"
printf 'guest_restart_exit_status=%s boot_count=%s request_count=%s result=gone\n' \
    "$RESTART_STATUS" "$READY_COUNT" "$REQUEST_COUNT" >> "$EVIDENCE"
cat "$EVIDENCE"
mv -- "$LOG" "$BUILD_ROOT/logs/guard-lifecycle-noreboot.log"
mv -- "$EVIDENCE" "$BUILD_ROOT/logs/guard-lifecycle-noreboot-relationships.log"
find "$RUN_DIR" -depth -delete
RUN_DIR=

# Exercise panic=1 separately from an ordinary restart. The static fault probe
# execs as guest PID 1, so its synchronous fault enters Linux's real panic and
# delayed restart path. noreboot must turn that restart into process exit.
make_run_dir
LOG="$RUN_DIR/console.log"
EVIDENCE="$RUN_DIR/panic-relationships.log"
start_guarded_uml "$RUN_DIR" "$LOG" pocket.lifecycle=panic
record_and_verify_relationships "$EVIDENCE"
PANIC_UML_PID=$UML_PID
PANIC_UML_DIR="$RUN_DIR/uml"
DEADLINE=$((SECONDS + TIMEOUT))
while pid_is_live "$GUARD_PID"; do
    (( SECONDS < DEADLINE )) || die "panic=1 noreboot path did not end the guarded launch"
    sleep 0.05
done
if wait "$GUARD_PID"; then PANIC_STATUS=0; else PANIC_STATUS=$?; fi
GUARD_PID=
wait "$LOGGER_PID"
LOGGER_PID=
READY_COUNT=$(grep -Fc POCKET_LIFECYCLE_READY "$LOG" || true)
PANIC_COUNT=$(grep -Fc POCKET_PANIC_REQUESTED "$LOG" || true)
[[ "$READY_COUNT" == 1 ]] || die "panic gate observed $READY_COUNT boots instead of exactly one"
[[ "$PANIC_COUNT" == 1 ]] || die "panic gate did not observe exactly one panic request"
! grep -Fq POCKET_PANIC_EXEC_FAILED "$LOG" || die "guest panic probe exec failed"
grep -Fq 'Kernel panic - not syncing' "$LOG" || die "guest PID 1 fault did not produce a kernel panic"
if grep -Eq 'epollctl (add|mod) err|BUG:|WARNING:|Oops:|soft lockup|hard LOCKUP' "$LOG"; then
    die "intentional panic probe emitted an unrelated UML diagnostic"
fi
wait_for_pid_absence "$PANIC_UML_PID" "panic-restarted UML"
wait_for_group_absence "$PANIC_UML_PID" "panic-restarted UML"
assert_no_owned_uml_process "$PANIC_UML_DIR" || die "panic restart leaked a UML process"
printf 'guest_panic_exit_status=%s boot_count=%s request_count=%s result=gone\n' \
    "$PANIC_STATUS" "$READY_COUNT" "$PANIC_COUNT" >> "$EVIDENCE"
cat "$EVIDENCE"
mv -- "$LOG" "$BUILD_ROOT/logs/guard-lifecycle-panic.log"
mv -- "$EVIDENCE" "$BUILD_ROOT/logs/guard-lifecycle-panic-relationships.log"
find "$RUN_DIR" -depth -delete
RUN_DIR=

printf 'POCKET_GUARD_LIFECYCLE_OK\n'
