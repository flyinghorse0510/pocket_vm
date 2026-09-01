#!/usr/bin/env bash

source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"

ROOT=$(project_root)
BUILD_ROOT=${POCKET_BUILD_ROOT:-"$ROOT/build"}
KERNEL="$BUILD_ROOT/kernel/x86_64-smp-p4k/linux"
INITRAMFS="$BUILD_ROOT/initramfs/smp-probe.cpio"
GUARD=${POCKET_GUARD:-"$ROOT/target/release/pocket-guard"}
RUNTIME_ROOT=${POCKET_RUNTIME_ROOT:-"/tmp/pocket-vm-$(id -u)"}

[[ -x "$KERNEL" && -f "$INITRAMFS" ]] || die "build the kernel and SMP probe initramfs first"
[[ -x "$GUARD" ]] || die "process guard is missing: $GUARD (run: cargo build --release -p pocket-guard)"
safe_managed_root "$BUILD_ROOT"
safe_managed_root "$RUNTIME_ROOT"
mkdir -p -- "$RUNTIME_ROOT" "$BUILD_ROOT/logs"
chmod 0700 "$RUNTIME_ROOT"

run_one() {
    local cpus=$1
    local run_dir log fifo uml_status elapsed

    run_dir=$(mktemp -d "$RUNTIME_ROOT/smp-$cpus.XXXXXXXX")
    mkdir -m 0700 -- "$run_dir/uml" "$run_dir/tmp"
    log="$run_dir/console.log"
    fifo="$run_dir/console.pipe"
    install -m 0600 /dev/null "$log"
    mkfifo -m 0600 "$fifo"
    open_pollable_serial_sink "$run_dir"

    # Invoked by the RETURN trap below.
    # shellcheck disable=SC2329
    cleanup_one() {
        local status=$?
        if [[ -n ${GUARD_PID:-} ]] && kill -0 "$GUARD_PID" 2>/dev/null; then
            kill -TERM "$GUARD_PID" 2>/dev/null || true
            wait "$GUARD_PID" 2>/dev/null || true
        fi
        if [[ -n ${LOGGER_PID:-} ]] && kill -0 "$LOGGER_PID" 2>/dev/null; then
            kill -TERM "$LOGGER_PID" 2>/dev/null || true
            wait "$LOGGER_PID" 2>/dev/null || true
        fi
        stop_pollable_serial_sink
        return "$status"
    }
    trap cleanup_one RETURN

    tee "$log" < "$fifo" >/dev/null &
    LOGGER_PID=$!
    local supervisor_pid=$BASHPID
    "$GUARD" \
        --supervisor-pid "$supervisor_pid" \
        --inherit-fd "$POCKET_CONSOLE_INPUT_FD" \
        --inherit-fd "$POCKET_SERIAL_INPUT_FD" \
        --inherit-fd "$POCKET_SERIAL_OUTPUT_FD" \
        --uml-personality \
        -- \
        env -i PATH=/usr/bin:/bin TMPDIR="$run_dir/tmp" \
        "$KERNEL" mem=256M "ncpus=$cpus" seccomp=on \
        "umid=smp-$cpus-${run_dir##*.}" "uml_dir=$run_dir/uml" \
        "initrd=$INITRAMFS" rdinit=/init rootfstype=ramfs \
        con=null "con0=fd:$POCKET_CONSOLE_INPUT_FD,fd:1" \
        "ssl=fd:$POCKET_SERIAL_INPUT_FD,fd:$POCKET_SERIAL_OUTPUT_FD" noreboot panic=1 \
        </dev/null >"$fifo" 2>&1 &
    GUARD_PID=$!
    close_pollable_serial_fds
    if wait "$GUARD_PID"; then uml_status=0; else uml_status=$?; fi
    GUARD_PID=
    wait "$LOGGER_PID"
    LOGGER_PID=
    wait_pollable_serial_sink || die "serial sink failed"

    [[ "$uml_status" == 0 ]] || die "SMP probe UML exited with status $uml_status"
    grep -Fq 'Checking that seccomp filters can be installed...OK' "$log" || \
        die "SMP probe did not use cooperative seccomp"
    grep -Fq "online=$cpus" "$log" || die "SMP probe online CPU mismatch"
    assert_clean_uml_log "$log" "SMP scaling probe"
    elapsed=$(sed -n 's/.*POCKET_SMP_OK .*elapsed_ns=\([0-9][0-9]*\).*/\1/p' "$log")
    [[ "$elapsed" =~ ^[1-9][0-9]*$ ]] || die "SMP probe did not report elapsed time"
    mv -- "$log" "$BUILD_ROOT/logs/smp-scaling-ncpus-$cpus.log"
    find "$run_dir" -depth -delete
    trap - RETURN
    printf '%s\n' "$elapsed"
}

ONE_CPU_NS=$(run_one 1)
FOUR_CPU_NS=$(run_one 4)
(( ONE_CPU_NS * 100 >= FOUR_CPU_NS * 130 )) || \
    die "four-vCPU multi-process workload did not reach the 1.30x scaling gate"

printf 'one_cpu_ns=%s\nfour_cpu_ns=%s\nspeedup_milli=%s\n' \
    "$ONE_CPU_NS" "$FOUR_CPU_NS" "$(( ONE_CPU_NS * 1000 / FOUR_CPU_NS ))"
