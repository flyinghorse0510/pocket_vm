#!/usr/bin/env bash

# Prove that nothing UML inherited reaches guest userspace.
#
# In seccomp mode the stub is supposed to end up holding exactly one
# descriptor: the socket at 0 that it signals the UML kernel through. Mapping
# descriptors arrive later by SCM_RIGHTS and are closed again after use, so a
# sample may briefly catch one. Anything else surviving is a descriptor the
# guest can reach, and one of the ones UML holds maps all of its physical
# memory.
#
# The audit is deliberately hostile about what it hands UML: a run of junk
# descriptors and one sparse high-numbered one, all inheritable, so the
# cleanup has to enumerate rather than assume a bound. Both cleanup paths end
# here -- close_range where the host has it, /proc/self/fd enumeration where it
# does not -- and neither is allowed to leak.

# shellcheck source=scripts/lib.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"
# shellcheck source=scripts/linux-source-lib.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/linux-source-lib.sh"

ROOT=$(project_root)
BUILD_ROOT=${POCKET_BUILD_ROOT:-"$ROOT/build"}
PROFILE=${POCKET_KERNEL_PROFILE:-x86_64-smp-p4k$LINUX_OUTPUT_SUFFIX}
KERNEL=${POCKET_KERNEL:-"$BUILD_ROOT/kernel/$PROFILE/linux"}
INITRAMFS=${POCKET_INITRAMFS:-"$BUILD_ROOT/initramfs/probe.cpio"}
DISK_SOURCE=${POCKET_PROBE_DISK:-"$BUILD_ROOT/disks/probe.ext4"}
CPUS=${POCKET_CPUS:-1}
MEMORY=${POCKET_MEMORY:-256M}
JUNK_DESCRIPTORS=${POCKET_JUNK_DESCRIPTORS:-40}
SPARSE_DESCRIPTOR=${POCKET_SPARSE_DESCRIPTOR:-900}
SAMPLES=${POCKET_FD_SAMPLES:-25}

for command in awk find mkfifo readlink; do
    require_command "$command"
done
safe_managed_root "$BUILD_ROOT"
[[ -x $KERNEL ]] || die "UML kernel is missing: $KERNEL"
[[ -f $INITRAMFS ]] || die "probe initramfs is missing: $INITRAMFS"
[[ -f $DISK_SOURCE ]] || die "probe ext4 disk is missing: $DISK_SOURCE"
[[ $JUNK_DESCRIPTORS =~ ^[0-9]+$ && $JUNK_DESCRIPTORS -le 200 ]] || \
    die "POCKET_JUNK_DESCRIPTORS must be 0..200"
[[ $SPARSE_DESCRIPTOR =~ ^[0-9]+$ && $SPARSE_DESCRIPTOR -ge 100 ]] || \
    die "POCKET_SPARSE_DESCRIPTOR must be at least 100"

WORK=$(mktemp -d "$BUILD_ROOT/tmp/stub-fd-audit.XXXXXX")
DISK="$WORK/disk.ext4"
FIFO="$WORK/console.in"
LOG="$WORK/console.log"
MARKER="$WORK/inherited-marker"
UML_PID=

cleanup() {
    local status=$?
    # The guest is deliberately left idling, so both of these are killed rather
    # than waited for; job-control notices about it are not findings.
    set +m
    [[ -z $UML_PID ]] || kill -9 "$UML_PID" 2>/dev/null || true
    [[ -z ${HOLDER_PID:-} ]] || kill "$HOLDER_PID" 2>/dev/null || true
    wait "$UML_PID" "${HOLDER_PID:-}" 2>/dev/null || true
    pkill -9 -f "ubda=$DISK" 2>/dev/null || true
    [[ $WORK == "$BUILD_ROOT/tmp/stub-fd-audit."* ]] || exit "$status"
    rm -rf -- "$WORK"
    exit "$status"
}
trap cleanup EXIT

cp -- "$DISK_SOURCE" "$DISK"
printf 'pocket-inherited-descriptor\n' > "$MARKER"
mkfifo -m 0600 "$FIFO"
# The console needs a stdin that never reaches EOF: on EOF UML hangs the
# console up, and the guest's init then dies writing to it.
sleep 600 > "$FIFO" &
HOLDER_PID=$!

# Hand UML a crowded, sparse descriptor table. All of these are marked
# inheritable on purpose; none of them may survive into the stub.
open_junk_descriptors() {
    local index
    for ((index = 0; index < JUNK_DESCRIPTORS; index++)); do
        eval "exec $((20 + index))<\"\$MARKER\""
    done
    eval "exec $SPARSE_DESCRIPTOR<\"\$MARKER\""
}
open_junk_descriptors

# The cleanup has to hold under conditions the ordinary path never produces.
#
#   crowded  descriptor 0 is the console's input, as usual.
#   free-fd0 the console reads from descriptor 3 instead, so descriptor 0 is
#            unused when UML opens its own. Anything UML then places there has
#            to be moved before the signalling socket claims it -- a case that
#            never arises when the launcher supplies open standard descriptors.
#   low-nofile
#            the soft descriptor limit is dropped below a descriptor that is
#            already open. Linux allows that, so any cleanup that trusts the
#            limit as an upper bound silently leaves that descriptor behind.
# shellcheck disable=SC2054  # the commas belong to UML's console syntax
case ${POCKET_FD_AUDIT_SCENARIO:-crowded} in
    crowded)    CONSOLE_ARGS=(con=null con0=fd:0,fd:1) ;;
    free-fd0)   CONSOLE_ARGS=(con=null con0=fd:3,fd:1) ;;
    low-nofile) CONSOLE_ARGS=(con=null con0=fd:0,fd:1) ;;
    *) die "unknown POCKET_FD_AUDIT_SCENARIO: $POCKET_FD_AUDIT_SCENARIO" ;;
esac

# /bin/sh idles on a console that never delivers a line, which keeps the stub
# alive long enough to sample it.
launch() {
    case ${POCKET_FD_AUDIT_SCENARIO:-crowded} in
        free-fd0)
            exec 3< "$FIFO"
            exec 0<&-
            ;;
        low-nofile)
            exec 0< "$FIFO"
            ulimit -S -n 64 || die "could not lower the soft descriptor limit"
            ;;
        *)
            exec 0< "$FIFO"
            ;;
    esac
    exec "$KERNEL" seccomp=on ncpus="$CPUS" mem="$MEMORY" \
        initrd="$INITRAMFS" ubda="$DISK" root=/dev/root rootfstype=ramfs \
        rdinit=/bin/sh "${CONSOLE_ARGS[@]}"
}
launch > "$LOG" 2>&1 &
UML_PID=$!

stub_pids() {
    local pid comm
    for pid in $(pgrep -P "$UML_PID" 2>/dev/null; pgrep -f uml-userspace 2>/dev/null); do
        comm=$(cat "/proc/$pid/comm" 2>/dev/null) || continue
        [[ $comm == uml-userspace ]] || continue
        printf '%s\n' "$pid"
    done | sort -u
}

deadline=$((SECONDS + 30))
while [[ -z $(stub_pids) ]]; do
    ((SECONDS < deadline)) || die "no uml-userspace stub appeared within 30s"
    sleep 0.2
done

observed_clean=0
checked_stubs=0
for ((sample = 0; sample < SAMPLES; sample++)); do
    for pid in $(stub_pids); do
        [[ -d /proc/$pid/fd ]] || continue
        mapfile -t descriptors < <(find "/proc/$pid/fd" -mindepth 1 -maxdepth 1 -printf '%f\n' 2>/dev/null | sort -n)
        [[ ${#descriptors[@]} -gt 0 ]] || continue
        ((checked_stubs += 1))

        for descriptor in "${descriptors[@]}"; do
            target=$(readlink "/proc/$pid/fd/$descriptor" 2>/dev/null) || continue
            [[ $target != *"$MARKER"* ]] || \
                die "stub $pid inherited descriptor $descriptor -> $target"
            # 0 is the signalling socket; 1 is where an SCM_RIGHTS mapping
            # descriptor lands while it is being used.
            [[ $descriptor == 0 || $descriptor == 1 ]] || \
                die "stub $pid holds unexpected descriptor $descriptor -> $target"
        done

        if [[ ${#descriptors[@]} -eq 1 && ${descriptors[0]} == 0 ]]; then
            observed_clean=1
        fi

        privs=$(awk '/^NoNewPrivs:/ { print $2 }' "/proc/$pid/status" 2>/dev/null)
        mode=$(awk '/^Seccomp:/ { print $2 }' "/proc/$pid/status" 2>/dev/null)
        [[ -z $privs || $privs == 1 ]] || die "stub $pid has NoNewPrivs=$privs"
        [[ -z $mode || $mode == 2 ]] || die "stub $pid has Seccomp=$mode"
    done
    sleep 0.1
done

((checked_stubs > 0)) || die "never sampled a live stub's descriptor table"
((observed_clean == 1)) || \
    die "no sample showed the stub holding only its signalling socket"

printf 'kernel: %s\n' "$KERNEL"
printf 'scenario: %s\n' "${POCKET_FD_AUDIT_SCENARIO:-crowded}"
printf 'inherited descriptors offered: %d contiguous plus one at %d\n' \
    "$JUNK_DESCRIPTORS" "$SPARSE_DESCRIPTOR"
printf 'stub descriptor samples: %d\n' "$checked_stubs"
printf 'stub retained only its signalling socket, NoNewPrivs=1, Seccomp=2\n'
printf 'POCKET_STUB_FD_AUDIT_OK\n'
