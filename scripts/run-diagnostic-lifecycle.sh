#!/usr/bin/env bash

# Run the real workload lifecycle against a kernel built from the release
# source with the kernel's own validators turned on, and fail if the guest
# console reports anything. CONFIG_DEBUG_ATOMIC_SLEEP is the point: it names
# the exact defect class that patches 0003-0005 fix.
#
# Guest programs are single-quoted so the host shell cannot expand them.
# shellcheck disable=SC2016

# shellcheck source=scripts/lib.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"
# shellcheck source=scripts/linux-source-lib.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/linux-source-lib.sh"

export LC_ALL=C

ROOT=$(project_root)
BUILD_ROOT=${POCKET_BUILD_ROOT:-"$ROOT/build"}
DIAG_ROOT="$BUILD_ROOT/diagnostic-lifecycle"
TREE="$DIAG_ROOT/tree"
TREE_BUILD="$DIAG_ROOT/build"
ITERATIONS=${POCKET_DIAGNOSTIC_ITERATIONS:-10}
# lib.sh narrows IFS, so split the CPU list explicitly rather than relying on
# word splitting.
IFS=' ' read -r -a CPU_SET <<<"${POCKET_DIAGNOSTIC_CPUS:-1 2 4}"

for command in awk cp find grep mkdir python3 sha256sum tar; do
    require_command "$command"
done
safe_managed_root "$BUILD_ROOT"
[[ "$ITERATIONS" =~ ^[1-9][0-9]*$ ]] || die "POCKET_DIAGNOSTIC_ITERATIONS must be positive"
[[ -d "$BUILD_ROOT/oci/ubuntu-24.04" ]] || die "fixture is missing; run: make ubuntu-24.04"
[[ -d "$BUILD_ROOT/downloads" && -d "$BUILD_ROOT/tools" ]] || \
    die "release build root is incomplete; run: make release-artifacts"

# The lane needs its own source copy because it deliberately differs from the
# release configuration. Exactly two differences are applied, both printed
# below, and both are consequences of the kernel being a debug build:
#
#  1. the diagnostic Kconfig fragment is merged into the profile fragment;
#  2. the guest's exact accepted-physical-memory assertion is relaxed to a
#     lower bound, because a larger kernel image widens UML's own exec-shield
#     gap adjustment in arch/um/kernel/um_arch.c and the accepted size then
#     legitimately exceeds the request.
#
# Nothing else is changed: same patch series, same guest init, same protocol,
# same runtime, same workload.
printf 'diagnostic lane deltas versus the release configuration:\n'
printf '  1. merges config/kernel/x86_64-uml-diagnostic.fragment\n'
printf '  2. relaxes the guest accepted-physmem equality to >= for the debug kernel\n'

# Sealed bundles and published generations are deliberately read-only, so make
# the previous lane's tree writable before replacing it.
if [[ -d "$DIAG_ROOT" ]]; then
    find "$DIAG_ROOT" -type d -exec chmod u+rwx -- {} + 2>/dev/null || true
    find "$DIAG_ROOT" -type f -exec chmod u+w -- {} + 2>/dev/null || true
    rm -rf -- "$DIAG_ROOT"
fi
mkdir -p -- "$TREE" "$TREE_BUILD"
tar -C "$ROOT" \
    --exclude=./build --exclude='./build[0-9]*' --exclude=./build-reproduce \
    --exclude=./target --exclude=./.git \
    -cf - . | tar -C "$TREE" -xf -

cat "$ROOT/config/kernel/x86_64-uml-diagnostic.fragment" \
    >> "$TREE/config/kernel/x86_64-uml.fragment"

python3 - "$TREE" <<'PYTHON'
import pathlib
import sys

tree = pathlib.Path(sys.argv[1])
substitutions = [
    (
        "observation.accepted_physmem_bytes != config.expected_memory_bytes",
        "observation.accepted_physmem_bytes < config.expected_memory_bytes",
    ),
    (
        "accepted_physmem_bytes != config.expected_memory_bytes",
        "accepted_physmem_bytes < config.expected_memory_bytes",
    ),
    (
        "observation.accepted_physmem_bytes != config.expected_physmem_bytes",
        "observation.accepted_physmem_bytes < config.expected_physmem_bytes",
    ),
    (
        "accepted_physmem_bytes != config.expected_physmem_bytes",
        "accepted_physmem_bytes < config.expected_physmem_bytes",
    ),
    (
        "start.expected_physmem_bytes != first_observation.accepted_physmem_bytes",
        "first_observation.accepted_physmem_bytes < start.expected_physmem_bytes",
    ),
    (
        "self.accepted_physmem_bytes != Some(start.expected_physmem_bytes)",
        "self.accepted_physmem_bytes.is_none_or(|value| value < start.expected_physmem_bytes)",
    ),
    (
        "start.expected_physmem_bytes != observation.accepted_physmem_bytes",
        "observation.accepted_physmem_bytes < start.expected_physmem_bytes",
    ),
    (
        "start.expected_physmem_bytes != evidence.accepted_physmem_bytes",
        "evidence.accepted_physmem_bytes < start.expected_physmem_bytes",
    ),
]
changed = 0
for path in sorted((tree / "crates").rglob("*.rs")):
    text = original = path.read_text()
    for before, after in substitutions:
        text = text.replace(before, after)
    if text != original:
        path.write_text(text)
        changed += 1

launch = tree / "crates/pocket-runtime/src/launch.rs"
text = launch.read_text()
marker = '"accepted_physmem_bytes"'
guard = """        if field.ends_with("accepted_physmem_bytes") && actual < expected {"""
builder = tree / "crates/pocket-runtime/src/builder.rs"
text = builder.read_text()
old = """        if expected != actual {"""
new = """        if (field.ends_with("accepted_physmem_bytes") && actual < expected)
            || (!field.ends_with("accepted_physmem_bytes") && expected != actual)
        {"""
count = text.count(old)
text = text.replace(old, new)
builder.write_text(text)

protocol = tree / "crates/pocket-runtime/src/protocol.rs"
text = protocol.read_text()
old = """    compare(
        "accepted_physmem_bytes",
        &memory.bytes().to_string(),
        &hello.accepted_physmem_bytes.to_string(),
    )?;"""
new = """    if hello.accepted_physmem_bytes < memory.bytes() {
        return Err(RuntimeError::HelloMismatch {
            field: "accepted_physmem_bytes",
            expected: memory.bytes().to_string(),
            actual: hello.accepted_physmem_bytes.to_string(),
        });
    }"""
assert old in text, "host accepted-physmem comparison not found"
protocol.write_text(text.replace(old, new, 1))
residual = []
for path in sorted((tree / "crates").rglob("*.rs")):
    for number, line in enumerate(path.read_text().splitlines(), 1):
        if (
            "accepted_physmem_bytes" in line
            and "!=" in line
            and "#[" not in line
            # The tabular comparison below is rewritten in place and keeps a
            # `!=` for every field that is not the memory size.
            and "!field.ends_with" not in line
        ):
            residual.append(f"{path.relative_to(tree)}:{number}: {line.strip()}")
if residual:
    raise SystemExit(
        "unrelaxed accepted-physmem equality remains:\n  " + "\n  ".join(residual)
    )
print(f"relaxed accepted-physmem assertions in {changed + 2} files, {count} tabular sites")
PYTHON

# Share the authenticated inputs rather than re-downloading them.
for shared in downloads tools cache oci; do
    [[ -d "$BUILD_ROOT/$shared" ]] || continue
    cp -al "$BUILD_ROOT/$shared" "$TREE_BUILD/$shared" 2>/dev/null || \
        cp -a "$BUILD_ROOT/$shared" "$TREE_BUILD/$shared"
done

# Rewrite one locked digest inside one named section.
#
# The section has to be named. These keys are not unique in the file: a kernel
# variant locks its own linux_uml_sha256, and rewriting whichever copy comes
# first would silently relock the variant and leave this lane's own digest
# untouched.
relock() {
    local key=$1 value=$2 section=${3:-development_artifacts}
    python3 - "$TREE/config/sources.lock.toml" "$key" "$value" "$section" <<'PYTHON'
import pathlib
import re
import sys

path, key, value, section = (
    pathlib.Path(sys.argv[1]),
    sys.argv[2],
    sys.argv[3],
    sys.argv[4],
)
text = path.read_text()
heading = f"[{section}]"
start = text.find(f"\n{heading}\n")
if start < 0:
    raise SystemExit(f"no [{section}] section to relock {key} in")
start += 1
end = text.find("\n[", start + len(heading))
end = len(text) if end < 0 else end + 1
body, count = re.subn(
    rf'^{re.escape(key)} = "[0-9a-f]{{64}}"$',
    f'{key} = "{value}"',
    text[start:end],
    count=1,
    flags=re.MULTILINE,
)
if count != 1:
    raise SystemExit(f"could not relock {section}.{key}")
path.write_text(text[:start] + body + text[end:])
PYTHON
}

printf 'building the diagnostic kernel (this differs from the release kernel by design)\n'
if POCKET_BUILD_ROOT="$TREE_BUILD" make -C "$TREE" kernel >"$DIAG_ROOT/kernel-first.log" 2>&1; then
    :
else
    # The expected first failure is the locked-digest check: a debug kernel is
    # a different kernel, so it cannot match the release artifact. Relock to
    # what it actually built and build again.
    #
    # Any other first failure -- a compiler error, a full disk -- leaves a
    # tree with no digests at all. Relocking from that would set empty locks
    # and the second build would fail on those instead, reporting "failed
    # after relocking" for what was really the first log's problem. Insist on
    # a complete pair before believing this was the digest check.
    failed=$(find "$TREE_BUILD/kernel/replaced" -maxdepth 1 -name '*.failed-build.*' -print 2>/dev/null | sort | tail -1)
    [[ -n "$failed" ]] || { sed -n '1,80p' "$DIAG_ROOT/kernel-first.log" >&2; die "diagnostic kernel build failed"; }
    built_linux_sha=$(awk '$2 == "linux" {print $1}' "$failed/SHA256SUMS" 2>/dev/null)
    built_config_sha=$(awk '$2 == ".config" {print $1}' "$failed/SHA256SUMS" 2>/dev/null)
    if [[ ! $built_linux_sha =~ ^[0-9a-f]{64}$ || ! $built_config_sha =~ ^[0-9a-f]{64}$ ]]; then
        tail -n 40 "$DIAG_ROOT/kernel-first.log" >&2
        die "the diagnostic kernel did not build; see $DIAG_ROOT/kernel-first.log"
    fi
    relock linux_uml_sha256 "$built_linux_sha"
    relock linux_uml_config_sha256 "$built_config_sha"
    POCKET_BUILD_ROOT="$TREE_BUILD" make -C "$TREE" kernel >"$DIAG_ROOT/kernel-second.log" 2>&1 || {
        sed -n '1,80p' "$DIAG_ROOT/kernel-second.log" >&2
        die "diagnostic kernel build failed after relocking"
    }
fi

grep -Fxq 'CONFIG_DEBUG_ATOMIC_SLEEP=y' "$TREE_BUILD/kernel/x86_64-smp-p4k$LINUX_OUTPUT_SUFFIX/.config" || \
    die "the diagnostic kernel did not enable CONFIG_DEBUG_ATOMIC_SLEEP"
grep -Fxq 'CONFIG_PROVE_LOCKING=y' "$TREE_BUILD/kernel/x86_64-smp-p4k$LINUX_OUTPUT_SUFFIX/.config" || \
    die "the diagnostic kernel did not enable CONFIG_PROVE_LOCKING"
printf 'diagnostic_kernel_sha256=%s\n' \
    "$(sha256sum "$TREE_BUILD/kernel/x86_64-smp-p4k$LINUX_OUTPUT_SUFFIX/linux" | awk '{print $1}')"

printf 'sealing the diagnostic profile\n'
POCKET_BUILD_ROOT="$TREE_BUILD" make -C "$TREE" release-profile >"$DIAG_ROOT/profile.log" 2>&1 || {
    sed -n '1,60p' "$DIAG_ROOT/profile.log" >&2
    die "diagnostic profile seal failed"
}
BUNDLE=$(python3 -c '
import json, sys
for line in open(sys.argv[1]):
    line = line.strip()
    if line.startswith("\"bundle\""):
        print(json.loads("{" + line.rstrip(",") + "}")["bundle"])
        break
' "$DIAG_ROOT/profile.log")
[[ -n "$BUNDLE" && -d "$BUNDLE" ]] || die "could not locate the sealed diagnostic bundle"

STORE="$DIAG_ROOT/store"
RUNTIME_ROOT="$DIAG_ROOT/runtime"
CONSOLES="$DIAG_ROOT/consoles"
mkdir -m 0700 -- "$RUNTIME_ROOT" "$CONSOLES"
# The lane's own CLI, built from the same tree as its guest artifacts.
POCKET_BIN="$TREE_BUILD/release/x86_64-smp-p4k/host/pocket"
[[ -x "$POCKET_BIN" ]] || die "diagnostic CLI was not produced: $POCKET_BIN"

printf 'importing the Ubuntu 24.04 fixture under the diagnostic kernel\n'
"$POCKET_BIN" image import \
    --profile-bundle "$BUNDLE" --store "$STORE" --runtime-root "$RUNTIME_ROOT" \
    --reference "x86_64-smp-p4k/ubuntu:24.04" --platform linux/amd64 \
    --oci "$TREE_BUILD/oci/ubuntu-24.04" --json >"$DIAG_ROOT/import.json" \
    2>"$DIAG_ROOT/import.stderr" || {
        sed -n '1,80p' "$DIAG_ROOT/import.stderr" >&2
        die "diagnostic import failed"
    }
GENERATION=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["generation_id"])' \
    "$DIAG_ROOT/import.json")
printf 'diagnostic_generation=%s\n' "$GENERATION"

# Anything the guest kernel's own validators print. Boot banners naming these
# subsystems are not reports, so the patterns match report headers only.
DIAGNOSTIC_PATTERNS='BUG:|WARNING:|Oops|bad: scheduling|Kernel panic|possible circular locking dependency|INCONSISTENT LOCK STATE|possible recursive locking|possible irq lock inversion|lock held when returning to user space|suspicious RCU usage|self-detected stall|detected stalls on CPU|held lock freed|ODEBUG:|list_add corruption|list_del corruption|Segfault'

failures=0
scan_console() {
    local label=$1 path=$2

    # Fail closed on a transcript that is missing, empty, or not actually a
    # guest console. grep exits 2 for a file it cannot read, which reads as
    # "found nothing" to an `if`, so a lane whose whole purpose is this scan
    # would report a clean result having scanned nothing at all.
    if [[ ! -f "$path" || -L "$path" ]]; then
        printf 'NO CONSOLE TRANSCRIPT for %s (%s)\n' "$label" "$path" >&2
        failures=$((failures + 1))
        return
    fi
    if ! grep -q 'Linux version' "$path"; then
        printf 'CONSOLE TRANSCRIPT for %s carries no kernel banner (%s)\n' \
            "$label" "$path" >&2
        failures=$((failures + 1))
        return
    fi
    if grep -nEm 5 "$DIAGNOSTIC_PATTERNS" "$path"; then
        printf 'DIAGNOSTIC REPORTED in %s (%s)\n' "$label" "$path" >&2
        failures=$((failures + 1))
    fi
}

for cpus in "${CPU_SET[@]}"; do
    for index in $(seq 1 "$ITERATIONS"); do
        label="cpus-$cpus-run-$index"
        console="$CONSOLES/$label.log"
        if ! "$POCKET_BIN" run \
            --profile-bundle "$BUNDLE" --store "$STORE" --runtime-root "$RUNTIME_ROOT" \
            --cpus "$cpus" --timeout 300s --console-log "$console" \
            "$GENERATION" -- /bin/sh -c 'exec nproc' \
            >"$CONSOLES/$label.stdout" 2>"$CONSOLES/$label.stderr"
        then
            printf 'FAIL %s\n' "$label" >&2
            sed -n '1,40p' "$CONSOLES/$label.stdout" >&2
            sed -n '1,40p' "$CONSOLES/$label.stderr" >&2
            failures=$((failures + 1))
            continue
        fi
        [[ $(cat "$CONSOLES/$label.stdout") == "$cpus" ]] || {
            printf 'FAIL %s: workload did not report %s online CPUs\n' "$label" "$cpus" >&2
            failures=$((failures + 1))
        }
        scan_console "$label" "$console"
    done
    printf 'diagnostic lane cpus=%s iterations=%s complete\n' "$cpus" "$ITERATIONS"
done

# Exercise the paths the correction actually touches: channel teardown under
# stdin traffic, and a signal-terminated workload.
# 256 KiB, not more, and the size is measured rather than guessed. This kernel
# validates every lock and every tracked object, and the guest serial line is a
# per-character path, so cost per byte explodes once a payload exceeds the tty
# buffer and flow control starts cycling that path. Measured on this host, same
# host binary and guest init throughout:
#
#   payload   release kernel   diagnostic kernel
#   256 KiB   1.9 s            2.3 s
#   1 MB      2.2 s            did not finish in 922 s
#   3 MB      3.1 s            --
#
# The release kernel is linear; the debug kernel is not. 256 KiB exercises the
# same channel-teardown-under-stdin path this lane exists to check, and the
# release suite covers the large-payload contract at 3 MB.
printf 'diagnostic stdin case\n'
head -c 262144 /dev/urandom >"$DIAG_ROOT/stdin-payload"
"$POCKET_BIN" run --profile-bundle "$BUNDLE" --store "$STORE" --runtime-root "$RUNTIME_ROOT" \
    --cpus 4 --timeout 600s --console-log "$CONSOLES/stdin.log" -i \
    "$GENERATION" -- /bin/sh -c 'sha256sum | cut -d" " -f1' \
    <"$DIAG_ROOT/stdin-payload" >"$CONSOLES/stdin.stdout" 2>"$CONSOLES/stdin.stderr" ||
    failures=$((failures + 1))
[[ $(awk '{print $1}' "$CONSOLES/stdin.stdout") == \
   $(sha256sum "$DIAG_ROOT/stdin-payload" | awk '{print $1}') ]] || {
    printf 'FAIL diagnostic stdin digest mismatch\n' >&2
    failures=$((failures + 1))
}
scan_console stdin "$CONSOLES/stdin.log"

printf 'diagnostic process-churn case\n'
"$POCKET_BIN" run --profile-bundle "$BUNDLE" --store "$STORE" --runtime-root "$RUNTIME_ROOT" \
    --cpus 4 --timeout 600s --console-log "$CONSOLES/churn.log" \
    "$GENERATION" -- /bin/sh -c 'i=0; while [ $i -lt 200 ]; do (/bin/true) & i=$((i+1)); done; wait; echo churn-ok' \
    >"$CONSOLES/churn.stdout" 2>"$CONSOLES/churn.stderr" || failures=$((failures + 1))
grep -Fqx churn-ok "$CONSOLES/churn.stdout" || {
    printf 'FAIL diagnostic churn case\n' >&2
    failures=$((failures + 1))
}
scan_console churn "$CONSOLES/churn.log"

# hostfs is the newest guest-kernel surface this runtime uses, and it is the
# one a debug kernel has the most to say about: every mount, every dentry and
# every page-cache write goes through validators that the release kernel does
# not run. Exercise it read-write, then read-only, and scan both consoles.
printf 'diagnostic shared-directory case\n'
SHARED="$DIAG_ROOT/shared"
mkdir -m 0700 -- "$SHARED"
printf 'from the host\n' >"$SHARED/input.txt"
"$POCKET_BIN" run --profile-bundle "$BUNDLE" --store "$STORE" --runtime-root "$RUNTIME_ROOT" \
    --cpus 4 --timeout 600s --console-log "$CONSOLES/volume.log" \
    --volume "$SHARED:/data" \
    "$GENERATION" -- /bin/sh -c 'cat /data/input.txt && head -c 65536 /dev/urandom > /data/out.bin && sync' \
    >"$CONSOLES/volume.stdout" 2>"$CONSOLES/volume.stderr" || failures=$((failures + 1))
[[ $(cat "$CONSOLES/volume.stdout") == "from the host" ]] || {
    printf 'FAIL diagnostic volume case did not read the host file\n' >&2
    failures=$((failures + 1))
}
[[ $(stat -c '%s' "$SHARED/out.bin" 2>/dev/null) == 65536 ]] || {
    printf 'FAIL diagnostic volume case did not write 65536 bytes to the host\n' >&2
    failures=$((failures + 1))
}
scan_console volume "$CONSOLES/volume.log"

"$POCKET_BIN" run --profile-bundle "$BUNDLE" --store "$STORE" --runtime-root "$RUNTIME_ROOT" \
    --cpus 4 --timeout 600s --console-log "$CONSOLES/volume-ro.log" \
    --volume "$SHARED:/data:ro" \
    "$GENERATION" -- /bin/sh -c 'if touch /data/denied 2>/dev/null; then echo wrote; else echo refused; fi' \
    >"$CONSOLES/volume-ro.stdout" 2>"$CONSOLES/volume-ro.stderr" || failures=$((failures + 1))
[[ $(cat "$CONSOLES/volume-ro.stdout") == "refused" ]] || {
    printf 'FAIL diagnostic read-only volume case was not refused\n' >&2
    failures=$((failures + 1))
}
[[ ! -e "$SHARED/denied" ]] || {
    printf 'FAIL diagnostic read-only volume case wrote to the host\n' >&2
    failures=$((failures + 1))
}
scan_console volume-ro "$CONSOLES/volume-ro.log"

printf 'console transcripts retained under %s\n' "$CONSOLES"
(( failures == 0 )) || die "diagnostic lane recorded $failures failures"
printf 'POCKET_DIAGNOSTIC_LIFECYCLE_OK\n'
