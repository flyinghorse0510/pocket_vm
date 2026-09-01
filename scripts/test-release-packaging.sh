#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
USER_HOME=$(python3 -c 'import os, pwd; print(pwd.getpwuid(os.geteuid()).pw_dir)')
TEST_ROOT=$(mktemp -d "$USER_HOME/.pocket-release-test.XXXXXXXX")

cleanup() {
    if [[ -n ${TEST_ROOT:-} && -d "$TEST_ROOT" &&
          "$TEST_ROOT" == "$USER_HOME/.pocket-release-test."* ]]; then
        find "$TEST_ROOT" -depth -type f -exec chmod u+w -- {} +
        find "$TEST_ROOT" -depth -type d -exec chmod u+rwx -- {} +
        find "$TEST_ROOT" -depth -delete
    fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

for command in chmod cmp cp find ln mkdir mktemp python3 sha256sum truncate wc; do
    command -v "$command" >/dev/null 2>&1 || {
        printf 'test-release-packaging: missing command: %s\n' "$command" >&2
        exit 1
    }
done

make_profile() {
    local revision=$1
    local artifact_text=$2
    local profile_root="$TEST_ROOT/profiles/x86_64-smp-p4k/$revision"

    mkdir -p -- "$profile_root/host"
    printf '%s\n' "$artifact_text" > "$profile_root/host/linux"
    chmod 0555 "$profile_root/host/linux"
    python3 - "$profile_root" "$revision" <<'PY'
import hashlib
import json
import os
import sys
from pathlib import Path

root = Path(sys.argv[1])
revision = sys.argv[2]
artifact = (root / "host/linux").read_bytes()
manifest = {
    "schema_version": 3,
    "profile_id": "x86_64-smp-p4k",
    "profile_revision": f"sha256:{revision}",
    "maturity": "experimental",
    "host_architecture": "x86_64",
    "host_elf_machine": 62,
    "artifacts": {
        "uml": {
            "path": "host/linux",
            "sha256": f"sha256:{hashlib.sha256(artifact).hexdigest()}",
            "size": len(artifact),
        }
    },
}
(root / "profile.json").write_text(
    json.dumps(manifest, sort_keys=True, indent=2) + "\n",
    encoding="utf-8",
)
os.chmod(root / "profile.json", 0o444)
os.chmod(root / "host", 0o555)
os.chmod(root, 0o555)
PY
    printf '%s\n' "$profile_root"
}

REVISION_A=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
REVISION_B=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
REVISION_LEGACY=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
PROFILE_A=$(make_profile "$REVISION_A" "synthetic-linux-a")
PROFILE_B=$(make_profile "$REVISION_B" "synthetic-linux-b")
PROFILE_LEGACY=$(make_profile "$REVISION_LEGACY" "synthetic-linux-legacy")
chmod 0644 "$PROFILE_LEGACY/profile.json"
python3 - "$PROFILE_LEGACY/profile.json" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
manifest = json.loads(path.read_text(encoding="utf-8"))
manifest["schema_version"] = 2
path.write_text(
    json.dumps(manifest, sort_keys=True, indent=2) + "\n",
    encoding="utf-8",
)
PY
chmod 0444 "$PROFILE_LEGACY/profile.json"
cp -- /usr/bin/true "$TEST_ROOT/pocket"
chmod 0755 "$TEST_ROOT/pocket"
mkdir -p -- \
    "$TEST_ROOT/output-a" \
    "$TEST_ROOT/output-b" \
    "$TEST_ROOT/output-c" \
    "$TEST_ROOT/output-cli-variant" \
    "$TEST_ROOT/output-foreign" \
    "$TEST_ROOT/output-legacy" \
    "$TEST_ROOT/sbom-a" \
    "$TEST_ROOT/sbom-b"

PACKAGE_A_JSON=$(
    "$ROOT/scripts/package-release.py" \
        --repo-root "$ROOT" \
        --profile "$PROFILE_A" \
        --pocket "$TEST_ROOT/pocket" \
        --output-dir "$TEST_ROOT/output-a"
)
PACKAGE_B_JSON=$(
    "$ROOT/scripts/package-release.py" \
        --repo-root "$ROOT" \
        --profile "$PROFILE_A" \
        --pocket "$TEST_ROOT/pocket" \
        --output-dir "$TEST_ROOT/output-b"
)
ARCHIVE_A=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["archive"])' <<<"$PACKAGE_A_JSON")
ARCHIVE_B=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["archive"])' <<<"$PACKAGE_B_JSON")
RELEASE_ID=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["release_id"])' <<<"$PACKAGE_A_JSON")
cmp -- "$ARCHIVE_A" "$ARCHIVE_B"

cp -- "$TEST_ROOT/pocket" "$TEST_ROOT/pocket-variant"
printf '\0' >> "$TEST_ROOT/pocket-variant"
chmod 0755 "$TEST_ROOT/pocket-variant"
PACKAGE_VARIANT_JSON=$(
    "$ROOT/scripts/package-release.py" \
        --repo-root "$ROOT" \
        --profile "$PROFILE_A" \
        --pocket "$TEST_ROOT/pocket-variant" \
        --output-dir "$TEST_ROOT/output-cli-variant"
)
RELEASE_ID_VARIANT=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["release_id"])' <<<"$PACKAGE_VARIANT_JSON")
[[ "$RELEASE_ID_VARIANT" != "$RELEASE_ID" ]]

if "$ROOT/scripts/package-release.py" \
    --repo-root "$ROOT" \
    --profile "$PROFILE_LEGACY" \
    --pocket "$TEST_ROOT/pocket" \
    --output-dir "$TEST_ROOT/output-legacy" \
    >"$TEST_ROOT/legacy.out" 2>"$TEST_ROOT/legacy.err"; then
    printf 'test-release-packaging: packager accepted a legacy profile schema\n' >&2
    exit 1
fi

ARCHIVE_DIGEST_BEFORE=$(sha256sum "$ARCHIVE_A")
if "$ROOT/scripts/package-release.py" \
    --repo-root "$ROOT" \
    --profile "$PROFILE_A" \
    --pocket "$TEST_ROOT/pocket" \
    --output-dir "$TEST_ROOT/output-a" \
    >"$TEST_ROOT/no-replace.out" 2>"$TEST_ROOT/no-replace.err"; then
    printf 'test-release-packaging: packager overwrote an archive\n' >&2
    exit 1
fi
[[ $(sha256sum "$ARCHIVE_A") == "$ARCHIVE_DIGEST_BEFORE" ]]

cp -- "$ARCHIVE_A" "$TEST_ROOT/trailing-data.tar"
chmod 0644 "$TEST_ROOT/trailing-data.tar"
truncate -s +10240 "$TEST_ROOT/trailing-data.tar"
chmod 0444 "$TEST_ROOT/trailing-data.tar"
if "$ROOT/scripts/install-release.py" install \
    --archive "$TEST_ROOT/trailing-data.tar" \
    --prefix "$TEST_ROOT/trailing-prefix" \
    >"$TEST_ROOT/trailing.out" 2>"$TEST_ROOT/trailing.err"; then
    printf 'test-release-packaging: verifier accepted trailing archive data\n' >&2
    exit 1
fi

cp -- "$ARCHIVE_A" "$TEST_ROOT/toctou.tar"
chmod 0644 "$TEST_ROOT/toctou.tar"
python3 - "$ROOT" "$TEST_ROOT/toctou.tar" <<'PY'
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(sys.argv[1]) / "scripts"))
from pocket_release import ReleaseError, inspect_archive, open_verified_archive

path = Path(sys.argv[2])
info = inspect_archive(path)
with path.open("r+b") as stream:
    stream.seek(1024)
    original = stream.read(1)
    assert original
    stream.seek(1024)
    stream.write(bytes([original[0] ^ 1]))
    stream.flush()
    os.fsync(stream.fileno())
try:
    with open_verified_archive(info):
        pass
except ReleaseError:
    pass
else:
    raise AssertionError("archive mutation between validation and use was accepted")
PY

python3 - "$ARCHIVE_A" "$TEST_ROOT/reordered.tar" <<'PY'
import sys
import tarfile

source_path, output_path = sys.argv[1:]
with tarfile.open(source_path, mode="r:") as source:
    members = source.getmembers()
    root = members[:1]
    directories = [member for member in members[1:] if member.isdir()]
    files = [member for member in members[1:] if member.isreg()]
    with tarfile.open(output_path, mode="w", format=tarfile.USTAR_FORMAT) as output:
        for member in [*root, *reversed(directories), *files]:
            stream = source.extractfile(member) if member.isreg() else None
            output.addfile(member, stream)
PY
chmod 0444 "$TEST_ROOT/reordered.tar"
if "$ROOT/scripts/install-release.py" install \
    --archive "$TEST_ROOT/reordered.tar" \
    --prefix "$TEST_ROOT/reordered-prefix" \
    >"$TEST_ROOT/reordered.out" 2>"$TEST_ROOT/reordered.err"; then
    printf 'test-release-packaging: verifier accepted reordered members\n' >&2
    exit 1
fi

"$ROOT/scripts/generate-release-sbom.py" \
    --cargo-lock "$ROOT/Cargo.lock" \
    --source-lock "$ROOT/config/sources.lock.toml" \
    --output "$TEST_ROOT/sbom-a/source-inputs.spdx.json" >/dev/null
"$ROOT/scripts/generate-release-sbom.py" \
    --cargo-lock "$ROOT/Cargo.lock" \
    --source-lock "$ROOT/config/sources.lock.toml" \
    --output "$TEST_ROOT/sbom-b/source-inputs.spdx.json" >/dev/null
cmp -- \
    "$TEST_ROOT/sbom-a/source-inputs.spdx.json" \
    "$TEST_ROOT/sbom-b/source-inputs.spdx.json"
python3 - "$TEST_ROOT/sbom-a/source-inputs.spdx.json" <<'PY'
import json
import sys
from pathlib import Path

document = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
assert document["spdxVersion"] == "SPDX-2.3"
assert document["dataLicense"] == "CC0-1.0"
assert document["documentDescribes"] == ["SPDXRef-PocketVmSourceInputs"]
assert any(package["name"] == "Linux" for package in document["packages"])
root = next(
    package
    for package in document["packages"]
    if package["SPDXID"] == "SPDXRef-PocketVmSourceInputs"
)
assert "not a binary scan" in root["comment"]
PY

PREFIX="$TEST_ROOT/prefix"
INSTALL_A_JSON=$(
    "$ROOT/scripts/install-release.py" install \
        --archive "$ARCHIVE_A" \
        --prefix "$PREFIX"
)
"$ROOT/scripts/install-release.py" verify \
    --archive "$ARCHIVE_A" \
    --prefix "$PREFIX" >/dev/null
REINSTALL_A_JSON=$(
    "$ROOT/scripts/install-release.py" install \
        --archive "$ARCHIVE_A" \
        --prefix "$PREFIX"
)
python3 - "$INSTALL_A_JSON" "$REINSTALL_A_JSON" <<'PY'
import json
import sys

first = json.loads(sys.argv[1])
second = json.loads(sys.argv[2])
assert first["changed"] is True
assert second["changed"] is False
assert first["release_changed"] is True
assert first["profile_changed"] is True
assert second["release_changed"] is False
assert second["profile_changed"] is False
assert first["launcher_changed"] is True
assert second["launcher_changed"] is False
assert first["release"] == second["release"]
assert first["launcher"] == second["launcher"]
assert first["profile"] == second["profile"]
PY

# A launcher deleted by hand is recreated, and that has to be reported as a
# change even though both installed trees are already exactly right.
rm -f -- "$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["launcher"])' "$INSTALL_A_JSON")"
RELAUNCH_A_JSON=$(
    "$ROOT/scripts/install-release.py" install \
        --archive "$ARCHIVE_A" \
        --prefix "$PREFIX"
)
python3 - "$RELAUNCH_A_JSON" <<'PY'
import json
import sys

recreated = json.loads(sys.argv[1])
assert recreated["launcher_changed"] is True, recreated
assert recreated["changed"] is True, recreated
assert recreated["release_changed"] is False, recreated
assert recreated["profile_changed"] is False, recreated
PY

PACKAGE_C_JSON=$(
    "$ROOT/scripts/package-release.py" \
        --repo-root "$ROOT" \
        --profile "$PROFILE_B" \
        --pocket "$TEST_ROOT/pocket" \
        --output-dir "$TEST_ROOT/output-c"
)
ARCHIVE_C=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["archive"])' <<<"$PACKAGE_C_JSON")
RELEASE_ID_C=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["release_id"])' <<<"$PACKAGE_C_JSON")
[[ "$RELEASE_ID_C" != "$RELEASE_ID" ]]
"$ROOT/scripts/install-release.py" install \
    --archive "$ARCHIVE_C" \
    --prefix "$PREFIX" >/dev/null
[[ $(find "$PREFIX/lib/pocket-vm/r" -mindepth 1 -maxdepth 1 -type d | wc -l) == 2 ]]
[[ $(find "$PREFIX/lib/pocket-vm/p/x86_64-smp-p4k" -mindepth 1 -maxdepth 1 -type d | wc -l) == 2 ]]
[[ $(find "$PREFIX/bin" -mindepth 1 -maxdepth 1 -type f -name 'pocket-*' | wc -l) == 2 ]]

# Two installers racing to publish the same release is a race one of them wins,
# not an error. The losers must verify what won and report that they changed
# nothing -- and each has to discard its own already-sealed stage, which is
# read-only by the time the rename fails.
# The prefix itself is left absent so the installers race to create it too.
CONCURRENT_PREFIX="$TEST_ROOT/concurrent-prefix"
CONCURRENT_PIDS=()
for slot in 1 2 3 4; do
    "$ROOT/scripts/install-release.py" install \
        --archive "$ARCHIVE_A" \
        --prefix "$CONCURRENT_PREFIX" \
        >"$TEST_ROOT/concurrent-$slot.out" 2>"$TEST_ROOT/concurrent-$slot.err" &
    CONCURRENT_PIDS+=("$!")
done
CONCURRENT_FAILURES=0
for pid in "${CONCURRENT_PIDS[@]}"; do
    wait "$pid" || CONCURRENT_FAILURES=$((CONCURRENT_FAILURES + 1))
done
if (( CONCURRENT_FAILURES != 0 )); then
    cat "$TEST_ROOT"/concurrent-*.err >&2
    printf 'test-release-packaging: %s concurrent installs failed\n' \
        "$CONCURRENT_FAILURES" >&2
    exit 1
fi
python3 - "$TEST_ROOT"/concurrent-*.out <<'PY'
import json
import sys

results = [json.load(open(path)) for path in sys.argv[1:]]
assert len(results) == 4, results
changed = [result for result in results if result["release_changed"]]
assert len(changed) == 1, f"expected exactly one publisher, got {len(changed)}"
assert all(result["verified"] for result in results), results
assert len({result["release"] for result in results}) == 1, results
assert len({result["launcher"] for result in results}) == 1, results
PY
if find "$CONCURRENT_PREFIX" -name '.install-*' -print -quit | grep -q .; then
    printf 'test-release-packaging: a concurrent install left its stage behind\n' >&2
    exit 1
fi
"$ROOT/scripts/install-release.py" verify \
    --archive "$ARCHIVE_A" --prefix "$CONCURRENT_PREFIX" >/dev/null

CONFLICT_PREFIX="$TEST_ROOT/conflict-prefix"
RELEASE_REVISION=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["release_revision"].removeprefix("sha256:"))' <<<"$PACKAGE_A_JSON")
mkdir -p -- "$CONFLICT_PREFIX/lib/pocket-vm/r/$RELEASE_REVISION"
printf 'do-not-overwrite\n' > \
    "$CONFLICT_PREFIX/lib/pocket-vm/r/$RELEASE_REVISION/marker"
if "$ROOT/scripts/install-release.py" install \
    --archive "$ARCHIVE_A" \
    --prefix "$CONFLICT_PREFIX" \
    >"$TEST_ROOT/conflict.out" 2>"$TEST_ROOT/conflict.err"; then
    printf 'test-release-packaging: installer overwrote a conflicting release\n' >&2
    exit 1
fi
[[ $(<"$CONFLICT_PREFIX/lib/pocket-vm/r/$RELEASE_REVISION/marker") == do-not-overwrite ]]

INSTALLED_RELEASE=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["release"])' <<<"$INSTALL_A_JSON")
chmod 0644 "$INSTALLED_RELEASE/share/pocket-vm/Cargo.lock"
printf 'corruption\n' >> "$INSTALLED_RELEASE/share/pocket-vm/Cargo.lock"
if "$ROOT/scripts/install-release.py" verify \
    --archive "$ARCHIVE_A" \
    --prefix "$PREFIX" \
    >"$TEST_ROOT/corruption.out" 2>"$TEST_ROOT/corruption.err"; then
    printf 'test-release-packaging: verifier accepted installed corruption\n' >&2
    exit 1
fi

ln -s -- "$ARCHIVE_A" "$TEST_ROOT/archive-link.tar"
if "$ROOT/scripts/install-release.py" install \
    --archive "$TEST_ROOT/archive-link.tar" \
    --prefix "$TEST_ROOT/link-prefix" \
    >"$TEST_ROOT/link.out" 2>"$TEST_ROOT/link.err"; then
    printf 'test-release-packaging: installer followed an archive symlink\n' >&2
    exit 1
fi

chmod 0755 "$PROFILE_A"
printf 'foreign\n' > "$PROFILE_A/foreign"
chmod 0444 "$PROFILE_A/foreign"
chmod 0555 "$PROFILE_A"
if "$ROOT/scripts/package-release.py" \
    --repo-root "$ROOT" \
    --profile "$PROFILE_A" \
    --pocket "$TEST_ROOT/pocket" \
    --output-dir "$TEST_ROOT/output-foreign" \
    >"$TEST_ROOT/foreign.out" 2>"$TEST_ROOT/foreign.err"; then
    printf 'test-release-packaging: packager accepted a foreign profile file\n' >&2
    exit 1
fi

printf 'release packaging tests passed\n'
