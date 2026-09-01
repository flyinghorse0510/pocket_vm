#!/usr/bin/env bash

# Rebuild the whole release in a second, completely independent build root and
# require the profile revision, the sealed bundle tree, and the release archive
# to match the primary build byte for byte.
#
# The second root shares no download, no Go module cache, no kernel object tree
# and no intermediate output with the first: everything under it is produced by
# this run. That is what makes the result evidence rather than a restatement of
# the first build's own outputs.
#
# The kernel, e2fsprogs and Skopeo builds dominate the wall clock, and the
# first Skopeo build needs HTTPS access to the Go module proxy and checksum
# database.

# shellcheck source=scripts/lib.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"

export LC_ALL=C

ROOT=$(project_root)
PRIMARY_ROOT=${POCKET_BUILD_ROOT:-"$ROOT/build"}
SECOND_ROOT=${POCKET_REPRODUCE_ROOT:-}

for command in cmp diff find make mkdir mktemp python3 sha256sum; do
    require_command "$command"
done
safe_managed_root "$PRIMARY_ROOT"
[[ -d "$PRIMARY_ROOT/profiles" ]] || die "run 'make release-profile' first: $PRIMARY_ROOT"

if [[ -z "$SECOND_ROOT" ]]; then
    mkdir -p -- "$ROOT/build-reproduce"
    SECOND_ROOT=$(mktemp -d "$ROOT/build-reproduce/r.XXXXXXXX")
fi
[[ "$SECOND_ROOT" = /* ]] || die "POCKET_REPRODUCE_ROOT must be absolute"
[[ "$SECOND_ROOT" != "$PRIMARY_ROOT" ]] || die "the second build root must not be the first"
mkdir -p -- "$SECOND_ROOT"
# A named root that already carries a sealed profile is one this script built
# on an earlier run: its independence was established when it was created, so
# reuse it rather than spend another full build to compare the same bytes. Any
# other non-empty directory is refused, because then nothing is established.
if [[ -d "$SECOND_ROOT/profiles" && -f "$SECOND_ROOT/seal.json" ]]; then
    printf 'reusing the independent build root from an earlier run\n'
elif [[ -n "$(find "$SECOND_ROOT" -mindepth 1 -print -quit)" ]]; then
    die "the second build root must start empty: $SECOND_ROOT"
fi

printf 'primary_build_root=%s\n' "$PRIMARY_ROOT"
printf 'second_build_root=%s\n' "$SECOND_ROOT"

# The profile revision is a content address, so the sealer publishes the second
# build under the same name if and only if every input byte matched.
POCKET_BUILD_ROOT="$SECOND_ROOT" make -C "$ROOT" release-profile >"$SECOND_ROOT/seal.json" || {
    tail -n 40 "$SECOND_ROOT/seal.json" >&2
    die "the second build root did not produce a sealed profile"
}
# The sealer prints its JSON object in the middle of the build log -- make
# still has its own trailing lines to emit -- so take the last complete object
# rather than everything from its opening brace onwards.
second_revision=$(python3 -c '
import json, sys
lines = sys.stdin.read().splitlines()
start = max(index for index, line in enumerate(lines) if line == "{")
end = max(index for index, line in enumerate(lines) if line == "}")
if end < start:
    raise SystemExit("the sealer printed no complete JSON object")
record = json.loads("\n".join(lines[start : end + 1]))
print(record["profile_revision"].removeprefix("sha256:"))
' <"$SECOND_ROOT/seal.json")

primary_bundle="$PRIMARY_ROOT/profiles/x86_64-smp-p4k/$second_revision"
second_bundle="$SECOND_ROOT/profiles/x86_64-smp-p4k/$second_revision"
[[ -d "$primary_bundle" ]] || \
    die "the second build produced revision $second_revision, which the first build never published"
diff -r --no-dereference "$primary_bundle" "$second_bundle" >"$SECOND_ROOT/bundle.diff" || {
    sed -n '1,40p' "$SECOND_ROOT/bundle.diff" >&2
    die "the two sealed bundle trees differ"
}
printf 'profile_revision=%s\n' "$second_revision"

# The archive is packaged from each root's own bundle and its own host CLI.
primary_output="$SECOND_ROOT/package-primary"
second_output="$SECOND_ROOT/package-second"
mkdir -m 0700 -- "$primary_output" "$second_output"
# The host CLI is a release artifact rather than a bundle member, and the
# archive's identity depends on its exact bytes, so each root packages with the
# CLI it built itself.
primary_cli="$PRIMARY_ROOT/release/x86_64-smp-p4k/host/pocket"
second_cli="$SECOND_ROOT/release/x86_64-smp-p4k/host/pocket"
cmp -- "$primary_cli" "$second_cli" || die "the two host CLIs differ"
primary_archive=$("$ROOT/scripts/package-release.py" --repo-root "$ROOT" \
    --profile "$primary_bundle" --pocket "$primary_cli" \
    --output-dir "$primary_output" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["archive"])')
second_archive=$("$ROOT/scripts/package-release.py" --repo-root "$ROOT" \
    --profile "$second_bundle" --pocket "$second_cli" \
    --output-dir "$second_output" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["archive"])')
cmp -- "$primary_archive" "$second_archive" || die "the two release archives differ"
printf 'release_archive_sha256=%s\n' "$(sha256sum "$second_archive" | awk '{print $1}')"
printf 'POCKET_RELEASE_REPRODUCED_OK\n'
