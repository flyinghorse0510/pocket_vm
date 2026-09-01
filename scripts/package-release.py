#!/usr/bin/env python3
"""Package one already sealed x86_64 pocket profile and matching host CLI."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path

from pocket_release import (
    CHECKSUMS_NAME,
    FORMAT_VERSION,
    MANIFEST_NAME,
    SBOM_NAME,
    BytesPayload,
    DiskPayload,
    ReleaseError,
    canonical_json,
    checksums_bytes,
    generate_spdx,
    hash_regular_stable,
    inspect_pocket_binary,
    inspect_profile,
    payload_manifest_entry,
    publish_file_noreplace,
    require_absolute_normal_path,
    source_epoch_and_version,
    write_ustar,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--profile",
        required=True,
        type=Path,
        help="exact sealed profile revision directory",
    )
    parser.add_argument(
        "--pocket",
        required=True,
        type=Path,
        help="x86_64 pocket host CLI",
    )
    parser.add_argument(
        "--output-dir",
        required=True,
        type=Path,
        help="existing output directory",
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
    )
    return parser.parse_args()


def disk_payload(
    archive_path: str, source: Path, mode: int
) -> DiskPayload:
    digest, state = hash_regular_stable(source, archive_path)
    return DiskPayload(
        archive_path, source, mode, state.size, digest, state
    )


def main() -> int:
    arguments = parse_args()
    repo_root = require_absolute_normal_path(
        arguments.repo_root, "repository root"
    )
    profile_root = require_absolute_normal_path(
        arguments.profile, "profile bundle"
    )
    pocket_path = require_absolute_normal_path(
        arguments.pocket, "pocket CLI"
    )
    output_directory = require_absolute_normal_path(
        arguments.output_dir, "output directory"
    )
    if not output_directory.is_dir() or output_directory.is_symlink():
        raise ReleaseError(
            "output directory must be one ordinary directory"
        )
    profile = inspect_profile(profile_root)
    pocket_digest, pocket_state = inspect_pocket_binary(pocket_path)

    cargo_path = repo_root / "Cargo.lock"
    source_lock_path = repo_root / "config/sources.lock.toml"
    license_apache_path = repo_root / "LICENSE-APACHE"
    license_mit_path = repo_root / "LICENSE-MIT"
    support_matrix_path = repo_root / "docs/release-support-matrix.md"
    packaging_doc_path = repo_root / "docs/release-packaging.md"
    cargo_bytes, source_lock_bytes, epoch, version = (
        source_epoch_and_version(cargo_path, source_lock_path)
    )
    sbom = generate_spdx(cargo_bytes, source_lock_bytes)
    profile_relative = (
        f"profiles/{profile.profile_id}/{profile.revision_hex}"
    )

    payloads: list[DiskPayload | BytesPayload] = [
        DiskPayload(
            "bin/pocket",
            pocket_path,
            0o555,
            pocket_state.size,
            pocket_digest,
            pocket_state,
        ),
        disk_payload(
            "share/licenses/pocket-vm/LICENSE-APACHE",
            license_apache_path,
            0o444,
        ),
        disk_payload(
            "share/licenses/pocket-vm/LICENSE-MIT",
            license_mit_path,
            0o444,
        ),
        disk_payload(
            "share/pocket-vm/Cargo.lock", cargo_path, 0o444
        ),
        disk_payload(
            "share/pocket-vm/config/sources.lock.toml",
            source_lock_path,
            0o444,
        ),
        disk_payload(
            "share/doc/pocket-vm/release-packaging.md",
            packaging_doc_path,
            0o444,
        ),
        disk_payload(
            "share/doc/pocket-vm/release-support-matrix.md",
            support_matrix_path,
            0o444,
        ),
        BytesPayload(f"share/pocket-vm/{SBOM_NAME}", sbom),
    ]
    for (
        relative,
        source,
        mode,
        size,
        digest,
        state,
    ) in profile.files:
        payloads.append(
            DiskPayload(
                f"{profile_relative}/{relative}",
                source,
                mode,
                size,
                digest,
                state,
            )
        )
    payloads.sort(key=lambda payload: payload.archive_path)
    file_inventory = [
        payload_manifest_entry(payload) for payload in payloads
    ]
    release_identity = {
        "format": "pocket-vm-release-identity-v1",
        "files": file_inventory,
        "package_version": version,
        "product": "pocket-vm",
        "profile_id": profile.profile_id,
        "profile_maturity": profile.maturity,
        "profile_revision": profile.revision,
        "sbom_scope": "source-input-locks-only-v1",
        "source_date_epoch": epoch,
        "target": "linux-x86_64",
    }
    release_revision_hex = hashlib.sha256(
        canonical_json(release_identity)
    ).hexdigest()
    release_revision = f"sha256:{release_revision_hex}"
    release_id = (
        f"{version}-{profile.profile_id}-{release_revision_hex}"
    )
    top = f"pocket-vm-{release_id}"
    manifest = {
        "format": FORMAT_VERSION,
        "product": "pocket-vm",
        "package_version": version,
        "release_id": release_id,
        "top_directory": top,
        "target": "linux-x86_64",
        "profile_id": profile.profile_id,
        "profile_revision": profile.revision,
        "profile_maturity": profile.maturity,
        "profile_relative_path": profile_relative,
        "release_revision": release_revision,
        "source_date_epoch": epoch,
        "archive_format": "ustar-uncompressed-v1",
        "sbom_scope": "source-input-locks-only-v1",
        "files": file_inventory,
    }
    manifest_bytes = canonical_json(manifest)
    payloads.append(
        BytesPayload(
            f"share/pocket-vm/{MANIFEST_NAME}", manifest_bytes
        )
    )
    checksum_inputs = [
        payload
        for payload in payloads
        if payload.archive_path
        != f"share/pocket-vm/{MANIFEST_NAME}"
    ]
    checksums = checksums_bytes(checksum_inputs, manifest_bytes)
    payloads.append(
        BytesPayload(
            f"share/pocket-vm/{CHECKSUMS_NAME}", checksums
        )
    )

    archive_name = f"{top}-linux-x86_64.tar"
    destination = output_directory / archive_name
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".pocket-release.", dir=output_directory
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w+b") as output:
            write_ustar(output, top, payloads, epoch)
            output.flush()
            os.fsync(output.fileno())
            os.fchmod(output.fileno(), 0o444)
            output.seek(0)
            archive_digest = hashlib.file_digest(
                output, "sha256"
            ).hexdigest()
            archive_size = output.seek(0, os.SEEK_END)
        if inspect_profile(profile_root) != profile:
            raise ReleaseError(
                "sealed profile changed during release packaging"
            )
        final_pocket_digest, final_pocket_state = inspect_pocket_binary(
            pocket_path
        )
        if (
            final_pocket_digest != pocket_digest
            or final_pocket_state != pocket_state
        ):
            raise ReleaseError(
                "pocket CLI changed during release packaging"
            )
        publish_file_noreplace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)
    print(
        json.dumps(
            {
                "archive": str(destination),
                "archive_sha256": archive_digest,
                "archive_size": archive_size,
                "profile_maturity": profile.maturity,
                "profile_revision": profile.revision,
                "release_id": release_id,
                "release_revision": release_revision,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ReleaseError as error:
        print(f"package-release: {error}", file=sys.stderr)
        raise SystemExit(1)
