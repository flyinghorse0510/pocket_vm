#!/usr/bin/env python3
"""Shared, standard-library-only release packaging primitives for pocket_vm."""

from __future__ import annotations

import ctypes
import datetime as dt
import errno
import hashlib
import io
import json
import os
import re
import stat
import tarfile
import tomllib
import urllib.parse
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Iterable, cast


FORMAT_VERSION = "pocket-vm-release-manifest-v1"
SBOM_NAME = "pocket-vm-source-inputs.spdx.json"
MANIFEST_NAME = "release-manifest.json"
CHECKSUMS_NAME = "SHA256SUMS"
MAX_INPUT_FILE_BYTES = 1 << 30
MAX_ARCHIVE_BYTES = 4 << 30
MAX_ARCHIVE_FILES = 4096
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")
PACKAGE_VERSION = re.compile(r"[0-9A-Za-z][0-9A-Za-z.+-]{0,63}\Z")
SAFE_MEMBER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/+@-]{0,511}\Z")


class ReleaseError(RuntimeError):
    """A release input or installed tree failed a closed-world check."""


@dataclass(frozen=True)
class FileState:
    device: int
    inode: int
    mode: int
    uid: int
    gid: int
    links: int
    size: int
    mtime_ns: int
    ctime_ns: int


@dataclass(frozen=True)
class DiskPayload:
    archive_path: str
    source: Path
    mode: int
    size: int
    sha256: str
    state: FileState


@dataclass(frozen=True)
class BytesPayload:
    archive_path: str
    data: bytes
    mode: int = 0o444

    @property
    def size(self) -> int:
        return len(self.data)

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.data).hexdigest()


Payload = DiskPayload | BytesPayload


@dataclass(frozen=True)
class ProfileInfo:
    profile_id: str
    revision: str
    revision_hex: str
    maturity: str
    host_architecture: str
    files: tuple[tuple[str, Path, int, int, str, FileState], ...]


@dataclass(frozen=True)
class ArchiveInfo:
    archive: Path
    top_directory: str
    release_id: str
    profile_id: str
    profile_revision: str
    profile_relative_path: str
    source_date_epoch: int
    archive_sha256: str
    archive_state: FileState
    manifest: dict[str, object]
    members: tuple[tarfile.TarInfo, ...]


def fail(message: str) -> None:
    raise ReleaseError(message)


def refuse_walk_error(error: OSError) -> None:
    """Turn an unreadable directory into a failure, not a silent omission.

    os.walk's default is to skip a directory it cannot scan. A tree walked that
    way is only partially enumerated, so an extra directory nobody can list
    would pass an inventory comparison that is meant to reject it.
    """
    raise ReleaseError(f"tree cannot be fully enumerated: {error}")


def canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
    ).encode()


def require_hex64(value: object, field: str) -> str:
    if not isinstance(value, str) or HEX64.fullmatch(value) is None:
        fail(f"{field} must be exactly 64 lowercase hexadecimal characters")
    return value


def require_identifier(value: object, field: str) -> str:
    if not isinstance(value, str) or IDENTIFIER.fullmatch(value) is None:
        fail(f"{field} contains unsupported characters or length")
    return value


def require_package_version(value: object, field: str) -> str:
    if not isinstance(value, str) or PACKAGE_VERSION.fullmatch(value) is None:
        fail(f"{field} contains unsupported characters or length")
    return value


def _path_text(path: Path, field: str) -> str:
    try:
        text = os.fspath(path)
        text.encode("utf-8", "strict")
    except (TypeError, UnicodeError) as error:
        fail(f"{field} is not a UTF-8 filesystem path: {error}")
    if "\n" in text or "\r" in text or "\x00" in text:
        fail(f"{field} contains a forbidden control character")
    return text


def require_absolute_normal_path(
    path: Path, field: str, *, must_exist: bool = True
) -> Path:
    text = _path_text(path, field)
    if not path.is_absolute() or os.path.normpath(text) != text:
        fail(f"{field} must be an absolute, lexically normalized path")
    current = Path(path.anchor)
    parts = path.parts[1:]
    for index, part in enumerate(parts):
        current /= part
        try:
            current_stat = os.lstat(current)
        except FileNotFoundError:
            if must_exist or index != len(parts) - 1:
                fail(f"{field} does not exist: {path}")
            break
        if stat.S_ISLNK(current_stat.st_mode):
            fail(f"{field} traverses a symbolic link: {current}")
    if must_exist and not path.exists():
        fail(f"{field} does not exist: {path}")
    return path


def _state(value: os.stat_result) -> FileState:
    return FileState(
        device=value.st_dev,
        inode=value.st_ino,
        mode=stat.S_IMODE(value.st_mode),
        uid=value.st_uid,
        gid=value.st_gid,
        links=value.st_nlink,
        size=value.st_size,
        mtime_ns=value.st_mtime_ns,
        ctime_ns=value.st_ctime_ns,
    )


def read_regular_stable(
    path: Path,
    field: str,
    *,
    maximum: int = MAX_INPUT_FILE_BYTES,
    reject_hardlinks: bool = True,
) -> tuple[bytes, FileState]:
    require_absolute_normal_path(path, field)
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        fail(f"cannot open {field} without following links: {error}")
    try:
        before_raw = os.fstat(descriptor)
        before = _state(before_raw)
        if not stat.S_ISREG(before_raw.st_mode):
            fail(f"{field} is not a regular file")
        if reject_hardlinks and before.links != 1:
            fail(f"{field} must not be hard-linked")
        if before.size > maximum:
            fail(f"{field} exceeds the {maximum}-byte limit")
        chunks: list[bytes] = []
        remaining = before.size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                fail(f"{field} became shorter while it was read")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            fail(f"{field} grew while it was read")
        after = _state(os.fstat(descriptor))
        if before != after:
            fail(f"{field} changed while it was read")
        return b"".join(chunks), before
    finally:
        os.close(descriptor)


def hash_regular_stable(path: Path, field: str) -> tuple[str, FileState]:
    require_absolute_normal_path(path, field)
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        fail(f"cannot open {field} without following links: {error}")
    try:
        before_raw = os.fstat(descriptor)
        before = _state(before_raw)
        if not stat.S_ISREG(before_raw.st_mode):
            fail(f"{field} is not a regular file")
        if before.links != 1:
            fail(f"{field} must not be hard-linked")
        if before.size > MAX_INPUT_FILE_BYTES:
            fail(f"{field} exceeds the {MAX_INPUT_FILE_BYTES}-byte limit")
        digest = hashlib.sha256()
        remaining = before.size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                fail(f"{field} became shorter while it was hashed")
            digest.update(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            fail(f"{field} grew while it was hashed")
        if _state(os.fstat(descriptor)) != before:
            fail(f"{field} changed while it was hashed")
        return digest.hexdigest(), before
    finally:
        os.close(descriptor)


def parse_posix_relative(value: object, field: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        fail(f"{field} must be a non-empty POSIX relative path")
    if SAFE_MEMBER.fullmatch(value) is None:
        fail(f"{field} contains unsupported characters or length")
    candidate = PurePosixPath(value)
    if candidate.is_absolute() or any(part in ("", ".", "..") for part in candidate.parts):
        fail(f"{field} is not a normalized relative path")
    if candidate.as_posix() != value:
        fail(f"{field} is not canonical")
    return value


def ancestor_directories(paths: Iterable[str]) -> set[str]:
    directories: set[str] = set()
    for value in paths:
        parent = PurePosixPath(value).parent
        while parent != PurePosixPath("."):
            directories.add(parent.as_posix())
            parent = parent.parent
    return directories


def inspect_profile(profile_root: Path) -> ProfileInfo:
    require_absolute_normal_path(profile_root, "profile bundle")
    root_stat = os.lstat(profile_root)
    if (
        not stat.S_ISDIR(root_stat.st_mode)
        or stat.S_IMODE(root_stat.st_mode) != 0o555
    ):
        fail("sealed profile root must be a mode-0555 directory")
    profile_bytes, profile_state = read_regular_stable(
        profile_root / "profile.json",
        "profile.json",
        maximum=8 << 20,
    )
    if profile_state.mode != 0o444:
        fail("sealed profile.json must have mode 0444")
    try:
        manifest = json.loads(profile_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"profile.json is not valid UTF-8 JSON: {error}")
    if not isinstance(manifest, dict):
        fail("profile.json must contain a JSON object")
    if manifest.get("schema_version") != 3:
        fail("profile.json must use the current schema_version 3")
    profile_id = require_identifier(manifest.get("profile_id"), "profile_id")
    revision = manifest.get("profile_revision")
    if not isinstance(revision, str) or not revision.startswith("sha256:"):
        fail("profile_revision must use the sha256:<digest> form")
    revision_hex = require_hex64(
        revision.removeprefix("sha256:"), "profile_revision"
    )
    if profile_root.name != revision_hex or profile_root.parent.name != profile_id:
        fail("profile path is not <profile-id>/<full-revision-digest>")
    maturity = manifest.get("maturity")
    if maturity not in ("experimental", "release"):
        fail("profile maturity must be experimental or release")
    host_architecture = manifest.get("host_architecture")
    if host_architecture != "x86_64" or manifest.get("host_elf_machine") != 62:
        fail("this packager accepts only the sealed x86_64/ELF-62 profile")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict) or not artifacts:
        fail("profile artifacts must be a non-empty object")

    files: list[tuple[str, Path, int, int, str, FileState]] = [
        (
            "profile.json",
            profile_root / "profile.json",
            0o444,
            len(profile_bytes),
            hashlib.sha256(profile_bytes).hexdigest(),
            profile_state,
        )
    ]
    seen_paths = {"profile.json"}
    for role in sorted(artifacts):
        descriptor = artifacts[role]
        if not isinstance(role, str) or not isinstance(descriptor, dict):
            fail(
                "every profile artifact must have a string role and object descriptor"
            )
        if set(descriptor) != {"path", "sha256", "size"}:
            fail(f"profile artifact descriptor has unexpected fields: {role}")
        relative = parse_posix_relative(
            descriptor.get("path"), f"artifacts.{role}.path"
        )
        if relative in seen_paths:
            fail(f"duplicate profile artifact path: {relative}")
        seen_paths.add(relative)
        expected_digest = descriptor.get("sha256")
        if not isinstance(expected_digest, str) or not expected_digest.startswith(
            "sha256:"
        ):
            fail(f"artifacts.{role}.sha256 must use sha256:<digest>")
        expected_digest = require_hex64(
            expected_digest.removeprefix("sha256:"),
            f"artifacts.{role}.sha256",
        )
        expected_size = descriptor.get("size")
        if (
            not isinstance(expected_size, int)
            or isinstance(expected_size, bool)
            or expected_size < 0
        ):
            fail(f"artifacts.{role}.size must be a non-negative integer")
        source = profile_root.joinpath(*PurePosixPath(relative).parts)
        actual_digest, source_state = hash_regular_stable(
            source, f"profile artifact {relative}"
        )
        if source_state.mode not in (0o444, 0o555):
            fail(f"sealed profile artifact has non-canonical mode: {relative}")
        if source_state.size != expected_size or actual_digest != expected_digest:
            fail(
                f"sealed profile artifact does not match profile.json: {relative}"
            )
        files.append(
            (
                relative,
                source,
                source_state.mode,
                source_state.size,
                actual_digest,
                source_state,
            )
        )

    observed_files: set[str] = set()
    observed_directories: set[str] = set()
    for current, directory_names, file_names in os.walk(
        profile_root, topdown=True, followlinks=False, onerror=refuse_walk_error
    ):
        current_path = Path(current)
        relative_current = current_path.relative_to(profile_root)
        if relative_current != Path("."):
            relative_text = relative_current.as_posix()
            parse_posix_relative(relative_text, "profile directory")
            observed_directories.add(relative_text)
            current_stat = os.lstat(current_path)
            if (
                not stat.S_ISDIR(current_stat.st_mode)
                or stat.S_IMODE(current_stat.st_mode) != 0o555
            ):
                fail(
                    f"sealed profile directory is not mode 0555: {relative_text}"
                )
        for name in directory_names:
            child = current_path / name
            child_stat = os.lstat(child)
            if stat.S_ISLNK(child_stat.st_mode) or not stat.S_ISDIR(
                child_stat.st_mode
            ):
                fail(
                    f"sealed profile contains a linked or special directory: {child}"
                )
        for name in file_names:
            child = current_path / name
            relative_text = child.relative_to(profile_root).as_posix()
            parse_posix_relative(relative_text, "profile file")
            child_stat = os.lstat(child)
            if not stat.S_ISREG(child_stat.st_mode):
                fail(
                    f"sealed profile contains a linked or special file: {relative_text}"
                )
            observed_files.add(relative_text)

    expected_directories = ancestor_directories(seen_paths)
    if observed_files != seen_paths:
        extra = sorted(observed_files - seen_paths)
        missing = sorted(seen_paths - observed_files)
        fail(
            f"sealed profile file inventory mismatch (extra={extra}, missing={missing})"
        )
    if observed_directories != expected_directories:
        extra = sorted(observed_directories - expected_directories)
        missing = sorted(expected_directories - observed_directories)
        fail(
            "sealed profile directory inventory mismatch "
            f"(extra={extra}, missing={missing})"
        )
    return ProfileInfo(
        profile_id=profile_id,
        revision=revision,
        revision_hex=revision_hex,
        maturity=maturity,
        host_architecture=host_architecture,
        files=tuple(sorted(files)),
    )


def inspect_pocket_binary(path: Path) -> tuple[str, FileState]:
    data, state = read_regular_stable(
        path, "pocket CLI", maximum=256 << 20
    )
    if state.mode & 0o022:
        fail("pocket CLI must not be group- or other-writable")
    if state.mode & 0o111 != 0o111:
        fail("pocket CLI must be executable by owner, group, and other")
    if (
        len(data) < 20
        or data[:6] != b"\x7fELF\x02\x01"
        or int.from_bytes(data[18:20], "little") != 62
    ):
        fail("pocket CLI must be a little-endian 64-bit x86_64 ELF executable")
    return hashlib.sha256(data).hexdigest(), state


def parse_release_inputs(
    cargo_lock: bytes, source_lock: bytes
) -> tuple[dict[str, object], dict[str, object]]:
    try:
        cargo = tomllib.loads(cargo_lock.decode("utf-8"))
        sources = tomllib.loads(source_lock.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        fail(f"release lock input is not valid UTF-8 TOML: {error}")
    if cargo.get("version") != 4 or not isinstance(cargo.get("package"), list):
        fail(
            "Cargo.lock must use lockfile version 4 and contain package entries"
        )
    required_sections = (
        "linux",
        "e2fsprogs",
        "skopeo",
        "go_toolchain",
        "registry_ca",
        "profile",
    )
    for section in required_sections:
        if not isinstance(sources.get(section), dict):
            fail(f"sources.lock.toml is missing [{section}]")
    return cargo, sources


def release_version(cargo: dict[str, object]) -> str:
    packages = cast(list[object], cargo["package"])
    versions = {
        package.get("version")
        for package in packages
        if isinstance(package, dict)
        and package.get("name") == "pocket"
        and package.get("source") is None
    }
    if len(versions) != 1:
        fail("Cargo.lock must contain exactly one workspace pocket package")
    return require_package_version(
        next(iter(versions)), "pocket package version"
    )


def source_date_epoch(sources: dict[str, object]) -> int:
    linux = cast(dict[str, object], sources["linux"])
    value = linux.get("source_date_epoch")
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 946684800 <= value <= 4102444799
    ):
        fail(
            "linux.source_date_epoch must be an integer in years 2000 through 2099"
        )
    return value


def _spdx_id(prefix: str, *values: str) -> str:
    digest = hashlib.sha256("\0".join(values).encode()).hexdigest()[:16]
    slug = re.sub(r"[^A-Za-z0-9.-]", "-", values[0])[:48].strip("-.") or "item"
    return f"SPDXRef-{prefix}-{slug}-{digest}"


def _purl(name: str, version: str) -> str:
    return (
        f"pkg:cargo/{urllib.parse.quote(name, safe='')}"
        f"@{urllib.parse.quote(version, safe='')}"
    )


def generate_spdx(cargo_lock: bytes, source_lock: bytes) -> bytes:
    cargo, sources = parse_release_inputs(cargo_lock, source_lock)
    epoch = source_date_epoch(sources)
    timestamp = (
        dt.datetime.fromtimestamp(epoch, dt.UTC)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
    input_digest = hashlib.sha256(cargo_lock + b"\0" + source_lock).hexdigest()
    root_id = "SPDXRef-PocketVmSourceInputs"
    packages: list[dict[str, object]] = [
        {
            "SPDXID": root_id,
            "name": "pocket-vm-source-inputs",
            "versionInfo": "1",
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
            "comment": (
                "Source-input inventory generated only from Cargo.lock and "
                "config/sources.lock.toml. It is not a binary scan, license "
                "analysis, vulnerability report, or proof that the build used "
                "no additional host inputs. Cargo.lock may include target-specific "
                "and development entries not linked into the packaged pocket executable."
            ),
        }
    ]
    relationships: list[dict[str, str]] = []
    cargo_packages = cast(list[object], cargo["package"])
    if any(not isinstance(package, dict) for package in cargo_packages):
        fail("Cargo.lock contains a non-object package entry")
    sorted_cargo = sorted(
        cargo_packages,
        key=lambda item: (
            str(item.get("name", "")),
            str(item.get("version", "")),
            str(item.get("source", "workspace")),
        ),
    )
    seen_coordinates: set[tuple[str, str, str]] = set()
    for package in sorted_cargo:
        if not isinstance(package, dict):
            fail("Cargo.lock contains a non-object package entry")
        name = package.get("name")
        version = package.get("version")
        source = package.get("source", "workspace")
        if (
            not isinstance(name, str)
            or not isinstance(version, str)
            or not isinstance(source, str)
        ):
            fail("Cargo.lock package coordinates must be strings")
        coordinate = (name, version, source)
        if coordinate in seen_coordinates:
            fail(f"Cargo.lock has a duplicate package coordinate: {coordinate}")
        seen_coordinates.add(coordinate)
        package_id = _spdx_id("Cargo", name, version, source)
        entry: dict[str, object] = {
            "SPDXID": package_id,
            "name": name,
            "versionInfo": version,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
            "supplier": "NOASSERTION",
            "comment": f"Cargo.lock source coordinate: {source}",
        }
        if source.startswith("registry+"):
            entry["externalRefs"] = [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": _purl(name, version),
                }
            ]
        checksum = package.get("checksum")
        if checksum is not None:
            checksum = require_hex64(
                checksum, f"Cargo.lock checksum for {name} {version}"
            )
            entry["checksums"] = [
                {"algorithm": "SHA256", "checksumValue": checksum}
            ]
        packages.append(entry)
        relationships.append(
            {
                "spdxElementId": root_id,
                "relationshipType": "OTHER",
                "relatedSpdxElement": package_id,
                "comment": "LOCKFILE_ENTRY",
            }
        )

    external_specs = (
        ("Linux", "linux", "release", "tarball_url", "tarball_sha256"),
        (
            "e2fsprogs",
            "e2fsprogs",
            "release",
            "tarball_url",
            "tarball_sha256",
        ),
        ("Skopeo", "skopeo", "release", "repository_url", None),
        (
            "Go",
            "go_toolchain",
            "release",
            "archive_url",
            "archive_sha256",
        ),
        (
            "Mozilla-CA-Bundle",
            "registry_ca",
            "revision",
            "bundle_url",
            "bundle_sha256",
        ),
    )
    for (
        display_name,
        section_name,
        version_key,
        location_key,
        checksum_key,
    ) in external_specs:
        section = cast(dict[str, object], sources[section_name])
        version = section.get(version_key)
        location = section.get(location_key)
        if (
            not isinstance(version, str)
            or not version
            or not isinstance(location, str)
            or not location
        ):
            fail(
                f"[{section_name}] lacks a usable version or source location"
            )
        package_id = _spdx_id("External", display_name, version, location)
        entry = {
            "SPDXID": package_id,
            "name": display_name,
            "versionInfo": version,
            "downloadLocation": location,
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
            "supplier": "NOASSERTION",
            "comment": (
                f"Pinned external source coordinate from [{section_name}] "
                "in sources.lock.toml."
            ),
        }
        if checksum_key is not None:
            checksum = require_hex64(
                section.get(checksum_key), f"{section_name}.{checksum_key}"
            )
            entry["checksums"] = [
                {"algorithm": "SHA256", "checksumValue": checksum}
            ]
        elif section_name == "skopeo":
            commit = section.get("commit")
            if (
                not isinstance(commit, str)
                or re.fullmatch(r"[0-9a-f]{40}", commit) is None
            ):
                fail("skopeo.commit must be a full lowercase Git object ID")
            entry["externalRefs"] = [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": (
                        f"pkg:golang/go.podman.io/skopeo@{version}"
                        f"?commit={commit}"
                        f"&vcs_url={urllib.parse.quote(location, safe='')}"
                    ),
                }
            ]
            entry["comment"] = (
                f"Pinned Git source from [skopeo]; commit {commit}. "
                "Git object IDs are not represented as SPDX package-file checksums."
            )
        packages.append(entry)
        relationships.append(
            {
                "spdxElementId": root_id,
                "relationshipType": "OTHER",
                "relatedSpdxElement": package_id,
                "comment": "PINNED_SOURCE_INPUT",
            }
        )

    packages.sort(key=lambda package: str(package["SPDXID"]))
    relationships.sort(
        key=lambda relation: (
            relation["spdxElementId"],
            relation["relationshipType"],
            relation["relatedSpdxElement"],
        )
    )
    document = {
        "SPDXID": "SPDXRef-DOCUMENT",
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "name": "pocket-vm-source-inputs",
        "documentNamespace": (
            f"https://pocket-vm.invalid/spdx/source-inputs/{input_digest}"
        ),
        "creationInfo": {
            "created": timestamp,
            "creators": ["Tool: pocket-vm-release-sbom/1"],
            "comment": (
                "The created field is the reproducible "
                "linux.source_date_epoch value from sources.lock.toml, "
                "not the wall-clock time at which this document was emitted."
            ),
        },
        "documentDescribes": [root_id],
        "packages": packages,
        "relationships": relationships,
    }
    return canonical_json(document)


def source_epoch_and_version(
    cargo_lock: Path, source_lock: Path
) -> tuple[bytes, bytes, int, str]:
    cargo_bytes, _ = read_regular_stable(
        cargo_lock, "Cargo.lock", maximum=16 << 20
    )
    source_bytes, _ = read_regular_stable(
        source_lock, "sources.lock.toml", maximum=16 << 20
    )
    cargo, sources = parse_release_inputs(cargo_bytes, source_bytes)
    return (
        cargo_bytes,
        source_bytes,
        source_date_epoch(sources),
        release_version(cargo),
    )


def _tar_info(
    name: str, mode: int, mtime: int, *, directory: bool, size: int = 0
) -> tarfile.TarInfo:
    info = tarfile.TarInfo(
        name + ("/" if directory and not name.endswith("/") else "")
    )
    info.type = tarfile.DIRTYPE if directory else tarfile.REGTYPE
    info.mode = mode
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = mtime
    info.size = 0 if directory else size
    return info


class _HashingReader:
    def __init__(self, source: BinaryIO) -> None:
        self.source = source
        self.digest = hashlib.sha256()

    def read(self, size: int = -1) -> bytes:
        data = self.source.read(size)
        self.digest.update(data)
        return data


def _add_disk_payload(
    archive: tarfile.TarFile, top: str, payload: DiskPayload, epoch: int
) -> None:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    descriptor = os.open(payload.source, flags)
    try:
        before = _state(os.fstat(descriptor))
        if before != payload.state:
            fail(f"release input changed before archival: {payload.source}")
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            reader = _HashingReader(source)
            archive.addfile(
                _tar_info(
                    f"{top}/{payload.archive_path}",
                    payload.mode,
                    epoch,
                    directory=False,
                    size=payload.size,
                ),
                reader,
            )
            if reader.digest.hexdigest() != payload.sha256:
                fail(f"release input changed while archived: {payload.source}")
        after = _state(os.fstat(descriptor))
        if before != after:
            fail(
                f"release input metadata changed while archived: {payload.source}"
            )
    finally:
        os.close(descriptor)


def write_ustar(
    output: BinaryIO, top: str, payloads: Iterable[Payload], epoch: int
) -> None:
    payload_list = sorted(payloads, key=lambda item: item.archive_path)
    files = {payload.archive_path for payload in payload_list}
    if len(files) != len(payload_list):
        fail("release payload contains duplicate archive paths")
    directories = ancestor_directories(files)
    with tarfile.open(
        fileobj=output, mode="w", format=tarfile.USTAR_FORMAT
    ) as archive:
        archive.addfile(_tar_info(top, 0o555, epoch, directory=True))
        for directory in sorted(directories):
            archive.addfile(
                _tar_info(
                    f"{top}/{directory}", 0o555, epoch, directory=True
                )
            )
        for payload in payload_list:
            if isinstance(payload, DiskPayload):
                _add_disk_payload(archive, top, payload, epoch)
            else:
                archive.addfile(
                    _tar_info(
                        f"{top}/{payload.archive_path}",
                        payload.mode,
                        epoch,
                        directory=False,
                        size=payload.size,
                    ),
                    io.BytesIO(payload.data),
                )


def payload_manifest_entry(payload: Payload) -> dict[str, object]:
    return {
        "path": payload.archive_path,
        "mode": f"{payload.mode:04o}",
        "size": payload.size,
        "sha256": payload.sha256,
    }


def checksums_bytes(
    payloads: Iterable[Payload], manifest_bytes: bytes
) -> bytes:
    entries = [
        (payload.archive_path, payload.sha256) for payload in payloads
    ]
    entries.append(
        (
            f"share/pocket-vm/{MANIFEST_NAME}",
            hashlib.sha256(manifest_bytes).hexdigest(),
        )
    )
    entries.sort()
    return "".join(
        f"{digest}  {path}\n" for path, digest in entries
    ).encode("ascii")


def publish_file_noreplace(
    temporary: Path, destination: Path, exist_ok: bool = False
) -> bool:
    """Publish `temporary` as `destination`, never replacing what is there.

    Returns whether this call is the one that created it. With `exist_ok`, a
    destination that already exists is reported rather than failed: two
    installers racing to publish the same bytes is a race one of them wins, not
    an error, and the caller verifies the result either way.

    This renames rather than hard-links. A link would leave the published file
    with two names until the publisher unlinked its own temporary, and every
    reader of an installed file rejects a hard-linked one -- so a concurrent
    installer would reject a launcher that is in fact correct. A rename also
    cannot leak the temporary if the process dies mid-publication.
    """
    return rename_noreplace(
        temporary, destination, exist_ok=exist_ok, role="release output"
    )


def rename_noreplace(
    source: Path,
    destination: Path,
    exist_ok: bool = False,
    role: str = "installed release",
) -> bool:
    """Rename `source` onto `destination`, never replacing what is there.

    Returns whether this call is the one that created it; see
    `publish_file_noreplace` for what `exist_ok` is for.
    """
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        fail(
            "libc does not expose renameat2; refusing non-atomic "
            "installation publication"
        )
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    result = renameat2(
        -100,
        os.fsencode(source),
        -100,
        os.fsencode(destination),
        1,
    )
    if result != 0:
        error_number = ctypes.get_errno()
        if error_number == errno.EEXIST:
            if exist_ok:
                return False
            fail(f"refusing to overwrite existing {role}: {destination}")
        fail(
            "renameat2(RENAME_NOREPLACE) failed: "
            f"{os.strerror(error_number)}"
        )
    directory_fd = os.open(
        destination.parent,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    return True


def archive_regular_file(path: Path) -> FileState:
    require_absolute_normal_path(path, "release archive")
    archive_stat = os.lstat(path)
    if (
        not stat.S_ISREG(archive_stat.st_mode)
        or archive_stat.st_nlink != 1
    ):
        fail("release archive must be one non-hard-linked regular file")
    if archive_stat.st_size > MAX_ARCHIVE_BYTES:
        fail(
            f"release archive exceeds the {MAX_ARCHIVE_BYTES}-byte limit"
        )
    return _state(archive_stat)


def _digest_descriptor(descriptor: int) -> str:
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
    os.lseek(descriptor, 0, os.SEEK_SET)
    return digest.hexdigest()


def _open_archive_descriptor(path: Path) -> tuple[int, FileState]:
    archive_regular_file(path)
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
        )
    except OSError as error:
        fail(f"cannot open release archive without following links: {error}")
    descriptor_stat = os.fstat(descriptor)
    descriptor_state = _state(descriptor_stat)
    if (
        not stat.S_ISREG(descriptor_stat.st_mode)
        or descriptor_state.links != 1
        or descriptor_state.size > MAX_ARCHIVE_BYTES
    ):
        os.close(descriptor)
        fail("release archive descriptor is not one bounded ordinary file")
    return descriptor, descriptor_state


@contextmanager
def open_verified_archive(info: ArchiveInfo):
    descriptor, before = _open_archive_descriptor(info.archive)
    try:
        if before != info.archive_state:
            fail("release archive identity or metadata changed after validation")
        if _digest_descriptor(descriptor) != info.archive_sha256:
            fail("release archive bytes changed after validation")
        with os.fdopen(os.dup(descriptor), "rb") as stream:
            try:
                archive = tarfile.open(fileobj=stream, mode="r:")
            except (OSError, tarfile.TarError) as error:
                fail(f"cannot reopen validated release archive: {error}")
            with archive:
                yield archive
        after = _state(os.fstat(descriptor))
        if after != info.archive_state:
            fail("release archive metadata changed during use")
        if _digest_descriptor(descriptor) != info.archive_sha256:
            fail("release archive bytes changed during use")
    finally:
        os.close(descriptor)


@contextmanager
def _open_initial_archive(path: Path):
    descriptor, before = _open_archive_descriptor(path)
    initial_digest = _digest_descriptor(descriptor)
    try:
        with os.fdopen(os.dup(descriptor), "rb") as stream:
            try:
                archive = tarfile.open(fileobj=stream, mode="r:")
            except (OSError, tarfile.TarError) as error:
                fail(
                    "release archive is not an uncompressed tar archive: "
                    f"{error}"
                )
            with archive:
                yield archive, before, initial_digest
        if _state(os.fstat(descriptor)) != before:
            fail("release archive metadata changed during validation")
        if _digest_descriptor(descriptor) != initial_digest:
            fail("release archive bytes changed during validation")
    finally:
        os.close(descriptor)


def _member_relative(name: str, top: str) -> str:
    if name.endswith("/"):
        name = name[:-1]
    if name == top:
        return ""
    prefix = f"{top}/"
    if not name.startswith(prefix):
        fail(
            "release archive contains more than one top-level directory"
        )
    return parse_posix_relative(
        name.removeprefix(prefix), "archive member"
    )


def _read_member(
    archive: tarfile.TarFile, member: tarfile.TarInfo, maximum: int
) -> bytes:
    if member.size > maximum:
        fail(f"archive member exceeds its size limit: {member.name}")
    stream = archive.extractfile(member)
    if stream is None:
        fail(f"cannot read archive member: {member.name}")
    data = stream.read(maximum + 1)
    if len(data) != member.size or len(data) > maximum:
        fail(f"archive member size mismatch: {member.name}")
    return data


def _hash_member(
    archive: tarfile.TarFile,
    member: tarfile.TarInfo,
    maximum: int,
) -> str:
    if member.size > maximum:
        fail(f"archive member exceeds its size limit: {member.name}")
    stream = archive.extractfile(member)
    if stream is None:
        fail(f"cannot read archive member: {member.name}")
    digest = hashlib.sha256()
    remaining = member.size
    while remaining:
        chunk = stream.read(min(1024 * 1024, remaining))
        if not chunk:
            fail(f"archive member became shorter while hashed: {member.name}")
        digest.update(chunk)
        remaining -= len(chunk)
    if stream.read(1):
        fail(f"archive member grew while hashed: {member.name}")
    return digest.hexdigest()


def inspect_archive(path: Path) -> ArchiveInfo:
    with _open_initial_archive(path) as (
        archive,
        archive_state,
        archive_digest,
    ):
        if archive.pax_headers:
            fail("release archive must not contain global PAX headers")
        members = archive.getmembers()
        if not 1 <= len(members) <= MAX_ARCHIVE_FILES:
            fail(
                "release archive member count is outside the accepted bound"
            )
        names: set[str] = set()
        for member in members:
            canonical_name = (
                member.name[:-1]
                if member.name.endswith("/")
                else member.name
            )
            if canonical_name in names:
                fail(
                    "release archive contains a duplicate member: "
                    f"{canonical_name}"
                )
            names.add(canonical_name)
            if member.pax_headers:
                fail(
                    "release archive member uses PAX metadata: "
                    f"{canonical_name}"
                )
            if not (member.isdir() or member.isreg()):
                fail(
                    "release archive contains a link or special member: "
                    f"{canonical_name}"
                )
            if (
                member.uid != 0
                or member.gid != 0
                or member.uname
                or member.gname
            ):
                fail(
                    "release archive member has non-canonical ownership: "
                    f"{canonical_name}"
                )
        first = members[0].name.rstrip("/")
        if (
            "/" in first
            or not first.startswith("pocket-vm-")
            or SAFE_MEMBER.fullmatch(first) is None
        ):
            fail(
                "release archive does not begin with its canonical "
                "top-level directory"
            )
        top = first
        manifest_member_name = (
            f"{top}/share/pocket-vm/{MANIFEST_NAME}"
        )
        checksums_member_name = (
            f"{top}/share/pocket-vm/{CHECKSUMS_NAME}"
        )
        member_map = {
            member.name.rstrip("/"): member for member in members
        }
        manifest_member = member_map.get(manifest_member_name)
        checksums_member = member_map.get(checksums_member_name)
        if (
            manifest_member is None
            or not manifest_member.isreg()
            or checksums_member is None
            or not checksums_member.isreg()
        ):
            fail(
                "release archive lacks its regular manifest or checksum file"
            )
        manifest_bytes = _read_member(
            archive, manifest_member, 8 << 20
        )
        try:
            manifest = json.loads(manifest_bytes)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            fail(
                f"release manifest is not valid UTF-8 JSON: {error}"
            )
        if (
            not isinstance(manifest, dict)
            or canonical_json(manifest) != manifest_bytes
        ):
            fail("release manifest is not canonical JSON")
        expected_manifest_fields = {
            "archive_format",
            "files",
            "format",
            "package_version",
            "product",
            "profile_id",
            "profile_maturity",
            "profile_relative_path",
            "profile_revision",
            "release_id",
            "release_revision",
            "sbom_scope",
            "source_date_epoch",
            "target",
            "top_directory",
        }
        if set(manifest) != expected_manifest_fields:
            fail("release manifest has missing or unexpected fields")
        if manifest.get("format") != FORMAT_VERSION:
            fail("release manifest has an unsupported format")
        if (
            manifest.get("product") != "pocket-vm"
            or manifest.get("target") != "linux-x86_64"
            or manifest.get("archive_format")
            != "ustar-uncompressed-v1"
            or manifest.get("sbom_scope")
            != "source-input-locks-only-v1"
            or manifest.get("profile_maturity")
            not in ("experimental", "release")
        ):
            fail("release manifest declares an unsupported package contract")
        top_manifest = manifest.get("top_directory")
        release_id = manifest.get("release_id")
        package_version = require_package_version(
            manifest.get("package_version"), "manifest package_version"
        )
        profile_id = require_identifier(
            manifest.get("profile_id"), "manifest profile_id"
        )
        profile_revision = manifest.get("profile_revision")
        release_revision = manifest.get("release_revision")
        profile_relative_path = manifest.get("profile_relative_path")
        epoch = manifest.get("source_date_epoch")
        if (
            top_manifest != top
            or not isinstance(release_id, str)
            or top != f"pocket-vm-{release_id}"
        ):
            fail(
                "release manifest identity does not match the archive "
                "top directory"
            )
        if (
            not isinstance(profile_revision, str)
            or not profile_revision.startswith("sha256:")
        ):
            fail("manifest profile_revision is malformed")
        revision_hex = require_hex64(
            profile_revision.removeprefix("sha256:"),
            "manifest profile_revision",
        )
        if (
            not isinstance(release_revision, str)
            or not release_revision.startswith("sha256:")
        ):
            fail("manifest release_revision is malformed")
        release_revision_hex = require_hex64(
            release_revision.removeprefix("sha256:"),
            "manifest release_revision",
        )
        expected_profile_path = (
            f"profiles/{profile_id}/{revision_hex}"
        )
        if profile_relative_path != expected_profile_path:
            fail(
                "manifest profile_relative_path is not revision exact"
            )
        if (
            not isinstance(epoch, int)
            or isinstance(epoch, bool)
            or not 946684800 <= epoch <= 4102444799
        ):
            fail("manifest source_date_epoch is outside years 2000 through 2099")
        raw_files = manifest.get("files")
        if not isinstance(raw_files, list) or not raw_files:
            fail("release manifest has no file inventory")
        manifest_entries: list[dict[str, object]] = []
        previous = ""
        executable_paths: set[str] = set()
        for entry in raw_files:
            if (
                not isinstance(entry, dict)
                or set(entry) != {"mode", "path", "sha256", "size"}
            ):
                fail(
                    "release manifest file entry has unexpected fields"
                )
            relative = parse_posix_relative(
                entry.get("path"), "manifest file path"
            )
            if relative <= previous:
                fail(
                    "release manifest file entries are not strictly sorted"
                )
            previous = relative
            if relative in (
                f"share/pocket-vm/{MANIFEST_NAME}",
                f"share/pocket-vm/{CHECKSUMS_NAME}",
            ):
                fail(
                    "release manifest must not recursively inventory "
                    "itself or SHA256SUMS"
                )
            mode = entry.get("mode")
            if mode not in ("0444", "0555"):
                fail(
                    "release manifest has a non-canonical mode for "
                    f"{relative}"
                )
            if mode == "0555":
                executable_paths.add(relative)
            if (
                not isinstance(entry.get("size"), int)
                or isinstance(entry.get("size"), bool)
                or entry["size"] < 0
            ):
                fail(
                    f"release manifest has an invalid size for {relative}"
                )
            require_hex64(
                entry.get("sha256"),
                f"manifest digest for {relative}",
            )
            manifest_entries.append(entry)

        release_identity = {
            "format": "pocket-vm-release-identity-v1",
            "files": manifest_entries,
            "package_version": package_version,
            "product": "pocket-vm",
            "profile_id": profile_id,
            "profile_maturity": manifest["profile_maturity"],
            "profile_revision": profile_revision,
            "sbom_scope": "source-input-locks-only-v1",
            "source_date_epoch": epoch,
            "target": "linux-x86_64",
        }
        computed_release_revision = hashlib.sha256(
            canonical_json(release_identity)
        ).hexdigest()
        expected_release_id = (
            f"{package_version}-{profile_id}-{release_revision_hex}"
        )
        if (
            computed_release_revision != release_revision_hex
            or release_id != expected_release_id
            or len(f"pocket-{release_id}") > 255
        ):
            fail("manifest release revision or release_id is not canonical")

        expected_files = {
            str(entry["path"]) for entry in manifest_entries
        }
        expected_files.update(
            (
                f"share/pocket-vm/{MANIFEST_NAME}",
                f"share/pocket-vm/{CHECKSUMS_NAME}",
            )
        )
        expected_directories = ancestor_directories(expected_files)
        observed_files: set[str] = set()
        observed_directories: set[str] = set()
        for member in members:
            relative = _member_relative(member.name, top)
            if relative == "":
                if not member.isdir():
                    fail("archive top member is not a directory")
            elif member.isdir():
                observed_directories.add(relative)
            else:
                observed_files.add(relative)
            expected_mode = (
                0o555
                if member.isdir() or relative in executable_paths
                else 0o444
            )
            if member.mode != expected_mode or member.mtime != epoch:
                fail(
                    "release archive member has non-canonical mode or "
                    f"timestamp: {member.name}"
                )
        if (
            observed_files != expected_files
            or observed_directories != expected_directories
        ):
            fail(
                "release archive member inventory does not exactly match "
                "the manifest"
            )
        expected_order = [top]
        expected_order.extend(
            f"{top}/{directory}"
            for directory in sorted(expected_directories)
        )
        expected_order.extend(
            f"{top}/{relative}" for relative in sorted(expected_files)
        )
        observed_order = [member.name.rstrip("/") for member in members]
        if observed_order != expected_order:
            fail("release archive members are not in canonical order")
        expected_offset = 0
        for member in members:
            relative = _member_relative(member.name, top)
            expected_mode = (
                0o555
                if member.isdir() or relative in executable_paths
                else 0o444
            )
            if member.offset != expected_offset:
                fail(
                    "release archive contains a hidden or misaligned "
                    f"header before {member.name}"
                )
            try:
                expected_header = _tar_info(
                    member.name.rstrip("/"),
                    expected_mode,
                    epoch,
                    directory=member.isdir(),
                    size=member.size,
                ).tobuf(
                    format=tarfile.USTAR_FORMAT,
                    encoding="utf-8",
                    errors="strict",
                )
            except (OverflowError, UnicodeError, ValueError) as error:
                fail(
                    "release archive member cannot be represented as "
                    f"canonical USTAR: {member.name}: {error}"
                )
            archive.fileobj.seek(member.offset)
            if archive.fileobj.read(tarfile.BLOCKSIZE) != expected_header:
                fail(
                    "release archive member header is not canonical USTAR: "
                    f"{member.name}"
                )
            padding_start = member.offset_data + member.size
            expected_offset = member.offset_data + (
                (member.size + tarfile.BLOCKSIZE - 1)
                // tarfile.BLOCKSIZE
                * tarfile.BLOCKSIZE
            )
            archive.fileobj.seek(padding_start)
            padding = archive.fileobj.read(expected_offset - padding_start)
            if any(padding):
                fail(
                    "release archive contains nonzero member padding: "
                    f"{member.name}"
                )
        canonical_size = (
            (
                expected_offset
                + (2 * tarfile.BLOCKSIZE)
                + tarfile.RECORDSIZE
                - 1
            )
            // tarfile.RECORDSIZE
            * tarfile.RECORDSIZE
        )
        if archive_state.size != canonical_size:
            fail("release archive has non-canonical end padding or trailing data")
        archive.fileobj.seek(expected_offset)
        end_padding = archive.fileobj.read(canonical_size - expected_offset)
        if len(end_padding) != canonical_size - expected_offset or any(end_padding):
            fail("release archive end padding is not canonical")

        expected_checksum_rows: list[tuple[str, str]] = [
            (str(entry["path"]), str(entry["sha256"]))
            for entry in manifest_entries
        ]
        expected_checksum_rows.append(
            (
                f"share/pocket-vm/{MANIFEST_NAME}",
                hashlib.sha256(manifest_bytes).hexdigest(),
            )
        )
        expected_checksum_rows.sort()
        expected_checksums = "".join(
            f"{digest}  {relative}\n"
            for relative, digest in expected_checksum_rows
        ).encode("ascii")
        checksums = _read_member(
            archive, checksums_member, 8 << 20
        )
        if checksums != expected_checksums:
            fail(
                "release SHA256SUMS is not canonical or does not bind "
                "the manifest"
            )
        for entry in manifest_entries:
            member = member_map[f"{top}/{entry['path']}"]
            if (
                member.size != entry["size"]
                or _hash_member(
                    archive, member, MAX_INPUT_FILE_BYTES
                ) != entry["sha256"]
            ):
                fail(
                    "release archive payload digest mismatch: "
                    f"{entry['path']}"
                )
        return ArchiveInfo(
            archive=path,
            top_directory=top,
            release_id=release_id,
            profile_id=profile_id,
            profile_revision=profile_revision,
            profile_relative_path=profile_relative_path,
            source_date_epoch=epoch,
            archive_sha256=archive_digest,
            archive_state=archive_state,
            manifest=manifest,
            members=tuple(members),
        )


def installed_expected_files(
    info: ArchiveInfo,
) -> dict[str, tuple[int, int, str]]:
    raw_files = cast(list[object], info.manifest["files"])
    result = {
        str(entry["path"]): (
            int(str(entry["mode"]), 8),
            int(entry["size"]),
            str(entry["sha256"]),
        )
        for entry in raw_files
        if isinstance(entry, dict)
    }
    with open_verified_archive(info) as archive:
        manifest_member = archive.getmember(
            f"{info.top_directory}/share/pocket-vm/{MANIFEST_NAME}"
        )
        checksums_member = archive.getmember(
            f"{info.top_directory}/share/pocket-vm/{CHECKSUMS_NAME}"
        )
        manifest_data = _read_member(
            archive, manifest_member, 8 << 20
        )
        checksums_data = _read_member(
            archive, checksums_member, 8 << 20
        )
    result[f"share/pocket-vm/{MANIFEST_NAME}"] = (
        0o444,
        len(manifest_data),
        hashlib.sha256(manifest_data).hexdigest(),
    )
    result[f"share/pocket-vm/{CHECKSUMS_NAME}"] = (
        0o444,
        len(checksums_data),
        hashlib.sha256(checksums_data).hexdigest(),
    )
    return result
