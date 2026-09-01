#!/usr/bin/env python3
"""Install or verify a pocket release under a versioned user prefix."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pwd
import secrets
import shlex
import stat
import sys
from pathlib import Path

from pocket_release import (
    ArchiveInfo,
    ReleaseError,
    ancestor_directories,
    archive_regular_file,
    hash_regular_stable,
    inspect_archive,
    installed_expected_files,
    open_verified_archive,
    publish_file_noreplace,
    read_regular_stable,
    refuse_walk_error,
    rename_noreplace,
    require_absolute_normal_path,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(
        dest="command", required=True
    )
    for command in ("install", "verify"):
        child = subparsers.add_parser(command)
        child.add_argument("--archive", required=True, type=Path)
        child.add_argument("--prefix", required=True, type=Path)
    install = subparsers.choices["install"]
    install.add_argument(
        "--store",
        type=Path,
        help="store recorded in the config file; defaults to "
        "$XDG_DATA_HOME/pocket/store",
    )
    install.add_argument(
        "--runtime-root",
        type=Path,
        help="runtime root recorded in the config file; defaults to "
        "$XDG_RUNTIME_DIR/pocket/run, which is short and on tmpfs",
    )
    install.add_argument(
        "--config",
        type=Path,
        help="config file to write; defaults to "
        "$XDG_CONFIG_HOME/pocket/config.toml",
    )
    install.add_argument(
        "--no-config",
        action="store_true",
        help="install without writing or updating a config file",
    )
    install.add_argument(
        "--no-default-link",
        action="store_true",
        help="install without pointing <prefix>/bin/pocket at this release",
    )
    return parser.parse_args()


def default_config_path() -> Path:
    if xdg := os.environ.get("XDG_CONFIG_HOME"):
        return Path(xdg) / "pocket/config.toml"
    return Path(user_home()) / ".config/pocket/config.toml"


def default_store_path() -> Path:
    if xdg := os.environ.get("XDG_DATA_HOME"):
        return Path(xdg) / "pocket/store"
    return Path(user_home()) / ".local/share/pocket/store"


def default_runtime_root() -> Path:
    # A runtime root on tmpfs keeps UML's own temporary files off disk, and
    # $XDG_RUNTIME_DIR is both tmpfs and short -- managed paths are capped at
    # 192 bytes because they become AF_UNIX socket paths inside UML.
    if xdg := os.environ.get("XDG_RUNTIME_DIR"):
        return Path(xdg) / "pocket/run"
    return Path(user_home()) / ".local/state/pocket/run"


def user_home() -> str:
    return pwd.getpwuid(os.geteuid()).pw_dir


def write_default_config(
    path: Path, profile: Path, store: Path, runtime_root: Path
) -> bool:
    """Record the three paths so ordinary commands need no flags.

    Returns whether the file was written. An existing config is never
    overwritten: it is the operator's, and silently repointing it at a
    different store would be exactly the surprise this project avoids.
    """
    for candidate in (store, runtime_root):
        if not candidate.is_absolute() or os.path.normpath(
            os.fspath(candidate)
        ) != os.fspath(candidate):
            raise ReleaseError(
                f"configured path must be absolute and normalized: {candidate}"
            )
    # Make the directories that hold the store and the runtime root. Pocket
    # creates each of those itself on first use, but not their parents, so
    # without this the very first command after an install fails on a path
    # this installer chose.
    for candidate in (store, runtime_root):
        candidate.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.exists() or path.is_symlink():
        return False
    # 0700: this file names the profile bundle every later command trusts, so
    # it is not left in a directory anyone else can write.
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    require_absolute_normal_path(path, "config file", must_exist=False)
    body = (
        "# Written by install-release.py. Every command reads these, and any\n"
        "# flag you pass still wins over them.\n"
        f'profile_bundle = "{profile}"\n'
        f'store = "{store}"\n'
        f'runtime_root = "{runtime_root}"\n'
    ).encode()
    temporary = path.parent / f".config-{secrets.token_hex(8)}"
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(body)
            output.flush()
            os.fsync(output.fileno())
        return publish_file_noreplace(temporary, path, exist_ok=True)
    finally:
        temporary.unlink(missing_ok=True)


def link_default_launcher(prefix: Path, launcher: Path) -> None:
    """Point `<prefix>/bin/pocket` at this release.

    Replacing this one symlink is the whole point -- it is how an operator
    selects which installed release is the default -- so unlike every other
    published path it is allowed to move.
    """
    link = prefix / "bin/pocket"
    # Not `require_absolute_normal_path`: this link is deliberately a symlink,
    # which that helper exists to reject everywhere else.
    if not link.is_absolute() or os.path.normpath(os.fspath(link)) != os.fspath(
        link
    ):
        raise ReleaseError(
            f"default launcher link must be absolute and normalized: {link}"
        )
    temporary = link.parent / f".pocket-{secrets.token_hex(8)}"
    os.symlink(launcher.name, temporary)
    try:
        os.replace(temporary, link)
    except OSError:
        temporary.unlink(missing_ok=True)
        raise
    descriptor = os.open(
        link.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def ensure_plain_user_directory(path: Path, *, create: bool) -> None:
    text = os.fspath(path)
    if (
        not path.is_absolute()
        or os.path.normpath(text) != text
        or "\n" in text
        or "\r" in text
    ):
        raise ReleaseError(
            "installation prefix must be an absolute normalized path"
        )
    uid = os.geteuid()
    user_home = Path(pwd.getpwuid(uid).pw_dir).resolve(strict=True)
    if path == user_home or user_home not in path.parents:
        raise ReleaseError(
            "installation prefix must be a child of the invoking "
            f"user's home: {user_home}"
        )
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        created = False
        try:
            current_stat = os.lstat(current)
        except FileNotFoundError:
            if not create:
                raise ReleaseError(
                    "installation prefix component does not exist: "
                    f"{current}"
                )
            try:
                os.mkdir(current, 0o755)
                created = True
            except FileExistsError:
                # Another installer created it between the stat and the mkdir.
                # Whatever it created is checked by the same rules below, so
                # losing this race is not a failure.
                pass
            current_stat = os.lstat(current)
        if stat.S_ISLNK(current_stat.st_mode) or not stat.S_ISDIR(
            current_stat.st_mode
        ):
            raise ReleaseError(
                "installation prefix traverses a link or non-directory: "
                f"{current}"
            )
        if current == user_home or user_home in current.parents:
            if current_stat.st_uid != uid:
                raise ReleaseError(
                    "installation prefix component is not owned by the "
                    f"invoking user: {current}"
                )
            if stat.S_IMODE(current_stat.st_mode) & 0o022:
                mode = stat.S_IMODE(current_stat.st_mode)
                raise ReleaseError(
                    "installation prefix component is group- or "
                    f"other-writable (mode {mode:04o}): {current}\n"
                    f"  fix it with: chmod go-w {current}\n"
                    "  or install somewhere else with: "
                    "make install PREFIX=<dir>"
                )
        if created:
            for directory in (current, current.parent):
                descriptor = os.open(
                    directory,
                    os.O_RDONLY
                    | os.O_DIRECTORY
                    | os.O_CLOEXEC
                    | os.O_NOFOLLOW,
                )
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)


def release_paths(
    prefix: Path, info: ArchiveInfo
) -> tuple[Path, Path, Path]:
    release_revision = info.manifest["release_revision"]
    if not isinstance(release_revision, str):
        raise ReleaseError("validated release revision is not a string")
    release_revision_hex = release_revision.removeprefix("sha256:")
    profile_revision_hex = info.profile_revision.removeprefix("sha256:")
    release = (
        prefix / "lib/pocket-vm/r" / release_revision_hex
    )
    profile = (
        prefix
        / "lib/pocket-vm/p"
        / info.profile_id
        / profile_revision_hex
    )
    launcher = prefix / "bin" / f"pocket-{info.release_id}"
    return release, profile, launcher


def launcher_bytes(release: Path) -> bytes:
    executable = release / "bin/pocket"
    return (
        f"#!/bin/sh\nexec {shlex.quote(os.fspath(executable))} \"$@\"\n"
    ).encode("utf-8")


def partition_install_files(
    info: ArchiveInfo,
) -> tuple[
    dict[str, tuple[str, int, int, str]],
    dict[str, tuple[str, int, int, str]],
]:
    all_files = installed_expected_files(info)
    profile_prefix = f"{info.profile_relative_path}/"
    release_files: dict[str, tuple[str, int, int, str]] = {}
    profile_files: dict[str, tuple[str, int, int, str]] = {}
    for archive_path, (mode, size, digest) in sorted(all_files.items()):
        if archive_path.startswith(profile_prefix):
            destination = archive_path.removeprefix(profile_prefix)
            if not destination:
                raise ReleaseError("profile archive path has no file name")
            profile_files[destination] = (
                archive_path,
                mode,
                size,
                digest,
            )
        else:
            release_files[archive_path] = (
                archive_path,
                mode,
                size,
                digest,
            )
    if "profile.json" not in profile_files or "bin/pocket" not in release_files:
        raise ReleaseError("release archive cannot be partitioned into runtime trees")
    return release_files, profile_files


def verify_plain_tree(
    root: Path,
    expected: dict[str, tuple[str, int, int, str]],
    epoch: int,
) -> None:
    expected_directories = ancestor_directories(expected)
    observed_files: set[str] = set()
    observed_directories: set[str] = set()
    root_stat = os.lstat(root)
    if (
        not stat.S_ISDIR(root_stat.st_mode)
        or stat.S_IMODE(root_stat.st_mode) != 0o555
        or int(root_stat.st_mtime) != epoch
    ):
        raise ReleaseError(
            "installed release root metadata is not canonical"
        )
    for current, directory_names, file_names in os.walk(
        root, topdown=True, followlinks=False, onerror=refuse_walk_error
    ):
        current_path = Path(current)
        relative_current = current_path.relative_to(root)
        if relative_current != Path("."):
            relative = relative_current.as_posix()
            observed_directories.add(relative)
            current_stat = os.lstat(current_path)
            if (
                not stat.S_ISDIR(current_stat.st_mode)
                or stat.S_IMODE(current_stat.st_mode) != 0o555
            ):
                raise ReleaseError(
                    "installed directory is linked, special, or has "
                    f"the wrong mode: {relative}"
                )
            if int(current_stat.st_mtime) != epoch:
                raise ReleaseError(
                    "installed directory has the wrong timestamp: "
                    f"{relative}"
                )
        for name in directory_names:
            child_stat = os.lstat(current_path / name)
            if stat.S_ISLNK(child_stat.st_mode) or not stat.S_ISDIR(
                child_stat.st_mode
            ):
                raise ReleaseError(
                    "installed release contains a linked or special "
                    f"directory: {name}"
                )
        for name in file_names:
            child = current_path / name
            relative = child.relative_to(root).as_posix()
            observed_files.add(relative)
            child_stat = os.lstat(child)
            if (
                not stat.S_ISREG(child_stat.st_mode)
                or child_stat.st_nlink != 1
            ):
                raise ReleaseError(
                    "installed release contains a linked, hard-linked, "
                    f"or special file: {relative}"
                )
            required = expected.get(relative)
            if required is None:
                continue
            _, mode, size, digest = required
            actual_digest, state = hash_regular_stable(
                child, f"installed file {relative}"
            )
            if (
                state.mode != mode
                or state.size != size
                or int(state.mtime_ns // 1_000_000_000)
                != epoch
            ):
                raise ReleaseError(
                    f"installed file metadata mismatch: {relative}"
                )
            if actual_digest != digest:
                raise ReleaseError(
                    f"installed file digest mismatch: {relative}"
                )
    if (
        observed_files != set(expected)
        or observed_directories != expected_directories
    ):
        raise ReleaseError(
            "installed release inventory does not exactly match its archive"
        )


def verify_launcher(launcher: Path, release: Path) -> None:
    expected = launcher_bytes(release)
    actual, state = read_regular_stable(
        launcher, "versioned pocket launcher"
    )
    if actual != expected or state.mode != 0o555:
        raise ReleaseError(
            "existing versioned launcher differs from the requested "
            f"release: {launcher}"
        )


def extract_to_stage(
    info: ArchiveInfo,
    stage: Path,
    expected: dict[str, tuple[str, int, int, str]],
) -> None:
    directories = sorted(
        ancestor_directories(expected),
        key=lambda value: (value.count("/"), value),
    )
    os.mkdir(stage, 0o700)
    for directory in directories:
        os.mkdir(stage / directory, 0o700)
    with open_verified_archive(info) as archive:
        for relative, (
            archive_path,
            mode,
            size,
            digest,
        ) in sorted(
            expected.items()
        ):
            member = archive.getmember(
                f"{info.top_directory}/{archive_path}"
            )
            stream = archive.extractfile(member)
            if stream is None:
                raise ReleaseError(
                    "cannot read archive member during installation: "
                    f"{relative}"
                )
            destination = stage / relative
            descriptor = os.open(
                destination,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | os.O_CLOEXEC
                | os.O_NOFOLLOW,
                0o600,
            )
            observed = hashlib.sha256()
            written = 0
            try:
                while True:
                    chunk = stream.read(1024 * 1024)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > size:
                        raise ReleaseError(
                            "archive member grew during installation: "
                            f"{relative}"
                        )
                    observed.update(chunk)
                    view = memoryview(chunk)
                    while view:
                        count = os.write(descriptor, view)
                        if count <= 0:
                            raise ReleaseError(
                                "short write while installing "
                                f"{relative}"
                            )
                        view = view[count:]
                if (
                    written != size
                    or observed.hexdigest() != digest
                ):
                    raise ReleaseError(
                        "archive member failed installation digest "
                        f"check: {relative}"
                    )
                os.fsync(descriptor)
                os.fchmod(descriptor, mode)
            finally:
                os.close(descriptor)
            os.utime(
                destination,
                (info.source_date_epoch, info.source_date_epoch),
                follow_symlinks=False,
            )
    for directory in sorted(
        directories,
        key=lambda value: (value.count("/"), value),
        reverse=True,
    ):
        destination = stage / directory
        os.chmod(destination, 0o555, follow_symlinks=False)
        os.utime(
            destination,
            (info.source_date_epoch, info.source_date_epoch),
            follow_symlinks=False,
        )
    os.chmod(stage, 0o555, follow_symlinks=False)
    os.utime(
        stage,
        (info.source_date_epoch, info.source_date_epoch),
        follow_symlinks=False,
    )
    for directory in [
        *(stage / relative for relative in sorted(
            directories,
            key=lambda value: (value.count("/"), value),
            reverse=True,
        )),
        stage,
    ]:
        descriptor = os.open(
            directory,
            os.O_RDONLY
            | os.O_DIRECTORY
            | os.O_CLOEXEC
            | os.O_NOFOLLOW,
        )
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    verify_plain_tree(stage, expected, info.source_date_epoch)


def remove_private_stage(stage: Path) -> None:
    """Remove a stage that may already have been sealed read-only.

    Removing an entry needs write permission on the directory that holds it,
    not on the entry itself, and extraction seals every staged directory to
    0555 before this can run. Each directory is therefore made writable again
    on the way in, or the cleanup raises PermissionError and masks whatever
    error sent us here.
    """
    if stage.is_symlink():
        stage.unlink()
        return
    if not stage.exists():
        return

    def remove_tree(directory: Path) -> None:
        os.chmod(directory, 0o700, follow_symlinks=False)
        with os.scandir(directory) as scan:
            entries = list(scan)
        for entry in entries:
            child = Path(entry.path)
            # Classified without following: a symlink to a directory is an
            # entry to unlink, never a tree to descend into.
            if entry.is_dir(follow_symlinks=False):
                remove_tree(child)
            else:
                child.unlink()
        directory.rmdir()

    remove_tree(stage)


def ensure_installed_tree(
    info: ArchiveInfo,
    parent: Path,
    final: Path,
    expected: dict[str, tuple[str, int, int, str]],
    label: str,
) -> bool:
    if final.exists() or final.is_symlink():
        require_absolute_normal_path(final, f"installed {label}")
        verify_plain_tree(final, expected, info.source_date_epoch)
        return False
    stage = parent / f".install-{label}-{secrets.token_hex(8)}"
    try:
        extract_to_stage(info, stage, expected)
        if not rename_noreplace(stage, final, exist_ok=True):
            # Another installer published this exact tree while this one was
            # extracting. That is a race one of us wins, not a failure: verify
            # what is there, which is the same check the already-installed path
            # makes, and report that this call changed nothing.
            verify_plain_tree(final, expected, info.source_date_epoch)
            return False
        return True
    finally:
        remove_private_stage(stage)


def enforce_profile_path_budget(
    profile: Path,
    expected: dict[str, tuple[str, int, int, str]],
) -> None:
    """Refuse a prefix pocket could install into but never load from.

    `--profile-bundle` is a managed UML path, and pocket's rule for one is more
    than a length: it must also be normalized, free of whitespace, and free of
    the characters UML's own command-line grammar reserves. Checking only the
    length here leaves prefixes -- a home directory with a space in its name is
    the ordinary case -- that install cleanly and then fail every single run.
    """
    text = os.fsdecode(profile)
    segments = text.removeprefix("/").split("/")
    if not text.startswith("/") or any(
        segment in ("", ".", "..") for segment in segments
    ):
        raise ReleaseError(
            f"installed profile path is not absolute and normalized: {text}"
        )
    if len(segments) < 3:
        raise ReleaseError(
            f"installed profile path is too broad for pocket to manage: {text}"
        )
    for character in text:
        if character.isspace():
            raise ReleaseError(
                "installed profile path contains whitespace, which pocket's "
                f"managed-path rule forbids: {text}"
            )
        if character in ",:\0":
            raise ReleaseError(
                f"installed profile path contains reserved {character!r}, "
                f"which pocket's managed-path rule forbids: {text}"
            )
    longest_path = max(
        [profile, *(profile / relative for relative in expected)],
        key=lambda path: len(os.fsencode(path)),
    )
    length = len(os.fsencode(longest_path))
    if length > 192:
        raise ReleaseError(
            "installed profile would exceed pocket's 192-byte managed "
            f"path limit ({length} bytes at {longest_path})"
        )


def install(
    info: ArchiveInfo, prefix: Path
) -> tuple[Path, Path, Path, bool, bool, bool]:
    ensure_plain_user_directory(prefix, create=True)
    release_files, profile_files = partition_install_files(info)
    releases_parent = prefix / "lib/pocket-vm/r"
    profiles_parent = prefix / "lib/pocket-vm/p" / info.profile_id
    bin_parent = prefix / "bin"
    ensure_plain_user_directory(releases_parent, create=True)
    ensure_plain_user_directory(profiles_parent, create=True)
    ensure_plain_user_directory(bin_parent, create=True)
    release, profile, launcher = release_paths(prefix, info)
    enforce_profile_path_budget(profile, profile_files)
    profile_changed = ensure_installed_tree(
        info,
        profiles_parent,
        profile,
        profile_files,
        f"profile-{info.profile_revision.removeprefix('sha256:')}",
    )
    release_changed = ensure_installed_tree(
        info,
        releases_parent,
        release,
        release_files,
        f"release-{info.manifest['release_revision'].removeprefix('sha256:')}",
    )
    wrapper = launcher_bytes(release)
    launcher_changed = False
    if launcher.exists() or launcher.is_symlink():
        require_absolute_normal_path(
            launcher, "versioned launcher"
        )
        verify_launcher(launcher, release)
    else:
        temporary = bin_parent / (
            f".launcher-{secrets.token_hex(8)}"
        )
        descriptor = os.open(
            temporary,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_CLOEXEC
            | os.O_NOFOLLOW,
            0o600,
        )
        try:
            with os.fdopen(descriptor, "wb") as output:
                output.write(wrapper)
                output.flush()
                os.fsync(output.fileno())
                os.fchmod(output.fileno(), 0o555)
            # A launcher deleted by hand is recreated here, and that is a
            # change the caller must be told about even when both trees were
            # already installed.
            launcher_changed = publish_file_noreplace(
                temporary, launcher, exist_ok=True
            )
        finally:
            temporary.unlink(missing_ok=True)
    verify_plain_tree(
        release, release_files, info.source_date_epoch
    )
    verify_plain_tree(
        profile, profile_files, info.source_date_epoch
    )
    verify_launcher(launcher, release)
    with open_verified_archive(info):
        pass
    return (
        release,
        profile,
        launcher,
        release_changed,
        profile_changed,
        launcher_changed,
    )


def verify(
    info: ArchiveInfo, prefix: Path
) -> tuple[Path, Path, Path]:
    ensure_plain_user_directory(prefix, create=False)
    release_files, profile_files = partition_install_files(info)
    release, profile, launcher = release_paths(prefix, info)
    enforce_profile_path_budget(profile, profile_files)
    require_absolute_normal_path(release, "installed release")
    require_absolute_normal_path(profile, "installed profile")
    require_absolute_normal_path(launcher, "versioned launcher")
    verify_plain_tree(
        release, release_files, info.source_date_epoch
    )
    verify_plain_tree(
        profile, profile_files, info.source_date_epoch
    )
    verify_launcher(launcher, release)
    with open_verified_archive(info):
        pass
    return release, profile, launcher


def main() -> int:
    if os.geteuid() == 0:
        raise ReleaseError(
            "this user-prefix installer refuses effective UID 0"
        )
    arguments = parse_args()
    archive_regular_file(arguments.archive)
    info = inspect_archive(arguments.archive)
    if arguments.command == "install":
        (
            release,
            profile,
            launcher,
            release_changed,
            profile_changed,
            launcher_changed,
        ) = install(
            info,
            arguments.prefix,
        )
        if arguments.no_default_link:
            default_link = None
        else:
            link_default_launcher(arguments.prefix, launcher)
            default_link = arguments.prefix / "bin/pocket"
        if arguments.no_config:
            for flag, value in (
                ("--config", arguments.config),
                ("--store", arguments.store),
                ("--runtime-root", arguments.runtime_root),
            ):
                if value is not None:
                    raise ReleaseError(
                        f"{flag} configures the config file, which "
                        "--no-config declines to write"
                    )
            config_path = None
            config_written = False
        else:
            config_path = arguments.config or default_config_path()
            config_written = write_default_config(
                config_path,
                profile,
                arguments.store or default_store_path(),
                arguments.runtime_root or default_runtime_root(),
            )
    else:
        release, profile, launcher = verify(
            info, arguments.prefix
        )
        release_changed = False
        profile_changed = False
        launcher_changed = False
        default_link = None
        config_path = None
        config_written = False
    print(
        json.dumps(
            {
                "changed": release_changed
                or profile_changed
                or launcher_changed
                or config_written,
                "config": str(config_path) if config_path else None,
                "config_written": config_written,
                "default_launcher": str(default_link) if default_link else None,
                "launcher": str(launcher),
                "launcher_changed": launcher_changed,
                "profile": str(profile),
                "profile_changed": profile_changed,
                "release": str(release),
                "release_id": info.release_id,
                "release_changed": release_changed,
                "release_revision": info.manifest["release_revision"],
                "verified": True,
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
        print(f"install-release: {error}", file=sys.stderr)
        raise SystemExit(1)
