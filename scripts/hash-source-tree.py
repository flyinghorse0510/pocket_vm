#!/usr/bin/env python3
"""Hash every visible source-tree entry with a canonical binary encoding."""

from __future__ import annotations

import hashlib
import os
import stat
import struct
import sys
from pathlib import Path


def add_bytes(digest: "hashlib._Hash", value: bytes) -> None:
    digest.update(struct.pack(">Q", len(value)))
    digest.update(value)


def hash_tree(root_argument: str) -> str:
    root = Path(root_argument)
    root_stat = root.lstat()
    if not stat.S_ISDIR(root_stat.st_mode) or stat.S_ISLNK(root_stat.st_mode):
        raise ValueError("source-tree root must be a real directory")

    digest = hashlib.sha256(b"pocket-source-tree-v1\0")

    def visit(directory: Path, relative_parts: tuple[str, ...]) -> None:
        entries = sorted(os.scandir(directory), key=lambda entry: os.fsencode(entry.name))
        for entry in entries:
            relative = relative_parts + (entry.name,)
            relative_bytes = b"/".join(os.fsencode(part) for part in relative)
            metadata = entry.stat(follow_symlinks=False)
            permissions = stat.S_IMODE(metadata.st_mode)

            if stat.S_ISREG(metadata.st_mode):
                kind = b"f"
            elif stat.S_ISDIR(metadata.st_mode):
                kind = b"d"
            elif stat.S_ISLNK(metadata.st_mode):
                kind = b"l"
            else:
                raise ValueError(
                    f"unsupported source-tree entry type at {relative_bytes!r}"
                )

            digest.update(kind)
            digest.update(struct.pack(">I", permissions))
            add_bytes(digest, relative_bytes)

            if kind == b"f":
                file_digest = hashlib.sha256()
                size = 0
                with open(entry.path, "rb", buffering=0) as source:
                    while chunk := source.read(1024 * 1024):
                        size += len(chunk)
                        file_digest.update(chunk)
                digest.update(struct.pack(">Q", size))
                digest.update(file_digest.digest())
            elif kind == b"l":
                add_bytes(digest, os.fsencode(os.readlink(entry.path)))
            else:
                visit(Path(entry.path), relative)

    visit(root, ())
    return digest.hexdigest()


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: hash-source-tree.py ROOT", file=sys.stderr)
        return 2
    try:
        print(hash_tree(sys.argv[1]))
    except (OSError, ValueError) as error:
        print(f"hash-source-tree.py: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
