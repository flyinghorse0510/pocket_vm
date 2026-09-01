#!/usr/bin/env python3
"""Generate a deterministic, source-input-scoped SPDX 2.3 SBOM."""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
from pathlib import Path

from pocket_release import (
    ReleaseError,
    generate_spdx,
    publish_file_noreplace,
    read_regular_stable,
    require_absolute_normal_path,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cargo-lock", required=True, type=Path)
    parser.add_argument("--source-lock", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    require_absolute_normal_path(
        arguments.output, "SBOM output", must_exist=False
    )
    cargo, _ = read_regular_stable(
        arguments.cargo_lock, "Cargo.lock", maximum=16 << 20
    )
    sources, _ = read_regular_stable(
        arguments.source_lock, "sources.lock.toml", maximum=16 << 20
    )
    result = generate_spdx(cargo, sources)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".sbom.", dir=arguments.output.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(result)
            output.flush()
            os.fsync(output.fileno())
            os.fchmod(output.fileno(), 0o444)
        publish_file_noreplace(temporary, arguments.output)
    finally:
        temporary.unlink(missing_ok=True)
    print(arguments.output)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ReleaseError as error:
        print(f"generate-release-sbom: {error}", file=sys.stderr)
        raise SystemExit(1)
