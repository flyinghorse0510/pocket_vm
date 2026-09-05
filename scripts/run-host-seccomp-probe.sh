#!/usr/bin/env bash

# Build and run the host seccomp probe.
#
# The probe is deliberately standalone: it depends on nothing pocket builds, so
# it can be carried to a candidate host on its own and answer "can UML's
# seccomp backend run here?" before anything else is attempted.

# shellcheck source=scripts/lib.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"

ROOT=$(project_root)
BUILD_ROOT=${POCKET_BUILD_ROOT:-"$ROOT/build"}
OUTPUT_DIR="$BUILD_ROOT/host-probe"
SOURCE="$ROOT/host/seccomp-probe/main.c"
CC=${CC:-gcc}

require_command "$CC"
safe_managed_root "$BUILD_ROOT"
[[ -f $SOURCE && ! -L $SOURCE ]] || die "host probe source is missing: $SOURCE"

mkdir -p -- "$OUTPUT_DIR"
"$CC" -std=gnu11 -O2 -Wall -Wextra -Werror -o "$OUTPUT_DIR/seccomp-probe" "$SOURCE"

"$OUTPUT_DIR/seccomp-probe"
