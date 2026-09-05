#!/usr/bin/env bash

# Build and run the host clone/id-cache probe.
#
# Standalone for the same reason the seccomp probe is: it depends on nothing
# pocket builds, so it can be carried to a candidate host on its own and answer
# "does this libc's clone() corrupt the caller's id cache?" -- the observation
# patch 0009 exists to act on.

# shellcheck source=scripts/lib.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"

ROOT=$(project_root)
BUILD_ROOT=${POCKET_BUILD_ROOT:-"$ROOT/build"}
OUTPUT_DIR="$BUILD_ROOT/host-probe"
SOURCE="$ROOT/host/clone-idcache-probe/main.c"
CC=${CC:-gcc}

require_command "$CC"
safe_managed_root "$BUILD_ROOT"
[[ -f $SOURCE && ! -L $SOURCE ]] || die "host probe source is missing: $SOURCE"

mkdir -p -- "$OUTPUT_DIR"
"$CC" -std=gnu11 -O2 -Wall -Wextra -Werror -pthread \
    -o "$OUTPUT_DIR/clone-idcache-probe" "$SOURCE"

"$OUTPUT_DIR/clone-idcache-probe"
