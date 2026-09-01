#!/usr/bin/env bash

source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"

ROOT=$(project_root)
BUILD_ROOT=${POCKET_BUILD_ROOT:-"$ROOT/build"}
OUTPUT_DIR="$BUILD_ROOT/disks"
OUTPUT="$OUTPUT_DIR/probe.ext4"
STAGING="$OUTPUT_DIR/probe.ext4.tmp"
UUID=99e47a26-5d63-4f6d-9ae9-e970d9f0936a

for command in mke2fs e2fsck truncate; do
    require_command "$command"
done
safe_managed_root "$BUILD_ROOT"
mkdir -p -- "$OUTPUT_DIR"

truncate -s 32M "$STAGING"
E2FSPROGS_FAKE_TIME=1786940622 mke2fs -q -t ext4 -b 4096 -I 256 -m 0 \
    -U "$UUID" -L pocket-probe \
    -O ext_attr,dir_index,filetype,extent,64bit,flex_bg,sparse_super,large_file,huge_file,uninit_bg,dir_nlink,extra_isize,metadata_csum,^has_journal,^orphan_file \
    -E lazy_itable_init=0,lazy_journal_init=0 \
    -d "$ROOT/fixtures/probe-root" "$STAGING"
e2fsck -fn "$STAGING"
mv -- "$STAGING" "$OUTPUT"
chmod 0600 "$OUTPUT"
sha256sum "$OUTPUT" > "$OUTPUT.sha256"
cat "$OUTPUT.sha256"

