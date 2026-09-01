#!/usr/bin/env bash

source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"

ROOT=$(project_root)

for MEMORY in 64M 256M 4G; do
    printf 'memory_probe_request=%s\n' "$MEMORY"
    POCKET_CPUS=1 POCKET_MEMORY="$MEMORY" "$ROOT/scripts/run-uml-probe.sh"
done

printf 'POCKET_MEMORY_MATRIX_OK\n'
