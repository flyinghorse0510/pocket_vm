# pocket-builder-init

`pocket-builder-init` is the production guest PID 1 for Pocket's trusted,
single-vCPU image-conversion UML. It does not mount anything on the host.
Inside the builder guest it:

1. measures the guest architecture, page size, online CPU count, exact accepted
   UML physical-memory bytes, and pinned umoci artifact/version;
2. performs the bounded `BUILD_HELLO` / `BUILD_START` handshake;
3. mounts `/dev/ubda` read-only at `/input` and `/dev/ubdb` at `/target`;
4. re-authenticates the selected canonical OCI manifest, config, compressed
   layers and uncompressed DiffIDs against `BUILD_START`;
5. invokes `/usr/bin/umoci` directly as the literal argv
   `raw unpack --image /input:root /target/rootfs`, with no shell and an empty
   environment;
6. resolves image `User` or records a canonical unresolved result for a valid
   missing account name, atomically writes
   `/target/.pocket-generation.cbor`, and streams a bounded canonical metadata
   manifest that includes content digests, hardlink topology, device metadata,
   symlinks and sorted xattrs;
7. syncs and unmounts both ext4 filesystems before `BUILD_DONE`.

Every partial-stream, helper, input, marker, sync or unmount failure returns a
typed `BUILD_ERROR`; the target remains an unpublished staging artifact.

## Pinned x86_64 release build

Rust 1.93.1, the GNU target standard library, GCC major, `Cargo.lock`, and all
crate sources are build-contract inputs. The canonical workspace recipe is:

```sh
make release-artifacts
file build/release/x86_64-smp-p4k/guest/pocket-builder-init
readelf -l build/release/x86_64-smp-p4k/guest/pocket-builder-init
```

The script invokes Cargo with explicit target `x86_64-unknown-linux-gnu` and
target-specific `-Ctarget-feature=+crt-static`. The result must be an x86-64
static PIE and `readelf` must show neither `INTERP` nor `DT_NEEDED`. Native
arm64 remains a separate profile build and native-hardware qualification track;
this x86-only recipe must not be relabeled as arm64 evidence.

The release builder installs the verified executable as `/init` and includes
the source-lock-pinned `/usr/bin/umoci` 0.4.7 plus exactly its pinned
`libc.so.6` and dynamic loader. It verifies the helper's digest, version,
interpreter and sole `DT_NEEDED` entry before packing. The umoci bytes and
`--version` output sent in `BUILD_HELLO` must still equal the profile manifest
and `BUILD_START` evidence.

The UML launch pairs its consumed arguments with guest-visible aliases. For
example, a 768 MiB SMP-capable builder receives both `mem=768M ncpus=1` and:

```text
pocket.builder.expected_memory_bytes=805306368
pocket.builder.expected_cpus=1
pocket.builder.expected_page_size=4096
pocket.builder.cpu_state_hwcap_policy=native-x86_64-v1
pocket.builder.manifest_schema=pocket-fs-manifest-v1
pocket.builder.guest_contract_id=SHA256_HEX
pocket.builder.init_build_id=SHA256_HEX
pocket.builder.kernel_build_id=SHA256_HEX
```

UML consumes `mem=` and `ncpus=` before exposing `/proc/cmdline`; the aliases
are therefore mandatory. PID 1 compares them with `_NPROCESSORS_ONLN` and the
revision-bound `/proc/uml_physmem_bytes` ABI before sending `BUILD_HELLO`.

## Integration boundary

The crate and builder protocol have unprivileged tests for canonical framing,
stream sequencing and totals, OCI/DiffID tampering, marker collision, account
resolution, hardlinks/symlinks, negotiated limits, exact umoci argv, and fake
helper success/failure behavior. They do not pretend to be a privileged UML
test. The host-side production builder launcher/stream receiver, target sizing
and retry policy, e2fsck, separate validation UML, cache transaction, and
metadata conformance corpus remain separate Phase 3 integration work. Until
those pieces verify and publish the result, this crate's successful guest-side
conversion alone is not a complete production importer.
