# pocket-runtime

`pocket-runtime` is the host-side library for one trusted UML workload. It is
not a public CLI and it is not a sandbox.

The implemented profile loader accepts only the current static x86_64
contract: native `linux/amd64`, 4 KiB guest pages, a Linux 7.2-compatible
kernel configuration, ext4 with 4 KiB blocks, UML COW v3,
`seccomp=on`, `noreboot`, the fixed serial-FD topology, and the fixed guest
capability policy. Unknown JSON fields and dynamic-linkage manifests are
rejected: a dynamically linked kernel would bind the sealed profile to the
host's libraries.

`seal_profile_bundle` is the sole release-profile assembler. It copies exact
non-symlink inputs into private staging, binds static Skopeo, the slirp4netns network
helper and a separate registry CA bundle alongside the UML/guard/e2fs/initramfs
artifacts, derives
the guest/build identities from the measured bytes and exact protocol feature
sets, computes the non-circular revision, and verifies the result through
`VerifiedProfile::load`. Publication uses Linux
`renameat2(RENAME_NOREPLACE)` beneath an owner-controlled collection directory;
a concurrent identical publication is reused, while differing or invalid
content at that revision pathname is rejected.

For every start the library:

- recomputes the non-circular profile revision and reverifies artifact paths,
  sizes, SHA-256 digests, static x86_64 ELF identity, file modes/capabilities,
  and normalized kernel configuration;
- acquires an immutable generation lease, or atomically resolves and leases an
  alias with `Store::lease_alias`, before observing generation paths;
- verifies generation/profile/platform/filesystem agreement and the clean
  4-KiB ext4 superblock before creating any per-run state;
- creates a mode-0700 run directory, holds an exclusive `owner.lock` on it for
  the run's whole life -- which is what lets a later operation reclaim an
  abandoned one and what `live_operations` reads to list running work -- and
  leaves `root.cow` absent for UML to initialize over the immutable base;
- maps lease, liveness, control, standard streams, and console to fixed FDs
  8–14 in a pre-exec child, then starts the verified `pocket-guard` directly
  with a cleared environment and explicit argv, handing it the profile's
  network helper to start and stop for a networked run;
- always supplies `--uml-personality`, `seccomp=on`, `noreboot`, `panic=1`,
  explicit memory/guest-memory assertions, and the SMP/guest-CPU assertion
  pair (the deliberately UP profile omits only UML's unavailable `ncpus=`
  parser);
- requires bounded HELLO/START/READY framing, exact build/policy/CPU/memory
  identity, and a valid COW v3 backing binding before READY;
- captures and drains distinct stdout, stderr, console, and guard diagnostics
  with hard retained-byte caps; and
- closes the liveness pipe, reaps or kills the guard, re-verifies the immutable
  base, and removes the run directory it recorded -- on success, on failure and
  on handle drop alike.

`HostBuilder` implements the bounded host half of the release-profile build
contract for a direct canonical OCI layout. It authenticates the selected
`linux/amd64` manifest and its raw descriptor/config/effective platform
evidence, atomically acquires the derivation transaction, formats private
payload and target ext4 images through `pocket-guard` with the profile's exact
`MKE2FS_CONFIG`, checks the target with only the sealed empty `E2FSCK_CONFIG`,
and gives both helpers one private per-build `BLKID_FILE`. Payload and target
sizes account separately for blocks and inodes; both receive derivation-bound
ext4 directory hash seeds, and a classified internal block/inode ENOSPC causes
one retry from a discarded image in the exact next size/inode class. It then
boots the profile's builder initramfs without a shell, sends the bounded build
epoch, and validates the bounded HELLO/BUILD_START/manifest/ACCOUNT_DB/
BUILD_DONE stream.
It publishes the verified base and canonical `accounts.cbor`, artifact digest,
build record, bounded log, authenticated image config, and metadata-manifest
sidecars before updating the platform-qualified alias.

Current limitations:

- No terminal/PTY, persistent managed-volume, dynamic UML/helper, or
  retained-COW workflow is implemented by this crate. Host-directory shares and
  slirp/BESS networking are implemented, and are carried per run in `START`
  along with the capability policy.
- The host builder accepts only the qualified x86 release contract and a
  direct canonical OCI image layout. It does not normalize Docker media types,
  nested indexes, or remote references, and it makes no arm64 qualification
  claim.
- Publication is supported by builder evidence, a guarded host `e2fsck`, and an
  independent read-only validator UML boot carrying a fresh random challenge.
  The build record
  truthfully labels the result as exact-output-digest-only: the guest clock is
  initialized from the bounded epoch before target mount, but advancing
  realtime, generated ctime, ext4 inode generation, and journal/runtime entropy
  are not all normalized yet, so identical base bytes are not claimed.
- Named image users must resolve unambiguously in the streamed account
  database. Preserving an unresolved typed user for a later policy decision is
  not implemented.
- Input and output use bounded in-memory synchronous buffers rather than a
  streaming caller API. `execution_timeout=None` still has a 24-hour hard
  protocol wait cap.
- Graceful termination sends the validated image stop signal and waits the
  caller's grace period (`wait` uses the policy's execution-timeout grace).
  If EXIT does not arrive, the runtime sends bounded SHUTDOWN, preserves any
  partial inbound frame across the timed waits, and gives pocket-init a
  separately bounded interval to acknowledge with EXIT. Only a missing or
  invalid acknowledgement closes guard liveness and forces host cleanup.
- A request within the profile's CPU maximum is never rejected for low current
  affinity or quota. `scaling_qualified` is false when affinity is too small,
  cgroup-v2 `cpu.max` is too small, or that quota cannot be observed. The CLI
  turns a false result on a multi-vCPU request into a note on standard error:
  the measurement is only worth taking if the caller is told.
- A guest may report an ERROR before it has sent HELLO. Its control channel
  exists from the moment its serial lines are open, so a failure in early setup
  reaches the host as its own typed cause rather than a startup timeout.
- Artifact digests are rechecked immediately before spawn, but this trusted
  single-user design does not defend against the artifact owner deliberately
  replacing bytes concurrently during exec.
- Unit tests exercise strict manifests, ELF/config/ext4/COW parsing, exact
  argv, bounded protocol sequencing (including SIGNAL/SHUTDOWN/forced EXIT and
  a frame split across a timeout), raw-platform identity, account/manifest
  evidence, and real fake-executable FD launches. An ignored test provides the
  explicit environment-variable gate for a qualified profile and real builder
  UML boot; the default test suite does not run it and therefore makes no
  production-boot claim.
