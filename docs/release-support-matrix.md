# Experimental support matrix and release checklist

This document states what the packaged profile supports today, and what remains
before it can be called anything other than experimental.

The packaging target is the mainline Linux 7.2 UML profile for x86_64 hosts and
`linux/amd64` OCI images. The package and installer preserve the profile's own
maturity field; neither promotes an experimental profile to release status, and
a successful package does not satisfy any gate below.

The profile is experimental because the portability, byte-reproducibility,
distribution and signing gates remain open.

## Declared support boundary

| Dimension | Packaged boundary | Status |
|---|---|---|
| Host kernel/userspace | x86_64 Linux 5.9 or newer, able to execute the sealed UML and host binaries | Qualified-host range not frozen. The floor is UML's mandatory `seccomp` mode, whose stub requires `close_range` and fails closed without it. The shipped artifacts are static and impose no userspace version. Measured on Ubuntu 26.04.1 / 7.0.0-30 |
| Guest architecture | x86_64 UML (EM_X86_64 host executables) | Implemented profile only |
| Hosts below the kernel floor | Optional `el7` kernel variant, selected by name | Experimental, and narrower than the row above. The kernel is built on the EL7 host because it is bound to that toolchain; the bundle's other artifacts are static host binaries built on a current host, and the two are sealed together. Validated on CentOS Linux 7.9.2009 / 3.10.0-1160.119.1.el7 / glibc 2.17. See [EL7 host support](el7-host-support.md) |
| OCI platform | `linux/amd64`, subject to the profile's accepted variants | Experimental |
| CPU count | 1 through the sealed profile's effective maximum, currently 64 — the range end `arch/um/Kconfig` permits | A request within that maximum is never refused for a narrower host: it runs oversubscribed and reports `scaling_qualified=false`. Correctness at a vCPU count therefore does not require a host of that width,. The ceiling is checked at its boundary: 64 boots and reports 64, 65 is refused before launch. Speedup beyond the host's core count is not characterised, and is not a claim this package makes |
| Guest memory | Profile minimum through effective maximum, aligned to 4096 bytes | Observed at 64 MiB, 256 MiB and 4 GiB through the full workload lifecycle. The guest asserts a floor rather than an equality, because `arch/um/kernel/um_arch.c` adds the gap between the kernel image and its initial program break to `physmem_size` once that gap exceeds a megabyte. Accepting less than the request is refused |
| Networking | Outbound NAT by default over an unprivileged userspace stack; `--network none` opts out | Implemented. Inbound port forwarding is not |
| Interactive terminal | `-t` allocates a guest PTY, holds the host terminal raw, and streams both directions with window-size forwarding | Implemented. `make terminal-session` asserts `isatty`, the startup and resized window sizes, a resolvable `ttyname`, `TERM`, an interrupt reaching the guest's line discipline, the workload's exit status, and the refusal when either descriptor is not a terminal |
| Guest console | Mirrored to stderr as a run boots; `--no-boot-log` opts out; `--console-log` writes the transcript to a file | Implemented. On a terminal in raw mode the mirror supplies the carriage returns the terminal would otherwise add |
| Kept runs | A run is retained under a name when it exits, listed by `ps -a`, resumed by `start`, removed by `rm`; `--rm` opts out; `commit` publishes a kept run as a new image | Implemented. The retained overlay roots its generation against `cache gc`. A committed image carries a commit record rather than the source's build evidence, and its account database derives from the merged filesystem. `make instances` asserts that resuming continues the kept overlay |
| Image filesystem size | Sized from contents with an 8 GiB floor; `image adjust` republishes at another size in either direction | Implemented. `make image-adjust` grows and shrinks one image, boots each result, and asserts the source is unmodified |
| Extra serial lines | `--consoles N` (max 8) adds guest `/dev/ttyS4` upwards, each published as a host pseudo-terminal with a login shell | Implemented. `make terminal-session` attaches to a line a workload never touches, asserts the waiting shell has the workload's identity and that a second line is independently usable |
| Host directory sharing | One directory per run through hostfs, claimed by an exclusive lock on the directory | Implemented. No coherence with host-side changes while a run holds it |
| Guest capabilities | Fixed 12-capability allowlist; `--privileged` grants the guest kernel's full set | Implemented. Grants nothing on the host |
| Managed path lengths | Store and profile up to 3840 bytes; runtime root capped at 66, derived from the kernel's 108-byte `sockaddr_un` | Hard kernel limit, not a policy choice |
| Trust model | Trusted guest userspace supplied by the user | Intentional boundary |
| Registry acquisition | Anonymous `docker` transport, sealed CA and Skopeo policy. A bare name expands the way a registry client would; other transports are refused | Experimental |
| Local image input | Canonical OCI layout plus constrained single-image OCI and Docker archives | Experimental |
| Installation | Any prefix the caller can write, including one shared between users; version-exact side-by-side releases | Foundation implemented; clean-host qualification pending |
| Host libc/runtime | Not yet declared portable | Release blocker. Host CLI linkage and minimum ABI need qualification |
| arm64 UML | Not in this package or profile | The seed is an out-of-tree port of Linux 7.2-rc4 plus 54 commits. Native execution is feasible, but seed reproduction and a reviewed transplant onto the selected maintained release are both required. No implied mainline support |
| Security isolation | Not a hostile-workload sandbox | Out of scope for this trusted-input profile |

## Mandatory release gates

Every item must have retained, revision-bound evidence before the profile or
package maturity changes. Each states the requirement, its status, and the
committed target that reproduces its evidence — reproduce the target rather
than trusting the text.

### Kernel and build inputs

- [x] **Authenticated kernel source.** Rebuild Linux 7.2 from the authenticated
  tarball and exact patch series in a clean tree, matching the Git-tree
  identity and canonical SHA-256 source manifest before and after.
  `make kernel` performs this on every invocation; `make audit-linux-source`
  and `make test-linux-source-pipeline` pass against the published tree.
- [x] **Pinned third-party inputs.** Rebuild pinned e2fsprogs and Skopeo from
  their authenticated sources. Reproducibility is checked by
  `make reproduce-release`, which rebuilds the whole release in an independent
  root; the per-tool builds do not rebuild themselves to compare, because a
  byte difference between two local passes blocks a build without telling the
  operator anything the release lane does not.
- [ ] **Rust artifact declaration.** Build every Rust host and guest artifact
  with `Cargo.lock`, locked dependency availability and recorded target
  configuration, and record whether each host artifact is static along with its
  minimum kernel and libc ABI. `make release-artifacts` pins the lock file and
  target, and the Rust toolchain is held to the workspace `rust-version` floor.
  `scripts/verify-artifacts.sh` reports recorded digests rather than enforcing
  them; `POCKET_STRICT_TOOLCHAIN=1` enforces them. The minimum kernel and libc
  ABI of each host artifact is undeclared.

### Guest correctness

- [x] **SMP correctness.** The `CONFIG_SMP=y` scheduler and RCU lifecycle
  failure is corrected at the source: `arch/um/drivers/chan_kern.c` drained its
  deferred channel-IRQ list from the SIGIO signal handler, where the generic
  `free_irq()` sleeps on an SMP kernel. Patches `0003`-`0005` move that drain
  into process context, and the series is bisectable. `make lifecycle-soak`
  runs 100 consecutive fresh lifecycles at each of 1, 2, 4, 12 and 16 vCPUs
  plus five eight-way concurrent waves with no failure and no leaked runtime
  directory; `make rust-release-e2e` passes for Ubuntu 24.04 and 26.04.
- [x] **Debug-kernel lifecycle.** `make diagnostic-lifecycle` rebuilds the same
  patched source with `CONFIG_DEBUG_ATOMIC_SLEEP`, `CONFIG_PROVE_LOCKING`,
  `CONFIG_PROVE_RCU`, `CONFIG_DEBUG_OBJECTS`, `CONFIG_DEBUG_LIST`,
  `CONFIG_DEBUG_SPINLOCK` and `CONFIG_DEBUG_MUTEXES`, runs the import,
  validation and workload lifecycles against it, and fails on any guest console
  report. It reports none across thirty lifecycles at 1, 2 and 4 vCPUs plus the
  stdin, process-churn and shared-directory cases. The lane differs from the
  release configuration in exactly one way, printed when it runs: the
  diagnostic Kconfig fragment is merged.

  The lane's stdin payload is 256 KiB rather than the 3 MB the release lane
  uses. A kernel that validates every lock and tracked object makes the guest
  serial line's per-character path superlinear once a payload exceeds the tty
  buffer: 256 KiB takes 1.9 s on the release kernel and 2.3 s on the diagnostic
  one, while 1 MB takes 2.2 s on the release kernel and does not complete in
  922 s on the diagnostic one. The large-payload stdin contract stays covered
  at 3 MB by `make rust-release-e2e`.
- [x] **Vector driver locking.** `vector_poll()` takes a queue's `head_lock`
  from NAPI, which runs in softirq context. `vector_reset_stats()` and
  `vector_get_ethtool_stats()` take the same locks in process context and so
  use the `_bh` variants, fixed by patch `0008`. `vector_poll()` is unchanged
  because softirqs are already off there, and `vector_send()` uses
  `spin_trylock()`, which is safe either way. The diagnostic lane reports zero
  lockdep complaints.
- [x] **CPU ceiling.** The ceiling is enforced at its boundary rather than
  exhaustively: a request of 64 boots and reports 64 online CPUs, and 65 is
  refused as `E_CPU_EXCEEDS_PROFILE_MAXIMUM` before launch. `make
  lifecycle-soak` covers correctness at representative counts, and accepts any
  `POCKET_SOAK_CPUS` if a particular value needs re-checking. Speedup above the
  host's core count is not characterised; the runtime reports that case as
  `scaling_qualified=false` rather than claiming it.
- [x] **Resource matrix.** Exercise 1, 2, 4, 12 and 16 vCPUs and 64 MiB,
  256 MiB and 4 GiB of guest memory through the complete workload and teardown
  lifecycle, checking accepted physical memory and the absence of warnings, RCU
  stalls, scheduler corruption, panics, dirty filesystems and post-exit
  failures. `make lifecycle-soak` runs one hundred consecutive lifecycles at a
  single vCPU count and is invoked once per count; each memory lane reports its
  exact requested byte count from inside the workload.
- [x] **Multiprocess scaling.** `make smp-scaling` records host CPU, kernel,
  scheduler, workload and raw timings. It measures 1678296064 ns at one vCPU
  against 435147776 ns at four on an idle host — a 3.856x speedup — and 3.484x
  on a loaded one. The probe reports raw timings, so the figure is a
  measurement rather than a constant.

### Runtime behaviour

- [x] **Image configuration semantics.** Entrypoint, Cmd, Env, User,
  WorkingDir and StopSignal defaults and explicit overrides, numeric and named
  users, stdin, stdout, stderr, exit status, normal and real-time signals, and
  descendant teardown are permanent end-to-end cases. A workload is PID 1 of
  its own namespace and therefore discards a default-disposition signal it
  sends to itself, as Docker does.
- [x] **Host directory sharing.** `make rust-release-e2e` reads a file the host
  wrote, writes one back and finds it on the host, reads it again in a later
  run, has a `:ro` share report its own refusal from inside the guest with no
  file created, and refuses a second run against a directory a live run holds,
  naming the directory and releasing it when the holder exits. The claim is an
  exclusive lock on the directory itself rather than a marker file inside the
  share, because a marker is part of what the workload sees. Taking the claim
  needs no write permission, so a read-only share is claimed like any other.
  Two collisions are refused before the run rather than discovered afterwards:
  a destination that collides with a path the runtime mounts or generates, and
  a destination the image made an absolute symlink, since `mount` follows
  symlinks in its target. Long-lived and multi-gigabyte hostfs workloads are
  not exercised.
- [x] **Unprivileged networking.** `make rust-release-e2e` asserts the address,
  default route and resolver come from the profile's sealed `slirp-bess-v1`
  contract, fetches a page over real DNS and TCP, checks that `--network none`
  leaves neither, and requires no helper process to outlive its run. The
  transport is UML's vector driver over bess, an `AF_UNIX` socket rather than a
  device, so no TUN, `CAP_NET_ADMIN` or host configuration is involved.
  Inbound port forwarding is not implemented and `--publish` is refused.
  Throughput is bounded by a single-threaded userspace stack and is not
  characterised.
- [x] **Container engine in the guest.** `make container-engine` starts
  `dockerd` in a guest and requires it to report itself, use overlay2 and
  cgroup v2, pull an image over the guest's own network, and run two containers
  to completion. `make rust-release-e2e` asserts the prerequisites separately
  and without a daemon: the default capability allowlist, that `--privileged`
  exceeds it, a writable `cgroup2` at `/sys/fs/cgroup`, and that a workload
  leaving its own mounts behind still tears down cleanly. Rootless engines,
  `--userns-remap` and long-running daemon workloads are not exercised.
- [x] **Daemonless listing.** `pocket ps` reports the runs in a runtime root
  whose owner still holds its directory lock, which is the reclamation sweep's
  liveness test read in reverse, so the listing cannot disagree with reality.
  `attach`, `exec` and `run --detach` are refused with
  `E_FEATURE_UNSUPPORTED` rather than left to read as unknown arguments.
  Detached runs, reattachable stdio and a second process in a live guest are
  unimplemented; the last needs a control message the protocol does not have.
- [ ] **Failure and cleanup matrix.** Verify COW isolation, read-only
  base-image integrity, concurrent launches, runtime-directory cleanup, guard
  cleanup after normal exit, signals, protocol failure and forced host-side
  interruption. All but injected protocol failure are permanent end-to-end
  cases; a SIGKILLed run is reclaimed by the next operation rather than leaking
  its directory. Injected protocol failure is outstanding.

### Image pipeline

- [x] **Profile sealing and validation.** Seal a fresh profile, validate it
  independently in the dedicated validator UML, and retain the transcript and
  evidence bound to the exact profile revision. Each published generation
  carries a mode-0400 `validation-evidence.cbor` and `build-record.json`.
- [x] **End-to-end suite.** `make rust-release-e2e` runs Ubuntu 24.04 and
  26.04 OCI inputs through import, immutable generation publication and
  workload execution, reporting `POCKET_RUST_RELEASE_E2E_OK`.
- [x] **Distribution independence.** `make distro-matrix` pulls and runs
  Debian 13, Alpine 3.22, Arch, Fedora and BusyBox, and runs a scratch image
  with no shell, no libc and no `/etc` through its own image `Cmd`. Debian is
  deliberately included because its manifest inlines a copy of the config blob
  in the descriptor's optional `data` field, which the layout verifier must
  check rather than refuse.
- [x] **Input transports.** Import the same pinned OCI fixture through
  canonical OCI layout, single-image OCI archive and single-image Docker
  archive, and verify the normalization boundary and cache identity. The OCI
  archive normalizes to the identical generation and reuses it; the Docker save
  archive is a distinct authenticated input that builds and runs on its own.
- [ ] **Builder capacity and derivation identity.** Verify builder byte and
  inode capacity retry policy at both boundaries, absence of partial generation
  publication, deterministic derivation identity, and independent ext4
  clean-state, UUID, size, manifest and account validation. Two conversions of
  one image produce byte-identical filesystem manifests, account databases and
  image configs. The generation ID remains per-build, because the guest clock
  leaves every created inode's `ctime` and `crtime` — which no syscall can set
  — and the journal's committed records in the raw image.

### Build, packaging and distribution

- [x] **Static checks.** `make test` runs the Rust tests, Clippy with warnings
  denied, Rust formatting, shell syntax checks and ShellCheck. The
  Linux-source pipeline and packaging tests are separate targets because both
  rebuild or repackage, and neither belongs in a check meant to be fast.
  Running them from a clean checkout in continuous integration is outstanding.
- [x] **Archive reproduction.** `make reproduce-release` builds everything a
  second time in a root that shares no download, Go module cache, kernel object
  tree or intermediate output, then requires the profile revision, the whole
  sealed bundle tree, the host CLI and the release archive to match. The two
  roots produce profile revision
  `d104d2f5e3672603489fa16364be38d1463c5ec8728f940774442cf5e8d43936`, a
  byte-identical bundle tree, an identical host CLI and an identical archive.

  The archive's own digest is deliberately not quoted here: this file is one of
  the archive's payloads, so recording that digest would change it. The lane
  prints `release_archive_sha256=` when it runs, and that is the number to
  record against a candidate. The profile revision above is stable under
  documentation changes, because the sealed bundle holds only the kernel, tools
  and initramfses.
- [x] **Usable after install.** `make install PREFIX=<dir>` publishes the
  versioned launcher, points `<prefix>/bin/pocket` at it, creates the parents
  of the store and runtime root it chose, and writes
  `$XDG_CONFIG_HOME/pocket/config.toml` naming all three, so
  `pocket run IMAGE -- ...` works with no path flags. An existing config is
  never overwritten; `--no-config` and `--no-default-link` decline each half,
  and a flag that only configures the config file is refused rather than
  ignored alongside `--no-config`. `make package` writes one relocatable
  archive carrying the installer and its single import, so a machine with no
  toolchain and no checkout performs the same digest-checked install.
  `scripts/test-release-packaging.sh` covers all of it.
- [ ] **Clean-host installation.** Install and verify the archive as a fresh
  non-root account under a normal home directory, and repeat on every declared
  host distribution and kernel. Two host-layout obstacles are removed and
  unit-tested: a `--store` behind a symlinked ancestor is resolved once rather
  than refused, which rpm-ostree systems need because `/home` is a symlink
  there; and a store on NFS, 9p or FUSE falls back to a checked rename instead
  of failing on the `EINVAL` those filesystems answer to `RENAME_NOREPLACE`, at
  the stated cost that the store's locks rather than the kernel enforce
  non-replacement. Neither is exercised on a real NFS or rpm-ostree host, which
  is what this gate wants.
- [ ] **Install lifecycle.** Test idempotent reinstall, coexistence of two
  revisions, selection of an older versioned launcher or profile, corrupted
  archive rejection, corrupted installed-tree rejection, symlink and
  special-member rejection, and no-replace behaviour under concurrent install
  attempts. `scripts/test-release-packaging.sh` covers idempotent reinstall,
  two coexisting revisions, corrupted archive and installed-tree rejection,
  symlink rejection, launcher recreation, and four installers racing on one
  absent prefix, where exactly one publishes and the rest verify what won. It
  also takes the installer out of the archive and installs with it, with no
  repository on the module path. Installing as a separate account and selecting
  an older launcher are outstanding; selection repoints `<prefix>/bin/pocket`,
  which the test exercises for creation but not for rollback.
- [ ] **SBOM validation.** Validate the SPDX JSON against an independent
  SPDX 2.3 schema or tool. A separate license review and binary-composition
  SBOM are required if release policy asks for either; this repository's
  generated document is source-input scoped.
- [ ] **Signing policy.** Define artifact signing, signer identity, key
  custody, transparency or publication log, checksum distribution, revocation
  and compromised-key response. The packager does not sign output.
- [ ] **Upgrade and removal policy.** Document upgrade and removal policy and
  recovery from an interrupted installation. The versioned layout is
  rollback-friendly and `<prefix>/bin/pocket` is the mutable activation
  pointer, but no automated remover is provided and rollback is a manual
  repointing rather than a command.
- [ ] **Licensing and distribution review.** Review both project licenses, all
  bundled third-party notices and source obligations, export controls, and
  distribution policy with the intended publisher.

## Release evidence record

Retain, for each candidate:

- Git commit and clean-worktree status.
- Complete `config/sources.lock.toml` and Cargo lock digests.
- Profile ID, full profile revision, maturity and `profile.json` digest.
- Kernel, kernel config, initramfs, guard, OCI tooling, filesystem tooling and
  `pocket` CLI digests.
- Package filename, byte size, SHA-256, canonical manifest and SPDX digest.
- Build host identity, compiler and linker versions, CPU architecture, host
  kernel, page size, and the relevant environment allowlist.
- Commands, logs, exit statuses and start/end timestamps for every gate.
- Independent archive reproduction and installed-package verification results.

Until every gate is closed, documentation and generated metadata must continue
to call the result **experimental**.
