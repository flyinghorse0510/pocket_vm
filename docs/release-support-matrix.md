# Experimental support matrix and release checklist

The only packaging target described here is the current mainline Linux 7.2
UML profile for x86_64 hosts and linux/amd64 OCI images. The package and
installer scripts preserve the profile's own maturity field. They do not
promote an experimental profile to release status. The `CONFIG_SMP=y`
scheduler/RCU lifecycle panic that previously blocked this profile is fixed by
Linux patches `0003`-`0005`; the profile is still experimental because the
portability, byte-reproducibility, distribution, and signing gates below
remain open, and packaging success cannot override any of them.

## Declared support boundary

| Dimension | Packaged boundary | Current status |
|---|---|---|
| Host kernel/userspace | x86_64 Linux 5.9 or newer, able to execute the sealed UML and host binaries | Experimental; qualified-host range not frozen. The floor is UML's mandatory `seccomp` mode, whose stub requires `close_range` and fails closed without it; the shipped artifacts are static and impose no userspace version. Measured only on Ubuntu 26.04.1 / 7.0.0-30 |
| Guest architecture | x86_64 UML (EM_X86_64 host executables) | Implemented profile only |
| OCI platform | linux/amd64, subject to the profile's accepted variants | Experimental |
| CPU count | SMP range is 1 through the sealed profile's effective maximum (currently 16) | Qualified on this host by `make lifecycle-soak`: 100 consecutive fresh full-lifecycle launches at each of 1, 2, 4, 12, and 16 vCPUs, plus five eight-way concurrent waves, with no failure and no leaked runtime directory; `make smp-scaling` measured between 3.48x and 3.86x for four separate guest processes at four vCPUs across runs, varying with host load |
| Guest memory | Profile minimum through effective maximum, aligned to 4096 bytes | Exact accepted physical memory observed at 64 MiB, 256 MiB, and 4 GiB through the full workload lifecycle; installed-package matrix remains a gate |
| Networking | Outbound NAT by default over an unprivileged userspace stack; `--network none` opts out | Implemented; inbound port forwarding is not |
| Interactive terminal | `-t` allocates a guest PTY, holds the host terminal raw, and streams both directions with window-size forwarding | Implemented; `make terminal-session` asserts `isatty`, the startup and resized window sizes, a resolvable `ttyname`, `TERM`, an interrupt reaching the guest's line discipline, the workload's exit status, and the refusal when either descriptor is not a terminal |
| Kept runs | A run is retained when it exits under a name, listed by `ps -a`, removed by `rm`; `--rm` opts out; `commit` publishes a kept run as a new image | Implemented; the retained overlay roots its generation against `cache gc`. A committed image carries a commit record instead of the source's build evidence, which described a different filesystem, and its account database is derived from the merged filesystem so accounts a run created resolve by name |
| Image filesystem size | Sized from contents with an 8 GiB floor; `image adjust` republishes at another size in either direction | Implemented; `make image-adjust` grows and shrinks one image, boots each result, and asserts the source is unmodified |
| Extra serial lines | `--consoles N` (max 8) adds guest `/dev/ttyS4` upwards, each published as a host pseudo-terminal with a login shell already on it | Implemented; `make terminal-session` attaches to a line with a workload that never touches it, asserts the waiting shell has the workload's identity, that the second line is independently usable, and that the run still exits cleanly |
| Host directory sharing | One directory per run through hostfs, claimed by an exclusive lock on the directory | Implemented; no coherence with host-side changes while a run holds it |
| Guest capabilities | Fixed 12-capability allowlist; `--privileged` grants the guest kernel's full set | Implemented; grants nothing on the host |
| Managed path lengths | Store and profile up to 3840 bytes; runtime root capped at 66, derived from the kernel's 108-byte `sockaddr_un` | Hard kernel limit, not a policy choice |
| Trust model | Trusted guest userspace supplied by the user | Intentional current boundary |
| Registry acquisition | Anonymous `docker` transport, sealed CA/Skopeo policy. A bare name expands the way a registry client would; other transports are refused | Experimental |
| Local image input | Canonical OCI layout plus constrained single-image OCI/Docker archives | Experimental |
| Installation | User-owned prefix below passwd home; version-exact side-by-side releases | Foundation implemented; clean-host qualification pending |
| Host libc/runtime | Not yet declared portable | Release blocker; host CLI linkage and minimum ABI need qualification |
| arm64 UML | Not in this package/profile | Separate, recent out-of-tree port whose exact seed is Linux 7.2-rc4 plus 54 commits; native execution is feasible, but seed reproduction and a separately identified reviewed transplant onto the selected maintained release are both required—no implied mainline support |
| Security isolation | Not a hostile-workload sandbox | Out of scope for this trusted-input profile |

## Mandatory release gates

Every item below must have retained, revision-bound evidence before changing
the profile/package maturity or publishing a release. A packaging test alone
does not satisfy any UML execution gate.

- [x] Complete the Phase 0-x86-SMP corrective gate. The defect was isolated to
  `arch/um/drivers/chan_kern.c` draining its deferred channel-IRQ list from the
  SIGIO signal handler, where the generic `free_irq()` sleeps on a
  `CONFIG_SMP=y` kernel. Patches `0003`-`0005` move that drain into process
  context, and the series is bisectable: every intermediate state builds.
  Reproduce the evidence rather than trusting this paragraph:
  `make lifecycle-soak` ran 100 consecutive fresh full lifecycles at each of
  1, 2, 4, 12, and 16 vCPUs plus five eight-way concurrent waves with no
  failure and no leaked runtime directory, and `make rust-release-e2e` passes
  for Ubuntu 24.04 and 26.04. `make diagnostic-lifecycle` rebuilds the same
  patched source with `CONFIG_DEBUG_ATOMIC_SLEEP`, `CONFIG_PROVE_LOCKING`,
  `CONFIG_PROVE_RCU`, `CONFIG_DEBUG_OBJECTS`, `CONFIG_DEBUG_LIST`,
  `CONFIG_DEBUG_SPINLOCK`, and `CONFIG_DEBUG_MUTEXES`, runs the import,
  validation, and workload lifecycles against it, and fails on any guest
  console report; it reported none. That lane differs from the release
  configuration in exactly two ways, both printed when it runs and both caused
  by the kernel being a debug build: the diagnostic Kconfig fragment is merged,
  and the guest's exact accepted-physical-memory assertion is relaxed to a
  lower bound because a larger kernel image widens UML's own exec-shield gap
  adjustment.

  That result only became meaningful in this revision. `--console-log` set the
  guest loglevel but never passed its path to the runtime, so it wrote no file,
  and the scan called `grep` on a path that did not exist -- which exits 2 and
  reads as "found nothing" to the surrounding `if`. Every earlier console scan
  therefore passed having scanned nothing. Both halves are fixed: the runtime
  writes the transcript on success and on failure, and the scan now fails
  closed on a transcript that is missing, or that carries no kernel banner.
  `assert_clean_uml_log` is hardened the same way. With both fixed, the lane
  retains a non-empty transcript for every case, each carrying the kernel
  banner, and reports no validator complaint across thirty lifecycles at 1, 2
  and 4 vCPUs plus the stdin, process-churn and shared-directory cases. The
  last of those is there because hostfs is the newest guest-kernel surface
  this runtime uses and the one a debug kernel has most to say about: it reads
  a host file, writes 64 KiB back through the page cache, and then checks that
  a read-only share refuses a write, with both consoles scanned.

  That lane's stdin payload is 256 KiB rather than 1 MB, and the size is
  measured rather than guessed. This kernel validates every lock and tracked
  object, and the guest serial line is a per-character path, so cost per byte
  explodes once a payload exceeds the tty buffer and flow control starts
  cycling it. On the same host, same host binary and same guest init: 256 KiB
  took 1.9 s on the release kernel and 2.3 s on the diagnostic one; 1 MB took
  2.2 s on the release kernel and did not finish in 922 s on the diagnostic
  one; 3 MB took 3.1 s on the release kernel. The release kernel is linear,
  the debug kernel is not, and the large-payload stdin contract stays covered
  at 3 MB by `make rust-release-e2e`. Long-duration soak testing is still
  outstanding.
- [x] Rebuild Linux 7.2 from the authenticated tarball and exact patch series
  in a clean source tree; match both the Git-tree identity and canonical
  SHA-256 source manifest before and after the build. `make kernel` performs
  this on every invocation, and `make audit-linux-source` plus
  `make test-linux-source-pipeline` pass against the published tree.
- [ ] Build every Rust host/guest artifact with the pinned Rust toolchain,
  Cargo.lock, locked/offline dependency availability, and recorded target
  configuration. Record whether each host artifact is static and its minimum
  required kernel/libc ABI. `make release-artifacts` pins the toolchain, the
  lock file, and the target, and `scripts/verify-artifacts.sh` now enforces the
  locked kernel and probe-initramfs digests; the minimum kernel/libc ABI of
  each host artifact is still undeclared.
- [x] Rebuild pinned e2fsprogs and Skopeo inputs from their authenticated
  sources in the documented environment and match every artifact digest in
  the profile. A completely fresh build root, including a new Go module cache,
  reproduced both byte-for-byte.
- [x] Seal a fresh profile, independently validate it in the dedicated
  validator UML, and retain the validator transcript/evidence bound to the
  exact profile revision. Each published generation carries a mode-0400
  `validation-evidence.cbor` and `build-record.json`.
- [x] Run the Rust-driven end-to-end suite with Ubuntu 24.04 and Ubuntu 26.04
  OCI inputs through import, immutable generation publication, and workload
  execution. `make rust-release-e2e` reports `POCKET_RUST_RELEASE_E2E_OK`.
- [x] Exercise image Entrypoint/Cmd/Env/User/WorkingDir/StopSignal defaults,
  explicit overrides, numeric and named users, stdin/stdout/stderr, exit
  status, normal and real-time signals, and descendant teardown. All of these
  are permanent end-to-end cases, including that a workload is PID 1 of its own
  namespace and therefore discards a default-disposition signal it sends to
  itself, exactly as Docker does.
- [x] Exercise 1, 2, 4, 12, and 16 vCPUs (subject to host capacity), plus
  64 MiB, 256 MiB, and 4 GiB guest memory, through the complete workload and
  teardown lifecycle while checking accepted physical memory and absence of
  warnings, RCU stalls, scheduler corruption, panics, dirty filesystems, or
  post-exit failures. `make lifecycle-soak` runs one hundred consecutive fresh
  lifecycles at a single vCPU count, and is invoked once per count; five
  hundred launches across 1, 2, 4, 12 and 16 vCPUs --
  plus five eight-way concurrent waves, with no failure and no leaked runtime
  directory; each memory lane reported its exact requested byte count from
  inside the workload.
- [x] Re-run the controlled multiprocess scaling probe and record host CPU,
  kernel, scheduler, workload, raw timings, and speedup. `make smp-scaling`
  measured 1678296064 ns at one vCPU against 435147776 ns at four on an idle
  host, a 3.856x speedup, and 3.484x on a loaded one. The probe reports its raw
  timings, so the number is a measurement rather than a constant.
- [ ] Verify COW isolation, read-only base-image integrity, concurrent
  launches, runtime-directory cleanup, guard cleanup after normal exit,
  signals, protocol failure, and forced host-side interruption. COW isolation,
  base integrity, concurrent launches, cleanup after normal exit and signals
  are permanent end-to-end cases, and a SIGKILLed run is now reclaimed by the
  next operation rather than leaking its directory. Injected protocol failure
  remains outstanding.
- [x] Verify that a shared host directory is readable and writable from the
  guest, survives the run, honours `:ro`, and is used by one run at a time.
  `make rust-release-e2e` reads a file the host wrote, writes one back and
  finds it on the host, reads that same file again in a later run, has a `:ro`
  share report its own refusal from inside the guest with no file created, and
  starts a second run against a directory a live run already holds: it is
  refused, names the directory, and the directory is claimable again once the
  holder exits. The claim is an exclusive lock on the directory itself rather
  than a marker file inside the share: a marker is part of what the workload
  sees, and deleting it let a third run claim a directory a live run still
  held -- reproduced against the marker implementation and refuted against
  this one. Taking the claim needs no write permission, so a read-only share
  is claimed like any other; that case is a unit test rather than a lane. Two collisions are
  refused rather than discovered afterwards, both unit-tested on the host and
  on the guest contract: a destination that collides with a path the runtime
  mounts or generates -- a share at `/etc` had the generated `hostname`,
  `hosts` and `resolv.conf` created inside the caller's own directory and left
  there -- and a destination the image made an absolute symlink, since `mount`
  follows symlinks in its target and would otherwise resolve it against the
  initramfs. Long-lived and multi-gigabyte hostfs workloads are not yet
  exercised.
- [x] Verify that the guest reaches the network by default without any host
  privilege, and that opting out removes it. `make rust-release-e2e` asserts
  the address, default route and resolver come from the profile's sealed
  `slirp-bess-v1` contract, fetches a page over real DNS and TCP, checks
  `--network none` leaves neither, and requires no helper process to outlive
  its run. The transport is UML's vector driver over bess, an `AF_UNIX` socket
  rather than a device, so no TUN, `CAP_NET_ADMIN` or host configuration is
  involved. Inbound port forwarding is not implemented and `--publish` is
  refused; throughput is bounded by a single-threaded userspace stack and is
  not characterised.
- [x] Verify that a container engine runs inside the guest.
  `make container-engine` starts `dockerd` in a guest and requires it to
  report itself, use overlay2 and cgroup v2, pull an image over the guest's
  own network, and run two containers to completion. `make rust-release-e2e`
  asserts the prerequisites separately and without a daemon: the default
  capability allowlist, that `--privileged` exceeds it, a writable `cgroup2`
  at `/sys/fs/cgroup`, and that a workload leaving its own mounts behind still
  tears down cleanly. That last case was a real defect -- the runtime unmounted
  only what it created, so an engine's overlay and cgroup mounts left the image
  root busy and the run was reported as an unclean filesystem. Rootless
  engines, `--userns-remap`, and long-running daemon workloads are not
  exercised.

  Enabling the vector driver exposed a second upstream UML defect, which the
  diagnostic lane caught on the first run and which patch `0008` fixes.
  `vector_poll()` takes a queue's `head_lock` from NAPI, which runs in softirq
  context, while `vector_reset_stats()` (reached through `ndo_open`) and
  `vector_get_ethtool_stats()` took the same locks in process context with
  softirqs enabled. lockdep called it: `inconsistent {SOFTIRQ-ON-W} ->
  {IN-SOFTIRQ-W} usage ... *** DEADLOCK ***`, on every boot with a network
  device, 34 failures across the lane. Those two callers now use the `_bh`
  variants; `vector_poll()` is unchanged because softirqs are already off
  there, and `vector_send()` uses `spin_trylock()`, which is safe either way.
  The same lane reports zero after the fix.
- [x] List running operations without a daemon. `pocket ps` reports the runs
  in a runtime root whose owner still holds its directory lock, which is the
  reclamation sweep's own liveness test read in reverse, so the listing cannot
  disagree with reality and a signal-killed run leaves it immediately.
  `attach`, `exec` and `run --detach` are named and refused with
  `E_FEATURE_UNSUPPORTED` rather than left to read as unknown arguments.
  Detached runs, reattachable stdio, and a second process in a live guest all
  remain unimplemented; the last needs a control message the protocol does not
  have.
- [ ] Verify builder byte and inode capacity retry policy at both boundaries,
  no partial generation publication, deterministic derivation identity, and
  independent ext4 clean-state/UUID/size/manifest/account validation. The
  authenticated half is now measured: two conversions of one image produce
  byte-identical filesystem manifests, account databases and image configs.
  The generation ID is still per-build, because the guest clock keeps running
  and leaves every created inode's `ctime`/`crtime` -- which no syscall can
  set -- and the journal's committed records in the raw image.
- [x] Show that nothing in the runtime is specific to the Ubuntu fixtures.
  `make distro-matrix` pulls and runs Debian 13, Alpine 3.22, Arch, Fedora and
  BusyBox, and runs a scratch image that has no shell, no libc and no `/etc`
  through its own image `Cmd`. Debian is deliberately included: its manifest
  inlines a copy of the config blob in the descriptor's optional `data` field,
  which the layout verifier must check rather than refuse.
- [x] Import the same pinned OCI fixture through canonical OCI layout,
  single-image OCI archive, and single-image Docker archive; verify the
  documented normalization boundary and cache identity. The OCI archive
  normalizes to the identical generation and reuses it; the Docker save archive
  is a distinct authenticated input that builds and runs on its own.
- [x] Run all Rust tests, Clippy with warnings denied, Rust formatting, shell
  syntax checks, ShellCheck, Linux-source pipeline tests, and packaging tests.
  All pass; ShellCheck reports one `SC2001` style suggestion and no warning or
  error. The first five are one committed target, `make test`. The
  Linux-source pipeline and packaging tests are separate targets, because both
  rebuild or repackage and neither belongs in a check meant to be fast. Running them from a genuinely clean checkout in
  continuous integration is still outstanding.
- [x] Produce the release archive twice in independent clean build roots and
  compare the archive bytes. `make reproduce-release` does exactly this, so the
  claim is a committed target rather than a recorded anecdote: it builds
  everything a second time in a root that shares no download, no Go module
  cache, no kernel object tree and no intermediate output, then requires the
  profile revision, the whole sealed bundle tree, the host CLI, and the release
  archive to match. The two roots produced profile revision
  `d104d2f5e3672603489fa16364be38d1463c5ec8728f940774442cf5e8d43936`, a
  byte-identical bundle tree, an identical host CLI, and an identical release
  archive.

  The archive's own digest is deliberately not quoted here. This file is one
  of the archive's payloads, so writing that digest into it would change it;
  the lane prints `release_archive_sha256=` when it runs, and that is the
  number to record against a candidate. The profile revision above is stable
  under documentation changes, because the sealed bundle holds only the
  kernel, tools and initramfses.
- [ ] Install and verify the archive as a fresh non-root account under a
  normal home directory; repeat on every declared host distribution/kernel.
  Two host-layout obstacles that made this impossible on whole families of
  hosts are now removed and covered by unit tests: a `--store` behind a
  symlinked ancestor is resolved once rather than refused, which is what
  rpm-ostree systems (Fedora Silverblue/Kinoite/CoreOS, Bluefin, Bazzite) need
  because `/home` is a symlink there; and a store on NFS, 9p or FUSE falls back
  to a checked rename instead of dying on the `EINVAL` those filesystems answer
  to `RENAME_NOREPLACE`, at the stated cost that the store's locks rather than
  the kernel then enforce non-replacement. Neither is yet exercised on a real
  NFS or rpm-ostree host, which is what this gate still wants.
- [ ] Test idempotent reinstall, coexistence of two revisions, selection of
  an older versioned launcher/profile, corrupted archive rejection,
  corrupted installed-tree rejection, symlink/special-member rejection, and
  no-replace behavior under concurrent install/package attempts.
  `scripts/test-release-packaging.sh` now covers idempotent reinstall, two
  coexisting revisions, corrupted archive and installed-tree rejection,
  symlink rejection, launcher recreation, and four installers racing on one
  absent prefix: exactly one publishes and the rest verify what won. It also
  takes the installer out of the archive and installs with it, with no
  repository on the module path, which is the situation on a machine that
  received only the tarball. Installing as a separate account and selecting an
  older launcher remain outstanding; selection is now repointing
  `<prefix>/bin/pocket`, which the same test exercises for creation but not
  yet for rollback.
- [x] Leave the machine usable after an install without any further setup.
  `make install PREFIX=<dir>` publishes the versioned launcher, points
  `<prefix>/bin/pocket` at it, creates the parents of the store and runtime
  root it chose, and writes `$XDG_CONFIG_HOME/pocket/config.toml` naming all
  three, so `pocket run IMAGE -- ...` works with no path flags. An existing
  config is never overwritten, and `--no-config` / `--no-default-link` decline
  each half; a flag that only configures the config file is refused rather
  than ignored when `--no-config` is given. `make package` writes one
  relocatable archive that carries the installer and its one import, so a
  machine with no toolchain and no checkout performs the same digest-checked
  install. All of this is covered by
  `scripts/test-release-packaging.sh`.
- [ ] Validate the SPDX JSON against an independent SPDX 2.3 schema/tool.
  Perform a separate license review and binary-composition SBOM if release
  policy requires either; this repository's generated document is explicitly
  source-input scoped.
- [ ] Define artifact signing, signer identity, key custody, transparency or
  publication log, checksum distribution, revocation, and compromised-key
  response. The current packager does not sign output.
- [ ] Document upgrade/removal policy and recovery from an interrupted
  installation. The versioned layout is rollback-friendly and
  `<prefix>/bin/pocket` is now the mutable activation pointer -- the one
  deliberately replaceable path the installer publishes -- but no automated
  remover is provided, and rollback is still a manual repointing rather than a
  command.
- [ ] Review both project licenses, all bundled third-party notices/source
  obligations, export controls, and distribution policy with the intended
  publisher.

## Release evidence record

For each candidate, retain at least:

- Git commit and clean-worktree status.
- Complete config/sources.lock.toml and Cargo lock digests.
- Profile ID, full profile revision, maturity, and profile.json digest.
- Kernel, kernel config, initramfs, guard, OCI tooling, filesystem tooling,
  and pocket CLI digests.
- Package filename, byte size, SHA-256, canonical manifest, and SPDX digest.
- Build host/container identity, compiler/linker versions, CPU architecture,
  host kernel, page size, and relevant environment allowlist.
- Commands, logs, exit statuses, and start/end timestamps for every gate.
- Independent archive reproduction and installed-package verification
  results.

Until the checklist is complete, documentation and generated metadata must
continue to call the result **experimental**.
