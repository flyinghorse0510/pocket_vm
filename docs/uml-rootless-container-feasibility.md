# Privilege-free trusted containers with native User-Mode Linux

Feasibility decision, architecture, and implementation plan  
Revised: 2026-08-28  
Targets: native linux/amd64 on x86_64; native linux/arm64 on arm64

## Executive decision

Proceed, with separate architecture qualification tracks. A daemonless runtime can run trusted Linux programs from existing Docker or OCI images under a User-Mode Linux kernel while requiring no host root access, capabilities, setuid helper, privileged daemon, KVM, TUN/TAP, FUSE, host namespace creation, host mount, or writable cgroup.

It would be incorrect to say that an arm64 UML cannot be implemented. As of 2026-08-28, upstream Linux does not contain an arm64 UML subarchitecture, but a recent out-of-tree `ARCH=um SUBARCH=arm64` proof-of-concept boots unmodified aarch64 Alpine and Debian userspace and provides a cooperative seccomp mode. Guest aarch64 instructions execute directly as arm64 EL0 instructions on the arm64 host; there is no QEMU or instruction translation in that path.

The resulting native path is exact, not approximate: an arm64 Linux host executes an aarch64 UML host binary built with `ARCH=um SUBARCH=arm64`; that UML kernel starts a `linux/arm64` root filesystem and executes supported ELF64 `EM_AARCH64` programs unchanged. The host, UML subarchitecture, selected OCI manifest, ELF machine, dynamic loader, libraries, and CPU-feature policy must all agree. Cross-building that UML binary on x86_64 is allowed, but running or qualifying it on x86_64 is not; Pocket deliberately contains no foreign-instruction emulator.

That proof-of-concept is evidence of technical feasibility, not yet a production dependency. The branch README is stale: it still describes a 38-patch uniprocessor port, while the exact audited head `8897487c52233cd00cf2850008ca068892f1ae91` is a 54-patch series over `1590cf0329716306e948a8fc29f1d3ee87d3989f` and already contains initial arm64 SMP support. Commit `03c57e1808f9fc3df91a770e42ce0ff7ac466269` selects `UML_SUBARCH_SUPPORTS_SMP`, supplies the arm64 UML queued-spinlock override, and adds a `CONFIG_SMP=y`, `CONFIG_NR_CPUS=16` fragment. Its commit record reports a four-CPU Raspberry Pi 5 boot, `nproc=4`, dockerd, and a parallel-compile improvement from 3000 ms at one CPU to 1483 ms at three. That is credible proof that native arm64 UML SMP exists, but it is evidence from one recent out-of-tree branch and one reported 16 KiB host-page platform—not yet Pocket's production qualification. The port remains aarch64-only with no AArch32 compatibility, has declared correctness work in areas such as timekeeping and page-size coverage, and its author does not undertake ongoing maintenance or upstream shepherding. Pocket must adopt and maintain an exact reviewed fork, independently reproduce the SMP result under `seccomp=on`, and close the broader correctness and stress gates before promising multiple vCPUs.

The clarified product is not an adversarial sandbox. Every image, guest program, and guest-side tool is trusted and cooperative. That permits UML's cooperative seccomp userspace backend, which is required by the selected SMP path and is explicitly unsuitable for hostile guest code. The product must say this plainly: it provides a separate Linux kernel and container-like filesystem/process semantics, not a security boundary against the code it runs.

Existing Docker images are first-class target inputs. They cannot be attached directly as UML disks because an image is an ordered manifest, configuration, and set of compressed filesystem changesets rather than a mountable block filesystem. The completed runtime automatically selects the matching native `linux/amd64` or `linux/arm64` manifest, converts it once into a metadata-faithful ext4 base, caches it by immutable provenance and platform, and gives every run a private UML UBD copy-on-write layer. The user therefore does not hand-build a root filesystem.

That target statement must not be confused with the current implementation boundary. The checked-in acquisition, OCI verification, profile verification, builder launch, and workload launch path is presently restricted to `x86_64`/`linux/amd64`. Its implemented inputs are a fully qualified anonymous `docker://` registry pull, an already canonical local OCI-layout directory, or an exact single-image OCI/Docker tar archive normalized under a fixed private name. Docker-daemon lookup, credentials, archive selectors, and multi-image archives remain unsupported. A compatible existing image supplies the filesystem and the current CLI now applies its authenticated Entrypoint/Cmd/Env/User/WorkingDir/StopSignal defaults, including named account resolution, while one continuous generation lease protects sidecar resolution and launch. The broader Phase 4 fixture, capability, metadata-inspection, affinity, and release gates remain open. Thus “use an existing image without manually constructing its rootfs or restating ordinary process defaults” is true; “run every Docker image unchanged with all Docker behavior today” is not.

The product status is deliberately asymmetric:

| Host and selected image | UML source status | CPU status | Product status |
|---|---|---|---|
| x86_64 and linux/amd64 | maintained upstream UML plus pinned fixes | SMP code is present and qualified: the scheduler/RCU lifecycle panic was root-caused to `free_irq()` being called from UML's SIGIO handler, corrected in locked patches `0003`-`0005`, and requalified across repeated full lifecycles at 1, 2, 4, 12 and 16 vCPUs | Phase 0-x86 SMP correctness gate passed; release still gated on the portability, distribution and signing items in the support matrix |
| arm64 and linux/arm64 at one vCPU | audited external seed at `8897487c…`; project-owned reviewed fork required | current branch supports UP operation; keep it as a regression lane | experimental base-correctness track |
| arm64 and linux/arm64 with more than one vCPU | same audited seed, whose current head already contains initial SMP; project-owned fork required | reported 4-CPU boot and 3-CPU scaling on one Raspberry Pi 5; not independently qualified by Pocket | experimental Phase 0-arm64-SMP adoption/hardening track; release-blocking until it passes |
| architecture-mismatched host and image | no emulator in Pocket | unsupported | reject before conversion |

For an SMP-qualified profile, current UML parallelism is useful but limited:

| Work inside one UML instance | Parallel across host CPUs? |
|---|---|
| UML guest-kernel execution | Yes |
| User code in different guest processes | Yes |
| User threads sharing one guest process/address space | Not fully; the current single-threaded userspace stub serializes this case |
| Multiple independent UML instances | Yes |

The first milestone is therefore architecture-specific. The x86_64 profile's scheduler/RCU corruption has been root-caused and corrected at the source, and the profile is now qualified through the full nested-PID-namespace lifecycle rather than only through raw boot and scaling spikes. The arm64 profile first needs a reproducible one-CPU base-correctness lane and then an adoption, code-audit, reproduction, stress, and hardware-matrix qualification of the SMP code already in the pinned branch. Arm64 UML and initial arm64 SMP do not need to be invented from scratch, but defects uncovered in either architecture still require source fixes. The common container-runtime work may be developed against experimental profiles, while release claims remain gated per profile and no profile inherits another architecture's evidence.

## Exact product contract

### Assumptions

- The selected host/UML/image triple is native and exact at OS/architecture level: x86_64 UML with `linux/amd64`, or arm64 UML with `linux/arm64`. Because OCI `variant` is optional, an absent or explicit variant must pass a versioned profile policy; absence is recorded, not silently rewritten.
- The program needs no CPU instruction or architectural state feature absent from, hidden by, or incorrectly virtualized on the host/UML profile.
- Image bytes, image metadata, guest tools, and executed programs are trusted.
- Programs may still crash, hang, consume excessive resources, encounter corrupt downloads, or expose ordinary software bugs; lifecycle and integrity handling remain required.
- One workload process tree runs in each UML instance.
- The runtime may download and execute ordinary user-owned binaries, create sparse regular files, create Unix sockets and pipes, and make normal outbound connections when networking is requested.
- Architecture-specific UML kernels and trusted initramfses, Skopeo, umoci, e2fsprogs, and optionally slirp4netns may be shipped as pinned user-space artifacts.
- Pocket may own and maintain an arm64 UML patch series; a moving third-party branch is not an acceptable release dependency.

### Product statement

The MVP is a privilege-free UML application runtime that:

- consumes registry references, OCI layouts or archives, and Docker save archives;
- preserves Docker/OCI image filesystem semantics and a documented image-configuration subset;
- runs supported same-architecture Linux ELF binaries and scripts without rebuilding them, provided their interpreter, libraries, CPU features, kernel interfaces, filesystems and virtual devices are present;
- offers a requested UML virtual-CPU count and page-aligned guest-memory size up to independently qualified profile maxima, rejecting any requested/accepted downgrade;
- provides ephemeral root writes by default through UBD COW;
- optionally provides user-mode networking and explicit port forwards;
- reports exact program output, exit status, and terminating signal;
- requires no continuously running daemon.

It is OCI-image-compatible, not initially a fully conforming OCI Runtime Specification implementation. Accepting an image configuration does not imply support for every runtime-spec namespace, hook, cgroup, mount, device, seccomp, capability, or lifecycle operation.

"Without modification" means Pocket does not rewrite a supported workload binary or image command. It does not mean every correctly labeled image is runnable. The support check and error taxonomy distinguish: host/image mismatch; wrong ELF machine or class; unsupported `linux/386` or AArch32 binary; missing ELF or script interpreter; absent shared library; unsupported CPU instruction or architectural state; missing guest-kernel syscall/filesystem/device; malformed or incomplete image; and a program's ordinary run-time failure. A production profile accepts only its exact 64-bit native OCI OS/architecture; an absent or explicit variant is accepted only through that profile revision's versioned compatibility policy and is preserved in provenance.

### Non-goals for the MVP

- isolation from malicious or compromised guest code;
- foreign-architecture emulation, including arm64 on x86_64 or amd64 on arm64;
- 32-bit x86/linux/386 and arm/AArch32 compatibility in the first release;
- Windows containers;
- direct attachment of Docker or OCI tar files as block devices;
- a required Docker daemon, Podman store, rootless user namespace, FUSE overlay, or host bind mount;
- KVM-like hardware isolation;
- true parallel user-mode execution for threads sharing one guest process until UML gains that feature;
- hard aggregate CPU, PID, I/O, memory-overhead, or disk guarantees without an optional delegated host control;
- privileged devices, GPU, USB, KVM-in-guest, DKMS, or arbitrary kernel modules;
- checkpoint/restore or OCI layer commit in the first release.

## Meaning of no required host privileges

The baseline must work for an ordinary non-root user with zero effective, permitted, inheritable, and ambient capabilities.

It may use:

- normal process and pthread creation;
- executable mappings and executable anonymous or temporary backing accepted by the host policy;
- unprivileged seccomp filters used internally by UML's cooperative execution backend;
- regular, sparse, and memory-backed files in user-owned directories;
- Unix socketpairs, pathname Unix sockets in private directories, pipes, event descriptors, PTYs, signals, and timers;
- outbound TCP and UDP sockets and unprivileged listening ports through slirp4netns when requested;
- sched_setaffinity for its own process tree when the user requests an allowed CPU set.

It must not require:

- UID 0, sudo, ambient or file capabilities;
- a setuid or setgid helper;
- a privileged system daemon or membership in a root-equivalent Docker socket group;
- /dev/kvm, /dev/net/tun, /dev/fuse, loop devices, or host block devices;
- host user, mount, PID, network, or other namespace creation;
- any host mount operation;
- sysctl, firewall, route, interface, LSM-policy, or cgroup-ownership changes;
- a writable or delegated cgroup subtree.

Optional deployment features may use a delegated cgroup, filesystem quota, or an already-accessible Docker daemon, but the runtime must detect and label them as optional rather than silently making them prerequisites.

## UML execution, architecture and SMP model

UML compiles the Linux kernel into a same-architecture host executable. Guest user instructions run natively on the host CPU, while system calls, page faults, signals, timers, memory mappings, and virtual-device operations are mediated by UML. Its devices terminate in ordinary host resources such as disk-image files, socket FDs, and pipes.

Upstream's `arch/um/Makefile` derives `HEADER_ARCH` from `SUBARCH` and requires architecture glue such as `arch/arm64/Makefile.um` and `arch/arm64/um/`. Those arm64 files are absent from the upstream tree, so an unmodified upstream checkout cannot build or run arm64 UML. This is an upstream implementation gap, not a CPU-virtualization impossibility. The out-of-tree arm64 branch supplies that missing glue and demonstrates native arm64 execution.

Initial UML SMP entered mainline in Linux 6.19 for the supported x86 UML subarchitecture. Current generic Kconfig permits two through sixty-four compiled CPUs only when the selected subarchitecture enables `UML_SUBARCH_SUPPORTS_SMP`. Upstream x86 selects it. Upstream has no arm64 UML at all, but the exact audited out-of-tree arm64 head also selects it and ships an SMP fragment with `CONFIG_NR_CPUS=16`. On an SMP-capable build, the UML kernel process uses one host pthread for CPU 0 and creates a pthread for each secondary vCPU. The host scheduler may run them simultaneously on CPUs allowed by affinity and cgroup policy. Guest address spaces additionally execute in separate `uml-userspace` host stub processes, one per guest `mm_struct`; these are distinct from the kernel vCPU pthreads and are part of the supervised process tree.

### Required execution backend

An SMP-qualified runtime profile must launch:

~~~text
seccomp=on ncpus=N
~~~

The setting is UML's own cooperative userspace execution backend. It is not an OCI workload seccomp profile and not an outer host sandbox filter.

Current upstream x86 startup behavior is:

| UML argument | Behavior with ncpus greater than 1 |
|---|---|
| omitted or seccomp=off | UML selects ptrace userspace and aborts because SMP is unsupported there |
| seccomp=auto | UML tries the cooperative backend, but a failed probe falls back to ptrace and then aborts |
| seccomp=on | UML uses the cooperative backend or fails immediately |

The table above describes the exact audited upstream x86 startup source. The arm64 branch's later generic commit `1d555ded4df4537a30f92839f3c34a5d91c1a221` instead clamps a ptrace-backend launch to one online CPU, and `7d1b5396f151b5990acfa791ebcc9bd552b9a51a` changes its default CPU request. Pocket relies on neither behavior: it always passes `seccomp=on`, never `auto`; every SMP build also receives explicit `ncpus=N`, and any reported online count other than the validated request is `E_CPU_COUNT_MISMATCH`. A `CONFIG_SMP=n` control does not link UML's `ncpus=` parser, so Pocket validates that its request is exactly one and omits the argument rather than leaking an unknown token to the generic kernel command line. Both arm64 one-CPU and SMP paths must pass the fail-closed cooperative-backend contract independently; x86 results are not evidence for arm64 signal frames, register handling, or SMP correctness.

A successful boot is compatibility evidence that UML's own startup probe accepted the host's seccomp, signal, register, and stub mechanisms; it is not proof of complete run-time correctness. No ptrace operation may need to succeed for any Pocket profile. Current code can contain best-effort ptrace operations whose failures are ignored, so CI returns `EPERM`—not a killing policy action—for ptrace and proves boot, execution and teardown still work on both architectures.

Upstream warns that the cooperative backend allows trusted guest userspace more influence over UML memory and scheduling than an adversarial boundary could permit. That warning exactly matches this product's trust assumption. If untrusted-workload support is ever requested, it is a different product profile and architecture review, not a command-line toggle.

### Parallelism boundary

An SMP-qualified UML can execute guest-kernel work and user code from different guest processes concurrently. Threads sharing one guest process still share a single-threaded stub for their user-mode execution. The current audited arm64 branch has initial SMP and reported multi-process scaling, but Pocket must independently verify that it has the same boundary and no architecture-specific regression. Consequences:

- prefork servers, multiple workers, compilers using child processes, shell job sets, and several services can scale;
- a single CPU-bound Go, Java, Rust, C, or C++ process using only threads should not be promised multi-core speedup;
- blocking I/O and guest-kernel work may still overlap;
- running several independent one-vCPU UML instances remains a valid alternative for density, but the audited arm64 SMP branch can also place multiple vCPU pthreads from one VM on multiple host CPUs once the profile passes qualification;
- every release must benchmark both a multi-process and a same-process multithread workload so this limitation remains visible.

### System-call path

~~~text
trusted same-architecture guest program executing in a per-mm uml-userspace process
        |
        | x86_64 syscall instruction or arm64 svc #0
        v
host seccomp filter returns TRAP; the host syscall is suppressed
        |
        | host signal delivery places siginfo + mcontext on the shared
        | alternate-signal-stack area in stub_data; the SIGSYS handler
        | records their offsets and wakes a vCPU pthread through a futex
        v
UML handle_syscall() -> guest syscall table
        |
        +-- guest VFS, credentials, processes, sockets and memory
        +-- UBD/vector/other backends issue implementation host syscalls
        +-- mapping commands make the per-mm stub perform fixed host mmap
        |   or munmap; mapping FDs arrive via recvmsg/SCM_RIGHTS and close
        |   after use
        v
UML writes result/errno into the shared mcontext and wakes the stub
        |
        | rt_sigreturn
        v
guest program resumes
~~~

A guest open of /etc/app.conf resolves through the guest ext4 filesystem. The host sees reads from the UBD base or COW file, not an open of the same host pathname. A guest socket uses the guest network stack and vector NIC before packets reach slirp. The mapping is not a direct one-for-one forwarding of guest syscall arguments to the host, and host calls are made by both UML device backends and the controlled per-mm stub machinery.

The guest syscall ABI is architecture-native: x86_64 programs enter the x86_64 guest table and aarch64 programs enter the arm64 guest table. The arm64 port must preserve and restore the complete aarch64 signal context, including FP/SIMD and every enabled scalable or tagged state, and must handle pointer-authentication behavior around its exec-created stubs. The published branch contains fixes for PAC and FP/SIMD bugs discovered on real Armv9 hardware; Pocket's Phase 0 treats those as regression seeds, not as sufficient coverage of every CPU. Guest page size, HWCAP/auxv exposure, SVE/SME/PAC/MTE policy, and 4 KiB versus 16 KiB behavior are explicit artifact properties and test dimensions.

## Architecture

Image preparation and workload execution are separate flows.

~~~text
UNPRIVILEGED LINUX HOST

IMAGE INGESTION - once per immutable image generation

  docker:// registry     docker-archive     OCI layout/archive
          \                   |                    /
           +-- [import supervisor + lifetime guard] --+
                              |
                       [pinned Skopeo]
                              |
              native-platform selector
          x86_64 -> linux/amd64 (release)
          arm64  -> linux/arm64 (port track)
                      private OCI layout
                              |
                   payload ext4, read-only
                              |
            +-----------------+------------------+
            | TRUSTED NATIVE BUILDER UML        |
            | matching host/image architecture |
            | seccomp=on; one CPU              |
            |                                   |
            | UML kernel -> builder init        |
            |                  |                |
            |          umoci raw unpack         |
            |          as guest UID 0           |
            |                  |                |
            |           blank target ext4       |
            +------------------+----------------+
                               |
                     validate, sync, fsck,
                       hash, atomic publish
                               |
                     immutable base.ext4
                     image-config sidecar


PER-WORKLOAD EXECUTION

  caller
    |
    v
  pocket CLI and supervisor
    |
    +-- resolve immutable base and image configuration
    +-- create private run directory and reserve root.cow pathname
    +-- create control, stdin, stdout, stderr and optional PTY FDs
    +-- spawn one per-run lifetime guard
    |       +-- hold crash-releasable lease and lifetime FDs
    |       +-- optionally start and reap slirp4netns
    |       +-- start, kill and reap the complete UML process tree
    |
    v
  selected same-architecture UML artifact
    x86_64-smp-p4k candidate: seccomp=on, ncpus=N, mem=M
      + guest-visible expected_cpus=N, expected_memory_bytes=B
      + Phase 0-x86-SMP lifecycle gate passed with patches 0003-0005
    x86_64-up-p4k-test: seccomp=on, no ncpus token, mem=M
      + optional diagnostic one-CPU control; never an SMP fallback
    arm64-smp-p16k-experimental: seccomp=on, ncpus=N, mem=M
      + guest-visible expected_cpus=N, expected_memory_bytes=B
    arm64 CONFIG_SMP=n build: qualification-only regression lane
    |
    +-- UBD: root.cow over immutable base.ext4
    +-- serial FDs: control and standard streams
    +-- optional vector NIC to slirp
    |
    v
  trusted pocket-init PID 1, remaining rooted in initramfs
    |
    +-- mount UBD at /volume and prepare /volume/rootfs
    +-- fork a workload child in guest namespaces and chroot it
    +-- materialize proc, sys, curated dev, run and fixed /dev/shm in guest
    +-- apply image command, environment, user, cwd and rlimits
    +-- launch, signal, reap, unmount and report workload
    +-- sync and power off
    |
    v
  supported unchanged native program from the Docker or OCI image
    x86_64 host -> x86_64 UML -> linux/amd64 ELF
    arm64 host  -> arm64 UML  -> linux/arm64 ELF
~~~

## Components and repository shape

A small Rust workspace is a suitable implementation because the host supervisor and guest init need explicit ownership of processes, FDs, protocol buffers, and cleanup state. Mature external tools should handle registries, OCI layer application, ext filesystems, and user-mode networking.

~~~text
pocket_vm/
  Cargo.toml
  crates/
    pocket-core/            implemented shared error, path, CPU and memory contracts
    pocket-protocol/        implemented bounded workload and builder messages
    pocket-guard/           implemented per-operation subreaping and parent-death cleanup
    pocket-oci/             implemented amd64 source/layout/platform/config/layer verifier
    pocket-store/           content store with crash-safe generation publication; full fault matrix remains
    pocket-init/            trusted workload PID 1; production UML matrix remains
    pocket-runtime/         amd64 profile, builder, COW, protocol and launch owner
    pocket/                 bounded run/image/inspect/cache CLI; release integration remains
    pocket-builder-init/    conversion PID 1 used by the Rust HostBuilder path
  config/
    kernel/                 current x86_64 UML fragment and final-config assertions
    initramfs/              current deterministic probe/build input manifests
  guest/                    current boot, workload, builder and lifecycle probe programs
  scripts/                  current pinned build and executable integration gates
  kernel/
    profiles/                 planned installed-profile source/config records
      x86_64-smp-p4k/
        source.lock
        config.fragment
        config.assert
      arm64-smp-p16k-experimental/
        source.lock
        config.fragment
        config.assert
      arm64-up-p16k-test/
        source.lock
        config.fragment
        config.assert
      arm64-smp-p16k/
        source.lock
        config.fragment
        config.assert
        promotion.lock
    patches/
      common/
      x86_64/
      arm64/
  initramfs/                  planned release-profile output layout
    x86_64-smp-p4k/workload/
    x86_64-smp-p4k/builder/
    arm64-smp-p16k-experimental/workload/
    arm64-smp-p16k-experimental/builder/
    arm64-up-p16k-test/workload/
    arm64-up-p16k-test/builder/
    arm64-smp-p16k/workload/          # created only at release promotion
    arm64-smp-p16k/builder/           # created only at release promotion
  packaging/                  planned relocatable release bundles
    x86_64-unknown-linux-gnu/
      x86_64-smp-p4k/PROFILE_REVISION/
    aarch64-unknown-linux-gnu/
      arm64-smp-p16k-experimental/PROFILE_REVISION/
      arm64-up-p16k-test/PROFILE_REVISION/       # qualification only
      arm64-smp-p16k/PROFILE_REVISION/           # release only
  tests/
    fixtures/images/
    fixtures/rootfs/
    integration/
    lifecycle/
    fault/
    performance/
  docs/
    uml-rootless-container-feasibility.md
    support-matrix.md
~~~

This is an explicit current-to-target map, not a second naming scheme. `pocket-oci` plus `pocket-store` own the image/cache responsibilities. `pocket-runtime` owns typed profile validation, COW/FD construction and guarded launch/protocol orchestration. `pocket` owns CLI parsing/presentation plus calls into those libraries. `pocket-init` is the workload PID 1, and `pocket-builder-init` owns builder boot/config/tool/marker/protocol logic. The Rust HostBuilder has completed one real Ubuntu 24.04 conversion under the sealed x86_64 profile; that is a useful integration result, not the complete conversion, workload-run, recovery, reproducibility, or release matrix. No phase may claim completion merely because its named owner exists or because one happy-path fixture passed.

`profile_id` is a stable semantic selector such as `x86_64-smp-p4k` or `arm64-smp-p16k-experimental`. An immutable, content-addressed `profile_revision` binds the exact kernel/initramfs/helper content and contracts for that ID. Define it as SHA-256 over a schema-domain separator plus the canonical serialization of an external artifact manifest with the `profile_revision` field omitted. That manifest contains the final kernel, initramfs and helper digests, so no artifact embeds or hashes its own eventual digest. Guest binaries instead embed non-circular `kernel_build_id`, `init_build_id` and `guest_contract_id` values derived from their source/config/toolchain input manifests before final packaging. The host validates final artifact bytes before exec and maps those reported build/contract IDs to the selected revision during HELLO. HELLO deliberately does not carry a semantic `profile_id`: the same byte-identical candidate kernel/initramfs may be bound by both an experimental profile and a later release profile, while START and the disk-generation marker carry the host-selected semantic profile and revision.

A profile revision fixes: host machine and ELF ABI; UML subarchitecture; accepted OCI OS/architecture and versioned variant policy; maturity; guest page size; CPU-state/HWCAP policy; CPU and physical-memory limits; workload and builder kernels/initramfses; filesystem consumer contract; and every helper role. Its CPU record contains `smp_enabled`, a product-policy `product_max_cpus`, `compiled_nr_cpus` only for an SMP build (deliberately null in the product schema for a UP build), and a checked `effective_max_cpus`. Linux Kconfig still defines `CONFIG_NR_CPUS=1` when SMP is disabled; the null product field records that the UP artifact has no `ncpus=` parser or selectable compiled ceiling. For UP, `effective_max_cpus=1`; for SMP, it is `min(product_max_cpus, compiled_nr_cpus)`. Its memory record contains page-aligned `minimum_memory_bytes`, `default_memory_bytes`, a policy `product_max_memory_bytes`, a layout-tested `effective_max_memory_bytes` no greater than that policy maximum, and fixed `builder_memory_bytes`. Both defaults must be aligned and in their declared tested ranges; the builder value has its own exact accepted-byte boot evidence. Linux 7.2 UML can silently reduce `physmem_size` when `mem=` exceeds the host-process address-space layout. Pocket therefore carries a small revision-bound UML proc ABI exposing the final accepted `physmem_size`, rejects requests above the effective maximum before launch, and requires HELLO's accepted byte count to equal the request. This value is distinct from usable `/proc/meminfo` RAM and from host RSS. All generic CLI, probe and run checks use the effective maxima. Identical initramfs bytes may be content-addressed once, but each profile revision still binds their digest and compatible guest contract explicitly; sharing is never inferred from filenames. The installed profile index maps each ID to exactly one active revision through an atomic, checksum-verified record; old revisions remain addressable only while installed for compatible COW/generation recovery. `--profile ID@REVISION` pins one exactly, while `--profile ID` resolves its active revision. Selection occurs before image resolution. A unique configured release-grade default may be selected automatically; experimental profiles require explicit opt-in; multiple eligible defaults fail as `E_PROFILE_AMBIGUOUS`. `--cpus` and `--memory` only validate against the already selected revision and never switch profiles or kernels.

Pinned external artifacts, independently for each supported host/UML/image profile revision:

- Linux UML source, ordered reviewed patch series and resulting tree identity, toolchain, final executable and normalized config;
- Skopeo and containers/image policy/configuration;
- umoci;
- e2fsprogs tools used for mke2fs, resize2fs and e2fsck;
- slirp4netns and libslirp when networking is enabled;
- dynamic loader and libraries required by a network-capable UML binary;
- Rust compiler, host and guest targets, and dependency lock used for static guest init binaries.

Each manifest entry is role-tagged with `execution_context=host|workload-initramfs|builder-initramfs`, ELF class/data/`e_machine`, static-versus-`PT_INTERP` status, complete loader/library closure, digest, and invocation template. Host-context executables must be native to the host: the x86_64 bundle uses an x86_64 UML ELF and host helpers; the arm64 bundle uses `EM_AARCH64` equivalents. Guest initramfs executables are native to their guest ABI and are not described as host tools. In particular, builder-side umoci and every helper it invokes must either be static or have its complete loader/library closure inside that builder initramfs, and the exact invocation must pass a clean-initramfs boot test. Cross-compiling an artifact is allowed, but executing a foreign helper through an undeclared emulator is not.

Every builder, workload and validation UML invocation template fixes the
literal `noreboot` and `panic=1` tokens; they are revision-bound lifecycle
inputs, not caller-selectable conveniences. In the pinned Linux 7.2 contract,
an ordinary guest restart reaches UML's restart/self-exec path and `noreboot`
converts it into process exit. A kernel panic instead reaches the UML panic
exit notifier and nonreturning core-dump/abort path immediately; it does not
perform the delayed ordinary-restart path. `panic=1` remains a fixed,
revision-bound defense-in-depth input. Both paths must produce one boot and a
bounded guarded-process exit. Any product-level restart is a fresh launch from
the reverified profile and generation, never UML's internal self-`exec` path.

No command is assembled through a shell. Every subprocess receives an explicit argv array and sanitized environment. Secrets are passed by FD or protected file, never placed on the UML kernel command line. Every external helper—including Skopeo, mke2fs/e2fsck, builder UML, workload UML and slirp—runs beneath a single-threaded per-operation guard or an equivalently proven parent-death/reaping contract.

## Host compatibility probe

The command pocket probe --json must perform operations, not infer compatibility from kernel versions or sysctls.

| Gate | Required behavior | Failure |
|---|---|---|
| Architecture mapping | Map host `x86_64` to `linux/amd64` and host `aarch64`/arm64 to `linux/arm64`; select only a matching profile | Refuse unknown or mismatched triples |
| ELF identity | UML, loader, helpers and initramfs executables have the profile's expected ELF class, endianness and `e_machine`; host executes the pinned UML ELF | Refuse |
| Image platform | Selected OCI OS and architecture match the native profile and its absent/explicit variant passes the versioned compatibility policy | Refuse before layer conversion |
| Artifact execution | Static artifacts run or every dynamic helper executes through its bundled loader/library closure | Refuse |
| Cooperative backend | A tiny UML boots with seccomp=on and does not fall back | Refuse |
| CPU profile | Every SMP revision, including arm64, boots `ncpus=1`, `2`, and its claimed matrix values and reports exactly the requested online count; the arm64 UP regression build accepts only one | Refuse the claimed profile; never silently downgrade or accept a branch clamp |
| Ptrace independence | Boot, workload and teardown work when ptrace attempts return EPERM | Refuse if any ptrace operation must succeed |
| Stub operations | Executable/shared mappings; clone with CLONE_VM/CLONE_VFORK; close_range; socketpair/SCM_RIGHTS; alternate signal stack/SIGSYS/rt_sigreturn; TSYNC seccomp; futex; timers/signalfd; wait/SIGCHLD; and mmap protection work | Refuse |
| arm64 context | Fork/exec, signals and TLS/crypto preserve general and FP/SIMD state across the seccomp handoff; initial SVE/SME/PAC-key/BTI/MTE/GCS/CPUID/HWCAP2 masking and stub-PAC behavior are coherent | Refuse arm64 profile |
| Page size | Guest page size is declared and is never smaller than the host page size; first arm64 candidate is 16 KiB on 4/16 KiB hosts, optional 4 KiB guest only on 4 KiB hosts, and 64 KiB hosts are initially unsupported | Refuse as `E_PAGE_SIZE_PAIR_UNSUPPORTED` |
| Executable backing | Executable memfd with MFD_EXEC or UML's unlinked temporary-file fallback, reopened read-only after mode 0500, works | Refuse configured temporary root |
| Memfd execution | memfd_create, fcntl seals and execveat with AT_EMPTY_PATH work where the pinned startup requires them | Refuse |
| Threads and signals | pthread creation and targeted real-time signals work within current host limits; SMP profiles exercise per-vCPU delivery | Refuse or lower the declared supported CPU count |
| Lifetime primitives | PR_SET_CHILD_SUBREAPER, PR_SET_PDEATHSIG, process groups, waitid and crash-released file locks behave as tested | Refuse |
| Storage | Private directory supports sparse files, required locking and atomic rename | Refuse configured path |
| Limits | Address space, maps, processes/threads, FDs, pending signals and disk headroom meet the requested run | Refuse with exact deficient limit |
| CPU availability | Observe effective affinity/cpuset and quota; an N-vCPU guest may be oversubscribed | Do not refuse a profile-valid N merely because fewer than N host CPUs or quota are currently available; report `scaling_qualified=false` unless at least N CPUs and near-N quota are available |
| UBD/ext4 | Probe artifact mounts and cleanly writes through a test COW | Refuse |
| BESS | Pinned slirp and UML exchange packets without TUN when network is requested | Refuse only networked mode |
| Cgroup/quota | Detect writable delegation or filesystem quota | Report optional capabilities; never require them |

The supplied development environment is x86_64 and demonstrates the strict privilege baseline: UID 1000 with zero capabilities, no KVM/TUN/FUSE, blocked user-namespace creation, and no writable cgroup delegation. In this workspace the pinned and patched Linux 7.2 x86_64 UML artifact has been built and raw-booted with `seccomp=on` at 1, 2, 4, 12 and 16 online CPUs. The revision-bound accepted-physmem proc ABI was boot-tested at the 64 MiB minimum, 256 MiB default and 4 GiB effective maximum; each reported the exact requested byte count. Those boots also prove that UML consumes `mem=`/`ncpus=` and that only the paired expected-value aliases remain in `/proc/cmdline`. Skopeo and umoci pulled and materialized the pinned Ubuntu 24.04 and 26.04 fixtures, and both ran from immutable ext4 bases with private UBD COW files. A fixed four-process compute test produced identical results and measured between 3.48x and 3.86x speedup at four vCPUs versus one on the corrected kernel, varying with host load.

The production-lifecycle loop initially contradicted that: ten of twenty fresh `CONFIG_SMP=y ncpus=1` boots failed and every one of twenty `ncpus=4` boots failed to complete cleanly with scheduler/RCU diagnostics or a panic, and periodic ticks did not cure it. The defect was then isolated to `arch/um/drivers/chan_kern.c` draining its deferred channel-IRQ list from the SIGIO signal handler, where the generic `free_irq()` sleeps on a `CONFIG_SMP=y` kernel. With that call moved into process context by patches `0003`-`0005`, repeated fresh lifecycles at 1, 2, 4, 12 and 16 vCPUs and the complete Ubuntu 24.04/26.04 suite run with no kernel diagnostic. These results are still not native-arm64 evidence; arm64 adoption and SMP qualification still require native arm64 hosts.

The probe record includes canonical host architecture; the profile's native OCI OS/architecture plus accepted/preferred variant and OS-feature policy (not an image-specific actual variant); `profile_id`; immutable `profile_revision`; maturity; host kernel release and page size; UML source/build ID; artifact ELF identities by execution context; guest page size; CPU-state/HWCAP and OCI-selector policy IDs; cooperative-backend result; requested, effective-maximum and online CPUs; nullable SMP-only `compiled_nr_cpus`; profile minimum/product/effective memory bytes and alignment; the probe boot's requested and UML-accepted physical-memory bytes; effective affinity; cgroup quota if visible; limits; selected executable temporary root; filesystem type; sparse-file result; every helper's execution result; BESS result; and a stable reason code for every refusal. `pocket image inspect` and run/generation reports carry actual raw/effective image platform fields. `pocket profile list` and `pocket probe --all` expose all installed revisions without choosing one for a run.

## UML kernel and artifact contract

### Source baseline

Maintain two independent source locks.

For `x86_64-smp-p4k`, pin an exact maintained Linux revision containing the initial SMP commit `1e4ee5135d81`, the TLB synchronization fix `102331b66bcaf1f41f50b9c4cd5c36e46bafa9f3` or its reviewed stable backport, and the userspace-stub parent-death fix `801e00d3a1b78b7f71675fae79946ff4aa3ee070`. Raw 6.19 through 7.0.9 are not acceptable because the initial SMP implementation has a page-table/TLB race fixed in mainline 7.1 and stable 7.0.10. The practical x86 TLB-safe source floor is v7.0.10 from linux-stable or v7.1 from mainline, but the source-lock check independently proves all required commits or equivalent fixes.

That floor does not define a releasable source by itself. The pinned Linux 7.2 candidate satisfies it, and additionally carries the reviewed Phase 0-x86-SMP correction: patches `0003`-`0005` stop UML from calling the sleeping generic `free_irq()` from its SIGIO signal handler. The accepted x86 SMP source is therefore Linux 7.2 plus that locked series, with source/patch identities and regression evidence recorded in `config/sources.lock.toml` and `kernel/patches/7.2/series.lock`.

For arm64, upstream status must be recorded honestly. Upstream master `1b78070aaef63512688aebfbc82365ef9d6660f1` from 2026-08-27 contains no `arch/arm64/Makefile.um` or `arch/arm64/um/`, so it is not an arm64 UML source baseline. The adoption seed is the published `linux-um-arm64` `um-arm64` branch. Its README describes Linux 7.2-rc4 plus 38 patches and UP-only status, but it lags the branch. On 2026-08-28 the audited head was `8897487c52233cd00cf2850008ca068892f1ae91`; the exact merge-base calculation against the fetched `next` object yielded `1590cf0329716306e948a8fc29f1d3ee87d3989f`, with 54 commits in the ordered difference. That exact series includes `03c57e1808f9fc3df91a770e42ce0ff7ac466269` (`um/arm64: enable SMP`), `1532f4aee863d3a580d13cc99685599c46caf3e1` (SMP benchmark harness), and later stub/backend fixes. Phase 0 fetches both objects by ID and regenerates the merge-base/count assertion; neither a branch name, README count, nor current GitHub state may appear as a floating build input.

The arm64 series must be split into independently reviewed generic UML fixes, x86-only fixes that are not part of an arm64 build, and arm64 port patches. Rebase or transplant the arm64 and required generic subset onto the selected maintained source, preserve authorship/DCO, audit licensing, and publish the ordered project-owned series. The external author explicitly disclaims ongoing maintenance and upstream shepherding, so an arm64 release requires a named Pocket maintainer, an update/rebase policy, and a supported-host regression lab. If the project cannot assume that maintenance obligation, arm64 remains a prototype and must not appear in the release support matrix.

The initial arm64 correctness backlog includes: reproduce the published Alpine and Debian boots and the later four-CPU SMP result; retest the RSS-accounting exit path at each offered guest page size; assert and validate the current syscall fallback for guest time because the proposed vDSO time fast path is not merged; retain regression tests for host PAC/FPAC behavior across fork-created stubs and guest FP/SIMD across SIGSYS; enforce the initial SVE/SME/MTE/tagged-address/PAC-key masking policy; validate HWCAP/auxv; and prove `seccomp=on` boot, SMP operation, and teardown with ptrace denied. Any future profile that enables vDSO time must separately add overflow protection, forced-wrap tests and the full timekeeping lane before exposure. The branch's 16 KiB guest-page build is the first adoption target because that is the reported SMP platform and it can in principle run on 4 KiB or 16 KiB hosts. A separate 4 KiB guest revision may be offered only after testing and only on 4 KiB hosts; it cannot run on a 16 KiB host. No 64 KiB guest profile or AArch32 compatibility is planned initially.

The current upstream parent-death fix `801e00d3a1b78b7f71675fae79946ff4aa3ee070` still arms `PR_SET_PDEATHSIG` only after the stub exec and lacks a parent-identity recheck. That commit is an ancestor of both the audited arm64 base and head, and the arm64 head contains the same post-exec protection; an earlier version of this plan incorrectly said otherwise. Both source lines still lack the pre-exec arm/recheck in `userspace_tramp()`. Every adopted profile must therefore retain the post-exec behavior and carry a reviewed extension that arms SIGKILL in `userspace_tramp()` before exec, immediately verifies the expected creating UML parent after `prctl`, and asserts that the embedded stub exec cannot clear the setting through set-ID or file capabilities. Source-audit every architecture's UML child/helper creation path for the same invariant. Kill injection is regression evidence after this proof; it cannot by itself prove a race absent. Record the exact source and patch commits, archive digest, toolchain versions, build environment, final config, ELF dependencies, and output digest.

The exact seed already implements initial arm64 SMP; merely describing the README or setting `CONFIG_SMP=y` by hand would both be wrong. Adoption begins by reviewing the existing capability selection and its stated assumptions: migration-safe AAPCS64 `setjmp` state, real `dmb ish` barriers, separate `TPIDR_EL0` regset, `NT_ARM_SYSTEM_CALL`, and the generic queued-spinlock override used instead of the hardware arm64 event-stream path. Pocket then reproduces and expands the result with the same TLB-shootdown, process/mm churn, timer, IPI, teardown, CPU-state, and same-mm-stub tests as x86. Any new kernel work is defect repair or hardening discovered by this qualification, not a prerequisite invented by the plan.

Each release profile tracks a maintained kernel line containing its required cooperative-backend and lifecycle fixes. A source update is not a routine dependency bump: it reruns that architecture's full boot, ABI/context, SMP when claimed, UBD, image, network, lifecycle, fault and performance suites.

### Configuration invariants

The normalized final config, not merely a fragment, must satisfy these common invariants. Network linkage is deliberately excluded from this common block and selected by the profile-specific block below:

~~~text
CONFIG_64BIT=y
CONFIG_SECCOMP=y               # guest application ABI, not backend selection
CONFIG_SECCOMP_FILTER=y        # guest application ABI, not backend selection
CONFIG_MULTIUSER=y             # setuid/setgid/groups and guest capabilities

CONFIG_BLK_DEV_UBD=y
CONFIG_BLK_DEV_INITRD=y
CONFIG_EXT4_FS=y
CONFIG_EXT4_FS_POSIX_ACL=y
CONFIG_EXT4_FS_SECURITY=y
CONFIG_SECURITY=y
CONFIG_DEVTMPFS=y
CONFIG_DEVTMPFS_MOUNT=y
CONFIG_PROC_FS=y
CONFIG_SYSFS=y
CONFIG_TMPFS=y
CONFIG_TMPFS_XATTR=y
CONFIG_TMPFS_POSIX_ACL=y
CONFIG_UNIX98_PTYS=y
CONFIG_POSIX_MQUEUE=y

CONFIG_BINFMT_ELF=y
CONFIG_BINFMT_SCRIPT=y
CONFIG_FUTEX=y
CONFIG_EPOLL=y
CONFIG_EVENTFD=y
CONFIG_SIGNALFD=y
CONFIG_TIMERFD=y

CONFIG_NAMESPACES=y
CONFIG_UTS_NS=y
CONFIG_IPC_NS=y
CONFIG_PID_NS=y
CONFIG_NET_NS=y
CONFIG_USER_NS=n

CONFIG_NET=y
CONFIG_UNIX=y
CONFIG_SSL=y
CONFIG_NULL_CHAN=y
CONFIG_INET=y
CONFIG_IPV6=n                 # initial networkless and BESS profiles are IPv4-only

CONFIG_UML_TIME_TRAVEL_SUPPORT=n  # one deterministic product profile
CONFIG_HOSTFS=n                # product minimalism and accident prevention
CONFIG_MODULES=n               # deterministic kernel surface
CONFIG_MCONSOLE=n              # control uses the trusted serial protocol
~~~

Network capability and linkage are profile-revision properties:

| Profile network contract | Required final configuration and packaging |
|---|---|
| Networkless static | `CONFIG_STATIC_LINK=y`, `CONFIG_UML_NET_VECTOR=n`, `CONFIG_IPV6=n`, and unused UML NIC drivers disabled. This is the current `x86_64-smp-p4k` boundary; it may omit Phase 5 only after every other applicable gate passes. |
| BESS/slirp network-capable | `CONFIG_UML_NET_VECTOR=y`, `CONFIG_IPV6=n` for the initial IPv4-only contract, plus the vector prerequisites, `CONFIG_STATIC_LINK=n` where selected runtime dependencies make those incompatible, and the guarded bundled-loader contract. This is a distinct profile revision and cannot be inferred from an otherwise matching kernel. |

The artifact manifest and support matrix record `uml_linkage=static|dynamic`, the exact launch template, and `network_capabilities=[]|bess-slirp` (or a future versioned set). The final-config assertion requires vector off for the static networkless contract and on only for a BESS-qualified contract. CLI `--network slirp` fails before launch when the selected revision does not advertise it; `--network none` never starts slirp or attaches a UML NIC.

CPU and ABI invariants are profile-specific:

| Profile | Required final configuration and policy |
|---|---|
| x86_64-smp-p4k | x86_64 UML; `CONFIG_UML_SUBARCH_SUPPORTS_SMP=y`; `CONFIG_SMP=y`; `CONFIG_NR_CPUS=16` initially; 4 KiB guest pages; reject i386 ELF inputs; Phase 0-x86-SMP corrective gate passed with locked patches `0003`-`0005` |
| x86_64-up-p4k-test | distinct optional control from authenticated x86 source with `CONFIG_SMP=n`, `CONFIG_NR_CPUS=1`, a hard one-CPU policy and no `ncpus=` launch token; cannot alias or promote the SMP profile |
| arm64-smp-p16k-experimental | exact adopted arm64 UML seed already selecting `CONFIG_UML_SUBARCH_SUPPORTS_SMP=y`; `CONFIG_SMP=y`; `CONFIG_NR_CPUS=16`; `CONFIG_COMPAT=n`; 16 KiB guest pages; release remains blocked on Phase 0 qualification |
| arm64-up-p16k-test | qualification-only build from the same adopted source with `CONFIG_SMP=n`; effective maximum one CPU; `CONFIG_COMPAT=n`; proves the non-SMP build and one-CPU base path without becoming the default product profile |
| arm64-smp-p4k-experimental | optional later revision only after a 4 KiB guest/host matrix passes; never selected on a host whose page size exceeds 4 KiB |
| arm64-smp-p16k | release-only profile that binds the exact source, final config, kernel, initramfs and helper digests of a candidate that passed every promotion gate; any byte or contract change creates a new revision and reruns affected qualification |

Several symbols vary or are selected indirectly by kernel release. The config assertion tool must inspect the final config and fail on an invariant violation, then boot-test every required device and channel because a symbol check alone is insufficient. It emits the architecture, ELF machine, guest page size, `smp_enabled`, nullable SMP-only `compiled_nr_cpus`, checked `effective_max_cpus`, minimum/default/product/effective workload memory bytes, fixed builder-memory bytes, alignment and the accepted-byte evidence for each gated value, `CONFIG_COMPAT` state, CPU-feature policy, linkage, and network capability set used to validate run-time requests. It rejects an SMP product maximum above the compiled value, any UP effective maximum other than one, a workload default outside minimum/effective range, a builder value outside its declared range, any unaligned value, a memory effective maximum above product policy, or any gated memory value without exact accepted-byte boot evidence; it also rejects linkage/vector mismatch. `CONFIG_SECCOMP` and `CONFIG_SECCOMP_FILTER` provide guest-visible seccomp for unchanged application compatibility; only the run-time `seccomp=on` probe proves the host cooperative backend. The initial bundle uses an uncompressed deterministic cpio initramfs; if compression is introduced, the matching in-kernel decompressor becomes another asserted invariant. The frozen mke2fs policy must retain ext4 extended attributes so the ACL and security-xattr guarantees are real.

Hostfs, modules, and mconsole are disabled for deterministic behavior and to avoid accidental host access, not because this trusted-only product claims an adversarial boundary. A future feature may enable a host-facing facility only after defining its user-visible semantics and zero-privilege behavior.

### Static versus dynamic UML

The vector network configuration may conflict with UML static linking or depend on dynamically loaded name-service behavior. A dynamically linked ELF records an absolute PT_INTERP path; copying a loader beside it does not change what the host kernel opens. The baseline must therefore use one of two tested packaging contracts:

1. Prefer a compatible static artifact where the upstream build and required feature set support it.
2. Otherwise the guard's freshly forked UML child must first set and verify `PER_LINUX|ADDR_NO_RANDOMIZE`, then exec the bundled dynamic loader under the verified closed-closure contract below. `--library-path` alone is only a preferred search path and is not accepted as closure. Illustrative shape:

   ~~~text
   [pocket-guard child pre-exec: set+verify PER_LINUX|ADDR_NO_RANDOMIZE]
   /absolute/user-prefix/profiles/PROFILE_ID/PROFILE_REVISION/host/lib/PROFILE_LOADER
     --inhibit-cache
     --library-path /absolute/user-prefix/profiles/PROFILE_ID/PROFILE_REVISION/host/lib
     /absolute/user-prefix/profiles/PROFILE_ID/PROFILE_REVISION/host/libexec/linux-uml ...
   ~~~

   `PROFILE_LOADER` is `ld-linux-x86-64.so.2` for the glibc x86_64 bundle and `ld-linux-aarch64.so.1` for the glibc arm64 bundle. The exact PT_INTERP string and loader digest are asserted from the executable rather than inferred from the host name. Every dynamic host-context role—not only UML—is linked with and verifies `DT_FLAGS_1: DF_1_NODEFLIB` (for example linker `-z nodefaultlib`), is invoked through its role-bound bundled loader with `--inhibit-cache`, receives a cleared loader-influencing environment, and refuses a nonempty host `/etc/ld.so.preload`. A helper that cannot satisfy this mechanism must be shipped static or excluded. Each role manifest recursively names every `DT_NEEDED`, glibc-hwcaps alternative, audited `dlopen` target and NSS module exercised by that role's supported feature set. Qualification runs the bundled loader's dependency listing and representative role operations, then inspects `/proc/*/maps` or an equivalent pre-exit audit channel and verifies every mapped ELF pathname is beneath the immutable revision bundle. The clean-host matrix may still contain its distribution's common libc DSOs; closure does not rely on their accidental absence. Instead the NODEFLIB/cache/environment controls plus mapped-path assertion prove they were unused, and an additional deliberately missing-unbundled-dependency fixture must fail. An unlisted runtime-loaded object, an object from a host directory, or an unexplained absolute-path configuration dependency fails the role; a source update reruns its audit. Static linkage remains preferred because this dynamic contract is materially broader than supplying `--library-path`.

The personality step is a correctness requirement, not an ASLR preference. Linux 7.2 UML calls `personality(PER_LINUX|ADDR_NO_RANDOMIZE)` during startup and, when the returned previous personality lacked those bits, resolves `/proc/self/exe` and re-execs that path. Under manual `ld.so UML ...` invocation, `/proc/self/exe` identifies `ld.so`; an unprepared launch would therefore re-exec the loader without its UML target and arguments. The guard implements the step with scalar syscalls in its child-side pre-exec path, verifies the resulting bits, and fails before exec if they cannot be established. A reviewed UML patch which reconstructs the complete loader invocation could replace this only in a new profile revision after equivalent tests; invoking the loader directly without either contract is prohibited.

Every product launch also passes UML's exact `noreboot` run-time option. Linux 7.2 otherwise handles a guest restart by `execvp(new_argv[0], new_argv)`. In the bundled-loader form UML sees its own ELF as `argv[0]`, so that restart would bypass the loader and verified closure even though the first launch was correct. `noreboot` makes an in-guest restart terminate the UML process instead, matching the MVP lifecycle contract; workload capability policy also excludes `CAP_SYS_BOOT`. Pocket-init uses poweroff for normal completion. A future user-facing restart operation must create a fresh guarded UML launch from the verified manifest rather than allowing in-process self-exec. Static and dynamic profile gates issue a guest restart, require exactly one boot followed by process exit, and verify that no replacement executable survives.

Skopeo, e2fsprogs, slirp4netns and every other host helper obey that same static-or-fail-closed-dynamic-role contract; the UML personality precondition alone is specific to executables with UML's self-reexec path. Certificates, registry policy, NSS behavior and helper executables are explicit bundle inputs. The x86_64 release Skopeo is built from v1.23.0 with the upstream-supported pure-Go OpenPGP backend and cgo disabled, twice, and must be byte-identical with no `PT_INTERP`, `PT_DYNAMIC`, `.dynamic`, or `DT_NEEDED`. Its `docker://` transport remains enabled. The profile also carries curl's immutable dated Mozilla bundle as `registry-ca.pem`; the sanitized Skopeo environment sets `SSL_CERT_FILE` to that exact file instead of consulting host trust roots. The bundle revision, official checksum-file bytes, PEM count, X.509 parsing, and root self-signatures are locked and verified. The probe executes every helper on a clean host and records the per-role dependency listing and mapped-ELF audit. For dynamic UML it starts with the personality bits deliberately clear, exercises the guard-plus-loader first launch, positively reaches guest readiness, and proves failure when the guard personality step is omitted; merely running `ldd` is not an acceptance test. Builder-initramfs helpers remain a separate guest-filesystem closure and are proven by a clean-initramfs boot.

Skopeo's v1.23.0 tag and release commit are not cryptographically signed. Pocket therefore pins the annotated tag object, commit, tree, module zip and `go.mod` hashes, and requires the module's exact `h1` identities to authenticate through Go's signed transparency-backed checksum database before building. This is stronger than trusting an unversioned distribution executable, but it is not misrepresented as a maintainer-signed release. The official Go toolchain archive and curl/Mozilla bundle are HTTPS-acquired and independently SHA-256 locked; initial acquisition needs those upstream network services, while the published tool and trust bundle are self-contained runtime inputs. Curl's CA extract also documents that Firefox-specific name constraints are not represented in the PEM conversion, so Pocket treats CA-revision changes as profile-revision changes and does not claim browser-equivalent trust semantics.

### Artifact manifest

Every release bundle contains:

- stable `profile_id` and immutable `profile_revision`; canonical host architecture; OCI OS/architecture plus versioned variant/OS-feature policy; UML subarchitecture; maturity; `smp_enabled`, `product_max_cpus`, nullable SMP-only `compiled_nr_cpus` and checked `effective_max_cpus`; minimum/default/product/effective workload physical-memory bytes, fixed builder-memory bytes and alignment, each with required accepted-byte evidence; guest page size; CPU-state/HWCAP policy; root-layout version; and filesystem/UBD consumer contract;
- native UML executable, ELF identity, final config and build ID;
- workload and builder initramfses with file manifests and digests;
- Skopeo, its explicit dated registry CA bundle, umoci, e2fsprogs and optional slirp binaries, each carrying its execution context and invocation record;
- exact dynamic interpreter/libraries;
- source, patch and dependency lock files;
- SHA-256 checksums and an SBOM;
- supported host and image-format matrix;
- reproducibility result or documented nondeterministic bytes.

## Existing Docker and OCI image ingestion

### Why conversion is necessary

An OCI image consists of an index or manifest, a configuration blob, and ordered layer changesets. Layers are tar streams whose whiteout entries delete lower-layer paths and whose opaque markers hide lower directory contents. Their portable OCI filesystem attributes include numeric ownership, modes, links, device entries, modification time (`mtime`), xattrs (including ACLs and file capabilities where represented), and file type. The Linux MVP preserves `mtime`, including an accepted POSIX PAX `mtime` value, but does not claim OCI portability for access time, inode-change time, or Windows creation time. Time-related PAX extensions use a closed policy: `mtime` is accepted; `atime`, `ctime`, and `LIBARCHIVE.creationtime` are rejected rather than silently folded into the cache contract.

UML UBD requires a block-device image. A Docker save archive, OCI archive, or OCI layout is not such a device. Generic tar extraction is also incorrect because it does not implement the complete ordered whiteout and replacement rules.

The user does not build the rootfs manually. Pocket performs a versioned one-time conversion and caches the exact hashed result. Byte-for-byte reproducibility is a release goal, not a current claim: directory hash seeds are now derivation-bound and the guest clock starts at the bounded build epoch before target mount, but advancing realtime/generated ctime and ext4 inode-generation/journal entropy remain explicitly recorded inputs. Until those remaining inputs are normalized, two valid builds from one derivation may have different final generation IDs.

### Accepted source transports

| Input | Baseline support | Normalization |
|---|---|---|
| Registry reference | Yes | Skopeo docker:// source to private OCI layout |
| Registry digest | Preferred | Copy exact selected manifest |
| Local OCI layout | Yes | Skopeo oci: source to private staged layout |
| OCI archive | Yes | Skopeo oci-archive: source |
| Docker save archive | Yes | Skopeo docker-archive: source; reject ambiguous multi-image selection |
| Docker daemon image | Optional adapter | Only when caller already has daemon-socket access; never a prerequisite |
| Docker container export tar | No image import | It loses image configuration and layer provenance; a future explicit raw-rootfs import would require command metadata |

Skopeo is preferred over requiring Docker because it is daemonless, normally unprivileged, handles all required transports, writes an OCI directory directly, and integrates registry authentication and containers/image policy. Pocket invokes only the exact profile-bundled v1.23.0 static executable, supplies a private explicit policy and authentication file plus private HOME/XDG/TMP locations, and sets `SSL_CERT_FILE` to the profile-bundled `registry-ca.pem`. It never searches `PATH` or silently falls back to host policy, credentials, or CA roots. For local sources, Pocket accepts path and optional reference as separate CLI fields, then copies the source into a safe managed staging name before constructing Skopeo's colon-delimited transport string.

### Acquisition and normalization

The same candidate-enumeration and platform-verification algorithm applies to every accepted transport: registry reference or digest, OCI layout/archive, and Docker archive. A registry tag adds only a mutable-name resolution step; a local multi-image or multi-platform source is not allowed to bypass selection.

1. Select the active `profile_id` and immutable `profile_revision` before resolving the image.
2. Enumerate every candidate image manifest. Authenticate and parse each candidate's required image configuration, then derive its required `os` and `architecture` and optional variant. A manifest descriptor's platform may be absent even when it appears in an OCI index: this is the normal shape produced by Skopeo's single-image `oci:PATH:REF` destination and is accepted by deriving the candidate platform from config while preserving the raw descriptor absence. Where descriptor platform is present, require it to agree with config. Apply selection only after derivation and reject multiple equal-precedence native candidates as ambiguous; never use descriptor order.
3. Apply the profile revision's versioned variant policy. OCI `variant` is optional on both the descriptor and config. If both are explicit they must agree; if only one is explicit, use it as the effective variant while preserving the other field as absent; if both are absent, the effective variant remains absent. The MVP accepts absent or the explicit baseline `amd64/v1` or `arm64/v8`; it rejects higher explicit variants until the profile exposes the required CPUID/HWCAP state and has a tested rule. The profile's preferred baseline or an explicit CLI variant has higher precedence than an accepted all-absent candidate; reject multiple candidates at the same precedence as `E_PLATFORM_AMBIGUOUS` rather than relying on source order.
4. Reject nonempty OCI `os.version`, `os.features`, or the descriptor platform's reserved `features` array in the MVP. Preserve their raw presence in diagnostic/provenance evidence even on rejection. Any future accepted value requires a versioned policy, compatible UML evidence, and inclusion in cache identity; reserved `features` must never be silently interpreted as ordinary image annotations.
5. For a registry tag, resolve it once, record the original reference and resolution result, and copy the selected immutable digest. For other transports, record the source object's immutable digest and selected internal reference.
6. Copy into a private mode-0700 staging layout and verify the staged OCI index when present, selected manifest, configuration, and every layer descriptor by size and digest.
7. Verify configuration OS and architecture, actual optional fields, rootfs type, layer count, and DiffID count. OS and architecture must agree wherever both descriptor and config supply them. Optional variants conflict only when both are explicit and unequal; optional OS fields are likewise checked when supplied, and the MVP rejects any nonempty `os.version`, `os.features`, or reserved descriptor `features`. Preserve both raw platform records plus the effective selection (or the typed rejected-platform evidence).
8. Apply a versioned source allowlist: OCI image/index/config/layer types and Docker v2 schema-2 manifest-list/manifest/config/layer types with supported uncompressed, gzip or zstd filesystem layers.
9. Require Skopeo's staged destination to be canonical OCI: OCI index, selected OCI image manifest, OCI config and allowed OCI layer media types only. `umoci raw unpack` must never receive a Docker-media-type selected manifest.
10. Reject Docker schema 1, artifact manifests, encrypted layers, external-URL/foreign layers, unknown media types, and unknown compression with stable typed errors.
11. Stream-decompress each layer under configured byte, entry, path-length and ratio limits and verify its uncompressed DiffID.
12. Preserve the exact verified canonical image-configuration bytes and descriptor/config platform fields as cache sidecars.
13. Treat tags only as mutable aliases; never use a tag as an artifact cache key.

Illustrative command shape, finalized against the pinned Skopeo version:

~~~text
skopeo --policy PRIVATE_POLICY --tmpdir PRIVATE_TMP copy
  --authfile PRIVATE_AUTH_JSON
  --override-os linux
  --override-arch PROFILE_OCI_ARCH
  [--override-variant PROFILE_OCI_VARIANT]
  --
  docker://REGISTRY/REPOSITORY@sha256:DIGEST
  oci:STAGING_LAYOUT:root
~~~

The process environment is cleared and explicitly includes `SSL_CERT_FILE=PROFILE/host/registry-ca.pem`; the command is constructed as an argv array rather than parsed by a shell. `--authfile` is a `copy` subcommand option in the pinned CLI and therefore appears after `copy`. `PROFILE_OCI_ARCH` is `amd64` or `arm64`; the variant argument is present only when the resolved target is explicit, on either architecture. This command illustrates a registry copy only; other transports use their corresponding source syntax after the same selection rules. Docker-to-OCI media-type conversion may change a local manifest digest. Record both upstream and canonical local digests rather than assuming they match. Preserve upstream digests only when the transport and media types allow it.

### Image-configuration record

Parse and retain a bounded subset:

- Entrypoint and Cmd;
- Env;
- WorkingDir;
- User;
- StopSignal;
- Labels;
- ExposedPorts and Volumes as informational hints;
- Healthcheck, when the accepted source/normalization contract preserves that Docker extension, as inspectable metadata only; otherwise report it as unavailable rather than inventing it;
- selected platform and manifest/config digests.

The image configuration is not an OCI runtime config.json. Pocket builds its own validated start request from the supported subset and CLI overrides.

### Payload and target filesystem construction

The host never mounts an image.

1. Create private operation state under the runtime root and a not-yet-selectable generation staging directory on the same filesystem as the final cache. The verified OCI layout root contains `oci-layout`, `index.json`, and `blobs/`; those entries will appear directly under `/input` in the builder.
2. Size the payload ext4 independently from the final root: sum every staged file's logical bytes and inode, add deterministic directory/ext4 metadata and free-space headroom, and enforce source byte/blob-count limits.
3. Create a sparse payload file and use pinned mke2fs with a frozen configuration to populate it from the OCI-layout directory. Metadata fidelity on this disk is irrelevant because it stores only blob bytes and names. On block/inode ENOSPC, discard it and retry once in the next deterministic payload size class; never boot a partial payload.
4. Create the sparse blank target inside the cache-filesystem generation staging directory and format it as ext4 with `filesystem_contract_id=ext4-v1-b4096` initially: 4096-byte blocks, plus pinned inode size/count, feature set, UUID policy, journal policy, lazy-init settings, reserved-block percentage, and label. A later block-size or feature change creates a new contract and cache namespace rather than silently reusing an old base.
5. Boot the builder UML with the payload UBD read-only and target UBD writable.

Before the first filesystem helper, create one empty mode-0600 `BLKID_FILE` inside the mode-0700 operation directory and pass that exact path to both mke2fs and e2fsck under a cleared environment; neither helper may consult the host libblkid cache. Only mke2fs receives the sealed `MKE2FS_CONFIG`. Only e2fsck receives `E2FSCK_CONFIG`, bound to a sealed, exactly empty file that has been parser-smoke-tested with the pinned e2fsprogs release, so `/etc/e2fsck.conf` cannot change validation. These policy files, helper binaries, and their hashes are all inputs to the immutable profile revision and build provenance.

Target sizing must not use compressed descriptor sizes as a proxy. The preferred implementation is two-pass:

- pass one verifies/decompresses layers, counts entries and logical regular-file bytes, and reports requirements;
- the host creates ext4 with deterministic metadata and journal headroom;
- pass two applies the image.

A faster MVP may use a generous sparse logical size and conservative inode density, but it must apply a best-effort free-space admission margin, detect both block and inode ENOSPC, discard the partial target, and retry once from an empty newly formatted target in a larger deterministic size class before failing. It never resumes a partial umoci application. A free-space check is not a capacity reservation; only an optional quota/reservation adapter can provide that guarantee.

### Builder UML

Illustrative boot:

~~~text
[pocket-guard child pre-exec: set+verify PER_LINUX|ADDR_NO_RANDOMIZE]
/absolute/user-prefix/profiles/PROFILE_ID/PROFILE_REVISION/host/lib/PROFILE_LOADER
  --inhibit-cache
  --library-path /absolute/user-prefix/profiles/PROFILE_ID/PROFILE_REVISION/host/lib
  /absolute/user-prefix/profiles/PROFILE_ID/PROFILE_REVISION/host/libexec/linux-uml
  mem=PROFILE_VALIDATED_BUILDER_MEMORY
  ncpus=1
  seccomp=on
  umid=build-OPAQUE_ID
  uml_dir=/absolute/runtime-root/build-OPAQUE_ID/uml
  initrd=/absolute/runtime-root/build-OPAQUE_ID/builder-initramfs.cpio
  rdinit=/init
  ubd0r=/absolute/runtime-root/build-OPAQUE_ID/oci-payload.ext4
  ubd1=/absolute/cache-root/.staging/build-OPAQUE_ID/base.ext4
  con=null
  con0=fd:14,fd:14
  ssl=null
  ssl0=fd:10,fd:10
  pocket.builder.expected_memory_bytes=PROFILE_VALIDATED_BUILDER_MEMORY_BYTES
  pocket.builder.expected_cpus=1
  quiet
  noreboot
  panic=1
~~~

Exact UBD suffixes, device names and serial syntax are acceptance-tested against the pinned kernel.

The first four lines show the guarded bundled-loader form; a verified static UML omits the loader arguments but still uses the same guard, parent-death and process-group path. This command shows an SMP-capable builder profile, which receives explicit `ncpus=1`; a `CONFIG_SMP=n` qualification builder omits that argv element after Pocket validates one CPU. UML consumes recognized `mem=` and `ncpus=` options before constructing the guest kernel command line, so neither is a guest-visible source of truth. The paired `pocket.builder.expected_memory_bytes=` and `pocket.builder.expected_cpus=` aliases remain in `/proc/cmdline`; builder-init requires them, compares them with `/proc/uml_physmem_bytes` and the online CPU count, and never attempts to recover the consumed UML options. The builder UML, builder initramfs and guest umoci/helper closure come from the selected native profile. Although applying tar changesets is not itself instruction-set emulation, using the matching builder keeps the executed toolchain and its validation evidence within one qualified profile. Before launch, the operation creates the managed initramfs alias shown above and validates every artifact digest and path bound.

Builder init:

1. Mount private proc, sysfs, devtmpfs, tmpfs and devpts.
2. Open the control serial line, put it in raw mode, send `BUILD_HELLO`, and wait for a validated `BUILD_START` before touching either filesystem.
3. Mount payload read-only at /input and target at /target.
4. Re-verify the expected OCI image manifest, config, layer descriptors and tool identities from the request.
5. Ensure /target/rootfs does not already exist.
6. Run the pinned equivalent of:

   ~~~text
   umoci raw unpack --image /input:root /target/rootfs
   ~~~

7. Do not use rootless mapping or keep-dirlinks behavior.
8. Parse completed `/etc/passwd` and `/etc/group` with strict size/line/field/count bounds and emit a canonical `accounts.cbor` database containing the records needed for Pocket's User grammar. Hash it and include its digest in the generation marker. Resolve the image-config User against that database when possible and record either numeric UID/GID/supplementary evidence or a typed unresolved/ambiguous result; an unresolved original named User does not abort conversion because a later explicit CLI override may make the image runnable. Malformed account files still fail conversion. Resolution accepts `user`, `uid`, `user:group`, `uid:gid`, `uid:group`, or `user:gid`. A named user/group must have exactly one usable match; a numeric ID remains valid without a name entry. When group is absent, use the selected user's passwd primary GID when an entry exists (otherwise the versioned numeric-UID fallback is GID 0) and include every deduplicated `/etc/group` membership for that user. When group/GID is explicit, use it and suppress image group memberships unless an explicitly supported runtime supplementary list is supplied.
9. Write `/target/.pocket-generation.cbor`, outside `/target/rootfs`, containing the non-circular `derivation_key` (the hash of verified inputs and contracts, not the output ext4 hash), `accounts.cbor` digest, `profile_id`, `profile_revision`, raw canonical descriptor platform, raw canonical config platform, effective platform tuple, selector-policy ID, root-layout version and filesystem contract. Cover this fixed-schema marker with the canonical metadata manifest and final base hash; the workload never sees it after chroot. The final globally addressable `generation_id` cannot be embedded here because it is computed only after this ext4 and its sidecars are complete.
10. Sync the target, then walk the final tree without following symlinks or updating access times and stream its canonical metadata manifest to the host with the protocol below.
11. Unmount both filesystems, send `BUILD_DONE` with the observed tool identities, named-User resolution evidence, manifest totals/digest and filesystem status, and power off normally.

The builder protocol is separate from the workload protocol and is the only route by which the host obtains the potentially large metadata sidecar; the host never mounts the target. It uses bounded, length-prefixed canonical CBOR frames:

~~~text
BUILD_HELLO     protocol, guest_contract_id, init_build_id, kernel_build_id,
                host_elf_machine, guest_uts_machine, guest_page_size,
                cpu_state_hwcap_policy, online_cpus, accepted_physmem_bytes,
                builder_tool_ids
BUILD_START     profile_id, profile_revision, derivation_key,
                selected_manifest_and_config, layer_descriptors,
                descriptor_config_platform, effective_platform,
                selector_policy, root_layout, filesystem_contract,
                manifest_schema, manifest_limits, expected_tool_ids
MANIFEST_BEGIN  schema, stream_id
MANIFEST_CHUNK  stream_id, sequence, first_entry, entry_count, bytes
MANIFEST_END    stream_id, entry_count, byte_count, sha256
ACCOUNT_DB      schema, byte_count, sha256, canonical_bytes
BUILD_DONE      status, manifest_sha256, entry_count, byte_count,
                generation_marker_sha256, account_db_sha256,
                original_user, optional_user_resolution_or_typed_failure,
                observed_tool_ids_and_versions, fs_status
BUILD_ERROR     stage, stable_code, errno, diagnostic
~~~

`MANIFEST_CHUNK` contains a sequence of complete length-prefixed canonical entries; an entry never straddles chunks. Paths use a component-wise byte-lexicographic depth-first order: a directory precedes every descendant, components within that directory are compared as raw filename bytes, and its complete subtree precedes the next sibling. This is deliberately not raw whole-path byte ordering (`Carp/Heavy.pm` precedes the sibling `Carp.pm`) and lets the guest stream a bounded sorted directory walk without retaining the entire image tree. The schema fixes maximum path, xattr, entry and chunk sizes, plus total entries and bytes. Sequence and entry indices must be contiguous. `ACCOUNT_DB` has its own strict record/count/byte limits and canonical decoder; the host writes it as immutable `accounts.cbor.tmp`, recomputes its digest, and never trusts a path from it. The host exclusively creates `metadata.manifest.tmp` in the generation staging directory, incrementally parses and validates canonical encoding and limits, writes each accepted byte, and computes the digest. It rejects extra, missing, reordered or post-END frames. It accepts `BUILD_DONE` only when its count, byte total, manifest/account digests, tool evidence and optional image-User resolution evidence agree; it then fsyncs both sidecars before treating the builder result as complete. Any disconnect, limit violation or mismatch kills the builder and leaves the staging generation unpublishable.

Guest UID 0 can create arbitrary numeric owners, modes, set-ID bits, device nodes, FIFOs, links, ACLs, security.capability and other xattrs on guest ext4. It confers no host privilege. This is why the builder preserves image metadata more faithfully than host-side rootless extraction followed by mke2fs -d.

The builder is launched through the same per-operation lifetime-guard pattern as a workload run. The guard holds the staging/build lease and ensures a killed importer or caller cannot leave a live builder or make an incomplete target selectable. Every validation UML likewise receives a unique managed `umid` and `uml_dir`; no operation may fall back to `$HOME/.uml`.

### Validation and atomic publication

After a successful builder exit:

- run pinned e2fsck -fn, either as a trusted host helper or in a validation UML;
- for the first implementation, boot a separate validation UML and mount the completed base read-only inside that guest; its bounded `VALIDATE_HELLO`/`VALIDATE_START`/`VALIDATE_DONE` exchange recomputes the canonical tree entry count, byte count and digest, canonical account database and generation-marker digest and compares them with the fsynced host sidecars, without retransmitting the whole tree manifest;
- validate the canonical metadata manifest against structural policy; for the conformance corpus, compare it with independently authored expected manifests rather than an oracle derived from the same umoci output;
- hash the completed ext4 and every immutable sidecar;
- derive the final global `generation_id` as SHA-256 over a versioned domain separator, the non-circular `derivation_key`, the base.ext4 digest/size and the canonical ordered sidecar name/digest/size records; the final manifest contains that ID but its own bytes are not an input to it;
- stage on the same filesystem as the final cache, fsync base.ext4 and every sidecar, write and fsync a final generation manifest, then fsync the staging directory;
- rename the complete staging generation into the cache and fsync the cache parent;
- never publish a partial or failed artifact.

The non-circular `derivation_key` includes:

- `profile_id`, immutable `profile_revision`, and the bound builder/workload architecture contract;
- canonical selected-manifest digest from the staged OCI layout;
- selected descriptor/config OS and architecture; actual absent/explicit variants; accepted `os.version`/`os.features` values (empty in the MVP); and OCI-selector-policy ID;
- config digest;
- UML builder kernel and initramfs digests;
- umoci and e2fsprogs versions/digests;
- root-layout version and `filesystem_contract_id`, including ext4 block size, features, sizing and inode-policy version;
- conversion and metadata-schema version.

A generation contains immutable base.ext4, image-config.json, accounts.cbor, the fsynced streamed metadata manifest, artifact digest, canonical build provenance including builder tool and image-User-resolution evidence, build log summary, and a final generation manifest carrying the `derivation_key`, final `generation_id`, every key field and every file hash. The derivation key answers “were the verified inputs and conversion contract the same?”; the final ID answers “are these immutable output bytes and sidecars the same?” Two builds with one derivation key but different explained output bytes necessarily receive different final IDs and may coexist; they can never alias to the same global ID. The derivation index is written under its derivation lock: its `canonical_generation_id` is the first successfully committed/revalidated result while that generation remains in the store, normal cache hits always return that ID, and later differing observed results are recorded in a sorted alternatives set but never silently replace the live winner or an alias. The derivation index is not a GC root: if GC lawfully removes an unaliased, unleased, unretained winner, it atomically promotes the lowest final ID among the surviving alternatives, or removes the index when none survives. Thus every cache hit remains deterministic without making all historical builds immortal. Explicit qualification tooling may pin/inspect an alternative; ordinary pulls do not select one nondeterministically. Original references, upstream registry/index digests, pull time and tag aliases live in external per-pull records because archives may not have them and equivalent transports may use different media-type digests. A mutable alias is keyed by source/reference plus resolved `profile_id`, `profile_revision`, normalized requested platform selector and policy ID, and its record contains the actual selected descriptor/config platform tuple. Pulling one multi-platform tag on arm64 therefore cannot replace its amd64 alias, and updating an active profile revision cannot overwrite an explicitly addressable old-revision alias. Mutable aliases, derivation lookup records, leases and run records never alter the immutable generation. An alias is nevertheless a durable reachability root for its final generation ID until that exact alias is atomically replaced or explicitly removed. Readers select a generation only after canonically parsing its final manifest, recomputing the final ID and file hashes, and validating artifact identities, platform tuple, root-layout version, filesystem contract, account sidecar and ext4 superblock against the selected profile revision. A foreign cache ID fails before UML launch as `E_GENERATION_PROFILE_MISMATCH`.

### Cache updates and garbage collection

- A tag is resolved on every explicit pull for the requested native platform and resolved profile revision. It is a hit only when the canonical selected-manifest/platform plus the entire builder/ext4/conversion contract yields a derivation key with an existing fully revalidated committed final generation; updating that revision-qualified alias leaves every other architecture/profile/revision alias untouched. Build serialization uses the derivation key, while published directories, aliases, leases, retained COWs and GC use the final generation ID.
- A changed multi-platform index that still selects the same canonical manifest for the same resolved `profile_id`/`profile_revision`, normalized native platform, actual absent/explicit variant and policy version may reuse that generation; any selected-platform, revision or build-contract change creates a new generation even if the upstream digest is unchanged.
- Publication commits and fsyncs the immutable generation before atomically creating or moving an alias. Moving one alias removes only that alias's root from its old generation; the old generation becomes collectible only if no other alias, retained COW or live lease reaches it. `image remove` on an alias removes exactly that resolved alias. Removal by immutable generation ID refuses with `E_GENERATION_IN_USE` while any such root exists.
- Active runs hold leases on their exact generation.
- Every retained COW has a sidecar binding its creator `profile_revision`, architecture, exact base identity/path, and UML UBD-COW format/consumer version. It is a durable GC root until deletion or a future explicit flatten/rebase operation, and it may reopen only under a declared-compatible runtime revision.
- No base file may change in contents, size, metadata expected by UBD COW, or path while a dependent COW exists.
- GC removes only generations with no valid alias, no live lease and no retained COW, plus abandoned staging directories proven to belong to Pocket. Reachability is checked under the same namespace/per-key locking discipline used for alias and lease updates.
- Cache and staging operations use per-key locks, exclusive create and atomic rename.
- Recovery verifies final generation manifests, ignores incomplete staging trees, reconciles aliases, retained-COW roots and external lease records before GC, and never leaves a selectable alias pointing at a deleted or invalid generation. A dangling/corrupt alias is quarantined with a typed diagnostic and treated as missing only by a pull policy that permits acquisition.
- COW files are not OCI layers. Snapshot or image commit requires a later OCI-aware diff and metadata encoder.

## Per-run runtime

### Preparation

1. Select exactly one installed `profile_id`/`profile_revision` using explicit CLI/config or the unique release-grade default; never let the image or `--cpus` choose it implicitly.
2. Under the store's profile-namespace/generation lock, resolve the image reference or cache ID to one immutable generation and atomically acquire its crash-releasable lease before releasing the lock. The lease pins that exact generation independently of later alias movement or removal; no generation path, manifest or artifact may be returned to the runtime before this resolve-and-lease transaction succeeds.
3. While that exact-generation lease is held, and before creating a COW or invoking UML, validate the generation-manifest hash and file hashes; descriptor/config OS, architecture and actual variant; OCI-selector policy; root-layout version; filesystem contract; and ext4 superblock against the selected revision. Reject any mismatch, including a manually supplied foreign cache ID.
4. Merge image configuration with validated CLI overrides. If unchanged image User is selected, use its stored successful resolution or fail with its stored typed resolution error. If `--user` overrides it, resolve the override exactly once from the verified canonical `accounts.cbor` sidecar, produce numeric IDs plus canonical resolution evidence, and bind that evidence into START; the host never mounts ext4.
5. Validate requested CPUs against profile maturity and manifest `effective_max_cpus`; the manifest/config assertion has already proved the SMP compiled ceiling or the UP value of one. Effective host affinity/cpuset and quota are recorded as scheduling telemetry, not an admission ceiling: Pocket allows a profile-valid N-vCPU guest to be oversubscribed and labels the run `scaling_qualified=false` when fewer than N host CPUs or near-N quota are available. An explicit future strict-admission option may refuse oversubscription, but the baseline never silently changes N. For an SMP build pass explicit UML-only `ncpus=N`; for the UP regression build accept only one and omit `ncpus=` because that build has no parser. In both cases pass guest-visible `pocket.expected_cpus=N`, require it in pocket-init, and compare it with the online count.
6. Validate requested memory against the selected profile's alignment, minimum and layout-tested `effective_max_memory_bytes`; pass exact UML-only `mem=M` plus guest-visible decimal `pocket.expected_memory_bytes=B`, require the alias in pocket-init, and reject any HELLO accepted-byte inequality. UML consumes `mem=` before `/proc/cmdline` is created, so the guest validates the alias against `/proc/uml_physmem_bytes` rather than trying to parse the consumed option. Separately validate disk, FD, process and signal limits.
7. Create a private mode-0700 run directory with an opaque random ID and safe, read-only launch aliases for verified artifacts that must appear on the UML kernel command line. Reserve `root.cow` as a required-absent leaf name but do not create it: UBD would parse a pre-created empty file as an invalid COW.
8. Create a framed control socketpair and separate stdin, stdout and stderr channels; create a PTY only for terminal mode.
9. If networking is requested, create the slirp/BESS configuration, sockets and lifetime channels without starting an unguarded process.
10. Create a private executable-temporary directory, set TMPDIR/TMP/TEMP to it, and use the same operation-level probe that selected it; never silently fall back to a host-global temporary path.
11. Verify the exact-generation lease remains held, then spawn the per-run lifetime guard, atomically transfer its crash-releasable lease descriptor and lifetime channels, sanitize the environment, assign stable FD numbers, close every unintended FD, and have the guard launch optional slirp and UML as separate process groups in the required readiness order. Failed spawn releases the parent lease exactly once; after successful transfer the guard holds it until every child and COW use ends.
12. UML UBD now creates and initializes `root.cow` over the selected immutable base. Before sending START, require the leaf to appear, wait within the boot deadline, validate its COW-v3 header and exact backing identity, and record the ephemeral binding. A requested future retention operation may publish a profile/UBD-format sidecar only after this validation; the MVP always discards the COW.
13. Complete HELLO validation, send START only after the post-spawn COW validation above, and then require READY. No pre-spawn step claims to validate a file that only UML can create.

Normal FD and path hygiene remain correctness requirements even though inputs are trusted: use CLOEXEC by default, private directories, file-relative operations, explicit artifact types, and no shell interpolation. Every path placed on a UML kernel command line is an absolute, runtime-managed path. Because the UBD grammar reserves comma and colon and the kernel command line reserves whitespace, configured runtime/cache roots must exclude those characters; generated components use a closed ASCII alphabet and bounded opaque hexadecimal IDs. A dynamic bundle prefix must also exclude colon because the loader's library-path value is colon-delimited. Before exec, validate every full path against the pinned UBD COW backing-path limit and the tighter pinned `umid`/Unix-socket limits. User-supplied local source paths are copied to managed safe paths before any colon-delimited Skopeo transport string is constructed and again before they can reach UML.

### Illustrative workload boot

~~~text
[pocket-guard child pre-exec: set+verify PER_LINUX|ADDR_NO_RANDOMIZE]
/absolute/user-prefix/profiles/PROFILE_ID/PROFILE_REVISION/host/lib/PROFILE_LOADER
  --inhibit-cache
  --library-path /absolute/user-prefix/profiles/PROFILE_ID/PROFILE_REVISION/host/lib
  /absolute/user-prefix/profiles/PROFILE_ID/PROFILE_REVISION/host/libexec/linux-uml
  mem=PROFILE_VALIDATED_MEMORY
  ncpus=PROFILE_VALIDATED_N
  seccomp=on
  umid=run-OPAQUE_ID
  uml_dir=/absolute/runtime-root/run-OPAQUE_ID/uml
  initrd=/absolute/runtime-root/run-OPAQUE_ID/workload-initramfs.cpio
  rdinit=/init
  ubd0=/absolute/runtime-root/run-OPAQUE_ID/root.cow,/absolute/cache-root/GEN/base.ext4
  con=null
  con0=fd:14,fd:14
  ssl=null
  ssl0=fd:10,fd:10
  ssl1=fd:13,fd:13
  ssl2=fd:11,fd:11
  ssl3=fd:12,fd:12
  pocket.expected_memory_bytes=PROFILE_VALIDATED_MEMORY_BYTES
  pocket.expected_cpus=PROFILE_VALIDATED_N
  quiet
  noreboot
  panic=1
~~~

`PROFILE_ID`, `PROFILE_REVISION`, `PROFILE_LOADER`, and `PROFILE_VALIDATED_N` come from one verified artifact manifest. The guard personality step precedes either loader form and is asserted by the profile's launch contract; it is not a shell command or a caller-selectable optimization. The illustrated command is for an SMP-capable x86 or arm64 profile and may substitute 4. A qualification-only `CONFIG_SMP=n` arm64 launch validates a one-CPU request but removes the entire `ncpus=PROFILE_VALIDATED_N` argv element while retaining the guest-visible expected-CPU alias. Recognized UML `mem=` and `ncpus=` options are consumed and are absent from `/proc/cmdline`; the paired `pocket.expected_*` aliases are therefore mandatory independently authenticated expectations, not redundant fallbacks. The example maps the bidirectional guest console endpoint to size-limited diagnostic FD 14, `/dev/ttyS0` to bidirectional control FD 10, `/dev/ttyS1` to input FD 13, `/dev/ttyS2` to output FD 11, and `/dev/ttyS3` to error FD 12. FDs 10 through 14 are full-duplex Unix socket endpoints even where the guest protocol uses only one direction; this avoids UML's null channel attempting to register `/dev/null` with epoll and logging `EPERM`. The supervisor never sends console input and rejects bytes received in a direction the protocol declares unused. Exact device names and channel grammar are locked to each profile revision. Pocket-init puts every serial endpoint into raw mode before transferring framed or workload bytes. In nonterminal mode it connects the workload to three pipes and pumps them independently with bounded backpressure. In terminal mode it connects the workload to a guest PTY slave, merges terminal output as normal PTY semantics require, and transports raw master bytes over the input/output serial pair.

When networking is enabled, add the pinned vector BESS or inherited-FD argument. UML logs use a captured, size-limited descriptor and never share the framed control stream.

The supervisor waits for a bounded HELLO and READY handshake. A timeout, protocol error, early UML exit, or backend failure transitions directly to cleanup with a stable diagnostic.

### Guest init sequence

The trusted workload initramfs contains a static pocket-init and the minimum early-boot files. Pocket-init remains the VM's true PID 1 and keeps its root in initramfs: Linux rootfs cannot be detached with pivot_root. A supervised child receives the image root with `chroot`, which is a correctness mechanism for this trusted profile, not a hostile-code boundary.

1. Mount the initramfs-side devtmpfs, proc, sysfs, tmpfs /run and devpts needed by pocket-init. Bring the guest's existing `lo` interface administratively up before HELLO in the initial network namespace for every network mode. Network-none therefore retains IPv4 localhost semantics without attaching any UML NIC or starting a host network helper; under the initial `CONFIG_IPV6=n` profiles an `AF_INET6` socket must fail with the profile's expected unsupported-family error.
2. Require the guest-visible expected-CPU and expected-memory aliases from `/proc/cmdline`; UML has already consumed its own `ncpus=` and `mem=` arguments, so their absence is expected and they are never inferred or defaulted by guest code. Compare the aliases with the online CPU count and the exact accepted UML physical-memory bytes read from the revision-bound `/proc/uml_physmem_bytes` ABI. Then open the serial control and I/O devices, put every endpoint in raw mode, and send HELLO containing non-circular kernel/init/guest-contract build IDs, host and guest ABI identities, guest page size, CPU-state/HWCAP policy, online CPU count, and accepted bytes. The supervisor has already hashed the final kernel/initramfs bytes before launch; it maps the reported IDs to the host-selected external profile manifest and compares every field, including requested versus accepted memory, before sending START. A mixed kernel/initramfs/helper bundle or silent CPU/memory downgrade fails without asking an artifact to report its own digest or semantic profile name.
3. Receive a bounded START request containing the globally immutable `generation_id`, its non-circular `derivation_key`, canonical descriptor/config platform tuple, selector-policy ID, root-layout and filesystem contracts, plus command, environment, numeric user/group and account-resolution evidence, working directory, rlimits, hostname, root mode, terminal and network parameters. The protocol's reserved managed-volume list must be empty in the MVP. Retain the contract fields for reconciliation after the root mount and before READY. The host has already recomputed and verified the final ID under lease; pocket-init reconciles the in-filesystem marker against the derivation key, account-database digest/evidence and contracts, not against a circular embedded output ID.
4. Mount /dev/ubda read-write at /volume; verify the expected root structure and `/volume/.pocket-generation.cbor` against START; require the image tree at /volume/rootfs and keep ext4 lost+found outside it.
5. Recompute the canonical account database from the mounted completed root, require its digest to match the marker/START, and reconcile START's already numeric User/Group/supplementary evidence without accepting a raw name. Resolve executable and WorkingDir beneath the image root without escaping it and create an absent WorkingDir, generated-file bind targets, and required proc/sys/dev/dev/pts/dev/mqueue/dev/shm/run directories while the private COW is writable.
6. Create the workload child with new guest PID, mount, UTS and IPC namespaces. While it still has the temporary guest `CAP_SYS_ADMIN` setup authority, call `sethostname` in the new UTS namespace and verify `/proc/sys/kernel/hostname` equals START. Later verify that the generated `/etc/hostname` content agrees with that effective hostname. It becomes PID 1 in its PID namespace while pocket-init remains PID 1 in the parent guest namespace. Keep the VM's initial guest network namespace unless an independently tested network-namespace setup is requested.
7. In the child's mount namespace, first make `/` recursively private with MS_REC|MS_PRIVATE and verify that propagation cannot reach pocket-init's parent namespace. Then bind /volume/rootfs onto /newroot and remount that bind `nodev` before workload execution; this disables device nodes preserved anywhere in the OCI image, not only entries under `/dev`. Mount fresh proc, a policy-qualified sysfs view, a separate device-capable curated tmpfs `/dev`, devpts, `/run`, mqueue and POSIX shared-memory views at their pre-created supported destinations. No additional UBD or persistent data volume is attached in the MVP. `/dev/shm` is its own `nodev,nosuid` mode-1777 tmpfs with a fixed profile-bound 64 MiB size in `workload-mounts-v1`; making its size configurable requires a protocol/profile revision and an effective-run report. Image `/tmp` is not overmounted: writable-root mode preserves its image contents and permissions, while root-readonly mode makes it read-only unless a future explicit tmpfs/mount option is versioned. Pocket-init creates only the declared safe character devices and links (`null`, `zero`, `full`, `random`, `urandom`, `tty`, `console`, `ptmx`, and `/dev/fd` links where supported) on the curated `/dev` mount. It never exposes `/dev/ubd*` or another block node on that device-capable mount. Acceptance tests exercise `shm_open`, cross-process mapped sharing, the 64 MiB admission boundary, cleanup after normal/forced exit, and mount flags; separate `/tmp` fixtures prove image-content preservation and read-only-root behavior.
8. Create generated resolv.conf, hosts and hostname files on the private `/run` tmpfs and bind them read-only with `nodev,nosuid,noexec` onto explicitly resolved targets. Follow and revalidate each symlink component using chroot semantics only while the result remains beneath the image root; create missing in-root parents/leaf targets before the root remount, and fail on an escape, loop, special-file target or excessive chain. The network-none revision writes an empty resolver file, `127.0.0.1 localhost` plus the selected hostname in hosts, and the exact selected hostname plus newline in hostname; a future networked revision must version and report its resolver contents. After chroot, pocket-init rereads all three binds and requires exact content, including agreement between `/etc/hostname` and the already verified UTS hostname.
9. Verify `ST_NODEV` on the `/newroot` bind in every mode. If read-only root was requested, remount it `ro,nodev,nosuid` after path preparation and verify all three flags; `no_new_privs` supplies the matching exec-time elevation guard. Writable-root mode deliberately omits `nosuid` so the separately stated trusted set-ID/file-capability policy remains possible, while retaining `nodev`. Generated files and fixed runtime pseudo-filesystems remain separate mounts and receive their own explicit flags.
10. In the still-privileged child, first remove every final-policy-disallowed capability from the future bounding set and clear inheritable/ambient state, while temporarily retaining only the current permitted/effective setup authority needed for the remaining proc mount and root transition (including `CAP_SYS_ADMIN` and `CAP_SYS_CHROOT`). Close every FD or directory handle which refers outside `/newroot`. Change cwd to `/newroot`, call `chroot(".")`, immediately change cwd to `/`, and verify both cwd and root resolve as `/` inside the new root. Only then install the exact final permitted/effective allowlist with inheritable and ambient sets empty, which removes the temporary setup capabilities. Apply umask and rlimits, then groups, GID and UID in the order defined below; for a non-root target explicitly verify final capability sets are zero. Chdir to the configured WorkingDir as the final identity, then exec argv directly without an implicit shell.
11. Use a CLOEXEC synchronization pipe: an exec failure writes a bounded error record; EOF means exec succeeded. Send READY only after the parent observes that result.
12. Forward supported signals and terminal resizes to the namespace-init workload. When that PID exits, the guest kernel terminates any remaining members of its PID namespace, including daemonizing and double-forked descendants; report the namespace init's exact exit code or signal.
13. After the child namespace is gone, sync and unmount /volume from pocket-init's original mount namespace, report filesystem status in EXIT, and power off normally.

Every mount, bind, remount, namespace and chroot operation in this sequence is implemented by the guest kernel against guest virtual devices; the host supervisor performs no mount or namespace syscall. The root-transition test must prove that the workload cannot see the initramfs tree through retained FDs, that PID-namespace descendants are gone after namespace-init exit, and that pocket-init can cleanly unmount the root afterward.

Guest capabilities are a functional contract even though they are not a host-security boundary. Each immutable profile revision publishes a `guest_capability_policy_id` and an exact allowlist; arbitrary OCI runtime-spec capability overrides are outside the MVP. `fixed-capabilities-v1` allows only `CAP_CHOWN`, `CAP_DAC_OVERRIDE`, `CAP_FOWNER`, `CAP_FSETID`, `CAP_KILL`, `CAP_SETGID`, `CAP_SETUID`, `CAP_SETPCAP`, `CAP_NET_BIND_SERVICE`, `CAP_NET_RAW`, `CAP_AUDIT_WRITE`, and `CAP_SETFCAP`. Pocket-init removes every other kernel-reported capability from the bounding set before the final privileged setup and clears inheritable/ambient state, but bounding removal deliberately does not revoke the setup process's current permitted/effective capabilities. It uses that temporary authority for the remaining mount and cwd-safe `chroot`, then immediately installs the exact allowlist in effective and permitted state while requiring inheritable and ambient to remain empty before identity change or exec. This final capset unconditionally excludes `CAP_SYS_CHROOT`, `CAP_SYS_ADMIN`, `CAP_SYS_RAWIO`, `CAP_MKNOD`, `CAP_SYS_MODULE`, `CAP_SYS_BOOT`, `CAP_SYS_PTRACE`, `CAP_SYS_TIME`, `CAP_MAC_ADMIN`, and any future capability not added by a new versioned policy. It closes all outside-root directory FDs and leaves neither an outside cwd nor a handle from which the workload can perform a classic chroot escape.

Identity/capability ordering is explicit. A non-root target initially receives no runtime-granted capabilities: pocket-init applies supplementary groups, GID and UID without `PR_SET_KEEPCAPS`, then explicitly zeros permitted/effective/inheritable and ambient sets. A root target remains UID 0 but receives only the profile's final allowlist after the root transition; ambient capabilities are always cleared. In the default writable-root mode, trusted image set-ID executables and separately qualified file capabilities are allowed to elevate a non-root process only within the already reduced profile bounding set; the effective result and blocked-capability failures are fixture-tested. In root-readonly mode, `PR_SET_NO_NEW_PRIVS` suppresses both set-ID and file-capability elevation. Thus preserved set-ID/file-capability metadata has explicit mode-dependent execution semantics rather than silently contradicting the capability policy. Future caller-configurable capability or `no_new_privs` semantics require a versioned protocol change.

`--root-readonly` is enforced rather than advisory. In that mode pocket-init also sets `PR_SET_NO_NEW_PRIVS`, retains only the same exact profile `fixed-capabilities-v1` allowlist used for a root target in writable mode, and verifies that no set-ID or file-capability transition can regain an excluded capability. The read-only difference is NNP plus mount flags, not an undocumented second capability subset. OCI metadata may contain arbitrary preexisting device nodes at any path, so hiding `/dev/ubd*`, dropping `CAP_MKNOD`, and dropping `CAP_SYS_RAWIO` are not treated as sufficient: the complete image-root bind is verified `nodev`, and the only device-capable mount is the curated `/dev` that contains no block devices. Together with `CAP_SYS_ADMIN` and `CAP_SYS_CHROOT` removal, this prevents guest UID 0 from reopening the backing UBD, mounting it elsewhere, remounting the root writable, or escaping the chroot to reach pocket-init's writable `/volume` view. Acceptance tests as UID 0 require ordinary image-root writes—including image `/tmp`—to fail read-only; `mount -o remount,rw`, mounting a recreated block node, `mknod`, direct block-device access through a preexisting out-of-`/dev` UBD node, and a cwd/second-chroot escape followed by a `/volume/rootfs` write all to fail. The explicitly separate generated-file binds, curated `/dev`, `/run` and `/dev/shm` retain their declared write semantics; these are enumerated exceptions, not evidence that the image-root remount failed. Pocket-init itself retains the outer-namespace authority needed to sync and unmount after the workload exits.

### Control protocol

Use a length-prefixed bounded binary format such as CBOR with a versioned schema.

~~~text
HELLO     protocol, guest_contract_id, init_build_id, kernel_build_id,
          host_elf_machine, guest_uts_machine, guest_page_size,
          cpu_state_hwcap_policy, guest_capability_policy, features, online_cpus,
          accepted_physmem_bytes
START     profile_id, profile_revision, generation_id, derivation_key,
          descriptor_config_platform, effective_platform, selector_policy,
          root_layout, filesystem_contract, process, user, cwd, rlimits,
          volumes, terminal, network
READY     guest_pid, effective_config
SIGNAL    sequence, signal
RESIZE    sequence, rows, columns
EXIT      code or signal, timing, fs_status
ERROR     stage, stable_code, errno, diagnostic
SHUTDOWN  sequence, grace_ms
~~~

Every frame, string, array and map has a hard bound. State-changing messages are accepted only in their corresponding lifecycle state. Workload stdout and stderr never enter this parser.

### Image command semantics

Define deterministic Docker-compatible behavior:

- With no CLI command, argv is Entrypoint followed by Cmd.
- CLI positional arguments replace Cmd but retain Entrypoint.
- An explicit entrypoint override replaces Entrypoint and clears the image Cmd;
  explicit CLI positional arguments, when present, are the replacement Cmd
  appended to that entrypoint.
- If Entrypoint is empty, Cmd or its CLI replacement becomes argv.
- Empty final argv is an error.
- Arrays are executed directly; Pocket never inserts a shell. If argv[0] contains no slash, pocket-init performs deterministic executable search using the final PATH inside the chroot; slash-containing values are resolved under normal guest path rules.
- On Linux the environment begins with Moby's default `PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin` and `HOSTNAME` equal to the selected workload hostname. Image Env replaces either default by key and appends its other entries in image order, then CLI environment overrides the last value by key. `TERM` is not synthesized because terminal mode fails closed, and `HOME` is not synthesized because current Moby's daemon environment path does not add it; image or CLI values for either are preserved. The CLI accepts only exact `KEY=VALUE`, not host-value lookup or the Docker API's key-only unset form.
- WorkingDir is created if absent during writable root preparation and before privilege drop, matching the documented product behavior.
- User accepts `user`, `uid`, `user:group`, `uid:gid`, `uid:group`, or `user:gid`; named components resolve only against the generation's hash-verified canonical `accounts.cbor`, which the builder and validation UML independently derive from the completed rootfs. Missing, duplicate or malformed records produce typed errors. With no explicit group, the user's passwd primary GID and deduplicated image `/etc/group` memberships apply; a numeric UID absent from passwd uses the versioned GID-0/no-supplementary fallback. With an explicit group/GID, image supplementary groups are suppressed, and only an explicitly supplied runtime supplementary list is used. The immutable build record's resolution evidence is authoritative only when the unchanged image-config User is selected; a stored unresolved image User fails only when that default is actually chosen. A CLI user/group override is resolved exactly once per run from the verified sidecar using the same grammar and policy; the host sends numeric UID/GID/supplementary IDs plus canonical resolution evidence in START, and pocket-init recomputes the account-database digest and reconciles that evidence without accepting raw names. Tests cover unresolved-default-plus-valid-override, unchanged image User, every named/numeric override form, explicit-group supplementary suppression, and rootfs/sidecar/evidence mismatch rejection.
- StopSignal is used when valid unless the CLI overrides it.
- ExposedPorts create no forwarding automatically.
- Image Volumes remain inspectable hints but create no mount or host exposure; persistent managed volumes are outside the MVP.
- A preserved Healthcheck is inspectable but not scheduled in the MVP.

### Filesystem and volume semantics

- The root is ephemeral and writable through COW by default.
- A read-only-root option exposes the composed image root read-only to the workload after the bounded preparation step; runtime-generated files, curated `/dev`, `/run`, fixed-policy `/dev/shm` and kernel pseudo-filesystems are separate guest mounts with their own explicit flags. Image `/tmp` is not an implicit exception. The profile-bound capability drop and curated `/dev` make the image-root policy enforceable even for trusted guest UID 0 rather than merely advisory.
- Persistent managed volumes -- named, UBD-backed, with their own lifecycle -- remain rejected. A later version must define a name-to-file registry, immutable format/identity record, exclusive-writer lease (or a qualified clustered filesystem), deterministic UBD slot mapping, START reconciliation, destination-conflict and mount-flag policy, dirty-shutdown/fsck recovery, and crash-safe detach before any of that is exposed.
- Host-directory sharing *is* implemented, through hostfs rather than a second block device, and needs none of that machinery: `--volume HOST:GUEST[:ro]` hands the guest the caller's own directory. One directory is used by one run at a time, enforced by an exclusive lock on the directory itself, and a second run is refused by name rather than serialized. What hostfs does not give is coherence with host-side changes, which the UML HOWTO states outright.
- Stdin/stdout streaming is the simplest small-data interface.
- Committing root.cow to an OCI image is a future feature, not a rename operation.

## Optional user-mode networking

Network mode none remains the deterministic default. Network mode slirp starts one pinned slirp4netns BESS process for one UML instance and requires neither TUN nor a host user namespace.

### MVP direct BESS path

Because all guest code is trusted, the documented pathname transport is acceptable and simpler:

1. Create BESS, API and lifetime objects in the private run directory.
2. Have pocket-guard start slirp4netns with target type bess, ready FD, exit FD, API socket and BESS socket path, using the pinned IPv4-only argv and explicitly omitting slirp's IPv6-enable option.
3. Wait for the BESS socket pathname to appear, not for readiness.
4. Start UML with the tested equivalent of vec0:transport=bess,dst=PATH.
5. UML's connection releases slirp's accept path; only then wait for the readiness byte.
6. Configure guest IPv4 address 10.0.2.100/24, gateway 10.0.2.2 and DNS 10.0.2.3 unless the pinned version reports a different explicit contract.

Waiting for slirp readiness before UML connects can deadlock because current BESS initialization accepts the UML connection before signalling ready.

### Optional connected-FD refinement

Current UML vector source also accepts an already-connected packet FD. A later robustness improvement can have the supervisor connect AF_UNIX SOCK_SEQPACKET to BESS and pass the FD to UML, eliminating a pathname dependency after setup. This must be proven against the pinned UML/slirp pair and is not an MVP security gate.

### Port forwarding

- Only explicit CLI forwards are created.
- Default host bind address is 127.0.0.1.
- Ports below the host's unprivileged-port threshold are rejected when unavailable.
- The supervisor records every slirp forwarding ID.
- Rollback and normal cleanup remove every forwarding entry.
- Image ExposedPorts remains documentation.

The initial slirp profile provides ordinary outbound access, not destination-filtered egress. DNS, IPv6, LAN reachability and host-loopback behavior must be documented and tested. IPv6 remains disabled until explicitly implemented.

## Lifecycle and cleanup

~~~text
NEW -> RESOLVING -> IMPORTING? -> PREPARING -> NETWORKING? -> BOOTING
                                                              |
                                                           READY
                                                              |
                                                           RUNNING
                                                              |
                                                           STOPPING
                                                              |
                                                EXITED -> CLEANING -> GONE
~~~

Every transition owns an explicit resource list and idempotent rollback. The CLI/supervisor is not the sole lifetime anchor. It creates a small, deliberately single-threaded per-run pocket-guard and a liveness pipe before starting external processes. The guard:

- is the direct parent and child subreaper for UML and slirp;
- creates each UML or slirp child in a separate, recorded process group and tracks direct children with pidfds where available;
- performs `setpgid(0, 0)` in the freshly forked child before exec, while it is still impossible for the parent to race the child into a different lifecycle state. Making UML a process-group leader deliberately causes Linux 7.2 UML's unconditional, unchecked `setsid()` to fail with `EPERM`, so the process cannot escape the guard-owned group. Launch tests record the guard, UML, SID and PGID relationships before readiness and prove group termination; a merely parent-side `setpgid` is not acceptable;
- launches every direct child from its sole lifetime thread, makes the child set PR_SET_PDEATHSIG to SIGKILL and recheck its expected parent before exec, and verifies the executable has no set-ID bits or file capabilities that could clear the setting;
- holds the crash-releasable cache lease lock and slirp exit FD;
- performs normal cleanup on an explicit command and forced cleanup when the supervisor's liveness pipe reaches EOF;
- reaps reparented UML helpers/stubs and does not exit until the tested process tree is empty.

This is a per-run guard, not a daemon. PR_SET_PDEATHSIG follows the creating parent thread, which is why the guard's process-launch and lifetime loop must remain on one thread. The pinned/patched UML source must establish the same race-free invariant before each per-mm stub exec. If the guard itself is killed, its direct children receive their parent-death signal; kill-to-zero tests then verify the source-level contract. If any UML creation path cannot meet it, the no-cgroup baseline is not releasable until a reliable upstream or launcher fix exists.

Normal stop:

1. Send the configured stop signal through the trusted guest control channel.
2. Wait the configured grace interval.
3. If the namespace init remains alive, send SHUTDOWN so pocket-init kills it, waits for its PID namespace to drain, and records the forced signal.
4. Ask pocket-init to sync, unmount and power off; absence of a bounded acknowledgement escalates to forced host cleanup.
5. Have pocket-guard reap UML, slirp and every reparented helper.
6. Close FDs and release forwards and sockets.
7. Delete the COW, or atomically register a retained COW's durable reference to its exact base generation; only then release the run's cache lease.

Forced stop:

1. Pocket-guard closes the slirp lifetime FD.
2. Signal the UML process group and every recorded/reparented child.
3. Wait a bounded interval.
4. Send SIGKILL to remaining known children and reap them.
5. Mark the COW crash-dirty; never publish or commit it implicitly.
6. Delete it or atomically register an explicit retained dirty-COW reference before releasing the crash-releasable generation lease.
7. Clean only the validated owned run directory.

CI must prove that each pinned cooperative implementation does not leave its CPU threads, `uml-userspace` stub processes, UBD helpers, or slirp descendants after normal cleanup, supervisor SIGKILL, guard SIGKILL, or simultaneous cancellation. A delegated cgroup may provide cgroup.kill as an optional final sweep, never as the baseline mechanism.

Durable run state is atomically updated so pocket gc can recover after crashes without broad filename matching or deleting an active generation. A lease is live only while its guard-held lock is live; recovery additionally validates recorded PID start time and owned paths. Stale records can be reconciled only after acquiring the lock, so PID reuse or a dead supervisor alone cannot collect a live run.

## Resource and scheduling model

| Setting | What it controls | What it does not guarantee |
|---|---|---|
| --cpus N / ncpus=N | Number of online UML virtual CPUs up to the qualified profile maximum, even when oversubscribed | CPU time quota, guaranteed simultaneous host execution or same-process thread scaling |
| optional --cpuset | Allowed host CPU affinity inherited by UML threads | One-to-one vCPU pinning unless implemented explicitly |
| mem=M | Exact UML physical-memory request, accepted byte-for-byte through the profile's measured-memory ABI | Total host RSS, page cache, process overhead or swap behavior |
| root image size | Guest filesystem capacity and maximum COW address space | Host free space reserved for sparse allocation |
| rlimits | Selected per-process resources | Aggregate UML process-tree accounting |
| timeout | Wall-clock lifecycle limit | CPU consumption before timeout |
| log limit | Captured output volume | Guest writes inside its disk |
| delegated cgroup | Aggregate CPU, memory, PID and I/O controls when available | Portability to hosts without delegation |
| filesystem quota/reservation | Host allocation protection when available | Portability to filesystems without it |

The baseline reports observed host RSS, process/thread count, COW allocation, elapsed time, effective affinity/cpuset, optional cgroup quota, and whether the host observation qualifies an N-vCPU run for scaling claims. It must not label mem as a complete memory limit or ncpus as a CPU quota, and it must not refuse an otherwise valid CPU request solely because the host currently oversubscribes it.

Before each conversion and run, apply a best-effort admission margin using current cache/run filesystem free blocks and inodes. This is not a reservation: concurrent consumers can invalidate the estimate, and sparse files consume real space as pages are dirtied. ENOSPC must yield a stable error and crash-recovery record. Only the optional quota/reservation adapter may make a hard host-capacity claim.

## Trust assumptions and engineering hygiene

The runtime deliberately trusts the guest. UML's cooperative backend is unsuitable for hostile code, and hostfs exposes real host data to it. Therefore:

- do not market the product as a sandbox, tenant boundary, or security isolation;
- do not accept untrusted public workloads under this profile;
- keep modules and unused host-facing devices off, and mount nothing from the host unless a `--volume` explicitly names it: HOSTFS is built in for that feature, but a run with no volume request mounts none of it, so the default remains a guest that can reach nothing of the host's;
- treat a shared directory as host state with host permissions, outside everything the immutable store guarantees: a workload can write there anything the invoking user could, which is the purpose of the feature and the caller's judgement to make;
- distinguish guest authority from host authority. `--privileged` grants a workload every capability the *guest* kernel implements, which is what a container engine inside the guest needs, and changes nothing about the host: the guest kernel is the isolation, and the host boundary stays an unprivileged process that no guest capability reaches. This is the one place a full-kernel guest is stronger than a namespaced container, which cannot be handed such privileges safely because it shares the host's kernel;
- use digest verification, TLS policy and immutable cache records for integrity and reproducibility, not as a claim that guest code is contained;
- use private directories, CLOEXEC, explicit FDs, atomic publication, bounded protocols, and exact cleanup to prevent ordinary bugs and cross-run confusion;
- validate formats and sizes because trusted inputs can still be truncated, corrupt, incompatible, or operationally excessive;
- document that a UML or guest-kernel bug may affect any resource accessible to the invoking host user.

If adversarial isolation becomes a requirement, stop and redesign around a secure UML execution path plus an outer boundary, or use a hardware-backed VM. Do not reuse these trusted cooperative profiles.

## Detailed implementation plan

The phases retire feasibility risks before investing in a polished product. A phase is complete only when its exit gate is automated and reproducible.

Current execution status (2026-08-28) is deliberately narrower than the plan:

- The architecture/source audit is complete enough to reject the earlier false premise: native arm64 UML is feasible and the pinned external seed already contains SMP. This is research evidence, not a passed Pocket arm64 gate.
- The seed's exact merge base is Linux 7.2-rc4 (`1590cf0329716306e948a8fc29f1d3ee87d3989f`), not the final Linux 7.2 release. Pocket therefore has two non-interchangeable arm64 source checkpoints: reproduce the immutable 54-patch seed to validate the published result, then review and transplant the required arm64/generic subset onto the exact selected maintained release (initially final Linux 7.2 or a later explicitly selected source), producing a new project-owned tree identity and rerunning every affected gate. Neither checkpoint may be described as unmodified mainline arm64 UML.
- The patched upstream Linux 7.2 x86_64 artifact boots locally under `seccomp=on` with exact 1, 2, 4, 12 and 16 online-vCPU observations, exact 64 MiB, 256 MiB and 4 GiB accepted-memory observations through the full workload lifecycle, and a separate-process four-vCPU scaling probe measuring 3.48x-3.86x depending on host load. The production lifecycle initially reproduced `bad: scheduling from the idle thread!`, RCU GP-kthread starvation, and `Kernel panic - not syncing: Segfault with no mm` in the scheduler/RCU wakeup path: of twenty fresh `CONFIG_SMP=y ncpus=1` workload boots ten failed, and all twenty corresponding `ncpus=4` boots failed to complete cleanly. Instrumenting the first `dequeue_task_idle` gave the exact call chain: `sigio_handler` -> `free_irqs` -> `um_free_irq` -> `free_irq` -> `__synchronize_irq` -> `irq_work_sync` -> `synchronize_rcu` -> `wait_for_completion` -> `schedule`. UML was calling a sleeping function from the SIGIO signal handler. Locked patches `0003`-`0005` move that work into process context, and every lane now runs clean.
- `ncpus=1` on a `CONFIG_SMP=y` UML binary is not a uniprocessor safety mode: it still compiles and exercises the SMP/Tree-RCU machinery implicated by the failure. The `CONFIG_SMP=n`, `CONFIG_NR_CPUS=1`, Tiny-RCU control that completed twenty of twenty fresh Ubuntu 24.04 lifecycles (kernel SHA-256 `8b6d175360756104a05a1c30ba3f49a0015f2e778f1573e50f48702e89f4ed16`, config SHA-256 `41c1c28ce7cb8f42bd27748fd772b3fb2d0f1ac838c0c9f5f31ec102933109bd`, diagnostic profile revision `3ccd6e657327bf30737d9ff38c985334cfaf2306f5c99448ff4281c4d3c43cce`) correctly isolated the compiled-SMP condition, and the reason is now exact: `synchronize_irqwork()` is compiled out on uniprocessor kernels and Tiny RCU's `synchronize_rcu()` never waits, so the illegal sleeping call could not block. With the defect corrected, the SMP profile carries the multiple-host-CPU claim and no separate one-CPU fallback profile is required.
- The common Rust protocol, guard, OCI verifier, content store, workload init, builder init, independent validator init, runtime, packaging foundation, and bounded CLI exist with unit/integration coverage. The CLI implements canonical-OCI import, constrained single-image OCI/Docker archive normalization, pinned anonymous `docker://` acquisition, immutable generation publication, image process defaults and overrides, generation leases, private UBD COW launch, and a fresh read-only validator-UML pass before publication. The Rust end-to-end suite now passes for both the Ubuntu 24.04 and 26.04 fixtures, covering import, publication, independent validation, workload execution, image process defaults, named and numeric users, standard streams, the exact-length standard-input contract, exit status, normal and real-time signal semantics, stop-signal escalation, concurrent COW isolation, guest memory lanes, and OCI/Docker archive normalization. `make distro-matrix` additionally runs Debian, Alpine, Arch, Fedora, BusyBox and a scratch image. The fault, recovery, installation-portability and signing matrices remain open.
- Shell-driven probes have pulled and materialized the pinned Ubuntu 24.04 and 26.04 fixtures and run workloads through UML. Those probes establish feasibility but do not substitute for the production Rust path or its failure matrix.
- The current verified host path is intentionally amd64-specific: profile/ELF validation, OCI selection, Skopeo arguments, HostBuilder checks, runtime launch tokens, generation reconciliation, release scripts and sealed artifacts still encode `x86_64`/`EM_X86_64`/`amd64`. The guest-init sources contain some `aarch64` compile-time observation support, but that is not an end-to-end arm64 product path.
- No Pocket arm64 kernel, native host helper bundle, builder/workload initramfs, profile revision, image generation, or workload has been run or qualified on this x86_64 host. Phase 0-arm64-base and Phase 0-arm64-SMP therefore both remain unpassed; cross-compilation may prepare artifacts but can never close either native execution gate.

The x86 SMP kernel failure is corrected at the source rather than hidden by reducing `--cpus`, changing to ptrace, removing the nested PID namespace, or suppressing diagnostics. The whole sealed profile now reproduces byte-identically from an independent clean build root, and the release archive produced from each root is byte-identical. Every documented lifecycle number is produced by a committed target (`make lifecycle-soak`, `make diagnostic-lifecycle`, `make rust-release-e2e`, `make distro-matrix`, `make smp-scaling`) so it can be reproduced rather than trusted. Other release gates remain explicit and open: the source/tool build still uses the ambient host toolchain rather than a pinned sysroot; the full fault, portability, SBOM-validation, and signing-policy matrices remain open; and host libc/ABI portability is undeclared.

Critical path:

~~~text
 Phase 0-common: platform/artifact schemas and profile-independent tooling
        |
        +--------------------> Phase 2 normalization implementation may start
        |
        +--------------------------+---------------------------+
        v                          v                           v
 Phase 0-x86-SMP          Phase 0-arm64-base          later profile tracks
 [passed: patches 0003-0005]       |
        |                          v
        |                   [arm64 ncpus=1 passed]
        |                          |
        |                          v
        |                  Phase 0-arm64-SMP
        |                          |
        v                          v
 [x86 SMP passed]          [arm64 SMP passed]

 ANY ONE applicable passed-profile gate above (logical OR, per profile)
        |
        +---------------------> Phase 1: supplied-ext4 runner
        |
        +----> Phase 2 implementation + native-profile executable integration

        [Phase 1 gate] AND [Phase 2 executable-integration gate]
                                   |
                                   v
                        Phase 3: builder/cache
                                   |
                                   v
                       Phase 4: image semantics
                                   |
               +-------------------+-------------------+
               |                                       |
               | networkless revision                  | revision advertises BESS
               v                                       v
       Phase 6: reliability                    Phase 5: network
               ^                                       |
               +---------------------------------------+
                                   |
                                   v
                     Phase 7: per-profile release
~~~

The gate is an OR across independently selected profiles, never an AND across architectures. Passing x86 SMP unlocks a multi-vCPU x86 release without waiting for arm64. A separately qualified x86 `CONFIG_SMP=n` profile may unlock a one-CPU x86 product lane, but it neither passes the x86 SMP gate nor meets the multiple-CPU goal. Passing the arm64 base gate similarly unlocks generic arm64 work at one CPU while its SMP qualification continues; only an arm64 claim of `--cpus > 1` waits for the arm64 SMP gate. Common implementation may proceed using experimental artifacts, but every release profile waits for its own applicable Phase 0 and downstream gates. Phase 2 may proceed in parallel with Phase 1 after Phase 0-common fixes the artifact and platform contracts. Phase 3 waits for both. Phase 5 is optional for a networkless release, but Phase 6 covers every enabled feature. Calendar estimates are intentionally deferred until the selected Phase 0 tracks measure build, boot, density and target-workload behavior.

#### Current ARM64 enablement delta

ARM64 support is an integration and qualification lane, not a plan to emulate AArch64 and not a plan to invent arm64 UML or arm64 UML SMP from nothing. The present repository nevertheless cannot become an arm64 product merely by replacing one `"amd64"` string. The architecture tuple is repeated at several trust and cache boundaries, so it must be made profile-driven as one validated unit:

~~~text
x86_64 host / ELF e_machine 62  -> UML SUBARCH=x86_64 -> guest UTS x86_64 -> OCI linux/amd64 -> initial 4 KiB guest page profile
aarch64 host / ELF e_machine 183 -> UML SUBARCH=arm64  -> guest UTS aarch64 -> OCI linux/arm64 -> initial 16 KiB guest page profile
~~~

| Boundary | Current checked-in state | Required arm64 change and gate |
|---|---|---|
| UML kernel | release artifacts use upstream x86_64 UML | adopt the pinned arm64 UML series into a project-owned tree; build `ARCH=um SUBARCH=arm64`; verify the resulting host executable is little-endian ELF64 `EM_AARCH64`; boot it only on arm64 |
| Profile and artifacts | `VerifiedProfile` accepts only `x86_64`, `EM_X86_64`, `amd64`, 4 KiB guest pages and x86 policy IDs; host executables are checked as x86_64 | introduce one closed `NativeArchitectureContract` selected from the verified profile, initially permitting only the coherent x86_64 and aarch64 tuples; verify `EM_AARCH64`, `aarch64` host/UTS identity, `arm64` OCI/subarchitecture identity, 16 KiB guest-page policy, arm64 selector/HWCAP policy IDs, and every host/helper/initramfs role; reject every mixed tuple before execution |
| OCI acquisition | the layout verifier, Skopeo platform constructor, selector-policy constant and some errors select `linux/amd64` | pass the verified architecture contract into enumeration, normalization and post-copy verification; select only `linux/arm64` for the arm64 profile; implement its absent/explicit `v8` variant policy; preserve raw descriptor/config variants; prove a dual-architecture index selects exactly one native manifest and rejects ambiguity or cross-architecture fallback |
| Builder | HostBuilder platform checks and `pocket.builder.expected_architecture=amd64` are hard-coded; the production builder artifacts are x86_64 | derive selected platform, expected UTS/ELF identity, CPU-state policy and boot aliases from the same profile contract; build an AArch64 builder initramfs containing the complete native AArch64 umoci/helper closure; on native arm64, materialize a `linux/arm64` fixture and independently validate the resulting ext4 and sidecars |
| Workload runtime | launch uses `pocket.expected_architecture=amd64`; HELLO/generation reconciliation expects x86_64/amd64 | derive launch aliases and all HELLO, START, generation, executable and profile comparisons from the contract; boot an AArch64 workload initramfs and run unchanged static, glibc, musl and script entrypoints from the arm64 image; reject an amd64 image, x86 kernel/helper, wrong loader, AArch32 ELF and mixed cache generation before READY |
| Guest init sources | workload and builder init already recognize compile-time `aarch64`, UTS `aarch64`, OCI `arm64` and ELF machine 183, but only the x86_64 release closure has been built and booted | cross-build and native-build the static guest binaries for AArch64, seal their identities into the arm64 revision, then exercise syscall, signal, FP/SIMD, TLS, fork/exec, PID-1, mount and teardown paths on native arm64; source recognition alone is not qualification |
| Host helpers and packaging | release scripts, Linux config, Skopeo, e2fsprogs, loader paths, initramfs lists and profile template are x86_64-specific | create per-profile build recipes and source locks for native AArch64 guard, Skopeo, e2fsprogs, UML, guest initramfses and any loader/library closures; keep cross-built output separate from native execution evidence; publish no arm64 default until clean-host install/pull/build/run and license/SBOM gates pass |
| CPU count | x86_64 SMP is qualified through the full lifecycle after correcting the SIGIO-handler `free_irq()` defect; arm64 has only the external seed's reported result | keep x86 SMP qualification bound to the corrected source identity; first close arm64 base correctness at one vCPU, then independently qualify the already-present arm64 SMP implementation at every versioned supported count (including 2, 3, 4 and the declared maximum when within policy) with explicit `seccomp=on`, exact online counts, lifecycle stress and separate-process scaling |

The implementation order is deliberately fail-closed:

1. Add the closed architecture contract and table-driven mixed-tuple rejection tests without enabling an arm64 profile.
2. Thread that verified value through artifact inspection, OCI/Skopeo selection, build derivation, builder protocol, generation identity, workload launch and HELLO reconciliation. Remove architecture literals from production decisions; architecture-specific test fixtures may retain them.
3. Lock and reproduce the external seed at its exact Linux 7.2-rc4 merge base plus 54-commit head on recorded native arm64 hardware. Its exit record must include unmodified aarch64 Alpine and Debian boots, the reported four-online-CPU topology and dockerd startup, and a randomized paired one-versus-three-CPU separate-process scaling run. This checkpoint validates the feasibility evidence only; its artifacts remain seed-labeled, experimental and non-promotable.
4. Split and review the seed, then transplant only the required arm64 and generic UML changes onto the exact maintained source selected for Pocket (initially final Linux 7.2 or a later explicitly locked source). Resolve semantic conflicts by review, not by accepting a textually clean rebase; record the new base, ordered patch identities, final tree and source manifest. Re-run the seed-vs-project differential audit so no feature or fix disappears silently.
5. Add per-profile AArch64 build recipes for the project-owned source. Cross-builds may prove reproducibility and ELF identity, but must be labeled `unqualified` and must never be run through QEMU in a native-evidence lane.
6. On native arm64, seal an experimental one-vCPU profile and pass probe, image import, builder, validation and workload tests for `linux/arm64` images. This is the first point at which Pocket may claim a working native arm64 path.
7. Qualify the existing arm64 SMP code under the Phase 0-arm64-SMP matrix. Only a passing experimental revision may be promoted to the multi-vCPU release profile.

Every intermediate state rejects arm64 rather than silently selecting amd64, emulating instructions, downgrading CPU count, or accepting a partially parameterized architecture tuple.

### Phase 0 - Architecture source, cooperative backend and CPU qualification

Phase 0-common defines shared schemas and tooling. Each selected profile must
instantiate and pass the architecture-specific items below before that
profile's Phase 0 gate can unlock its own downstream runtime work; release additionally requires Phases 1 through 4, applicable Phase 5, Phase 6, and Phase 7. An x86
instantiation does not wait for arm64, and an arm64 instantiation does not wait
for x86. Phase 0-common delivers:

- a closed `NativeArchitectureContract` derived only from the verified profile, binding host name and ELF machine, UML subarchitecture, guest UTS machine, OCI OS/architecture/variant policy, guest page-size policy, selector policy and CPU-state/HWCAP policy; the initial allowed tuples are x86_64/amd64 and aarch64/arm64, and mixed tuples fail before helper or UML execution;
- deterministic `profile_id` selection before image resolution and immutable `profile_revision` binding of host/UML/image ABI, OCI-selector policy, helper roles, initramfses, filesystem contract, guest page size, CPU-state policy and maximum vCPUs;
- schema for a per-profile artifact manifest containing maturity, exact source/base/patch identities, toolchain, final config, role-tagged loader closures and invocation templates, and all revision-bound contracts;
- common config assertions for required and deliberately disabled features;
- a common parent-death invariant and test machinery, instantiated per selected profile with a reviewed pre-exec race patch until upstream-equivalent, architecture-specific source assertions for every host child process, parent-death arming/recheck and a non-privileged stub artifact;
- a common probe-initramfs recipe, instantiated for each selected architecture as a tiny static initramfs that reports ABI, page size, HWCAP/auxv and CPUs and runs test commands;
- reproducible native and cross-build instructions for each selected profile, whose outputs are compared after nondeterministic build metadata is normalized or explained;
- `pocket probe` prototype with stable architecture/profile reason codes;
- test profiles with UID nonzero, all capabilities zero, no KVM/TUN/FUSE, unusable user namespace, no writable cgroup, and ptrace returning EPERM.

Phase 0-x86 delivers and tests:

- exact maintained source lock at v7.0.10/v7.1 or newer containing the initial SMP, TLB synchronization and userspace-stub parent-death fixes;
- normalized x86_64 UML config with `CONFIG_SMP=y` and `CONFIG_NR_CPUS=16`, plus an asserted product/effective maximum no greater than 16;
- boot seccomp=on ncpus=1, 2, 4 and the effective maximum;
- verify nproc, /proc/cpuinfo and /sys/devices/system/cpu/online;
- inspect the UML kernel process's task directory for the CPU0 plus secondary-vCPU pthread delta, separately identify per-mm uml-userspace stub PIDs, and attribute host CPU time to both;
- prove omitted seccomp or seccomp=off with ncpus=2 fails rather than silently changing mode;
- prove seccomp=on failure produces a stable refusal;
- reject malformed ncpus syntax with a typed parse error, and reject numeric zero, negative and `effective_max_cpus+1` values before UML can clamp numeric out-of-range inputs;
- boot at the profile memory minimum, default and `effective_max_memory_bytes`, require HELLO's accepted physical-memory bytes to equal each request, and reject malformed, unaligned, zero, below-minimum and maximum-plus-alignment inputs before UML can silently shrink them;
- on a scaling-qualified host with at least N effective CPUs and near-N quota, run N separate CPU-bound guest processes and observe host parallelism;
- run one N-thread CPU-bound process and record the current non-scaling behavior;
- sustain IPI/reschedule traffic, verify UML IPI counters in /proc/interrupts, and exercise timers/signalfd on every vCPU;
- combine process churn with concurrent mmap, munmap, mprotect, page faults, fork and exit to stress the fixed TLB synchronization path;
- exercise futexes, signals, exec and clean shutdown;
- use a test hook at every UML child-creation boundary to kill the parent before and after PDEATHSIG arming and exec, proving the reviewed source invariant closes the startup window;
- boot repeatedly with ptrace attempts forced to return EPERM;
- prove a noexec default temporary directory fails with a clear diagnostic and a configured executable temporary root succeeds.

Phase 0-x86-SMP corrective gate has passed. It was a source-correction and
qualification track, not a runtime workaround, and the record below is kept as
the method that produced the fix:

1. Freeze the failing kernel/config/initramfs/profile identities, exact launch argv, host identity, exit status, bounded serial logs, and hashes of representative one- and four-vCPU failures as non-promotable evidence. Preserve a matching successful one-vCPU run so minimization does not erase the differentiating behavior.
2. Reduce the production sequence to a source-controlled lifecycle reproducer that needs no OCI registry or mutable cache: boot, mount a disposable ext4/COW root, create the nested PID namespace, fork/exec a short workload, reap its descendants, unmount, and power off. Keep the full Rust path as a confirmation lane rather than making it the only reproducer.
3. Run an exact three-way build/launch matrix from the same authenticated Linux source: true `CONFIG_SMP=n`, `CONFIG_NR_CPUS=1`; `CONFIG_SMP=y`, `ncpus=1`; and `CONFIG_SMP=y`, `ncpus=4`. Separately vary raw boot, ordinary fork/exit, nested-PID-namespace churn, seccomp-stub churn, timers, RCU synchronization and teardown. This distinguishes compiled SMP machinery from online-CPU count and workload trigger; an SMP build at `ncpus=1` is never labeled UP. The first cell established that the isolated UP/Tiny-RCU build passed 20/20 fresh full lifecycles with clean teardown, and the SMP cells failed. Minimization then showed that the differentiator is not the online CPU count but whether `CONFIG_SMP` compiles in the blocking `synchronize_irqwork()`/Tree-RCU path reached from the SIGIO handler.
4. Audit every change from the initial upstream UML SMP series through the pinned Linux 7.2 source and current upstream/stable heads. The 2026-08-28 audit found no later change to the relevant UML SMP/current/signal files and no matching published fix, so no unrelated generic scheduler/RCU change may be guessed or cherry-picked as a remedy.
5. Add a diagnostic-only kernel patch that records host TID, TLS UML CPU, `current`, `cpu_rq(cpu)->curr`, scheduling class/state/on-rq fields, IRQ/preemption nesting, signal number and `siginfo` sender at signal ingress, deferral/replay, `__switch_to`, IPI handling and the pre-failure scheduler boundary. Use bounded per-CPU buffers or rate limiting so logging cannot create the race being measured. Assert and stop at the first current/runqueue ownership mismatch instead of continuing into secondary corruption.
6. Test source-derived hypotheses independently. In particular, determine whether process-directed `SIGCHLD` from seccomp stub or namespace child churn can execute against the wrong vCPU/current state, whether timer or IPI delivery crosses TLS CPU ownership, and whether deferred signal replay is per-vCPU consistent. RCU wakeup tuning, periodic ticks, CPU affinity and reduced CPU counts are diagnostic controls only. The already-failed periodic-tick build prevents a NO_HZ config change from being accepted as a fix.
7. Implement the smallest source-level correction supported by the instrumentation. If signal routing is the defect, define explicit ownership and forwarding for process-directed child events and make pending/mask state coherent per vCPU; if current/runqueue ownership or context migration is the defect, fix that invariant at its source. Do not suppress `dequeue_task_idle`, serialize the whole VM, remove the nested PID namespace, switch to ptrace, retry a panicked run, or treat successful workload output followed by a kernel failure as success.
8. Review the correction for signal-safety, memory ordering, lost/coalesced events, PID reuse, CPU hotplug/startup/teardown, nested delivery, async-signal-safe host operations and the `ncpus=1` SMP case. Add deterministic race hooks and focused regression tests. Seek upstream UML review when feasible, but keep Pocket's exact reviewed patch and rationale locked rather than depending on an unmerged moving branch.
9. Add the accepted change as the next ordered Linux patch; update the patch-series digest, patched Git-tree identity, canonical source manifest, config identity and artifact/profile revision. Rebuild in two fresh output roots, compare all deterministic outputs, and rerun the pre/post-build source audit. Diagnostic binaries and logs must never be sealed into a release profile.
10. Before resuming the full release suite, require zero failures and zero `BUG:`, `WARNING:`, Oops, RCU stall, scheduler-from-idle, panic, orphan, FD leak or dirty-ext4 result across: at least 100 consecutive lifecycle boots at each of 1, 2, 4 and the effective maximum vCPUs on capable hosts; repeated parallel-instance waves; a long process/mm/PID-namespace/timer/signal/UBD churn lane; and applicable lockdep, RCU-debug and preemption-debug builds. Every accepted CPU count must still equal the online count and must demonstrate the intended cooperative backend.
11. Rerun the complete Ubuntu 24.04 and 26.04 Rust import/build/independent-validation/workload matrix, Docker process semantics, standard streams, normal and real-time signals, descendant teardown, concurrent COW isolation, forced interruption, package-twice comparison and clean non-root installation. Only a newly sealed profile produced from the corrected source may supply promotion evidence.
12. If no reviewable correction passes these gates, keep x86 `CONFIG_SMP=y` blocked. Pocket may separately qualify and publish an explicitly one-CPU `CONFIG_SMP=n` x86 profile if useful, but documentation, schemas and CLI limits must make its one-CPU ceiling unmistakable. It is not completion of the multiple-host-CPU requirement and it supplies no arm64 correctness evidence.

Phase 0-arm64-base/adoption delivers and tests:

- fetch and lock base `1590cf0329716306e948a8fc29f1d3ee87d3989f` and head `8897487c52233cd00cf2850008ca068892f1ae91`; assert that the former is the merge base and that the ordered range contains exactly 54 commits;
- record that the seed base identifies Linux 7.2-rc4 rather than final Linux 7.2; reproduce the exact seed on native arm64 as a non-promotable feasibility checkpoint before altering its history. The checkpoint records host CPU/ISA, board, kernel, page size, affinity/quota, toolchain, source/config/artifact identities and raw logs; boots unmodified aarch64 Alpine and Debian; reproduces four online CPUs plus dockerd; and runs at least thirty randomized paired one-versus-three-vCPU separate-process benchmark samples. Any discrepancy is retained as a finding and blocks treating the author's observation as reproduced;
- inventory and review the series as generic UML correctness, arm64 ABI/base-port, SMP enablement/prerequisite, or optional policy/performance patches; establish a project-owned tree and named ownership/update policy rather than blindly shipping a moving branch;
- select and lock the maintained Pocket base independently (initially final Linux 7.2 or a later explicitly chosen source), transplant the required reviewed subset, and record old-base/new-base range-diff, semantic-conflict decisions, ordered patch hashes, final tree identity and canonical source manifest. A cleanly applying rebase is not sufficient evidence, and an artifact built from the rc4 seed may not be labeled as final Linux 7.2;
- repeat all source assertions and every runtime gate affected by generic UML, scheduler, RCU, signal, memory-management, seccomp, UBD or arm64 changes between the seed base and selected Pocket base; the seed reproduction cannot qualify the rebased release candidate by inheritance;
- independently prove that the adopted source contains the required generic SMP and corrected TLB synchronization code. Review rather than automatically inherit the fork's `1d555ded4df4537a30f92839f3c34a5d91c1a221` ptrace CPU clamp, `7d1b5396f151b5990acfa791ebcc9bd552b9a51a` CPU-default change, and `d06cc2a4ec6fae227dadfebb70059ae320e2da3e` asynchronous reaping change; Pocket's observable contract remains explicit/fail-closed regardless of which are retained;
- produce native-arm64 and x86_64-to-arm64 Clang builds with exact compiler, binutils/linker, target libc/sysroot and build-environment locks; validate every output as little-endian ELF64 `EM_AARCH64`, executing it only on arm64;
- build an SMP candidate from the reviewed series with `CONFIG_SMP=y`, `CONFIG_NR_CPUS=16`, `CONFIG_COMPAT=n`, and 16 KiB guest pages, plus a `CONFIG_SMP=n` build from the same series as a one-CPU build/regression control—not as evidence that the source lacks SMP;
- use the 16 KiB guest as the first candidate and test it on both 4 KiB and 16 KiB hosts. Offer a distinct 4 KiB guest revision only on 4 KiB hosts after it passes; reject a 16 KiB guest on a 64 KiB host and every other guest-smaller-than-host pairing, and reject 64 KiB hosts until a 64 KiB port is implemented and qualified;
- boot minimal initramfs, Alpine, and Debian-derived ext4 images with `seccomp=on ncpus=1` on the SMP candidate and `seccomp=on` with no `ncpus=` token on the UP control after Pocket validates a one-CPU request; verify the log-selected backend and require exactly one online CPU;
- meet the versioned `arm64-phase0-v1` minimums below with zero unexpected `BUG:`, `WARNING:`, Oops, lockup, lockdep or accounting diagnostics across process creation and exit;
- preserve baseline FP/SIMD and verify general registers, x8/in-flight syscall state, TPIDR_EL0, v0-v31, FPCR/FPSR, nested signals, pthread/futex, fork/exec and glibc `_Fork` across syscall, fault and signal storms on Armv8, Armv9, pre-PAC and PAC/FPAC hosts;
- keep the seed's initial feature exposure: SVE/SVE2, SME, guest PAC keys, BTI, MTE/tagged-address, GCS, CPUID and all HWCAP2 are masked/disabled. On capable hosts prove that auxv and `/proc/cpuinfo` remain coherent and that unsupported state is neither exposed nor corrupting baseline FP/SIMD. Enabling any item requires new ABI/context/regset/mapping work and a separate profile revision, not a policy toggle;
- assert the seed's current boundary: its vDSO supplies signal-return support but its proposed guest vDSO time fast path is not merged, so `clock_gettime` must use the correct syscall fallback. Run the `arm64-phase0-v1` 24-hour monotonicity/drift lane. If Pocket later enables vDSO time, require `GENERIC_VDSO_OVERFLOW_PROTECT`, a deterministic forced-wrap test and the same 24-hour lane before exposing that profile;
- test ext4/UBD/COW, raw serial FDs, clean poweroff, forced teardown and deterministic parent-death hooks; only an arm64 revision which advertises `network_capabilities=bess-slirp` also builds and gates vector networking here, while a networkless revision asserts the vector driver is absent;
- repeat boot, workload, process/mm churn and teardown with every ptrace request returning `EPERM`;
- compare native and one-vCPU UML compute, syscall, open, fault, fork/exec and intended-application results with thermal/frequency controls recorded.

Phase 0-arm64-SMP qualifies the implementation already present in commit `03c57e1808f9fc3df91a770e42ce0ff7ac466269`; it is mandatory for the user's multiple-host-CPU requirement:

1. Freeze the reviewed source, SMP and UP-control configs, fixtures and one-CPU baselines; do not qualify a moving branch.
2. Source-audit the existing capability selection and its assumptions: migration-safe AAPCS64 setjmp state, real `dmb ish` barriers, TPIDR_EL0 regset, `NT_ARM_SYSTEM_CALL`, generic queued-spinlock override, vCPU pthread creation, signal IPIs, per-CPU data, timer delivery, TLB synchronization and stub handoff.
3. Reproduce the branch's reported Raspberry Pi 5 result using immutable Pocket artifacts and explicit `seccomp=on`, not the supplied harness's `seccomp=auto`: four online CPUs, `nproc=4`, dockerd, and a controlled 1-versus-3-CPU parallel workload. Treat discrepancies as findings, not as permission to weaken the gate.
4. Boot every CPU count in the versioned manifest's deduplicated supported-count set (initially 1, 2, 3, 4 and the effective maximum, omitting values above that maximum) on hosts with sufficient affinity/quota; require the boot log to report the cooperative backend, guest online mask to equal the request, and the expected CPU0-plus-secondary-vCPU host pthread count. Induced seccomp failure must abort rather than fall back or clamp.
5. With guest userspace initially idle, prove scheduler ticks, reschedule/call-function/stop IPIs, the profile's `noreboot` restart-as-exit contract, and targeted signals on every CPU; then run distinct guest address spaces concurrently and attribute host CPU time to vCPUs and stubs.
6. Stress the corrected generic TLB path with concurrent mmap, munmap, mprotect, faults, fork, exec and exit, using deterministic delays around translation publication, IPI acknowledgement and mm teardown to detect stale translations and use-after-free.
7. Across migration and nested signal delivery verify all supported arm64 general/TLS/syscall/FP/SIMD state and pthread/futex behavior. On PAC/FPAC and SVE-capable hosts verify the seed's stub-PAC handling and that masked extended state remains masked.
8. Run supported KASAN/KCSAN/lockdep/debug configurations, long non-debug stress, repeated cold boots, and an Armv8/Armv9 plus 4/16 KiB host-page matrix; require no warning, corruption, lockup, zombie, FD leak or orphan.
9. Measure separate-process scaling and the remaining single-stub same-mm limitation, publishing controlled results separately from x86 and from the seed author's report.
10. Re-run the complete one-CPU, lifecycle, ptrace-EPERM, UBD/COW, serial, network and fault matrix. If the asynchronous reaper patch is retained, add deterministic SIGCHLD/reaping tests for races, use-after-free and leaks.
11. Patch only defects or hardening gaps found by review/testing and rerun every affected gate. The candidate already selects `UML_SUBARCH_SUPPORTS_SMP`; passing these gates promotes a product profile, not a Kconfig capability. Failure leaves it explicitly experimental or stops arm64 SMP.

`arm64-phase0-v1` is a machine-readable, profile-revision-bound test manifest
that must be checked in before native qualification starts. These are minimums,
not discretionary examples; a later revision may only strengthen them or
explain and review an intentional compatibility-policy change:

For a candidate with effective maximum `E`, the manifest computes the
deduplicated supported-count set `S = {1, 2, 3, 4, E} intersect [1, E]`, the
multi-vCPU set `M = S - {1}`, and the density count `D = max(S intersect
[1, 4])`. An SMP candidate requires `E >= 2`. No lane launches or claims an
unsupported count; lowering `E` reduces declared capability and creates a new
profile revision, but never converts omitted evidence into a pass.

A `host_cell` is an immutable tuple of physical machine/CPU implementer, part
and revision; Armv8/Armv9 class and exposed PAC/FPAC/SVE features; host page
size; exact host-kernel build/config and oldest-versus-current policy class;
distribution/libc family; LSM/seccomp/ptrace policy; backing filesystem; and
effective affinity/cpuset/quota/memory. Before testing, the manifest enumerates
and hashes the required cell set `H`; failures cannot be removed retroactively.
`H` must provide at least pairwise covering-array coverage across the required
distribution, kernel, ISA/features, 4/16-KiB page-size, security-policy and
backing-filesystem values, plus complete coverage of these high-risk
interactions: every permitted guest-page/host-page pair; Armv9 PAC/FPAC/SVE
context handling; oldest and current kernels with explicit seccomp plus
ptrace-EPERM; each distribution through clean install and Ubuntu end to end;
and each backing filesystem through sparse UBD/COW tests. A missing physical
combination narrows advertised support in a new manifest revision; it is not a
waiver. The manifest separately fixes `H_density` (at least one capable cell
for every host-page and ISA class) and `H_perf(N)` (capacity-qualified cells
covering every host-page and ISA class for each claimed `N`).

| Lane | Minimum execution | Pass condition |
|---|---|---|
| Exact seed feasibility | One recorded native Raspberry Pi 5 with four Cortex-A76 CPUs and 16-KiB host pages, matching the published result; explicit `seccomp=on`; 20 cold four-vCPU boots each for pinned unmodified Alpine and Debian fixtures; 20 cold boot/dockerd-readiness samples in a content-pinned `debian-docker.ext4` fixture reproduced from the seed harness; 30 randomized paired one-versus-three-vCPU samples of that harness's separate-process compile workload | Exact seed/config/artifact/fixture identities, four online CPUs every time, successful dockerd client readiness in all 20 Debian-Docker samples, zero kernel diagnostics/failures/leaks, median three-vCPU speedup at least 1.5x and bootstrapped 95% lower confidence bound above 1.0; remains non-promotable |
| Project-owned base correctness | Every cell in `H`; 100 cold minimal-initramfs boots and 100 full image lifecycles at one CPU, run separately on the SMP candidate and the distinct UP control | Zero failure, warning, corruption, dirty filesystem, orphan or accepted/reported mismatch; all native host/source/profile provenance retained; neither configuration inherits the other's result |
| Timekeeping | 24 continuous hours on every cell in `H`, run separately on SMP-at-one-CPU and UP; sample guest and contemporaneous host monotonic, boottime and realtime clocks; at least ten million guest clock reads across process/thread migration and signal load; host suspend/resume, clocksource change or a host realtime step larger than the manifest tolerance invalidates and restarts the sample | Guest monotonic and boottime never move backwards or discontinuously; their elapsed deltas remain within the manifest's initial 100-ppm bound of the matching host deltas; guest realtime tracks host realtime within the recorded offset/tolerance and may step only when the paired host sample shows the same step; syscall/vDSO path is explicitly observed and matches profile policy |
| SMP lifecycle | 100 fresh complete workloads at every `N` in `S` on every cell in `H`; correctness cells may oversubscribe host CPUs, and the evidence records that fact | Zero failure or kernel diagnostic during boot, workload, unmount or shutdown; requested, online and reported counts exactly equal |
| Concurrent density | On every cell in predeclared `H_density`, 25 waves of at least eight concurrent VMs with recorded adequate memory/affinity/quota, repeated at `N=1` and `N=D` (one lane when `D=1`) | Zero cross-run mutation, timeout, orphan, FD/lease/runtime leak or base-hash change |
| Churn/debug | On every cell in `H`, 24 continuous hours of non-debug process/mm/PID-namespace/timer/signal/UBD churn, plus two hours each for applicable lockdep, RCU-debug, KASAN/KCSAN and preemption-debug builds | Zero warning, sanitizer report, RCU stall, lockup, corruption, zombie, leak or liveness failure |
| SMP scaling | For every `N` in `M`, at least 30 randomized paired one-versus-`N` runs on every cell in predeclared `H_perf(N)`, using separate address spaces with at least `N` allowed physical CPUs and near-`N` quota | Simultaneous host execution is observed; every `N`/cell has a bootstrapped 95% speedup lower bound above 1.0; when `E >= 3`, the explicitly collected three-versus-one lane has at least 1.5x median speedup, otherwise no three-vCPU claim is made |

Every command, timeout, fixture digest, host cell, raw result, parser version and
pass/fail rule is part of the manifest/evidence bundle. Cross-build, QEMU, seed,
x86 or another arm64 profile's result cannot close a project-owned native arm64
cell. “Repeated,” “long,” and “reliable” elsewhere in this phase mean meeting
these versioned minima; they are not subjective reviewer judgments.

Architecture qualification gates are per profile:

- x86_64 Phase-0 qualification requires the complete corrective gate above, reliable `ncpus=1` and `ncpus=2` or greater under `seccomp=on`, no kernel diagnostic during or after workload exit, no privilege, useful separate-process scaling and accepted same-mm limitations; the current Linux 7.2 profile fails this gate;
- arm64 base/adoption requires native aarch64 execution to meet every applicable `arm64-phase0-v1` count/duration/zero-failure rule under `seccomp=on ncpus=1` on the SMP candidate and `seccomp=on` with the CPU token omitted on the validated-one-CPU UP control, no ptrace success, no unexpected kernel diagnostics, and all declared page-size/CPU-state tests;
- arm64 SMP Phase-0 qualification requires independent reproduction plus the complete Phase 0-arm64-SMP audit/stress sequence under `arm64-phase0-v1`, useful separate-process scaling on multiple host CPUs, and a hard failure rather than downgrade when the requested CPU count/backend is unavailable;
- the final process tree exits cleanly with no leaked file or child;
- source audit plus deterministic race-hook tests cover every UML child/helper creation path;
- build inputs and output hashes are reproducible or explained.

Stop the affected architecture profile if its gate fails. The common runtime may continue on another passed profile, but Pocket must not turn either an x86 raw boot/scaling result or the branch author's single reported arm64 SMP result into a production claim, label a UP regression control as the only capability of its source, or use multiple independent one-vCPU VMs as evidence that one VM uses multiple CPUs.

### Phase 1 - Minimal trusted ext4 runner

Start from a known trusted handcrafted ext4 base; do not add OCI ingestion yet.

Deliver:

- Rust workspace, CLI and synchronous supervisor;
- per-run pocket-guard, parent-death contract and crash-releasable lease lock;
- child-side pre-exec process-group establishment, observed SID/PGID assertions, and group-kill/orphan tests against the pinned UML executable;
- private run directory and cache-lease primitives;
- UBD immutable base plus fresh COW;
- raw serial control channel and separate stdin/stdout/stderr mappings;
- PTY terminal mode;
- static pocket-init;
- deterministic activation and verification of IPv4 loopback in every network mode;
- guest mount/PID namespace plus chroot root transition, with the workload as nested PID 1 and pocket-init retained in initramfs;
- command, environment, working directory, numeric user/group, umask and rlimits;
- ncpus and mem validation;
- exact exit/signal propagation;
- graceful and forced termination with idempotent cleanup.

Exit gate:

- representative supported static, dynamic and script programs for every enabled native profile run without binary rewriting; `EM_X86_64` is required for amd64 and `EM_AARCH64` for arm64; 32-bit, cross-machine, missing-interpreter and unsupported-kernel cases fail distinctly;
- exit 0, nonzero exit, exec failure and signal death are exact;
- stdout and stderr remain distinct outside terminal mode;
- in network-none mode an `AF_INET` server/client pair communicates over `127.0.0.1`, no non-loopback interface or host network helper exists, and the initial IPv4-only profile rejects `AF_INET6` with `EAFNOSUPPORT`;
- every byte value, binary framing, stdin EOF, slow readers, large output and PTY resize work without translation or deadlock;
- namespace-init exit removes daemonizing and double-forked descendants, preserves its exact status, and lets pocket-init unmount the image root;
- two concurrent runs from one base cannot see each other's writes;
- base bytes and identity remain unchanged;
- 1,000 sequential short boots and a bounded concurrent-boot test leave no processes, FDs, sockets or directories;
- supervisor SIGKILL alone triggers guard cleanup; guard death triggers child parent-death handling; neither case leaves UML stubs/helpers or an unreclaimable lease.

### Phase 2 - Source normalization and image metadata

Deliver:

- Skopeo integration for docker://, oci:, oci-archive: and docker-archive:;
- optional docker-daemon adapter clearly outside baseline requirements;
- one verified `NativeArchitectureContract` passed through Skopeo override arguments, candidate selection, canonical-layout verification, provenance and error reporting; no acquisition component infers a default architecture independently;
- deterministic native-platform selection, supplied by the already selected profile revision, across every transport; exact OS/architecture plus versioned absent/explicit variant and `os.version`/`os.features` policy rather than a hard-coded amd64 value;
- immutable digest resolution and provenance;
- staged OCI-layout verifier;
- closed allowed-media-type and compression policy with typed rejection reasons;
- layer size, descriptor and DiffID verification;
- bounded image-configuration parser;
- image inspect/list/remove commands;
- acquisition cancellation, retries and authentication diagnostics;
- an explicit resolver-input contract: either a bundled resolver implementation/configuration that demonstrably avoids host `/etc/resolv.conf`, `/etc/hosts` and `/etc/nsswitch.conf`, or a snapshot/hash/provenance record for those files and the effective network-routing context for every pull; local imports need no network record.

Exit gate:

- registry, OCI layout/archive and Docker save forms of the same image select the same canonical filesystem/configuration meaning;
- the same multi-platform fixture selects only `linux/amd64` on x86_64 and only `linux/arm64` on arm64, with the actual absent or accepted explicit baseline variant preserved;
- direct manifests without descriptor platforms are verified from config, while OS/architecture disagreement or unequal dual-explicit variants, unsupported higher variants, nonempty `os.version`/`os.features`, equal-precedence duplicates and every cross-architecture candidate fail with stable typed errors; descriptor-explicit/config-absent and the reverse remain valid when policy accepts the effective variant;
- ambiguous archives, platform-less non-image/artifact candidates, and any missing platform which cannot be derived from an accepted image configuration fail with stable errors; a platform-less image-manifest descriptor with a valid config remains a supported Skopeo/OCI baseline input;
- mutable tag updates atomically change only the matching platform/profile/revision-qualified external alias, create a generation only when the full canonical build key changes, and leave other aliases plus existing digest/generation references stable;
- corrupted descriptor, config, layer, DiffID and incomplete layout are rejected;
- no Docker daemon or privileged storage service is used in the required lane;
- local source paths containing whitespace, comma or colon are normalized without shell parsing or transport-reference ambiguity.

### Phase 3 - Builder UML, faithful ext4 conversion and cache

Deliver:

- payload-ext4 creator;
- managed-path validator covering UML and OCI-reference reserved characters;
- deterministic target sizing and ext4 format policy;
- inode-aware target sizing based on bounded entry counts, plus a classified block-or-inode ENOSPC path that discards the partial filesystem and retries once in the next deterministic size class;
- a derivation-bound ext4 directory `hash_seed`, a bounded `source_date_epoch` carried in `BUILD_START`, and builder-guest clock initialization before mounting the target; normalize every remaining entropy/time source or record it as explained nondeterminism so exact output hashes remain truthful;
- trusted builder initramfs with pinned umoci;
- two-pass measurement/apply protocol or documented sparse-size retry policy;
- canonical metadata manifest plus the bounded builder-to-host streaming and validation-UML digest protocols;
- independently authored expected manifests for the conformance fixtures;
- fsck on the regular file and a read-only validation mount inside a separate validation UML, never on the host;
- content-addressed immutable cache, per-key lock, atomic publication and leases;
- profile-qualified generation manifests and a frozen `ext4-v1-b4096` filesystem contract, with pre-UBD manifest/hash/platform/root-layout/superblock validation;
- crash-safe staging cleanup and generation GC.

Image fixture coverage:

- multiple ordered layers;
- ordinary and opaque whiteouts, including out-of-order cases supported by the pinned tool;
- file-to-directory and directory-to-file replacement;
- hardlinks, symlinks and dangling symlinks;
- numeric UID/GID boundaries;
- set-ID modes, FIFO and device entries;
- ACLs, user and security xattrs, file capabilities and supported labels, with ext4 ACL/security config assertions;
- modification time, including the accepted PAX `mtime` form, rejection of unsupported time extensions, and large regular files; sparse-tar input is rejected because the portable OCI layer baseline advises against it;
- gzip and zstd layer compression supported by the selected OCI/tool versions;
- block and inode ENOSPC.

Exit gate:

- canonical metadata matches expected results for the supported fixture corpus;
- the builder uses seccomp=on, no host mount and no host root/capability;
- a completed image boots through Phase 1 and runs its dynamic loader and executable;
- repeat conversion yields the defined reproducibility result;
- cancellation, builder crash, umoci failure, fsck failure and ENOSPC never publish a cache entry;
- two active COWs share a base safely and block its GC or mutation;
- the full alias/lease/retained-COW reachability matrix preserves every rooted generation, atomically moving or removing one alias affects no other root, and only the final unrooted generation is collectible;
- builder manifest truncation, reordering, duplication, oversized entry/stream, digest/count mismatch, incorrect tool evidence, incorrect named-User evidence and validation-UML mismatch all prevent publication;
- x86/arm64, different page-size/profile, wrong initramfs/kernel, foreign cache-ID and incompatible retained-COW mix-and-match fixtures all fail before READY; compatible upgrade cases are explicitly enumerated rather than inferred.

### Phase 4 - Docker image execution semantics and qualified CPU profiles

Current subset: the host implementation now completes Entrypoint/Cmd/CLI argv
composition, Docker's Linux `PATH`/`HOSTNAME` defaults plus ordered image/CLI
environment overrides, all documented User/Group forms
against leased `accounts.cbor`, WorkingDir selection, and named/numeric
StopSignal selection. It retains a separately named exact-argv mode for callers
that need the former complete-vector behavior. Alias resolution, both mandatory
sidecar reads, and launch use one continuous exact-generation lease; sidecar
bytes are bounded and reauthenticated before parsing. The remaining deliverables
and the cross-image/native-UML exit gate below are not implied complete by that
host-side subset.

Deliver:

- Entrypoint, Cmd and CLI override composition;
- environment merge;
- named and numeric User/Group resolution;
- WorkingDir and StopSignal behavior;
- enforced read-only root; managed UBD volumes remain a later milestone and nonempty reserved volume requests fail explicitly;
- profile-bound guest capability sets and curated workload `/dev`, including enforced root-readonly behavior for guest UID 0;
- required nested guest PID-1 workload semantics while pocket-init remains the VM's outer PID 1;
- inspectable ExposedPorts, Volumes, Labels and Healthcheck metadata;
- machine-readable support/rejection matrix;
- CPU affinity option and observed resource reporting.

Exit gate:

- Alpine, Debian/Ubuntu, BusyBox, distroless/static, and non-root-user fixtures run as expected; writable-root set-ID and policy-allowed file-capability fixtures can elevate only within the published bounding set, while the same transitions are suppressed by root-readonly `PR_SET_NO_NEW_PRIVS`; fixtures requesting blocked capabilities fail with a typed unsupported-policy result;
- exact argv contains no implicit shell or quoting mutation;
- absolute, relative and PATH-searched argv[0] cases match the documented Docker-compatible rules, including missing/non-executable results;
- environment, cwd, UID/GID/groups, umask and rlimits match the effective report; fixtures cover every numeric/named User form, numeric IDs absent from passwd/group, missing and duplicate names, default primary/supplementary groups, and explicit-group suppression of image supplementary memberships;
- `ncpus` requests are visible in guest and host observations and equal the request; the arm64 UP regression build rejects every value other than one, while the candidate arm64 SMP revision accepts only values proven by Phase 0;
- representative multi-process workloads scale acceptably on each SMP-qualified profile; the arm64 UP build remains a non-scaling control;
- representative same-process threaded workloads have documented measured behavior independently on each SMP profile;
- every unsupported image/runtime request is rejected or reported rather than silently treated as supported.

### Phase 5 - Optional slirp/BESS networking

Deliver:

- one slirp4netns BESS process per networked run;
- correct socket-appearance, UML-connect and readiness ordering;
- IPv4 guest configuration and resolver generation;
- explicit localhost port forwards through the slirp API;
- lifetime-FD supervision and teardown;
- optional connected-FD vector experiment.

Exit gate:

- DNS and outbound TCP/UDP work without root, TUN, user namespace or host network configuration;
- network and DNS work with a read-only workload root through the generated-file tmpfs mounts;
- randomized startup timing cannot deadlock readiness;
- cancellation at every startup point cleans all sockets, forwards and children;
- networkless mode starts no slirp process and no UML NIC;
- only declared forwards exist, default host bind is 127.0.0.1, and all disappear on exit;
- the support matrix accurately states IPv4, IPv6 and egress behavior.

### Phase 6 - Reliability, resource adapters and recovery

Deliver:

- optional delegated-cgroup adapter;
- optional filesystem quota/reservation adapter;
- durable state records and pocket gc;
- fault-injection hooks after every resource acquisition and state transition;
- observed CPU/RSS/process/thread/disk/network statistics;
- log rotation/limits and diagnostic bundles;
- raw Linux wait-status decoding for the complete admitted signal range 1 through 64, including real-time signal termination, without routing it through an enum that cannot represent those signals;
- explicit nested workload-PID-namespace/process-group teardown that kills and reaps every descendant even when set-ID or file-capability exec clears `PDEATHSIG`.

Exit gate:

- a real guest restart and an intentional guest panic each produce exactly one boot followed by bounded UML exit under the fixed `noreboot panic=1` template, with no self-executed replacement; guest hang, shutdown failure, supervisor SIGKILL, guard death, closed protocol FD, malformed frame, slirp crash, builder crash, COW ENOSPC, host ENOSPC, exhausted FDs/processes and forced kill otherwise recover predictably;
- no partial, uncommitted, or identity-mismatched cache artifact is selected after a crash;
- no aliased, active/leased or retained-COW generation is collected; an alias move/remove makes the old generation collectible only after every other root is gone;
- crash recovery either retains a verified alias target or quarantines the alias before selection, and `never`, `missing` and `always` pull policies retain their specified no-network/acquisition behavior after recovery;
- cgroup-enabled runs honor configured aggregate controls;
- non-cgroup runs never claim hard limits;
- all cleanup operations are idempotent.

### Phase 7 - Packaging and release

Deliver:

- checksummed or signed profile-revision bundles with no foreign executable dependency, each using the non-circular external-manifest identity and role-tagged artifact records;
- explicit candidate-to-release promotion records; `arm64-smp-p16k` may bind the exact passed experimental kernel/initramfs/helper digests, but any changed byte or contract creates a new revision and reruns affected gates;
- user-prefix installer needing no administrator action;
- SBOM, source locks, licenses and rebuild instructions;
- exact compiler, linker, libc/sysroot, Cargo/Rust target, Go and binutils/e2fs toolchain locks; build every release artifact twice from separate clean roots and compare bytes or publish a bounded explanation for each difference;
- support matrix for host kernels/distributions, filesystems, UML features, image media types and configuration fields;
- benchmark report;
- update, rollback and cache-migration policy;
- concise trusted-only warning in CLI help and documentation.

Exit gate:

- a fresh ordinary account on a clean native host installs the matching bundle and completes every bundled-helper probe, pull and run without privilege; every dynamic host role proves `DF_1_NODEFLIB`, bundled-loader `--inhibit-cache`, sanitized loader state, preload refusal, complete declared dependency/dlopen/NSS inventory and bundle-only mapped ELF paths, while a deliberately omitted bundled dependency fails rather than falling back to a host DSO; a dynamic-UML profile additionally starts with personality bits clear, succeeds through the guard's verified personality-plus-loader path, and has a negative test showing that the unprepared manual-loader form cannot be selected;
- the zero-capability/no-device/no-userns/no-cgroup/ptrace-denied CI lane remains mandatory;
- artifact verification fails before execution on mismatch;
- experimental profiles are never installed as an implicit release default, and revision-qualified aliases remain distinct through update/rollback;
- supported image corpus passes from clean cache;
- upgrade preserves or explicitly rebuilds cache generations safely;
- release notes include the current same-process-thread SMP limitation and the non-security-boundary statement.

### Later milestones

Only after the MVP:

- daemonless create/start/state/kill/delete lifecycle;
- OCI-runtime-compatible CLI shim and runtime-tools conformance;
- persistent managed-volume create/attach/detach/import/export with exclusive-writer leasing, fixed UBD mapping and dirty-volume recovery;
- OCI-aware snapshot commit;
- destination-aware network policy and IPv6;
- EROFS or other read-only base optimization;
- per-vCPU host affinity;
- full same-process userspace SMP if UML implements it;
- architectures beyond x86_64/amd64 and arm64/aarch64 after independent evidence.

## Validation strategy

### Required host matrix

- at least two current distribution families with differing libc and host security defaults for each architecture promoted to release status;
- x86_64 at the oldest supported host kernel and a current stable lane, using the independently pinned v7.0.10/v7.1-or-newer UML source with the SMP TLB fix;
- native little-endian arm64 Linux at the eventual oldest supported host kernel and a current stable lane, using the exact project-owned arm64 source lock rather than upstream x86 evidence;
- for arm64, at least one baseline Armv8 system and one Armv9 system with PAC/FPAC and SVE capability; the initial profile must prove its stub-PAC behavior and that unsupported SVE/PAC-key/MTE-class state stays masked;
- first qualify a 16 KiB arm64 guest on 4 KiB and 16 KiB hosts; if a 4 KiB guest is later offered, test it only on 4 KiB hosts; reject 64 KiB hosts until a 64 KiB guest exists, and never extrapolate across page-size pairs;
- ptrace returning EPERM while cooperative seccomp is permitted;
- no KVM, TUN, FUSE, loop device, user namespace or writable cgroup;
- optional delegated-cgroup lane;
- ext4, XFS and Btrfs backing filesystems where supported, plus explicit rejection of unsuitable sparse-file behavior;
- constrained process, FD, map, pending-signal and disk limits;
- a networkless lane for every revision; a BESS-enabled lane only for revisions whose immutable manifest advertises `network_capabilities=bess-slirp`, with no BESS requirement for a static networkless release.

### Functional suite

- native static, glibc, musl and script entrypoints on every enabled profile, plus cross-machine and 32-bit rejection fixtures;
- fork/exec, multi-process workers, threads, futexes, signals and timers;
- namespace-init exit with child, orphan, daemonizing and double-forked descendants;
- file I/O, mmap, fsync, rename, links, xattrs and file locking;
- stdin/stdout/stderr, binary data, PTY, resize and EOF;
- exact image command/env/user/cwd/stop behavior;
- read-only root, including guest-UID-0 attempts to remount, recreate/open UBD, mount another view, or regain excluded capabilities; nonempty managed-volume requests are rejected until the later lifecycle contract exists;
- concurrent COW isolation and base immutability;
- clean and forced shutdown;
- every CLI command and stable error code.

### Image suite

- every accepted transport and authentication mode;
- platform indexes containing both amd64 and arm64; absent, descriptor-only, config-only and dual-explicit baseline variants; unequal dual-explicit variants; unsupported higher variants; duplicate-precedence candidates; direct-manifest config selection; OS/architecture disagreement; nonempty `os.version`/`os.features`; wrong-platform inputs; and ambiguous archives;
- descriptor and DiffID integrity;
- layer compression and whiteout semantics;
- full supported metadata corpus;
- conversion size classes, inode pressure and cache hits;
- tag updates, concurrent pulls/builds, aliases, retained COWs, leases and GC, including every root combination and alias replacement/removal;
- cross-version cache invalidation;
- actual execution of each produced rootfs.

### CPU and performance suite

Measure each profile against same-architecture native execution and one-vCPU UML:

- boot to HELLO, READY and first output;
- the arm64 UP regression build at exactly one vCPU and the arm64 SMP candidate at one vCPU, including density across independent instances;
- each SMP-qualified profile at every count in its versioned supported set `S`, with any additional product counts such as 8 included when within policy;
- N independent CPU-bound processes on each SMP-qualified profile;
- one N-thread CPU-bound process to expose the same-mm stub limitation;
- compiler, prefork server, shell jobs, package manager and mixed I/O workloads;
- host CPU utilization, migrations, context switches and per-vCPU pthread behavior;
- on arm64, host-PAC/FPAC interaction, FP/SIMD, TLS, signal and fork/exec workloads; capable-host negative tests prove SVE/SME/PAC-key/MTE and other masked state is not exposed; every result records HWCAP policy and both page sizes;
- idle and peak host RSS versus mem;
- host process/thread/map count per guest process count;
- ext4 sequential/random I/O, fsync and COW amplification;
- network throughput, latency and CPU;
- 1, 10 and 100 concurrent instances where host capacity permits;
- cold/warm image conversion and cache-hit latency.

Set release targets only after Phase 0 and representative application measurements. Do not substitute microbenchmarks for the actual intended workload.

### Fault and recovery suite

Inject failure after each state transition. Kill the supervisor, UML, builder and slirp at each meaningful point. Close or corrupt every protocol channel, including every builder-manifest stream boundary. Simulate short reads/writes, slow consumers, full COW, full cache, inode exhaustion, digest/count mismatch, base mismatch, invalid ext4, expired auth, interrupted download and unsupported image metadata. Crash between generation publication and alias replacement, and exercise alias/lease/retained-COW root changes concurrently with GC. At the resolve boundary, deterministically interleave full-ID and alias resolution with alias move/removal plus GC; either atomic resolve-and-lease returns a still-existing pinned generation or resolution fails before exposing any path, never a dangling generation. Inject wrong-architecture/profile kernels, initramfses, generations and retained COW sidecars; every mix-and-match case must fail before workload READY and, where detectable host-side, before UML launch.

After every case assert:

- bounded termination;
- no unexpected child or thread;
- no live forwarding or socket;
- base unchanged;
- partial generation not selectable;
- lease count correct;
- every valid alias and retained COW still reaches an existing generation, and no uncommitted target becomes reachable;
- repeated cleanup harmless;
- diagnostic names the failing stage and preserves no secret.

### Privilege audit

The release suite runs under a nonzero UID with CapEff, CapPrm, CapInh and CapAmb all zero. Trace or audit startup and representative runs to prove the required path performs no host mount, namespace creation, privileged ioctl, KVM/TUN/FUSE/loop access, sysctl change, firewall operation or cgroup modification.

## Risk register and go/no-go gates

| Risk | Evidence needed | Decision |
|---|---|---|
| Cooperative seccomp fails on target hosts | Phase 0 host matrix | Refuse unsupported hosts; stop if common target hosts fail |
| x86 UML SMP is unstable—the profile reproduced this risk and it was corrected | corrective source gate plus repeated/concurrent full-lifecycle suite | the reviewed fix is pinned in `kernel/patches/7.2/0003`-`0005`; any regression re-opens the gate rather than reducing `--cpus` |
| Upstream has no arm64 UML | exact project fork, maintainer and rebase policy | Own the port or do not ship arm64 |
| Arm64 README/RFC status is stale and the exact SMP seed is very recent | exact 54-patch adoption audit, ownership and base-correctness matrix | Maintain a reviewed fork or do not ship arm64 |
| Existing arm64 SMP implementation is incorrect, narrowly portable or does not scale | independent reproduction, Phase 0-arm64-SMP audit/stress and application benchmarks | Keep experimental; do not advertise `--cpus > 1`; stop if it is a hard requirement |
| Arm64 CPU state or page-size pairing is wrong | baseline FP/SIMD, masked-feature, HWCAP and 4/16 KiB supported plus 64 KiB rejection matrix | Restrict the profile policy or stop arm64 |
| Profile/kernel/initramfs/base/COW artifacts are mixed | manifest, HELLO/START and negative compatibility fixtures | Reject before launch/READY; never guess compatibility |
| UML child parent-death race leaves an orphan | reviewed pre-exec patch, creation-path audit and deterministic race hooks | Carry/fix upstream or stop; random stress alone is insufficient |
| Target application is one threaded process | application benchmark | Use multiple processes/VMs or choose another runtime |
| Host thread/process overhead is too high | density benchmark | Restrict supported density or stop |
| OCI metadata cannot be reproduced | Phase 3 canonical corpus | Fix/pin importer or drop generic OCI input |
| Conversion latency or storage is excessive | cold/warm benchmark and size classes | Improve cache/sizing; consider later EROFS |
| UBD COW base invalidation or corruption | concurrent/crash suite | Fix immutability/lifecycle before release |
| BESS is unreliable | randomized network startup/fault suite | Ship networkless or choose another unprivileged stack |
| Dynamic UML dependencies vary by host | bundled-loader clean-host tests | Bundle exact runtime or offer networkless static variant |
| No hard aggregate resource controls | capability report and optional adapters | Accept for trusted use; never claim hard isolation |
| Upstream/project UML maintenance is insufficient | per-profile release/update review | Reassess the affected profile's viability |

Immediate common no-go conditions:

- `seccomp=on` cannot boot reliably without successful ptrace on the intended host fleet;
- a no-privilege lane requires any forbidden host mechanism;
- Docker/OCI images cannot be converted with required metadata fidelity;
- normal cancellation cannot prove all UML/slirp processes and leases are gone;
- resource or performance overhead misses the target by an unacceptable margin.

Profile-specific no-go conditions:

- x86 SMP: any supported `seccomp=on ncpus=N` full-lifecycle run is unreliable or emits a kernel diagnostic during/after workload exit, separate guest processes do not produce useful parallelism, or target workloads fundamentally require same-process thread scaling. The corrective source gate identified and validated a reviewable fix, and the current profile is out of this no-go state; a regression returns it here;
- arm64 base/adoption: native aarch64 fork/exec, signals, baseline FP/SIMD/TLS, masked-feature policy, timekeeping, page-size, UBD or teardown correctness remains unresolved, or no one owns the fork;
- arm64 SMP: the current candidate cannot reproduce two or more requested/online vCPUs under explicit `seccomp=on`, fails the IPI/TLB/context/lifecycle suite, cannot use multiple host CPUs effectively with separate processes, or the user's workloads require same-mm thread scaling that the stub still serializes.

## Recommended MVP interface

~~~text
pocket profile list
pocket probe [--json] [--all] [--profile PROFILE_ID[@PROFILE_REVISION]]

pocket image pull IMAGE[@DIGEST] [--profile PROFILE_ID[@PROFILE_REVISION]] [--platform PLATFORM]
pocket image import --oci PATH [--ref REF] [--profile PROFILE_ID[@PROFILE_REVISION]] [--platform PLATFORM]
pocket image import --oci-archive FILE [--ref REF] [--profile PROFILE_ID[@PROFILE_REVISION]] [--platform PLATFORM]
pocket image import --docker-archive FILE [--ref REF] [--profile PROFILE_ID[@PROFILE_REVISION]] [--platform PLATFORM]
pocket image inspect IMAGE_OR_ID [--profile PROFILE_ID[@PROFILE_REVISION]]
pocket image list [--profile PROFILE_ID[@PROFILE_REVISION]|--all]
pocket image remove IMAGE_OR_ID [--profile PROFILE_ID[@PROFILE_REVISION]]

pocket run
  [--profile PROFILE_ID[@PROFILE_REVISION]]
  [--pull missing|always|never]
  [--cpus N]
  [--cpuset LIST]
  [--memory SIZE]
  [--timeout DURATION]
  [--root-readonly]
  [--network none|slirp]
  [-p 127.0.0.1:HOST:GUEST]
  [--entrypoint PATH]
  [--user USER[:GROUP]]
  [--workdir PATH]
  [--stop-signal SIGNAL]
  [--stop-timeout DURATION]
  [-e KEY=VALUE]
  [-i] [-t]
  IMAGE_OR_ID
  [COMMAND ARG...]

pocket gc
~~~

`--platform` is an assertion/selector within the already selected profile's compatibility policy; it cannot request emulation or switch `profile_id`. An explicit platform/profile conflict fails before acquisition.

A full immutable generation ID resolves globally and carries its profile revision. Mutable image aliases resolve only within the explicit or unique-default `profile_id` and its resolved active or explicitly pinned `profile_revision`. If an alias exists in more than one eligible profile/revision, inspect/run/remove fails with `E_PROFILE_AMBIGUOUS`; remove never broadens ambiguity into deletion across profiles. `image list --all` is the only cross-profile listing operation. A valid alias is a durable GC root. `--pull never` performs no acquisition and requires a valid committed generation or alias, otherwise returning `E_IMAGE_MISSING` or `E_ALIAS_INVALID`. `--pull missing` reuses a valid alias but resolves and pulls when it is absent or was quarantined as dangling/corrupt. `--pull always` resolves the source and atomically moves only the exact revision-qualified alias after a generation is committed. A full immutable ID never triggers network acquisition under any policy.

MVP defaults:

- trusted images and workloads only;
- one workload process tree per UML;
- profile selection precedes image selection: use the unique installed release-grade default, require explicit `--profile` for experimental revisions, and reject ambiguity; the selected profile then accepts exact native `linux/amd64` or `linux/arm64` OS/architecture plus only its versioned absent/explicit variant policy;
- seccomp=on always;
- Pocket defaults the requested CPU count to one. It passes `ncpus=1` to an SMP-capable build; the arm64 UP regression build has a hard maximum of one and receives no `ncpus=` argument;
- CPU requests never exceed the selected manifest's checked `effective_max_cpus`; UP manifests fix it at one, while SMP manifests prove it is no greater than both product policy and compiled `CONFIG_NR_CPUS`;
- an omitted `--memory` selects the revision-bound aligned `default_memory_bytes`; explicit requests are aligned, remain within the selected manifest's minimum and tested `effective_max_memory_bytes`, and are rejected unless the measured UML accepted byte count equals the exact request;
- network none;
- ephemeral root COW discarded after a clean run unless retention is explicit;
- image tag resolved and digest reported;
- pull policy missing;
- no automatic host mount, device, port forward, persistent volume or healthcheck; nonempty runtime volume requests are unsupported;
- no claim of malicious-code isolation or full OCI runtime compliance.

## Definition of done

The common runtime is complete for a profile when, on every host in that profile's matrix:

1. A fresh non-root user installs the matching native bundle without administrator action.
2. `pocket probe` reports `profile_id`/`profile_revision`, exact architecture, native OCI OS/architecture plus accepted/preferred platform policy, source/build identities, filesystem contract, page/CPU-state policy, cooperative backend, CPU requested/online/compiled/product/effective limits, memory alignment and minimum/default/product/effective workload plus fixed-builder values, and the probe boots' requested/accepted physical-memory bytes; image inspect/run reports carry actual raw/effective image platform fields.
3. `pocket image pull` imports a reviewed digest-pinned fixture for that native platform from a registry without Docker or host mounts; image trust remains the caller's responsibility.
4. `pocket run --cpus 1` executes an existing native image entrypoint with correct argv, environment, user, cwd, output and exit status.
5. Two concurrent runs share the immutable profile-qualified base but cannot see each other's COW writes, while foreign profile/generation/COW combinations fail before execution; aliased, leased and retained-COW bases survive GC and become collectible only after their final root is removed.
6. If included in the release, optional slirp networking works without TUN or host namespace creation.
7. Every normal, cancellation and injected-failure path leaves no process, FD, socket, forward, lease or partial selectable cache generation.
8. The privilege audit observes none of the forbidden host mechanisms and no successful ptrace dependency.
9. The native bundle, config, exact source locks, ordered patches, checksums, SBOM, support matrix and architecture-specific benchmarks are published together.
10. Experimental selection always requires explicit opt-in, `--cpus` never changes a profile, and mixed architecture/profile kernel, initramfs, generation and retained-COW fixtures fail at the earliest defined validation stage.

Additional profile definitions of done:

- `x86_64-smp-p4k`: the corrective scheduler/RCU gate passes; `pocket run --cpus 1`, `--cpus 2` and the larger supported matrix work repeatedly through the full nested-PID lifecycle without kernel diagnostics; two separate guest processes use two host CPUs; and the same-mm limitation is displayed and measured. The current profile meets this definition.
- `x86_64-up-p4k-test`: a separately sealed true `CONFIG_SMP=n` control, if retained, passes the full one-CPU lifecycle matrix and rejects every larger request. The present diagnostic revision has passed its initial 20/20 Ubuntu 24.04 loop, but not the complete release matrix. It is never an alias or silent fallback for `x86_64-smp-p4k` and does not satisfy a multiple-CPU definition of done.
- `arm64-up-p16k-test`: the deliberately non-SMP control passes unmodified `EM_AARCH64` glibc/musl, context, page-size and timekeeping gates at one CPU and rejects every larger request; it is a test artifact, not the source's capability ceiling.
- `arm64-smp-p16k-experimental`: all arm64 base requirements pass, the exact seed's SMP result is independently reproduced with `seccomp=on`, `pocket run --cpus 2` and the larger supported matrix meet every `arm64-phase0-v1` zero-failure/count/duration criterion, separate aarch64 guest processes use multiple host CPUs, and the same-mm limitation is displayed and measured. It remains explicitly experimental until the maintenance and host-matrix release gates pass.
- `arm64-smp-p16k`: a separately published release profile revision may be created only after the experimental candidate also has named maintenance ownership, passes the complete target-host/oldest-kernel/long-stress and packaging gates, and publishes all supporting evidence. Promotion is an explicit manifest/profile decision, never a silent maturity-field mutation of an installed revision.

For the user's stated native-arm64 plus multiple-host-CPU goal, completion means the common definition plus a release-promoted arm64 SMP profile; the one-CPU base/control milestone alone is not completion.

## Final feasibility assessment

The trusted native design is feasible, but readiness differs by architecture:

- UML is an ordinary unprivileged executable;
- upstream x86_64 UML maps virtual CPUs to host pthreads under its cooperative seccomp backend;
- the exact out-of-tree arm64 UML seed already demonstrates native unmodified aarch64 userspace and contains initial SMP, with one reported four-CPU/scaling result;
- disks and COW layers are regular files;
- control and standard streams use ordinary inherited FDs;
- slirp BESS provides optional networking without TUN;
- Skopeo consumes existing Docker and OCI images without a daemon;
- a trusted builder UML applies layers as guest root and creates a faithful ext4 base without host root or mounts.

Native arm64 user-code execution and the existence of an initial arm64 SMP implementation are therefore not the blockers. The blockers for a supported arm64 release are adopting and maintaining the out-of-tree series, independently reproducing its evidence, and qualifying/hardening its existing SMP implementation across the correctness, page-size, CPU-state, lifecycle and workload matrices. Until that gate passes, Pocket must not enable the arm64 multi-vCPU product profile; the candidate contains code with one author-reported multi-CPU boot, not yet a Pocket-reproduced result.

The x86 situation was different and is now resolved: Linux 7.2 contains upstream x86 UML SMP, and Pocket's full nested-PID lifecycle reproducibly reached invalid scheduler/RCU state because UML called the sleeping generic `free_irq()` from its SIGIO signal handler, which only blocks when `CONFIG_SMP=y` selects Tree RCU and the SMP `synchronize_irqwork()`. No published upstream fix existed at the 2026-08-28 audit, so Pocket carries its own reviewed correction as locked patches `0003`-`0005` and qualifies the profile against the corrected source.

For every SMP profile, the leading product-fit question remains whether target workloads benefit from process-parallel SMP despite the same-process stub limit. The leading correctness question is now full lifecycle stability under process/mm/stub/signal churn, not whether a minimal SMP boot reaches a shell. The reviewed pre-exec parent-death invariant, deterministic child-creation race tests, and post-workload clean-kernel exit remain mandatory as well.

The present x86_64 workspace has implemented the Rust protocol, OCI verifier, guard, content store, builder/workload/validator guest init, runtime, bounded CLI and packaging foundation. It has authenticated and built Linux 7.2, constructed sealed experimental artifacts, daemonlessly acquired existing Ubuntu images, converted them to immutable ext4 inside builder UML, independently validated a generation, and launched workloads on private UBD COW files. The complete Rust release matrix stopped correctly when repeated workload lifecycle boots exposed the kernel panic; it, packaging promotion and clean-host release qualification are incomplete. For the native-arm64 plus multiple-CPU goal, the remaining architecture-specific work starts by reproducing the immutable rc4-based seed on native arm64 as non-promotable evidence, then transplanting the reviewed series onto the separately locked maintained base, rerunning base validation, and independently qualifying the project-owned tree's already-present SMP code. Neither seed, cross-build, x86 success nor x86 failure evidence can substitute for that gate, although the shared generic UML SMP lifecycle failure mode must be tested deliberately on arm64.

## Primary sources

- [Upstream Linux master audited on 2026-08-27](https://github.com/torvalds/linux/commit/1b78070aaef63512688aebfbc82365ef9d6660f1)
- [Upstream host-to-SUBARCH mapping](https://github.com/torvalds/linux/blob/1b78070aaef63512688aebfbc82365ef9d6660f1/scripts/subarch.include)
- [Upstream UML architecture-glue build rules](https://github.com/torvalds/linux/blob/1b78070aaef63512688aebfbc82365ef9d6660f1/arch/um/Makefile)
- [Upstream arm64 tree, which has no UML glue](https://github.com/torvalds/linux/tree/1b78070aaef63512688aebfbc82365ef9d6660f1/arch/arm64)
- [Out-of-tree native arm64 UML source and status](https://github.com/zalexdev/linux-um-arm64/tree/um-arm64)
- [Arm64 seed head observed on 2026-08-28](https://github.com/zalexdev/linux-um-arm64/commit/8897487c52233cd00cf2850008ca068892f1ae91)
- [Arm64 seed `next` ref observed on 2026-08-28](https://github.com/zalexdev/linux-um-arm64/commit/1590cf0329716306e948a8fc29f1d3ee87d3989f)
- [Arm64 UML SMP enablement and reported four-CPU result](https://github.com/zalexdev/linux-um-arm64/commit/03c57e1808f9fc3df91a770e42ce0ff7ac466269)
- [Arm64 UML SMP benchmark harness](https://github.com/zalexdev/linux-um-arm64/commit/1532f4aee863d3a580d13cc99685599c46caf3e1)
- [Fork ptrace-backend CPU-clamp change](https://github.com/zalexdev/linux-um-arm64/commit/1d555ded4df4537a30f92839f3c34a5d91c1a221)
- [Fork default-CPU change](https://github.com/zalexdev/linux-um-arm64/commit/7d1b5396f151b5990acfa791ebcc9bd552b9a51a)
- [Fork asynchronous stub-reaping change](https://github.com/zalexdev/linux-um-arm64/commit/d06cc2a4ec6fae227dadfebb70059ae320e2da3e)
- [Exact arm64 seed UML kernel Makefile showing SMP-only `smp.o`](https://github.com/zalexdev/linux-um-arm64/blob/8897487c52233cd00cf2850008ca068892f1ae91/arch/um/kernel/Makefile)
- [Exact arm64 seed `ncpus=` parser in `smp.c`](https://github.com/zalexdev/linux-um-arm64/blob/8897487c52233cd00cf2850008ca068892f1ae91/arch/um/kernel/smp.c)
- [Arm64 guest HWCAP sanitization](https://github.com/zalexdev/linux-um-arm64/commit/db12996e882d0c04f835f3420823aeb8c98870c7)
- [Arm64 FP/SIMD preservation across seccomp signals](https://github.com/zalexdev/linux-um-arm64/commit/4741dd4073e6d4471cb8004b95e18ddb78a9e85e)
- [Pointer-authentication disabling in arm64 stubs](https://github.com/zalexdev/linux-um-arm64/commit/eb18fac1d000b24c7ee82bffc74db2837ed8e213)
- [Arm64 UML RFC announcement](https://lkml.iu.edu/2608.1/14307.html)
- [Linux 6.19 initial UML SMP commit](https://github.com/torvalds/linux/commit/1e4ee5135d81)
- [UML SMP TLB synchronization fix](https://github.com/torvalds/linux/commit/102331b66bcaf1f41f50b9c4cd5c36e46bafa9f3)
- [UML userspace-stub parent-death fix](https://github.com/torvalds/linux/commit/801e00d3a1b78b7f71675fae79946ff4aa3ee070)
- [Linux 7.0.10 stable changelog containing the backport](https://cdn.kernel.org/pub/linux/kernel/v7.x/ChangeLog-7.0.10)
- [UML Kconfig and SMP semantics](https://github.com/torvalds/linux/blob/master/arch/um/Kconfig)
- [x86 UML Kconfig](https://github.com/torvalds/linux/blob/master/arch/x86/um/Kconfig)
- [UML SMP implementation](https://github.com/torvalds/linux/blob/master/arch/um/kernel/smp.c)
- [UML host pthread implementation](https://github.com/torvalds/linux/blob/master/arch/um/os-Linux/smp.c)
- [UML cooperative seccomp and startup checks](https://github.com/torvalds/linux/blob/master/arch/um/os-Linux/start_up.c)
- [Linux UML HOWTO](https://docs.kernel.org/virt/uml/user_mode_linux_howto_v2.html)
- [Linux initramfs and rootfs behavior](https://docs.kernel.org/filesystems/ramfs-rootfs-initramfs.html)
- [UML vector transport implementation](https://github.com/torvalds/linux/blob/master/arch/um/drivers/vector_user.c)
- [slirp4netns BESS manual](https://github.com/rootless-containers/slirp4netns/blob/master/slirp4netns.1.md)
- [slirp4netns implementation](https://github.com/rootless-containers/slirp4netns/blob/master/main.c)
- [Skopeo copy documentation](https://github.com/containers/skopeo/blob/main/docs/skopeo-copy.1.md)
- [containers/image transports](https://github.com/containers/image/blob/main/docs/containers-transports.5.md)
- [OCI Image Specification](https://github.com/opencontainers/image-spec/blob/main/spec.md)
- [OCI image layout](https://github.com/opencontainers/image-spec/blob/main/image-layout.md)
- [OCI image index](https://github.com/opencontainers/image-spec/blob/main/image-index.md)
- [OCI image configuration](https://github.com/opencontainers/image-spec/blob/main/config.md)
- [OCI layer changesets and whiteouts](https://github.com/opencontainers/image-spec/blob/main/layer.md)
- [umoci workflow](https://umo.ci/quick-start/workflow/)
- [umoci rootless limitations](https://umo.ci/quick-start/rootless/)
- [umoci raw unpack](https://manpages.debian.org/testing/umoci/umoci-raw-unpack.1.en.html)
- [mke2fs](https://man7.org/linux/man-pages/man8/mke2fs.8.html)
- [Linux cgroup v2](https://docs.kernel.org/admin-guide/cgroup-v2.html)

Branch-moving source links above support this planning record. Phase 0 replaces every version-sensitive kernel and tool link in the artifact manifest with the exact selected commit or release permalink.
