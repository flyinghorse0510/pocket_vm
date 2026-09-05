# Running on an EL7-vintage host (experimental)

pocket_vm's kernel floor is Linux **5.9**, because UML's seccomp backend calls
`close_range`. That floor is a property of UML's source, not of seccomp: the
kernel machinery the backend actually depends on has been present since 3.5,
and Red Hat backported the rest of it into the EL7 kernel.

This page describes an **experimental, opt-in** kernel variant that removes the
dependency on syscalls newer than the host, so the seccomp backend runs on a
CentOS 7 host with a 3.10 kernel and glibc 2.17.

It is off by default. `make kernel` never reads any of it, and the default
kernel's bytes are unchanged.

## Status

| | |
|---|---|
| Validated host | CentOS Linux 7.9.2009, kernel `3.10.0-1160.119.1.el7.x86_64`, glibc 2.17 |
| Reference toolchain | GCC 13.4.0, GNU ld 2.44, GNU Make 4.4.1 |
| Guest boot, `seccomp=on` | the release e2e lane, which boots a guest at 1 and 4 vCPUs and asserts what it reports |
| Descriptor invariant | `make stub-fd-audit-el7`, which runs all three scenarios including the one the release kernel fails |
| Locked digests | `make verify-el7` passing against the variant's own lock section |
| Patch pipeline | `make audit-linux-source-el7` and `POCKET_KERNEL_VARIANT=el7 make test-linux-source-pipeline` |
| libc id-cache defect | `make host-clone-idcache-probe`, reproducing the table below on both hosts |
| Kernel reproducibility | `make kernel-el7` rebuilt from scratch on the host, same digest every time |
| `pocket` itself | `image pull` and `run` verified on the host; the release e2e lane run there |

`pocket`'s own binaries are static-PIE with no interpreter and no `NEEDED`
entries, so the ones built on a current host run unmodified against glibc 2.17.
Only the kernel has to be built for the variant; everything else in a sealed
profile is byte-identical to the default build's.

## Why the default kernel does not run here

Two syscalls UML calls are absent from a 3.10 kernel, and one glibc behaviour
defeats UML's own capability probe. All three were measured on the host rather
than inferred from version numbers:

| | EL7 result | Consequence |
|---|---|---|
| `close_range` (436) | `ENOSYS` | The probe rejects the backend before trying it, and the stub cannot shed inherited descriptors |
| `execveat` (322) | `ENOSYS` | The trampoline cannot start the stub at all, in either backend |
| `MFD_EXEC` | `EINVAL` | Expected; UML already falls back to a temporary file |
| glibc 2.17 `sleep(0)` | issues no syscall | The probe filters `clock_nanosleep` and then calls `sleep(0)`, so the trap it waits for can never fire |

Everything else the backend needs is present and behaves correctly, including
the part no capability list covers: register edits written into the SIGSYS
signal frame survive `rt_sigreturn`. That write-back is how UML returns a
syscall result to its guest.

Check any candidate host for yourself:

```sh
make host-seccomp-probe
```

The probe is standalone — it depends on nothing pocket builds, so it can be
copied to a candidate host on its own. It reports 19 checks and ends in
`POCKET_HOST_SECCOMP_PROBE_OK`, naming any syscall the host is missing.

## Building it

```sh
make kernel-el7
```

This applies the fourteen patches in `kernel/patches/7.2/el7/` on top of the
default series and publishes to paths of its own:

| | Default | `el7` |
|---|---|---|
| Source | `build/src/linux-7.2` | `build/src/linux-7.2-el7` |
| Output | `build/kernel/x86_64-smp-p4k` | `build/kernel/x86_64-smp-p4k-el7` |

Selecting the variant cannot disturb the default build or be mistaken for it.
The overlay is locked the same way the default series is — every patch's
SHA-256, its single changed path, mode, and full pre- and post-image blobs,
then the resulting Git tree and filesystem manifest — and it additionally
declares both the tree and the filesystem manifest it builds on, which must be
exactly what the default series produces. The two locks are a chain, not two
independent claims.

Audit it at any time, without building:

```sh
make audit-linux-source-el7
```

Once built, check the kernel against its own locked digests. The variant is
locked under its own section, so `make verify` would compare it against the
default kernel's digest; use the variant's target instead:

```sh
make verify-el7
```

Sealing a profile around that kernel takes two toolchains, so it is worth being
precise about which host does what. The kernel is bound to the reference
toolchain above -- building it with anything else produces different bytes and
fails closed -- so it is built on the EL7 host. Everything else in the bundle is
a static host binary; e2fsprogs is pinned to `development_tools.cc_major`, which
EL7 does not have, so those are built on a current host. The seal builds
`pocket` itself and pins the Rust toolchain exactly, so it runs where that
toolchain and both halves are present:

```sh
POCKET_KERNEL_VARIANT=el7 ./scripts/build-release-profile.sh
```

Call the script, not `make release-profile`: the make target depends on the
kernel, so it would rebuild the variant with the local compiler and refuse its
own output. The script reads `build/kernel/x86_64-smp-p4k-el7` as it finds it
and writes to `build/profiles-el7/`, leaving the default profile and its
`latest` marker alone. The resulting bundle is what `pocket --profile-bundle`
is pointed at on the EL7 host.

The descriptor cleanup this variant replaces is the whole basis for the claim
that nothing UML inherited reaches guest userspace, so it is checked directly
rather than argued:

```sh
make stub-fd-audit-el7
```

That hands UML a crowded, sparse descriptor table -- forty inheritable
descriptors plus one at 900 -- and then reads the live stub's `/proc/<pid>/fd`
while a guest is running. It requires that none of them survive, that the stub
settles holding only its signalling socket, and that it is running with
`NoNewPrivs=1` and `Seccomp=2`. It exercises whichever cleanup path the host
takes, so it is worth running on a current host too.

`POCKET_FD_AUDIT_SCENARIO` selects what it is asked to survive:

| | |
|---|---|
| `crowded` (default) | the descriptor table above, with the console on descriptor 0 |
| `free-fd0` | descriptor 0 unused at startup, so UML may place its own there |
| `low-nofile` | the soft descriptor limit dropped below an already-open descriptor |

The last one is the reason the fallback enumerates rather than looping to a
bound: Linux permits lowering `RLIMIT_NOFILE` below an open descriptor, so a
bounded loop would walk straight past it.

`POCKET_KERNEL_VARIANT=el7` is the underlying switch if you are calling the
scripts directly. An unrecognised value is refused rather than ignored.

## What the patches do

Eight of the fourteen are build compatibility: names and wrappers that a glibc
2.17-era header set does not have, for constants and syscalls the kernel has
had for years. They change no behaviour on a current host.

| Patch | File |
|---|---|
| `0001` ARM relocation names absent from glibc 2.17's `elf.h` | `scripts/mod/modpost.h` |
| `0002` `copy_file_range` wrapper (glibc 2.27) | `usr/gen_init_cpio.c` |
| `0003` `PTRACE_SYSEMU` (glibc 2.27) | `arch/x86/um/shared/sysdep/ptrace_user.h` |
| `0004` `gettid` wrapper (glibc 2.30) | `arch/um/os-Linux/time.c` |
| `0005` `getrandom` wrapper and `<sys/random.h>` (glibc 2.25) | `arch/um/os-Linux/util.c` |
| `0006` glibc/kernel signal FP-state type clash | `arch/x86/um/os-Linux/mcontext.c` |
| `0007` `PACKET_QDISC_BYPASS` (Linux 3.14) | `arch/um/drivers/vector_user.c` |
| `0008` `statx` (Linux 4.11, glibc 2.28) | `fs/hostfs/hostfs_user.c` |

Six are functional:

**`0009` — clone without disturbing the libc id cache.** A `clone` that issues
the syscall directly and enters the child on its own stack, so libc's cached
process and thread ids are never overwritten. The section below explains what
depends on that.

**`0010` — probe with the syscall the filter names.** Replaces `sleep(0)` with
a raw `clock_nanosleep`, so a host whose seccomp support is complete is
recognised as such. Turns the `close_range` requirement into a check of the
cleanup this host will actually perform, separates a refused
`PR_SET_NO_NEW_PRIVS` from a refused filter, and clones the probe raw.

**`0011` — launch the stub without `execveat` or `close_range`.** Where
`execveat` is missing, the stub is still reachable by name through the
descriptor that is open at that moment, so it is named that way; the path is
formatted by hand because this runs in a `CLONE_VM | CLONE_VFORK` child sharing
the address space of a suspended parent. Where `close_range` is missing,
`/proc/self/fd` is enumerated with raw `openat`/`getdents64` and everything
outside an exact keep-list is closed, with every record validated before it is
trusted and any incomplete step fatal — a descriptor whose fate is unknown may
reach the guest, and one of them maps all of UML's physical memory.

**`0012` — close the stub's mapping descriptors without `close_range`.** The
trampoline has already proven what survived, so the stub closes the two mapping
descriptors by number. It also gives `SECCOMP_RET_KILL_PROCESS` its value where
the headers are too old to name it, rather than aliasing it to
`SECCOMP_RET_KILL` -- which is the *thread* kill, and would let the build
host's headers decide the filter's kill semantics on whatever kernel runs the
result.

**`0013` — run driver helpers without disturbing the id cache.** The third and
last `CLONE_VM` site. Nothing pocket runs reaches it, but leaving one caller
behind would make the corruption harder to reach rather than gone.

**`0014` — deliver IPIs without the libc pid cache.** Removes the dependency
from the interrupt path outright, and makes a dropped interrupt loud.


## What this turned up

None of it is specific to pocket, and all of it is invisible on an ordinary
current host — which is why it was still there to find.

### One root cause, two symptoms: libc's clone corrupts the caller's ids

libc's `clone()` stores `-1` into the thread control block's cached process and
thread ids whenever `CLONE_VM` is set without `CLONE_THREAD`; it cannot cheaply
learn the ids the child was given. UML clones exactly that way, and does not
pass `CLONE_SETTLS`, so the child shares the caller's control block and the
`-1` lands in the UML kernel thread itself. libc 2.25 removed the cache, so no
current host sees any of this.

libc before that reads those ids back, and builds syscalls out of them:

**UML never exits.** `pthread_cancel()` sends `tgkill(cached_pid, tid,
SIGCANCEL)`. With the pid at `-1` the cancel is never delivered, the helper
thread never terminates, and the `pthread_join()` behind it blocks forever:

```
pthread_join()          ← never returns
os_kill_helper_thread()
sigio_cleanup()
machine_power_off()
```

The guest powers down normally — and the host process stays alive indefinitely.
Anything supervising it sees a run that never finishes.

**SMP stops making progress.** `pthread_sigqueue()` builds its syscall the same
way, so every inter-processor interrupt is `rt_tgsigqueueinfo(-1, ...)` and
returns `EINVAL`. All five callers discard the result, so a multi-CPU guest
simply stalls with every CPU idle and nothing logged.

Both are fixed at the cause, by `0009`: a clone that issues the syscall
directly and never touches the cache. `0010`, `0011` and `0013` move UML's
three `CLONE_VM` sites onto it. `0014` additionally stops the IPI path reading
the cache at all and makes a dropped IPI `panic()` rather than return into a
hang — no caller checks, and a lost reschedule is not survivable.

Isolated by `make host-clone-idcache-probe`, which cancels and joins a helper
thread after cloning three ways and reports what it observes. It depends on
nothing this repository builds, so it runs on a candidate host on its own:

| | baseline | after a **raw** clone | after a **libc** clone |
|---|---|---|---|
| CentOS 7, glibc 2.17 | joins | joins | **hangs** |
| Ubuntu 26.04, glibc 2.43 | joins | joins | joins |

### UML crashes when started with descriptor 0 free

Nothing guarantees a process is handed open standard descriptors, and UML
allocates its mapping and stub-executable descriptors from whatever is
available. If one lands on descriptor 0, `userspace_tramp()`'s
`dup2(sockpair[0], 0)` overwrites it and the guest's first userspace process
takes the kernel down:

```
fatal_sigsegv+0x48
wait_stub_done_seccomp+0x2ba
userspace+0x10a
```

That reproduces on a current, unpatched host — it is not an EL7 problem at all.
`0011` moves anything still needed off descriptor 0 before the socket claims
it. The `free-fd0` scenario is the evidence, and the asymmetry is the point:
`make stub-fd-audit-el7` runs it and passes, while `make stub-fd-audit` does
not run it at all, because the release kernel this repository ships still
crashes on it.

### Two latent trampoline bugs

The same function closed the signalling socket after a `dup2()` onto itself —
which would close the descriptor just installed — and cleared close-on-exec on
only one of the two mapping descriptors. Both are unreachable today, and `0011`
fixes them while it is restructuring that code anyway.


## Host settings this needs

RHEL 7 and its rebuilds ship `user.max_user_namespaces` at 0, so unprivileged
user namespaces are refused even though the kernel supports them. UML itself
does not need one, but the unprivileged networking path does, so raise it if
you want guest networking:

```sh
sudo sysctl -w user.max_user_namespaces=15000
```

The kernel already has the support compiled in on 7.9; nothing needs a reboot.

## Limits

`seccomp=on` on this kernel is not a stronger sandbox than it is anywhere else,
and the upstream warning applies unchanged: the backend is for trusted guest
userspace. An EL7 host additionally carries its own lifecycle and security
position, which this variant does not change.

The variant's artifact digests are bound to the reference toolchain above, as
the default build's are bound to its own. A different compiler or linker
produces different bytes and fails the build closed rather than shipping
something unverified.

Two diagnostic targets cannot be built on the validated host. `make probe`
needs busybox and `make smp-scaling` needs `musl-gcc` to build the initramfs
each one boots, and neither tool is present on EL7, in the reference toolchain,
or in that host's package repositories. Nothing about that is specific to the
variant: both need the same two tools on any host, and neither builds anything
the product ships.

Booting one is a separate question from building it. `make stub-fd-audit-el7`
boots the probe initramfs without building it, so it runs on an EL7 host that
was given one -- which is how the descriptor invariant above was established
there. `make verify-el7` says plainly when there is no probe initramfs to check
rather than demanding one the host cannot produce.
