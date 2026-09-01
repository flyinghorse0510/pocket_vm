# pocket_vm

**Run Docker images in a real Linux kernel — without root, KVM, or a daemon.**

pocket_vm boots an actual mainline Linux kernel per container using
[User-Mode Linux](https://docs.kernel.org/virt/uml/user_mode_linux_howto_v2.html),
so a workload gets a genuine kernel of its own rather than a namespaced view of
yours. It needs no root, no setuid helper, no `CAP_*`, no KVM, no user
namespaces, and no privileged mounts — just an ordinary unprivileged process.

Your existing images work unchanged. Point it at anything on a registry.

## Quick start

```sh
# Build and install. The build fetches and GPG-verifies Linux 7.2, compiles it,
# then installs and writes a config file so no command needs path flags.
make install PREFIX="$HOME/.local"
export PATH="$HOME/.local/bin:$PATH"

pocket image pull alpine:3.22

pocket run alpine:3.22 -- /bin/sh -c 'cat /etc/alpine-release'
```

```
3.22.5
```

That is a Linux kernel booting, mounting the converted image, and running your
command as an unprivileged user.

The guest has outbound network access by default, with no setup and no host
privilege — no TUN device, no `CAP_NET_ADMIN`, nothing to configure:

```sh
pocket run alpine:3.22 -- /bin/sh -c 'apk add --no-cache curl && curl -sI https://example.com | head -1'
```

Because the guest has its own kernel, it can run things a container cannot.
Docker included:

```sh
pocket run --privileged docker:27-dind -- /bin/sh -c \
  'dockerd & sleep 10; docker run --rm hello-world'
```

That is a Docker daemon, with overlay2 and cgroup v2, inside a guest you
started as an ordinary user. The usual reason to be wary of that — the inner
engine having privileges over the *host's* kernel — does not apply here: the
guest's kernel is its own, and the host boundary is an unprivileged process
either way.

Share a folder with the host, and ask for more of the machine:

```sh
pocket run --volume "$PWD:/work" --cpus 4 --memory 2G alpine:3.22 -- \
  /bin/sh -c 'nproc && ls /work'
```

Building once and installing elsewhere? `make package` writes a single
relocatable tarball that carries its own installer, so the receiving machine
needs no toolchain and no checkout.

Full walkthrough, prerequisites and gotchas: **[Getting started](docs/getting-started.md)**.

## Why

- **No privilege on the host.** No root, no setuid, no capabilities, no KVM,
  no `/dev/fuse`, no host user namespaces, no writable host cgroups — and
  networking still works, because the guest reaches a userspace TCP/IP stack
  over an ordinary Unix socket rather than a TUN device. Works where you
  cannot install or configure anything.
- **A real kernel per container.** Own scheduler, own page cache, own
  filesystem. Not a shared host kernel behind namespaces.
- **Your images, unmodified.** Verified against Debian, Alpine, Arch, Fedora,
  BusyBox, and `scratch` images with no shell and no `/etc`.
- **Verifiable builds.** The kernel is fetched and signature-checked at build
  time, never vendored. The whole release reproduces byte-for-byte in an
  independent build root.

## How it works

1. **Acquire** — a sealed, static Skopeo pulls the image into an OCI layout.
2. **Verify** — every blob digest and the manifest graph are authenticated
   before anything is built.
3. **Convert** — a *builder* UML unpacks the layers into an ext4 image.
4. **Validate** — a *second*, read-only UML independently re-walks the result
   and checks it against the builder's evidence.
5. **Run** — the image is published immutable (mode `0400`), and each run gets
   a fresh copy-on-write overlay on top of it.

Writes inside the container go to that overlay, so `apk add` works — but the
overlay is discarded when the run ends. To keep data, share a host directory
with `--volume /host/dir:/guest/dir`; it is the host's own folder, so writes
land there and survive.

## Status

Working and reproducible on `linux/amd64`; the profile is marked
**experimental** until the remaining gates in the
[support matrix](docs/release-support-matrix.md) pass.

Every claim here is produced by a committed target, so you can check it rather
than trust it:

| | |
|---|---|
| `make test` | Rust suite, Clippy (warnings denied), rustfmt, ShellCheck |
| `make rust-release-e2e` | Ubuntu 24.04 + 26.04 end to end |
| `make lifecycle-soak` | 500 launches at 1/2/4/12/16 vCPUs, plus concurrent waves |
| `make distro-matrix` | six unrelated image families |
| `make diagnostic-lifecycle` | the same lifecycles under lockdep, `PROVE_RCU` and `DEBUG_ATOMIC_SLEEP` |
| `make reproduce-release` | byte-identical rebuild in an independent build root |

**Not supported:** inbound port forwarding, arm64, private registries, and
interactive TTYs. This is a runtime for workloads you already trust — it is
deliberately **not** a security boundary against hostile code.

## Upstream kernel fix

pocket_vm carries eight UML patches against Linux 7.2. Four of them fix real
upstream defects. Three made multi-CPU UML unusable:

`arch/um/drivers/chan_kern.c` drained its deferred channel-IRQ list from
`_sigio_handler()` — the SIGIO *signal handler*. `free_irq()` may sleep, and
under `CONFIG_SMP=y` it reaches `synchronize_rcu()`, so `schedule()` ran from
inside an interrupt: scheduler corruption, RCU stalls, and kernel panics.

A `CONFIG_SMP=n` control passed, because there `synchronize_irqwork()` is an
empty stub and Tiny RCU never waits — which is why `SMP=n` looked fine while
`SMP=y ncpus=1` failed. The vCPU count was never the variable. The fix drains
the list from a work item in process context.

The fourth is in the network driver, and lockdep found it the first time this
project enabled one. `vector_poll()` takes a queue lock from NAPI — softirq
context — while `vector_reset_stats()` and `vector_get_ethtool_stats()` took
the same lock in process context with softirqs enabled: a self-deadlock, on
every boot with a network device. Those two now take it with softirqs off.

The remaining four arm the stub's parent-death signal before `exec`, expose
the kernel's accepted physical memory size so the host can verify its request
was honoured, and let the vector driver be built into a statically linked
kernel by confining the NSS dependency to the two transports that actually
resolve a name.

## Documentation

- [Getting started](docs/getting-started.md) — build it and run your first image
- [CLI reference](crates/pocket/README.md) — the complete command surface
- [Kernel source contract](kernel/README.md) — how the kernel is fetched and verified
- [Release support matrix](docs/release-support-matrix.md) — what is and is not qualified
- [Design study](docs/uml-rootless-container-feasibility.md) — the architecture in depth

## License

Dual-licensed under [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your
option.
