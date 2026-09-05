# pocket_vm

**A rootless, unprivileged Linux VM with a container-shaped CLI.**

Every workload gets its own mainline Linux kernel, running entirely in user
space via
[User-Mode Linux](https://docs.kernel.org/virt/uml/user_mode_linux_howto_v2.html)
— not a namespaced view of yours. On the host it is an ordinary process owned
by you: no root, no setuid helper, no `CAP_*`, no KVM, no `/dev` node, no
daemon, nothing to install as an administrator.

It takes ordinary OCI images and the commands you already know.

## Familiar commands

If you know Docker, you already know this:

```sh
pocket image pull ubuntu:24.04                    # docker pull
pocket run ubuntu:24.04 -- /bin/sh -c 'nproc'     # docker run
pocket run -t ubuntu:24.04 -- /bin/bash           # docker run -it
pocket ps -a                                      # docker ps -a
pocket start build                                # docker start
pocket commit build ubuntu:with-tools             # docker commit
pocket rm build                                   # docker rm
```

The flags are the ones you would guess:

```sh
pocket run --name build --cpus 4 --memory 2G \
  --volume "$PWD:/work" --user daemon --workdir /work \
  -e BUILD=release ubuntu:24.04 -- /bin/bash -c 'echo $BUILD; nproc; ls'
```

A run is kept when it exits, so you can come back to what it produced — list it
with `ps -a`, run it again on the filesystem it left behind with `start`, turn
it into an image with `commit`, drop it with `rm`, or pass `--rm` to not keep it
at all.

Where it differs, it says so by name rather than failing obscurely: there is no
daemon, so `attach`, `exec` and `-d` are refused with the reason. A run is a
foreground process you own, and its exit status is yours.

## Requirements

x86_64 Linux, kernel **5.9 or newer**, and no privilege of any kind — no root,
no `sudo`, no kernel module, no `/dev/kvm`, `/dev/net/tun` or `/dev/fuse`.

The kernel floor is UML's: every run uses its `seccomp` mode, whose stub needs
`close_range`. Nothing else about the distribution matters at run time, because
everything shipped is statically linked and depends on nothing the host
provides.

That floor is UML's source, not seccomp's. An experimental, opt-in kernel
variant lifts it for EL7-vintage hosts — kernel 3.10, glibc 2.17 — and boots a
guest there under `seccomp=on`. It is off unless asked for by name and does not
affect the default build: see [EL7 host support](docs/el7-host-support.md).

Building additionally wants Rust 1.93.1 exactly, the Linux 7.2 tree's own tool
minimums (GCC 8.1, binutils 2.30, make 4.0, Python 3.9), and a host that allows
unprivileged user namespaces. Verified end to end on Ubuntu 26.04;
[Getting started](docs/getting-started.md) has the full list and a
distribution table.

## Quick start

```sh
# Build and install. The build fetches and GPG-verifies Linux 7.2, compiles it,
# then installs and writes a config file so no command needs path flags.
make install PREFIX="$HOME/.local"
export PATH="$HOME/.local/bin:$PATH"

pocket image pull ubuntu:24.04
pocket run ubuntu:24.04 -- /bin/sh -c '. /etc/os-release; echo "$PRETTY_NAME"'
```

```
Ubuntu 24.04.4 LTS
```

That is a Linux kernel booting, mounting the converted image and running your
command — from an unprivileged process on your host.

## What the kernel buys you

Because the guest owns a kernel rather than borrowing yours, it can do things a
container cannot, and none of it costs the host any privilege:

- **Outbound networking by default**, with no TUN device, no `CAP_NET_ADMIN`
  and nothing to configure — the guest reaches a userspace TCP/IP stack over a
  Unix socket.
- **Real terminals.** `-t` gives an interactive session on a guest PTY, so job
  control, `^C`, line editing and full-screen programs work, and resizing your
  window resizes the guest's. `--consoles N` adds extra serial lines, each with
  a login shell already on it and published as a host pseudo-terminal you can
  `screen` into while the workload runs.
- **Resizable disks.** `pocket image adjust --size 32G` republishes an image's
  filesystem at another size.
- **Its own mounts, cgroups and namespaces** — enough to run a full container
  engine, unmodified. Not a shim and not a compatible subset: the stock
  `docker:dind` image and the real `dockerd`, started by an unprivileged
  process on your host.

  ```sh
  pocket run --privileged --cpus 4 --memory 2G \
    -e DOCKER_HOST=unix:///var/run/docker.sock docker:27-dind -- /bin/sh -c '
      dockerd --host=unix:///var/run/docker.sock >/tmp/d.log 2>&1 &
      until docker info >/dev/null 2>&1; do sleep 1; done
      docker run --rm hello-world'
  ```

  ```
  Hello from Docker!
  ```

  `docker info` inside reports `engine=27.5.1 storage=overlay2 cgroup=v2
  kernel=7.2.0-pocket.1` — its own kernel, not yours. It is the sharpest
  measure of what owning a kernel means, because the daemon wants mount
  namespaces, cgroup writes and its own overlay filesystem, which is exactly
  the list a container cannot have. `--privileged` grants all of it inside the
  guest and nothing at all on your machine. `make container-engine` reproduces
  it.

Installing elsewhere? `make package` writes a single relocatable tarball that
carries its own installer, so the receiving machine needs no toolchain and no
checkout.

Full walkthrough, prerequisites and gotchas: **[Getting started](docs/getting-started.md)**.

## Why

- **Unprivileged where that is normally the hard part.** Mounts, device nodes,
  cgroups and networking all work *inside* the guest without `/dev/fuse`, a
  host user namespace or a delegated cgroup on your side. The network is a
  userspace TCP/IP stack over a Unix socket, not a TUN device.
- **A kernel, not a namespace.** Own scheduler, page cache and filesystem, so
  guest root is genuinely root — of something that is not your machine.
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

Every claim here has a committed target behind it, so you can check it rather
than trust it:

| | |
|---|---|
| `make test` | Rust suite, Clippy (warnings denied), rustfmt, ShellCheck |
| `make rust-release-e2e` | Ubuntu 24.04 + 26.04 end to end |
| `make lifecycle-soak` | 100 fresh lifecycles at one vCPU count; run per count for the full matrix |
| `make distro-matrix` | six unrelated image families |
| `make diagnostic-lifecycle` | the same lifecycles under lockdep, `PROVE_RCU` and `DEBUG_ATOMIC_SLEEP` |
| `make terminal-session` | one interactive `-t` session driven through a real PTY |
| `make image-adjust` | an image resized both ways, each result booted |
| `make instances` | a kept run listed, committed into an image, and removed |
| `make container-engine` | dockerd inside the guest, running containers of its own |
| `make reproduce-release` | byte-identical rebuild in an independent build root |

**Not supported:** inbound port forwarding, arm64, and private registries.
Docker's `attach`, `exec` and `-d` are refused by name:
there is no daemon, so a run is a foreground process you own. `pocket ps -a`
lists what is running and what was kept; runs are kept when they exit, named
with `--name`, turned into images with `pocket commit`, and removed with
`pocket rm`.

This is a runtime for workloads you already trust — it is deliberately **not**
a security boundary against hostile code.

## Upstream kernel fixes

pocket_vm carries eight UML patches against Linux 7.2. Four of them fix real
upstream defects; the rest adjust build-time policy.

Three fix one defect that made multi-CPU UML unusable:

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
