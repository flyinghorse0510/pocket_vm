# Getting started

Build the runtime from source, then run an ordinary Docker image on it.

Everything below was run verbatim on Ubuntu with a 12-core x86_64 host. Two
things to know before you start:

- The first build fetches and *verifies* a Linux 7.2 tarball, e2fsprogs,
  Skopeo and a Go toolchain, then compiles a kernel. Budget **40-60 minutes**
  and roughly **40 GB** of disk. Later builds reuse all of it.
- This is `linux/amd64` on an x86_64 host only, and it is deliberately **not**
  a security boundary against hostile code. It is a runtime for workloads you
  already trust.

## Prerequisites

No root is needed for anything here, including running containers. The build
needs packages; installing them is the only step that uses `sudo`.

```sh
sudo apt install -y \
  bc bison build-essential cpio curl file flex git gnupg jq make \
  musl-tools python3 shellcheck xz-utils
```

You do **not** need `skopeo`, `mke2fs` or `e2fsck` on the host — the build
produces its own static copies and uses only those. They appear in the
prerequisites of the optional probe lanes, not of `make release-profile`.

`busybox-static` is needed only for the optional probe lanes:

```sh
sudo apt install -y busybox-static
```

Rust must be **exactly 1.93.1** — the release build refuses any other version,
because the artifact digests are pinned to it:

```sh
rustup toolchain install 1.93.1 && rustup default 1.93.1
rustc --version    # rustc 1.93.1
```

You do **not** need Go installed. The Skopeo build downloads a pinned Go
toolchain, checks its SHA-256, and uses it in an isolated cache.

The first build needs HTTPS access to `cdn.kernel.org`, `go.dev`,
`proxy.golang.org`, `sum.golang.org`, `github.com` and `curl.se`. Pulling an
image later needs access to whichever registry you name.

## Build

```sh
git clone <this repository> pocket_vm
cd pocket_vm
make release-profile
```

That single target does everything, in order:

1. **`make kernel`** — downloads `linux-7.2.tar.xz`, checks its SHA-256 and
   the signature's, GPG-verifies it, and asserts the signer fingerprint is
   Greg Kroah-Hartman's. It then extracts a fresh tree, applies the five
   patches in `kernel/patches/7.2/`, checks the patched tree against the
   identity recorded in `config/sources.lock.toml`, builds `ARCH=um`, and
   audits the source again afterwards.
2. **Host tools** — builds static e2fsprogs and Skopeo from authenticated
   sources, each twice, requiring identical bytes.
3. **Rust artifacts** — builds the host CLI, the guard, and the three guest
   init programs as static PIEs.
4. **Initramfses** — packs the workload, builder and validator images
   reproducibly.
5. **Seals a profile bundle** — a content-addressed directory holding the
   exact kernel, tools and initramfses this runtime will use.

### Install it

The quickest path from here is to install into a prefix you choose. This also
writes a config file, so afterwards no command needs any path flags:

```sh
make install PREFIX="$HOME/.local"
export PATH="$HOME/.local/bin:$PATH"

pocket image pull --reference alpine:3.22 --platform linux/amd64 \
  docker://docker.io/library/alpine:3.22
pocket run alpine:3.22 -- /bin/sh -c 'cat /etc/alpine-release'
```

```
3.22.5
```

`make install` puts the release under `<prefix>/lib/pocket-vm/`, adds a
versioned launcher `<prefix>/bin/pocket-<release-id>`, and points
`<prefix>/bin/pocket` at it. Each install keeps the previous versions beside
the new one, so pointing that symlink at an older launcher rolls back.

It also writes `~/.config/pocket/config.toml` naming the installed profile, a
store under `~/.local/share/pocket/store`, and a runtime root under
`$XDG_RUNTIME_DIR` — which is short and on tmpfs, both of which UML prefers.
An existing config is never overwritten. To choose different locations, or to
skip either piece of setup:

```sh
make install PREFIX="$HOME/.local" \
  STORE="$HOME/data/pocket-store" RUNTIME_ROOT=/run/user/$(id -u)/pocket
make install PREFIX="$HOME/.local" NO_CONFIG=1 NO_DEFAULT_LINK=1
```

`CONFIG=<path>` writes the config file somewhere else; `pocket` then needs
`POCKET_CONFIG` set to find it.

If the prefix is group- or other-writable, the installer refuses and says how
to fix it. On distributions with a `002` umask, `~/.local` is often `0775`:

```
install-release: installation prefix component is group- or other-writable
(mode 0775): /home/you/.local
  fix it with: chmod go-w /home/you/.local
  or install somewhere else with: make install PREFIX=<dir>
```

### Or take the tarball

`make package` produces one relocatable, self-contained archive — kernel,
tools, initramfses, CLI and the installer itself — which installs on another
machine with no toolchain, no repository and no build:

```sh
make package                       # prints package=<path>.tar
```

Copy that one file to the other machine. The installer travels inside it, so
nothing else is needed — take it out and run it:

```sh
tar -xf pocket-vm-....tar --strip-components=2 --wildcards \
  '*/bin/pocket-vm-install' '*/bin/pocket_release.py'

./pocket-vm-install install --archive pocket-vm-....tar --prefix "$HOME/.local"
```

That is the same digest-checked install as `make install`, and it writes the
same config file.

Do not unpack the whole archive by hand instead. Its directories are `0555`,
mirroring the read-only tree the installer publishes, so a plain `tar -xf`
fails part-way with `Cannot open: Permission denied` — it creates each
directory read-only before writing what goes in it. (`tar -xf ...
--delay-directory-restore` unpacks it, but you get an unverified tree with no
launcher and no config.) Let the installer do it.

From a checkout you can use the Makefile instead:

```sh
make install-archive ARCHIVE=/path/to/pocket-vm-....tar PREFIX="$HOME/.local"
```

The archive name carries the release revision, so re-running `make package`
after an unchanged build reproduces the same file and checks the bytes match
rather than overwriting it. `pocket-vm-install verify --archive ... --prefix
...` re-checks an installed tree against the archive at any time.

### Or use the build tree directly

The build prints its sealed bundle path as `"bundle"` in the JSON on the last
lines, and writes it to `build/profiles/latest`:

```sh
export POCKET_PROFILE_BUNDLE=$(cat build/profiles/latest)
echo "$POCKET_PROFILE_BUNDLE"
```

Each build publishes a new revision beside the old ones, so neither sorting by
name nor picking the newest directory is reliable — that file is what the build
actually sealed. If you keep several, name the one you want explicitly.

Check the build with `make test` (Rust suite, Clippy, rustfmt, ShellCheck) and
`make verify` (artifact ABI, linkage and locked digests).

## The three paths

Every command needs three directories. They are separate because they have
different lifetimes and different trust:

| Flag | What it is | Lifetime |
|---|---|---|
| `--profile-bundle` | The sealed, verified build you just made: kernel, tools, initramfses. Read-only, content-addressed. | One per build |
| `--store` | Where converted images live as immutable generations, plus their aliases. Created on first use. | Long-lived; shared across runs |
| `--runtime-root` | Scratch for one process's in-flight runs: the per-run COW file and UML sockets. | Emptied as runs finish |

**Write them down once instead of passing them every time.** Put them in
`~/.config/pocket/config.toml` and every command picks them up:

```toml
# ~/.config/pocket/config.toml
profile_bundle = "/home/you/pocket_vm/build/profiles/x86_64-smp-p4k/<revision>"
store          = "/home/you/.pocket/store"
runtime_root   = "/home/you/.pocket/run"
```

Then the commands get short:

```sh
pocket image pull --reference alpine:3.22 --platform linux/amd64 \
  docker://docker.io/library/alpine:3.22
pocket run alpine:3.22 -- /bin/sh -c 'cat /etc/alpine-release'
```

A flag always wins over the file, so you can point one command at a different
store without editing anything. Nothing is ever guessed: a path has a default
only because you wrote one down. The file is read from `$POCKET_CONFIG`, else
`$XDG_CONFIG_HOME/pocket/config.toml`, else `~/.config/pocket/config.toml`.

The grammar is deliberately tiny — `key = "value"`, `#` comments, blank lines —
and anything else is refused with the file and line, so a typo can never
silently send a command at the wrong store:

```
pocket: [E_CLI_INVALID_INPUT] invalid config:
        /home/you/.config/pocket/config.toml:2: unknown key "stores"
```

If you would rather not use a file, pass `--profile-bundle`, `--store` and
`--runtime-root` explicitly; omitting one without a config entry says so:

```
pocket: [E_CLI_INVALID_INPUT] invalid store: pass --store or set store in
        /home/you/.config/pocket/config.toml
```

Keep the **runtime root** short. A run creates AF_UNIX sockets inside it, and
the kernel's socket-address field is 108 bytes and cannot be raised, so once a
run directory and its socket leaf are accounted for the root itself may be at
most **66 bytes**:

```
pocket: [E_CLI_INVALID_INPUT] invalid runtime-root: runtime root is 95 bytes; a
run directory and its socket need the rest of the 107 the kernel allows for a
Unix socket path, so the maximum here is 66
```

`$XDG_RUNTIME_DIR/pocket/run` is 25 bytes, so the default has plenty of room.

The store and the profile bundle are **not** socket paths, and get a much
larger budget — 3840 bytes. They need it: a generation path spends 114 bytes on
`/generations/pkvm-gen-v1-<64 hex>/validation-evidence.cbor` before your store
root contributes anything.

## First run

Pull an ordinary image from a registry and run it. No special image
preparation: this is `docker.io/library/alpine:3.22` exactly as published.

The rest of this guide uses the installed `pocket` and the config file that
`make install` wrote. If you are working from the build tree instead, the
binary is `target/release/pocket` and every command below also needs
`--profile-bundle`, `--store` and `--runtime-root`.

```sh
pocket image pull --reference alpine:3.22 --platform linux/amd64 \
  docker://docker.io/library/alpine:3.22
```

`pull` fetches the image, authenticates every blob digest, converts it to an
immutable ext4 filesystem inside a builder UML, re-validates that filesystem
in a *separate* read-only UML, and publishes it. It prints a
`generation_id=pkvm-gen-v1-...` and an alias — here, `alpine:3.22`.

Now run it, by that alias:

```sh
pocket run alpine:3.22 -- /bin/sh -c 'cat /etc/alpine-release'
```

```
3.22.5
```

That is a real Linux kernel booting, mounting the converted image, and running
your command — with no root, no KVM, no user namespaces, and no privileged
mounts.

Ask for more vCPUs:

```sh
pocket run --cpus 4 alpine:3.22 -- /usr/bin/nproc
```

```
4
```

`run` uses the image's own `Entrypoint`, `Cmd`, `Env`, `User`,
`WorkingDir` and `StopSignal` when you give no command, and accepts
Docker-compatible overrides (`--entrypoint`, `--user`, `--workdir`, `-e`,
`--umask`, `--stop-signal`). It exits with the workload's exit status, and
reports `128+n` when the workload dies of a signal.

## CPU and memory

Both are per-run requests, and neither is clamped silently — if the host cannot
honour a request you are told, rather than quietly given less.

```sh
pocket run --cpus 4 --memory 2G IMAGE -- /usr/bin/nproc
```

`--cpus` defaults to `1` and accepts up to the profile's maximum (16 in the
shipped profile). If the host's CPU affinity or cgroup-v2 `cpu.max` cannot
actually deliver that many in parallel, the run still proceeds and prints a
note on stderr saying the guest will be oversubscribed.

`--memory` takes a decimal size (`512M`, `2G`, `4G`) and defaults to the
profile's own default. The guest reports the physical memory the kernel
actually accepted, and the host refuses the run if it differs from what was
requested — so `--memory 2G` means 2 GiB or an error, never a silent 1.5.

## Sharing a folder with the host

`--volume HOST_PATH:GUEST_PATH[:ro]` mounts a host directory into the guest
through hostfs. The guest sees the host's own files rather than a copy, so what
it writes lands on the host and **survives the run** — unlike the copy-on-write
root.

```sh
mkdir -p ~/work
echo 'from the host' > ~/work/input.txt

pocket run --volume "$HOME/work:/data" IMAGE -- \
  /bin/sh -c 'cat /data/input.txt && echo "from the guest" > /data/output.txt'

cat ~/work/output.txt      # from the guest
```

Both paths must be absolute, and the host directory must already exist. Append
`:ro` to mount it read-only, which the guest kernel enforces; `:rw` is the
default and may be written out. Up to 32 volumes per run. The host path may not
contain a colon — the first colon is the separator.

The guest destination cannot collide with a path the runtime mounts or writes
itself — `/proc`, `/sys`, `/dev`, `/run`, and the generated `/etc/hostname`,
`/etc/hosts` and `/etc/resolv.conf`. Sharing at `/etc` is refused for that
reason; `/etc/myconfig`, beside them, is fine:

```
pocket: [E_CLI_INVALID_INPUT] invalid volume.destination: /etc collides with
/etc/hostname, which the runtime mounts or generates itself
```

**One caveat, from the UML HOWTO:** hostfs does not watch the host for changes.
If you edit a file on the host *while a run is using it*, the guest may keep
serving a stale cached copy. Write from one side at a time — set inputs up
before the run, and read outputs after it — rather than treating the directory
as live shared memory between host and guest.

**One run at a time per directory.** A shared directory is claimed with an
exclusive lock on the directory itself for the length of the run — nothing is
written into your folder to take the claim, so there is nothing for a workload
to delete and nothing left behind afterwards. A second run asking for the same
directory is refused loudly:

```
pocket: [E_CLI_INVALID_INPUT] invalid volume.source: host path /home/you/work
is already shared by another running pocket; one shared directory is used by
one run at a time
```

Two guests writing one hostfs tree through independent page caches is a
corruption that cannot be made safe, so it fails instead of being serialized or
silently allowed. Different directories run concurrently without restriction.

Taking the claim needs no write permission, so an ordinary read-only share
works: a system data directory, or a tree deliberately made immutable, is
claimed like any other.

On a network filesystem the lock may be local to your machine, so two hosts
sharing one directory are not excluded from each other. Within one machine the
guarantee holds.

A shared directory is your own directory, with your own permissions, and
nothing about the immutable store applies to it: a workload can write anything
there that you could. That is what the feature is for.

## Networking

**On by default.** A run gets NAT'd outbound access — DNS, TCP, UDP — with no
setup and no host privilege:

```sh
pocket run alpine:3.22 -- /bin/sh -c 'apk add --no-cache curl && curl -sI https://example.com | head -1'
```

The guest lands on a private `10.0.2.0/24`:

| | |
|---|---|
| guest address | `10.0.2.100/24` on `vec0` |
| default gateway | `10.0.2.2` |
| resolver | `10.0.2.3`, written into `/etc/resolv.conf` |

Turn it off per run, and `/etc/resolv.conf` becomes empty rather than absent:

```sh
pocket run --network none alpine:3.22 -- /bin/sh -c 'wget -T 5 -O - http://example.com/'
```

Put `network = "none"` in your config file to make that the default.

### How it works, and why it needs no privileges

UML's `vector` driver has one transport that is simply an `AF_UNIX` socket:
**bess**. It needs no TUN device, no `CAP_NET_ADMIN`, and no host
configuration — unlike `tap` (which needs `TUNSETIFF` on `/dev/net/tun`) and
`raw` (which needs `CAP_NET_RAW`). The other end is `slirp4netns`, a userspace
TCP/IP stack that does the NAT, sealed into the profile like every other
artifact. Both sides implement the same documented protocol, so there is no
translation layer between them.

The guard starts the helper and stops it when the run ends, so a `SIGKILL`ed
`pocket` cannot leave one behind holding your socket open.

### What you do not get

- **Inbound connections.** `-p/--publish` is still refused. The helper accepts
  port forwards over an API socket, but nothing is wired to it yet.
- **Your LAN.** This is NAT, not bridging. The guest cannot be reached from
  another machine, and it is not on your network's subnet.
- **Throughput.** `slirp4netns` is a single-threaded userspace stack that
  copies every packet. Fine for `apk add`, `pip install` and API calls; poor
  for bulk transfer.
- **IPv6.** Not enabled.

Upstream marks bess mode experimental, and this build inherits that.

## Using a local image instead of a registry

```sh
# an already-normalized OCI layout directory
pocket image import --reference local:tag --platform linux/amd64 \
  --oci /abs/path/to/layout

# a single-image OCI or Docker archive
pocket image import ... --oci-archive /abs/path/to/image.tar
pocket image import ... --docker-archive /abs/path/to/saved.tar
```

`docker save`-style archives work. So do archives built by hand with
`tar -cf image.tar -C layout .`.

## What is immutable, and where your writes go

The converted image — `base.ext4` inside the store — is mode `0400` in a `0500`
directory and is never written to. Each run attaches it as the read-only
backing file of a **fresh copy-on-write overlay**:

```
ubd0=<runtime-root>/run-<id>/root.cow , <store>/generations/<id>/base.ext4
```

So inside the guest you have a normal read-write filesystem. `apk add`,
`apt install`, editing files — all work.

**But the overlay is discarded when the run ends.** The next run starts from
the pristine base again:

```sh
pocket run alpine:3.22 -- /bin/sh -c 'echo hi > /marker; cat /marker'   # hi
pocket run alpine:3.22 -- /bin/sh -c 'test -e /marker || echo gone'     # gone
```

This is deliberate — it is what lets many runs share one verified base. To keep
changes to the *image itself*, build a new image and import it. To keep
**data**, share a host folder with `--volume`: that is a real host directory and
it persists (see [Sharing a folder with the host](#sharing-a-folder-with-the-host)).

If you want the root read-only inside the guest as well, pass
`--root-readonly`.

## Managing the store

```sh
pocket image inspect alpine:3.22 --json

pocket cache roots            # what is keeping generations alive
pocket cache forget --alias <ALIAS_ID>
pocket cache gc     --apply
```

A generation stays on disk while any alias points at it. `cache gc` only
reclaims what nothing references, so drop the alias first with `cache forget`
if you want the space back.

To delete a whole store, note that `rm -rf` alone will not do it. Published
generations are mode `0400` files inside `0500` directories — that is what
"immutable" means here — and you need write permission on a directory to
remove what is in it:

```sh
chmod -R u+rwX ~/.local/share/pocket/store && rm -rf ~/.local/share/pocket/store
```

## When something goes wrong

Keep the guest kernel console — it holds kernel and guest-init diagnostics
(never your workload's output):

```sh
pocket run --console-log /tmp/guest.log alpine:3.22 -- /bin/true
```

It is written on success and on failure alike, which is the case it exists
for. Errors are machine-readable: `E_CLI_INVALID_INPUT` means your command
line, `E_STORE` the store, `E_IMAGE_BUILD` the conversion, `E_GUEST` the
workload itself.

## What is not supported

Stated plainly, so you do not go looking:

- **Inbound networking.** Outbound works by default; `-p/--publish` does not.
  See [Networking](#networking).
- **arm64.** `linux/amd64` on an x86_64 host only.
- **Private registries.** Pulls are anonymous by design; credential flags are
  rejected.
- **A TTY.** `--tty` is refused; streams are buffered and non-interactive.

The full gate list, including what is and is not yet verified, is in
[the release support matrix](release-support-matrix.md). The CLI's complete
surface and its exact semantics are in
[the CLI reference](../crates/pocket/README.md).
