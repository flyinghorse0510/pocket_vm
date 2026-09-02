# Getting started

Build the runtime from source, then run an ordinary Docker image on it.

Everything below was run verbatim on Ubuntu with a 12-core x86_64 host. Two
things to know before you start:

- The first build fetches and *verifies* a Linux 7.2 tarball, e2fsprogs,
  Skopeo, slirp4netns and a Go toolchain, then compiles a kernel. Budget
  **40-60 minutes** and roughly **10 GB** of disk. Later builds reuse the
  downloads, but each one that replaces the kernel source or output *keeps*
  the old tree as evidence under `build/src/replaced/` and
  `build/kernel/replaced/` — roughly 1.8 GB per replaced source tree and
  150 MB per kernel output, never reclaimed for you. See
  [When something goes wrong](#when-something-goes-wrong).
- This is `linux/amd64` on an x86_64 host only, and it is deliberately **not**
  a security boundary against hostile code. It is a runtime for workloads you
  already trust.

## Prerequisites

No root is needed for anything here, including running containers. The build
needs packages; installing them is the only step that uses `sudo`.

```sh
sudo apt install -y \
  autoconf automake bc bison bubblewrap build-essential cpio curl file flex \
  git gnupg jq libtool make meson ninja-build openssl pkg-config python3 \
  rsync shellcheck xz-utils
```

You do **not** need `skopeo`, `mke2fs`, `e2fsck` or `slirp4netns` on the host —
the build produces its own static copies and uses only those.

The optional probe lanes need two more packages; `make release-profile` does
not:

```sh
sudo apt install -y busybox-static musl-tools
```

Rust must be **exactly 1.93.1** — the release build refuses any other version,
because the artifact digests are pinned to it:

```sh
rustup toolchain install 1.93.1 && rustup default 1.93.1
rustc --version    # rustc 1.93.1
```

You do **not** need Go installed. The Skopeo build downloads a pinned Go
toolchain, checks its SHA-256, and uses it in an isolated cache.

The first build needs HTTPS access to `cdn.kernel.org`, `github.com`,
`gitlab.freedesktop.org`, `download.gnome.org`, `curl.se`, `go.dev`,
`proxy.golang.org` and `sum.golang.org`, plus `hkps://keyserver.ubuntu.com`
to fetch the e2fsprogs signing key. Pulling an image later needs access to
whichever registry you name.

## Build

```sh
git clone <this repository> pocket_vm
cd pocket_vm
make release-profile
```

That single target does everything, in order:

1. **`make kernel`** — downloads `linux-7.2.tar.xz`, checks its SHA-256 and
   the signature's, GPG-verifies it, and asserts the signer fingerprint is
   Greg Kroah-Hartman's. It then extracts a fresh tree, applies the eight
   patches in `kernel/patches/7.2/`, checks the patched tree against the
   identity recorded in `config/sources.lock.toml`, builds `ARCH=um`, and
   audits the source again afterwards.
2. **Host tools** — builds static e2fsprogs, Skopeo and slirp4netns from
   authenticated sources, each twice, requiring identical bytes. slirp4netns
   brings its own chain: zlib, libffi, PCRE2, GLib and libslirp.
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

pocket image pull alpine:3.22
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

# An absolute archive path: the installer will not resolve one against the
# working directory.
./pocket-vm-install install --archive "$PWD/pocket-vm-....tar" \
  --prefix "$HOME/.local"
```

That is the same digest-checked install as `make install`, and it writes the
same config file.

Let the installer unpack it. The archive's directories are `0555`, mirroring
the read-only tree it publishes, so a plain `tar -xf` fails part-way with
`Cannot open: Permission denied`, and forcing it through gives you an
unverified tree with no launcher and no config.

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

`pull` and `run` need three directories. They are separate because they have
different lifetimes and different trust. Other commands need only what they
touch — `ps` just the runtime root, `cache gc` just the store:

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
pocket image pull alpine:3.22
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
binary is `build/release/<profile>/host/pocket` — for the default profile,
`build/release/x86_64-smp-p4k/host/pocket` — and each command needs the paths
above, either as flags or from a config file.

```sh
pocket image pull alpine:3.22
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
your command. On the host it is an ordinary unprivileged process: no root, no
KVM, no host user namespace, no privileged mount. (Inside the guest,
namespaces do exist — that is how it runs Docker.)

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

There is no config-file setting for this; the config file carries the three
paths only.

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

slirp4netns marks its bess mode experimental, and this build inherits that.

## Running containers inside the guest

The guest has its own kernel, so it can run a container engine with its own
overlay filesystem, cgroups and networking. Docker is what `make
container-engine` exercises; other engines are untested here. Pass
`--privileged`:

```sh
pocket run --privileged --cpus 4 --memory 2G \
  -e DOCKER_HOST=unix:///var/run/docker.sock docker:27-dind -- /bin/sh -c '
    dockerd --host=unix:///var/run/docker.sock >/tmp/d.log 2>&1 &
    until docker info >/dev/null 2>&1; do sleep 1; done
    docker run --rm hello-world'
```

```
Hello from Docker!
This message shows that your installation appears to be working correctly.
```

`docker info` inside reports `overlay2`, `cgroup v2`, and kernel
`7.2.0-pocket.1` — its own, not yours.

**Why `--privileged` is safe here, and is not the same thing Docker means by
it.** In Docker, `--privileged` hands a container capabilities over the
*host's* kernel, which is why it is a serious decision. Here the guest kernel
*is* the isolation, and the host boundary is an unprivileged process that this
flag does not touch. Granting the guest every capability changes what the
workload can do to its own kernel and nothing about what it can do to yours.

It is still opt-in rather than the default, because most workloads never need
`CAP_SYS_ADMIN` and a smaller set is a better default.

Two practical notes:

- **`/var/lib/docker` does not survive the run.** The root filesystem is a
  copy-on-write overlay that is discarded, so images are pulled again each
  time. A `--volume` will *not* fix this: `hostfs` has no extended attributes
  and overlay2 requires them. Keeping an engine's storage across runs is not
  solved here.
- **The `docker:dind` image presets `DOCKER_HOST` to a TCP endpoint** for its
  own daemon-in-a-sibling-container arrangement. Override it as above, or the
  client will look for a daemon that is not there.

Reproduce all of this with `make container-engine`.

## An interactive shell

`-t` gives the workload a real terminal, the same way `docker run -it` does:

```sh
pocket run -t alpine:3.22 -- /bin/sh
```

```
/ # whoami
root
/ # exit
```

The guest allocates a PTY and makes it the workload's controlling terminal, so
`^C`, `^D`, line editing and full-screen programs like `vi` work, and `tty`
resolves to a real `/dev/pts/N`. Resizing your window resizes the guest's.

To get a session as an account the image already defines, name it:

```sh
pocket run -t --user daemon debian:13 -- /bin/bash
```

```
daemon@pocket:/$ id
uid=1(daemon) gid=1(daemon) groups=1(daemon)
```

`--user` takes a name or a `uid:gid`, and resolves names against the image's
own `/etc/passwd`, captured when the image was converted.

The image's own `login` also works, because the terminal is real:

```sh
pocket run -t debian:13 -- /bin/login -f root
```

That prints the image's MOTD and gives you a login shell. `-f` is what skips
authentication; a plain `login` prompts for a password, which base images do
not set for `root`, so use it with an account whose password you have set.

Two things to know:

- **`-t` needs a terminal on both sides.** Piping into it is refused rather
  than quietly falling back to buffered streams. Drop `-t` to pipe.
- **`^C` goes to the workload, not to `pocket`.** The host terminal is raw for
  the session, so the guest decides what a keystroke means. Exit the workload
  to end the run.

## Coming back to a finished run

A run is kept when it exits, the way a container is:

```sh
pocket run --name build-one alpine:3.22 -- /bin/sh -c 'echo built > /out'
pocket ps -a
```

```
name=build-one status=exited(0) image=alpine:3.22 created=... command=/bin/sh -c echo built > /out
```

Without `--name` you get a generated one like `nimble-delta-1d4d`. Add `--rm` to
throw the run away instead; the two cannot be combined, because a discarded run
leaves nothing to name.

What is kept is the run's copy-on-write overlay, inside the store. It is sparse,
so it costs what the workload wrote rather than the size of the filesystem, and
it keeps its image alive -- `cache gc` will not collect an image a kept run
still needs. Remove it when you are done:

```sh
pocket rm build-one
```

Turn what a run produced into a new image with `commit`, the way
`docker commit` does:

```sh
pocket run --name build alpine:3.22 -- /bin/sh -c 'apk add --no-cache jq'
pocket commit build alpine:with-jq
pocket run --rm alpine:with-jq -- jq --version
```

```
jq-1.8.1
```

The image you started from is not modified; `commit` publishes a new one beside
it.

Accounts the run created come with it, and can be selected by name:

```sh
pocket run --name setup alpine:3.22 -- /bin/sh -c 'adduser -D -u 1000 alice'
pocket commit setup alpine:alice
pocket run --user alice alpine:alice -- id
```

```
uid=1000(alice) gid=1000(alice)
```

## A second terminal into a running guest

`--consoles N` adds serial lines to the guest and publishes each as a
pseudo-terminal you can attach to, the way `-serial pty` works on qemu:

```sh
pocket run --consoles 1 alpine:3.22 -- /bin/sh -c '
    setsid sh -c "exec /bin/sh -i </dev/ttyS4 >/dev/ttyS4 2>&1" &
    sleep 300'
```

```
pocket: guest /dev/ttyS4 is attachable at /dev/pts/10
```

Then from another terminal:

```sh
screen /dev/pts/10
```

You get a second, independent shell inside the same guest while the workload
keeps running.

The runtime provides the line; it does not decide what listens on it. A run
executes one process and there is no init spawning login prompts, so the
`setsid` line above is what puts a shell there. Inside the guest the lines are
`/dev/ttyS4` upwards, and at most 8 can be asked for.

## Disk space inside the guest

A converted image's filesystem is at least **8 GiB**, and that is also the
workload's writable space: everything outside a `--volume` goes to the
copy-on-write overlay above it, including `/tmp`.

```sh
pocket run alpine:3.22 -- df -h /
```

The space is fixed when the image is converted, not when it runs, so change it
on the image:

```sh
pocket image adjust --size 32G alpine:3.22     # same name, bigger filesystem
pocket image adjust --size 2G --reference alpine:small alpine:3.22
```

Sizes must be a multiple of 4096 bytes. The original image is not modified --
`adjust` publishes a new one and moves the alias, and `--reference` keeps the
old name pointing where it did.

The file is sparse, so a large filesystem is cheap to keep: an 8 GiB base
holding Alpine occupies about 14 MB on disk. It is not free to *publish*,
because the whole logical file is hashed -- roughly 20 seconds at 8 GiB, and
proportionally longer above that.

## Using a local image instead of a registry

```sh
# an already-normalized OCI layout directory
pocket image import --reference local:tag \
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

## Seeing what is running

```sh
pocket ps
```

```
id=run-7c500389004fffd1777240d717e8afdc generation=pkvm-gen-v1-f1c8c0… pid=2654078 started=1788241378 cpus=1 memory_bytes=268435456
```

`--json` gives the same rows as JSON. There is no daemon behind this: each run
holds a lock on its own directory, and the kernel drops that lock when the
owner dies, so a run killed with `kill -9` disappears from the list at once.

**`attach`, `exec` and `-d` are not available**, and say so rather than looking
like typos:

```
pocket: [E_FEATURE_UNSUPPORTED] feature "detach" is unavailable: a run is a
foreground process with no daemon to hand it to; its exit status is the point,
and nothing would be left to report it
```

To run something in the background, background the `pocket` process itself —
it owns the run, and its exit status is the workload's.

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
for. To watch the boot happen instead of reading it afterwards -- the useful
form when a guest never reaches a prompt -- use `--boot-log`, which mirrors the
kernel console to stderr as it is produced and works alongside `-t`:

```sh
pocket run --boot-log alpine:3.22 -- /bin/true
```

```
[    0.000000] Linux version 7.2.0-pocket.1 ...
[    0.130000] EXT4-fs (ubda): unmounting filesystem ...
[    0.130000] reboot: Power down
```
 Errors are machine-readable: `E_CLI_INVALID_INPUT` means your command
line, `E_STORE` the store, `E_IMAGE_BUILD` the conversion, `E_GUEST` the
workload itself.

**If `build/` grows unexpectedly**, it is the retained trees. Every kernel
rebuild renames the previous source and output aside instead of deleting them,
so they can be audited later; nothing reclaims them automatically. Once you no
longer need that history, remove it yourself:

```sh
du -sh build/src/replaced build/kernel/replaced
rm -rf build/src/replaced build/kernel/replaced
```

## What is not supported

Stated plainly, so you do not go looking:

- **Inbound networking.** Outbound works by default; `-p/--publish` does not.
  See [Networking](#networking).
- **arm64.** `linux/amd64` on an x86_64 host only.
- **Private registries.** Pulls are anonymous by design; credential flags are
  rejected.
- **Host privileges.** `--privileged` grants capabilities inside the *guest*
  only. Nothing gives a workload any authority over the host.
- **`attach`, `exec`, `--detach`.** There is no daemon, and a run executes one
  process. `pocket ps` lists what is running; the rest refuse by name.

The full gate list, including what is and is not yet verified, is in
[the release support matrix](release-support-matrix.md). The CLI's complete
surface and its exact semantics are in
[the CLI reference](../crates/pocket/README.md).
