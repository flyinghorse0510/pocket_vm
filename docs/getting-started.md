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

The build prints its sealed bundle path as `"bundle"` in the JSON on the last
lines. Keep it — every command needs it. To pick it up afterwards, take the
newest and strip the trailing slash, which the path validator rejects:

```sh
export POCKET_PROFILE_BUNDLE=$(
  ls -dt "$PWD"/build/profiles/x86_64-smp-p4k/*/ | head -1 | sed 's:/*$::'
)
echo "$POCKET_PROFILE_BUNDLE"
```

Each build publishes a new revision beside the old ones, so sorting by name
would hand you a stale profile. If you keep several, name the one you want
explicitly rather than guessing.

Check the build with `make test` (Rust suite, Clippy, rustfmt, ShellCheck) and
`make verify` (artifact ABI, linkage and locked digests).

## The three paths

Every command takes three directories and has no defaults for them, which is
the first thing that trips people up. They are separate because they have
different lifetimes and different trust:

| Flag | What it is | Lifetime |
|---|---|---|
| `--profile-bundle` | The sealed, verified build you just made: kernel, tools, initramfses. Read-only, content-addressed. | One per build |
| `--store` | Where converted images live as immutable generations, plus their aliases. Created on first use. | Long-lived; shared across runs |
| `--runtime-root` | Scratch for one process's in-flight runs: the per-run COW file and UML sockets. | Emptied as runs finish |

Pick a store and runtime root once and reuse them:

```sh
export POCKET_STORE="$HOME/.pocket/store"
export POCKET_RT="$HOME/.pocket/run"
mkdir -p "$HOME/.pocket"
```

Keep these paths **short**. They become AF_UNIX socket paths inside UML, so a
managed path over 192 bytes is refused:

```
pocket: [E_PATH_TOO_LONG] invalid run path: managed UML path is 221 bytes; maximum is 192
```

## First run

Pull an ordinary image from a registry and run it. No special image
preparation: this is `docker.io/library/alpine:3.22` exactly as published.

```sh
# The CLI is built at target/release/pocket. Capture it once so the rest of
# this works from any directory.
export POCKET=$PWD/target/release/pocket

"$POCKET" image pull \
  --profile-bundle "$POCKET_PROFILE_BUNDLE" \
  --store "$POCKET_STORE" \
  --runtime-root "$POCKET_RT" \
  --reference alpine:3.22 --platform linux/amd64 \
  docker://docker.io/library/alpine:3.22
```

`pull` fetches the image, authenticates every blob digest, converts it to an
immutable ext4 filesystem inside a builder UML, re-validates that filesystem
in a *separate* read-only UML, and publishes it. It prints a
`generation_id=pkvm-gen-v1-...` and an alias — here, `alpine:3.22`.

Now run it, by that alias:

```sh
"$POCKET" run \
  --profile-bundle "$POCKET_PROFILE_BUNDLE" \
  --store "$POCKET_STORE" \
  --runtime-root "$POCKET_RT" \
  alpine:3.22 -- /bin/sh -c 'cat /etc/alpine-release'
```

```
3.22.5
```

That is a real Linux kernel booting, mounting the converted image, and running
your command — with no root, no KVM, no user namespaces, and no host mounts.

Ask for more vCPUs:

```sh
"$POCKET" run --profile-bundle "$POCKET_PROFILE_BUNDLE" --store "$POCKET_STORE" \
  --runtime-root "$POCKET_RT" --cpus 4 alpine:3.22 -- /usr/bin/nproc
```

```
4
```

`run` uses the image's own `Entrypoint`, `Cmd`, `Env`, `User`,
`WorkingDir` and `StopSignal` when you give no command, and accepts
Docker-compatible overrides (`--entrypoint`, `--user`, `--workdir`, `-e`,
`--umask`, `--stop-signal`). It exits with the workload's exit status, and
reports `128+n` when the workload dies of a signal.

## Using a local image instead of a registry

```sh
# an already-normalized OCI layout directory
"$POCKET" image import ... --oci /abs/path/to/layout

# a single-image OCI or Docker archive
"$POCKET" image import ... --oci-archive /abs/path/to/image.tar
"$POCKET" image import ... --docker-archive /abs/path/to/saved.tar
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
"$POCKET" run ... alpine:3.22 -- /bin/sh -c 'echo hi > /marker; cat /marker'   # hi
"$POCKET" run ... alpine:3.22 -- /bin/sh -c 'test -e /marker || echo gone'     # gone
```

This is deliberate — it is what lets many runs share one verified base — but
it means **there is no way to persist changes today**. To keep a change, put it
in an image and import that image. Persistent volumes (`--volume`) are
explicitly rejected as unimplemented, and retained overlays exist in the store
layer but are not exposed by any command.

If you want the root read-only inside the guest as well, pass
`--root-readonly`.

## Managing the store

```sh
"$POCKET" image inspect --profile-bundle "$POCKET_PROFILE_BUNDLE" \
  --store "$POCKET_STORE" alpine:3.22 --json

"$POCKET" cache roots  --store "$POCKET_STORE"            # what is keeping generations alive
"$POCKET" cache forget --store "$POCKET_STORE" --alias <ALIAS_ID>
"$POCKET" cache gc     --store "$POCKET_STORE" --apply
```

A generation stays on disk while any alias points at it. `cache gc` only
reclaims what nothing references, so drop the alias first with `cache forget`
if you want the space back.

To delete a whole store, note that `rm -rf` alone will not do it. Published
generations are mode `0400` files inside `0500` directories — that is what
"immutable" means here — and you need write permission on a directory to
remove what is in it:

```sh
chmod -R u+rwX "$POCKET_STORE" && rm -rf "$POCKET_STORE"
```

## When something goes wrong

Keep the guest kernel console — it holds kernel and guest-init diagnostics
(never your workload's output):

```sh
"$POCKET" run ... --console-log /tmp/guest.log alpine:3.22 -- /bin/true
```

It is written on success and on failure alike, which is the case it exists
for. Errors are machine-readable: `E_CLI_INVALID_INPUT` means your command
line, `E_STORE` the store, `E_IMAGE_BUILD` the conversion, `E_GUEST` the
workload itself.

## What is not supported

Stated plainly, so you do not go looking:

- **Networking.** `--network none` only; there is no port forwarding.
- **Persistence.** No volumes, no retained overlays (see above).
- **arm64.** `linux/amd64` on an x86_64 host only.
- **Private registries.** Pulls are anonymous by design; credential flags are
  rejected.
- **A TTY.** `--tty` is refused; streams are buffered and non-interactive.

The full gate list, including what is and is not yet verified, is in
[the release support matrix](release-support-matrix.md). The CLI's complete
surface and its exact semantics are in
[the CLI reference](../crates/pocket/README.md).
