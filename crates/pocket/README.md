# `pocket` CLI

`pocket` is the strict command-line frontend for the Pocket libraries that are
implemented in this workspace today. It runs only trusted images and workloads;
the current UML runtime is not a security boundary for hostile code.

The CLI never invokes a shell. It constructs an argument vector from the
authenticated image configuration and explicit run overrides, and all profile,
store, and runtime roots must be absolute, normalized, narrowly scoped managed
paths of at most 3840 bytes. The runtime root is capped at 66 instead, because
a run's sockets live inside it and the kernel's `sockaddr_un` is 108 bytes.

## Implemented commands

```text
pocket profile verify BUNDLE [--json]
pocket profile list BUNDLE... [--json]

pocket image inspect \
  --profile-bundle BUNDLE --store STORE [--platform OS/ARCH[/VARIANT]] \
  IMAGE_OR_GENERATION [--json]

pocket image adjust \
  [--profile-bundle BUNDLE] [--store STORE] [--runtime-root RUNTIME_ROOT] \
  [--reference REFERENCE] [--platform OS/ARCH[/VARIANT]] --size SIZE \
  [--json] IMAGE

pocket image import \
  [--profile-bundle BUNDLE] [--store STORE] [--runtime-root RUNTIME_ROOT] \
  --reference REFERENCE [--platform OS/ARCH[/VARIANT]] \
  (--oci ABSOLUTE_CANONICAL_OCI_LAYOUT | \
   --oci-archive ABSOLUTE_SINGLE_IMAGE_TAR | \
   --docker-archive ABSOLUTE_SINGLE_IMAGE_TAR) \
  [--evidence-out ABSENT_PATH] [--json]

pocket image pull \
  [--profile-bundle BUNDLE] [--store STORE] [--runtime-root RUNTIME_ROOT] \
  [--reference REFERENCE] [--platform OS/ARCH[/VARIANT]] \
  [--acquisition-timeout DURATION] [--evidence-out ABSENT_PATH] [--json] \
  IMAGE | docker://REGISTRY/REPOSITORY[:TAG|@DIGEST]

pocket generation inspect --store STORE GENERATION_ID [--json]
pocket generation list --store STORE --derivation DERIVATION_KEY [--json]

pocket ps [--runtime-root RUNTIME_ROOT] [--store STORE] [-a] [--json]

pocket rm [--store STORE] NAME...

pocket commit [--store STORE] [--profile-bundle BUNDLE] \
  [--runtime-root RUNTIME_ROOT] NAME REFERENCE [--json]

pocket cache gc --store STORE --apply [--json]
pocket cache roots --store STORE [--json]
pocket cache forget --store STORE --alias ALIAS_ID

pocket run \
  --profile-bundle BUNDLE \
  --store STORE \
  --runtime-root RUNTIME_ROOT \
  [--platform OS/ARCH[/VARIANT]] \
  [--cpus N] [--memory SIZE] [--timeout DURATION] \
  [--entrypoint EXECUTABLE | --entrypoint=] [--exact-argv] \
  [--user USER[:GROUP]] [--workdir ABSOLUTE_PATH] [-e KEY=VALUE] \
  [--hostname NAME] [--umask OCTAL] [--stop-signal SIGNAL] \
  [--volume HOST_DIR:GUEST_DIR[:ro]]... [--network slirp|none] [--privileged] \
  [--root-readonly] [-i] [-t] [--name NAME | --rm] \
  [--boot-log] [--consoles N] [--console-log ABSENT_PATH] \
  IMAGE_OR_GENERATION [-- ARG...]
```

`--profile-bundle`, `--store` and `--runtime-root` may also come from a config
file, so the common case needs no path flags at all. See **Configuration file**
below.

`profile list` deliberately verifies only the bundle paths supplied by the
caller; there is no installed-profile index yet. `generation list` is scoped to
one full derivation key and returns the canonical winner first, followed by
deterministically ordered alternative immutable outputs.

`--store` may sit behind a symlinked ancestor: the ancestor chain is resolved
once, and the final component is left exactly as written, so a store root that
is itself a symlink is still refused. A root left incomplete by an interrupted
or failed initialization is completed in place, but only when every entry in it
is one a store put there -- an unrelated directory is refused and untouched.

A store on NFS, 9p, or a FUSE filesystem works: those reject
`RENAME_NOREPLACE`, so publication falls back to a checked rename. On such a
filesystem the store's own locks, rather than the kernel, are what make a
publication non-replacing.

`cache roots` lists the aliases that are currently keeping generations alive,
and `cache forget` drops one by its own ID. An alias outlives the profile that
created it and reconstructing its key needs that bundle, so without these two a
resealed profile's aliases root their generations permanently and `cache gc` can
never reclaim the space. Forgetting an alias removes only the alias record; the
generation it named is collected by the next `cache gc --apply` if nothing else
roots or leases it.

`image inspect` and `run` distinguish a full `pkvm-gen-v1-...` ID from an alias.
Malformed values beginning with that prefix are rejected and never reinterpreted
as aliases. Alias resolution and generation leasing are one atomic store
operation, so garbage collection cannot create a resolve/use gap. The alias key
is qualified by the verified profile ID and exact profile revision.

`image import --oci` accepts an already-normalized canonical OCI directory. It
authenticates the layout before construction, then the host builder repeats
verification before and after taking its derivation lock. `--oci-archive` and
`--docker-archive` accept exact non-symlink, uncompressed tar files containing
one top-level image. They are copied through one nonblocking, no-follow file
descriptor into a private operation under fixed transport-safe basenames,
preflighted for duplicate or ambiguous root indexes, and normalized by the
profile's sealed Skopeo. Archive selectors and multi-image archives are rejected
instead of choosing an implicit tag or ordering. Relative paths and daemon
imports remain unsupported.

`image pull` accepts a registry name or an explicit `docker://` source; other
transports are refused. It runs the verified profile's exact static Skopeo artifact beneath
`pocket-guard`; neither executable is resolved through `PATH`. HOME, XDG,
temporary, registry-policy, registry-configuration, and authentication state
are private per operation. TLS verification uses the CA bundle sealed into the
same profile revision. Pulls are deliberately anonymous: credential flags are
not accepted and an empty private auth file plus `--src-no-creds` prevent host
credential discovery. The profile's documented trust model accepts image
content without a signature policy (`--insecure-policy`); authenticated OCI
blob digests and TLS are still enforced. Failed, timed-out, and partial copies
are removed with the identity-checked operation directory. Each registry pull
snapshots `/etc/resolv.conf`, `/etc/hosts`, and `/etc/nsswitch.conf` before and
after Skopeo, including content hashes and file/link identity; any drift fails
the acquisition. Local archives do not consult or claim resolver evidence.

`image pull` accepts a registry-client shorthand: `alpine:3.22` expands to
`docker://docker.io/library/alpine:3.22`, a single-segment name takes Docker
Hub's `library` namespace, and a bare name takes `:latest`. A name whose first
segment looks like a host (`ghcr.io/o/i`, `localhost:5000/i`) keeps its
registry. An explicit `docker://` source is used verbatim. Any *other*
transport -- `oci:`, `dir:`, `containers-storage:` and the rest of skopeo's set
-- is still refused by name rather than reinterpreted as a repository, because
guessing there would acquire something other than what was asked for.

`--reference` defaults to the source exactly as the caller wrote it, so
`pocket image pull alpine:3.22` is run as `alpine:3.22` rather than as its
expanded form. `--platform` defaults to the verified profile's own
`oci_os`/`oci_architecture`: the assertion still holds, since that is the only
platform the profile can run, it simply no longer has to be typed. `import`
still requires `--reference`, because a tarball has no name to borrow.

Both build commands report the reference and platform they actually used.
They emit generation, derivation, alias, and cache-hit identities in stable text
or JSON together with the exact source kind and selected manifest/config
digests. JSON retains the complete bounded Skopeo stdout/stderr as hex plus
lengths and hashes, and the resolver provenance. `--evidence-out` atomically
creates the same complete JSON receipt at an absent path with mode 0600; it does
not add foreign files to the immutable generation store. A missing store root is initialized privately and atomically; an
existing invalid directory is never repaired or replaced.

`--console-log` writes the guest kernel console to a new owner-only file, on
success and on failure alike, and asks the guest kernel for its full console
rather than the `quiet` subset. It carries kernel and guest-init diagnostics,
never workload output. A path that already exists is never overwritten: the run
still delivers its result and the refusal is reported on standard error, because
losing a workload's exit status over a side file would be the worse outcome.

`run` reports on standard error when the host's CPU affinity or cgroup-v2
`cpu.max` cannot actually deliver the requested vCPUs in parallel. A request
within the profile's maximum is never rejected over the host's current limits,
so the note is the only way the caller learns the guest will be oversubscribed.

`run` defaults to one CPU. If `--memory` is omitted, it uses the verified
profile's revision-bound default. Generation selection, profile/platform
validation, image-process resolution, and launch use one continuous lease. The
mandatory `image-config.json` and `accounts.cbor` sidecars are opened relative
to the verified generation directory, bounded, and rehashed before their exact
bytes are parsed. A missing, empty, malformed, noncanonical, or digest-mismatched
sidecar fails before a COW or UML process is created.

The default command behavior is Docker-compatible and explicit:

- with no arguments after the image, final argv is image Entrypoint followed by
  image Cmd;
- arguments after `--` replace Cmd while retaining Entrypoint;
- `--entrypoint VALUE` replaces Entrypoint with that single executable and,
  like Docker, clears the image Cmd; `--entrypoint=` clears both defaults, so a
  positional command is then required for nonempty argv;
- `--exact-argv -- PROGRAM [ARG...]` preserves the former complete-argv escape
  hatch and bypasses both image Entrypoint and Cmd; combining it with
  `--entrypoint` or omitting its argv is an error;
- an empty final argv or empty argv[0] is an error, and no form inserts a shell
  or performs host-side word splitting.

On Linux the environment begins with Docker's default
`PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin` and
`HOSTNAME` equal to the selected `--hostname`. Image Env replaces those two
defaults by key and appends its other entries in image order. Each repeated
`-e KEY=VALUE` then replaces the last existing entry for `KEY` in place, or
appends a new key; later CLI overrides win. `TERM` is synthesized only under
`-t`, and only when neither the image nor `-e` already supplies one: it takes
the host's `TERM`, or `xterm` when that is unset or is not a plain terminal
name. Current Moby does not synthesize `HOME`; either variable is preserved
when supplied by the image or CLI. Host-value
lookup and the Docker API's key-only unset form are intentionally absent:
`-e` requires an exact `KEY=VALUE`.

`--workdir`, `--user`, and `--stop-signal` override their image values,
otherwise the image values apply. User accepts `user`, `uid`,
`user:group`, `uid:gid`, `uid:group`, and `user:gid`; names resolve only against
the sealed account database. With no group suffix, passwd primary GID and
deduplicated group memberships apply. An unknown numeric UID uses GID 0 and no
supplementary groups. An explicit group suppresses image supplementary groups.
StopSignal accepts decimal 1 through 64, conventional Linux names such as
`SIGTERM`, and bounded `RTMIN+N`/`RTMAX-N` spellings; absent image and CLI values
default to SIGTERM.

A valid OCI image document may omit its optional `config` object. That means
zero image process defaults (`User=0`, `WorkingDir=/`, no environment,
Entrypoint, Cmd, or StopSignal); it remains runnable when a command/entrypoint or
`--exact-argv` supplies a nonempty argv. `-i` buffers at most 16 MiB of stdin.
Standard output and standard error remain separate, but are emitted after the
synchronous run completes. Runtime capture truncation is reported as an error
rather than silently returning partial success.

Garbage collection is intentionally asymmetric. `--apply` invokes the store's
real lock-aware collection operation. Omitting `--apply` returns
`E_FEATURE_UNSUPPORTED` because the store has no classify-only preview API; it
does not approximate a dry run or delete anything.

## Listing running operations

`pocket ps` lists the runs in a runtime root whose owner is still alive, one
`id= generation= pid= started= cpus= memory_bytes=` line each, or `--json`.

There is no daemon to ask. A run holds an exclusive lock on its own directory
for its whole life, and the kernel releases it when the owner dies however it
dies, so a directory whose lock cannot be taken has a living owner. The listing
reads that state rather than recording its own, which is why a SIGKILLed run
leaves it immediately.

## Capabilities

A workload runs as uid 0 with a fixed 12-capability allowlist
(`fixed-capabilities-v1`): the conventional Docker default set less
`CAP_MKNOD` and `CAP_SYS_CHROOT`. The bounding set is reduced to match, so a
workload cannot regain what it was not given.

`--privileged` replaces that with every capability the guest kernel
implements, and leaves the bounding set intact so the workload can grant
capabilities to processes it starts. This is what a container engine inside
the guest requires, and it is carried per run in `START` rather than being a
property of the profile.

It grants nothing over the host. The guest kernel is the isolation, and the
host boundary is an unprivileged process that this flag does not affect --
unlike Docker's flag of the same name, which hands a container authority over
the host's own kernel.

## Mounts the runtime provides

A workload's namespace receives the image root, `sysfs` (read-only), a `tmpfs`
`/dev` with a curated device set, `devpts`, `mqueue`, `/dev/shm` (64 MiB), a
writable `cgroup2` at `/sys/fs/cgroup`, a `tmpfs` `/run` (16 MiB), and
`procfs` -- which is mounted last, by the child created after
`CLONE_NEWPID`, so it shows that child's PID namespace rather than its
parent's. The cgroup hierarchy is the guest kernel's own; a container
engine will not start without one it can write.

Anything the workload mounts for itself is unmounted at teardown, deepest
first, before the runtime unmounts what it provided -- otherwise the image
root stays busy and the run is reported as an unclean filesystem.

## Networking

`--network` selects `slirp` (the default) or `none`. Under `slirp` the guest
gets `10.0.2.100/24` on `vec0`, a default route via `10.0.2.2`, and
`nameserver 10.0.2.3` in a generated `/etc/resolv.conf`; under `none` it has
loopback only and that file is empty rather than absent.

The addressing is the profile's sealed `slirp-bess-v1` contract, not a per-run
choice, so it is not carried in `START`: the host configures the helper and the
guest configures its interface from the same constants, and a profile that
changes them changes its revision.

The transport is UML's `vector` driver over `bess`, which is an `AF_UNIX`
socket -- no TUN device, no `CAP_NET_ADMIN`, no host configuration. The
profile's `slirp4netns` artifact serves that socket. The guard starts it and
stops it with the run, so a SIGKILLed caller cannot orphan it.

`-p/--publish` remains refused: the helper accepts forwards over an API socket
that is not wired up.

## Extra serial lines

`--consoles N` gives the guest N serial lines beyond the four the runtime uses
itself, each published as a pseudo-terminal an operator can attach to. This is
what `-serial pty` is on qemu: the runtime provides the line, and what runs on
it is the guest's business.

```sh
pocket run --consoles 2 alpine:3.22 -- /bin/sh -c '...'
```

```
pocket: guest /dev/ttyS4 is attachable at /dev/pts/10
pocket: guest /dev/ttyS5 is attachable at /dev/pts/11
```

The paths are printed as soon as the run starts, because that is when they are
useful, and stay valid for as long as it runs. Attach with any terminal
program:

```sh
screen /dev/pts/10          # or minicom -D, picocom, socat, tio
```

`pocket ps` reports them too, which is how a backgrounded run's lines are found
without going back through its output:

```
id=run-af990f6c... generation=pkvm-gen-v1-... pid=3538462 ... consoles=/dev/pts/10,/dev/pts/11
```

Inside the guest the lines are `/dev/ttyS4` upwards, `0600` and owned by root.
Nothing runs on one unless the workload puts something there -- a run executes
one process, and there is no init spawning gettys. A workload that wants a
second session on a line starts one:

```sh
setsid sh -c 'exec /bin/sh -i </dev/ttyS4 >/dev/ttyS4 2>&1' &
```

That gives a full independent session -- its own prompt, its own commands --
running concurrently with the workload, which is the usual reason for wanting
the line at all.

At most 8 lines, refused before anything is opened if more are asked for. UML
compiles in 64 and four are reserved, so the limit is policy rather than the
kernel's: each line costs a host pseudo-terminal and an inherited descriptor
for the life of the run.

Allocating a line needs no privilege: the host end is `open("/dev/ptmx")`, the
same call every terminal program makes, and the kernel names the device and
gives it to the caller. If it fails -- no `/dev/pts`, no descriptors left --
the run is refused rather than started without the lines it was asked for.
Omitting `--consoles` allocates nothing and produces the same launch as before
it existed.

## Seeing the guest boot

Neither the kernel console nor guest-init diagnostics reach your terminal by
default: a run prints what the workload printed and nothing else. The console
is a separate UML channel from the workload's streams, so the two never mix in
either direction.

Two ways to see it:

```sh
pocket run --boot-log alpine:3.22 -- /bin/true            # live, on stderr
pocket run --console-log /tmp/boot.log alpine:3.22 -- /bin/true   # to a file
```

`--console-log` writes the transcript on success and on failure alike, but only
once the run is over, which is no help when the question is why a guest never
reached a prompt. `--boot-log` mirrors the console as it is produced, and
composes with `-t`: the session rides its own channel, so a boot log cannot
scribble over a full-screen program.

Both ask the kernel for its full log rather than the `quiet` subset a run
otherwise boots with, because a transcript filtered to errors hides the lockdep
and RCU reports someone keeping one is looking for. `--boot-log` mirrors rather
than redirects, so asking for it never truncates the captured transcript.

A failed run already reports a bounded console excerpt in its error without
either flag.

## Kept runs

A run is kept when it exits, so what it produced can be looked at afterwards.
It is recorded under a name -- `--name`, or a generated one like
`nimble-delta-1d4d` -- and its copy-on-write overlay is retained:

```sh
pocket run --name build-one alpine:3.22 -- /bin/sh -c 'make'
pocket run --rm alpine:3.22 -- /bin/true      # discarded instead
pocket ps -a                                  # running, plus what was kept
pocket rm build-one                           # the record and its overlay
```

`--rm` and `--name` cannot be combined: a discarded run leaves nothing to
name. A name already in use is refused before the guest starts, not after the
run has been paid for.

A kept run's overlay is written inside the store from the start rather than
moved there at teardown, because moving a multi-gigabyte sparse file would cost
every run for the benefit of the kept ones. It is sparse, so it occupies what
the workload wrote -- typically a few hundred kilobytes -- against a logical
size that matches the image's filesystem.

Keeping a run roots its image: `cache gc` reports the generation as `rooted`
and will not collect it while any instance needs it. That root and the name are
separate records, so removing an instance releases both, and a crash between
them leaves reclaimable space rather than an instance whose image has been
collected.

`commit` publishes what a kept run produced as a new image:

```sh
pocket run --name build alpine:3.22 -- /bin/sh -c 'apk add --no-cache jq'
pocket commit build alpine:with-jq
```

It merges the run's overlay onto a copy of the base -- a UML COW is a v3
header, a sector bitmap and the sectors that changed -- rewrites the generation
marker, and publishes the result. The source is untouched, and committing the
same overlay onto the same base twice converges on one generation rather than
producing a new one each time.

A committed image carries only evidence that is true of it.
`image-config.json` describes how the image is started, which a commit does not
change, so it carries over. `accounts.cbor` is **derived from the committed
filesystem**, not inherited: it is the host-readable index of the guest's
`/etc/passwd` and `/etc/group` that `--user NAME` is resolved against, and a
run is free to have added or renamed an account, so it is read back out of the
merged image. An account the run created is therefore selectable by name:

```sh
pocket run --name setup alpine:3.22 -- /bin/sh -c 'adduser -D -u 1000 alice'
pocket commit setup alpine:alice
pocket run --user alice alpine:alice -- id      # uid=1000(alice)
```

The build evidence -- the filesystem manifest, the validation evidence, the
build record -- describes a conversion that did not produce this filesystem, so
it is replaced by a `commit-record.json` naming the source generation, the
instance and the overlay digest. Carrying the old manifest instead would
publish an image whose recorded inventory lists a filesystem that no longer
exists.

Regenerating the account database also moves the marker: a generation marker
binds its account digest, so both it and the derivation key are rewritten.

A run that changed nothing is refused rather than republished unchanged.

## Filesystem size

A converted image's filesystem is sized from its contents, with a floor of
**8 GiB**. The floor exists because the filesystem is also the workload's
writable space: everything outside a `--volume` lands in the copy-on-write
overlay above it, `/tmp` included, and that space is fixed when the image is
converted rather than when it runs.

It is cheap to store and not free to publish. The file is sparse -- an 8 GiB
base holding Alpine occupies about 14 MiB -- but publication hashes the
complete logical file, so the cost of a larger floor is time rather than disk:
roughly 20 seconds at 8 GiB, scaling linearly.

`image adjust` republishes an image's filesystem at another size, in either
direction:

```sh
pocket image adjust --size 32G alpine:3.22
pocket image adjust --size 2G --reference alpine:small alpine:3.22
```

The size must be a multiple of the 4096-byte block. Shrinking below what the
contents occupy is refused by `resize2fs` rather than truncated.

The source is never modified. A generation is immutable, so `adjust` copies the
base -- preserving its holes, so the copy costs what is allocated rather than
what is addressable -- resizes the copy, checks it with `e2fsck` before and
after, and publishes the result as its own generation. Size is part of a
generation's identity, because the build contract binds it, so the adjusted
image has a different derivation key and sits beside the original rather than
replacing it. Only the alias moves, and `--reference` keeps even that.

The contents are untouched by a resize, so every sidecar the source carries
still describes the result exactly and is copied across unchanged.

## Terminal sessions

`-t` runs the workload on a terminal. The guest allocates a PTY, makes it the
workload's controlling terminal, and gives it stdin, stdout and stderr; the
host puts its own terminal into raw mode and streams both directions until the
workload exits. That is what makes an interactive shell, `login`, `su`, and
full-screen programs work.

```sh
pocket run -t alpine:3.22 -- /bin/sh
pocket run -t --user builder alpine:3.22 -- /bin/sh   # as a pre-configured account
```

Because the host terminal is raw, keys are not interpreted by the host: `^C`,
`^Z`, `^D` and the rest travel to the guest, and the guest's line discipline
decides what they mean -- so `^C` interrupts the workload, not `pocket`. The
terminal is restored on every exit path, including failures.

`-t` requires that both stdin and stdout are terminals, and says so rather than
silently falling back to buffered streams. It implies `-i`: input is streamed
for as long as the session lasts instead of being read up front, so there is no
16 MiB input cap and no need to close stdin before the run starts. End of file
still reaches the workload, because the PTY turns the operator's `^D` into one.

Window size is sent at startup and again on every `SIGWINCH`, so resizing the
terminal resizes the guest's; the guest also receives `SIGWINCH` itself.

Output in this mode goes straight to the terminal as it is produced rather than
being captured, so a long session is never truncated by the capture cap. It is
therefore not retained: `--console-log` still captures the guest *kernel*
console, which is a different stream.

The PTY is allocated before the workload's mount namespace exists. Every
`devpts` mount is an independent instance in current kernels -- `newinstance`
has been a no-op since mounts became independent -- so the namespace's own
instance would renumber the terminal and break `ttyname`, and with it `tty`,
`script` and `who`. A terminal session therefore binds the instance the PTY
came from over the namespace's, which holds exactly this workload's own
terminal. A run without `-t` keeps the private instance.

## Configuration file

Every command that takes `--profile-bundle`, `--store` or `--runtime-root`
reads them from a config file when the flag is absent. An explicit flag always
wins, so the file only ever supplies a default:

```
$XDG_CONFIG_HOME/pocket/config.toml     # or ~/.config/pocket/config.toml
```

`POCKET_CONFIG` overrides the location. `scripts/install-release.py` writes one
at install time, pointing at the profile it installed, and never overwrites a
file that already exists.

The grammar is a deliberately small subset: `key = "value"`, `#` comments, and
blank lines. The three keys above are the only ones accepted. An unknown key, a
repeated key, an unquoted value or a backslash escape is an error naming the
file and line rather than a silently ignored setting.

## Sharing host directories

`--volume HOST_DIR:GUEST_DIR[:ro|:rw]` mounts a host directory into the guest
over `hostfs`. `:rw` is the default, written out. The host directory must already exist; the guest mount point is
created if it does not. Writes land in the host's own directory, so unlike the
copy-on-write root they survive the run. `:ro` mounts it read-only.

The guest destination may not collide with a path the runtime mounts or
generates -- `/proc`, `/sys`, `/dev`, `/run`, `/etc/hostname`, `/etc/hosts`,
`/etc/resolv.conf` -- in either direction. Under one it would be silently
shadowed; over one, the runtime's own mounts and generated files would be
created inside the caller's directory and left there. A sibling such as
`/etc/myconfig` is unaffected. The refusal happens in the CLI and again in the
guest's `START` contract.

One host directory is used by one run at a time. A second run naming the same
directory is refused with `E_CLI_INVALID_INPUT` rather than serialized or
silently allowed: `hostfs` does not track host-side changes, so two guests
writing through their own caches would corrupt each other's view.

The claim is an advisory lock on the directory itself, released when the run's
process exits. Not a marker file inside the share: a workload can see and
delete that, and one that tidies its own output directory did. Locking the
directory writes nothing into the caller's folder and needs no write
permission, which is what makes a read-only share work. On a network
filesystem the lock may be local to one machine.

At most 32 volumes per run. A host path may not contain a colon, because the
first colon separates it from the guest path. Two volumes may not name the same
host path or the same guest path.

A file altered on the host while a run holds the directory may still be served
from the guest's cache.

A shared directory is host state with host permissions. It is outside
everything the immutable store guarantees, and a workload can write anything
the invoking user can write. That is the point of the feature, and it is the
caller's judgement to make.

## Explicitly unavailable surface

This build does not implement:

- authenticated registry pulls, credential-helper/Docker-config discovery,
  Docker daemon imports, archive selectors or multi-image archives, or image
  removal. `cache roots` lists the aliases a store holds; `image list` does not
  exist;
- installed-profile discovery, implicit profile selection, or `probe`;
- inbound port forwards or host CPU affinity;
- `attach`, `exec`, and `run --detach`. Each is a named command or flag that
  refuses with `E_FEATURE_UNSUPPORTED` and the reason, rather than reading as
  a typo: a run is a foreground process with no daemon behind it, and it
  executes exactly one process, decided before the guest starts;
- `pocket run` pull policies other than `never`, retained root COWs, or dynamic UML
  profile bundles.

Unsupported run features are rejected before profile or store access. Unknown
options and malformed command syntax are never ignored.

## Exit contract

| Status | Meaning |
| ---: | --- |
| `0` | command success, help/version success, or guest exit 0 |
| `0..=255` | a guest's explicit exit code is propagated exactly |
| `128 + N` (capped at 255) | guest termination by signal `N` |
| `2` | CLI syntax/usage error |
| `125` | Pocket operational, validation, unsupported-feature, or output error when no guest status exists |

Operational diagnostics use `pocket: [STABLE_CODE] message` on standard error.
Machine-readable build/inspect/list/GC output is available with `--json`; workload
stdout remains raw workload bytes.

As with common container CLIs, an explicit guest exit `125` is necessarily
indistinguishable by status alone from a pre-guest Pocket operational failure;
the latter always has a coded `pocket:` diagnostic on standard error.
