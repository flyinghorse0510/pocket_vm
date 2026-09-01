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

pocket ps [--runtime-root RUNTIME_ROOT] [--json]

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
  [--root-readonly] [-i] [--console-log ABSENT_PATH] \
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
appends a new key; later CLI overrides win. Pocket does not synthesize `TERM`
because TTY mode is unsupported, and current Moby does not synthesize `HOME`;
either variable is preserved when supplied by the image or CLI. Host-value
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
- PTYs, inbound port forwards, or host CPU affinity;
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
