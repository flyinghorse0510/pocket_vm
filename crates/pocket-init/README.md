# pocket-init

`pocket-init` is Pocket's static guest PID 1. It is installed as `/init` in
the trusted initramfs and executes a workload from the verified root volume.

## Pinned x86_64 release build

The repository lockfile, Rust version, GNU target standard library, and GCC
major are build inputs. The canonical workspace recipe is:

```sh
make release-rust-artifacts
file build/release/x86_64-smp-p4k/guest/pocket-init
readelf -l build/release/x86_64-smp-p4k/guest/pocket-init
```

The script invokes Cargo with explicit target `x86_64-unknown-linux-gnu` and
target-specific `-Ctarget-feature=+crt-static`. The result must be an x86-64
static PIE with no `PT_INTERP` or `DT_NEEDED`. Build the complete normalized
archive with:

```sh
make release-initramfs
```

The release initramfs builder installs that binary as `/init`, supplies only
the required early-boot mount points and `/dev/console`, fixes all archive
ownership and timestamps, and writes an atomic SHA-256 sidecar. The runtime
still passes immutable contract/build IDs in the UML kernel command line.

The workload image-root bind is always verified `nodev`, so an OCI layer's
preexisting device node cannot reopen a UBD. Read-only mode additionally
verifies `readonly,nosuid`, enables `no_new_privs`, uses a private curated
`/dev`, closes outside-root directory descriptors, and applies the fixed
capability policy. These are guest-kernel controls; their UML boot acceptance
tests remain part of release qualification rather than this host build recipe.

Early boot recreates `/dev/pts` after mounting devtmpfs because that mount hides
the initramfs copy of the directory. The workload mount namespace also creates
a private `/run`, materializes deterministic network-none `hostname`, `hosts`,
and empty `resolv.conf` files there, and follows image-controlled target
symlinks with in-chroot/beneath-root semantics. Resolution and target creation
use the effective post-overlay root, so an `/etc` symlink into `/run` is created
on the visible tmpfs rather than invisibly in the underlying image. Each file
is bind-mounted `readonly,nodev,nosuid,noexec`. The workload child rereads their
exact contents after chroot and reconciles `/etc/hostname` with the already
verified UTS hostname. Persistent volumes and a slirp resolver are still
rejected by this profile revision.

After READY, the versioned control loop accepts SHUTDOWN exactly once. It
SIGKILLs nested PID-namespace init, waits within the message's bounded grace
for the namespace to drain, retains the kernel's raw wait status—including all
terminating signals 1 through 64—drains output, syncs and unmounts the root
volume, and reports EXIT before poweroff. Before exec, the namespace supervisor
publishes the exact outer workload PID and only then releases the child through
a one-byte gate. PID 1 therefore has an explicit teardown path even when a
set-ID or file-capability exec clears `PDEATHSIG`. Protocol and internal-event
tests cover ordering, malformed bounds, the complete terminating-signal range,
and the forced-signal outcome; a real UML shutdown boot remains a
release-profile integration gate rather than a simulated test claim.
