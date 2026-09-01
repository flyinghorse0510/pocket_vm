# Experimental release packaging

This repository contains a source-only packaging foundation. It can turn one
already sealed x86_64-smp-p4k profile revision and one x86_64 pocket CLI into
a deterministic archive, then install that archive below an unprivileged
user's home directory. This does **not** make the project release-ready; the
qualification gates in
[release-support-matrix.md](release-support-matrix.md) remain mandatory.

## Package contract

Most callers want the make targets, which pick the profile the last build
sealed and pass these paths for you:

    make package                       # writes build/package/<archive>.tar
    make install PREFIX=<dir>          # builds, packages and installs
    make install-archive ARCHIVE=<tar> PREFIX=<dir>

The script beneath them accepts explicit absolute paths only. It does not
select a "latest" profile:

    mkdir -p "$PWD/build/packages"
    ./scripts/package-release.py \
      --profile "$PWD/build/profiles/x86_64-smp-p4k/FULL_64_HEX_REVISION" \
      --pocket "$PWD/build/release/x86_64-smp-p4k/host/pocket" \
      --output-dir "$PWD/build/packages"

The packager verifies a closed profile inventory against profile.json,
including every artifact's size and SHA-256. The profile directory and files
must already have the sealed modes (0555 directories, 0444 data, and 0555
executables). Symbolic links, hard-linked input files, devices, FIFOs,
sockets, empty foreign directories, and unlisted files are rejected. The
host CLI must be an executable, little-endian x86_64 ELF file that is neither
group- nor other-writable. The package also includes both project license texts, Cargo.lock,
config/sources.lock.toml, this document, the support matrix, and a generated
SPDX file.

The installer travels inside the archive it installs, so a machine holding
only the tarball can still perform the digest-checked install rather than an
unpacking that skips every check. Its one import sits beside it in bin/,
because Python puts a script's own directory on the module path and nothing
else about an extracted tree is guaranteed to be there. Take the two out and
run the installer:

    tar -xf pocket-vm-....tar --strip-components=2 --wildcards \
      '*/bin/pocket-vm-install' '*/bin/pocket_release.py'
    # The archive path must be absolute: the installer refuses one it cannot
    # resolve without depending on the working directory.
    ./pocket-vm-install install --archive "$PWD/pocket-vm-....tar" \
      --prefix "$HOME/.local"

Both files are part of the payload inventory, so editing either changes the
release revision and the archive name.

Unpacking the whole archive by hand is not a supported install path. Archive
directories are 0555, mirroring the read-only tree the installer publishes,
so a plain `tar -xf` fails part-way: it creates each directory read-only
before writing what belongs in it. `--delay-directory-restore` unpacks it,
but the result is unverified, has no launcher and no configuration.

The output is a single uncompressed USTAR file. Publication renames an adjacent
temporary with `renameat2(RENAME_NOREPLACE)`; an existing archive is never
replaced. Every tar member has UID/GID 0, empty owner names, a mode of
0444 or 0555, and the frozen linux.source_date_epoch timestamp from
config/sources.lock.toml. Member order and JSON serialization are canonical.
No host path is recorded.

Inside the archive:

    pocket-vm-<version>-<profile-id>-<full-release-revision>/
    |-- bin/pocket
    |-- bin/pocket-vm-install          (scripts/install-release.py)
    |-- bin/pocket_release.py          (its one import, beside it)
    |-- profiles/<profile-id>/<full-revision>/...
    +-- share/
        |-- licenses/pocket-vm/{LICENSE-APACHE,LICENSE-MIT}
        |-- doc/pocket-vm/...
        +-- pocket-vm/
            |-- Cargo.lock
            |-- config/sources.lock.toml
            |-- pocket-vm-source-inputs.spdx.json
            |-- release-manifest.json
            +-- SHA256SUMS

The full release revision is a SHA-256 over the canonical identity fields and
the complete pre-manifest payload inventory. It therefore changes when the
CLI, sealed profile, locks, licenses, documentation, or generated SBOM
changes. It is distinct from, and binds, the full profile revision.

release-manifest.json inventories every payload except itself and
SHA256SUMS, with exact relative path, mode, byte count, and SHA-256.
SHA256SUMS covers every payload plus the canonical manifest; it omits only
itself to avoid a recursive digest. The archive SHA-256 printed by the
packager is a transport digest and should be recorded by the publication
system. No signature is produced by this foundation.

## SPDX scope

The standalone generator is:

    ./scripts/generate-release-sbom.py \
      --cargo-lock "$PWD/Cargo.lock" \
      --source-lock "$PWD/config/sources.lock.toml" \
      --output "$PWD/build/packages/source-inputs.spdx.json"

It emits deterministic SPDX 2.3 JSON. It enumerates all Cargo lockfile
entries and the pinned Linux, e2fsprogs, Skopeo, Go-toolchain, and CA-bundle
source coordinates from sources.lock.toml. Cargo archive checksums and pinned
downloadable-source checksums are included when the locks contain them. Git
object IDs are described as source coordinates, not mislabeled as file
checksums. License fields remain NOASSERTION because neither lock is a
license-analysis database.

This is intentionally a **source-input lock inventory**, not a binary SBOM.
It does not scan ELF dependencies, infer license conclusions, determine which
target-specific or development Cargo entries were linked, enumerate
unrecorded host build inputs, perform vulnerability analysis, or attest
reproducibility. Those limitations are embedded in the SPDX document.

## User-prefix installation and rollback

The installer refuses effective UID 0 and accepts only an absolute prefix
strictly below the invoking account's passwd-database home directory. Every
existing prefix component below the home directory must be owned by that user
and must not be group- or other-writable. It performs ordinary file-system
operations only; it does not call sudo, a package manager, set-ID helpers, or
privilege APIs.

    ./scripts/install-release.py install \
      --archive "$PWD/build/packages/pocket-vm-...-linux-x86_64.tar" \
      --prefix "$HOME/.local"

    ./scripts/install-release.py verify \
      --archive "$PWD/build/packages/pocket-vm-...-linux-x86_64.tar" \
      --prefix "$HOME/.local"

The exact archive is revalidated before either operation. The validator
rejects compression, multiple roots, duplicate paths, non-canonical paths,
PAX metadata, links, special files, unexpected ownership/modes/timestamps,
inventory drift, and checksum drift. Extraction is member-by-member into a
private sibling staging directory; extractall is never used. The completed
tree is published with Linux renameat2(RENAME_NOREPLACE).

Installation deliberately separates each short immutable release tree from
the shared immutable profile tree. This avoids nesting two full SHA-256
identities, which lengthens every installed path. The
installer also checks the longest installed profile artifact path against
that limit before publishing anything.

Installed releases coexist at:

    <prefix>/lib/pocket-vm/r/<full-release-revision>/

Exact profiles coexist at:

    <prefix>/lib/pocket-vm/p/<profile-id>/<full-profile-revision>/

A revision-specific launcher is created at:

    <prefix>/bin/pocket-<version>-<profile-id>-<full-release-revision>

The launcher does not inject a profile silently. It passes no path of its
own; what makes the flags unnecessary is a separate config file, written once
at install time and readable in full:

    $XDG_CONFIG_HOME/pocket/config.toml      (default ~/.config/pocket/config.toml)

It names the installed profile, a store under $XDG_DATA_HOME and a runtime
root under $XDG_RUNTIME_DIR, whose parents the installer creates with mode
0700. An explicit flag always overrides it. An existing config is never
overwritten -- a reinstall reports config_written false and leaves the file
alone -- and --store, --runtime-root, --config or --no-config choose
otherwise. The installer creates no other host state.

An identical reinstall is an idempotent verification. An existing release
tree or launcher that differs in any byte, mode, timestamp, or inventory
entry is an error and is never overwritten.

Profile publication happens before release-tree publication, and the
versioned launcher is last. Each immutable tree is staged and published
atomically on its own, and each relevant directory is fsynced. A crash can
therefore leave an already valid profile or release tree without its later
consumer, but never a partially populated published tree. Re-running the
same install verifies and reuses each valid tree before completing the next
step.

<prefix>/bin/pocket is a symlink to that versioned launcher, and it is the
one deliberately replaceable thing the installer publishes: rollback is
repointing it at an earlier launcher, which is also what a reinstall of an
earlier archive does. --no-default-link skips it. Every immutable tree stays
exactly where it was, so an older revision remains runnable by its own
launcher path whatever the link says.

Removal is not implemented; retain an archive and successful verification
record before manually removing a versioned tree.

## Local packaging test

scripts/test-release-packaging.sh constructs a small synthetic sealed profile,
produces the package twice in separate directories, compares the archives
byte-for-byte, installs and verifies it, exercises idempotent installation,
and checks representative fail-closed corruption/link/foreign inventory
cases. It also takes the installer out of the archive and installs with it,
with no repository on the module path, which is the situation on a machine
that received only the tarball; and it checks that the install writes a
config file and a default link, that a second install rewrites neither, and
that --no-config and --no-default-link leave both alone. It does not replace
the real-UML or clean-host release qualification matrix.
