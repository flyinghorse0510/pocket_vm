# Linux source and rebuild contract

Pocket's x86_64 UML profile uses the exact Linux 7.2 release archive. A source
directory is generated output, never a cache trust root. Every invocation of
`scripts/build-linux.sh` performs this sequence while holding one exclusive
pipeline lock:

1. `fetch-linux.sh` verifies the compressed archive SHA-256, detached-signature
   SHA-256, uncompressed signed-tar SHA-256, and the kernel.org signature's
   exact `VALIDSIG` fingerprint from `config/sources.lock.toml`.
2. `apply-linux-patches.sh` extracts into a new managed staging directory. It
   rejects archive traversal, Git metadata, `.orig`, and `.rej` entries, then
   reproduces the upstream commit's exact Git tree and the locked canonical
   filesystem manifest.
3. An isolated temporary Git repository with a real deterministic HEAD applies
   only the ordered patches in `patches/7.2/series.lock`. Each patch's SHA-256,
   sole changed path, mode, full preimage blob, and full postimage blob must
   match. Git applies with `--index --whitespace=error-all`, creates no backup
   or reject files, and must accept an immediate reverse check.
4. The final Git tree and full filesystem manifest must match their locks. Only
   then is the staged directory renamed onto the fixed
   `build/src/linux-7.2` path.
5. The kernel is built out of tree at a fixed staging path with a cleared,
   enumerated environment. Source identity is audited again after compilation,
   and the kernel/config SHA-256 values must equal their artifact locks before
   the output is atomically published at `build/kernel/x86_64-smp-p4k`.

`scripts/hash-source-tree.py` is an explicit Python 3 build dependency. Every
entry point checks for `python3`, and kernel builds record its observed version
in `BUILD-METADATA`. Its canonical digest includes every regular file,
directory and symlink, full permission mode, path bytes, file size/content,
and symlink target. Git tree identity independently binds Git modes, paths,
symlinks, and blob contents. Together they also detect contamination which a
Makefile version check, Git index alone, or a content-only checksum would miss.

Run the non-mutating reverse/forward proof at any time:

```sh
make audit-linux-source
```

The audit starts from the published patched tree, reverses the locked series in
an index-only temporary repository until it reproduces the upstream tree, then
reapplies it until it reproduces the patched tree. It also rejects all Git,
patch-backup/reject, special-file, untracked-content, mode, and empty-directory
contamination.

Replacement is recoverable. Previous source trees, interrupted build trees,
and published kernel output trees are renamed rather than deleted and retained
under `build/src/replaced/` and `build/kernel/replaced/`. They are evidence and
must be removed only through an explicit operator retention decision.

## Reproducibility boundary

The source, patch series, build timestamp, config, fixed source/build paths, and
final kernel/config bytes are locked. The build uses the host programs resolved
from `PATH` (including GCC, binutils, make, flex, bison, Python, Perl, and host
libraries); their versions are not yet supplied by a hermetic toolchain image.
`BUILD-METADATA` records the primary observed tool versions, and the locked
artifact digests make an ambient-toolchain difference fail closed, but this is
verification of an expected output rather than a fully bootstrappable toolchain
supply chain. A release claiming independently reproducible toolchain inputs
must additionally pin and rebuild that complete compiler/linker/host-tool
closure.
