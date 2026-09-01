SHELL := /bin/bash

.PHONY: terminal-session container-engine static-slirp4netns package install install-archive test kernel audit-linux-source diagnostic-kernel diagnostic-lifecycle lifecycle-soak distro-matrix reproduce-release test-linux-source-pipeline host-tools static-e2fsprogs static-skopeo audit-arm64-seed release-rust-artifacts release-initramfs release-artifacts release-profile rust-release-e2e probe-initramfs probe-disk probe memory-matrix smp-probe-initramfs smp-scaling lifecycle-probe-initramfs lifecycle-probe builder-initramfs workload-probe-initramfs ubuntu-24.04 ubuntu-26.04 e2e-probe e2e-probe-26.04 verify

host-tools:
	cargo build --release -p pocket-guard

static-e2fsprogs:
	./scripts/build-static-e2fsprogs.sh

terminal-session:
	./scripts/run-terminal-session.sh

static-slirp4netns:
	./scripts/build-static-slirp4netns.sh

static-skopeo:
	./scripts/build-static-skopeo.sh

audit-arm64-seed:
	./scripts/audit-arm64-uml-seed.sh

release-rust-artifacts:
	./scripts/build-release-rust-artifacts.sh

release-initramfs: kernel release-rust-artifacts
	./scripts/build-release-initramfs.sh

release-artifacts: static-e2fsprogs static-skopeo static-slirp4netns release-initramfs

release-profile: release-artifacts
	./scripts/build-release-profile.sh

# Defaults to whatever the last `make release-profile` sealed. Set
# POCKET_PROFILE_BUNDLE to run against a different one.
rust-release-e2e:
	./scripts/run-rust-release-e2e.sh \
	    "$${POCKET_PROFILE_BUNDLE:-$$(cat "$(CURDIR)/build/profiles/latest")}"

kernel:
	./scripts/build-linux.sh

audit-linux-source:
	./scripts/audit-linux-source.sh

# Build the release source with the kernel's own lock/RCU/atomic-sleep
# validators enabled. Never publishable; used to qualify, not to ship.
diagnostic-kernel:
	./scripts/build-diagnostic-kernel.sh

# Run the real workload lifecycle under that validator kernel and fail on any
# guest-console report. This is the reproducible form of the SMP correctness
# evidence.
diagnostic-lifecycle:
	./scripts/run-diagnostic-lifecycle.sh

# Repeated fresh lifecycles at a fixed vCPU count, plus optional concurrent
# waves. Set POCKET_PROFILE_BUNDLE, POCKET_SOAK_STORE and POCKET_SOAK_GENERATION.
lifecycle-soak:
	./scripts/run-lifecycle-soak.sh

# Run a real container engine inside the guest, and a container inside that.
# Separate from the end-to-end suite because the image is large and the run is
# slow, not because the evidence is optional.
container-engine:
	./scripts/run-container-engine.sh

# Pull and run a set of unrelated base images. Requires network access.
distro-matrix:
	./scripts/run-distro-matrix.sh

# Rebuild everything in a second, completely independent build root and require
# the profile revision, sealed bundle tree, and release archive to match.
reproduce-release:
	./scripts/reproduce-release.sh

test-linux-source-pipeline:
	./scripts/test-linux-source-pipeline.sh

probe-initramfs: kernel
	./scripts/build-probe-initramfs.sh

probe-disk:
	./scripts/build-probe-disk.sh

probe: probe-initramfs probe-disk
	./scripts/run-uml-probe.sh

memory-matrix: host-tools probe-initramfs probe-disk
	./scripts/run-memory-matrix-probe.sh

smp-probe-initramfs: kernel
	./scripts/build-smp-probe-initramfs.sh

smp-scaling: smp-probe-initramfs
	./scripts/run-smp-scaling-probe.sh

lifecycle-probe-initramfs: kernel
	./scripts/build-lifecycle-probe-initramfs.sh

lifecycle-probe: host-tools lifecycle-probe-initramfs probe-disk
	./scripts/run-guard-lifecycle-probe.sh

builder-initramfs: kernel
	./scripts/build-builder-initramfs.sh

workload-probe-initramfs: kernel
	./scripts/build-workload-probe-initramfs.sh

ubuntu-24.04:
	./scripts/pull-ubuntu-fixture.sh 24.04

ubuntu-26.04:
	./scripts/pull-ubuntu-fixture.sh 26.04

e2e-probe: builder-initramfs workload-probe-initramfs ubuntu-24.04
	./scripts/build-oci-rootfs-probe.sh 24.04
	./scripts/run-oci-workload-probe.sh 24.04

e2e-probe-26.04: builder-initramfs workload-probe-initramfs ubuntu-26.04
	./scripts/build-oci-rootfs-probe.sh 26.04
	./scripts/run-oci-workload-probe.sh 26.04

# Where `make install` puts things, and where `make package` writes the
# tarball. Both are overridable: `make install PREFIX=/opt/pocket`.
PREFIX ?= $(HOME)/.local
PACKAGE_DIR ?= $(CURDIR)/build/package

# Build a relocatable release tarball from the sealed profile. Optional: the
# ordinary build does not produce one, because most people building from source
# just want `make install`.
#
# Idempotent, and stricter than it needs to be on the second run: the archive
# name is content-addressed, so if one is already there the bytes must match,
# and a mismatch is a reproducibility failure worth hearing about.
package: release-profile
	@mkdir -p -- "$(PACKAGE_DIR)"
	@set -e; \
	profile=$$(cat "$(CURDIR)/build/profiles/latest"); \
	stage=$$(mktemp -d "$(PACKAGE_DIR)/.stage.XXXXXX"); \
	trap 'rm -rf -- "$$stage"' EXIT; \
	./scripts/package-release.py --repo-root "$(CURDIR)" --profile "$$profile" \
	    --pocket "$(CURDIR)/build/release/x86_64-smp-p4k/host/pocket" \
	    --output-dir "$$stage" > "$$stage/package.json"; \
	built=$$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["archive"])' "$$stage/package.json"); \
	final="$(PACKAGE_DIR)/$$(basename "$$built")"; \
	if [ -e "$$final" ]; then \
	    cmp -s "$$built" "$$final" || { echo "an archive of this release already exists and differs: $$final" >&2; exit 1; }; \
	else \
	    mv -- "$$built" "$$final"; \
	fi; \
	printf '%s\n' "$$final" > "$(PACKAGE_DIR)/latest"; \
	printf 'package=%s\n' "$$final"

# What `make install` records in the config file it writes. All optional: the
# installer picks XDG defaults for the first three, and the last two decline
# the config file and the <prefix>/bin/pocket link respectively.
#
#   make install PREFIX=/opt/p STORE=/data/store RUNTIME_ROOT=/run/user/1000/p
#   make install NO_CONFIG=1 NO_DEFAULT_LINK=1
INSTALL_OPTIONS = \
	$(if $(STORE),--store "$(STORE)") \
	$(if $(RUNTIME_ROOT),--runtime-root "$(RUNTIME_ROOT)") \
	$(if $(CONFIG),--config "$(CONFIG)") \
	$(if $(NO_CONFIG),--no-config) \
	$(if $(NO_DEFAULT_LINK),--no-default-link)

# Install into a user-owned prefix and write a config file so ordinary commands
# need no flags. Never runs as root: this installs for one user, not a machine.
install: package
	./scripts/install-release.py install \
	    --archive "$$(cat "$(PACKAGE_DIR)/latest")" \
	    --prefix "$(PREFIX)" $(INSTALL_OPTIONS)

# Install a tarball someone else built. The whole point of `make package`.
install-archive:
	@[ -n "$(ARCHIVE)" ] || { echo "usage: make install-archive ARCHIVE=<path> [PREFIX=<dir>]" >&2; exit 2; }
	./scripts/install-release.py install --archive "$(ARCHIVE)" \
	    --prefix "$(PREFIX)" $(INSTALL_OPTIONS)

# The Rust suite, the lints, and the shell checks, as one committed target.
# Without this the unit tests were reachable only by knowing to type them,
# which is exactly the state that lets a claim outlive the check behind it.
test:
	cargo fmt --all --check
	cargo clippy --workspace --all-targets --release -- -D warnings
	cargo test --workspace --release
	bash -c 'for f in scripts/*.sh; do bash -n "$$f" || exit 1; done'
	# SC1091 is the sourced lib.sh, which shellcheck cannot resolve from a
	# glob; SC2001 is one style suggestion. Neither is a warning or an error.
	shellcheck -x -e SC1091,SC2001 scripts/*.sh
	python3 -m compileall -q scripts

verify:
	./scripts/verify-kernel-config.sh
	./scripts/verify-artifacts.sh
