/// Capabilities excluded by Pocket's fixed workload profile.
///
/// In particular, this makes a read-only root meaningful even for UID 0:
/// the workload cannot remount it, access arbitrary I/O ports, or recreate a
/// hidden UBD block device after `/dev` has been curated.
pub const BLOCKED_CAPABILITIES: [u32; 9] = [
    16, // CAP_SYS_MODULE
    17, // CAP_SYS_RAWIO
    18, // CAP_SYS_CHROOT
    19, // CAP_SYS_PTRACE
    21, // CAP_SYS_ADMIN
    22, // CAP_SYS_BOOT
    25, // CAP_SYS_TIME
    27, // CAP_MKNOD
    33, // CAP_MAC_ADMIN
];

/// Exact `fixed-capabilities-v1` allowlist.
///
/// This is the conventional Docker default set with `CAP_MKNOD` and
/// `CAP_SYS_CHROOT` removed. Starting from an allowlist, rather than merely a
/// denylist, keeps the result stable as kernels add capability bits.
pub const ALLOWED_CAPABILITIES: [u32; 12] = [
    0,  // CAP_CHOWN
    1,  // CAP_DAC_OVERRIDE
    3,  // CAP_FOWNER
    4,  // CAP_FSETID
    5,  // CAP_KILL
    6,  // CAP_SETGID
    7,  // CAP_SETUID
    8,  // CAP_SETPCAP
    10, // CAP_NET_BIND_SERVICE
    13, // CAP_NET_RAW
    29, // CAP_AUDIT_WRITE
    31, // CAP_SETFCAP
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapabilitySets {
    pub effective: [u32; 2],
    pub permitted: [u32; 2],
    pub inheritable: [u32; 2],
}

/// Independently testable evidence required by the UID-0 read-only profile.
///
/// The privileged runtime constructs these conditions with kernel operations;
/// keeping the final predicate pure makes omissions in that setup policy easy
/// to exercise without requiring a privileged test runner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RootReadOnlyGuards {
    pub capability_sets: CapabilitySets,
    pub no_new_privs: bool,
    pub root_mount_read_only: bool,
    pub root_mount_nodev: bool,
    pub root_mount_nosuid: bool,
    pub private_curated_dev: bool,
    pub bounding_set_restricted: bool,
    pub outside_root_directory_fds: usize,
}

#[must_use]
pub fn apply_fixed_capability_mask(mut sets: CapabilitySets) -> CapabilitySets {
    let allowed = allowed_capability_words();
    for (index, allowed_word) in allowed.into_iter().enumerate() {
        sets.effective[index] &= allowed_word;
        sets.permitted[index] &= allowed_word;
        sets.inheritable[index] &= allowed_word;
    }
    sets
}

/// Exact post-setup capability state for a UID-0 workload. Inheritable and
/// ambient state are deliberately empty; only effective/permitted carry the
/// versioned allowlist.
#[must_use]
/// Every capability the running kernel implements, for a privileged run.
pub fn full_root_capability_sets(last: u32) -> CapabilitySets {
    let mut words = [0u32; 2];
    let mut capability = 0;
    while capability <= last && capability < 64 {
        words[(capability / 32) as usize] |= 1 << (capability % 32);
        capability += 1;
    }
    CapabilitySets {
        effective: words,
        permitted: words,
        inheritable: [0; 2],
    }
}

pub const fn fixed_root_capability_sets() -> CapabilitySets {
    let allowed = allowed_capability_words();
    CapabilitySets {
        effective: allowed,
        permitted: allowed,
        inheritable: [0; 2],
    }
}

#[must_use]
pub const fn capability_is_allowed(capability: u32) -> bool {
    let mut index = 0;
    while index < ALLOWED_CAPABILITIES.len() {
        if ALLOWED_CAPABILITIES[index] == capability {
            return true;
        }
        index += 1;
    }
    false
}

const fn allowed_capability_words() -> [u32; 2] {
    let mut words = [0_u32; 2];
    let mut index = 0;
    while index < ALLOWED_CAPABILITIES.len() {
        let capability = ALLOWED_CAPABILITIES[index];
        words[(capability / 32) as usize] |= 1_u32 << (capability % 32);
        index += 1;
    }
    words
}

#[must_use]
pub fn uid_zero_read_only_guards_hold(guards: RootReadOnlyGuards) -> bool {
    guards.no_new_privs
        && guards.root_mount_read_only
        && guards.root_mount_nodev
        && guards.root_mount_nosuid
        && guards.private_curated_dev
        && guards.bounding_set_restricted
        && guards.outside_root_directory_fds == 0
        && guards.capability_sets == fixed_root_capability_sets()
}

#[cfg(test)]
mod tests {
    use super::{
        ALLOWED_CAPABILITIES, BLOCKED_CAPABILITIES, CapabilitySets, RootReadOnlyGuards,
        apply_fixed_capability_mask, capability_is_allowed, fixed_root_capability_sets,
        uid_zero_read_only_guards_hold,
    };

    fn complete_read_only_guards() -> RootReadOnlyGuards {
        RootReadOnlyGuards {
            capability_sets: fixed_root_capability_sets(),
            no_new_privs: true,
            root_mount_read_only: true,
            root_mount_nodev: true,
            root_mount_nosuid: true,
            private_curated_dev: true,
            bounding_set_restricted: true,
            outside_root_directory_fds: 0,
        }
    }

    #[test]
    fn fixed_policy_removes_every_blocked_capability_from_every_set() {
        let masked = apply_fixed_capability_mask(CapabilitySets {
            effective: [u32::MAX; 2],
            permitted: [u32::MAX; 2],
            inheritable: [u32::MAX; 2],
        });
        for capability in BLOCKED_CAPABILITIES {
            let word = (capability / 32) as usize;
            let bit = 1_u32 << (capability % 32);
            assert_eq!(masked.effective[word] & bit, 0);
            assert_eq!(masked.permitted[word] & bit, 0);
            assert_eq!(masked.inheritable[word] & bit, 0);
        }
        for capability in 0..64 {
            let word = (capability / 32) as usize;
            let bit = 1_u32 << (capability % 32);
            if capability_is_allowed(capability) {
                assert_ne!(masked.effective[word] & bit, 0);
            } else {
                assert_eq!(masked.effective[word] & bit, 0);
                assert_eq!(masked.permitted[word] & bit, 0);
                assert_eq!(masked.inheritable[word] & bit, 0);
            }
        }
        assert_eq!(
            ALLOWED_CAPABILITIES,
            [0, 1, 3, 4, 5, 6, 7, 8, 10, 13, 29, 31]
        );
        assert_ne!(masked.effective[0] & 1, 0, "unrelated CAP_CHOWN changed");
    }

    #[test]
    fn uid_zero_read_only_policy_excludes_every_privilege_escalation_capability() {
        // UID 0 starts with all capability words populated in this model. The
        // runtime additionally sets no_new_privs for root-read-only execution;
        // this test proves the independently testable mask it applies first.
        let masked = apply_fixed_capability_mask(CapabilitySets {
            effective: [u32::MAX; 2],
            permitted: [u32::MAX; 2],
            inheritable: [u32::MAX; 2],
        });
        assert_eq!(BLOCKED_CAPABILITIES, [16, 17, 18, 19, 21, 22, 25, 27, 33]);
        for capability in BLOCKED_CAPABILITIES {
            let word = (capability / 32) as usize;
            let bit = 1_u32 << (capability % 32);
            assert_eq!(masked.effective[word] & bit, 0);
            assert_eq!(masked.permitted[word] & bit, 0);
            assert_eq!(masked.inheritable[word] & bit, 0);
        }
    }

    #[test]
    fn root_policy_is_exact_effective_permitted_with_empty_inheritable() {
        let exact = fixed_root_capability_sets();
        assert_eq!(exact.effective, exact.permitted);
        assert_eq!(exact.inheritable, [0; 2]);
        for capability in 0..64 {
            let word = (capability / 32) as usize;
            let bit = 1_u32 << (capability % 32);
            assert_eq!(
                exact.effective[word] & bit != 0,
                capability_is_allowed(capability)
            );
        }
    }

    #[test]
    fn uid_zero_read_only_guards_reject_chroot_escape_preconditions() {
        let complete = complete_read_only_guards();
        assert!(uid_zero_read_only_guards_hold(complete));

        let mut chroot_retained = complete;
        let word = (18 / 32) as usize;
        let bit = 1_u32 << 18;
        chroot_retained.capability_sets.effective[word] |= bit;
        chroot_retained.capability_sets.permitted[word] |= bit;
        assert!(!uid_zero_read_only_guards_hold(chroot_retained));

        let mut outside_directory_retained = complete;
        outside_directory_retained.outside_root_directory_fds = 1;
        assert!(!uid_zero_read_only_guards_hold(outside_directory_retained));
    }

    #[test]
    fn uid_zero_read_only_guards_reject_root_write_preconditions() {
        let complete = complete_read_only_guards();

        let mut writable_mount = complete;
        writable_mount.root_mount_read_only = false;
        assert!(!uid_zero_read_only_guards_hold(writable_mount));

        let mut host_devices_visible = complete;
        host_devices_visible.private_curated_dev = false;
        assert!(!uid_zero_read_only_guards_hold(host_devices_visible));

        // OCI layers may contain a preexisting UBD block node outside /dev.
        // NODEV on the image-root bind is what makes opening that node fail;
        // curating only /dev and denying MKNOD would not be sufficient.
        let mut preexisting_image_device_usable = complete;
        preexisting_image_device_usable.root_mount_nodev = false;
        assert!(!uid_zero_read_only_guards_hold(
            preexisting_image_device_usable
        ));

        let mut set_id_metadata_active = complete;
        set_id_metadata_active.root_mount_nosuid = false;
        assert!(!uid_zero_read_only_guards_hold(set_id_metadata_active));

        let mut mount_capability_retained = complete;
        let word = (21 / 32) as usize;
        let bit = 1_u32 << 21;
        mount_capability_retained.capability_sets.effective[word] |= bit;
        mount_capability_retained.capability_sets.permitted[word] |= bit;
        assert!(!uid_zero_read_only_guards_hold(mount_capability_retained));

        let mut privilege_reacquisition_allowed = complete;
        privilege_reacquisition_allowed.no_new_privs = false;
        assert!(!uid_zero_read_only_guards_hold(
            privilege_reacquisition_allowed
        ));

        let mut unrestricted_bounding_set = complete;
        unrestricted_bounding_set.bounding_set_restricted = false;
        assert!(!uid_zero_read_only_guards_hold(unrestricted_bounding_set));
    }

    #[test]
    fn policy_is_idempotent() {
        let initial = CapabilitySets {
            effective: [0x1357_9bdf, 0x2468_ace0],
            permitted: [0xaaaa_5555, 0x5555_aaaa],
            inheritable: [0xffff_0000, 0x0000_ffff],
        };
        let once = apply_fixed_capability_mask(initial);
        assert_eq!(apply_fixed_capability_mask(once), once);
    }
}
