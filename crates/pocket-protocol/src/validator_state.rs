use crate::{Direction, ProtocolError, ValidatorMessage, validator_evidence_sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidatorState {
    AwaitHello,
    AwaitStart,
    AwaitDone,
    Completed,
    Failed,
}

impl ValidatorState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::AwaitHello => "await-validate-hello",
            Self::AwaitStart => "await-validate-start",
            Self::AwaitDone => "await-validate-done",
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }

    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed)
    }
}

#[derive(Debug, Clone)]
pub struct ValidatorSession {
    state: ValidatorState,
    next_host_sequence: u64,
    next_guest_sequence: u64,
    accepted_physmem_bytes: Option<u64>,
    start: Option<Box<crate::ValidatorStart>>,
}

impl Default for ValidatorSession {
    fn default() -> Self {
        Self::new()
    }
}

impl ValidatorSession {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: ValidatorState::AwaitHello,
            next_host_sequence: 0,
            next_guest_sequence: 0,
            accepted_physmem_bytes: None,
            start: None,
        }
    }

    #[must_use]
    pub const fn state(&self) -> ValidatorState {
        self.state
    }

    #[must_use]
    pub const fn next_sequence(&self, direction: Direction) -> u64 {
        match direction {
            Direction::HostToGuest => self.next_host_sequence,
            Direction::GuestToHost => self.next_guest_sequence,
        }
    }

    pub fn accept(
        &mut self,
        direction: Direction,
        message: &ValidatorMessage,
        frame_sequence: u64,
    ) -> Result<(), ProtocolError> {
        let expected = self.next_sequence(direction);
        if frame_sequence != expected {
            return Err(ProtocolError::SequenceMismatch {
                expected,
                actual: frame_sequence,
            });
        }
        message.validate()?;
        let mut next = self.clone();
        next.accept_inner(direction, message)?;
        let incremented = frame_sequence
            .checked_add(1)
            .ok_or(ProtocolError::SequenceExhausted)?;
        match direction {
            Direction::HostToGuest => next.next_host_sequence = incremented,
            Direction::GuestToHost => next.next_guest_sequence = incremented,
        }
        *self = next;
        Ok(())
    }

    fn accept_inner(
        &mut self,
        direction: Direction,
        message: &ValidatorMessage,
    ) -> Result<(), ProtocolError> {
        match (self.state, direction, message) {
            (
                ValidatorState::AwaitHello,
                Direction::GuestToHost,
                ValidatorMessage::Hello(hello),
            ) => {
                self.accepted_physmem_bytes = Some(hello.accepted_physmem_bytes);
                self.state = ValidatorState::AwaitStart;
                Ok(())
            }
            (
                ValidatorState::AwaitStart,
                Direction::HostToGuest,
                ValidatorMessage::Start(start),
            ) => {
                if self.accepted_physmem_bytes != Some(start.expected_physmem_bytes) {
                    return invalid("expected_physmem_bytes");
                }
                self.start = Some(start.clone());
                self.state = ValidatorState::AwaitDone;
                Ok(())
            }
            (ValidatorState::AwaitDone, Direction::GuestToHost, ValidatorMessage::Done(done)) => {
                let start = self
                    .start
                    .as_ref()
                    .ok_or(ProtocolError::InvalidStateTransition {
                        state: self.state.as_str(),
                        direction: "guest-to-host",
                        kind: message.kind() as u16,
                    })?;
                if done.challenge != start.challenge
                    || done.evidence.manifest_sha256 != start.expected_manifest_sha256
                    || done.evidence.manifest_entry_count != start.expected_manifest_entry_count
                    || done.evidence.manifest_byte_count != start.expected_manifest_byte_count
                    || done.evidence.generation_marker_sha256
                        != start.expected_generation_marker_sha256
                    || done.evidence.account_db_sha256 != start.expected_account_db.sha256
                    || done.evidence.filesystem_uuid != start.expected_filesystem_uuid
                    || done.evidence.filesystem_bytes != start.expected_filesystem_bytes
                    || done.evidence_sha256 != validator_evidence_sha256(start, &done.evidence)
                {
                    return invalid("validation_evidence");
                }
                self.state = ValidatorState::Completed;
                Ok(())
            }
            (
                ValidatorState::AwaitStart | ValidatorState::AwaitDone,
                Direction::GuestToHost,
                ValidatorMessage::Error(_),
            ) => {
                self.state = ValidatorState::Failed;
                Ok(())
            }
            _ => Err(ProtocolError::InvalidStateTransition {
                state: self.state.as_str(),
                direction: match direction {
                    Direction::HostToGuest => "host-to-guest",
                    Direction::GuestToHost => "guest-to-host",
                },
                kind: message.kind() as u16,
            }),
        }
    }
}

fn invalid(field: &'static str) -> Result<(), ProtocolError> {
    Err(ProtocolError::InvalidMessage {
        field,
        reason: "validator transcript differs from its prior evidence",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{VALIDATOR_GUEST_FEATURES, ValidatorDone, ValidatorEvidence, ValidatorHello};

    #[test]
    fn rejects_done_bound_to_a_different_challenge_transactionally() {
        let start = crate::validator::tests::start();
        let hello = ValidatorHello {
            guest_contract_id: "1".repeat(64),
            init_build_id: "2".repeat(64),
            kernel_build_id: "3".repeat(64),
            host_elf_machine: 62,
            guest_uts_machine: "x86_64".to_owned(),
            guest_page_size: 4096,
            cpu_state_hwcap_policy: "native-x86_64-v1".to_owned(),
            online_cpus: 1,
            accepted_physmem_bytes: start.expected_physmem_bytes,
            features: VALIDATOR_GUEST_FEATURES
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
        };
        let evidence = ValidatorEvidence {
            manifest_sha256: start.expected_manifest_sha256.clone(),
            manifest_entry_count: start.expected_manifest_entry_count,
            manifest_byte_count: start.expected_manifest_byte_count,
            generation_marker_sha256: start.expected_generation_marker_sha256.clone(),
            account_db_sha256: start.expected_account_db.sha256.clone(),
            filesystem_uuid: start.expected_filesystem_uuid.clone(),
            filesystem_bytes: start.expected_filesystem_bytes,
            clean_before_mount: true,
            block_device_read_only: true,
            mounted_read_only: true,
            unmounted: true,
            clean_after_unmount: true,
        };
        let mut session = ValidatorSession::new();
        session
            .accept(Direction::GuestToHost, &ValidatorMessage::Hello(hello), 0)
            .expect("hello");
        session
            .accept(
                Direction::HostToGuest,
                &ValidatorMessage::Start(Box::new(start.clone())),
                0,
            )
            .expect("start");
        let mut done = ValidatorDone::from_evidence(&start, evidence);
        done.challenge = "9".repeat(64);
        assert!(
            session
                .accept(Direction::GuestToHost, &ValidatorMessage::Done(done), 1,)
                .is_err()
        );
        assert_eq!(session.state(), ValidatorState::AwaitDone);
    }
}
