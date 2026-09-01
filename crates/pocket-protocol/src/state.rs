use crate::{MessageKind, ProtocolError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    HostToGuest,
    GuestToHost,
}

impl Direction {
    const fn as_str(self) -> &'static str {
        match self {
            Self::HostToGuest => "host-to-guest",
            Self::GuestToHost => "guest-to-host",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkloadState {
    AwaitHello,
    AwaitStart,
    AwaitReady,
    Running,
    ShuttingDown,
    Exited,
    Failed,
}

impl WorkloadState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::AwaitHello => "await-hello",
            Self::AwaitStart => "await-start",
            Self::AwaitReady => "await-ready",
            Self::Running => "running",
            Self::ShuttingDown => "shutting-down",
            Self::Exited => "exited",
            Self::Failed => "failed",
        }
    }

    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Exited | Self::Failed)
    }
}

/// Validates both semantic ordering and independent per-direction frame
/// sequences for one workload session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkloadSession {
    state: WorkloadState,
    next_host_sequence: u64,
    next_guest_sequence: u64,
}

impl Default for WorkloadSession {
    fn default() -> Self {
        Self::new()
    }
}

impl WorkloadSession {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: WorkloadState::AwaitHello,
            next_host_sequence: 0,
            next_guest_sequence: 0,
        }
    }

    #[must_use]
    pub const fn state(&self) -> WorkloadState {
        self.state
    }

    #[must_use]
    pub const fn next_sequence(&self, direction: Direction) -> u64 {
        match direction {
            Direction::HostToGuest => self.next_host_sequence,
            Direction::GuestToHost => self.next_guest_sequence,
        }
    }

    /// Accept one header only if sequence and lifecycle transition are exact.
    /// State and sequence counters are left unchanged on an error.
    pub fn accept(
        &mut self,
        direction: Direction,
        kind: MessageKind,
        sequence: u64,
    ) -> Result<(), ProtocolError> {
        let expected = self.next_sequence(direction);
        if sequence != expected {
            return Err(ProtocolError::SequenceMismatch {
                expected,
                actual: sequence,
            });
        }

        let next_state = match (self.state, direction, kind) {
            (WorkloadState::AwaitHello, Direction::GuestToHost, MessageKind::Hello) => {
                WorkloadState::AwaitStart
            }
            (WorkloadState::AwaitStart, Direction::HostToGuest, MessageKind::Start) => {
                WorkloadState::AwaitReady
            }
            (WorkloadState::AwaitReady, Direction::GuestToHost, MessageKind::Ready) => {
                WorkloadState::Running
            }
            // A guest that fails before it can describe itself still has a
            // control channel and still knows why. Without this transition its
            // ERROR is refused as an invalid transition and the host is left
            // with a timeout instead of the cause.
            (
                WorkloadState::AwaitHello | WorkloadState::AwaitStart | WorkloadState::AwaitReady,
                Direction::GuestToHost,
                MessageKind::Error,
            ) => WorkloadState::Failed,
            (
                WorkloadState::Running,
                Direction::HostToGuest,
                MessageKind::Signal | MessageKind::Resize,
            ) => WorkloadState::Running,
            (WorkloadState::Running, Direction::HostToGuest, MessageKind::Shutdown) => {
                WorkloadState::ShuttingDown
            }
            (
                WorkloadState::Running | WorkloadState::ShuttingDown,
                Direction::GuestToHost,
                MessageKind::Exit,
            ) => WorkloadState::Exited,
            (
                WorkloadState::Running | WorkloadState::ShuttingDown,
                Direction::GuestToHost,
                MessageKind::Error,
            ) => WorkloadState::Failed,
            _ => {
                return Err(ProtocolError::InvalidStateTransition {
                    state: self.state.as_str(),
                    direction: direction.as_str(),
                    kind: kind as u16,
                });
            }
        };

        let next_sequence = sequence
            .checked_add(1)
            .ok_or(ProtocolError::SequenceExhausted)?;
        match direction {
            Direction::HostToGuest => self.next_host_sequence = next_sequence,
            Direction::GuestToHost => self.next_guest_sequence = next_sequence,
        }
        self.state = next_state;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{Direction, MessageKind, ProtocolError, WorkloadSession, WorkloadState};

    #[test]
    fn accepts_complete_workload_lifecycle_with_independent_sequences() {
        let mut session = WorkloadSession::new();
        assert_eq!(session.state(), WorkloadState::AwaitHello);
        assert!(
            session
                .accept(Direction::GuestToHost, MessageKind::Hello, 0)
                .is_ok()
        );
        assert!(
            session
                .accept(Direction::HostToGuest, MessageKind::Start, 0)
                .is_ok()
        );
        assert!(
            session
                .accept(Direction::GuestToHost, MessageKind::Ready, 1)
                .is_ok()
        );
        assert!(
            session
                .accept(Direction::HostToGuest, MessageKind::Resize, 1)
                .is_ok()
        );
        assert!(
            session
                .accept(Direction::HostToGuest, MessageKind::Signal, 2)
                .is_ok()
        );
        assert!(
            session
                .accept(Direction::HostToGuest, MessageKind::Shutdown, 3)
                .is_ok()
        );
        assert_eq!(session.state(), WorkloadState::ShuttingDown);
        assert!(
            session
                .accept(Direction::GuestToHost, MessageKind::Exit, 2)
                .is_ok()
        );
        assert_eq!(session.state(), WorkloadState::Exited);
        assert!(session.state().is_terminal());
    }

    #[test]
    fn rejects_out_of_order_messages_without_mutating_state() {
        let mut session = WorkloadSession::new();
        let result = session.accept(Direction::HostToGuest, MessageKind::Start, 0);
        assert!(matches!(
            result,
            Err(ProtocolError::InvalidStateTransition { .. })
        ));
        assert_eq!(session.state(), WorkloadState::AwaitHello);
        assert_eq!(session.next_sequence(Direction::HostToGuest), 0);

        assert!(
            session
                .accept(Direction::GuestToHost, MessageKind::Hello, 0)
                .is_ok()
        );
        let result = session.accept(Direction::GuestToHost, MessageKind::Ready, 1);
        assert!(matches!(
            result,
            Err(ProtocolError::InvalidStateTransition { .. })
        ));
        assert_eq!(session.state(), WorkloadState::AwaitStart);
        assert_eq!(session.next_sequence(Direction::GuestToHost), 1);
    }

    #[test]
    fn rejects_duplicate_or_skipped_sequences_without_mutating_state() {
        let mut session = WorkloadSession::new();
        let result = session.accept(Direction::GuestToHost, MessageKind::Hello, 1);
        assert!(matches!(
            result,
            Err(ProtocolError::SequenceMismatch {
                expected: 0,
                actual: 1
            })
        ));
        assert_eq!(session.state(), WorkloadState::AwaitHello);
        assert_eq!(session.next_sequence(Direction::GuestToHost), 0);
    }

    /// A guest that fails before it can describe itself still has a control
    /// channel and still knows why. Refusing its ERROR turns a precise cause
    /// into a bare startup timeout on the host.
    #[test]
    fn a_guest_may_report_a_failure_before_it_has_sent_hello() {
        let mut session = WorkloadSession::new();
        session
            .accept(Direction::GuestToHost, MessageKind::Error, 0)
            .expect("pre-HELLO ERROR");
        assert_eq!(session.state(), WorkloadState::Failed);
        assert_eq!(session.next_sequence(Direction::GuestToHost), 1);

        // Failed is still terminal: nothing follows it, HELLO least of all.
        assert!(
            session
                .accept(Direction::GuestToHost, MessageKind::Hello, 1)
                .is_err()
        );
        // And the host still cannot invent one on the guest's behalf.
        let mut session = WorkloadSession::new();
        assert!(
            session
                .accept(Direction::HostToGuest, MessageKind::Error, 0)
                .is_err()
        );
    }

    #[test]
    fn shutdown_is_running_only_and_cannot_be_duplicated() {
        let mut session = WorkloadSession::new();
        assert!(
            session
                .accept(Direction::HostToGuest, MessageKind::Shutdown, 0)
                .is_err()
        );
        assert_eq!(session.next_sequence(Direction::HostToGuest), 0);
        session
            .accept(Direction::GuestToHost, MessageKind::Hello, 0)
            .expect("HELLO");
        session
            .accept(Direction::HostToGuest, MessageKind::Start, 0)
            .expect("START");
        assert!(
            session
                .accept(Direction::HostToGuest, MessageKind::Shutdown, 1)
                .is_err()
        );
        session
            .accept(Direction::GuestToHost, MessageKind::Ready, 1)
            .expect("READY");
        session
            .accept(Direction::HostToGuest, MessageKind::Shutdown, 1)
            .expect("SHUTDOWN");
        assert_eq!(session.state(), WorkloadState::ShuttingDown);
        assert!(
            session
                .accept(Direction::HostToGuest, MessageKind::Shutdown, 2)
                .is_err()
        );
        assert_eq!(session.next_sequence(Direction::HostToGuest), 2);
    }

    #[test]
    fn terminal_states_reject_further_messages() {
        let mut session = WorkloadSession::new();
        assert!(
            session
                .accept(Direction::GuestToHost, MessageKind::Hello, 0)
                .is_ok()
        );
        assert!(
            session
                .accept(Direction::HostToGuest, MessageKind::Start, 0)
                .is_ok()
        );
        assert!(
            session
                .accept(Direction::GuestToHost, MessageKind::Ready, 1)
                .is_ok()
        );
        assert!(
            session
                .accept(Direction::GuestToHost, MessageKind::Exit, 2)
                .is_ok()
        );
        assert!(
            session
                .accept(Direction::HostToGuest, MessageKind::Signal, 1)
                .is_err()
        );
    }

    #[test]
    fn guest_error_is_a_terminal_transition() {
        let mut session = WorkloadSession::new();
        assert!(
            session
                .accept(Direction::GuestToHost, MessageKind::Hello, 0)
                .is_ok()
        );
        assert!(
            session
                .accept(Direction::HostToGuest, MessageKind::Start, 0)
                .is_ok()
        );
        assert!(
            session
                .accept(Direction::GuestToHost, MessageKind::Error, 1)
                .is_ok()
        );
        assert_eq!(session.state(), WorkloadState::Failed);
    }
}
