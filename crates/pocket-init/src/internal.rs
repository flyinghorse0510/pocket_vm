use crate::InitError;

const INTERNAL_HEADER_LEN: usize = 5;
const MAX_INTERNAL_PAYLOAD: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InternalEvent {
    Ready {
        outer_pid: i32,
    },
    Exit {
        code: Option<u8>,
        signal: Option<u16>,
        namespace_clean: bool,
    },
    Error {
        errno: Option<i32>,
        diagnostic: String,
    },
}

impl InternalEvent {
    pub fn encode(&self) -> Result<Vec<u8>, InitError> {
        let (tag, payload) = match self {
            Self::Ready { outer_pid } => (1_u8, outer_pid.to_be_bytes().to_vec()),
            Self::Exit {
                code,
                signal,
                namespace_clean,
            } => {
                let mut payload = Vec::with_capacity(4);
                match (code, signal) {
                    (Some(code), None) => {
                        payload.push(0);
                        payload.extend_from_slice(&u16::from(*code).to_be_bytes());
                    }
                    (None, Some(signal)) => {
                        payload.push(1);
                        payload.extend_from_slice(&signal.to_be_bytes());
                    }
                    _ => {
                        return Err(InitError::contract(
                            "internal-event",
                            "exit event requires exactly one status",
                        ));
                    }
                }
                payload.push(u8::from(*namespace_clean));
                (2, payload)
            }
            Self::Error { errno, diagnostic } => {
                let diagnostic = diagnostic.as_bytes();
                if diagnostic.len() > MAX_INTERNAL_PAYLOAD - 5 {
                    return Err(InitError::contract(
                        "internal-event",
                        "internal diagnostic exceeds hard cap",
                    ));
                }
                let mut payload = Vec::with_capacity(5 + diagnostic.len());
                payload.extend_from_slice(&errno.unwrap_or(0).to_be_bytes());
                payload.push(u8::from(errno.is_some()));
                payload.extend_from_slice(diagnostic);
                (3, payload)
            }
        };
        if payload.len() > MAX_INTERNAL_PAYLOAD {
            return Err(InitError::contract(
                "internal-event",
                "internal payload exceeds hard cap",
            ));
        }
        let length = u32::try_from(payload.len()).map_err(|_| {
            InitError::contract("internal-event", "internal payload length overflow")
        })?;
        let mut encoded = Vec::with_capacity(INTERNAL_HEADER_LEN + payload.len());
        encoded.push(tag);
        encoded.extend_from_slice(&length.to_be_bytes());
        encoded.extend_from_slice(&payload);
        Ok(encoded)
    }
}

#[derive(Debug, Default)]
pub struct InternalEventDecoder {
    pending: Vec<u8>,
}

impl InternalEventDecoder {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            pending: Vec::new(),
        }
    }

    pub fn feed(&mut self, bytes: &[u8]) -> Result<Vec<InternalEvent>, InitError> {
        let maximum_pending = INTERNAL_HEADER_LEN + MAX_INTERNAL_PAYLOAD;
        if self.pending.len().saturating_add(bytes.len()) > maximum_pending {
            return Err(InitError::contract(
                "internal-event",
                "pending internal event exceeds hard cap",
            ));
        }
        self.pending.extend_from_slice(bytes);
        let mut events = Vec::new();
        loop {
            if self.pending.len() < INTERNAL_HEADER_LEN {
                break;
            }
            let length = u32::from_be_bytes([
                self.pending[1],
                self.pending[2],
                self.pending[3],
                self.pending[4],
            ]) as usize;
            if length > MAX_INTERNAL_PAYLOAD {
                return Err(InitError::contract(
                    "internal-event",
                    "declared internal payload exceeds hard cap",
                ));
            }
            let total = INTERNAL_HEADER_LEN + length;
            if self.pending.len() < total {
                break;
            }
            let frame: Vec<u8> = self.pending.drain(..total).collect();
            events.push(decode_one(frame[0], &frame[INTERNAL_HEADER_LEN..])?);
        }
        Ok(events)
    }

    #[must_use]
    pub fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }
}

fn decode_one(tag: u8, payload: &[u8]) -> Result<InternalEvent, InitError> {
    match tag {
        1 if payload.len() == 4 => Ok(InternalEvent::Ready {
            outer_pid: i32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]),
        }),
        2 if payload.len() == 4 => {
            let value = u16::from_be_bytes([payload[1], payload[2]]);
            let clean = match payload[3] {
                0 => false,
                1 => true,
                _ => return Err(malformed()),
            };
            match payload[0] {
                0 if value <= u16::from(u8::MAX) => Ok(InternalEvent::Exit {
                    code: Some(value as u8),
                    signal: None,
                    namespace_clean: clean,
                }),
                1 if (1..=64).contains(&value) => Ok(InternalEvent::Exit {
                    code: None,
                    signal: Some(value),
                    namespace_clean: clean,
                }),
                _ => Err(malformed()),
            }
        }
        3 if payload.len() >= 5 => {
            let raw_errno = i32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
            let errno = match payload[4] {
                0 if raw_errno == 0 => None,
                1 if raw_errno > 0 => Some(raw_errno),
                _ => return Err(malformed()),
            };
            let diagnostic = std::str::from_utf8(&payload[5..])
                .map_err(|_| malformed())?
                .to_owned();
            Ok(InternalEvent::Error { errno, diagnostic })
        }
        _ => Err(malformed()),
    }
}

fn malformed() -> InitError {
    InitError::contract("internal-event", "malformed namespace supervisor event")
}

#[cfg(test)]
mod tests {
    use super::{InternalEvent, InternalEventDecoder};

    #[test]
    fn fragmented_and_coalesced_events_round_trip() {
        let events = [
            InternalEvent::Ready { outer_pid: 42 },
            InternalEvent::Exit {
                code: None,
                signal: Some(15),
                namespace_clean: true,
            },
        ];
        let mut bytes = Vec::new();
        for event in &events {
            match event.encode() {
                Ok(encoded) => bytes.extend(encoded),
                Err(error) => panic!("event encode failed: {error}"),
            }
        }
        let mut decoder = InternalEventDecoder::new();
        let first = match decoder.feed(&bytes[..3]) {
            Ok(events) => events,
            Err(error) => panic!("fragment rejected: {error}"),
        };
        assert!(first.is_empty());
        let decoded = match decoder.feed(&bytes[3..]) {
            Ok(events) => events,
            Err(error) => panic!("events rejected: {error}"),
        };
        assert_eq!(decoded, events);
        assert!(!decoder.has_pending());
    }

    #[test]
    fn error_event_preserves_errno_and_text() {
        let event = InternalEvent::Error {
            errno: Some(2),
            diagnostic: "execve: not found".to_owned(),
        };
        let bytes = match event.encode() {
            Ok(bytes) => bytes,
            Err(error) => panic!("event encode failed: {error}"),
        };
        let decoded = match InternalEventDecoder::new().feed(&bytes) {
            Ok(events) => events,
            Err(error) => panic!("event decode failed: {error}"),
        };
        assert_eq!(decoded, vec![event]);
    }

    #[test]
    fn forced_sigkill_outcome_is_exact_and_malformed_statuses_fail() {
        let forced = InternalEvent::Exit {
            code: None,
            signal: Some(9),
            namespace_clean: true,
        };
        let bytes = forced.encode().expect("encode forced exit");
        let decoded = InternalEventDecoder::new()
            .feed(&bytes)
            .expect("decode forced exit");
        assert_eq!(decoded, vec![forced]);

        // Exit tag, four-byte payload, signal discriminant, signal zero, and
        // a canonical clean flag. Signal zero is never a process outcome.
        let malformed = [2, 0, 0, 0, 4, 1, 0, 0, 1];
        assert!(InternalEventDecoder::new().feed(&malformed).is_err());
    }
}
