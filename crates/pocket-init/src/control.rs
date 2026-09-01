use pocket_protocol::{
    FrameHeader, HEADER_LEN, MAX_CONTROL_PAYLOAD, ProtocolError, RawFrame, decode_frame_exact,
};

const MAX_READ_CHUNK: usize = 8192;
const MAX_PENDING: usize = HEADER_LEN + MAX_CONTROL_PAYLOAD + MAX_READ_CHUNK;

/// Incremental decoder used after START, when PID 1 must multiplex control
/// messages with stream pumping and child lifecycle events.
#[derive(Debug)]
pub struct ControlFrameDecoder {
    pending: Vec<u8>,
    expected_sequence: u64,
}

impl ControlFrameDecoder {
    #[must_use]
    pub const fn new(expected_sequence: u64) -> Self {
        Self {
            pending: Vec::new(),
            expected_sequence,
        }
    }

    pub fn feed(&mut self, bytes: &[u8]) -> Result<Vec<RawFrame>, ProtocolError> {
        if bytes.len() > MAX_READ_CHUNK
            || self.pending.len().saturating_add(bytes.len()) > MAX_PENDING
        {
            return Err(ProtocolError::PayloadTooLarge {
                actual: self.pending.len().saturating_add(bytes.len()),
                maximum: MAX_PENDING,
            });
        }
        self.pending.extend_from_slice(bytes);
        let mut frames = Vec::new();
        loop {
            if self.pending.len() < HEADER_LEN {
                break;
            }
            let header = FrameHeader::from_bytes(&self.pending[..HEADER_LEN])?;
            let total = HEADER_LEN.checked_add(header.payload_len as usize).ok_or(
                ProtocolError::PayloadTooLarge {
                    actual: header.payload_len as usize,
                    maximum: MAX_CONTROL_PAYLOAD,
                },
            )?;
            if self.pending.len() < total {
                break;
            }
            let encoded: Vec<u8> = self.pending.drain(..total).collect();
            let frame = decode_frame_exact(&encoded, self.expected_sequence)?;
            self.expected_sequence = self
                .expected_sequence
                .checked_add(1)
                .ok_or(ProtocolError::SequenceExhausted)?;
            frames.push(frame);
        }
        Ok(frames)
    }

    #[must_use]
    pub const fn expected_sequence(&self) -> u64 {
        self.expected_sequence
    }

    #[must_use]
    pub fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use pocket_protocol::{MessageKind, encode_frame};

    use super::ControlFrameDecoder;

    #[test]
    fn handles_fragmented_and_coalesced_frames() {
        let one = match encode_frame(MessageKind::Signal, 7, b"one") {
            Ok(frame) => frame,
            Err(error) => panic!("cannot encode frame: {error}"),
        };
        let two = match encode_frame(MessageKind::Resize, 8, b"two") {
            Ok(frame) => frame,
            Err(error) => panic!("cannot encode frame: {error}"),
        };
        let mut decoder = ControlFrameDecoder::new(7);
        assert!(
            decoder
                .feed(&one[..11])
                .unwrap_or_else(|error| panic!("fragment rejected: {error}"))
                .is_empty()
        );
        let mut rest = one[11..].to_vec();
        rest.extend(two);
        let frames = decoder
            .feed(&rest)
            .unwrap_or_else(|error| panic!("frames rejected: {error}"));
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].payload, b"one");
        assert_eq!(frames[1].payload, b"two");
        assert_eq!(decoder.expected_sequence(), 9);
    }

    #[test]
    fn sequence_failure_does_not_advance() {
        let frame = match encode_frame(MessageKind::Signal, 2, &[]) {
            Ok(frame) => frame,
            Err(error) => panic!("cannot encode frame: {error}"),
        };
        let mut decoder = ControlFrameDecoder::new(1);
        assert!(decoder.feed(&frame).is_err());
        assert_eq!(decoder.expected_sequence(), 1);
    }
}
