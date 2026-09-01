pub const MAX_PUMP_BUFFER: usize = 64 * 1024;

/// Fixed-capacity queue state used by each stream pump. It never reads more
/// input while full, thereby propagating backpressure to the workload or host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PumpBuffer {
    bytes: Vec<u8>,
    offset: usize,
    capacity: usize,
}

impl Default for PumpBuffer {
    fn default() -> Self {
        Self::new(MAX_PUMP_BUFFER)
    }
}

impl PumpBuffer {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "pump capacity must be nonzero");
        Self {
            bytes: Vec::with_capacity(capacity),
            offset: 0,
            capacity,
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len() - self.offset
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[must_use]
    pub fn remaining_capacity(&self) -> usize {
        self.capacity - self.len()
    }

    #[must_use]
    pub fn readable(&self) -> &[u8] {
        &self.bytes[self.offset..]
    }

    /// Length of the backing allocation currently in use. Exposed so tests can
    /// prove the declared capacity bounds real memory and not just the queue.
    #[must_use]
    pub fn backing_len(&self) -> usize {
        self.bytes.len()
    }

    pub fn push(&mut self, input: &[u8]) -> usize {
        let count = input.len().min(self.remaining_capacity());
        if count == 0 {
            return 0;
        }
        self.compact_for(count);
        self.bytes.extend_from_slice(&input[..count]);
        debug_assert!(self.bytes.len() <= self.capacity);
        count
    }

    pub fn consume(&mut self, count: usize) {
        let actual = count.min(self.len());
        self.offset += actual;
        if self.offset == self.bytes.len() {
            self.bytes.clear();
            self.offset = 0;
        }
    }

    /// Reclaim the consumed prefix whenever the tail cannot absorb `count`
    /// within the declared capacity. Deciding this from the backing
    /// allocation instead stops reclaiming as soon as the `Vec` has grown
    /// once, which lets the allocation climb with total bytes pumped while the
    /// logical cap still appears to hold.
    fn compact_for(&mut self, count: usize) {
        if self.offset > 0 && self.bytes.len() + count > self.capacity {
            self.bytes.drain(..self.offset);
            self.offset = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::PumpBuffer;

    #[test]
    fn buffer_enforces_cap_and_preserves_order_across_compaction() {
        let mut buffer = PumpBuffer::new(8);
        assert_eq!(buffer.push(b"abcdef"), 6);
        buffer.consume(4);
        assert_eq!(buffer.push(b"ghijkl"), 6);
        assert_eq!(buffer.readable(), b"efghijkl");
        assert_eq!(buffer.push(b"overflow"), 0);
        assert!(buffer.backing_len() <= 8);
        buffer.consume(8);
        assert!(buffer.is_empty());
    }

    #[test]
    fn declared_capacity_bounds_the_backing_allocation_across_many_rounds() {
        let mut buffer = PumpBuffer::new(64);
        let payload: Vec<u8> = (0..=u8::MAX).collect();
        let mut written = 0_usize;
        let mut read = 0_usize;
        // Partial fills and partial drains of coprime sizes keep the offset
        // nonzero, which is exactly the state the previous compaction rule
        // stopped reclaiming once the backing Vec had grown.
        for round in 0..4_000_usize {
            let take = 7 + round % 23;
            let start = written % payload.len();
            let end = (start + take).min(payload.len());
            written += buffer.push(&payload[start..end]);
            buffer.consume(5 + round % 11);
            read += 1;
            assert!(
                buffer.backing_len() <= 64,
                "round {round}: backing {} exceeded the declared capacity",
                buffer.backing_len()
            );
            assert!(buffer.len() <= 64);
        }
        assert!(written > 64 && read > 0);
    }
}
