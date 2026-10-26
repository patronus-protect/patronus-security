use crate::WolfExecutionOptions;

/// Keeps only the current window. Retained overlap alone never creates a final window.
pub(super) struct Windows {
    pending: Vec<u32>,
    capacity: usize,
    overlap: usize,
    fresh: bool,
    emitted: bool,
}
impl Windows {
    pub(super) fn new(options: WolfExecutionOptions) -> Self {
        Self {
            pending: Vec::with_capacity(options.content_tokens()),
            capacity: options.content_tokens(),
            overlap: options.overlap_tokens,
            fresh: false,
            emitted: false,
        }
    }
    pub(super) fn push(&mut self, token: u32) -> Option<Vec<u32>> {
        self.pending.push(token);
        self.fresh = true;
        if self.pending.len() < self.capacity {
            return None;
        }
        let window = std::mem::replace(&mut self.pending, Vec::with_capacity(self.capacity));
        self.pending
            .extend_from_slice(&window[self.capacity - self.overlap..]);
        self.fresh = false;
        self.emitted = true;
        Some(window)
    }
    pub(super) fn finish(self) -> Option<Vec<u32>> {
        (self.fresh || !self.emitted).then_some(self.pending)
    }
}

pub(super) fn count(tokens: u64, options: WolfExecutionOptions) -> u64 {
    let capacity = options.content_tokens() as u64;
    1 + tokens
        .saturating_sub(capacity)
        .div_ceil(capacity - options.overlap_tokens as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn overlap_and_exact_boundaries() {
        for capacity in [1, 3, 254, 2046] {
            for overlap in [0, capacity / 2, capacity - 1] {
                let options = WolfExecutionOptions {
                    window_tokens: capacity + 2,
                    overlap_tokens: overlap,
                    batch_size: 4,
                };
                for size in [0, 1, capacity, capacity + 1, capacity * 3, capacity * 3 + 1] {
                    let tokens: Vec<u32> = (0..size as u32).collect();
                    let mut windows = Windows::new(options);
                    let mut actual = Vec::new();
                    for &token in &tokens {
                        if let Some(window) = windows.push(token) {
                            actual.push(window);
                        }
                    }
                    if let Some(window) = windows.finish() {
                        actual.push(window);
                    }
                    let mut expected = Vec::new();
                    let mut start = 0;
                    loop {
                        let end = (start + capacity).min(size);
                        expected.push(tokens[start..end].to_vec());
                        if end == size {
                            break;
                        }
                        start += capacity - overlap;
                    }
                    assert_eq!(actual, expected);
                    assert_eq!(actual.len() as u64, count(size as u64, options));
                }
            }
        }
    }
}
