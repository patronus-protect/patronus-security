/// Buffer bytes until an SSE frame is complete; transport chunks may split UTF-8.
#[derive(Default)]
pub(super) struct Frames {
    pending: Vec<u8>,
    searched: usize,
}

impl Frames {
    pub fn push(&mut self, bytes: &[u8]) -> Vec<String> {
        self.pending.extend_from_slice(bytes);
        let mut frames = Vec::new();
        let mut consumed = 0;
        while let Some(index) = self.pending[self.searched..]
            .windows(2)
            .position(|bytes| bytes == b"\n\n")
        {
            let end = self.searched + index;
            frames.push(String::from_utf8_lossy(&self.pending[consumed..end]).into_owned());
            consumed = end + 2;
            self.searched = consumed;
        }
        self.pending.drain(..consumed);
        self.searched = self.pending.len().saturating_sub(1);
        frames
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_transport_split_preserves_unicode_and_frame_order() {
        let input = "event: result\ndata: {\"text\":\"Grüße 🛡️\"}\n\nevent: finished\ndata: {}\n\n";
        let expected = input
            .split("\n\n")
            .filter(|frame| !frame.is_empty())
            .map(str::to_string)
            .collect::<Vec<_>>();
        for split in 0..=input.len() {
            let mut decoder = Frames::default();
            let mut frames = decoder.push(&input.as_bytes()[..split]);
            frames.extend(decoder.push(&input.as_bytes()[split..]));
            assert_eq!(frames, expected, "split at byte {split}");
        }
    }

    #[test]
    fn partial_tail_survives_completed_frames_and_one_byte_chunks() {
        let mut decoder = Frames::default();
        let input = b"event: one\n\nevent: two\n\npartial";
        let frames = input
            .iter()
            .flat_map(|byte| decoder.push(&[*byte]))
            .collect::<Vec<_>>();
        assert_eq!(frames, ["event: one", "event: two"]);
        assert_eq!(decoder.push(b"\n\n"), ["partial"]);
    }
}
