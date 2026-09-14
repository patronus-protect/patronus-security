use sha2::{Digest, Sha256};
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct TextChunk {
    pub id: String,
    pub index: usize,
    /// Parent UTF-8 byte range.
    pub start: usize,
    pub end: usize,
    /// Parent Unicode scalar-value range (not grapheme or byte indices).
    pub start_char: usize,
    pub end_char: usize,
    source: Arc<str>,
}
impl TextChunk {
    pub fn text(&self) -> &str {
        &self.source[self.start..self.end]
    }
}
#[derive(Clone)]
pub struct TextBatch {
    pub id: String,
    pub chunks: Vec<TextChunk>,
}
impl TextBatch {
    pub fn work_bytes(&self) -> usize {
        self.chunks.iter().map(|c| c.end - c.start).sum()
    }
}

pub fn split_text(parent: &str, text: Arc<str>, chunk_bytes: usize) -> Vec<TextChunk> {
    assert!(chunk_bytes >= 4);
    let mut result = Vec::new();
    let mut start = 0;
    let mut start_char = 0;
    while start < text.len() {
        let mut hard_end = (start + chunk_bytes).min(text.len());
        while !text.is_char_boundary(hard_end) {
            hard_end -= 1;
        }
        let mut end = hard_end;
        if hard_end < text.len() {
            // Prefer the last sentence boundary in the latter half of the byte
            // window, then whitespace. Unbroken text uses the exact UTF-8-safe
            // byte cap. There is no overlap: every original byte occurs once.
            let lower = start + (hard_end - start) / 2;
            let mut sentence = None;
            let mut whitespace = None;
            for (relative, ch) in text[start..hard_end].char_indices() {
                let after = start + relative + ch.len_utf8();
                if after < lower {
                    continue;
                }
                if ch.is_whitespace() {
                    whitespace = Some(after);
                }
                if ch == '\n'
                    || (matches!(ch, '.' | '!' | '?')
                        && text[after..]
                            .chars()
                            .next()
                            .is_some_and(char::is_whitespace))
                {
                    sentence = Some(after);
                }
            }
            end = sentence.or(whitespace).unwrap_or(hard_end);
        }
        let mut hash = Sha256::new();
        hash.update(b"ark-text-chunk-v1\0");
        hash.update(parent.as_bytes());
        hash.update(start.to_be_bytes());
        hash.update(end.to_be_bytes());
        hash.update(&text.as_bytes()[start..end]);
        let end_char = start_char + text[start..end].chars().count();
        result.push(TextChunk {
            id: format!("{:x}", hash.finalize()),
            index: result.len(),
            start,
            end,
            start_char,
            end_char,
            source: text.clone(),
        });
        start = end;
        start_char = end_char;
    }
    result
}
pub fn batch(parent: &str, chunks: &[TextChunk], offset: usize, count: usize) -> TextBatch {
    TextBatch {
        id: format!("{parent}-batch-{offset}"),
        chunks: chunks[offset..offset + count].to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn utf8_chunks_cover_original_once_and_batches_keep_offsets() {
        let text: Arc<str> = Arc::from("Hallo 🌍! Noch ein Satz. 日本語 ohne_spaces_äöü");
        let chunks = split_text("parent", text.clone(), 16);
        assert_eq!(
            chunks.iter().map(TextChunk::text).collect::<String>(),
            text.as_ref()
        );
        assert!(chunks.iter().all(|c| c.end - c.start <= 16
            && text.is_char_boundary(c.start)
            && text.is_char_boundary(c.end)));
        assert!(chunks.windows(2).all(|pair| pair[0].end == pair[1].start));
        let repeated = split_text("parent", text, 16);
        assert_eq!(
            chunks.iter().map(|c| &c.id).collect::<Vec<_>>(),
            repeated.iter().map(|c| &c.id).collect::<Vec<_>>()
        );
        assert_eq!(batch("parent", &chunks, 0, 2).work_bytes(), chunks[1].end);
    }
    #[test]
    fn boundaries_prefer_sentence_then_whitespace_with_utf8_fallback() {
        assert_eq!(
            split_text("p", Arc::from("abcde. fghijklmno"), 12)[0].text(),
            "abcde."
        );
        assert_eq!(
            split_text("p", Arc::from("abcdef ghijklmno"), 10)[0].text(),
            "abcdef "
        );
        assert_eq!(split_text("p", Arc::from("🌍🌍🌍"), 5)[0].text(), "🌍");
    }
}
