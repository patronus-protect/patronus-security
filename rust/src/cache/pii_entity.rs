// SPDX-License-Identifier: GPL-3.0-only
use crate::EvidenceSpan;

pub(crate) fn merge_pii_spans(spans: Vec<EvidenceSpan>) -> Vec<EvidenceSpan> {
    let mut spans = spans;
    spans.sort_by(|left, right| {
        right.score.total_cmp(&left.score).then_with(|| {
            (right.end_byte - right.start_byte).cmp(&(left.end_byte - left.start_byte))
        })
    });
    let mut selected = Vec::new();
    for span in spans {
        if selected.iter().all(|existing: &EvidenceSpan| {
            existing.label != span.label
                || span.end_byte <= existing.start_byte
                || span.start_byte >= existing.end_byte
        }) {
            selected.push(span);
        }
    }
    selected.sort_by_key(|span| (span.start_byte, span.end_byte));
    selected
}

#[cfg(test)]
mod tests {
    use super::*;

    fn span(label: &str, text: &str, score: f64) -> EvidenceSpan {
        EvidenceSpan {
            label: label.to_string(),
            text: text.to_string(),
            score,
            start_byte: 0,
            end_byte: text.len(),
            start_char: 0,
            end_char: text.chars().count(),
        }
    }

    #[test]
    fn merging_keeps_overlapping_hypotheses_with_distinct_labels() {
        let spans = merge_pii_spans(vec![
            span("person", "Alexandr Stone", 0.91),
            span("legal_party", "Alexandr Stone", 0.85),
        ]);

        assert_eq!(spans.len(), 2);
        assert_eq!(spans[0].label, "person");
        assert_eq!(spans[1].label, "legal_party");
    }

    #[test]
    fn merging_keeps_highest_scoring_duplicate_across_inference_groups() {
        let spans = merge_pii_spans(vec![
            span("person", "Alexandr Stone", 0.72),
            span("person", "Alexandr Stone", 0.91),
        ]);

        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].label, "person");
        assert_eq!(spans[0].score, 0.91);
    }
}
