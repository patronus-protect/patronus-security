use crate::cube::batching::TextChunk;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Default)]
pub struct TextLedger {
    chunks: BTreeMap<usize, (TextChunk, Value)>,
}
impl TextLedger {
    pub fn insert(&mut self, chunk: TextChunk, job: Value) -> Result<(), &'static str> {
        if self.chunks.contains_key(&chunk.index) {
            return Err("duplicate_chunk_result");
        }
        self.chunks.insert(chunk.index, (chunk, job));
        Ok(())
    }
    pub fn finish(
        self,
        id: &str,
        source: &str,
        expected: usize,
        elapsed_ms: f64,
        errors: Vec<String>,
        requested_categories: Option<&BTreeSet<String>>,
    ) -> Value {
        let timed_out = errors.iter().any(|code| code.contains("deadline"));
        let mut categories = Map::new();
        let mut next_global_chunk_id = 0u64;
        let mut failures: Vec<Value> = errors
            .into_iter()
            .map(|code| json!({"code":code}))
            .collect();
        let mut blocked = false;
        let mut expected_categories: Option<BTreeSet<String>> = None;
        let (mut queue_wait_ms, mut worker_submit_ms, mut worker_ms, mut l2_ms) =
            (0.0, 0.0, 0.0, 0.0);
        for (chunk, job) in self.chunks.values() {
            match job.get("decision").and_then(Value::as_str) {
                Some("block") => blocked = true,
                Some("allow") => (),
                _ => failures
                    .push(json!({"code":"cube_decision_unresolved","chunk_index":chunk.index})),
            }
            if job.get("status").and_then(Value::as_str) != Some("completed") {
                failures.push(json!({"code":"cube_job_incomplete","chunk_index":chunk.index}));
            }
            if let Some(values) = job
                .pointer("/completion/failures")
                .and_then(Value::as_array)
            {
                failures.extend(values.iter().cloned());
            }
            if job.pointer("/completion/state").and_then(Value::as_str) != Some("complete") {
                failures.push(json!({"code":"cube_completion_degraded","chunk_index":chunk.index}));
            }
            queue_wait_ms += timing(job, "queue_wait_ms");
            worker_submit_ms += timing(job, "worker_submit_ms");
            worker_ms += timing(job, "worker_ms");
            l2_ms += timing(job, "l2_ms");
            if let Some(values) = job.get("categories").and_then(Value::as_object) {
                let keys = values.keys().cloned().collect::<BTreeSet<_>>();
                if requested_categories.is_some_and(|requested| !requested.is_subset(&keys)) {
                    failures.push(
                        json!({"code":"incomplete_category_coverage","chunk_index":chunk.index}),
                    );
                }
                if expected_categories
                    .as_ref()
                    .is_some_and(|expected| expected != &keys)
                {
                    failures.push(
                        json!({"code":"incomplete_category_coverage","chunk_index":chunk.index}),
                    );
                }
                expected_categories.get_or_insert(keys);
                for (name, category) in values {
                    blocked |= category.get("accepted").and_then(Value::as_bool) == Some(true);
                    let mut corrected = category.clone();
                    shift_evidence(&mut corrected, chunk.start, chunk.start_char, false);
                    // Each Cube scan restarts local chunk numbering. Scope the
                    // remapping to this independent category result, while every
                    // repeated reference inside that result uses the same ID.
                    remap_chunk_ids(
                        &mut corrected,
                        &mut BTreeMap::new(),
                        &mut next_global_chunk_id,
                    );
                    match categories.get_mut(name) {
                        None => {
                            categories.insert(name.clone(), corrected);
                        }
                        Some(current) => merge_category(current, corrected),
                    }
                }
            } else {
                failures.push(json!({"code":"cube_categories_missing","chunk_index":chunk.index}));
            }
        }
        if self.chunks.len() != expected {
            failures.push(json!({"code":"incomplete_chunk_coverage"}));
        }
        let failed = self.chunks.is_empty() && !timed_out;
        let degraded = failed || !failures.is_empty();
        // This is aggregation of the Cube's public category decisions, not a
        // reconstruction of unavailable raw head logits. Full successful coverage
        // keeps the Cube decisions; partial/error coverage cannot become allow.
        let mut completion =
            json!({"state":if failed {"failed"} else if degraded {"degraded"} else {"complete"}});
        if !failures.is_empty() {
            completion["failures"] = json!(failures);
        }
        json!({"job_id":id,"source":source,"status":if failed {"failed"} else {"completed"},
            "worker":"coordinator","worker_request_id":id,"progress":{},"categories":categories,
            "completion":completion,"decision":if blocked {"block"} else if degraded {"review"} else {"allow"},
            "timings":{"queue_wait_ms":queue_wait_ms,"worker_submit_ms":worker_submit_ms,"worker_ms":worker_ms,"total_ms":elapsed_ms,"l2_ms":l2_ms,"l2_cache_hit":null}})
    }
}
fn timing(job: &Value, key: &str) -> f64 {
    job.get("timings")
        .and_then(|t| t.get(key))
        .and_then(Value::as_f64)
        .unwrap_or(0.0)
}
fn strength(value: &Value) -> (u8, u64) {
    let accepted = value
        .get("accepted")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let confidence = value
        .get("confidence")
        .and_then(Value::as_f64)
        .unwrap_or(0.0)
        .clamp(0.0, 1.0);
    (
        if accepted {
            2
        } else if !matches!(
            value.get("class_name").and_then(Value::as_str),
            Some("safe" | "benign")
        ) {
            1
        } else {
            0
        },
        (confidence * 1_000_000.0) as u64,
    )
}
fn merge_category(current: &mut Value, other: Value) {
    let duration = current
        .get("duration_ms")
        .and_then(Value::as_f64)
        .unwrap_or(0.0)
        + other
            .get("duration_ms")
            .and_then(Value::as_f64)
            .unwrap_or(0.0);
    let (mut chosen, remaining) = if strength(&other) > strength(current) {
        (other, current.clone())
    } else {
        (current.clone(), other)
    };
    // Metadata follows the strongest decision; evidence is a union of every
    // chunk's corrected lists, including nested decision-evidence structures.
    for key in ["evidence_spans", "decision_evidence"] {
        if let Some(extra) = remaining.get(key) {
            if let Some(base) = chosen.get_mut(key) {
                merge_evidence(base, extra);
            } else {
                chosen[key] = extra.clone();
            }
        }
    }
    if chosen.get("duration_ms").is_some() || remaining.get("duration_ms").is_some() {
        chosen["duration_ms"] = json!(duration);
    }
    *current = chosen;
}
fn merge_evidence(base: &mut Value, extra: &Value) {
    match (base, extra) {
        (Value::Array(values), Value::Array(more)) => {
            for value in more {
                if !values.contains(value) {
                    values.push(value.clone());
                }
            }
        }
        (Value::Object(values), Value::Object(more)) => {
            for (key, value) in more {
                if let Some(existing) = values.get_mut(key) {
                    merge_evidence(existing, value);
                } else {
                    values.insert(key.clone(), value.clone());
                }
            }
        }
        (base @ Value::Null, extra) => *base = extra.clone(),
        _ => (),
    }
}
fn remap_chunk_ids(value: &mut Value, ids: &mut BTreeMap<String, u64>, next: &mut u64) {
    fn remap(value: &mut Value, ids: &mut BTreeMap<String, u64>, next: &mut u64) {
        if value.is_null() {
            return;
        }
        let local = value.to_string();
        let global = ids.entry(local).or_insert_with(|| {
            let id = *next;
            *next += 1;
            id
        });
        *value = json!(*global);
    }
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if matches!(key.as_str(), "chunk_id" | "decisive_chunk_id") {
                    remap(child, ids, next);
                } else if matches!(key.as_str(), "chunk_ids" | "decisive_chunk_ids") {
                    if let Some(values) = child.as_array_mut() {
                        for value in values {
                            remap(value, ids, next);
                        }
                    }
                } else {
                    remap_chunk_ids(child, ids, next);
                }
            }
        }
        Value::Array(values) => {
            for child in values {
                remap_chunk_ids(child, ids, next);
            }
        }
        _ => (),
    }
}
fn shift_evidence(value: &mut Value, byte_offset: usize, char_offset: usize, span: bool) {
    match value {
        Value::Object(map) => {
            if span {
                for (keys, offset) in [
                    (&["start", "end", "start_byte", "end_byte"][..], byte_offset),
                    (&["start_char", "end_char"][..], char_offset),
                ] {
                    for key in keys {
                        if let Some(position) = map.get_mut(*key) {
                            if let Some(n) = position.as_u64() {
                                *position = json!(n.saturating_add(offset as u64));
                            }
                        }
                    }
                }
            }
            for (name, child) in map.iter_mut() {
                shift_evidence(
                    child,
                    byte_offset,
                    char_offset,
                    span || matches!(
                        name.as_str(),
                        "span" | "byte_span" | "evidence_spans" | "decision_evidence" | "spans"
                    ),
                );
            }
        }
        Value::Array(values) => {
            for child in values {
                shift_evidence(child, byte_offset, char_offset, span);
            }
        }
        _ => (),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::cube::batching::split_text;
    use std::sync::Arc;
    fn benign() -> Value {
        json!({"status":"completed","decision":"allow","completion":{"state":"complete"},"categories":{"threat":{"accepted":false,"class_name":"safe","confidence":0.99}},"timings":{"queue_wait_ms":5.0,"worker_submit_ms":10.0,"worker_ms":3.0,"l2_ms":2.0}})
    }
    #[test]
    fn single_chunk_is_parent_normalized_and_degraded_results_never_allow() {
        let chunk = split_text("parent", Arc::from("hello"), 4096)
            .into_iter()
            .next()
            .unwrap();
        let mut ledger = TextLedger::default();
        ledger
            .insert(
                chunk,
                json!({
                    "job_id":"cube-job",
                    "source":"chunk-0.txt",
                    "status":"completed",
                    "worker":"cube-worker",
                    "worker_request_id":"cube-request",
                    "decision":"allow",
                    "completion":{"state":"degraded"},
                    "categories":{"threat":{"accepted":false,"class_name":"safe","confidence":0.99}},
                    "timings":{}
                }),
            )
            .unwrap();
        let result = ledger.finish("parent", "input.txt", 1, 4.0, vec![], None);
        assert_eq!(result["job_id"], "parent");
        assert_eq!(result["source"], "input.txt");
        assert_eq!(result["worker"], "coordinator");
        assert_eq!(result["worker_request_id"], "parent");
        assert_eq!(result["completion"]["state"], "degraded");
        assert_eq!(result["decision"], "review");
    }

    #[test]
    fn explicitly_requested_categories_require_per_chunk_coverage() {
        let requested = ["injection".to_owned()].into_iter().collect();
        for categories in [Some(json!({})), None] {
            let chunk = split_text("parent", Arc::from("hello"), 4096)
                .into_iter()
                .next()
                .unwrap();
            let mut job = benign();
            match categories {
                Some(categories) => job["categories"] = categories,
                None => {
                    job.as_object_mut().unwrap().remove("categories");
                }
            }
            let mut ledger = TextLedger::default();
            ledger.insert(chunk, job).unwrap();
            let result = ledger.finish("parent", "input.txt", 1, 4.0, vec![], Some(&requested));
            assert_eq!(result["completion"]["state"], "degraded");
            assert_eq!(result["decision"], "review");
        }
    }
    #[test]
    fn complete_benign_text_over_four_kib_is_allow() {
        let chunks = split_text("p", Arc::from("a".repeat(9000)), 4096);
        let count = chunks.len();
        assert_eq!(count, 3);
        let mut ledger = TextLedger::default();
        for chunk in chunks {
            ledger.insert(chunk, benign()).unwrap();
        }
        let result = ledger.finish("p", "text", count, 20.0, vec![], None);
        assert_eq!(result["decision"], "allow");
        assert_eq!(result["completion"]["state"], "complete");
    }
    #[test]
    fn merge_preserves_evidence_from_both_risky_chunks_and_offsets() {
        let chunks = split_text("p", Arc::from("abcdefgh"), 4);
        let mut ledger = TextLedger::default();
        for (index, chunk) in chunks.into_iter().enumerate() {
            ledger.insert(chunk,json!({"status":"completed","decision":"block","completion":{"state":"complete"},"categories":{"threat":{"accepted":true,"confidence":if index==0 {0.99} else {0.7},"evidence_spans":[{"start":1,"end":3}],"decision_evidence":{"spans":[{"span":{"start":1,"end":3}}]}}}})).unwrap();
        }
        let result = ledger.finish("p", "text", 2, 12.0, vec![], None);
        assert_eq!(result["decision"], "block");
        assert_eq!(result["completion"]["state"], "complete");
        let spans = result["categories"]["threat"]["evidence_spans"]
            .as_array()
            .unwrap();
        assert_eq!(spans.len(), 2);
        assert!(spans.contains(&json!({"start":1,"end":3})));
        assert!(spans.contains(&json!({"start":5,"end":7})));
        assert_eq!(
            result["categories"]["threat"]["decision_evidence"]["spans"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
    }
    #[test]
    fn incomplete_coverage_never_allows() {
        let chunks = split_text("p", Arc::from("abcdefgh"), 4);
        let mut ledger = TextLedger::default();
        ledger.insert(chunks[0].clone(), benign()).unwrap();
        let result = ledger.finish("p", "text", 2, 0.0, vec![], None);
        assert_eq!(result["decision"], "review");
        assert_eq!(result["completion"]["state"], "degraded");
    }
    #[test]
    fn transport_timings_sum_work_while_total_is_parent_wall_time() {
        let chunks = split_text("p", Arc::from("abcdefgh"), 4);
        let mut ledger = TextLedger::default();
        for chunk in chunks {
            ledger.insert(chunk, benign()).unwrap();
        }
        let job = ledger.finish("p", "text", 2, 35.0, vec![], None);
        assert_eq!(job["timings"]["queue_wait_ms"], 10.0);
        assert_eq!(job["timings"]["worker_submit_ms"], 20.0);
        assert_eq!(job["timings"]["total_ms"], 35.0);
    }
    #[test]
    fn second_utf8_chunk_shifts_byte_and_character_positions_independently() {
        let text: Arc<str> = Arc::from("ä🌍öAB");
        let chunks = split_text("p", text.clone(), 6);
        assert_eq!((chunks[1].start, chunks[1].start_char), (6, 2));
        let mut ledger = TextLedger::default();
        ledger.insert(chunks[0].clone(), benign()).unwrap();
        let mut detected = benign();
        detected["decision"] = json!("block");
        detected["categories"]["threat"]["accepted"] = json!(true);
        detected["categories"]["threat"]["evidence_spans"] = json!([{
            "start":2,"end":3,"start_byte":2,"end_byte":3,"start_char":1,"end_char":2
        }]);
        ledger.insert(chunks[1].clone(), detected).unwrap();
        let result = ledger.finish("p", "text", 2, 1.0, vec![], None);
        let span = &result["categories"]["threat"]["evidence_spans"][0];
        let byte = text.find('A').unwrap();
        let character = text[..byte].chars().count();
        assert_eq!(span["start"], byte);
        assert_eq!(span["end"], byte + 1);
        assert_eq!(span["start_byte"], byte);
        assert_eq!(span["end_byte"], byte + 1);
        assert_eq!(span["start_char"], character);
        assert_eq!(span["end_char"], character + 1);
    }
    #[test]
    fn independent_local_chunk_ids_are_global_and_references_stay_consistent() {
        let chunks = split_text("p", Arc::from("abcdefgh"), 4);
        let mut ledger = TextLedger::default();
        for chunk in chunks {
            let mut result = benign();
            result["decision"] = json!("block");
            result["categories"]["threat"]["accepted"] = json!(true);
            result["categories"]["threat"]["decision_evidence"] = json!({
                "contributors":[{"chunk_id":0,"span":{"start":0,"end":1}}],
                "decisive_chunks":[{"chunk_id":0,"span":{"start":0,"end":1}}]
            });
            ledger.insert(chunk, result).unwrap();
        }
        let result = ledger.finish("p", "text", 2, 1.0, vec![], None);
        let evidence = &result["categories"]["threat"]["decision_evidence"];
        let contributors = evidence["contributors"].as_array().unwrap();
        let references = evidence["decisive_chunks"].as_array().unwrap();
        assert_eq!(contributors.len(), 2);
        assert_eq!(references.len(), 2);
        assert_ne!(contributors[0]["chunk_id"], contributors[1]["chunk_id"]);
        for reference in references {
            let row = contributors
                .iter()
                .find(|row| row["chunk_id"] == reference["chunk_id"])
                .unwrap();
            assert_eq!(row["span"], reference["span"]);
        }
        assert_eq!(contributors[0]["span"]["start"], 0);
        assert_eq!(contributors[1]["span"]["start"], 4);
    }
}
