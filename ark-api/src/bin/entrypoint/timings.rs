use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Default, Serialize, Deserialize)]
pub(super) struct JobTimings {
    pub queue_wait_ms: f64,
    pub worker_submit_ms: f64,
    pub worker_ms: Option<f64>,
    pub total_ms: Option<f64>,
    pub l2_ms: Option<f64>,
    pub l2_cache_hit: Option<bool>,
}

impl JobTimings {
    pub fn observe(&mut self, result: &Value) {
        for layer in result
            .get("layers")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if layer.get("layer_type").and_then(Value::as_str) != Some("ntdb_l2") {
                continue;
            }
            let Some(ms) = layer
                .get("duration_ms")
                .and_then(Value::as_f64)
                .filter(|ms| ms.is_finite() && *ms >= 0.0)
            else {
                continue;
            };
            // NTDB scores a text's L2 heads in one shared call and copies that
            // same duration onto each head. Never add these duplicate timings.
            self.l2_ms = Some(self.l2_ms.unwrap_or(0.0).max(ms));
            let cached = layer
                .pointer("/details/decision_cache_hit")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            self.l2_cache_hit = Some(self.l2_cache_hit.unwrap_or(true) && cached);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn l2_timing_survives_promotion_and_does_not_double_count_shared_heads() {
        let mut timing = JobTimings::default();
        let provisional = json!({"layers": [
            {"layer_type":"ntdb_l2", "duration_ms":12.5, "details":{"decision_cache_hit":false}},
            {"layer_type":"native_l1", "duration_ms":3.0}
        ]});
        timing.observe(&provisional);
        timing.observe(&provisional);
        timing.observe(&json!({"layers":[{"layer_type":"unified_l3", "duration_ms":200.0}]}));
        assert_eq!(timing.l2_ms, Some(12.5));
        assert_eq!(timing.l2_cache_hit, Some(false));
    }

    #[test]
    fn absent_l2_is_not_reported_as_zero_and_cache_hits_are_explicit() {
        let mut timing = JobTimings::default();
        timing.observe(&json!({"layers":[]}));
        assert_eq!(timing.l2_ms, None);
        timing.observe(
            &json!({"layers":[{"layer_type":"ntdb_l2", "duration_ms":0.0,
            "details":{"decision_cache_hit":true}}]}),
        );
        assert_eq!(timing.l2_ms, Some(0.0));
        assert_eq!(timing.l2_cache_hit, Some(true));
    }
}
