use std::collections::HashMap;

use crate::{EvaluationResult, LayerResult, ScanExecution, SecurityScanResult};

pub fn degraded_fallback_confidence(confidence: f64) -> f64 {
    (confidence * 0.5).min(0.5)
}

pub fn l3_pending_layer(result: &EvaluationResult, execution: &ScanExecution) -> LayerResult {
    LayerResult {
        level: "L3".to_string(),
        layer_type: "l3_pending".to_string(),
        class_name: result.class_name.clone(),
        confidence: 0.0,
        matched: false,
        duration_ms: 0.0,
        thresholds: HashMap::new(),
        details: HashMap::from([
            ("queued".to_string(), serde_json::json!(true)),
            (
                "fallback_level".to_string(),
                serde_json::json!(result.level.clone()),
            ),
            (
                "fallback_class".to_string(),
                serde_json::json!(result.class_name.clone()),
            ),
            (
                "fallback_confidence".to_string(),
                serde_json::json!(result.confidence),
            ),
            (
                "batch_mode".to_string(),
                serde_json::json!(execution.onnx_batch_mode().as_str()),
            ),
            (
                "backend".to_string(),
                serde_json::json!(execution.backend().as_str()),
            ),
        ]),
    }
}

pub fn has_l3_pending(result: &SecurityScanResult) -> bool {
    result
        .layers
        .iter()
        .any(|layer| layer.level == "L3" && layer.layer_type == "l3_pending")
}

pub fn degraded_timeout_result(
    mut result: SecurityScanResult,
    queued_ms: f64,
    ttl_ms: u64,
    degraded_factor: f64,
) -> SecurityScanResult {
    result.confidence = (result.confidence * degraded_factor).clamp(0.0, 1.0);
    for layer in &mut result.layers {
        if layer.level == result.level && layer.layer_type != "l3_pending" {
            layer.confidence = result.confidence;
            layer.matched = true;
            layer
                .details
                .insert("degraded".to_string(), serde_json::json!(true));
            layer.details.insert(
                "degraded_reason".to_string(),
                serde_json::json!("l3_timeout"),
            );
        }
    }
    result.layers.push(LayerResult {
        level: "L3".to_string(),
        layer_type: "degraded_timeout".to_string(),
        class_name: "timeout".to_string(),
        confidence: 0.0,
        matched: false,
        duration_ms: 0.0,
        thresholds: HashMap::new(),
        details: HashMap::from([
            (
                "fallback_due_to_timeout".to_string(),
                serde_json::json!(true),
            ),
            ("degraded".to_string(), serde_json::json!(true)),
            ("queued_ms".to_string(), serde_json::json!(queued_ms)),
            ("ttl_ms".to_string(), serde_json::json!(ttl_ms)),
            (
                "degraded_factor".to_string(),
                serde_json::json!(degraded_factor),
            ),
        ]),
    });
    result.duration_ms = result.layers.iter().map(|layer| layer.duration_ms).sum();
    result
}

pub fn degraded_error_result(
    mut result: SecurityScanResult,
    queued_ms: f64,
    ttl_ms: u64,
    degraded_factor: f64,
    error: String,
) -> SecurityScanResult {
    result.confidence = (result.confidence * degraded_factor).clamp(0.0, 1.0);
    for layer in &mut result.layers {
        if layer.level == result.level && layer.layer_type != "l3_pending" {
            layer.confidence = result.confidence;
            layer.matched = true;
            layer
                .details
                .insert("degraded".to_string(), serde_json::json!(true));
            layer
                .details
                .insert("degraded_reason".to_string(), serde_json::json!("l3_error"));
        }
    }
    result.layers.push(LayerResult {
        level: "L3".to_string(),
        layer_type: "degraded_error".to_string(),
        class_name: "error".to_string(),
        confidence: 0.0,
        matched: false,
        duration_ms: 0.0,
        thresholds: HashMap::new(),
        details: HashMap::from([
            ("fallback_due_to_error".to_string(), serde_json::json!(true)),
            ("degraded".to_string(), serde_json::json!(true)),
            ("error".to_string(), serde_json::json!(error)),
            ("queued_ms".to_string(), serde_json::json!(queued_ms)),
            ("ttl_ms".to_string(), serde_json::json!(ttl_ms)),
            (
                "degraded_factor".to_string(),
                serde_json::json!(degraded_factor),
            ),
        ]),
    });
    result.duration_ms = result.layers.iter().map(|layer| layer.duration_ms).sum();
    result
}

pub fn l3_metadata_layer(
    class_name: &str,
    model: &str,
    confidence: f64,
    duration_ms: f64,
) -> LayerResult {
    LayerResult {
        level: "L3".to_string(),
        layer_type: "onnx".to_string(),
        class_name: class_name.to_string(),
        confidence,
        matched: true,
        duration_ms,
        thresholds: HashMap::new(),
        details: HashMap::from([("model".to_string(), serde_json::json!(model))]),
    }
}
