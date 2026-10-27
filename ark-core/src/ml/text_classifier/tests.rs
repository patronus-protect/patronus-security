use super::*;

#[test]
fn exact_sequence_classification_shapes_only() {
    assert!(logits_shape_matches(&[2, 3], 3, 2));
    assert!(logits_shape_matches(&[3], 3, 1));
    for shape in [&[2, 3][..], &[2, 1, 2], &[4], &[], &[1, 2]] {
        assert!(!logits_shape_matches(shape, 2, 2));
    }
    assert!(!logits_shape_matches(&[1, 0], 0, 1));
}

#[test]
fn row_decoding_rejects_truncation_and_nonfinite_values() {
    let rows = rows_from_logits([0.0, 1.0, 2.0, 3.0], 2, 2).unwrap();
    assert_eq!(rows, [vec![0.0, 1.0], vec![2.0, 3.0]]);
    assert!(rows_from_logits([0.0, 1.0, 2.0, 3.0, 4.0, 5.0], 2, 2).is_err());
    assert!(rows_from_logits([0.0], 2, 1).is_err());
    assert!(rows_from_logits([], 0, 1).is_err());
    assert!(rows_from_logits([], 2, 0).is_err());
    for bad in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
        assert!(rows_from_logits([0.0, bad], 2, 1).is_err());
    }
}

#[test]
fn checked_raw_decoding_is_additive_to_existing_methods() {
    let labels = vec!["benign".into(), "attack".into()];
    let output = RawClassifierOutput {
        logits: vec![0.0, 1.0],
    };
    let checked = output.try_decode(&labels).unwrap();
    let legacy = output.decode(&labels);
    assert_eq!(checked.class_name, legacy.class_name);
    assert_eq!(checked.confidence, legacy.confidence);
    assert_eq!(output.try_probabilities().unwrap(), output.probabilities());
    assert!(output.try_decode(&[]).is_err());
    assert!(output.try_decode(&labels[..1]).is_err());
    let bad = RawClassifierOutput {
        logits: vec![f32::NAN, 1.0],
    };
    assert!(bad.try_decode(&labels).is_err());
    assert!(bad.try_probabilities().is_err());
}
