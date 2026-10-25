//! Keep repository research metadata aligned with the shared native table.
//! This repository-only check stays outside the independently packaged Core.
use patronus_ark::detectors::dlp::documented_reference_metadata;

#[test]
fn table_mirrors_research_documented_values_yaml() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../research/dlp/documented_values.yaml"
    );
    let yaml: serde_yaml::Value =
        serde_yaml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let metadata = documented_reference_metadata();
    let values = yaml["values"].as_sequence().unwrap();
    let documented = metadata["values"].as_array().unwrap();
    assert_eq!(values.len(), documented.len());
    for (entry, documented) in values.iter().zip(documented) {
        for field in ["id", "rule_id", "sha256", "kind"] {
            assert_eq!(
                entry[field].as_str(),
                documented[field].as_str(),
                "{}: {field}",
                documented["id"]
            );
        }
    }
    let claims = yaml["jwt_claims"].as_sequence().unwrap();
    let documented = metadata["jwt_claims"].as_array().unwrap();
    assert_eq!(claims.len(), documented.len());
    for (entry, documented) in claims.iter().zip(documented) {
        assert_eq!(entry["id"].as_str(), documented["id"].as_str());
        let listed = entry["claims"].as_mapping().unwrap();
        let expected = documented["claims"].as_object().unwrap();
        assert_eq!(listed.len(), expected.len(), "{}", documented["id"]);
        for (name, expected) in expected {
            let found = &listed[name.as_str()];
            if let Some(expected) = expected.as_str() {
                assert_eq!(found.as_str(), Some(expected), "{}", documented["id"]);
            } else {
                assert_eq!(found.as_i64(), expected.as_i64(), "{}", documented["id"]);
            }
        }
    }
}
