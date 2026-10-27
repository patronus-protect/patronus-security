use std::{fs, path::Path};

#[test]
fn core_owned_catalogs_declare_the_core_license_without_rewriting_provenance() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/detectors/injection/rules");
    for name in [
        "skillspector_0_1_7.json",
        "governance_attack_regressions_0_1_9.json",
        "source_derived_p0_0_1_6.json",
        "source_derived_coverage_0_1_6.json",
    ] {
        let catalog: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(base.join(name)).unwrap()).unwrap();
        assert_eq!(catalog["license"], "MIT OR Apache-2.0", "{name}");
        assert!(!catalog["rules"].as_array().unwrap().is_empty());
    }
    let upstream: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(base.join("prompt_armor_95e532e.json")).unwrap())
            .unwrap();
    assert_eq!(upstream["license"], "Apache-2.0");
    let derived: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(base.join("source_derived_coverage_0_1_6.json")).unwrap(),
    )
    .unwrap();
    assert!(derived["rules"]
        .as_array()
        .unwrap()
        .iter()
        .any(|rule| rule["source_license"] == "GPL-3.0-only"));
}
