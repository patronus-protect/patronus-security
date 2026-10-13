//! Secret-safe DLP goldens: `dlp_l1.jsonl` stores secret values only as generator
//! recipes. These tests pin the Rust materialization to the Python generator
//! (96-bit SHA-256 fingerprint of the materialized text recorded at generation
//! time) and check that
//! the checked-in file itself carries no detectable secret.

use std::path::{Path, PathBuf};

use patronus_ark::{
    golden_recipes::{materialize, GeneratorSet, RecipeError, SecretRecipe, SplitMix64},
    SecurityCategory, SecurityGateway, SecurityLevel,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct Row {
    id: String,
    case_type: String,
    target_label: String,
    text: Option<String>,
    template: Option<String>,
    secrets: Option<Vec<SecretRecipe>>,
    text_fingerprint: Option<String>,
    entities: Vec<Entity>,
}

#[derive(Deserialize)]
struct Entity {
    start: usize,
    end: usize,
    secret: Option<usize>,
}

const SECRET_GROUPS: &[&str] = &[
    "API_KEY",
    "CLOUD_KEY",
    "CREDENTIAL",
    "CRYPTO_KEY",
    "PASSWORD_HASH",
    "PAYMENT_KEY",
    "PRIVATE_KEY",
    "SECRET_TOKEN",
];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn golden_path() -> PathBuf {
    repo_root().join("python/patronus_ark/benchmark_data/dlp_l1.jsonl")
}

fn generators() -> GeneratorSet {
    GeneratorSet::load(repo_root().join("python/patronus_ark/dlp_synth/generators.json"))
        .expect("generator spec must load")
}

fn rows() -> Vec<Row> {
    std::fs::read_to_string(golden_path())
        .expect("dlp_l1.jsonl must exist")
        .lines()
        .map(|line| serde_json::from_str(line).expect("valid golden row"))
        .collect()
}

/// First 24 hex digits of SHA-256, as recorded by `recipes.fingerprint`.
fn fingerprint(text: &str) -> String {
    ring::digest::digest(&ring::digest::SHA256, text.as_bytes()).as_ref()[..12]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[test]
fn splitmix64_matches_reference_vectors() {
    let mut rng = SplitMix64::new(1_234_567);
    let outputs = (0..5).map(|_| rng.next_u64()).collect::<Vec<_>>();
    assert_eq!(
        outputs,
        [
            6_457_827_717_110_365_317,
            3_203_168_211_198_807_973,
            9_817_491_932_198_370_423,
            4_593_380_528_125_082_431,
            16_408_922_859_458_223_821,
        ]
    );
    assert_eq!(SplitMix64::new(0).next_u64(), 0xE220_A839_7B1D_CDAF);
}

#[test]
fn generators_are_deterministic_and_fixed_length() {
    let generators = generators();
    assert!(!generators.names().is_empty());
    for name in generators.names() {
        let value = generators.generate(name, 7).expect("known generator");
        assert_eq!(value, generators.generate(name, 7).unwrap(), "{name}");
        assert_eq!(value.len(), generators.length(name).unwrap(), "{name}");
        assert!(value.is_ascii(), "{name}");
    }
    assert!(matches!(
        generators.generate("no_such_generator", 1),
        Err(RecipeError::UnknownGenerator(_))
    ));
}

#[test]
fn materialize_reports_code_point_spans_and_rejects_bad_templates() {
    let generators = generators();
    let recipes = vec![
        SecretRecipe::new("aws_access_key_id", 1),
        SecretRecipe::new("gitlab_pat", 2),
    ];
    let (text, spans) = materialize(
        &generators,
        "Schlüssel: <<secret:1>> / ä <<secret:0>>.",
        &recipes,
    )
    .unwrap();
    let first = generators.generate("aws_access_key_id", 1).unwrap();
    let second = generators.generate("gitlab_pat", 2).unwrap();
    assert_eq!(text, format!("Schlüssel: {second} / ä {first}."));
    let chars = text.chars().collect::<Vec<_>>();
    let slice = |(start, end): (usize, usize)| chars[start..end].iter().collect::<String>();
    assert_eq!(slice(spans[0]), first);
    assert_eq!(slice(spans[1]), second);
    assert_eq!(spans[1].0, "Schlüssel: ".chars().count());

    let one = vec![SecretRecipe::new("aws_access_key_id", 1)];
    for (template, recipes) in [
        ("no placeholder", one.clone()),
        ("<<secret:0>> <<secret:0>>", one.clone()),
        ("<<secret:1>>", one.clone()),
        ("<<secret:0>> <<secret:1>>", one.clone()),
        ("<<secret:00>>", one.clone()),
        ("<<secret:0>>", Vec::new()),
    ] {
        assert!(
            materialize(&generators, template, &recipes).is_err(),
            "{template}"
        );
    }
}

#[test]
fn recipe_rows_materialize_identically_to_the_python_generator() {
    let generators = generators();
    let mut recipe_rows = 0;
    for row in rows() {
        let secret_positive =
            row.case_type == "positive" && SECRET_GROUPS.contains(&row.target_label.as_str());
        let Some(template) = &row.template else {
            assert!(!secret_positive, "{}: secret value stored in clear", row.id);
            assert!(row.text.is_some(), "{}", row.id);
            continue;
        };
        assert!(row.text.is_none(), "{}", row.id);
        recipe_rows += 1;
        let recipes = row.secrets.as_deref().expect("recipe rows list secrets");
        let (text, spans) = materialize(&generators, template, recipes)
            .unwrap_or_else(|error| panic!("{}: {error}", row.id));
        assert_eq!(
            Some(fingerprint(&text)),
            row.text_fingerprint,
            "{}: Rust and Python materialization differ",
            row.id
        );
        for entity in &row.entities {
            let index = entity.secret.expect("recipe entities point to a secret");
            assert_eq!((entity.start, entity.end), spans[index], "{}", row.id);
        }
    }
    assert!(
        recipe_rows >= 24,
        "expected every secret positive as recipe"
    );
}

#[test]
fn checked_in_goldens_and_generator_spec_have_no_default_dlp_finding() {
    let gateway = SecurityGateway::with_max_level(
        vec![SecurityCategory::Dlp],
        SecurityLevel::L1,
        None,
        false,
    );
    let synth = repo_root().join("python/patronus_ark/dlp_synth");
    let spec = std::fs::read_to_string(synth.join("generators.json")).unwrap();
    let rules = std::fs::read_to_string(synth.join("rules.json")).unwrap();
    let raw = std::fs::read_to_string(golden_path()).unwrap();
    for (number, line) in [spec.as_str(), rules.as_str()]
        .into_iter()
        .chain(raw.lines())
        .enumerate()
    {
        let spans = gateway
            .scan_category(SecurityCategory::Dlp, line)
            .into_iter()
            .flat_map(|result| result.evidence_spans)
            .map(|span| (span.label, span.start_char, span.end_char))
            .collect::<Vec<_>>();
        // Inputs 0 and 1 are generators.json and rules.json, input n is line n - 1.
        assert!(spans.is_empty(), "input {number}: {spans:?}");
    }
}
