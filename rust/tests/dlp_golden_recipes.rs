//! Secret-safe DLP goldens: `dlp_l1.jsonl` stores secret values only as generator
//! recipes. These tests pin the Rust materialization to the Python generator
//! (96-bit SHA-256 fingerprint of the materialized text recorded at generation
//! time) and check that
//! the checked-in file itself carries no detectable secret.

use std::path::{Path, PathBuf};

use patronus_ark::{
    detectors::dlp::dlp::DLP_PATTERNS,
    golden_recipes::{
        materialize, materialize_fragments, transform, Fragment, GeneratorSet, RecipeError,
        SecretRecipe, SplitMix64,
    },
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
    /// Scored DLP mode of the row (K04); rows without it run in `strict`.
    dlp_mode: Option<String>,
    rule_id: Option<String>,
}

#[derive(Deserialize)]
struct Entity {
    start: usize,
    end: usize,
    secret: Option<usize>,
    part: Option<usize>,
    encoding: Option<Vec<String>>,
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

/// Fingerprints of fill recipes (T06), shared with
/// python/tests/test_dlp_golden_recipes.py.
const FILL_VECTORS: &[(&str, u64, &str, &str)] = &[
    (
        "discord_bot_token",
        3,
        "BEISPIEL",
        "d11dbcce9d135339073d4b7b",
    ),
    ("jwt_signed_hs256", 4, "TEST", "b4882c1e8ceb557640c94fe5"),
    (
        "slack_user_token",
        5,
        "1234567890",
        "675ae1cdc899798059fe00cd",
    ),
    (
        "pem_pkcs8_ed25519_private_key",
        6,
        "EXAMPLEKEY",
        "bc01d602c9960964878238e1",
    ),
    (
        "github_ghp_token",
        7,
        "EXAMPLEKEY",
        "44968e27b5851e702074d3da",
    ),
    (
        "bearer_opaque_token",
        8,
        "DUMMY",
        "732f853eb396c222a69bfb5c",
    ),
];

#[test]
fn fill_recipes_match_the_python_vectors_and_keep_the_shape() {
    let generators = generators();
    for (name, seed, fill, expected) in FILL_VECTORS {
        let value = generators
            .generate_filled(name, *seed, Some(fill))
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(fingerprint(&value), *expected, "{name}");
    }
    // Values are assembled here from the word; the checksum is zeroed.
    let word = "EXAMPLEKEY";
    let value = generators
        .generate_filled("github_ghp_token", 7, Some(word))
        .unwrap();
    assert_eq!(value, format!("ghp_{}000000", &word.repeat(3)[..30]));
    let signature = generators
        .generate_filled("jwt_signed_hs256", 4, Some("TEST"))
        .unwrap();
    assert_eq!(
        signature.rsplit('.').next().unwrap(),
        &"TEST".repeat(11)[..43]
    );
    for name in generators.names() {
        for fill in ["EXAMPLEKEY", "deadbeef", "1234567890"] {
            let Ok(value) = generators.generate_filled(name, 3, Some(fill)) else {
                continue;
            };
            assert_eq!(value.len(), generators.length(name).unwrap(), "{name}");
        }
    }
    for (name, fill) in [
        ("github_ghp_token", ""),
        ("github_ghp_token", "EXAMPLE KEY"),
        ("github_ghp_token", "BEISPIEL-1"),
        ("github_ghp_token", "Müster"),
        ("md5_hex", "TESTKEY"),
        ("btc_wif_mainnet_compressed", "EXAMPLEKEY"),
    ] {
        assert!(
            generators.generate_filled(name, 1, Some(fill)).is_err(),
            "{name} {fill:?}"
        );
    }
    let (text, spans) = materialize(
        &generators,
        "k=<<secret:0>>",
        &[SecretRecipe::filled("gitlab_pat", 1, "TEST")],
    )
    .unwrap();
    assert_eq!(
        &text[spans[0].0..spans[0].1],
        generators
            .generate_filled("gitlab_pat", 1, Some("TEST"))
            .unwrap()
    );
}

#[test]
fn transforms_match_the_python_vectors() {
    // Same vectors as python/tests/test_dlp_golden_recipes.py.
    let value = "a/b c+d:\"e\"\\\n\t\u{1}~";
    assert_eq!(
        transform(value, "base64").unwrap(),
        "YS9iIGMrZDoiZSJcCgkBfg=="
    );
    assert_eq!(
        transform(value, "hex").unwrap(),
        "612f6220632b643a2265225c0a09017e"
    );
    assert_eq!(
        transform(value, "url").unwrap(),
        "a%2Fb%20c%2Bd%3A%22e%22%5C%0A%09%01~"
    );
    assert_eq!(
        transform(value, "json").unwrap(),
        "a/b c+d:\\\"e\\\"\\\\\\n\\t\\u0001~"
    );
    assert_eq!(transform("\u{8}\u{c}\r", "json").unwrap(), "\\b\\f\\r");
    assert!(transform(value, "rot13").is_err());
}

#[test]
fn encoded_and_split_placeholders_yield_fragments() {
    let generators = generators();
    let token = generators.generate("github_ghp_token", 3).unwrap();
    let (text, fragments) = materialize_fragments(
        &generators,
        "tok: <<secret:0|base64>>!",
        &[SecretRecipe::new("github_ghp_token", 3)],
    )
    .unwrap();
    let encoded = transform(&token, "base64").unwrap();
    assert_eq!(text, format!("tok: {encoded}!"));
    assert_eq!(
        fragments,
        [Fragment {
            secret: 0,
            part: 0,
            start: 5,
            end: 5 + encoded.len(),
            encoding: Some("base64".into()),
        }]
    );

    let recipes = vec![
        SecretRecipe::new("aws_access_key_id", 4),
        SecretRecipe::new("gitlab_pat", 5),
    ];
    let first = generators.generate("aws_access_key_id", 4).unwrap();
    let second = generators.generate("gitlab_pat", 5).unwrap();
    let template = "k = \"<<secret:0[0:4]>>\" + \"ä<<secret:1>>\" + \"<<secret:0[4:20]>>\"";
    let (text, fragments) = materialize_fragments(&generators, template, &recipes).unwrap();
    assert_eq!(
        text,
        format!(
            "k = \"{}\" + \"ä{second}\" + \"{}\"",
            &first[..4],
            &first[4..]
        )
    );
    let chars = text.chars().collect::<Vec<_>>();
    let slice = |fragment: &Fragment| {
        chars[fragment.start..fragment.end]
            .iter()
            .collect::<String>()
    };
    assert_eq!(
        fragments
            .iter()
            .map(|fragment| (fragment.secret, fragment.part))
            .collect::<Vec<_>>(),
        [(0, 0), (1, 0), (0, 1)]
    );
    assert_eq!(slice(&fragments[0]) + &slice(&fragments[2]), first);
    assert_eq!(slice(&fragments[1]), second);
    assert!(materialize(&generators, template, &recipes).is_err());

    let one = [SecretRecipe::new("aws_access_key_id", 1)];
    for template in [
        "<<secret:0|rot13>>",
        "<<secret:0|>>",
        "<<secret:0|BASE64>>",
        "<<secret:0|json>>",
        "<<secret:0[0:20]>>",
        "<<secret:0[0:4]>><<secret:0[5:20]>>",
        "<<secret:0[0:4]>><<secret:0[3:20]>>",
        "<<secret:0[4:20]>><<secret:0[0:4]>>",
        "<<secret:0[0:4]>><<secret:0[4:19]>>",
        "<<secret:0[0:4]>><<secret:0[4:21]>>",
        "<<secret:0[0:4]>><<secret:0>>",
        "<<secret:0[0:4]>><<secret:0[4:20]|hex>>",
        "<<secret:0[00:4]>><<secret:0[4:20]>>",
        "<<secret:0[0:0]>><<secret:0[0:20]>>",
        "<<secret:0|hex>> <<secret:0|hex>>",
    ] {
        assert!(
            materialize_fragments(&generators, template, &one).is_err(),
            "{template}"
        );
    }
}

/// T01: every placeholder of `template` continues a word, `+` or `/` run.
fn is_glued(template: &str) -> bool {
    let mut placeholders = template.match_indices("<<secret:").peekable();
    placeholders.peek().is_some()
        && placeholders.all(|(index, _)| {
            template[..index]
                .bytes()
                .last()
                .is_some_and(|byte| byte.is_ascii_alphanumeric() || b"_+/".contains(&byte))
        })
}

/// F01: whether `rule_id` reports a value only in its key context.
/// F03: generators in a rule's shape with a wrong check value or length (`lookalike` in
/// `dlp_synth/rules.json`). They are no secret, so hard negatives hold them as plain recipes.
fn lookalike_generators() -> Vec<String> {
    let raw = std::fs::read_to_string(repo_root().join("python/patronus_ark/dlp_synth/rules.json"))
        .expect("rules.json must exist");
    let map: serde_json::Value = serde_json::from_str(&raw).expect("valid rules.json");
    map["rules"]
        .as_object()
        .expect("rules object")
        .values()
        .filter_map(|entry| entry["lookalike"].as_array())
        .flatten()
        .map(|name| name.as_str().expect("generator name").to_owned())
        .collect()
}

fn is_context_gated(rule_id: Option<&str>) -> bool {
    rule_id.is_some_and(|rule_id| {
        DLP_PATTERNS
            .iter()
            .any(|pattern| pattern.name == rule_id && pattern.meta.context_gate.is_some())
    })
}

#[test]
fn recipe_rows_materialize_identically_to_the_python_generator() {
    let generators = generators();
    let lookalikes = lookalike_generators();
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
        let (text, fragments) = materialize_fragments(&generators, template, recipes)
            .unwrap_or_else(|error| panic!("{}: {error}", row.id));
        assert_eq!(
            Some(fingerprint(&text)),
            row.text_fingerprint,
            "{}: Rust and Python materialization differ",
            row.id
        );
        if row.case_type == "hard_negative" {
            // T06: example/test values in a provider format are fill recipes. A
            // hard negative of a scored mode (K04) is a generated value whose
            // context marks it as no secret; it is no example value. So is a
            // value glued into a longer run (T01), which is no whole token. A
            // context-gated rule (F01) may have either: an example value or a
            // generated value without key context. A lookalike value (F03) has a
            // wrong check value or length and is no secret either.
            assert!(row.entities.is_empty(), "{}", row.id);
            if is_context_gated(row.rule_id.as_deref()) {
                continue;
            }
            let plain = row.dlp_mode.as_deref().is_some_and(|mode| mode != "strict")
                || is_glued(template)
                || recipes
                    .iter()
                    .all(|recipe| lookalikes.contains(&recipe.gen));
            assert!(
                recipes.iter().all(|recipe| recipe.fill.is_some() != plain),
                "{}: strict hard negatives use fill recipes, scored and glued ones plain recipes",
                row.id
            );
            continue;
        }
        assert!(
            recipes.iter().all(|recipe| recipe.fill.is_none()),
            "{}",
            row.id
        );
        assert_eq!(row.entities.len(), fragments.len(), "{}", row.id);
        for (entity, fragment) in row.entities.iter().zip(&fragments) {
            let split = fragments
                .iter()
                .any(|other| other.secret == fragment.secret && other.part > 0);
            assert_eq!(
                (entity.start, entity.end, entity.secret),
                (fragment.start, fragment.end, Some(fragment.secret)),
                "{}",
                row.id
            );
            assert_eq!(entity.part, split.then_some(fragment.part), "{}", row.id);
            assert_eq!(
                entity.encoding,
                fragment.encoding.clone().map(|encoding| vec![encoding]),
                "{}",
                row.id
            );
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
