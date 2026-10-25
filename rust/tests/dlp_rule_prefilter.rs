// SPDX-License-Identifier: GPL-3.0-only
//! K07: the rule prefilter. Every DLP rule has a gate proven from its regex:
//! keywords that every match contains, or for a keywordless rule a run of
//! value characters. A rule without one fails here. The prefilter never
//! changes a result: on every golden and fixture text, and on texts built to
//! stress it, each rule finds exactly the matches of `Regex::captures_iter`.
//! Token values are synthetic and assembled at test time.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use patronus_ark::{
    detectors::dlp::{
        dlp::{DlpPattern, RuleMeta, ValidatorStrength, DLP_PATTERNS},
        prefilter::{
            has_short_probes, keyword_lead, keywords_are_required, required_value_run, rule_gate,
            RuleGate, RulePrefilter, ValueClass, ValueRun, FOLDS_TO_ASCII,
        },
    },
    golden_recipes::{materialize_fragments, GeneratorSet, SecretRecipe, SplitMix64},
};
use regex::Regex;
use serde::Deserialize;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn generators() -> GeneratorSet {
    GeneratorSet::load(repo_root().join("python/patronus_ark/dlp_synth/generators.json"))
        .expect("generator spec must load")
}

#[derive(Deserialize)]
struct GoldenRow {
    id: String,
    text: Option<String>,
    template: Option<String>,
    secrets: Option<Vec<SecretRecipe>>,
}

fn golden_texts(generators: &GeneratorSet) -> Vec<(String, String)> {
    std::fs::read_to_string(repo_root().join("python/patronus_ark/benchmark_data/dlp_l1.jsonl"))
        .expect("dlp_l1.jsonl must exist")
        .lines()
        .map(|line| serde_json::from_str::<GoldenRow>(line).expect("valid golden row"))
        .map(|row| {
            let text = match (row.text, row.template) {
                (Some(text), _) => text,
                (None, Some(template)) => {
                    materialize_fragments(generators, &template, &row.secrets.unwrap_or_default())
                        .expect("golden template must materialize")
                        .0
                }
                (None, None) => panic!("{}: neither text nor template", row.id),
            };
            (row.id, text)
        })
        .collect()
}

#[derive(Deserialize)]
struct FixtureCase {
    rule_id: String,
    de: String,
    en: String,
    #[serde(default)]
    secrets: Vec<SecretRecipe>,
    #[serde(default)]
    hard_negatives: BTreeMap<String, Vec<String>>,
}

fn fixture_texts(generators: &GeneratorSet) -> Vec<(String, String)> {
    let cases: Vec<FixtureCase> = serde_json::from_str(
        &std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../ark-core/tests/fixtures/l1_bilingual_rules.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let mut texts = Vec::new();
    for case in cases.iter().filter(|case| case.rule_id.starts_with("dlp_")) {
        for (language, template) in [("de", &case.de), ("en", &case.en)] {
            let text = if case.secrets.is_empty() {
                template.clone()
            } else {
                materialize_fragments(generators, template, &case.secrets)
                    .expect("fixture template must materialize")
                    .0
            };
            texts.push((format!("{}:{language}", case.rule_id), text));
        }
        for (language, negatives) in &case.hard_negatives {
            for (index, text) in negatives.iter().enumerate() {
                texts.push((
                    format!("{}:{language}:hn{index}", case.rule_id),
                    text.clone(),
                ));
            }
        }
    }
    texts
}

/// Byte ranges of every capture group of every match.
type Spans = Vec<Vec<Option<std::ops::Range<usize>>>>;

fn spans<'t>(captures: impl IntoIterator<Item = regex::Captures<'t>>) -> Spans {
    captures
        .into_iter()
        .map(|captures| {
            captures
                .iter()
                .map(|group| group.map(|m| m.range()))
                .collect()
        })
        .collect()
}

struct Rules {
    prefilter: RulePrefilter,
    regexes: Vec<Regex>,
}

impl Rules {
    fn new() -> Self {
        Self {
            prefilter: RulePrefilter::new(DLP_PATTERNS),
            regexes: DLP_PATTERNS
                .iter()
                .map(|rule| Regex::new(rule.pattern).unwrap())
                .collect(),
        }
    }

    /// Asserts that every rule finds the full-scan matches through the
    /// prefilter; returns how many rules were searched locally.
    fn assert_exact(&self, id: &str, text: &str) -> usize {
        let scan = self.prefilter.scan(text);
        let mut local = 0;
        for (index, regex) in self.regexes.iter().enumerate() {
            let full = spans(regex.captures_iter(text));
            let filtered = spans(self.prefilter.captures(index, regex, text, &scan));
            assert_eq!(
                filtered, full,
                "{}: prefilter changed the matches in {id}",
                DLP_PATTERNS[index].name
            );
            if !full.is_empty() {
                assert!(scan.is_active(index), "{}: {id}", DLP_PATTERNS[index].name);
            }
            local += usize::from(scan.is_local(index));
        }
        local
    }
}

fn rule(pattern: &'static str, keywords: &'static [&'static str]) -> DlpPattern {
    DlpPattern {
        name: "dlp_test_rule",
        pattern,
        entity_group: "API_KEY",
        validator: None,
        span_group: None,
        base_score: 50,
        meta: RuleMeta::new(ValidatorStrength::Format, "ark", keywords),
    }
}

/// Acceptance: a rule without keywords, or with keywords its regex does not
/// require, has no gate; the registry holds no such rule.
#[test]
fn every_rule_has_a_proven_prefilter() {
    let mut coverage = BTreeMap::<&str, Vec<&str>>::new();
    for rule in DLP_PATTERNS {
        let gate = rule_gate(rule);
        coverage.entry(gate.as_str()).or_default().push(rule.name);
        match gate {
            RuleGate::Keywords => assert!(!rule.meta.keywords.is_empty(), "{}", rule.name),
            RuleGate::Structural(run) => {
                assert!(
                    rule.meta.keywords.is_empty(),
                    "{}: keywords that the regex does not require",
                    rule.name
                );
                assert_eq!(rule.meta.value_run, Some(run), "{}", rule.name);
            }
            RuleGate::Ungated => panic!(
                "{}: no prefilter; declare keywords that every match contains \
                 (RuleMeta::keywords) or, without any literal, a value run \
                 (RuleMeta::with_value_run)",
                rule.name
            ),
        }
        if rule.meta.value_run.is_some() {
            assert!(
                rule.meta.keywords.is_empty(),
                "{}: a value run only for keywordless rules",
                rule.name
            );
        }
    }
    assert_eq!(
        coverage.values().map(Vec::len).sum::<usize>(),
        DLP_PATTERNS.len()
    );
    assert_eq!(
        coverage.get("structural"),
        Some(&vec!["dlp_discord_token", "dlp_btc_wif"]),
        "{coverage:?}"
    );
}

#[test]
fn new_rules_without_a_required_keyword_have_no_gate() {
    assert_eq!(rule_gate(&rule(r"[A-Z]{3}-\d{6}", &[])), RuleGate::Ungated);
    // The keyword names only one of two prefixes.
    assert_eq!(
        rule_gate(&rule(r"(?:sk|pk)-[a-z0-9]{32}", &["sk-"])),
        RuleGate::Ungated
    );
    // An optional keyword is no necessary condition.
    assert_eq!(
        rule_gate(&rule(r"(?:token=)?[a-f0-9]{40}", &["token="])),
        RuleGate::Ungated
    );
    // A keyword the regex does not contain at all.
    assert_eq!(
        rule_gate(&rule(r"tok_[a-z0-9]{32}", &["token"])),
        RuleGate::Ungated
    );
    assert_eq!(
        rule_gate(&rule(r"(?:sk|pk)-[a-z0-9]{32}", &["sk-", "pk-"])),
        RuleGate::Keywords
    );
    // A declared value run longer than the regex guarantees.
    let mut wif = rule(r"[KL][1-9A-HJ-NP-Za-km-z]{51}", &[]);
    wif.meta = wif.meta.with_value_run(ValueClass::Base58, 53);
    assert_eq!(rule_gate(&wif), RuleGate::Ungated);
    wif.meta = wif.meta.with_value_run(ValueClass::Base58, 52);
    assert_eq!(
        rule_gate(&wif),
        RuleGate::Structural(ValueRun {
            class: ValueClass::Base58,
            min_len: 52
        })
    );
}

#[test]
fn keyword_proof_vectors() {
    let valid: &[(&str, &[&str])] = &[
        (r"sk-ant-[a-zA-Z0-9\-_]{10,}", &["sk-ant-"]),
        (r"(?i)\bAuthorization\s*:\s*Bearer\s+(\S+)", &["bearer"]),
        (
            r"[sr]k[-_](live|test)[-_]\w{20,}",
            &["k_live", "k-live", "k_test", "k-test"],
        ),
        (r"(AKIA|ASIA)[A-Z0-9]{16}", &["akia", "asia"]),
        (r"(?:ey[a-z0-9]{10,}\.){2}[a-z0-9]{10,}", &["ey"]),
        (
            r"(?i)\b(?:api[ _-]?schl(?:ü|ue)ssel|secret)\b",
            &["api", "secret"],
        ),
        (
            r"(?i)Projekt[ -]?(?:ID|Nummer)|Project[ -]?ID",
            &["projekt", "project"],
        ),
    ];
    for (pattern, keywords) in valid {
        assert!(keywords_are_required(pattern, keywords), "{pattern}");
    }
    let invalid: &[(&str, &[&str])] = &[
        (r"[sr]k[-_](live|test)[-_]\w{20,}", &["k_live", "k_test"]),
        (r"(?:ghp|gho)_[A-Za-z0-9]{36}", &["ghp_"]),
        (r"(?:sk-)*[a-z]{10}", &["sk-"]),
        (r"(?i)\b(?:api|secret)\b", &["api"]),
        (r"(?i)geheimnis|sekret", &["geheimnis"]),
    ];
    for (pattern, keywords) in invalid {
        assert!(!keywords_are_required(pattern, keywords), "{pattern}");
    }
    assert!(FOLDS_TO_ASCII.contains(&('\u{17F}', 's')));
    assert!(FOLDS_TO_ASCII.contains(&('\u{212A}', 'k')));
}

#[test]
fn value_run_vectors() {
    let base58 = ValueClass::Base58;
    let alnum = ValueClass::Alphanumeric;
    assert_eq!(
        required_value_run(
            r"(?P<anchor_1>5[1-9A-HJ-NP-Za-km-z]{50}|[KL][1-9A-HJ-NP-Za-km-z]{51})",
            base58
        ),
        51
    );
    assert_eq!(
        required_value_run(
            r"[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9\-_]{6}\.[A-Za-z0-9\-_]{27,}",
            alnum
        ),
        24
    );
    // `0`, `O`, `I` and `l` are no Base58 characters.
    assert_eq!(required_value_run(r"[0-9a-f]{64}", base58), 0);
    assert_eq!(required_value_run(r"[1-9a-km-z]{64}", base58), 64);
    assert_eq!(required_value_run(r"[a-z]{4}-?[a-z]{9}", alnum), 9);
    assert_eq!(required_value_run(r"(?:[a-z]{3}\.){3}", alnum), 3);
    assert_eq!(
        required_value_run(r"(?i)[a-z]{30}", alnum),
        0,
        "KELVIN SIGN"
    );

    let run = |min_len| ValueRun {
        class: base58,
        min_len,
    };
    let text = ["--", &"a".repeat(50), "0", &"b".repeat(51), "--"].concat();
    assert!(run(51).occurs_in(&text));
    assert!(!run(52).occurs_in(&text));
    assert!(run(1).occurs_in("+a+"));
    assert!(!run(1).occurs_in("0OIl+"));
    assert!(!run(3).occurs_in("ab"));
}

#[test]
fn lead_and_probe_vectors() {
    assert_eq!(keyword_lead(r"sk-ant-[a-z]{10,}", &["sk-ant-"]), Some(0));
    assert_eq!(
        keyword_lead(
            r"(?i)\b(?:client[ _-]?secret|token)\s*=",
            &["secret", "token"]
        ),
        Some(7)
    );
    assert_eq!(keyword_lead(r"[a-z]{2,4}_secret", &["secret"]), Some(5));
    // Unbounded text before the keyword: no local search.
    assert_eq!(keyword_lead(r"[a-z]+_secret", &["secret"]), None);
    assert_eq!(keyword_lead(r"(?:secret)?", &["secret"]), None);
    assert!(has_short_probes(r"(?i)\bsecret\b\s*=\s*([^\s;]{8,150})"));
    assert!(has_short_probes(r"(?i)\bumsatz\b\s*\d+(?:[.\s]\d{3})*"));
    assert!(!has_short_probes(r"(?is)\bSELECT\b.*?\bFROM\b"));
    assert!(!has_short_probes(r"(?i)\bselect\b[^;\n]*;"));
}

/// The prefilter never changes a match on the goldens and the rule fixture.
#[test]
fn prefilter_is_exact_on_goldens_and_fixture() {
    let generators = generators();
    let rules = Rules::new();
    let mut texts = golden_texts(&generators);
    texts.extend(fixture_texts(&generators));
    assert!(texts.len() > 600, "{}", texts.len());
    let mut local = 0;
    for (id, text) in &texts {
        local += rules.assert_exact(id, text);
        // The same text upper-cased, after multi-byte text, and repeated.
        rules.assert_exact(&format!("{id}:upper"), &text.to_uppercase());
        rules.assert_exact(
            &format!("{id}:umlaut"),
            &format!("Grüße – Prüfung ✓\n{text}"),
        );
        rules.assert_exact(&format!("{id}:twice"), &format!("{text}{text}"));
    }
    assert!(
        local > texts.len(),
        "local search must be exercised: {local}"
    );
}

fn random_text(seed: u64, len: usize) -> String {
    const WORDS: &[&str] = &[
        "api",
        "key",
        "api_key",
        "API-Key",
        "token",
        "Token",
        "secret",
        "geheimnis",
        "schl",
        "Schlüssel",
        "API-Schlüssel",
        "client_secret",
        "access-token",
        "=",
        ":",
        " ",
        " ",
        "\n",
        "\t",
        "\"",
        "'",
        "ist",
        "is",
        "lautet",
        "Abc123xyz789QRS",
        "sk-",
        "sk-ant-",
        "ghp_",
        "0x",
        "ey",
        ".",
        "ä",
        "é",
        "€",
        "✓",
        "_",
        "-",
        "Kx9vQ2mLp7Rt",
        "passwort",
        "password",
        ";",
        "Authorization: Bearer ",
        "cookie",
        "csrf",
        "://",
        "@",
        "umsatz",
        "1.234",
        "EUR",
        "%",
    ];
    let mut rng = SplitMix64::new(seed);
    let mut text = String::new();
    while text.len() < len {
        text.push_str(WORDS[(rng.next_u64() % WORDS.len() as u64) as usize]);
    }
    text
}

/// Keyword-dense random texts: adjacent and overlapping matches, keywords
/// next to multi-byte characters, at the start and the end of the text.
#[test]
fn prefilter_is_exact_on_keyword_dense_texts() {
    let rules = Rules::new();
    let mut local = 0;
    for seed in 0..400 {
        let text = random_text(seed, 64 + (seed as usize % 7) * 200);
        local += rules.assert_exact(&format!("random {seed}"), &text);
    }
    assert!(local > 400, "local search must be exercised: {local}");
    for text in [
        "api_key=Abc123xyz789QRS",
        "api_key=Abc123xyz789QRSapi_key=Abc123xyz789QRS",
        "secret=Abc123xyz789QRS;token=Kx9vQ2mLp7RtKx9v",
        "äsecret=Abc123xyz789QRS",
        "éclient_secret = Abc123xyz789QRS",
        "client_secret\u{a0}=\u{a0}Abc123xyz789QRS",
        "x secret",
        "secret",
    ] {
        rules.assert_exact(text, text);
    }
}

/// `(?i)` regexes match LONG S and KELVIN SIGN for `s` and `k`; a text with
/// either runs every rule on the whole text.
#[test]
fn long_s_and_kelvin_sign_disable_the_prefilter() {
    let rules = Rules::new();
    for text in [
        "Das Pa\u{17F}\u{17F}wort lautet Kx9vQ2mLp7Rt",
        "api_\u{212A}ey=Abc123xyz789QRS",
        "\u{17F}ecret: Abc123xyz789QRS",
        "Temperatur 300 \u{212A}, kein Geheimnis",
    ] {
        let scan = rules.prefilter.scan(text);
        for (index, rule) in DLP_PATTERNS.iter().enumerate() {
            assert!(scan.is_active(index), "{}", rule.name);
            assert!(!scan.is_local(index), "{}", rule.name);
        }
        rules.assert_exact(text, text);
    }
    let password = DLP_PATTERNS
        .iter()
        .position(|rule| rule.name == "dlp_password_assignment")
        .unwrap();
    assert!(rules.regexes[password].is_match("Das Pa\u{17F}\u{17F}wort lautet Kx9vQ2mLp7Rt"));
}

/// A text without any keyword activates only rules whose value run occurs;
/// the structural gates open exactly at the run length.
#[test]
fn keywordless_rules_open_on_their_value_run() {
    let rules = Rules::new();
    let index = |name: &str| {
        DLP_PATTERNS
            .iter()
            .position(|rule| rule.name == name)
            .unwrap()
    };
    let (wif, discord) = (index("dlp_btc_wif"), index("dlp_discord_token"));
    let mut rng = SplitMix64::new(7);
    let base58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let body = |len: usize, rng: &mut SplitMix64| -> String {
        (0..len)
            .map(|_| base58.as_bytes()[(rng.next_u64() % base58.len() as u64) as usize] as char)
            .collect()
    };
    let short = format!("Wert: {} Ende", body(50, &mut rng));
    let scan = rules.prefilter.scan(&short);
    assert!(!scan.is_active(wif));
    assert!(scan.is_active(discord));
    let long = format!("Wert: K{} Ende", body(51, &mut rng));
    let scan = rules.prefilter.scan(&long);
    assert!(scan.is_active(wif));
    rules.assert_exact("wif", &long);
    let quiet = "Hallo Team, bitte lest die Liste bis Freitag.";
    let scan = rules.prefilter.scan(quiet);
    for (index, rule) in DLP_PATTERNS.iter().enumerate() {
        assert!(!scan.is_active(index), "{}", rule.name);
    }
}
