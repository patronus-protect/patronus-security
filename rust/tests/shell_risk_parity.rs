//! Parity of the K26 shell-risk verdict pipeline with its Python reference.
//!
//! The reference rows come from `shellrisk parity-export` in the research
//! repository (deterministic; hashes in its `data/manifest.json`):
//!
//! - `fixtures/shell_risk_parity_ci.jsonl.gz`: 2,108 public rows (MIT,
//!   Apache-2.0, synthetic), always checked.
//! - `PATRONUS_SHELL_PARITY=<parity.jsonl.gz>`: the full 28,275-row file, not
//!   redistributable, checked locally.
//! - `fixtures/shell_risk_chains.jsonl`: 10 multi-step chains with `prior_facts`.
//!
//! `kf1` tokens, facts and fired policies need no model and are always
//! checked. Scores, decisions and the verdict need the released bundle:
//! `PATRONUS_SHELL_RISK_BUNDLE=<dir>` (model.json, config.json,
//! policy_levels.json, manifest.json); CI downloads the pinned one. Every
//! field must match on every row.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use patronus_ark::assets::download_shell_command_assets;
use patronus_ark::detectors::shell::{
    facts::{extract, Facts, ShellContext},
    kf1,
    policies::ShellPolicies,
    shell_risk::{ShellRiskPipeline, ShellVerdict},
    testing,
};
use serde_json::Value;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn rows(path: &Path) -> Vec<Value> {
    let file = std::fs::File::open(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let reader: Box<dyn std::io::Read> = if path.extension().is_some_and(|e| e == "gz") {
        Box::new(flate2::read::GzDecoder::new(file))
    } else {
        Box::new(file)
    };
    BufReader::new(reader)
        .lines()
        .map(|line| serde_json::from_str(&line.unwrap()).unwrap())
        .collect()
}

fn bundle_policies() -> ShellPolicies {
    let levels: HashMap<String, String> =
        serde_json::from_str(testing::POLICY_LEVELS_JSON).unwrap();
    ShellPolicies::from_levels(&levels).unwrap()
}

/// The released bundle: `PATRONUS_SHELL_RISK_BUNDLE`, or in CI (`CI` set) the
/// pinned `SHELL_COMMAND_ASSET` fetched once through ARK's asset download into
/// `PATRONUS_SHELL_RISK_CACHE` (default `target/shell_risk_bundle`). CI fails
/// instead of skipping the model fields when the bundle cannot be had.
fn bundle_dir() -> Option<PathBuf> {
    static BUNDLE: OnceLock<Option<PathBuf>> = OnceLock::new();
    BUNDLE
        .get_or_init(|| {
            if let Some(dir) = std::env::var_os("PATRONUS_SHELL_RISK_BUNDLE") {
                return Some(PathBuf::from(dir));
            }
            std::env::var_os("CI")?;
            let cache = std::env::var_os("PATRONUS_SHELL_RISK_CACHE")
                .map(PathBuf::from)
                .unwrap_or_else(|| {
                    Path::new(env!("CARGO_MANIFEST_DIR")).join("../target/shell_risk_bundle")
                });
            let dir = download_shell_command_assets(&cache).unwrap_or_else(|error| {
                panic!("CI needs the pinned shell-risk bundle for parity: {error}")
            });
            Some(dir)
        })
        .clone()
}

fn pipeline() -> Option<ShellRiskPipeline> {
    let dir = bundle_dir()?;
    Some(ShellRiskPipeline::from_bundle_dir(&dir).unwrap())
}

fn token_counts<'a>(tokens: impl IntoIterator<Item = &'a str>) -> BTreeMap<&'a str, usize> {
    let mut counts = BTreeMap::new();
    for token in tokens {
        *counts.entry(token).or_default() += 1;
    }
    counts
}

/// `[[id, decision, where...]]` as in the export.
fn policy_rows(hits: &[patronus_ark::detectors::shell::policies::PolicyHit]) -> Value {
    Value::Array(
        hits.iter()
            .map(|hit| {
                let mut row = vec![
                    Value::from(hit.id.clone()),
                    Value::from(hit.decision.as_str()),
                ];
                row.extend(hit.r#where.iter().cloned().map(Value::from));
                Value::Array(row)
            })
            .collect(),
    )
}

#[derive(Default)]
struct Mismatches {
    rows: usize,
    by_field: BTreeMap<&'static str, usize>,
    examples: Vec<String>,
}

impl Mismatches {
    fn check(
        &mut self,
        field: &'static str,
        row: &str,
        equal: bool,
        detail: impl FnOnce() -> String,
    ) {
        self.by_field.entry(field).or_default();
        if !equal {
            *self.by_field.get_mut(field).unwrap() += 1;
            if self.examples.len() < 12 {
                self.examples.push(format!("{row} {field}: {}", detail()));
            }
        }
    }

    fn assert_clean(&self, name: &str) {
        eprintln!(
            "{name}: {} rows, mismatches per field {:?}",
            self.rows, self.by_field
        );
        for example in &self.examples {
            eprintln!("  {example}");
        }
        assert!(
            self.by_field.values().all(|count| *count == 0),
            "{name}: parity mismatches {:?}",
            self.by_field
        );
    }
}

fn float_field(row: &Value, key: &str) -> f64 {
    row[key].as_str().unwrap().parse().unwrap()
}

fn check_verdict(
    m: &mut Mismatches,
    label: &str,
    row: &Value,
    verdict: &ShellVerdict,
    with_scores: bool,
) {
    let policies = policy_rows(&verdict.policies);
    m.check("policies", label, policies == row["policies"], || {
        format!("rust={policies} python={}", row["policies"])
    });
    if !with_scores {
        return;
    }
    let decision = verdict.decision.as_str();
    m.check("decision", label, decision == row["decision"], || {
        format!("rust={decision} python={}", row["decision"])
    });
    // The verdict without `model.top_features`, byte for byte.
    let mut rust = verdict.to_json(false);
    let mut python: Value = serde_json::from_str(row["verdict"].as_str().unwrap()).unwrap();
    let rust_top = rust["model"]["top_features"].take();
    let python_top = python["model"]["top_features"].take();
    m.check("verdict", label, rust == python, || {
        format!("rust={rust} python={python}")
    });
    m.check(
        "top_features",
        label,
        same_top_features(&rust_top, &python_top),
        || format!("rust={rust_top} python={python_top}"),
    );
}

/// Equal weights in the same order, and the same features per weight. The
/// reference orders equal weights by numpy's unstable argsort, the port by
/// feature name; a tie group cut by the top-5 limit is not comparable.
fn same_top_features(rust: &Value, python: &Value) -> bool {
    let groups = |top: &Value| {
        let mut groups: Vec<(f64, BTreeSet<String>)> = Vec::new();
        for feature in top.as_array().unwrap() {
            let weight = feature["weight"].as_f64().unwrap();
            let name = feature["feature"].as_str().unwrap().to_string();
            match groups.last_mut() {
                Some((w, names)) if *w == weight => {
                    names.insert(name);
                }
                _ => groups.push((weight, BTreeSet::from([name]))),
            }
        }
        groups
    };
    let (rust, python) = (groups(rust), groups(python));
    let weights =
        |g: &[(f64, BTreeSet<String>)]| g.iter().map(|(w, n)| (*w, n.len())).collect::<Vec<_>>();
    if weights(&rust) != weights(&python) {
        return false;
    }
    let complete = rust.len().saturating_sub(1);
    rust[..complete] == python[..complete]
}

fn check_rows(name: &str, path: &Path) {
    let policies = bundle_policies();
    let pipeline = pipeline();
    let mut m = Mismatches::default();
    for row in rows(path) {
        m.rows += 1;
        let text = row["text"].as_str().unwrap();
        let label = format!("row {}", row["id"]);

        let rust_tokens = kf1(text);
        let python_tokens: Vec<&str> = row["kf1"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t.as_str().unwrap())
            .collect();
        let (rust_counts, python_counts) = (
            token_counts(rust_tokens.iter().map(String::as_str)),
            token_counts(python_tokens.iter().copied()),
        );
        m.check("kf1", &label, rust_counts == python_counts, || {
            let missing: Vec<_> = python_counts
                .iter()
                .filter(|(t, c)| rust_counts.get(*t) != Some(c))
                .map(|(t, c)| format!("{t}x{c}"))
                .take(5)
                .collect();
            let extra: Vec<_> = rust_counts
                .iter()
                .filter(|(t, c)| python_counts.get(*t) != Some(c))
                .map(|(t, c)| format!("{t}x{c}"))
                .take(5)
                .collect();
            format!("python-only {missing:?} rust-only {extra:?}")
        });

        let facts = extract(text, None, &[]);
        let json = facts.canonical_json();
        m.check(
            "facts",
            &label,
            json == row["facts"].as_str().unwrap(),
            || format!("rust={json}\n    python={}", row["facts"].as_str().unwrap()),
        );

        match &pipeline {
            Some(pipeline) => {
                let verdict = pipeline.verdict(text, None, &[]).unwrap();
                let json = verdict.to_json(false);
                let score = json["model"]["score"].as_f64().unwrap();
                m.check(
                    "score",
                    &label,
                    (score - float_field(&row, "score")).abs() < 1e-9,
                    || format!("rust={} python={}", verdict.model_score, row["score"]),
                );
                let bundle = json["score"].as_f64().unwrap();
                m.check(
                    "bundle",
                    &label,
                    (bundle - float_field(&row, "bundle")).abs() < 1e-9,
                    || format!("rust={} python={}", verdict.score, row["bundle"]),
                );
                check_verdict(&mut m, &label, &row, &verdict, true);
            }
            None => {
                let (hits, _) = policies.evaluate(&facts, text).unwrap();
                let policies = policy_rows(&hits);
                m.check("policies", &label, policies == row["policies"], || {
                    format!("rust={policies} python={}", row["policies"])
                });
            }
        }
    }
    if pipeline.is_none() {
        eprintln!("{name}: scores and verdicts skipped; set PATRONUS_SHELL_RISK_BUNDLE");
    }
    m.assert_clean(name);
}

#[test]
fn public_parity_rows_match_the_python_reference() {
    check_rows("parity_ci", &fixture("shell_risk_parity_ci.jsonl.gz"));
}

/// The full, non-redistributable parity file, when available locally.
#[test]
fn full_parity_rows_match_the_python_reference() {
    let Some(path) = std::env::var_os("PATRONUS_SHELL_PARITY") else {
        eprintln!("skipping full shell-risk parity; set PATRONUS_SHELL_PARITY");
        return;
    };
    check_rows("parity", Path::new(&path));
}

#[test]
fn chains_with_prior_facts_match_the_python_reference() {
    let policies = bundle_policies();
    let pipeline = pipeline();
    let mut m = Mismatches::default();
    for chain in rows(&fixture("shell_risk_chains.jsonl")) {
        let ctx = &chain["context"];
        let context = ShellContext {
            cwd: ctx["cwd"].as_str().map(str::to_string),
            home: ctx["home"].as_str().map(str::to_string),
            repo_root: ctx["repo_root"].as_str().map(str::to_string),
            dialect: None,
        };
        let mut prior: Vec<Facts> = Vec::new();
        for (step, row) in chain["steps"].as_array().unwrap().iter().enumerate() {
            m.rows += 1;
            let label = format!("chain {} step {step}", chain["id"]);
            let command = row["command"].as_str().unwrap();
            let facts = extract(command, Some(&context), &prior);
            let json = facts.canonical_json();
            m.check(
                "facts",
                &label,
                json == row["facts"].as_str().unwrap(),
                || format!("rust={json}\n    python={}", row["facts"].as_str().unwrap()),
            );
            match &pipeline {
                Some(pipeline) => {
                    let verdict = pipeline.verdict(command, Some(&context), &prior).unwrap();
                    check_verdict(&mut m, &label, row, &verdict, true);
                }
                None => {
                    let (hits, _) = policies.evaluate(&facts, command).unwrap();
                    let policies = policy_rows(&hits);
                    m.check("policies", &label, policies == row["policies"], || {
                        format!("rust={policies} python={}", row["policies"])
                    });
                }
            }
            prior.push(facts);
        }
    }
    m.assert_clean("chains");
}
