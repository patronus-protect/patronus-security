// SPDX-License-Identifier: MIT OR Apache-2.0
//! K07: rule prefilter. One Aho-Corasick pass over the text finds the prefilter
//! keywords (`RuleMeta::keywords`) of every rule at once; a rule none of whose
//! keywords occurs cannot match and its regex does not run. A rule without a
//! keyword has a structural prefilter instead: a run of value characters that
//! every match contains (`RuleMeta::value_run`).
//!
//! A gate only applies once it is proven from the rule's regex: every match
//! contains one of the keywords (ASCII case-insensitive), or a run of at least
//! `min_len` characters of the class. A rule without a proven gate always runs
//! and fails `rust/tests/dlp_rule_prefilter.rs`.
//!
//! Where every match starts at most `lead` bytes before a keyword, the rule
//! does not scan the whole text either: its matches are searched only at the
//! positions up to `lead` bytes before its keyword hits, in text order, with
//! the same leftmost-first result as `Regex::captures_iter`.
//!
//! A rule that scans the whole text and has a Unicode word boundary searches
//! a text with non-ASCII characters without its word boundaries, which keeps
//! the lazy DFA off the slow NFA, and probes each start anchored with its own
//! regex (H03-2, as the PII rules since H03).
use aho_corasick::{AhoCorasick, AhoCorasickBuilder, AhoCorasickKind, MatchKind};
use regex::{Captures, Regex};
use regex_automata::{meta, Anchored, Input};
use regex_syntax::hir::{Class, Hir, HirKind};
use std::{collections::BTreeSet, sync::OnceLock};

use super::dlp::DlpPattern;
use crate::detectors::word_boundary::{leftmost_start, without_unicode_word_boundaries};

/// Characters outside ASCII that case-insensitive regexes fold onto an ASCII
/// letter: `(?i)s` matches LATIN SMALL LETTER LONG S, `(?i)k` the KELVIN SIGN.
/// ASCII case-insensitive keyword search does not see them, so a text that
/// contains one runs every rule on the whole text.
pub const FOLDS_TO_ASCII: &[(char, char)] = &[('\u{17F}', 's'), ('\u{212A}', 'k')];

/// Most strings an exact sub-pattern may spell before the proof gives up.
const MAX_SPELLINGS: usize = 256;
/// Most code points of a class that the proof spells out.
const MAX_CLASS_CHARS: usize = 16;
/// Longest lead before a keyword for which a rule searches near its keywords.
const MAX_LEAD: usize = 64;
/// Lazy-DFA cache of a rule regex (the `regex` default is 2 MiB). The large
/// case-insensitive rules (`dlp_cli_password`, `dlp_prose_secret`,
/// `dlp_jwk_private_key`) outgrow the default on 100 KiB texts; the cache is
/// then cleared again and again and the search falls back to the NFA, up to
/// 100 times slower. The cache grows only as far as a search needs it.
pub const RULE_DFA_CACHE_BYTES: usize = 16 << 20;
/// A rule scans the whole text once its keyword windows would cover more than
/// 1/`LOCAL_DENSITY` of it.
const LOCAL_DENSITY: usize = 8;
/// Most printable ASCII characters (of 94) of a class under an unbounded
/// repetition of a rule that is searched near its keywords. A wider class
/// (`(?s).*?`, `[^;\n]*`) lets a probe that fails run on to the end of the
/// text or line; token alphabets, digits and whitespace stay below.
const MAX_OPEN_CLASS: usize = 80;

/// ASCII character classes of structural prefilters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValueClass {
    /// `[A-Za-z0-9]`.
    Alphanumeric,
    /// The Bitcoin Base58 alphabet (`[1-9A-HJ-NP-Za-km-z]`).
    Base58,
    /// `[0-9]`.
    Digit,
}

impl ValueClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Alphanumeric => "alphanumeric",
            Self::Digit => "digit",
            Self::Base58 => "base58",
        }
    }

    pub const fn contains(self, byte: u8) -> bool {
        match self {
            Self::Alphanumeric => byte.is_ascii_alphanumeric(),
            Self::Digit => byte.is_ascii_digit(),
            Self::Base58 => {
                byte.is_ascii_alphanumeric() && !matches!(byte, b'0' | b'O' | b'I' | b'l')
            }
        }
    }

    fn contains_char(self, c: char) -> bool {
        c.is_ascii() && self.contains(c as u8)
    }

    /// The longest run of class characters in `text`.
    pub fn longest_run(self, text: &str) -> usize {
        text.as_bytes()
            .split(|&byte| !self.contains(byte))
            .map(<[u8]>::len)
            .max()
            .unwrap_or(0)
    }
}

/// A run of at least `min_len` characters of `class` that every match contains.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValueRun {
    pub class: ValueClass,
    pub min_len: usize,
}

impl ValueRun {
    /// Whether `text` holds such a run. Checks each window from its end, so a
    /// byte outside the class skips every window that contains it.
    pub fn occurs_in(self, text: &str) -> bool {
        let bytes = text.as_bytes();
        let mut start = 0;
        while start + self.min_len <= bytes.len() {
            match (start..start + self.min_len)
                .rev()
                .find(|&index| !self.class.contains(bytes[index]))
            {
                None => return true,
                Some(outside) => start = outside + 1,
            }
        }
        false
    }
}

/// The prefilter of one rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleGate {
    /// Every match contains one of the rule's keywords.
    Keywords,
    /// Every match contains the value run.
    Structural(ValueRun),
    /// No proven necessary condition: the rule runs on every text.
    Ungated,
}

impl RuleGate {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Keywords => "keywords",
            Self::Structural(_) => "structural",
            Self::Ungated => "ungated",
        }
    }
}

/// The proven prefilter of `rule`: its keywords if they are necessary, else its
/// declared value run if that is necessary, else [`RuleGate::Ungated`].
pub fn rule_gate(rule: &DlpPattern) -> RuleGate {
    let Ok(hir) = regex_syntax::parse(rule.pattern) else {
        return RuleGate::Ungated;
    };
    let keywords = rule.meta.keywords;
    if !keywords.is_empty()
        && keywords.iter().all(|keyword| keyword.is_ascii())
        && keywords_required(&hir, keywords)
    {
        return RuleGate::Keywords;
    }
    match rule.meta.value_run {
        Some(run) if required_run(&hir, run.class).best >= run.min_len => RuleGate::Structural(run),
        _ => RuleGate::Ungated,
    }
}

/// Whether every match of `pattern` contains one of `keywords` (ASCII
/// case-insensitive, with [`FOLDS_TO_ASCII`] folded).
pub fn keywords_are_required(pattern: &str, keywords: &[&str]) -> bool {
    regex_syntax::parse(pattern).is_ok_and(|hir| keywords_required(&hir, keywords))
}

/// The most bytes by which a non-empty match of `pattern` can start before
/// its first keyword; `None` without such a bound.
pub fn keyword_lead(pattern: &str, keywords: &[&str]) -> Option<usize> {
    let hir = regex_syntax::parse(pattern).ok()?;
    if hir.properties().minimum_len().unwrap_or(0) == 0 {
        return None;
    }
    lead(&hir, keywords)
}

/// Whether a match attempt of `pattern` at one position stays short: every
/// unbounded repetition is over a narrow class (whitespace, a token alphabet).
pub fn has_short_probes(pattern: &str) -> bool {
    regex_syntax::parse(pattern).is_ok_and(|hir| short_probes(&hir))
}

fn short_probes(hir: &Hir) -> bool {
    match hir.kind() {
        HirKind::Empty | HirKind::Look(_) | HirKind::Literal(_) | HirKind::Class(_) => true,
        HirKind::Capture(capture) => short_probes(&capture.sub),
        HirKind::Concat(parts) | HirKind::Alternation(parts) => parts.iter().all(short_probes),
        HirKind::Repetition(repeat) => {
            let open = repeat.max.is_none_or(|max| max > 256);
            (!open || narrow(&repeat.sub)) && short_probes(&repeat.sub)
        }
    }
}

/// Whether every class in `hir` holds at most [`MAX_OPEN_CLASS`] printable
/// ASCII characters.
fn narrow(hir: &Hir) -> bool {
    match hir.kind() {
        HirKind::Empty | HirKind::Look(_) | HirKind::Literal(_) => true,
        HirKind::Class(Class::Unicode(class)) => {
            ('!'..='~')
                .filter(|&c| {
                    class
                        .ranges()
                        .iter()
                        .any(|range| range.start() <= c && c <= range.end())
                })
                .count()
                <= MAX_OPEN_CLASS
        }
        HirKind::Class(Class::Bytes(class)) => {
            (b'!'..=b'~')
                .filter(|&b| {
                    class
                        .ranges()
                        .iter()
                        .any(|range| range.start() <= b && b <= range.end())
                })
                .count()
                <= MAX_OPEN_CLASS
        }
        HirKind::Capture(capture) => narrow(&capture.sub),
        HirKind::Repetition(repeat) => narrow(&repeat.sub),
        HirKind::Concat(parts) | HirKind::Alternation(parts) => parts.iter().all(narrow),
    }
}

/// The longest run of `class` characters that every match of `pattern` contains.
pub fn required_value_run(pattern: &str, class: ValueClass) -> usize {
    regex_syntax::parse(pattern).map_or(0, |hir| required_run(&hir, class).best)
}

/// Searches a rule near its keywords.
struct Local {
    pattern: &'static str,
    /// The rule's regex for anchored probes, built on first use; the same
    /// syntax and semantics as the `regex::Regex` of the rule.
    anchored: OnceLock<meta::Regex>,
    lead: usize,
}

impl Local {
    fn anchored(&self) -> &meta::Regex {
        self.anchored.get_or_init(|| anchored_regex(self.pattern))
    }
}

/// The regex of a rule for anchored probes.
fn anchored_regex(pattern: &str) -> meta::Regex {
    meta::Builder::new()
        .configure(meta::Config::new().hybrid_cache_capacity(RULE_DFA_CACHE_BYTES))
        .build(pattern)
        .expect("valid DLP rule regex")
}

/// Searches a rule with a Unicode word boundary on a non-ASCII text: a
/// Unicode word boundary sends the lazy DFA to the NFA at the first non-ASCII
/// byte, for the rest of the text (about 0.5 s for the URL userinfo rules on a
/// 1.5 MiB minified bundle).
struct Relaxed {
    pattern: &'static str,
    /// The rule without its word boundaries and the rule for anchored probes,
    /// built on first use.
    regexes: OnceLock<(Regex, meta::Regex)>,
}

impl Relaxed {
    fn new(pattern: &'static str) -> Option<Self> {
        let hir = regex_syntax::parse(pattern).ok()?;
        (hir.properties().minimum_len().unwrap_or(0) > 0
            && without_unicode_word_boundaries(pattern).is_some())
        .then(|| Self {
            pattern,
            regexes: OnceLock::new(),
        })
    }

    /// The matches of the rule's `regex` in `text`, identical to
    /// `regex.captures_iter(text)` (matches are never empty).
    fn captures<'t>(&self, regex: &Regex, text: &'t str) -> Vec<Captures<'t>> {
        let (relaxed, anchored) = self.regexes.get_or_init(|| {
            let relaxed = without_unicode_word_boundaries(self.pattern)
                .expect("checked when the rule was set up");
            (
                regex::RegexBuilder::new(&relaxed)
                    .dfa_size_limit(RULE_DFA_CACHE_BYTES)
                    .build()
                    .expect("a pattern without assertions stays valid"),
                anchored_regex(self.pattern),
            )
        });
        let mut matches = Vec::new();
        let mut at = 0;
        while let Some(start) = leftmost_start(relaxed, anchored, text, at) {
            // The match starts here, so the leftmost one from here.
            let Some(captures) = regex.captures_at(text, start) else {
                break;
            };
            at = captures.get(0).map_or(text.len(), |matched| matched.end());
            matches.push(captures);
        }
        matches
    }
}

/// The prefilters of a rule set. Built once per pipeline.
pub struct RulePrefilter {
    matcher: AhoCorasick,
    /// Rules per keyword pattern of `matcher`.
    keyword_rules: Vec<Vec<usize>>,
    gates: Vec<RuleGate>,
    locals: Vec<Option<Local>>,
    relaxed: Vec<Option<Relaxed>>,
}

/// The prefilter result for one text.
pub struct RuleScan {
    active: Vec<bool>,
    /// Per rule searched near its keywords: the keyword hit offsets, ascending.
    hits: Vec<Option<Vec<usize>>>,
    /// Whether the text has a non-ASCII character.
    non_ascii: bool,
}

impl RuleScan {
    /// A scan that only gates rules: rule `i` may match if `active[i]`.
    pub fn from_active(active: Vec<bool>) -> Self {
        let hits = active.iter().map(|_| None).collect();
        Self {
            active,
            hits,
            non_ascii: false,
        }
    }

    /// Whether rule `index` may match. A rule marked `false` has no match.
    pub fn is_active(&self, index: usize) -> bool {
        self.active[index]
    }

    /// Whether rule `index` is searched near its keywords only.
    pub fn is_local(&self, index: usize) -> bool {
        self.hits[index].is_some()
    }
}

impl RulePrefilter {
    pub fn new(rules: &[DlpPattern]) -> Self {
        let gates: Vec<_> = rules.iter().map(rule_gate).collect();
        let mut keywords = Vec::<&str>::new();
        let mut keyword_rules = Vec::<Vec<usize>>::new();
        let mut locals = Vec::new();
        let mut relaxed = Vec::new();
        for (index, rule) in rules.iter().enumerate() {
            let gated = gates[index] == RuleGate::Keywords;
            locals.push(
                keyword_lead(rule.pattern, rule.meta.keywords)
                    .filter(|&lead| gated && lead <= MAX_LEAD && has_short_probes(rule.pattern))
                    .map(|lead| Local {
                        pattern: rule.pattern,
                        anchored: OnceLock::new(),
                        lead,
                    }),
            );
            relaxed.push(Relaxed::new(rule.pattern));
            if !gated {
                continue;
            }
            for keyword in rule.meta.keywords {
                let slot = keywords
                    .iter()
                    .position(|known| known == keyword)
                    .unwrap_or_else(|| {
                        keywords.push(keyword);
                        keyword_rules.push(Vec::new());
                        keywords.len() - 1
                    });
                keyword_rules[slot].push(index);
            }
        }
        let matcher = AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::Standard)
            .kind(Some(AhoCorasickKind::DFA))
            .build(&keywords)
            .expect("valid DLP keyword automaton");
        Self {
            matcher,
            keyword_rules,
            gates,
            locals,
            relaxed,
        }
    }

    /// Which rules may match `text`, and where the local rules' keywords are.
    pub fn scan(&self, text: &str) -> RuleScan {
        let rules = self.gates.len();
        let non_ascii = !text.is_ascii();
        if FOLDS_TO_ASCII
            .iter()
            .any(|&(folded, _)| text.contains(folded))
        {
            return RuleScan {
                active: vec![true; rules],
                hits: (0..rules).map(|_| None).collect(),
                non_ascii,
            };
        }
        let mut active: Vec<bool> = self
            .gates
            .iter()
            .map(|gate| match gate {
                RuleGate::Keywords => false,
                RuleGate::Structural(run) => run.occurs_in(text),
                RuleGate::Ungated => true,
            })
            .collect();
        let mut hits: Vec<Option<Vec<usize>>> = self
            .locals
            .iter()
            .map(|local| local.as_ref().map(|_| Vec::new()))
            .collect();
        for hit in self.matcher.find_overlapping_iter(text) {
            for &rule in &self.keyword_rules[hit.pattern().as_usize()] {
                active[rule] = true;
                if let Some(offsets) = &mut hits[rule] {
                    offsets.push(hit.start());
                }
            }
        }
        for (rule, offsets) in hits.iter_mut().enumerate() {
            let Some(found) = offsets else {
                continue;
            };
            let lead = self.locals[rule].as_ref().map_or(0, |local| local.lead);
            if found.len() * (lead + 1) * LOCAL_DENSITY > text.len() {
                *offsets = None;
            } else {
                found.sort_unstable();
                found.dedup();
            }
        }
        RuleScan {
            active,
            hits,
            non_ascii,
        }
    }

    /// The matches of rule `index` (`regex`) in `text`, identical to
    /// `regex.captures_iter(text)`. An inactive rule has none.
    pub fn captures<'t>(
        &self,
        index: usize,
        regex: &Regex,
        text: &'t str,
        scan: &RuleScan,
    ) -> Vec<Captures<'t>> {
        if !scan.active[index] {
            return Vec::new();
        }
        let (Some(local), Some(hits)) = (&self.locals[index], &scan.hits[index]) else {
            return match &self.relaxed[index] {
                Some(relaxed) if scan.non_ascii => relaxed.captures(regex, text),
                _ => regex.captures_iter(text).collect(),
            };
        };
        // Every match starts in a window [hit - lead, hit]. The windows are
        // tried in text order; after a match the search goes on at its end, as
        // in `captures_iter` (matches are never empty).
        let mut matches = Vec::new();
        let mut next = 0;
        for &hit in hits {
            let mut start = next.max(hit.saturating_sub(local.lead));
            while start <= hit {
                if text.is_char_boundary(start) {
                    let input = Input::new(text).range(start..).anchored(Anchored::Yes);
                    if let Some(found) = local.anchored().find(input) {
                        // The match starts here, so the leftmost one from here.
                        if let Some(captures) = regex.captures_at(text, start) {
                            let matched = captures.get(0).map(|m| m.range());
                            debug_assert_eq!(matched, Some(found.range()));
                            next = matched.map_or(found.end(), |range| range.end);
                            matches.push(captures);
                            start = next;
                            continue;
                        }
                    }
                }
                start += 1;
            }
            next = next.max(hit + 1);
        }
        matches
    }
}

/// The lowercase spelling the keyword search sees for a matched character.
fn fold(c: char) -> char {
    if let Some(&(_, ascii)) = FOLDS_TO_ASCII.iter().find(|(folded, _)| *folded == c) {
        ascii
    } else {
        // Other non-ASCII characters keep their spelling: keywords are ASCII,
        // so they never complete a keyword.
        c.to_ascii_lowercase()
    }
}

/// Every string a match of `hir` can spell (folded), if there are few.
fn spellings(hir: &Hir) -> Option<BTreeSet<String>> {
    match hir.kind() {
        HirKind::Empty | HirKind::Look(_) => Some(BTreeSet::from([String::new()])),
        HirKind::Literal(literal) => std::str::from_utf8(&literal.0)
            .ok()
            .map(|text| BTreeSet::from([text.chars().map(fold).collect()])),
        HirKind::Class(class) => {
            let mut chars = BTreeSet::new();
            match class {
                Class::Unicode(class) => {
                    for range in class.ranges() {
                        for code in range.start() as u32..=range.end() as u32 {
                            chars.insert(fold(char::from_u32(code)?));
                            if chars.len() > MAX_CLASS_CHARS {
                                return None;
                            }
                        }
                    }
                }
                Class::Bytes(class) => {
                    for range in class.ranges() {
                        for byte in range.start()..=range.end() {
                            if !byte.is_ascii() {
                                return None;
                            }
                            chars.insert(fold(byte as char));
                            if chars.len() > MAX_CLASS_CHARS {
                                return None;
                            }
                        }
                    }
                }
            }
            Some(chars.into_iter().map(String::from).collect())
        }
        HirKind::Capture(capture) => spellings(&capture.sub),
        HirKind::Concat(parts) => parts
            .iter()
            .try_fold(BTreeSet::from([String::new()]), |prefixes, part| {
                product(&prefixes, &spellings(part)?)
            }),
        HirKind::Alternation(branches) => {
            let mut all = BTreeSet::new();
            for branch in branches {
                all.extend(spellings(branch)?);
                if all.len() > MAX_SPELLINGS {
                    return None;
                }
            }
            Some(all)
        }
        HirKind::Repetition(repeat) if repeat.max.is_some_and(|max| max <= 8) => {
            let sub = spellings(&repeat.sub)?;
            let mut all = BTreeSet::new();
            let mut copies = BTreeSet::from([String::new()]);
            for count in 0..=repeat.max? {
                if count >= repeat.min {
                    all.extend(copies.iter().cloned());
                }
                if count < repeat.max? {
                    copies = product(&copies, &sub)?;
                }
            }
            (all.len() <= MAX_SPELLINGS).then_some(all)
        }
        HirKind::Repetition(_) => None,
    }
}

fn product(prefixes: &BTreeSet<String>, suffixes: &BTreeSet<String>) -> Option<BTreeSet<String>> {
    if prefixes.len() * suffixes.len() > MAX_SPELLINGS {
        return None;
    }
    Some(
        prefixes
            .iter()
            .flat_map(|prefix| {
                suffixes
                    .iter()
                    .map(move |suffix| format!("{prefix}{suffix}"))
            })
            .collect(),
    )
}

fn contains_keyword(spellings: &BTreeSet<String>, keywords: &[&str]) -> bool {
    spellings
        .iter()
        .all(|spelling| keywords.iter().any(|keyword| spelling.contains(keyword)))
}

/// Whether every match of `hir` contains one of `keywords`.
fn keywords_required(hir: &Hir, keywords: &[&str]) -> bool {
    if spellings(hir).is_some_and(|all| contains_keyword(&all, keywords)) {
        return true;
    }
    match hir.kind() {
        HirKind::Capture(capture) => keywords_required(&capture.sub, keywords),
        HirKind::Repetition(repeat) => repeat.min > 0 && keywords_required(&repeat.sub, keywords),
        HirKind::Alternation(branches) => branches
            .iter()
            .all(|branch| keywords_required(branch, keywords)),
        HirKind::Concat(parts) => {
            parts.iter().any(|part| keywords_required(part, keywords))
                // A keyword may span adjacent parts with few spellings.
                || (0..parts.len()).any(|start| {
                    let mut joined = BTreeSet::from([String::new()]);
                    for part in &parts[start..] {
                        let Some(next) = spellings(part).and_then(|next| product(&joined, &next))
                        else {
                            return false;
                        };
                        joined = next;
                        if contains_keyword(&joined, keywords) {
                            return true;
                        }
                    }
                    false
                })
        }
        _ => false,
    }
}

/// Offset of the first keyword in `spelling`.
fn first_keyword(spelling: &str, keywords: &[&str]) -> Option<usize> {
    keywords
        .iter()
        .filter_map(|keyword| spelling.find(keyword))
        .min()
}

/// The most bytes by which a match of `hir` can start before a keyword it
/// contains. Folded spellings keep the byte length of the text outside
/// [`FOLDS_TO_ASCII`], whose texts are never searched locally.
fn lead(hir: &Hir, keywords: &[&str]) -> Option<usize> {
    let spelled_lead = |all: &BTreeSet<String>| {
        all.iter()
            .map(|spelling| first_keyword(spelling, keywords))
            .try_fold(0, |most, offset| Some(most.max(offset?)))
    };
    if let Some(found) = spellings(hir).and_then(|all| spelled_lead(&all)) {
        return Some(found);
    }
    match hir.kind() {
        HirKind::Capture(capture) => lead(&capture.sub, keywords),
        HirKind::Repetition(repeat) if repeat.min > 0 => lead(&repeat.sub, keywords),
        HirKind::Alternation(branches) => branches
            .iter()
            .try_fold(0, |most, branch| Some(most.max(lead(branch, keywords)?))),
        HirKind::Concat(parts) => {
            // `before`: the longest text the parts before `start` can match.
            let mut before = 0;
            for (start, part) in parts.iter().enumerate() {
                if let Some(found) = lead(part, keywords) {
                    return Some(before + found);
                }
                let mut joined = BTreeSet::from([String::new()]);
                for next in &parts[start..] {
                    let Some(extended) = spellings(next).and_then(|all| product(&joined, &all))
                    else {
                        break;
                    };
                    joined = extended;
                    if let Some(found) = spelled_lead(&joined) {
                        return Some(before + found);
                    }
                }
                before += part.properties().maximum_len()?;
            }
            None
        }
        _ => None,
    }
}

/// Guaranteed runs of class characters in every match of a sub-pattern.
#[derive(Clone, Copy, Debug)]
struct Run {
    /// Every character of every match is in the class.
    full: bool,
    /// Shortest run at the start / end of a match (the match length if `full`).
    prefix: usize,
    suffix: usize,
    /// Longest run every match contains.
    best: usize,
}

impl Run {
    const fn full(len: usize) -> Self {
        Self {
            full: true,
            prefix: len,
            suffix: len,
            best: len,
        }
    }

    const BROKEN: Self = Self {
        full: false,
        prefix: 0,
        suffix: 0,
        best: 0,
    };

    fn then(self, next: Self) -> Self {
        match (self.full, next.full) {
            (true, true) => Self::full(self.prefix + next.prefix),
            (true, false) => Self {
                full: false,
                prefix: self.prefix + next.prefix,
                suffix: next.suffix,
                best: next.best.max(self.prefix + next.prefix),
            },
            (false, true) => Self {
                full: false,
                prefix: self.prefix,
                suffix: self.suffix + next.prefix,
                best: self.best.max(self.suffix + next.prefix),
            },
            (false, false) => Self {
                full: false,
                prefix: self.prefix,
                suffix: next.suffix,
                best: self.best.max(next.best).max(self.suffix + next.prefix),
            },
        }
    }
}

fn required_run(hir: &Hir, class: ValueClass) -> Run {
    match hir.kind() {
        HirKind::Empty | HirKind::Look(_) => Run::full(0),
        HirKind::Literal(literal) => std::str::from_utf8(&literal.0).map_or(Run::BROKEN, |text| {
            text.chars().fold(Run::full(0), |run, c| {
                run.then(if class.contains_char(c) {
                    Run::full(1)
                } else {
                    Run::BROKEN
                })
            })
        }),
        HirKind::Class(Class::Unicode(set)) => {
            let inside = set
                .ranges()
                .iter()
                .all(|range| (range.start()..=range.end()).all(|c| class.contains_char(c)));
            if inside {
                Run::full(1)
            } else {
                Run::BROKEN
            }
        }
        HirKind::Class(Class::Bytes(set)) => {
            let inside = set
                .ranges()
                .iter()
                .all(|range| (range.start()..=range.end()).all(|byte| class.contains(byte)));
            if inside {
                Run::full(1)
            } else {
                Run::BROKEN
            }
        }
        HirKind::Capture(capture) => required_run(&capture.sub, class),
        HirKind::Concat(parts) => parts.iter().fold(Run::full(0), |run, part| {
            run.then(required_run(part, class))
        }),
        HirKind::Alternation(branches) => branches
            .iter()
            .map(|branch| required_run(branch, class))
            .reduce(|a, b| {
                if a.full && b.full {
                    Run::full(a.prefix.min(b.prefix))
                } else {
                    Run {
                        full: false,
                        prefix: a.prefix.min(b.prefix),
                        suffix: a.suffix.min(b.suffix),
                        best: a.best.min(b.best),
                    }
                }
            })
            .unwrap_or(Run::BROKEN),
        HirKind::Repetition(repeat) => {
            let sub = required_run(&repeat.sub, class);
            let min = repeat.min as usize;
            if sub.full {
                Run::full(sub.prefix * min)
            } else if min == 0 {
                Run::BROKEN
            } else {
                // Repeated copies join the suffix of one to the prefix of the next.
                let joined = if min >= 2 { sub.suffix + sub.prefix } else { 0 };
                Run {
                    full: false,
                    prefix: sub.prefix,
                    suffix: sub.suffix,
                    best: sub.best.max(joined),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Whether the lazy DFA of `pattern` (configured as in `meta::Regex`)
    /// gives up on `text` with a cache of `capacity` bytes and falls back
    /// to the NFA.
    fn dfa_gives_up(pattern: &str, text: &str, capacity: usize) -> bool {
        use regex_automata::hybrid::dfa::DFA;
        let dfa = DFA::builder()
            .configure(
                DFA::config()
                    .cache_capacity(capacity)
                    .minimum_cache_clear_count(Some(3))
                    .minimum_bytes_per_state(Some(10)),
            )
            .build(pattern)
            .expect("valid DLP rule regex");
        let mut cache = dfa.create_cache();
        let mut input = Input::new(text);
        loop {
            match dfa.try_search_fwd(&mut cache, &input) {
                Err(_) => return true,
                Ok(None) => return false,
                Ok(Some(found)) => input.set_start(found.offset().max(input.start() + 1)),
            }
        }
    }

    #[test]
    fn word_boundary_rules_stay_on_the_dfa_in_non_ascii_bundles() {
        // H03-2: in a minified bundle with non-ASCII strings the Unicode `\b`
        // of the URL userinfo rules made the lazy DFA quit at the first `é`;
        // the rule without it stays on the DFA and finds the same matches (none
        // after `ü`, a word character).
        let rules = crate::detectors::dlp::dlp::DLP_PATTERNS;
        let prefilter = RulePrefilter::new(rules);
        let mut text = String::new();
        for line in 0..2_000 {
            text.push_str(&format!(
                "var s{line}=\"Résumé\",u{line}=\"https://cdn.example.org/a/{line}.js\";"
            ));
            if line % 500 == 7 {
                text.push_str(&format!(
                    "é_x=\"redis://user{line}:Kx9vQ2mLp7{line}@db.internal:6379\";"
                ));
                text.push_str(&format!(
                    "ühttps://Tok{line}abcdefgh:x-oauth-basic@github.com/o/r https://Tok{line}abcdefgh:x-oauth-basic@github.com/o/r "
                ));
            }
        }
        let scan = prefilter.scan(&text);
        // The password rule also reads `x-oauth-basic` as a password.
        for (name, found) in [
            ("dlp_url_userinfo_password", 8),
            ("dlp_url_userinfo_token", 4),
        ] {
            let index = rules.iter().position(|rule| rule.name == name).unwrap();
            let pattern = rules[index].pattern;
            assert!(prefilter.relaxed[index].is_some(), "{name}");
            let relaxed = without_unicode_word_boundaries(pattern).unwrap();
            assert!(
                !dfa_gives_up(&relaxed, &text, RULE_DFA_CACHE_BYTES),
                "{name}"
            );
            let regex = Regex::new(pattern).unwrap();
            let spans = |matches: Vec<Captures<'_>>| -> Vec<_> {
                matches
                    .iter()
                    .map(|captures| {
                        captures
                            .iter()
                            .map(|group| group.map(|m| m.range()))
                            .collect::<Vec<_>>()
                    })
                    .collect()
            };
            let expected = spans(regex.captures_iter(&text).collect());
            assert_eq!(expected.len(), found, "{name}");
            assert_eq!(
                spans(prefilter.captures(index, &regex, &text, &scan)),
                expected,
                "{name}"
            );
        }
    }

    #[test]
    fn rule_dfa_cache_holds_a_100_kib_command_log() {
        // H03: on 100 KiB of `curl` calls chained in one line the default
        // 2 MiB cache of `dlp_cli_password` thrashes (every `curl` opens a
        // window of up to 256 characters for its `-u`) and the search runs
        // on the NFA.
        let pattern = crate::detectors::dlp::dlp::DLP_PATTERNS
            .iter()
            .find(|rule| rule.name == "dlp_cli_password")
            .expect("rule exists")
            .pattern;
        let mut text = String::new();
        for call in 0..5_000 {
            text.push_str(&format!(
                "curl -sS -o out{call}.bin {} ",
                "x".repeat(call % 97)
            ));
        }
        text.truncate(100 * 1024);
        assert!(dfa_gives_up(pattern, &text, 2 << 20));
        assert!(!dfa_gives_up(pattern, &text, RULE_DFA_CACHE_BYTES));
    }

    #[test]
    fn longest_run_counts_ascii_class_characters_only() {
        assert_eq!(ValueClass::Digit.longest_run("Nr. 12 und 4567, ٣٤٥٦٧٨"), 4);
        assert_eq!(ValueClass::Digit.longest_run("keine Ziffern"), 0);
        assert_eq!(ValueClass::Alphanumeric.longest_run("ab1 ä xyz42"), 5);
        assert_eq!(
            required_value_run(
                r"(?-u:\b)[0-9]{3} [0-9]{3} [0-9]{3}(?-u:\b)",
                ValueClass::Digit
            ),
            3
        );
        assert_eq!(required_value_run(r"\d{9}", ValueClass::Digit), 0);
    }

    #[test]
    fn keywords_must_be_required_by_every_branch() {
        assert!(keywords_are_required(r"sk-ant-[a-z]{10,}", &["sk-ant-"]));
        assert!(keywords_are_required(r"(?i)\bapi[ _-]?key\b", &["api"]));
        assert!(keywords_are_required(
            r"[sr]k[-_](live|test)[-_]\w+",
            &["k_live", "k-live", "k_test", "k-test"]
        ));
        assert!(!keywords_are_required(
            r"[sr]k[-_](live|test)[-_]\w+",
            &["k_live", "k_test"]
        ));
        assert!(!keywords_are_required(r"(?:sk-|pk-)[a-z]{10}", &["sk-"]));
        assert!(!keywords_are_required(r"(?:sk-)?[a-z]{10}", &["sk-"]));
        assert!(!keywords_are_required(r"(?:sk-)*[a-z]{10}", &["sk-"]));
        assert!(keywords_are_required(r"(?:ey[a-z]{4}\.){2}", &["ey"]));
        assert!(keywords_are_required(
            r"(?i)\b(?:Projekt[ -]?(?:ID|Nummer)|Project[ -]?ID)\b",
            &["projekt", "project"]
        ));
        assert!(!keywords_are_required(
            r"(?i)\b(?:Projekt[ -]?ID|Project[ -]?ID)",
            &["projekt"]
        ));
    }

    #[test]
    fn long_s_and_kelvin_fold_onto_ascii() {
        assert_eq!(fold('\u{17F}'), 's');
        assert_eq!(fold('\u{212A}'), 'k');
        assert_eq!(fold('Ä'), 'Ä');
        assert!(keywords_are_required(r"(?i)secret", &["secret"]));
    }

    #[test]
    fn value_runs_are_lower_bounds() {
        let base58 = ValueClass::Base58;
        assert_eq!(
            required_value_run(
                r"5[1-9A-HJ-NP-Za-km-z]{50}|[KL][1-9A-HJ-NP-Za-km-z]{51}",
                base58
            ),
            51
        );
        assert_eq!(
            required_value_run(r"[MN][A-Za-z0-9]{23,}\.x", ValueClass::Alphanumeric),
            24
        );
        assert_eq!(
            required_value_run(r"[a-z]{5}-?[a-z]{5}", ValueClass::Alphanumeric),
            5
        );
        assert_eq!(
            required_value_run(r"(?:[a-z]{3}-){2}", ValueClass::Alphanumeric),
            3
        );
        assert_eq!(required_value_run(r"[a-z0O]{30}", base58), 0);
        assert!(ValueRun {
            class: base58,
            min_len: 3
        }
        .occurs_in("--abc--"));
        assert!(!ValueRun {
            class: base58,
            min_len: 3
        }
        .occurs_in("--a0c--"));
    }
}
