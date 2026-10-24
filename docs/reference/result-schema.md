# Result schema

What the async queue (`enqueue` + `consume_next_event`) and the blocking `scan_*` helpers
return. Python names are shown; the Rust types (`SecurityScanResult`, `LayerResult`,
`EvaluationResult`, `QueuedSecurityEvent`, `SecurityFailure`) are in the
[Rust API reference](../rust-api.md).

## Scan result

A single result — the `result` field of a queue `result` event, or one element of the list the
blocking `scan_*` helpers return — is a **dictionary describing one category's verdict**:

```python
[
    {
        "category": "dlp",
        "class_name": "safe",
        "confidence": 1.0,
        "level": "L1",
        "model": "native:dlp",
        "duration_ms": 0.4,
        "evidence_spans": [],
        "label_scores": [],
        "layers": [
            {
                "level": "L1",
                "layer_type": "native",
                "class_name": "safe",
                "confidence": 1.0,
                "matched": True,
                "duration_ms": 0.4,
                "thresholds": {},
                "details": {},
            }
        ],
    }
]
```

| Field | Type | Meaning |
| --- | --- | --- |
| `category` | str | The scan category this result belongs to. |
| `class_name` | str | Winning class (a category-specific label, or `safe`). |
| `confidence` | float | Confidence in `class_name`, `0.0`–`1.0`. |
| `level` | str | The level that produced the winning verdict: `L1`, `L2`, or `L3`. |
| `model` | str | The producing scanner, e.g. `native:dlp`, `external:<id>`, or a model id. |
| `duration_ms` | float | Wall-clock time spent producing this result. |
| `decision` | dict | Structured classifier decision envelope for terminal model-backed classifier results. Python omits this key when no authoritative classifier decision exists; Rust exposes `SecurityScanResult.decision: Option<DecisionEnvelope>`. |
| `evidence_spans` | list | Exact matched spans from span-producing native scanners and dynamic PII; empty for safe/model-only results. |
| `label_scores` | list | Per-label scores for multi-label heads (e.g. `tool_tags`); each entry is `{label, confidence, matched}`. Empty for single-label results. |
| `layers` | list | Per-layer breakdown of everything that ran for this category. |

### Layer entry

Each element of `layers` records one layer's output:

| Field | Type | Meaning |
| --- | --- | --- |
| `level` | str | `L1` / `L2` / `L3`. |
| `layer_type` | str | e.g. `native`, or the model layer type. |
| `class_name` | str | This layer's class. |
| `confidence` | float | This layer's confidence. |
| `matched` | bool | Whether this layer produced a positive match. |
| `duration_ms` | float | Wall-clock time spent in this layer. |
| `thresholds` | dict | Thresholds applied at this layer (operating point, etc.). |
| `details` | dict | Layer-specific extra detail. Native PII/DLP layers can expose non-blocking `l1_anchors`; NTDB L2 layers add L3 promotion context; L3 layers add chunk execution metadata. The stable policy contract is `decision`, not free-form `details`. |

### Decision envelope

Model-backed classifier pipelines (`injection`, `threat`, `routing`, `sensitive_document`,
`tool_class`, `tool_action`, and `tool_tags`) apply the configured final-decision threshold profile
after raw L2/L3 scoring. The top-level `class_name` / `confidence` is the accepted final verdict.
When no candidate passes its threshold, the result falls back to the pipeline default class
(`benign`, `unknown`, `other`, etc.) and uses the model's default-class confidence when available,
or `0.0` otherwise.

Terminal classifier results expose that policy input and Ark's calibrated recommendation under
`decision`. `decision.is_some()` is the lifecycle marker for an authoritative classifier policy
input. Early L2 results that still contain an `l3_pending` layer, provisional events, progress
events, and result-preview events leave `decision` unset (`None` in Rust) even when they carry
classifier-looking scores.

```python
{
    "schema_version": "ark.decision.v1",
    "final_result": {"class_name": "benign", "confidence": 0.0, "source": "default"},
    "decision_candidate": {
        "source": "l2",
        "class_name": "instruction_override",
        "confidence": 0.5640919208526611,
        "acceptance_threshold": 0.86471,
        "accepted": False,
        "evidence": None,
    },
    "recommendation": {
        "accepted": False,
        "final_arbitration": "default",
        "operating_point": "best_f1",
        "acceptance_threshold": 0.86471,
    },
    "candidates": [
        {
            "source": "l2",
            "class_name": "instruction_override",
            "confidence": 0.5640919208526611,
            "acceptance_threshold": 0.86471,
            "accepted": False,
            "evidence": None,
        }
    ],
    "terminality": {"completion": "complete", "degraded": False, "degradation_reason": None},
    "provenance": {
        "ark_version": "0.1.7",
        "schema_version": "ark.decision.v1",
        "model": "unified-v3-threat",
    },
}
```

| Field | Type | Meaning |
| --- | --- | --- |
| `schema_version` | str | Decision-envelope schema version. Currently `ark.decision.v1`. |
| `final_result` | dict | The final Ark verdict after threshold arbitration: `{class_name, confidence, source}`. |
| `decision_candidate` | dict \| null | Canonical policy input. It is the selected accepted or rejected candidate from L1/L2/L3/Union arbitration. `None` when no valid candidate exists. |
| `recommendation` | dict | Ark's calibrated default recommendation. `accepted` is false only for `final_arbitration: "default"`. |
| `candidates` | list | All typed L1, L2, L3, and Union candidates available to arbitration. |
| `terminality` | dict | Completion state for the result: `completion`, `degraded`, and optional `degradation_reason`. |
| `provenance` | dict | Minimal source provenance: `ark_version`, `schema_version`, and `model`. |

Candidate entries have this shape:

| Field | Type | Meaning |
| --- | --- | --- |
| `source` | str | `l1`, `l2`, `l3`, or `union`. `final_result.source` may also be `default`. |
| `class_name` | str | Candidate class before downstream Patronus policy. |
| `confidence` | float | Candidate confidence from that source. |
| `acceptance_threshold` | float | Ark's calibrated acceptance threshold for this candidate's source/class/operating point. |
| `accepted` | bool | Whether this candidate passed Ark's calibrated acceptance threshold. |
| `evidence` | dict \| null | Extra candidate evidence. Union candidates include `l2_weight`, `l3_weight`, `l2_confidence`, and `l3_confidence`. |

Example: if Threat L2 predicts `instruction_override` at `0.5640919`, but the selected threshold
profile requires a higher L2 confidence, the top-level result is the default `benign` class while
`decision.decision_candidate` retains the rejected `l2` candidate with
`acceptance_threshold: 0.86471` and `decision.recommendation.accepted: False`.

`label_scores[].matched` is layer-local model output metadata. It is not threshold acceptance and
must not be treated as equivalent to `decision.recommendation.accepted` or
`decision.candidates[].accepted`.

Candidate confidences are calibrated for Ark's bundled threshold profiles. Treat them in the
context of their `category`, `source`, `model`, and `operating_point`; do not compare scores across
unrelated sources or model versions without their matching thresholds.

### Native L1 components

Built-in L1 matchers emit components directly from regex captures, lexical/structural
relationships, or decoded payloads. PII and DLP expose them under
`layers[].details.matched_rules[].components`, alongside the rule ID and finding range.
Components include `component_id`, `explanation`, `start_byte`, `end_byte`, and
`span_precision`. Contextual identifiers retain an anchor prefix/suffix and the validated
value. Injection's candidate features retain a complete `rule_match` plus its `anchor`
components; structural producer features retain their `structural` kind. Anchor decomposition
does not multiply the completed rule's scoring weight.

`exact` refers to original-text offsets, including mapped Unicode normalization.
`transformed_source` identifies the source container of a decoded payload when a narrower
character mapping is unavailable; the explanation identifies the decoded match.

### Evidence spans

Native PII, all built-in DLP producers, accepted native Injection findings, and
`dynamic-pii` entities populate `evidence_spans` with original-text offsets:

```python
for span in result["evidence_spans"]:
    print(span["label"], span["text"], span["score"], span["start_byte"], span["end_byte"])
```

Each span carries the matched `label`, the matched `text`, a `score`, and both **byte** and
**character** offsets (`start_byte`/`end_byte`/`start_char`/`end_char`). Safe native results
leave `evidence_spans` empty.

PII spans with different labels may overlap: each matching class is retained, including a
numeric IBAN substring that also passes the credit-card validator. The primary `class_name`
does not enumerate every match; consume `evidence_spans` for all detected classes. Overlapping
matches within the same PII label are deduplicated.

DLP secret spans (credential and secret groups) never overlap (K08). Where several secret
rules match one value, one span stays:

1. A span of the same tier that only adds quotes or a trailing `;`/`,` to a tighter span gives
   way to it (`'value'` of `dlp_env_var_secret` against `value` of the assignment rule).
2. A substring artefact gives way to the value it lies in: a fixed-format match strictly inside a
   longer fixed-format value of another rule (a WIF-shaped Base58 run inside a Stripe key or a
   JWT), or a match of a rule without keywords strictly inside a longer secret value.
3. Then the tier decides: provider and key-material formats > platform-format tokens (JWT,
   bearer, CSRF, session cookie, URL signature) > password hashes > structural credentials (URL
   userinfo and parameters, Basic auth) > generic assignments (`dlp_env_var_secret`,
   `dlp_password_assignment`, `dlp_generic_credential_assignment`); within a tier the stronger
   validator, then the registry order.

A generic key that is the userinfo of a URL (`https://token:…@host`) belongs to the URL
credential and is no assignment of its own. A suppressed match stays in `matched_rules` and names
the rule it gave way to in `suppressed_by`. Identifier and content classes keep overlapping spans
(the first match per label).

When one request scans DLP and PII on the same text, a DLP secret span owns its range: PII L1
spans that overlap it (a URL password read as the local part of an e-mail address, token digits
read as a card number) are dropped from the PII `evidence_spans`. The PII result's `class_name`
and `confidence` stay as scanned, and a PII-only scan is unchanged.

### PII score and modes

The PII `score` depends on the PII mode, an opt-in execution gate (Rust
`ScanGateMatrix.pii_mode`, Python `execution_gates={"pii_mode": "balanced"}`, Ark API
`gates: {pii_mode: balanced}`). Unknown mode names are rejected.

| Mode | `evidence_spans[].score` | Threshold | `confidence` |
| --- | --- | --- | --- |
| `strict` (default) | always `1.0` | none: the rules decide | `1.0` |
| `balanced` | model score | findings below `0.50` are dropped | highest span score |
| `recall` | model score | findings below `0.30` are dropped | highest span score |

The model score of a finding is the sum of three parts, capped at 100 and divided by 100:

- **Base** (1–100 points) of the rule: how specific its pattern is on its own.
- **Validator strength**: `checksum` +35 (Luhn, ISO 7064 MOD 97-10, Steuer-ID check digit),
  `format` +15 (length, alphabet, ranges, dates, prefixes), `none` +0 (no validator).
- **Context**: +25 when the rule binds the value to a field name such as `IBAN:` or
  `Steuer-ID`. Otherwise the context engine looks at both sides of the value, on the same line,
  for a term of the DE/EN lexicon in `rust/src/detectors/anchor_lexicons/pii.json` that belongs
  to the label (`Telefon`, `erreichbar`, `call me at`, `Kreditkarte`, `IBAN`, `client IP` …):
  +25 up to 16 characters away, +20 up to 32, +15 up to 48 before or 32 after the value.
  A counter-context term (order, invoice, tracking, ticket, reference or serial number:
  `Bestellnummer`, `Rechnungsnummer`, `Sendungsnummer`, `invoice no`, `transaction ID` …) that
  is strictly nearer than every support term subtracts 30 instead. A term does not count across
  a line break, a digit (the value of another field) or `;`/`|`; after the value it also does
  not count behind `,`, `:`, `=` or `#`, or when it is followed by `:`, `=`, `#` or a digit,
  because then it names the next value. The
  [L1 rule catalog](l1-rule-catalog.md#pii-context-lexicon) lists the lexicon entries per label.

**Structure (K04).** A key names the value it holds like a field name right before it: a JSON
or Python-dict key (`"kundennummer": "KD-1"`, `customerId`), a `key: value` or `key=value` line
(YAML, INI, forms), an XML element or attribute (`<bic>…</bic>`, `<customer id="…"/>`, qualified by
the parent element), a CSV header (`;`, `,`, tab or `|` separated, two or more lines with the same
number of cells) and the header row or key cell of a Markdown or HTML table. Keys are compared
lowercased with `_`, `-`, `.` and camelCase boundaries as spaces. In every mode, including
`strict`, a key binds the value to a rule that names a field (`captured_value`) only if that
rule accepts the key as its own field name and the value matches its value form in full; the
validator and the rule's extra checks decide as for a regex match, so `Arztnummer`, `Kennung`
or an `order_id` column bind nothing. Such a finding's `matched_rules` entry carries
`structure` (`json`, `kv`, `xml`, `csv` or `table`) and the components `structure_key` and
`value`. For rules without a field name, a key that names exactly the value is its context
instead of proximity: a key of the label scores +25 (`anchor` is the lexicon entry, `side` is
`key`), a counter-context key such as a `Bestellnummer` column subtracts 30, and a context-bound
rule takes its required context from it. A number inside a longer value (`Phone: (987)
012-3456`) is not the value its key names.

**Obfuscation (K06).** Values hidden behind characters that leave them readable are found in a
normalized view of the text and reported with their original span (byte and character offsets
of the text as sent, including the hidden characters). In every mode, including `strict`, the
scanner removes zero-width characters (U+200B–U+200D, U+2060, U+FEFF, soft hyphen) between two
characters of a value, maps full-width forms to ASCII (`０３０ １２３４５６７８`, `ada.wong＠northwind.com`;
a run counts if it contains a full-width letter or digit, or is a full-width separator between
ASCII letters or digits) and undoes defanged separators between ASCII letters or digits
(`203[.]0[.]113[.]5`, `ops(@)example{.}com`, `[:]`). Zero-width joiners in emoji and lone
full-width punctuation in CJK text stay. In `recall` only, the scanner also undoes spelled-out
e-mail separators (`ada [at] northwind [dot] com`, `max punkt mustermann ät firma punkt de`,
`info @ firma . de`; without brackets or `@` the local part needs `.`, `_`, `-`, a digit or a dot
word and the domain a common top-level domain, so `docs at example dot com` stays prose) and
numbers spaced character by character (`D E 8 9 3 7 …`, at least eight characters, six of them
digits); such findings score 10 points less than the plain form. `strict` and `balanced` keep
these forms negative (gold convention T01). Rules and validators run on the normalized value, so
a wrong check digit stays unreported. A finding that needed normalization replaces a same-label
finding it contains and yields to any other; its `matched_rules` entry carries original offsets
and `obfuscation` (`zero_width`, `full_width`, `defanged`, `spelled_out`, `spaced_digits`).

**Cross-label overlaps (K07).** Number labels compete for the same digits: the BBAN of an IBAN can
be a valid card number, and an account field can hold an IBAN or a card-shaped number. Since B-PAN
a card needs Luhn plus the IIN prefix and a length of its brand and never starts right after `+`,
so phone digits no longer compete as a card. In `balanced` and `recall` one value yields one label among `IBAN`,
`CREDITCARD`, `FINANCIAL_ACCOUNT_NUMBER`, `STEUERID`, `PHONE`, `VAT_ID_IT`, `VAT_ID_FR`, `VAT_ID_HR`
and `VAT_ID_LT` (a bare Partita IVA and the digits of a spaced French or Croatian VAT ID have 11
digits like a Steuer-ID, B01/B02; the twelve digits of a Lithuanian one can be card-shaped, B02).
Of two overlapping findings
with different labels the first criterion that differs decides: an IBAN (`iban`), the longer
value (`longer_value`: a card-shaped part of a longer value), context that supports the finding's
own label, i.e. a field name, a structural key or a nearby support term (`context`:
`Kontonummer: 4111-1111-1111-1111`), a checksum (`checksum`), the higher score (`score`), the earlier rule
(`rule_order`). A finding inside a printed IBAN form (country code, two digits, groups of four:
`DE34 6659 4134 6836 7322 13`) yields even when the IBAN's check digits fail and no IBAN is
reported (`iban_form`). The loser leaves `evidence_spans`; its `matched_rules` entries stay and
carry `overlap` with the `reason` and, except for `iban_form`, the winning label in `yields_to`.
`class_name` and `confidence` follow the remaining findings. `PASSPORT_NUMBER` and
`IDENTITY_CARD_NUMBER` compete with an overlapping finding of any other label (F08): a bare check
digit of 7-3-1 mod 10 fits one in ten letter-led codes, so a document finding with only a nearby term
ranks below every other supported label, and `Kundennummer K12345676` stays `CUSTOMER_ID` and
`Passport number: Y22400855` stays `PASSPORT_NUMBER`. Other labels keep their
overlaps (an e-mail address after `Username:` stays `EMAIL` and `USERNAME`), and `strict` keeps both
labels (decision T07).

**Secondary evidence in `strict` (T07).** `strict` keeps reporting both labels, with spans, class
and confidence unchanged, but a `CREDITCARD` or `FINANCIAL_ACCOUNT_NUMBER` finding inside a reported
(MOD-97-valid) IBAN is secondary evidence of it: the card-shaped BBAN of
`DE94 5001 0517 5401 2345 65`, or the account after `Bank account:` on
`GB82WEST12345698765432`. `details.secondary_evidence` lists each one as `label`, `start_byte`,
`end_byte`, `reason` (`iban_value` for the IBAN's own span, `iban_part` for a part of it) and
`primary_label` (`IBAN`); it is absent when there is none. Evaluations (`13_l1_golden_eval`,
`scripts/l1_presidio/run_ark.py` for the scoreboard) score primary findings only. A card or
account next to an IBAN, and the digits of an IBAN form whose check digits fail, stay primary.
The scored modes drop these findings instead (K07) and list nothing.

For example, a Steuer-ID after its field name scores `1.0`, an IBAN without a field name `0.90`
(`1.0` right after the word `IBAN`), a licence plate after `Kennzeichen:` `0.65`, and a card
number after `Bestellnummer` `0.45`, below the `balanced` threshold. The [L1 rule catalog](l1-rule-catalog.md) lists
strength, base and score per rule. In `balanced` and `recall`, every `details.matched_rules`
entry also carries the `score` of its finding and its `context`: `bonus` and `penalty` points
and, when a term decided them, its lexicon `anchor` (`field` for a field name bound by the
rule), `side` (`before`/`after`, `key` for a structural key) and `distance` in characters. `strict` results are unchanged
and carry neither field.

Every rule that does not require context scores at least `0.50` without it, so `balanced` and
`recall` return the `strict` spans except those a nearer counter-context term pushes below their
threshold and those that yield to an overlapping finding of a competing label (K07). They also report checksum-strong values without a field name (K05): IBAN and card
numbers as in `strict`, and scored-only rules add the bare form of values that `strict` reports
only after their field name. The first is `pii_steuer_id_de_context_free`: 11 digits or
`86 095 742 719` that pass the check digit and the digit distribution of issued Steuer-IDs (one
digit twice or three times, never three in a row), standing alone rather than inside a longer
number, range or decimal. It scores `0.55` bare, `0.80` after `Steuer-ID ist`, and `0.25` behind
a nearer counter-context term (`Rechnungsnummer 86095742719`), below both thresholds. The VAT ID
rules (B01) are scored-only as well, with one label per country (`VAT_ID_DE`, `VAT_ID_AT`,
`VAT_ID_CH`, `VAT_ID_FR`, `VAT_ID_NL`, `VAT_ID_BE`, `VAT_ID_IT`, `VAT_ID_ES`): an upper-case
country prefix, the national form (`DE 136 695 976`, `ATU13585627`, `CHE-100.155.212`,
`FR 40 303 265 045`, `NL004495445B01`, `BE 0403.019.261`, `IT00743110157`, `ESA13585625`) and its
check digit; `0.55` bare, `0.80` with a VAT term such as `USt-IdNr.`, `TVA` or `Partita IVA`. A
bare Partita IVA without `IT` (`pii_vat_id_it_proximity`) needs such a term or key. Part 2 (B02)
adds `VAT_ID_BG`, `VAT_ID_CY`, `VAT_ID_CZ`, `VAT_ID_DK`, `VAT_ID_EE`, `VAT_ID_EL` (prefix `EL` or
`GR`), `VAT_ID_FI`, `VAT_ID_HR`, `VAT_ID_HU`, `VAT_ID_IE` and `VAT_ID_LT` in the same way
(`BG175074752`, `CY-10259033P`, `CZ25123891`, `DK 13 58 56 28`, `EE100931558`, `EL094259216`,
`FI20774740`, `HR33392005961`, `HU-12892312`, `IE6433435OA`, `LT100001919017`), with national terms
such as `DIČ`, `CVR-nr.`, `ΑΦΜ`, `OIB` or `PVM kodas`. B16 adds `VAT_ID_LU`, `VAT_ID_LV`,
`VAT_ID_MT`, `VAT_ID_PL`, `VAT_ID_PT`, `VAT_ID_RO`, `VAT_ID_SE`, `VAT_ID_SI`, `VAT_ID_SK`,
`VAT_ID_NO` and `VAT_ID_GB` the same way (`LU15027442`, `LV40003521600`, `MT 1167-9112`,
`PL 856-734-62-15`, `PT 501 964 843`, `RO18547290`, `SE556677889901`, `SI 5022 3054`,
`SK 202 274 96 19`, `NO 995 525 828 MVA` with the suffix in the span, `GB 980 7806 84` with an
optional three-digit branch); Northern Ireland numbers (`XI 980 7806 84`) are `VAT_ID_GB`. German passport
and identity card numbers (F08) are scored-only with their ICAO 9303 check digit (weights 7-3-1):
passport series `C F G H J K`, identity card series `L M N P R T V W X Y`, eight characters plus the
check digit (`F12345671`, `L01X00T44`) or the MRZ form of nine plus the check digit (`C01X00T478`,
`T220001293`); `0.55` bare, `0.80` with a document term such as `Pass-Nr.` or `Ausweis-Nr.`. A bare
value of a field that names something else is not reported (`DEA-Nummer: RN4135883`, a
`driver_license_number` column). The old numeric serial of ten digits (`1220001297`) needs such a
term or key. The field-bound rules keep
their format check in every mode, since a printed nine-character serial carries no check digit. A context-bound rule (`pii_phone_de_national_proximity`: a national number such as
`ist unter 0176 90817263 erreichbar`) reports only with a support term and no nearer counter term,
in every mode including `strict`, and then scores at least `0.50`. Validators decide in every
mode: a value with a wrong check digit is never reported. Scores are rule-based evidence strengths, not calibrated
probabilities; do not compare them with model confidences of other layers.

Ambiguous PII fields require additional context before they emit findings or
`matched_rules`: card expiry dates need a payment-card marker or a Luhn-valid PAN
within the preceding 128 bytes of the same clause. Sentence, newline, semicolon,
and pipe boundaries stop that context. Generic `Kennung` and OCR `ID` fields need
an `EMP`, `HR`, or `STAFF` prefix separated from the rest of the value, or local
employment context. Explicit employee fields such as `Personalnummer` remain
supported. SWIFT/BIC fields require `:`, `#`, or `=` assignment, or `SWIFT code is` /
`BIC [code] is` followed by an uppercase code. Lowercase codes remain accepted in
explicit assignments. Bare expiry dates, product IDs, and Swift-language prose
are insufficient on their own.

Native PII and DLP scans do not compute or return the separate diagnostic context anchors by default.
Enable diagnostic context explicitly with Rust `ScanGateMatrix.explain = true`, Python
`execution_gates={"explain": True}`, or worker API `gates: {explain: true}`. Explained layers
can expose context under `details.l1_anchors`; these anchors are not findings:

```json
{
  "kind": "anchor",
  "anchor_kind": "lexical",
  "category": "date_of_birth",
  "strength": "strong",
  "text": "Geburtsdatum",
  "start_byte": 18,
  "end_byte": 30,
  "start_char": 18,
  "end_char": 30
}
```

Consumers must base immediate findings on `evidence_spans` and the result decision, not on an
anchor alone. Anchor metadata is diagnostic only and does not affect detection. Each native
layer includes at most 12 anchors within a 4-KiB serialized metadata budget; omitted anchors
set `details.l1_anchors_truncated` to `true`. Match text is previewed at most 96 UTF-8 bytes;
`text_truncated: true` marks a shortened preview, while all offsets still cover the full match.

Dynamic PII L3 layers expose `details.inference_groups`. Each entry identifies a stable base or
conditional GLiNER call, its labels, the conditional rule index, and optional byte ranges inherited
from matching final source-pipeline chunks. This is diagnostic provenance; the public findings
remain the merged `evidence_spans`, with the highest-scoring exact duplicate retained.

For registered native injection findings, the span label is the stable Ark rule ID. The
corresponding layer `details` contain an ordered `matched_rules` list with the Ark ID, optional
upstream ID, family, severity, description, source revision, byte offsets, and `span_precision`.
Data-driven regex rules use `exact`; procedural detectors currently use a localized `clause` or
bounded `window`, and a relationship assembled from independently matched components uses
`composed`. A provenance weight, when present, is metadata and not an Ark decision threshold.
Source-derived rules also expose `references` for secondary pinned sources, while `source`,
`source_revision`, `source_license`, `upstream_id`, and `adaptation` identify the primary origin
and Ark-specific narrowing.

The aggregated native Injection result exposes `layers[].details.l1_candidates` for accepted and
rejected candidates. Each candidate has a deterministic ID derived from its original-document
byte span, byte and character offsets, contributing producers, rule IDs and families, maximum
severity, calibrated score, threshold, acceptance result, and typed features:

```json
{
  "candidate_id": "injection:l1:18:57",
  "category": "injection",
  "start_byte": 18,
  "end_byte": 57,
  "start_char": 18,
  "end_char": 57,
  "rule_ids": ["ark.injection.override.hierarchy"],
  "rule_severities": {"ark.injection.override.hierarchy": "critical"},
  "families": ["instruction_override"],
  "max_severity": "critical",
  "producers": ["native:instruction_override"],
  "score": 0.91,
  "acceptance_threshold": 0.85,
  "accepted": true,
  "score_version": "injection-l1-0.1.6",
  "features": [
    {
      "feature_id": "rule:ark.injection.override.hierarchy:18:57",
      "kind": "rule_match",
      "value": 1.0,
      "explanation": "Invalidates or replaces a prior instruction hierarchy",
      "start_byte": 18,
      "end_byte": 57,
      "span_precision": "clause",
      "provenance": {
        "rule_id": "ark.injection.override.hierarchy",
        "source": "ark-native",
        "source_revision": "71ff48e513ffee7810b29704e4cd9d4715aeaebd"
      }
    }
  ]
}
```

The separately gateable internal `native:injection_structural` producer uses the same candidate
contract. It may create a candidate without a flat catalog match.
Its relationship ID remains in `rule_ids`, while `features[].kind` is
`structural`; each feature has the exact span of one required component, such
as a context override, instruction-hierarchy reference, disclosure action, or
sensitive instruction object. The candidate span is the smallest
original-document region containing all required components.

The `native:injection_l1` aggregate scores each merged candidate. Accepted candidates create
public finding spans and use `source: "l1"`; rejected candidates remain visible in
`decision.candidates` with `accepted: false` while the top-level result stays safe. Individual
native Injection producer verdicts are no longer returned as separate public results. Registered
external L1 detectors remain separate and unchanged.

### DLP taxonomy

DLP findings use the `entity_group` of their rule as the span `label` and the result
`class_name`. Taxonomy v2 (K09) keeps these groups unchanged: the credential/secret groups
`API_KEY`, `CLOUD_KEY`, `PAYMENT_KEY`, `SECRET_TOKEN`, `CREDENTIAL`, `PASSWORD_HASH`,
`PRIVATE_KEY` and `CRYPTO_KEY` (on by default), plus the opt-in identifier and content groups
(`dlp.de.*`, `dlp.record.*`, `dlp.project_id`, `dlp.organization_id`,
`dlp.internal.business_metric`, `dlp.content.*`). Every `matched_rules` entry of a
credential/secret rule names what the value is within its group as `subtype`, next to
`provider` (provider-bound formats only), `validator_strength`, `source_ref` and `severity`;
identifier and content rules carry no `subtype`.

| `subtype` | Groups | Values |
| --- | --- | --- |
| `api_key` | `API_KEY`, `CLOUD_KEY`, `PAYMENT_KEY` | Provider-issued API or access keys (LLM keys, AWS access key ID, Google API key, Stripe key). |
| `access_token` | `SECRET_TOKEN`, `CLOUD_KEY` | OAuth, personal, bot and bearer tokens, JWTs (GitHub, GitLab, npm, Slack, Discord, Google OAuth). |
| `secret_key` | `API_KEY`, `CLOUD_KEY`, `PAYMENT_KEY` | The secret half of a key pair or client credential, signing secrets (AWS secret access key, GCP client secret, Stripe webhook secret). |
| `private_key` | `PRIVATE_KEY`, `CRYPTO_KEY` | PEM private keys, wallet keys (Ethereum, Bitcoin WIF). |
| `seed_phrase` | `CRYPTO_KEY` | Mnemonic wallet seeds (planned). |
| `password` | `CREDENTIAL` | Passwords in assignments and prose, URL userinfo, Basic auth. |
| `password_hash` | `PASSWORD_HASH` | Password hashes. |
| `generic_secret` | `CREDENTIAL` | Any value under a secret-like key or variable name. |
| `session_token` | `SECRET_TOKEN`, `CREDENTIAL` | Session IDs in cookies, CSRF tokens. |
| `signature` | `CREDENTIAL` | Signatures of signed URLs. |
| `connection_string` | `CREDENTIAL` | Database and service connection strings with credentials (planned). |
| `auth_url` | `CREDENTIAL` | Credentials carried in a URL: token, password and API key parameters; reset and magic links, OAuth redirects (planned). |
| `webhook_url` | `SECRET_TOKEN` | Incoming webhook URLs that authorize by themselves (planned). |
| `otp_secret` | `CREDENTIAL` | TOTP/HOTP seeds, `otpauth://` URIs, recovery codes (planned). |

Subtypes marked planned have no rule yet; new rules for them report the listed group, so
group filters and gates written for the existing groups keep covering them. The
[L1 rule catalog](l1-rule-catalog.md#dlp-regex-rules-59) lists the subtype of every rule.

### DLP score and modes

The DLP `score` of the `native:dlp` producer depends on the DLP mode, an opt-in execution gate
(Rust `ScanGateMatrix.dlp_mode`, Python `execution_gates={"dlp_mode": "balanced"}`, Ark API
`gates: {dlp_mode: balanced}`). Unknown mode names are rejected. The modes and thresholds are
those of the [PII modes](#pii-score-and-modes); the two gates are independent.

| Mode | `evidence_spans[].score` | Threshold | `confidence` |
| --- | --- | --- | --- |
| `strict` (default) | always `1.0` | none: the rules decide | `1.0` |
| `balanced` | model score | findings below `0.50` are dropped | highest span score |
| `recall` | model score | findings below `0.30` are dropped | highest span score |

The model score is the PII score model applied to the DLP rules, capped at 100 and divided by 100:

- **Base** (1–100 points) of the rule: how specific its pattern is on its own (a long provider
  prefix such as `github_pat_` scores higher than a bare `0x` + 64 hex digits).
- **Validator strength** from the rule metadata: `checksum` +35, `structure` +25, `format` +15,
  `none` +0.
- **Context**: +25 when the rule captures the value behind a field name of its own (assignments,
  `Authorization` headers, URL parameters and userinfo, cookies, keyed provider secrets such as
  `aws_secret_access_key`, business identifiers). A secret without a field name (provider
  tokens, wallet keys, PEM keys, JWTs) takes the nearest DE/EN term on its line with the windows
  and boundaries of the PII context engine: a credential term of
  `rust/src/detectors/anchor_lexicons/dlp.json` (`private key`, `privater Schlüssel`,
  `access token`, `API-Schlüssel`, `GITHUB_TOKEN` …) adds +25/+20/+15, a strictly nearer digest,
  hash or ID term (`dlp.digest_reference`: `checksum`, `tx hash`, `Transaktionshash`,
  `Prüfsumme`, `commit sha`, `sha256`, `UUID`, `request id` …) subtracts 30. Content classes
  score without context.

So a bare `0x` + 64 hex value scores 0.40 (kept by `recall` only), next to `private key` 0.65,
and next to `tx hash` 0.10 (dropped in both scored modes); a provider token scores 0.50–0.75
without context, which a counter term lowers below `balanced`. Every field-bound and content rule
scores at least 0.50, so `balanced` changes only findings without a field name.

A scored mode scores the findings that `strict` reports, after the same overlap resolution, and
then drops those below the threshold: its spans are always a subset of the `strict` spans, and a
value dropped for its context does not free its range for a weaker rule. Each surviving
`matched_rules` entry carries `score` and `context` (`bonus`, `penalty` and, if a term decided,
`anchor` — the lexicon entry or `field` —, `side` and `distance`) next to the rule metadata.
The [L1 rule catalog](l1-rule-catalog.md#dlp-regex-rules-59) lists base, context source and
score range per rule.

### Shell command results

`shell_command` returns one L1 result with `model: "cat-shell-risk-commander"` and `class_name`
`shell_risk` or `safe`. Its `confidence` is `sigmoid(|decision_score − threshold|)` — the
distance from the threshold squashed into `0.5`–`1.0`, **not** a calibrated probability.
`layers[0].details` contains:

| Field | Meaning |
| --- | --- |
| `model` | `cat-shell-risk-commander`. |
| `decision_score` | Raw logit of the scored variant. |
| `threshold` / `threshold_policy` | Decision threshold and its policy (default `external_commands_1pct_fpr`, ≈1.15). |
| `variant` | `full` or `comments_stripped` — whichever scored higher. |
| `full_score` | Logit of the unmodified input. |
| `comments_stripped_score` | Logit with comments blanked; present only when comments were found. |

Flagged results carry up to three `evidence_spans` with label `shell_risk` over the character
n-gram regions that pushed the score up; `score` is that region's share of the positive
contribution.

## Async queue events

`consume_next_event(timeout)` returns one event dict at a time (or `None` on timeout).
`consume_events(timeout)` yields them. There are up to four `event_type`s: `result` and
`finished` always, plus `progress` and `provisional` when L3 progress reporting is enabled
(`execution_gates.l3.progress`, off by default). The blocking `scan_*` helpers only ever return
`result` / `finished`.

### `result`

```python
{
    "event_type": "result",
    "request_id": "…",
    "result": { …a scan result dict, as above… },
}
```

One request can emit **several** `result` events. L1 results are visible as soon as L1
finishes; L2 and a later promoted L3 result follow independently.

Promoting NTDB L2 layers expose `details.l3_candidates` (each entry: byte `span`,
`promote_score`, `promote_threshold`, `source_pipeline`, `source_model`, `l2_class`) and
`details.l2_chunk_outputs` (the per-chunk L2 outputs retained for aggregation, with the raw
embeddings stripped). Under `l3_strategy="multi"`, candidates from every promoted pipeline in the
coalesced run are deduplicated by **exact span match** — when two heads promote the same span,
`source_pipeline` / `source_model` / `l2_class` become comma-joined unions; under the default
`l3_strategy="dedicated"` each pipeline's candidates stay separate and this merge never runs. The
L3 worker maps candidate spans onto tokenizer-bounded windows; with representative
clustering enabled it groups near-duplicate windows, infers only cluster representatives, and
propagates their verdict to the rest (see
[L3 worker policy](configuration.md#l3-worker-policy)). An empty or unusable candidate list
deliberately falls back to full-text L3.

For Package-v4 Union decisions, the final `decision_candidate` may contain `chunk_evidence` with
the aggregation method and the contributing document chunks. This provenance never changes the
scan verdict.

### `progress`

Opt-in, non-authoritative status while a long L3 scan resolves — only under the dedicated L3
strategy (`l3_strategy="multi"` never emits it):

```python
{
    "event_type": "progress",
    "request_id": "…",
    "progress": {
        "category": "injection", "model": "…", "stage": "l3_chunk",
        "completed_chunks": 3, "total_chunks": 8,
        "inferred_chunks": 2, "propagated_chunks": 1, "cache_hits": 0,
        "early_exit": False, "coverage": 0.375, "details": { … },
    },
}
```

`stage` is one of `l3_started`, `l3_chunk`, `l3_cluster_propagated`, `l3_early_exit`. A progress
event carries no verdict — never treat it as a result.

### `provisional`

Same shape as a `result` event's `result`, but an **interim preview** re-aggregated from the
chunks resolved so far. It is non-authoritative and may be superseded by later `result` /
`finished` events; only emitted when `execution_gates.l3.progress` is set to `"provisional"`.

### `finished`

Exactly one terminal event follows all results for a request:

```python
{
    "event_type": "finished",
    "request_id": "…",
    "completion": "…",     # "complete" | "degraded" | "failed"
    "failures": [ … ],     # structured failures, if any
}
```

`completion` is one of `complete` (all planned work succeeded), `degraded` (some layer failed
but a lower-layer result was delivered), or `failed` (no usable result). Consuming `finished`
removes all library state for that request ID. Correlate every event by `request_id`.

### Failures

Each `failures` entry is a structured `SecurityFailure` dict:

| Field | Type | Meaning |
| --- | --- | --- |
| `stage` | str | `warmup`, `asset`, `scanner`, `inference`, `queue`, or `worker`. |
| `kind` | str | `not_ready`, `missing_asset`, `integrity_failure`, `initialization_failure`, `inference_failure`, `timeout`, `queue_full`, `worker_unavailable`, or `internal`. |
| `level` | str \| null | The level that failed (`L1`/`L2`/`L3`), if applicable. |
| `detector_id` | str \| null | The specific detector or model that failed, if applicable. |
| `retryable` | bool | Whether the failure is transient and could succeed on retry. |
| `message` | str | Human-readable description. |

A failure does not throw during scanning — the scan
[degrades](../concepts/layered-scanning.md#degradation-contract) to the best available
lower-layer result and reports the failure here. (`warmup()` itself is the exception: a missing
required asset there raises rather than degrades.)

## Request introspection

| Method | Returns |
| --- | --- |
| `has_request(request_id)` | Whether the gateway still tracks this request. |
| `request_state(request_id)` | Current state dict, or `None`. |
| `is_finished(request_id)` | `True` / `False`, or `None` if unknown. |
| `runtime_readiness()` | Initialized runtime state (levels ready, per stage/kind). |

Request state reflects `SecurityRequestState` — whether any planned scanner or promoted L3 job
can still publish an event.
