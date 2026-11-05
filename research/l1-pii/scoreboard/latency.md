# L1-PII latency: Ark vs. Presidio

Machine: Intel Core Processor (Haswell, no TSX), 6 usable CPUs, Linux x86_64. One call per sample, sequential, each engine in its own process. Workloads v1: DE + EN pooled per size class.

| Engine | Init ms | short p50 / p95 / p99 ms | 4kib p50 / p95 / p99 ms | 100kib p50 / p95 / p99 ms |
|---|---:|---:|---:|---:|
| ark | 515 | 0.292 / 0.404 / 0.491 | 1.904 / 2.548 / 2.861 | 12.319 / 15.003 / 15.855 |
| ark-native | 324 | 0.288 / 0.367 / 0.438 | 1.880 / 2.641 / 3.175 | 8.334 / 9.774 / 11.099 |
| presidio-default | 4565 | 10.151 / 13.928 / 16.559 | 212.486 / 338.831 / 390.239 | 10407.527 / 13634.609 / 15005.935 |
| presidio-tuned | 8764 | 12.540 / 30.829 / 33.890 | 200.656 / 259.931 / 290.922 | 9803.598 / 11978.768 / 12399.738 |

| p95 / Ark (Python) | short | 4kib | 100kib |
|---|---:|---:|---:|
| ark-native | 0.91× | 1.04× | 0.65× |
| presidio-default | 34× | 133× | 909× |
| presidio-tuned | 76× | 102× | 798× |

| Workload | Bytes | Chars | ark spans | ark-native spans | presidio-default spans | presidio-tuned spans |
|---|---:|---:|---:|---:|---:|---:|
| short-de | 115 | 115 | 2 | 2 | 7 | 3 |
| short-en | 98 | 98 | 2 | 2 | 5 | 5 |
| 4kib-de | 4096 | 4052 | 46 | 46 | 140 | 82 |
| 4kib-en | 4096 | 4096 | 42 | 42 | 117 | 109 |
| 100kib-de | 102400 | 101229 | 1173 | 1173 | 3613 | 2051 |
| 100kib-en | 102400 | 102400 | 1038 | 1038 | 2907 | 2701 |

M4 (ark 100kib p95 ≤ 10 ms): 15.003 ms, FAIL.
M4 (ark-native 100kib p95 ≤ 10 ms): 9.774 ms, pass.
## Profile and remaining hotspots (H06 pass 6)

Stage profile of one native PII scan of the 100 KiB workloads (`detect_prepared_with_mode`, strict,
explain off, median over 50 calls, 6 rayon threads, quiet machine):

| Part | DE ms | EN ms |
|---|---:|---:|
| Rule scan before the parallel step (value runs, word shapes) | 0.39 | 0.39 |
| Parallel rule step, wall (search CPU 14.9, accept CPU 4.0–5.3) | 4.5 | 4.9 |
| Collecting the findings and overlap resolution | 0.51 | 0.57 |
| Deobfuscated view (`Deobfuscated::new`) | 0.29 | 0.31 |
| `mark_secondary` | 0.11 | 0.10 |
| Whole call including the drop of the result | 7.6 | 7.8 |

No single rule bounds the parallel step: the most expensive rule costs about 1.5 ms CPU (search and
accept). Two zero-match rules (`pii_applicant_id`, `pii_health_insurance_number_de`) looked like
1.0–1.4 ms searches; their regexes take 0.04 ms, the rest is the first search of each thread waiting
for the lazy lexical anchors of the text (0.75–0.9 ms per 100 KiB, one Aho-Corasick pass over 6 399
words). Measured and not in, each an interleaved A/B of the native worker (5 rounds) that did not
beat the noise or was slower:

- the rule scan, the anchors and the structure parse joined on the rayon pool before the parallel
  step (EN p50 about +0.8 ms, DE unchanged);
- the anchors split into overlapping chunks over the pool (standalone 0.8 → 0.3–0.5 ms, search CPU
  15 → 13.4 ms, but the wall time of the call unchanged: the wake-up of the pool costs what the
  overlap saves on 6 shared CPUs);
- a DFA instead of the contiguous NFA for the anchor automaton (EN 0.74 → 0.58 ms, DE unchanged,
  much more memory).

Found on the way, outside the M4 path (explain is off by default): with `explain` on, PII and DLP add
the matches of their context anchor patterns, all `(?i)\b…\b`. A Unicode word boundary sends the
lazy DFA to the slow NFA at the first non-ASCII byte, so a German text paid about 65 ms per 100 KiB
for the anchor details alone. Pass 6 searches these patterns like the PII rules since H03: without
their word boundaries on the DFA, each candidate start probed anchored with the pattern itself (the
shared `detectors::word_boundary` module, used by the PII rules and the anchor details of PII and
DLP). The anchor JSON is byte-identical on the six workloads; tests check that every PII rule and
PII/DLP anchor pattern finds what its regex finds on the bilingual fixture after German prose.
Explain on, p50 per call: 100 KiB DE 71.9 → 9.6 ms, 4 KiB DE 8.35 → 1.31 ms; EN and explain off
unchanged.

The default path (explain off) runs the same search code as before (the PII rule search only moved into
the shared module), so the M4 rows at the top are the pass 5 run; the interleaved A/B rounds of this
pass on the native worker kept 100 KiB p95 at 9.7–11.6 ms under a load of 1.3–2.5. M4 holds for
ark-native (within the noise), not for ark (Python). Remaining hotspots, each ≥ 10 % of the ark p95,
for H06-7:

- The `matched_rules` entries as `serde_json::Value` (unchanged): the Python `details` getter
  (1.3–3 ms) and about 1.5 ms native drop. A typed entry that serializes to the same JSON touches
  56 uses in 13 files (overlap resolution, the deobfuscated merge, DLP, MCP and injection
  detectors, the binding); the remaining lever, too large for one pass next to the measurements.
- The parallel rule step at about 1.4× its ideal (wall 4.5–4.9 ms against CPU/6 ≈ 3.2 ms): the
  zero-match searches (most of the 13–15 ms search CPU) and the scheduling of 300+ small tasks.

## Profile and remaining hotspots (H06 pass 5)

Ark rows measured after H06-5 (`latency.py run`; ark under a load average of about 1.3–1.4, ark-native
in a second run at about 1.8, as the first ark-native run at about 2.8–3.0 gave 10.606 ms with unchanged
native code); the Presidio rows are the H03 run. 100 KiB p95: ark 15.170 → 15.003 ms, ark-native
9.803 → 9.774 ms; the 4 KiB rows of both engines moved up by the same amount with the load (the native
code is unchanged). Spans per workload are unchanged.

Profile of the 100 KiB workloads through the Python binding before pass 5 (median per call; the
machine is noisy, so ranges over DE and EN and repeated runs):

| Part | ms |
|---|---:|
| Native scan (`scan_category` with the GIL released) | 7.0–8.0 |
| Layer `details` getter (1 369 `matched_rules` entries, about 11 000 Python objects) | 2.9–3.3 (fastest 1.5) |
| `evidence_spans` getter (about 1 100 dicts) | 0.7–0.9 (fastest 0.45) |
| Freeing the result dicts | 0.5–0.6 |
| Freeing the native result (details on the release thread) | 0.2–0.3 |

The `details` getter looks every dict key and string value up in a per-call string cache (about
22 000 lookups per 100 KiB call). Pass 5 hashes that cache with Fx instead of SipHash (`rustc-hash`,
already in the lock): the getter's fastest call 1.55 → 1.25 ms. An A/B of the whole Python call
against main, interleaved three times on the same machine (100 samples per workload and round,
mean over the rounds): 100 KiB p50 11.12 → 10.55 ms, p95 13.63 → 13.25 ms. The JSON values are
unchanged (`test_layer_details_and_thresholds_are_their_json_values`). For comparison, building the
same dicts from Python objects already in hand costs about 0.5 ms; the rest of the getter is reading
the scattered `serde_json` maps. Measured and not in: sharing one Python int per distinct offset
(slower, 1.25 → 1.4 ms), a presized list per JSON array and a presized dict per span (each below
0.05 ms).

M4 holds for ark-native (within the noise), not for ark (Python). Remaining hotspots, each ≥ 10 % of
the ark p95, for H06-6:

- The `matched_rules` entries as `serde_json::Value`: the details getter (1.3–3 ms) and about 1.5 ms
  native drop. A typed entry that serializes to the same JSON is the remaining lever; it touches every
  reader of `details["matched_rules"]` (overlap resolution, the deobfuscated merge, DLP and MCP
  detectors) and the binding reads it field by field.
- The zero-match rule searches of rules with separators or field names (7.6–8.6 of 14 ms search CPU,
  pass 4).
- The sequential preparation before the parallel step (lowercase view, lexical anchors, structure
  parse; 1.4–1.7 ms).

## Profile and remaining hotspots (H06 pass 4)

Ark rows measured after H06-4 (`latency.py run --engines ark ark-native`); the Presidio rows are the
H03 run. The machine was busier than in pass 3 (load average about 5–6 during the run, against 1.2),
so the wall times move within the noise: 100 KiB p95 ark 14.641 → 15.170 ms (p50 11.864 → 11.761 ms),
ark-native 9.947 → 9.803 ms. Spans per workload are unchanged.

Pass 4 adds a word shape gate to the PII rules (`detectors/pii/word_shape.rs`). A rule whose every
match is one maximal ASCII word run (`\b[A-Z]{5}[0-9]{4}[A-Z]\b`, `\b[A-Z0-9]{18}[0-9]{2}\b`) carries
the run length range, the character kinds the run may hold (digit, upper, lower, underscore) and the
kinds it must hold; `rule_scan` records the lengths of the word runs of the text per kind set in one
pass and leaves a rule whose shape occurs nowhere unsearched. 41 of the PII rules have a shape. The
gate is a necessary condition of the regex, so results are the same; a test checks it on the PII
goldens and the bilingual fixture, and the prefilter equivalence test runs against the pipeline
without it.

Rule searches of the 100 KiB workloads (sum of the single-rule searches, fastest of 15, one thread):

| Workload | Before, ms | After, ms | Of which zero-match rules, before → after |
|---|---:|---:|---:|
| 100kib-de | 17.2 | 14.3 | 11.0 → 8.6 |
| 100kib-en | 16.7 | 13.9 | 10.3 → 7.6 |

That is about 0.5 ms of the parallel step on 6 threads, below the noise of the busy machine.

M4 holds for ark-native, not for ark (Python). Remaining hotspots, each ≥ 10 % of the ark p95, for
H06-5:

- The `matched_rules` entries as `serde_json::Value` (unchanged since pass 3): about 3.8 ms of the
  Python conversion right after the scan and about 1.5 ms native drop. A typed entry that serializes
  to the same JSON is the remaining lever; it touches every reader of `details["matched_rules"]`
  (overlap resolution, the deobfuscated merge, DLP and MCP detectors).
- The zero-match rule searches still cost 7.6–8.6 ms search CPU: most of them are rules with
  separators inside the value (`[0-9]{6}[-+]?[0-9]{4}`, plates, grouped numbers) or field names before
  it, which a single word run does not describe. Each costs the floor of one lazy DFA pass over the
  text (about 0.18 ms per 100 KiB).
- The sequential preparation before the parallel step (lowercase view, lexical anchors, structure
  parse; 1.4–1.7 ms).

## Profile and remaining hotspots (H06 pass 3)

Ark rows measured after H06-3 (`latency.py run --engines ark ark-native`, the second of three runs;
100 KiB p95 over the three: ark 14.058 / 14.641 / 14.900 ms, ark-native 10.251 / 9.947 / 9.897 ms);
the Presidio rows are the H03 run. The native code is unchanged, so the ark-native spread is the
noise of the machine, which was busier than in pass 2. Spans per workload are unchanged. An A/B of
the Python binding against main, both in turn under the same load: 100 KiB p95 17.6–18.0 → 13.2–13.9
ms, short and 4 KiB unchanged.

Profile of the 100 KiB workloads through the Python binding (median per call, DE and EN pooled,
before → after pass 3):

| Part | ms |
|---|---:|
| Native scan (`scan_category` with the GIL released) | 7.9 (unchanged) |
| `_to_dict`: layer `details` (about 4 600 Python objects of 1 369 `matched_rules` entries), warm | 2.5 → 1.6 |
| `_to_dict`: layer `details`, right after the scan (the entries were built on the rayon workers) | 5.1 → 3.8 |
| `_to_dict`: `evidence_spans` (about 1 100 dicts) | 1.7 → 1.5 |
| Freeing the result dicts | 0.8 → 0.6 |
| Freeing the native result (serde values of the `matched_rules`) with the GIL held | 2.8 → 0.3 |

Pass 3 builds one Python string per distinct key or value text per `details` call (keys interned as
before, values not, as they may hold scanned text) and passes `Bound` values, so no dropped
`PyObject` checks the GIL; span labels are shared the same way. A released layer with at least 64
`matched_rules` entries hands its details to a background thread through a bounded queue (the caller
frees them when the queue is full); smaller ones are freed in place, as waking the thread costs short
texts as much as the free. Measured and not in: a `RegexSet` of all PII rules as a shared pre-pass
(about 1 s per 100 KiB: the union does not fit the lazy DFA), and anchor gates that require every
lexicon word inside a literal instead of one (2–3 of about 60 zero-match rule searches gated).

M4 holds for ark-native (within the noise), not for ark (Python). Remaining hotspots, each ≥ 10 % of
the ark p95, for H06-4:

- The rule searches: 60–65 of the 93 searched PII rules find nothing in either workload and still
  scan the whole text, about 10 of 19 ms search CPU per call (about 1.7 ms wall on 6 threads). Most
  start with their value, not a keyword, so the lexicon gates do not apply; a shared value-shape
  pre-pass (one scan that records which value classes and lengths occur) would skip them.
- The `matched_rules` entries as `serde_json::Value`: about 16 allocations per match, built on the
  rayon workers and read cache-cold when Python converts them (3.8 ms after the scan vs 1.6 ms warm),
  and freed natively (about 1.5 ms of the ark-native call). A typed entry (a struct that serializes to
  the same JSON) would cut the allocations, the drop and the conversion; the JSON shape stays.
- The sequential preparation before the parallel step (lowercase view, lexical anchors, structure
  parse; 1.4–1.7 ms).

## Profile and remaining hotspots (H06 pass 2)

Ark rows measured after H06-2 (`latency.py run --engines ark ark-native`, the second of three runs;
100 KiB p95 over the three: ark 14.139 / 15.920 / 15.811 ms, ark-native 8.822 / 9.402 / 10.025 ms, so
ark-native sits at the budget within the noise of the machine); the Presidio rows are the H03 run.
Spans per workload are unchanged. 100 KiB p95 since pass 1: ark 24.651 → 15.920 ms, ark-native
15.324 → 9.402 ms.

Profile of the 100 KiB workloads (median per call, DE and EN alike, release build with timers):

| Part | ms |
|---|---:|
| Native: lowercase view, lexical anchors, structure parse | 1.4–1.7 |
| Native: value runs (`rule_scan`) | 0.2–0.3 |
| Native: per-rule gates, searches, validation, scoring, `matched_rules` entries (parallel; CPU sum about 17: searches 13.3, per-match work 3.1) | 4.0–4.5 wall |
| Native: overlap resolution, finalize, char offsets; deobfuscation view; secondary marks | 0.9 |
| Native: drop of the result (about 1 360 `matched_rules` objects) | 1.5–1.6 |
| Python: `_to_dict`, mostly the `matched_rules` details as Python objects (about 4 500 dicts) | 3.4–4.5 |
| Python: freeing the result dicts and the native result | 1.6–2.5 |

Pass 2 moves the whole per-rule work of large texts onto the rayon pool: each rule is gated,
searched, and its matches validated, scored and turned into `matched_rules` entries and spans on its
own (`NativeRegexDetector::rule_findings`); the results are joined in rule order, so overlap
resolution is unchanged. The Python binding no longer round-trips the layer details through JSON
text (serialize in Rust, `json.loads` in Python, about 3.7 ms): the `details` and `thresholds`
getters build the Python objects directly. The `evidence_spans` getter returns the span dicts of
the public result. Building the anchors and the structure side by side before the parallel search
was measured and gave nothing; it is not in.

M4 holds for ark-native, not for ark (Python). Remaining hotspots, each ≥ 10 % of the ark p95, for
H06-3: the `matched_rules` details as Python objects and their release (about 5–6 ms together; a
lazy details view or a leaner entry would cut them, but the result shape is public), the CPU time of
the rule searches (13 ms over 6 threads; most PII rules start with their value, not a keyword), and
the native result drop (1.5 ms, about 20 000 small allocations of the `matched_rules` JSON).

## Profile and remaining hotspots (H06 pass 1)

Ark rows measured after H06 pass 1 (`latency.py run --engines ark ark-native`); the Presidio rows are
the H03 run on the same machine (Presidio and the workloads are unchanged). Spans per workload are
unchanged. 100 KiB p95 since H03: ark 35.898 → 24.651 ms, ark-native 28.441 → 15.324 ms.

Profile of the 100 KiB workloads through the gateway (native, strict, mean per call, before → after
pass 1; DE / EN):

| Part | DE ms | EN ms |
|---|---:|---:|
| Whole call | 25.9 → 12.3 | 24.5 → 12.2 |
| Rule gates and searches (93 rules, each a full-text lazy-DFA scan of about 0.18 ms) | 14.4 → parallel | 14.7 → parallel |
| Validation, scoring and `matched_rules` JSON of about 1 360 matches | 3.4 | 3.4 |
| Drop of the result (1 360 `matched_rules` objects, 1 100 spans) | 2.3 | 2.5 |
| Lowercase view + lexical anchors | 2.3 → 1.0 | 1.0 |
| Overlap resolution, finalize, char offsets | 0.7 | 0.7 |
| Structure parse, deobfuscation view, value runs | 1.1 | 1.4 |

Pass 1 lowercases the ASCII runs of non-ASCII text in place and gates and searches the rules of texts
from 32 KiB on in parallel (rayon); validation, scoring and overlap resolution stay sequential.
Remaining hotspots, each ≥ 10 % of p95, for H06-2: the Python result conversion (ark minus
ark-native, about 9 ms: the `matched_rules` details of every match become Python objects), the
sequential per-match work and the result drop (about 6 ms together), and the rule searches themselves
(CPU time unchanged; a shared literal or multi-pattern prefilter would cut it, but most PII rules start
with their value, not a keyword).
