# DLP L1 latency and throughput (H03)

Performance loop after all rules (`research/dlp/backlog.yaml`, H03). Budget: 100 KiB p95 ≤ 10 ms,
throughput ≥ gitleaks on the same machine, prefilter coverage 100 %, no quality change.

Machine: VPS, 6 vCPU, every process pinned to one CPU. ARK in process
(`SecurityGateway.scan_category("dlp", text)`, default profile, release build); gitleaks as its
pinned binary. Workloads from the frozen dev split (`scripts/l1_dlp/latency.py`): `short`
(256 carrier rows), `4 KiB` (64 documents), `100 KiB` (32 documents, one carrier row per 4 KiB
of benign code), `10 MiB repo` (938 benign-code files, one carrier file per 64 KiB).

## Pass 1 (2026-11-10)

### Head vs. gitleaks

`python3 scripts/l1_dlp/latency.py bench --dev $ARK_L1_DEV_DATA --tools ark,gitleaks --rounds 3 --invocations 4`

| tool | workload | docs | MiB | p50 ms | p95 ms | scan MiB/s | end-to-end MiB/s | start ms |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| ark | short | 256 | 0.07 | 0.312 | 0.991 | 0.72 | 0.05 | 1255.7 |
| ark | 4 KiB | 64 | 0.25 | 0.609 | 1.190 | 6.27 | 0.19 | 1255.7 |
| ark | 100 KiB | 32 | 3.12 | 10.463 | 16.898 | 9.79 | 1.98 | 1255.7 |
| ark | 10 MiB repo | 938 | 10.00 | 0.320 | 2.220 | 6.40 | 3.55 | 1255.7 |
| gitleaks | short | 256 | 0.07 | 599.821 | 1027.514 | 0.08 | 0.04 | 801.1 |
| gitleaks | 4 KiB | 64 | 0.25 | 736.553 | 1158.280 | 0.42 | 0.18 | 801.1 |
| gitleaks | 100 KiB | 32 | 3.12 | 1340.019 | 1864.989 | 0.44 | 0.39 | 801.1 |
| gitleaks | 10 MiB repo | 938 | 10.00 | – | – | 2.92 | 2.36 | 801.1 |

Throughput ≥ gitleaks holds on every workload (10 MiB repo: 6.40 vs. 2.92 MiB/s scan,
3.55 vs. 2.36 MiB/s end to end). The 100 KiB p95 budget does not hold yet (16.9 ms).

### Base → head

Same workloads and gateway, three rounds in one process pinned to one CPU (the in-process loop
of `latency.py`; main `63ba1a6c` → head):

| workload | p50 ms | p95 ms | MB/s |
|---|---:|---:|---:|
| short | 0.39 → 0.35 | 1.79 → 1.46 | 0.32 → 0.41 |
| 4 KiB | 0.67 → 0.65 | 2.78 → 1.66 | 2.67 → 3.42 |
| 100 KiB | 11.40 → 10.30 | 19.07 → 18.67 | 8.34 → 9.30 |
| 10 MiB repo | 0.33 → 0.29 | 2.17 → 1.84 | 4.96 → 7.52 |

Native gateway alone (Rust, same 100 KiB documents): p50 about 9.3 ms, p95 about 12.5 ms in
both builds; the Python figures add the binding and result conversion.

### Profile

Per-rule timing of the 100 KiB workload (default profile, rules run one after another; perf
sampling is not permitted on the VPS, so a temporary example timed `rule_matches` and
`accepted_matches` per rule). Rule regex and validation take about 90 % of the scan; the rule
prefilter about 7 %. Top rules before the fix, ms per 32 documents:

| rule | total | regex | note |
|---|---:|---:|---|
| `dlp_generic_credential_assignment` | 67 | 27 | 461 matches; validation (`allows_match`, example and placeholder checks) |
| `dlp_cli_password` | 23 | 23 | 0 matches; lazy-DFA cache thrash |
| `dlp_prose_secret` | 22 | 22 | lazy-DFA cache thrash |
| `dlp_env_var_secret` | 18 | 3 | 115 matches; validation |
| `dlp_bip39_seed_phrase` | 18 | 18 | word finder |
| `dlp_btc_wif` | 12 | 12 | |
| `dlp_jwk_private_key` | 7 | 7 | lazy-DFA cache thrash (a whole-text scan 53 ms) |

On the 10 MiB repo, minified JS bundles dominate: `swagger-ui-es-bundle.js` (1.5 MiB) took
515 ms, of which `dlp_url_userinfo_password` 239 ms and `dlp_url_userinfo_token` 108 ms with no
match (Unicode `\b` makes the lazy DFA quit at the first non-ASCII byte, the NFA scans the rest).

### Change

The large case-insensitive rules outgrew the 2 MiB default lazy-DFA cache of `regex` on 100 KiB
texts: the cache was cleared again and again and the search fell back to the NFA. Rule regexes
and the anchored keyword-window probes now get a 16 MiB cache (`prefilter::RULE_DFA_CACHE_BYTES`,
grown only as far as a search needs it; 8 MiB was the smallest size that held). Whole-text scan
per 32 documents: `dlp_cli_password` 916 → 8.5 ms, `dlp_jwk_private_key` 53 → 3.6 ms,
`dlp_prose_secret` 17 → 2.5 ms. Results are identical (`rust/tests/dlp_rule_prefilter.rs`), the
DLP goldens unchanged (1183/1183 positives, 2239/2239 hard negatives).

Tried and dropped (no measurable gain): probing only start bytes a match can begin with in the
keyword windows; switching dense keyword rules to whole-text scans (`LOCAL_DENSITY` 8 → 128).

### Prefilter coverage

100 %: every DLP rule has a keyword or structural gate proven from its regex, enforced by
`rust/tests/dlp_rule_prefilter.rs`.

### Remaining hotspots → H03-2

The budget is not met, and hotspots worth ≥ 10 % of the 100 KiB p95 remain, so H03-2 follows:

- `dlp_generic_credential_assignment` validation: about 25 % of the 100 KiB rule time, spread
  over the `allows_match` checks (example, placeholder, fixed-format, entropy);
- `dlp_env_var_secret` validation and the `dlp_bip39_seed_phrase` finder;
- `dlp_url_userinfo_password` / `dlp_url_userinfo_token` on non-ASCII bundles (repo throughput);
  candidate fix: the boundary-free DFA search with anchored probes of the PII H03 pass.

## Pass 2 (2026-11-10, H03-2)

### Head vs. gitleaks

`python3 scripts/l1_dlp/latency.py bench --dev $ARK_L1_DEV_DATA --tools ark,gitleaks --rounds 3 --invocations 4`

| tool | workload | docs | MiB | p50 ms | p95 ms | scan MiB/s | end-to-end MiB/s | start ms |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| ark | short | 256 | 0.07 | 0.374 | 1.196 | 0.49 | 0.05 | 1150.6 |
| ark | 4 KiB | 64 | 0.25 | 0.670 | 1.284 | 5.08 | 0.21 | 1150.6 |
| ark | 100 KiB | 32 | 3.12 | 10.380 | 15.295 | 9.94 | 2.13 | 1150.6 |
| ark | 10 MiB repo | 938 | 10.00 | 0.290 | 1.817 | 9.91 | 4.63 | 1150.6 |
| gitleaks | short | 256 | 0.07 | 598.511 | 614.116 | 0.07 | 0.04 | 624.4 |
| gitleaks | 4 KiB | 64 | 0.25 | 621.366 | 655.801 | 0.27 | 0.16 | 624.4 |
| gitleaks | 100 KiB | 32 | 3.12 | 737.464 | 778.326 | 0.46 | 0.42 | 624.4 |
| gitleaks | 10 MiB repo | 938 | 10.00 | – | – | 4.07 | 3.24 | 624.4 |

Against pass 1 (same machine and script): 100 KiB p95 16.9 → 15.3 ms (p50 unchanged at about
10.4 ms), 10 MiB repo scan 6.40 → 9.91 MiB/s and end to end 3.55 → 4.63 MiB/s. Throughput ≥
gitleaks holds on every workload (repo 9.91 vs. 4.07 MiB/s scan). The 100 KiB p95 budget does
not hold yet.

### Profile

Per-rule timing of the native DLP pipeline (default profile, strict mode, a temporary example
that timed `rule_matches`, `structured_values` and `accepted_matches` per rule; ms per workload
round). The native pipeline alone has a 100 KiB p95 of about 6–8 ms on the same documents.

| rule / step | workload | before | after | note |
|---|---|---:|---:|---|
| `dlp_url_userinfo_password` regex | 10 MiB repo | 252.7 | 12.1 | Unicode `\b` on non-ASCII bundles |
| `dlp_url_userinfo_token` regex | 10 MiB repo | 116.4 | 12.5 | same |
| all rules | 10 MiB repo | 951 | about 500 | |
| `dlp_generic_credential_assignment` structured values | 100 KiB | 31.8 | 18.2 | `key_value_line` captures |
| all rules | 100 KiB | about 320 | about 280 | |

### Change

- A DLP rule that scans the whole text and has a Unicode word boundary searches a text with a
  non-ASCII character without its word boundaries, on the lazy DFA, and probes each start
  anchored with its own regex (`prefilter::Relaxed`, the shared `word_boundary` helpers of the
  PII H03 pass). ASCII texts and the keyword-window rules are searched as before.
- `structure::key_value_line` (the config-line reader of K05) ran the capture engine over each
  whole candidate line for its lazy value group (about 35 µs per call); only the short key
  prefix runs on a regex now, the value is read off the rest of the line.

Results are identical: `rust/tests/dlp_rule_prefilter.rs` (every golden and fixture text, also
after multi-byte text), `key_value_line_matches_the_full_line_regex`, the DLP goldens unchanged.

Tried and dropped: a DFA for the shared lexical-anchor automaton (6,399 words). The presence
scan per 100 KiB document went from about 1.2 to 0.7 ms, but the automaton takes 46.6 MB instead
of 0.8 MB and 135 instead of 19 ms to build, for every process and all four categories.

### Remaining hotspots → H03-3

The budget is not met, and hotspots worth ≥ 10 % of the 100 KiB p95 remain, so H03-3 follows:

- the gateway above the DLP pipeline: 15.3 ms p95 through `SecurityGateway.scan_category` vs.
  about 6–8 ms for the native pipeline on the same documents (text preparation, the D01 decoded
  view, the Python binding and result conversion); to be profiled first;
- the lexical-anchor presence scan (Aho-Corasick NFA over the shared lexicon, about 1.2 ms per
  100 KiB document, about 8 % of p95), paid by every text that opens an anchor-gated rule;
- the generic tier: `dlp_generic_credential_assignment` regex (about 1 ms per document) and its
  config-value binding and validation (about 0.7 ms);
- the regexes of `dlp_prose_secret`, `dlp_openai_key`, `dlp_anthropic_key`, `dlp_xai_key` and
  the `dlp_bip39_seed_phrase` finder (0.4–0.8 ms per 100 KiB document each).
