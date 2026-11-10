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
