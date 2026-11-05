# D-BARE (#284): false positives per bare rule and latency

Measured on 2026-11-05 on VPS1 (Intel Core Processor, Haswell without TSX, 6 CPUs, x86-64 Linux),
release builds. Head `48d68918`, base `deb6256e` (`main` before the PR).

## False positives per rule

Each bare rule runs alone, enabled through the `rules` gate. The table counts the spans it adds to
the default gates in the same mode:

- **Hard negatives:** the 2311 PII hard negatives of the goldens (`pii_l1.jsonl`, 1904) and of the
  bilingual fixture (407). Many of them are deliberately bare valid values, which is why they
  count. The goldens themselves run on the default gates and are unchanged.
- **Code and docs:** the pinned benign corpora, dev split (`scripts/l1_dlp/prepare_corpora.py`):
  37.76 MB of code (8 repositories, `benign_code_repos.json`) and 7.54 MB of docs (18F guides,
  de/en Wikipedia, German statutes, Wikimedia; `benign_docs_sources.json`).

```bash
ARK_BENIGN_CODE=~/ark-dlp/data/dev/benign_code ARK_BENIGN_DOCS=~/ark-dlp/data/dev/benign_docs \
  cargo test --release -p patronus-ark --test pii_bare_rules -- --ignored --nocapture
```

| Rule | Hard-negative spans strict / balanced | Code FP per MB strict / balanced | Docs FP per MB strict / balanced |
|---|---:|---:|---:|
| `pii_steuer_id_de_bare` | 8 / 5 | 0.00 / 0.00 | 0.00 / 0.00 |
| `pii_steuernummer_de_bare` | 6 / 0 | 0.00 / 0.00 | 0.13 / 0.00 |
| `pii_physician_number_lanr_de_bare` | 10 / 10 | 0.72 / 0.72 | 0.00 / 0.00 |
| `pii_facility_number_bsnr_de_bare` | 59 / 0 | 6.09 / 0.00 | 0.00 / 0.00 |
| `pii_driver_license_number_de_bare` | 64 / 0 | 0.03 / 0.00 | 0.00 / 0.00 |
| `pii_ssn_us_bare` | 60 / 0 | 5.93 / 0.00 | 0.00 / 0.00 |
| `pii_sin_ca_bare` | 24 / 24 | 0.58 / 0.58 | 0.00 / 0.00 |
| `pii_aadhaar_in_bare` | 6 / 6 | 0.00 / 0.00 | 0.00 / 0.00 |
| `pii_npi_us_bare` | 7 / 7 | 0.16 / 0.16 | 0.00 / 0.00 |
| `pii_pesel_pl_bare` | 8 / 8 | 0.00 / 0.00 | 0.00 / 0.00 |
| `pii_acn_au_bare` | 13 / 13 | 0.56 / 0.56 | 0.00 / 0.00 |
| `pii_brn_kr_bare` | 7 / 7 | 0.32 / 0.32 | 0.00 / 0.00 |
| `pii_pan_in_bare` | 6 / 0 | 0.00 / 0.00 | 0.00 / 0.00 |
| `pii_voter_id_in_bare` | 7 / 0 | 0.00 / 0.00 | 0.00 / 0.00 |
| `pii_vehicle_registration_ng_bare` | 13 / 0 | 0.00 / 0.00 | 0.00 / 0.00 |

The format-only rules (BSNR, driver's licence, SSN, PAN, voter ID, Nigerian plate, Steuernummer)
score `0.30` and add nothing in `balanced`; in `strict` the 9-digit BSNR and SSN forms are the
noisiest on code (any free-standing 9-digit number in the SSA ranges or BSNR format).

## Latency (default gates)

The default output is unchanged; the bare rules stay off, but they are entries of `PII_PATTERNS`
that every scan walks. `scripts/l1_presidio/latency.py run --engines ark ark-native` on base and
head, four alternating pairs on a host without other ARK jobs, then `latency.py compare` per pair
(gate: 100 KiB p95 at most +10 %; every pair passed for both engines):

| Pair | ark base → head ms | ark-native base → head ms |
|---|---:|---:|
| 1 | 13.147 → 12.808 | 11.133 → 9.191 |
| 2 | 12.609 → 13.640 | 10.131 → 10.017 |
| 3 | 12.221 → 11.809 | 9.487 → 8.985 |
| 4 | 13.297 → 13.340 | 10.200 → 9.476 |
| Median | 12.878 → 13.074 (+1.5 %) | 10.166 → 9.334 (−8.2 %) |

The spread between pairs (up to 17 % on the same commit) is larger than the difference, so the
change has no measurable effect on default-gate latency. The `ark-native` 100 KiB p95 of base is
already at the 10 ms M4 line on this host (Haswell, no VNNI); the head does not move it.
