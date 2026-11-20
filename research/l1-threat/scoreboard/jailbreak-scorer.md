# Jailbreak scorer choice (JB02)

Generated 2026-11-20 on branch `threat/130-jb02` (base `fc203c03`) with `scripts/l1_threat/ablation.py
calibrate --class jailbreak`. Facts: `text_facts --threat-findings` (release build) over `$ARK_L1_DEV_DATA`
`train_dev`, `generated` and `report`.

- **Single source (S10 setup):** `--rows train_dev --eval-rows generated`. The candidate trains on the hash
  half of `train_dev`; its only jailbreak source is WildJailbreak (`adversarial_harmful`, 2 000 rows).
- **Mix:** `--rows train_dev --rows generated`. Both files split by the same row-id hash: the train half adds
  the generated jailbreak carriers (class templates, carrier insertion, obfuscation slices; DE and EN) and
  the look-alike twins as hard negatives; the other half calibrates. No calibration row was seen in training.

Cuts at 0.1 % FPR (detect) and 1 % FPR (clear) on the benign calibration rows (dev benign pool incl. the
hard benigns and twins). `gen. held-out`: jailbreak positives of the generated half that no candidate
trained on (82 rows), at the detect cut. `jackhhao matched`: TPR at 1 % / 0.1 % FPR on the
`jackhhao_jailbreak` report set (out of distribution, never trained or calibrated on), each at its own
matched cut. ms/100 KiB: p95 of the model on top of the facts (`text_model_latency`), median of three runs
on the same six 100 KiB German windows (GermanQuAD dev text; the E03 corpus is not on this host), so only
the A/B between rows is meaningful.

| Candidate | train rows | benign cal. rows | TPR@0.1% all | DE | EN | gen. held-out | jackhhao matched @1% / @0.1% | twins FP | ms/100 KiB p95 | RAM KiB |
|---|---|---|---|---|---|---|---|---|---|---|
| FT, WildJailbreak only (S10) | 25 433 | 17 002 | 81.3 | 0.0 (0/42) | 84.2 | 18/82 | 2.6 / 0.6 | 3/1 800 | 3.05 | 256 |
| **FT, mix (chosen)** | 27 202 | 16 102 | **89.2** | **100.0 (24/24)** | **89.0** | **57/82** | 3.5 / 0.7 | 0/900 | 3.21 | 256 |
| B4 hashed TF-IDF + LR, mix | 27 202 | 16 102 | 95.7 | 100.0 (24/24) | 95.6 | 66/82 | 48.3 / 20.0 | 0/900 | 13.24 | 576 |

Comparison values from `baseline.md` (full gated dev split, matched FPR): rules and scorer today (B0)
5.4 / 5.4 TPR@1 % / 0.1 %; best heuristic baseline 56.2 / 12.9 (prompt_guard heuristic); on the report set
`jackhhao_jailbreak` the best heuristic is 89.9 / 70.0 (ATR). The candidates are measured on the
calibration half, not on the same rows as the baselines (the baseline cache is not readable on this host).

**Choice:** `FT` trained on the mix. Within the accepted ~4 ms per model it is the best candidate at
0.1 % FPR on dev (89.2 vs 81.3 for S10's single-source model, German 0 → 24/24, generated held-out positives
18 → 57 of 82) and clears every look-alike twin. `B4` is better on every quality column but costs ~13 ms
per 100 KiB, over the budget. Model file: sha256 `d15ce3ae13c9…` (11.2 MB JSON, not checked in; the
command above rebuilds it deterministically from the frozen dev data). Nothing is wired into the scan path:
it runs only when a cascade configures it as `cascade.modules.jailbreak.l1_model`.

**Open / regressions named:**
- Out of distribution the fastText-type model does not carry: on `jackhhao_jailbreak` it reaches 3.5 / 0.7
  at matched FPR, far below ATR's 89.9 / 70.0; at the dev detect cut it flags 5.45 % of that set's benigns
  and 3.14 % of `civil_comments`. More jailbreak sources for training are needed (the only native one is
  WildJailbreak; the report set must stay untouched).
- Hard benigns at the detect cut: WildJailbreak `adversarial_benign` 7/12, WildGuardMix 2/243 (0.82 %).
- German positives are generated rows only (24); there is no native German jailbreak source in dev.
- Latency A/B of this change in the default scan: 0 ms (no model enabled). With the model configured the
  jailbreak module adds ~3.2 ms p95 per 100 KiB.

## Per-source table of the chosen candidate

| Scope | Source | rows | FP | FPR |
|---|---|---|---|---|
| calibration | agent_safetybench | 31 | 0 | 0.00 |
| calibration | agentdojo | 66 | 0 | 0.00 |
| calibration | approve_or_deny_de | 24 | 0 | 0.00 |
| calibration | bipia | 21 | 0 | 0.00 |
| calibration | dolly_15k | 7439 | 6 | 0.08 |
| calibration | germanquad | 5690 | 0 | 0.00 |
| calibration | spml | 1676 | 1 | 0.06 |
| calibration | twins | 900 | 0 | 0.00 |
| calibration | wildguardmix | 243 | 2 | 0.82 |
| calibration | wildjailbreak | 12 | 7 | 58.33 |
| report | civil_comments | 5856 | 184 | 3.14 |
| report | jackhhao_jailbreak | 1321 | 72 | 5.45 |
| report | textdetox_de | 2492 | 0 | 0.00 |
