# Built-in L1 models in Ark Core (S13)

Generated 2026-11-22, branch `threat/175-s13` (base `ab537a3a`).

**What ships.** The eleven S12 fastText-type models, retrained with the S12 command (`ablation.py calibrate --stage FT
--rows train_dev --rows generated --rows agent_scenarios --rows translated --oversample-de 4 --report-rows report`,
`agent_scenarios` again generated dev-side only with the public dev seed; every class reproduces the S12 table), packed
with `category_model.py pack --language-safe-cuts --name ark-l1-<class>-fasttext` into
`ark-core/models/l1/<class>.ftpack`: the folded per-bucket values (2^15 little-endian f64, the form Rust folds a
`model.json` into at load time), the bias difference, the pooled cuts replaced by the strictest of pooled, DE and EN
(detect: highest, clear: lowest) and the DE/EN cuts of `calibration.language_thresholds`. Those cuts are calibrated
on the language Core detects in the text (the facts' `language`), the key Core picks them by, not on the row's
label: each detect cut sits at 0.1 % FPR of the benign rows Core routes to it and rises to its lowest false positive
while a labelled language would exceed 0.1 % (`ablation.py::routed_detect_cuts`); the clear cut at 1 % of the same
rows. Retraining reproduces the shipped bucket values byte for byte; only the cuts moved. They are compiled into
`patronus-ark-core` (`include_bytes!`), so the Rust crate and the Python wheel carry them; nothing is downloaded.

**How they are named.** `cascade.modules.<category>.l1_model: {"builtin": "<class>"}` (`instruction_injection` for the
module `injection`, every other class under its own name). A built-in model only loads for its own module. The L1 model
stage applies the cut of the text facts' language (`de`, `en`) and the strict cut otherwise; configured
`detect_threshold`/`clear_threshold` replace all cuts. Without a cascade, or without `l1_model`, nothing runs
(`builtin_l1_models_run_only_when_a_cascade_names_them`, `without_a_cascade_reports_are_unchanged`).

**Parity.** The packed synthetic fastText model scores the parity goldens bit for bit
(`ark-core/tests/text_model_parity.rs`), and `pack_fasttext` reproduces the checked-in packed file byte for byte
(`scripts/tests/test_l1_threat_category_model.py`). For each shipped model the packed values equal the Python
`FastTextModel` values of its `model.json` (checked by the evaluation below).

**Size.** 262 KB per model, 2 888 911 bytes for all eleven (2.78 MB gzip-compressed: the values hardly compress). The
`.crate` and the wheel grow by about 2.8 MB each (the wheel's native module by 2.9 MB uncompressed); before, an 11 MB
`model.json` per model. Resident: 256 KiB per loaded model, only for the modules a cascade names.

## Per class and language at the shipped cuts (held-out S12 calibration rows)

The S12 calibration half (never a train row; dev benign pool incl. hard benigns, look-alike twins and the M09 chat
pool), scored by the shipped model at the cut Core applies (the cut of the row's detected language, else the strict
one). Language = the row's language label. `clear` / `escalate` / `detect`: share of all the class's rows (positives
and benign) the L1 model clears (at or below the clear cut), escalates (between the cuts; to L3 where a module has one)
and detects. The heuristic decides nothing here: in the calibrated `cascade-config.json` neither heuristic cut is
reachable at 0.1 % / 1 % FPR, so every row the rules do not detect goes to the L1 model (decided shares on the whole dev
split are in `cascade.md`).

| Class | Lang | positives | TPR | benign | FPR | hard-benign FPR | clear % | escalate % | detect % |
|---|---|---|---|---|---|---|---|---|---|
| instruction_injection | DE | 133 | 90.2 | 11726 | 0.06 | 1.48 (5/337) | 98.0 | 1.0 | 1.1 |
| instruction_injection | EN | 1487 | 74.6 | 15585 | 0.10 | 0.00 (0/717) | 90.3 | 3.1 | 6.6 |
| instruction_injection | all | 1620 | 75.9 | 27311 | 0.08 | 0.47 (5/1054) | 93.4 | 2.2 | 4.3 |
| jailbreak | DE | 260 | 90.8 | 11726 | 0.08 | 1.48 (5/337) | 97.0 | 1.0 | 2.0 |
| jailbreak | EN | 1071 | 87.3 | 15585 | 0.10 | 0.84 (6/717) | 92.6 | 1.7 | 5.7 |
| jailbreak | all | 1331 | 88.0 | 27311 | 0.09 | 1.04 (11/1054) | 94.4 | 1.4 | 4.2 |
| prompt_extraction | DE | 192 | 97.4 | 11726 | 0.08 | 0.00 (0/337) | 97.6 | 0.8 | 1.6 |
| prompt_extraction | EN | 7587 | 99.2 | 15585 | 0.10 | 0.14 (1/717) | 66.6 | 0.9 | 32.6 |
| prompt_extraction | all | 7779 | 99.2 | 27311 | 0.09 | 0.09 (1/1054) | 77.1 | 0.8 | 22.1 |
| tool_poisoning | DE | 44 | 100.0 | 11726 | 0.09 | 0.00 (0/337) | 98.3 | 1.2 | 0.5 |
| tool_poisoning | EN | 38 | 100.0 | 15585 | 0.10 | 0.00 (0/717) | 98.8 | 0.9 | 0.3 |
| tool_poisoning | all | 82 | 100.0 | 27311 | 0.09 | 0.00 (0/1054) | 98.6 | 1.0 | 0.4 |
| agent_config_tampering | DE | 45 | 100.0 | 11726 | 0.09 | 0.00 (0/337) | 98.5 | 1.0 | 0.5 |
| agent_config_tampering | EN | 55 | 100.0 | 15585 | 0.04 | 0.00 (0/717) | 98.7 | 0.9 | 0.4 |
| agent_config_tampering | all | 100 | 100.0 | 27311 | 0.06 | 0.00 (0/1054) | 98.6 | 1.0 | 0.4 |
| memory_poisoning | DE | 57 | 100.0 | 11726 | 0.09 | 0.30 (1/337) | 98.4 | 1.0 | 0.6 |
| memory_poisoning | EN | 51 | 100.0 | 15585 | 0.06 | 0.00 (0/717) | 98.8 | 0.9 | 0.4 |
| memory_poisoning | all | 108 | 100.0 | 27311 | 0.08 | 0.09 (1/1054) | 98.6 | 0.9 | 0.5 |
| exfiltration | DE | 45 | 100.0 | 11726 | 0.08 | 0.00 (0/337) | 98.7 | 0.9 | 0.5 |
| exfiltration | EN | 145 | 96.6 | 15585 | 0.10 | 0.00 (0/717) | 97.9 | 1.2 | 1.0 |
| exfiltration | all | 190 | 97.4 | 27311 | 0.09 | 0.00 (0/1054) | 98.2 | 1.0 | 0.8 |
| unsafe_action | DE | 69 | 60.9 | 11726 | 0.09 | 0.00 (0/337) | 98.5 | 1.1 | 0.4 |
| unsafe_action | EN | 265 | 82.6 | 15585 | 0.08 | 0.00 (0/717) | 97.2 | 1.3 | 1.5 |
| unsafe_action | all | 334 | 78.1 | 27311 | 0.09 | 0.00 (0/1054) | 97.8 | 1.2 | 1.0 |
| resource_exhaustion | DE | 47 | 100.0 | 11726 | 0.09 | 0.00 (0/337) | 98.5 | 1.0 | 0.5 |
| resource_exhaustion | EN | 43 | 100.0 | 15585 | 0.10 | 0.00 (0/717) | 98.7 | 0.9 | 0.4 |
| resource_exhaustion | all | 90 | 100.0 | 27311 | 0.10 | 0.00 (0/1054) | 98.6 | 1.0 | 0.4 |
| harmful_content | DE | 164 | 49.4 | 11726 | 0.08 | 0.00 (0/337) | 97.8 | 1.4 | 0.8 |
| harmful_content | EN | 286 | 32.5 | 15585 | 0.10 | 0.14 (1/717) | 97.6 | 1.7 | 0.7 |
| harmful_content | all | 450 | 38.7 | 27311 | 0.09 | 0.09 (1/1054) | 97.7 | 1.6 | 0.7 |
| toxic_language | DE | 111 | 83.8 | 11726 | 0.08 | 0.00 (0/337) | 98.1 | 1.1 | 0.9 |
| toxic_language | EN | 389 | 50.4 | 15585 | 0.10 | 0.00 (0/717) | 96.6 | 2.1 | 1.3 |
| toxic_language | all | 500 | 57.8 | 27311 | 0.09 | 0.00 (0/1054) | 97.2 | 1.7 | 1.1 |

- **German recall holds** with per-language cuts: one cut for both languages (the strict cut alone) cost instruction_injection
  DE 90.2 → 51.9, toxic_language DE 83.8 → 46.8, harmful_content DE 49.4 → 31.7.
- **Within budget in both languages:** every class holds 0.1 % FPR on German and on English text at the cut Core
  applies. Before, the cuts were calibrated per labelled language and Core picked them by detected language, so
  German rows detected as English got an English cut calibrated without them: agent_config_tampering DE was at
  0.13 % (15 of 11 726), now 0.09 % (11). Against the label-calibrated cuts, no TPR drops (unsafe_action DE 59.4 →
  60.9).
- **Hard benigns:** instruction_injection DE 1.48 % (5 of 337 twins; 2.67 % before), jailbreak DE 1.48 % (5 of 337;
  0.89 % before) and EN 0.84 % (6 of 717); agent_config_tampering EN 0.98 % → 0.00 %.

## cascade.md

`cascade-config.json` names the eleven built-in models; `scoreboard.py calibrate` found no reachable heuristic cut, so
the heuristic keeps Core's acceptance and escalates the rest to the L1 model. `cascade.md` is rendered on the whole dev
split, **including the rows the models trained on** (the train half of `train_dev`, `generated`, `translated`), so its
TPR is an upper bound; the table above is the held-out number. Wolf (L3) is off in this config: the Wolf Edge fp32
column at its published settings is not rendered in this round (Wolf bundle not prepared on this host).

## Latency

Defaults are unchanged (no model loads or runs without a cascade that names one), so `scripts/benchmark_injection_l1.py`
and `scripts/l1_dlp/latency.py` measure the same default path. The model stage itself: the S12 per-model cost (p95
3.2–4.4 ms per 100 KiB, `text_model_latency`) is unchanged (same Rust inference, the packed form loads the same
values). In `cascade.md`, the whole scan with all eleven models named goes from p50 0.31 / p95 1.51 ms per dev row
(heuristic only) to p50 0.83 / p95 5.48 ms with every row escalated to the models of all eleven classes (the
native L1 producers alone stay at p50 0.21 / p95 1.57 ms); that cost is opt-in per named module.
