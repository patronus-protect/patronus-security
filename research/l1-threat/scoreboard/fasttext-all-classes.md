# fastText-type L1 models for all eleven classes (S12)

Generated 2026-11-22 with `scripts/l1_threat/ablation.py calibrate --stage FT` per class, branch
`threat/173-s12` (base `8720eae6`). Same model form as S10/S11 (2^15 × 16 buckets, 256 KiB resident), same setup as
S11 (German train positives ×4), on every dev set there is:

    ablation.py calibrate --rows train_dev --rows generated --rows agent_scenarios --rows translated \
        --oversample-de 4 --report-rows report --class <class> --model-out <class>.model.json --out <class>.json

- **Facts:** `text_facts --threat-findings` (release build) over `$ARK_L1_DEV_DATA` `train_dev` (incl. the M09
  chat pool `massive_de`/`massive_en` and `simple_safety_tests`), `generated`, `translated`
  (`runner_translations_de`) and `report`.
- **`agent_scenarios`** (the M09 second generator family for the four agent classes) is **not yet frozen in DEV**
  (DEV/generated is still generator version 7). It was generated for this run, dev side only, with the public dev
  seed: `generators.py generate --dev-out /tmp/dev8` with `train_dev` and `translated` linked from DEV (no
  `--holdout-out`, no holdout read or written). The four existing sets came out byte-identical to DEV/generated;
  `agent_scenarios` is what the owner command from M09 (`generators.py generate --dev-out ~/ark-threat/data/dev
  --holdout-out ~/ark-threat/holdout`, generator version 8) writes into DEV.
- **Split:** template-disjoint as in S11, plus (new in S12) the template families of one class set take turns in
  sha256 order (`split_rows`, test `test_split_puts_one_template_family_of_every_class_on_each_side`). Before, the
  hash put both `class_templates` families of resource_exhaustion on the eval side (no train positive) and both of
  tool_poisoning on the train side (no eval positive). Rows outside the generators keep the hash split.
- **Benign pool:** the held-out half of every benign row: dev benign pool incl. hard benigns, look-alike twins
  (incl. those of `agent_scenarios`) and the M09 chat pool; never a train negative (`calibration_rows`). 39 773
  calibration rows, 27 311 of them benign (DE 11 726, EN 15 585). Detect cut at 0.1 % FPR and clear cut at 1 % FPR **per language** on that language's benign rows.
- **Rules only:** a rule finding of the class in the text facts (`R`), on the same rows. The injection-detector
  classes (instruction_injection, jailbreak, prompt_extraction) and the content classes (harmful_content,
  toxic_language) have no text-facts rule findings, so their rules-only column is 0; their rule and scorer numbers
  are in `baseline.md` (B0). memory_poisoning's MP01 rules sit in the injection detector too.

## Result per class

TPR in % at the language's own cut; FPR in % on that language's benign rows (≤ 0.1 % for every class and language).
"Without agent_scenarios" is the same command without that file (today's DEV) — the fix of the agent classes.
"report FPR" is the out-of-distribution report sets (`civil_comments`, `jackhhao_jailbreak`, `textdetox_de`, …)
at the pooled dev detect cut; they never move a cut.

| Class | DE TPR@0.1% | EN TPR@0.1% | rules-only DE | rules-only EN | DE TPR@1% (clear) | EN TPR@1% (clear) | FPR DE / EN | without agent_scenarios DE / EN | positives DE / EN | positive sources DE / EN | report FPR |
|---|---|---|---|---|---|---|---|---|---|---|---|
| instruction_injection | 90.2 | 74.6 | 0.0 | 0.0 | 99.2 | 99.6 | 0.09 / 0.10 | 90.2 / 74.4 | 133 / 1487 | 6 / 7 | 0.37 |
| jailbreak | 90.8 | 87.3 | 0.0 | 0.0 | 99.6 | 99.7 | 0.09 / 0.10 | 89.6 / 86.6 | 260 / 1071 | 2 / 6 | 3.34 |
| prompt_extraction | 97.4 | 99.2 | 0.0 | 0.0 | 100.0 | 99.9 | 0.09 / 0.10 | 97.4 / 99.3 | 192 / 7587 | 5 / 5 | 2.08 |
| tool_poisoning | 100.0 | 100.0 | 43.2 | 39.5 | 100.0 | 100.0 | 0.09 / 0.10 | 0.0 / 0.0 | 44 / 38 | 2 / 2 | 0.60 |
| agent_config_tampering | 100.0 | 100.0 | 48.9 | 43.6 | 100.0 | 100.0 | 0.09 / 0.09 | 0.0 / 0.0 | 45 / 55 | 2 / 2 | 0.33 |
| memory_poisoning | 100.0 | 100.0 | 0.0 | 0.0 | 100.0 | 100.0 | 0.09 / 0.08 | 0.0 / 0.0 | 57 / 51 | 2 / 2 | 0.41 |
| exfiltration | 100.0 | 96.6 | 100.0 | 67.6 | 100.0 | 100.0 | 0.09 / 0.10 | 100.0 / 96.6 | 45 / 145 | 1 / 7 | 0.26 |
| unsafe_action | 59.4 | 82.6 | 27.5 | 92.8 | 72.5 | 93.2 | 0.09 / 0.10 | 60.9 / 82.6 | 69 / 265 | 6 / 8 | 0.06 |
| resource_exhaustion | 100.0 | 100.0 | 44.7 | 51.2 | 100.0 | 100.0 | 0.09 / 0.10 | 0.0 / 0.0 | 47 / 43 | 2 / 2 | 0.37 |
| harmful_content | 51.8 | 32.5 | 0.0 | 0.0 | 90.9 | 76.6 | 0.09 / 0.10 | 53.7 / 32.2 | 164 / 286 | 1 / 2 | 0.02 |
| toxic_language | 83.8 | 50.4 | 0.0 | 0.0 | 98.2 | 88.4 | 0.09 / 0.10 | 83.8 / 51.9 | 111 / 389 | 2 / 2 | 5.73 |

Rules-only FPR is 0.00 for every class and language (rules use none of the budget, as in S10).

Cost per model (all eleven the same form): `model.json` 11.2–11.5 MB serialised, 256 KiB resident (RAM estimate
262 144 bytes each). p95 ms per 100 KiB with `text_model_latency --tokens tf1`, median of three solo runs on an idle
host: tool_poisoning 3.94, memory_poisoning 3.79, resource_exhaustion 4.34, agent_config_tampering 3.49,
instruction_injection 4.37, harmful_content 3.18 — the S10/S11 band (3.1–4.9 ms), within the ~4 ms per model
budget up to noise. The E03 latency corpus is not on this host; the windows are 17 × 100 KiB packed from
`germanquad` and `dolly_15k` dev text. Rust inference and the model form are unchanged, so the parity goldens
(`ark-core/tests/text_model_parity.rs`, fastText-type model included) still cover these models bit-exact. Nothing
is wired into a scan path; S13 ships the models and hangs them into the cascade.

## Findings

- **agent_config_tampering, tool_poisoning, memory_poisoning, resource_exhaustion: 0 → 100 / 100.** Without
  `agent_scenarios` each class trains on at most one `class_templates` family (~45 rows) and finds 0 of the other
  family at 0.1 % FPR (agent_config_tampering 0/0 again, the S10 number; the other three likewise 0/0). With it, each
  class has five families (three train, two held out). The held-out `class_templates` families are found in full
  although the model trained mostly on another generator (tool_poisoning `mcp_tool_description` 34/34,
  agent_config_tampering `rules_file` 46/46, resource_exhaustion `repetition_request` 43/43), so it is transfer
  across generators, not memorised templates. It is still synthetic only: the directive pools of one generator are
  shared between its families, the positives come from two sources per language, and 100 % is an upper bound for
  what a new source would give. The report sets flag 0.33–0.60 % at these cuts (above the 0.1 % in-pool budget).
- **The other seven classes** move by at most one or two rows against the same run without `agent_scenarios`
  (its benign look-alike twins join the pool): jailbreak DE +1.2 / EN +0.7, harmful_content DE −1.9 (3 of 164) /
  EN +0.3, toxic_language EN −1.5 (6 of 389), unsafe_action DE −1.5 (1 of 69), the rest ±0.2. Against S11
  (`fasttext-language-cuts.md`, another pool: no chat pool, no `translated`, no `simple_safety_tests`), the
  German numbers rose with the translated rows: instruction_injection DE 65.7 → 90.2, jailbreak DE 0 → 90.8,
  prompt_extraction DE – → 97.4 (192 positives).
- **Rules vs model:** unsafe_action EN is the one class where the rules alone (92.8) beat the model (82.6); exfiltration
  DE both 100. In the cascade the rules decide first, so the model adds what the rules miss.
- **Open:** harmful_content (DE 1 source) and toxic_language stay the weakest (EN 32.5 / 50.4); toxic_language has
  the highest out-of-distribution FPR (5.73 %, `civil_comments`), jailbreak 3.34 % (`jackhhao_jailbreak` benigns).
  Both need a second open source per language (M09 open item).

## Owner command

To make the agent-class numbers reproducible from DEV, freeze generator version 8 (M09):

    python3 scripts/l1_threat/generators.py generate --dev-out ~/ark-threat/data/dev --holdout-out ~/ark-threat/holdout

## Calibration report

| Class | Stage | benign rows | detect cut | TPR all | TPR DE | TPR EN | FPR | FPR at train-negative cut | ms/100 KiB | RAM KiB |
|---|---|---|---|---|---|---|---|---|---|---|
| instruction_injection | FT | 27311 | 4.0239 | 80.1 | 58.6 | 82.0 | 0.10 | 0.21 | – | 256.0 |
| jailbreak | FT | 27311 | 2.6440 | 92.1 | 88.8 | 92.9 | 0.10 | 0.67 | – | 256.0 |
| prompt_extraction | FT | 27311 | 0.6599 | 99.1 | 83.3 | 99.5 | 0.10 | 0.42 | – | 256.0 |
| tool_poisoning | FT | 27311 | -2.4164 | 100.0 | 100.0 | 100.0 | 0.10 | 0.01 | – | 256.0 |
| agent_config_tampering | FT | 27311 | -1.4299 | 100.0 | 100.0 | 100.0 | 0.10 | 0.03 | – | 256.0 |
| memory_poisoning | FT | 27311 | -2.2301 | 100.0 | 100.0 | 100.0 | 0.10 | 0.04 | – | 256.0 |
| exfiltration | FT | 27311 | 0.8712 | 99.5 | 100.0 | 99.3 | 0.10 | 0.14 | – | 256.0 |
| unsafe_action | FT | 27311 | 3.4039 | 77.8 | 59.4 | 82.6 | 0.10 | 0.22 | – | 256.0 |
| resource_exhaustion | FT | 27311 | -1.8540 | 100.0 | 100.0 | 100.0 | 0.10 | 0.02 | – | 256.0 |
| harmful_content | FT | 27311 | 4.3557 | 34.7 | 34.1 | 35.0 | 0.10 | 0.78 | – | 256.0 |
| toxic_language | FT | 27311 | 3.1994 | 57.6 | 58.6 | 57.3 | 0.10 | 0.78 | – | 256.0 |

## Per-language cuts

Each language's detect cut sits at the target FPR and its clear cut at the clear FPR of that language's benign rows; rules only is a rule finding of the class on the same rows.

| Class | Language | benign rows | detect cut | TPR | FPR | clear cut | TPR at clear | FPR at clear | rules-only TPR | rules-only FPR | positives | positive sources |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| instruction_injection | DE | 11726 | 1.4290 | 90.2 | 0.09 | -1.5706 | 99.2 | 1.00 | 0.0 | 0.00 | 133 | 6 |
| instruction_injection | EN | 15585 | 4.5557 | 74.6 | 0.10 | -0.1556 | 99.6 | 0.99 | 0.0 | 0.00 | 1487 | 7 |
| jailbreak | DE | 11726 | 2.0250 | 90.8 | 0.09 | -0.6661 | 99.6 | 1.00 | 0.0 | 0.00 | 260 | 2 |
| jailbreak | EN | 15585 | 3.3726 | 87.3 | 0.10 | -0.1202 | 99.7 | 0.99 | 0.0 | 0.00 | 1071 | 6 |
| prompt_extraction | DE | 11726 | -1.0073 | 97.4 | 0.09 | -2.7187 | 100.0 | 0.99 | 0.0 | 0.00 | 192 | 5 |
| prompt_extraction | EN | 15585 | 1.2304 | 99.2 | 0.10 | -1.5432 | 99.9 | 0.99 | 0.0 | 0.00 | 7587 | 5 |
| tool_poisoning | DE | 11726 | -2.4498 | 100.0 | 0.09 | -3.5524 | 100.0 | 0.98 | 43.2 | 0.00 | 44 | 2 |
| tool_poisoning | EN | 15585 | -2.3897 | 100.0 | 0.10 | -3.7194 | 100.0 | 0.99 | 39.5 | 0.00 | 38 | 2 |
| agent_config_tampering | DE | 11726 | -1.3332 | 100.0 | 0.09 | -2.9446 | 100.0 | 0.99 | 48.9 | 0.00 | 45 | 2 |
| agent_config_tampering | EN | 15585 | -1.7015 | 100.0 | 0.09 | -3.0883 | 100.0 | 0.99 | 43.6 | 0.00 | 55 | 2 |
| memory_poisoning | DE | 11726 | -1.9364 | 100.0 | 0.09 | -3.1041 | 100.0 | 1.00 | 0.0 | 0.00 | 57 | 2 |
| memory_poisoning | EN | 15585 | -2.2777 | 100.0 | 0.08 | -3.5755 | 100.0 | 0.99 | 0.0 | 0.00 | 51 | 2 |
| exfiltration | DE | 11726 | -0.2264 | 100.0 | 0.09 | -3.4771 | 100.0 | 1.00 | 100.0 | 0.00 | 45 | 1 |
| exfiltration | EN | 15585 | 1.6179 | 96.6 | 0.10 | -1.8863 | 100.0 | 0.99 | 67.6 | 0.00 | 145 | 7 |
| unsafe_action | DE | 11726 | 3.3837 | 59.4 | 0.09 | -2.8338 | 72.5 | 1.00 | 27.5 | 0.00 | 69 | 6 |
| unsafe_action | EN | 15585 | 3.4417 | 82.6 | 0.10 | -0.3890 | 93.2 | 0.99 | 92.8 | 0.00 | 265 | 8 |
| resource_exhaustion | DE | 11726 | -2.0224 | 100.0 | 0.09 | -3.3353 | 100.0 | 1.00 | 44.7 | 0.00 | 47 | 2 |
| resource_exhaustion | EN | 15585 | -1.7735 | 100.0 | 0.10 | -3.6317 | 100.0 | 0.99 | 51.2 | 0.00 | 43 | 2 |
| harmful_content | DE | 11726 | 3.0161 | 51.8 | 0.09 | -0.8793 | 90.9 | 1.00 | 0.0 | 0.00 | 164 | 1 |
| harmful_content | EN | 15585 | 4.7755 | 32.5 | 0.10 | 0.3003 | 76.6 | 0.99 | 0.0 | 0.00 | 286 | 2 |
| toxic_language | DE | 11726 | 1.1516 | 83.8 | 0.09 | -2.2752 | 98.2 | 1.00 | 0.0 | 0.00 | 111 | 2 |
| toxic_language | EN | 15585 | 3.8091 | 50.4 | 0.10 | -0.1240 | 88.4 | 0.99 | 0.0 | 0.00 | 389 | 2 |

## instruction_injection DE: sources at the DE cut

| Kind | Source | rows | hits | rate |
|---|---|---|---|---|
| benign | approve_or_deny_de | 24 | 0 | 0.00 |
| benign | germanquad | 5690 | 0 | 0.00 |
| benign | massive_de | 5600 | 2 | 0.04 |
| benign | runner_translations_de | 75 | 0 | 0.00 |
| benign | twins | 337 | 9 | 2.67 |
| positive | carrier_insertion:blog_post | 6 | 6 | 100.0 |
| positive | carrier_insertion:helpdesk | 14 | 5 | 35.7 |
| positive | carrier_insertion:kb_chunk | 11 | 11 | 100.0 |
| positive | carrier_insertion:report_page | 15 | 13 | 86.7 |
| positive | cyberseceval_multilingual | 5 | 4 | 80.0 |
| positive | runner_translations_de | 82 | 81 | 98.8 |

## instruction_injection EN: sources at the EN cut

| Kind | Source | rows | hits | rate |
|---|---|---|---|---|
| benign | agent_safetybench | 31 | 0 | 0.00 |
| benign | agentdojo | 66 | 3 | 4.55 |
| benign | bipia | 21 | 4 | 19.05 |
| benign | dolly_15k | 7439 | 3 | 0.04 |
| benign | massive_en | 5635 | 5 | 0.09 |
| benign | spml | 1676 | 0 | 0.00 |
| benign | twins | 462 | 0 | 0.00 |
| benign | wildguardmix | 243 | 0 | 0.00 |
| benign | wildjailbreak | 12 | 0 | 0.00 |
| positive | agentdojo | 67 | 42 | 62.7 |
| positive | bipia | 89 | 33 | 37.1 |
| positive | carrier_insertion:blog_post | 17 | 4 | 23.5 |
| positive | carrier_insertion:helpdesk | 41 | 7 | 17.1 |
| positive | carrier_insertion:kb_chunk | 32 | 10 | 31.2 |
| positive | carrier_insertion:report_page | 38 | 10 | 26.3 |
| positive | spml | 1203 | 1004 | 83.5 |

## jailbreak DE: sources at the DE cut

| Kind | Source | rows | hits | rate |
|---|---|---|---|---|
| benign | approve_or_deny_de | 24 | 0 | 0.00 |
| benign | germanquad | 5690 | 1 | 0.02 |
| benign | massive_de | 5600 | 6 | 0.11 |
| benign | runner_translations_de | 75 | 0 | 0.00 |
| benign | twins | 337 | 3 | 0.89 |
| positive | class_templates:refusal_suppression | 20 | 0 | 0.0 |
| positive | xl_safetybench | 240 | 236 | 98.3 |

## jailbreak EN: sources at the EN cut

| Kind | Source | rows | hits | rate |
|---|---|---|---|---|
| benign | agent_safetybench | 31 | 1 | 3.23 |
| benign | agentdojo | 66 | 0 | 0.00 |
| benign | bipia | 21 | 0 | 0.00 |
| benign | dolly_15k | 7439 | 2 | 0.03 |
| benign | massive_en | 5635 | 5 | 0.09 |
| benign | spml | 1676 | 1 | 0.06 |
| benign | twins | 462 | 0 | 0.00 |
| benign | wildguardmix | 243 | 0 | 0.00 |
| benign | wildjailbreak | 12 | 6 | 50.00 |
| positive | carrier_insertion:blog_post | 4 | 4 | 100.0 |
| positive | carrier_insertion:helpdesk | 6 | 4 | 66.7 |
| positive | carrier_insertion:kb_chunk | 9 | 7 | 77.8 |
| positive | carrier_insertion:report_page | 10 | 8 | 80.0 |
| positive | class_templates:refusal_suppression | 20 | 0 | 0.0 |
| positive | wildjailbreak | 1022 | 912 | 89.2 |

## prompt_extraction DE: sources at the DE cut

| Kind | Source | rows | hits | rate |
|---|---|---|---|---|
| benign | approve_or_deny_de | 24 | 1 | 4.17 |
| benign | germanquad | 5690 | 1 | 0.02 |
| benign | massive_de | 5600 | 9 | 0.16 |
| benign | runner_translations_de | 75 | 0 | 0.00 |
| benign | twins | 337 | 0 | 0.00 |
| positive | carrier_insertion:blog_post | 3 | 3 | 100.0 |
| positive | carrier_insertion:helpdesk | 9 | 7 | 77.8 |
| positive | carrier_insertion:kb_chunk | 9 | 8 | 88.9 |
| positive | carrier_insertion:report_page | 7 | 6 | 85.7 |
| positive | runner_translations_de | 164 | 163 | 99.4 |

## prompt_extraction EN: sources at the EN cut

| Kind | Source | rows | hits | rate |
|---|---|---|---|---|
| benign | agent_safetybench | 31 | 0 | 0.00 |
| benign | agentdojo | 66 | 2 | 3.03 |
| benign | bipia | 21 | 0 | 0.00 |
| benign | dolly_15k | 7439 | 5 | 0.07 |
| benign | massive_en | 5635 | 5 | 0.09 |
| benign | spml | 1676 | 2 | 0.12 |
| benign | twins | 462 | 0 | 0.00 |
| benign | wildguardmix | 243 | 1 | 0.41 |
| benign | wildjailbreak | 12 | 0 | 0.00 |
| positive | carrier_insertion:blog_post | 4 | 1 | 25.0 |
| positive | carrier_insertion:helpdesk | 6 | 0 | 0.0 |
| positive | carrier_insertion:kb_chunk | 4 | 2 | 50.0 |
| positive | carrier_insertion:report_page | 7 | 2 | 28.6 |
| positive | mosscap | 7566 | 7522 | 99.4 |

## tool_poisoning DE: sources at the DE cut

| Kind | Source | rows | hits | rate |
|---|---|---|---|---|
| benign | approve_or_deny_de | 24 | 1 | 4.17 |
| benign | germanquad | 5690 | 0 | 0.00 |
| benign | massive_de | 5600 | 10 | 0.18 |
| benign | runner_translations_de | 75 | 0 | 0.00 |
| benign | twins | 337 | 0 | 0.00 |
| positive | agent_scenarios:package_readme | 25 | 25 | 100.0 |
| positive | class_templates:mcp_tool_description | 19 | 19 | 100.0 |

## tool_poisoning EN: sources at the EN cut

| Kind | Source | rows | hits | rate |
|---|---|---|---|---|
| benign | agent_safetybench | 31 | 0 | 0.00 |
| benign | agentdojo | 66 | 2 | 3.03 |
| benign | bipia | 21 | 0 | 0.00 |
| benign | dolly_15k | 7439 | 4 | 0.05 |
| benign | massive_en | 5635 | 9 | 0.16 |
| benign | spml | 1676 | 0 | 0.00 |
| benign | twins | 462 | 0 | 0.00 |
| benign | wildguardmix | 243 | 0 | 0.00 |
| benign | wildjailbreak | 12 | 0 | 0.00 |
| positive | agent_scenarios:package_readme | 23 | 23 | 100.0 |
| positive | class_templates:mcp_tool_description | 15 | 15 | 100.0 |

## agent_config_tampering DE: sources at the DE cut

| Kind | Source | rows | hits | rate |
|---|---|---|---|---|
| benign | approve_or_deny_de | 24 | 8 | 33.33 |
| benign | germanquad | 5690 | 0 | 0.00 |
| benign | massive_de | 5600 | 3 | 0.05 |
| benign | runner_translations_de | 75 | 0 | 0.00 |
| benign | twins | 337 | 0 | 0.00 |
| positive | agent_scenarios:readme_setup | 23 | 23 | 100.0 |
| positive | class_templates:rules_file | 22 | 22 | 100.0 |

## agent_config_tampering EN: sources at the EN cut

| Kind | Source | rows | hits | rate |
|---|---|---|---|---|
| benign | agent_safetybench | 31 | 0 | 0.00 |
| benign | agentdojo | 66 | 0 | 0.00 |
| benign | bipia | 21 | 0 | 0.00 |
| benign | dolly_15k | 7439 | 2 | 0.03 |
| benign | massive_en | 5635 | 5 | 0.09 |
| benign | spml | 1676 | 0 | 0.00 |
| benign | twins | 462 | 7 | 1.52 |
| benign | wildguardmix | 243 | 0 | 0.00 |
| benign | wildjailbreak | 12 | 0 | 0.00 |
| positive | agent_scenarios:readme_setup | 31 | 31 | 100.0 |
| positive | class_templates:rules_file | 24 | 24 | 100.0 |

## memory_poisoning DE: sources at the DE cut

| Kind | Source | rows | hits | rate |
|---|---|---|---|---|
| benign | approve_or_deny_de | 24 | 1 | 4.17 |
| benign | germanquad | 5690 | 0 | 0.00 |
| benign | massive_de | 5600 | 9 | 0.16 |
| benign | runner_translations_de | 75 | 0 | 0.00 |
| benign | twins | 337 | 1 | 0.30 |
| positive | agent_scenarios:kb_chunk | 26 | 26 | 100.0 |
| positive | agent_scenarios:support_chat | 31 | 31 | 100.0 |

## memory_poisoning EN: sources at the EN cut

| Kind | Source | rows | hits | rate |
|---|---|---|---|---|
| benign | agent_safetybench | 31 | 0 | 0.00 |
| benign | agentdojo | 66 | 0 | 0.00 |
| benign | bipia | 21 | 0 | 0.00 |
| benign | dolly_15k | 7439 | 1 | 0.01 |
| benign | massive_en | 5635 | 11 | 0.20 |
| benign | spml | 1676 | 0 | 0.00 |
| benign | twins | 462 | 0 | 0.00 |
| benign | wildguardmix | 243 | 0 | 0.00 |
| benign | wildjailbreak | 12 | 0 | 0.00 |
| positive | agent_scenarios:kb_chunk | 25 | 25 | 100.0 |
| positive | agent_scenarios:support_chat | 26 | 26 | 100.0 |

## exfiltration DE: sources at the DE cut

| Kind | Source | rows | hits | rate |
|---|---|---|---|---|
| benign | approve_or_deny_de | 24 | 8 | 33.33 |
| benign | germanquad | 5690 | 0 | 0.00 |
| benign | massive_de | 5600 | 3 | 0.05 |
| benign | runner_translations_de | 75 | 0 | 0.00 |
| benign | twins | 337 | 0 | 0.00 |
| positive | exfil_lookalikes:cli_log | 45 | 45 | 100.0 |

## exfiltration EN: sources at the EN cut

| Kind | Source | rows | hits | rate |
|---|---|---|---|---|
| benign | agent_safetybench | 31 | 0 | 0.00 |
| benign | agentdojo | 66 | 7 | 10.61 |
| benign | bipia | 21 | 4 | 19.05 |
| benign | dolly_15k | 7439 | 1 | 0.01 |
| benign | massive_en | 5635 | 3 | 0.05 |
| benign | spml | 1676 | 0 | 0.00 |
| benign | twins | 462 | 0 | 0.00 |
| benign | wildguardmix | 243 | 0 | 0.00 |
| benign | wildjailbreak | 12 | 0 | 0.00 |
| positive | agentdojo | 30 | 30 | 100.0 |
| positive | bipia | 19 | 19 | 100.0 |
| positive | carrier_insertion:blog_post | 7 | 7 | 100.0 |
| positive | carrier_insertion:helpdesk | 17 | 15 | 88.2 |
| positive | carrier_insertion:kb_chunk | 11 | 10 | 90.9 |
| positive | carrier_insertion:report_page | 10 | 8 | 80.0 |
| positive | exfil_lookalikes:cli_log | 51 | 51 | 100.0 |

## unsafe_action DE: sources at the DE cut

| Kind | Source | rows | hits | rate |
|---|---|---|---|---|
| benign | approve_or_deny_de | 24 | 11 | 45.83 |
| benign | germanquad | 5690 | 0 | 0.00 |
| benign | massive_de | 5600 | 0 | 0.00 |
| benign | runner_translations_de | 75 | 0 | 0.00 |
| benign | twins | 337 | 0 | 0.00 |
| positive | approve_or_deny_de | 18 | 9 | 50.0 |
| positive | carrier_insertion:blog_post | 5 | 5 | 100.0 |
| positive | carrier_insertion:helpdesk | 13 | 13 | 100.0 |
| positive | carrier_insertion:kb_chunk | 6 | 6 | 100.0 |
| positive | carrier_insertion:report_page | 8 | 8 | 100.0 |
| positive | class_templates:agent_task | 19 | 0 | 0.0 |

## unsafe_action EN: sources at the EN cut

| Kind | Source | rows | hits | rate |
|---|---|---|---|---|
| benign | agent_safetybench | 31 | 11 | 35.48 |
| benign | agentdojo | 66 | 3 | 4.55 |
| benign | bipia | 21 | 0 | 0.00 |
| benign | dolly_15k | 7439 | 0 | 0.00 |
| benign | massive_en | 5635 | 1 | 0.02 |
| benign | spml | 1676 | 0 | 0.00 |
| benign | twins | 462 | 0 | 0.00 |
| benign | wildguardmix | 243 | 0 | 0.00 |
| benign | wildjailbreak | 12 | 0 | 0.00 |
| positive | agent_safetybench | 22 | 17 | 77.3 |
| positive | agentdojo | 12 | 10 | 83.3 |
| positive | carrier_insertion:blog_post | 3 | 2 | 66.7 |
| positive | carrier_insertion:helpdesk | 20 | 14 | 70.0 |
| positive | carrier_insertion:kb_chunk | 17 | 9 | 52.9 |
| positive | carrier_insertion:report_page | 29 | 23 | 79.3 |
| positive | class_templates:agent_task | 18 | 0 | 0.0 |
| positive | redcode | 144 | 144 | 100.0 |

## resource_exhaustion DE: sources at the DE cut

| Kind | Source | rows | hits | rate |
|---|---|---|---|---|
| benign | approve_or_deny_de | 24 | 0 | 0.00 |
| benign | germanquad | 5690 | 0 | 0.00 |
| benign | massive_de | 5600 | 11 | 0.20 |
| benign | runner_translations_de | 75 | 0 | 0.00 |
| benign | twins | 337 | 0 | 0.00 |
| positive | agent_scenarios:code_todo | 26 | 26 | 100.0 |
| positive | class_templates:repetition_request | 21 | 21 | 100.0 |

## resource_exhaustion EN: sources at the EN cut

| Kind | Source | rows | hits | rate |
|---|---|---|---|---|
| benign | agent_safetybench | 31 | 0 | 0.00 |
| benign | agentdojo | 66 | 0 | 0.00 |
| benign | bipia | 21 | 1 | 4.76 |
| benign | dolly_15k | 7439 | 2 | 0.03 |
| benign | massive_en | 5635 | 12 | 0.21 |
| benign | spml | 1676 | 0 | 0.00 |
| benign | twins | 462 | 0 | 0.00 |
| benign | wildguardmix | 243 | 0 | 0.00 |
| benign | wildjailbreak | 12 | 0 | 0.00 |
| positive | agent_scenarios:code_todo | 21 | 21 | 100.0 |
| positive | class_templates:repetition_request | 22 | 22 | 100.0 |

## harmful_content DE: sources at the DE cut

| Kind | Source | rows | hits | rate |
|---|---|---|---|---|
| benign | approve_or_deny_de | 24 | 0 | 0.00 |
| benign | germanquad | 5690 | 2 | 0.04 |
| benign | massive_de | 5600 | 9 | 0.16 |
| benign | runner_translations_de | 75 | 0 | 0.00 |
| benign | twins | 337 | 0 | 0.00 |
| positive | nemotron_safety_v3 | 164 | 85 | 51.8 |

## harmful_content EN: sources at the EN cut

| Kind | Source | rows | hits | rate |
|---|---|---|---|---|
| benign | agent_safetybench | 31 | 0 | 0.00 |
| benign | agentdojo | 66 | 0 | 0.00 |
| benign | bipia | 21 | 0 | 0.00 |
| benign | dolly_15k | 7439 | 10 | 0.13 |
| benign | massive_en | 5635 | 4 | 0.07 |
| benign | spml | 1676 | 0 | 0.00 |
| benign | twins | 462 | 0 | 0.00 |
| benign | wildguardmix | 243 | 1 | 0.41 |
| benign | wildjailbreak | 12 | 0 | 0.00 |
| positive | nemotron_safety_v3 | 246 | 84 | 34.1 |
| positive | simple_safety_tests | 40 | 9 | 22.5 |

## toxic_language DE: sources at the DE cut

| Kind | Source | rows | hits | rate |
|---|---|---|---|---|
| benign | approve_or_deny_de | 24 | 0 | 0.00 |
| benign | germanquad | 5690 | 0 | 0.00 |
| benign | massive_de | 5600 | 11 | 0.20 |
| benign | runner_translations_de | 75 | 0 | 0.00 |
| benign | twins | 337 | 0 | 0.00 |
| positive | nemotron_safety_v3 | 28 | 23 | 82.1 |
| positive | xsafety_de | 83 | 70 | 84.3 |

## toxic_language EN: sources at the EN cut

| Kind | Source | rows | hits | rate |
|---|---|---|---|---|
| benign | agent_safetybench | 31 | 0 | 0.00 |
| benign | agentdojo | 66 | 0 | 0.00 |
| benign | bipia | 21 | 0 | 0.00 |
| benign | dolly_15k | 7439 | 4 | 0.05 |
| benign | massive_en | 5635 | 11 | 0.20 |
| benign | spml | 1676 | 0 | 0.00 |
| benign | twins | 462 | 0 | 0.00 |
| benign | wildguardmix | 243 | 0 | 0.00 |
| benign | wildjailbreak | 12 | 0 | 0.00 |
| positive | dynahate | 367 | 186 | 50.7 |
| positive | nemotron_safety_v3 | 22 | 10 | 45.5 |

## instruction_injection: FPR per benign source at the detect cut

| Scope | Source | rows | FP | FPR |
|---|---|---|---|---|
| calibration | agent_safetybench | 31 | 0 | 0.00 |
| calibration | agentdojo | 66 | 6 | 9.09 |
| calibration | approve_or_deny_de | 24 | 0 | 0.00 |
| calibration | bipia | 21 | 10 | 47.62 |
| calibration | dolly_15k | 7439 | 3 | 0.04 |
| calibration | germanquad | 5690 | 0 | 0.00 |
| calibration | massive_de | 5600 | 1 | 0.02 |
| calibration | massive_en | 5635 | 6 | 0.11 |
| calibration | runner_translations_de | 75 | 0 | 0.00 |
| calibration | spml | 1676 | 0 | 0.00 |
| calibration | twins | 799 | 0 | 0.00 |
| calibration | wildguardmix | 243 | 1 | 0.41 |
| calibration | wildjailbreak | 12 | 0 | 0.00 |
| report | civil_comments | 5856 | 24 | 0.41 |
| report | jackhhao_jailbreak | 1321 | 8 | 0.61 |
| report | textdetox_de | 2492 | 4 | 0.16 |

## jailbreak: FPR per benign source at the detect cut

| Scope | Source | rows | FP | FPR |
|---|---|---|---|---|
| calibration | agent_safetybench | 31 | 1 | 3.23 |
| calibration | agentdojo | 66 | 0 | 0.00 |
| calibration | approve_or_deny_de | 24 | 0 | 0.00 |
| calibration | bipia | 21 | 0 | 0.00 |
| calibration | dolly_15k | 7439 | 5 | 0.07 |
| calibration | germanquad | 5690 | 0 | 0.00 |
| calibration | massive_de | 5600 | 3 | 0.05 |
| calibration | massive_en | 5635 | 6 | 0.11 |
| calibration | runner_translations_de | 75 | 0 | 0.00 |
| calibration | spml | 1676 | 1 | 0.06 |
| calibration | twins | 799 | 0 | 0.00 |
| calibration | wildguardmix | 243 | 2 | 0.82 |
| calibration | wildjailbreak | 12 | 9 | 75.00 |
| report | civil_comments | 5856 | 191 | 3.26 |
| report | jackhhao_jailbreak | 1321 | 110 | 8.33 |
| report | textdetox_de | 2492 | 22 | 0.88 |

## prompt_extraction: FPR per benign source at the detect cut

| Scope | Source | rows | FP | FPR |
|---|---|---|---|---|
| calibration | agent_safetybench | 31 | 0 | 0.00 |
| calibration | agentdojo | 66 | 2 | 3.03 |
| calibration | approve_or_deny_de | 24 | 1 | 4.17 |
| calibration | bipia | 21 | 0 | 0.00 |
| calibration | dolly_15k | 7439 | 10 | 0.13 |
| calibration | germanquad | 5690 | 0 | 0.00 |
| calibration | massive_de | 5600 | 2 | 0.04 |
| calibration | massive_en | 5635 | 8 | 0.14 |
| calibration | runner_translations_de | 75 | 0 | 0.00 |
| calibration | spml | 1676 | 2 | 0.12 |
| calibration | twins | 799 | 0 | 0.00 |
| calibration | wildguardmix | 243 | 2 | 0.82 |
| calibration | wildjailbreak | 12 | 0 | 0.00 |
| report | civil_comments | 5856 | 161 | 2.75 |
| report | jackhhao_jailbreak | 1321 | 39 | 2.95 |
| report | textdetox_de | 2492 | 1 | 0.04 |

## tool_poisoning: FPR per benign source at the detect cut

| Scope | Source | rows | FP | FPR |
|---|---|---|---|---|
| calibration | agent_safetybench | 31 | 0 | 0.00 |
| calibration | agentdojo | 66 | 2 | 3.03 |
| calibration | approve_or_deny_de | 24 | 1 | 4.17 |
| calibration | bipia | 21 | 0 | 0.00 |
| calibration | dolly_15k | 7439 | 4 | 0.05 |
| calibration | germanquad | 5690 | 0 | 0.00 |
| calibration | massive_de | 5600 | 10 | 0.18 |
| calibration | massive_en | 5635 | 10 | 0.18 |
| calibration | runner_translations_de | 75 | 0 | 0.00 |
| calibration | spml | 1676 | 0 | 0.00 |
| calibration | twins | 799 | 0 | 0.00 |
| calibration | wildguardmix | 243 | 0 | 0.00 |
| calibration | wildjailbreak | 12 | 0 | 0.00 |
| report | civil_comments | 5856 | 43 | 0.73 |
| report | jackhhao_jailbreak | 1321 | 4 | 0.30 |
| report | textdetox_de | 2492 | 11 | 0.44 |

## agent_config_tampering: FPR per benign source at the detect cut

| Scope | Source | rows | FP | FPR |
|---|---|---|---|---|
| calibration | agent_safetybench | 31 | 0 | 0.00 |
| calibration | agentdojo | 66 | 0 | 0.00 |
| calibration | approve_or_deny_de | 24 | 10 | 41.67 |
| calibration | bipia | 21 | 0 | 0.00 |
| calibration | dolly_15k | 7439 | 1 | 0.01 |
| calibration | germanquad | 5690 | 0 | 0.00 |
| calibration | massive_de | 5600 | 4 | 0.07 |
| calibration | massive_en | 5635 | 4 | 0.07 |
| calibration | runner_translations_de | 75 | 0 | 0.00 |
| calibration | spml | 1676 | 0 | 0.00 |
| calibration | twins | 799 | 8 | 1.00 |
| calibration | wildguardmix | 243 | 0 | 0.00 |
| calibration | wildjailbreak | 12 | 0 | 0.00 |
| report | civil_comments | 5856 | 28 | 0.48 |
| report | jackhhao_jailbreak | 1321 | 0 | 0.00 |
| report | textdetox_de | 2492 | 4 | 0.16 |

## memory_poisoning: FPR per benign source at the detect cut

| Scope | Source | rows | FP | FPR |
|---|---|---|---|---|
| calibration | agent_safetybench | 31 | 0 | 0.00 |
| calibration | agentdojo | 66 | 0 | 0.00 |
| calibration | approve_or_deny_de | 24 | 3 | 12.50 |
| calibration | bipia | 21 | 0 | 0.00 |
| calibration | dolly_15k | 7439 | 1 | 0.01 |
| calibration | germanquad | 5690 | 0 | 0.00 |
| calibration | massive_de | 5600 | 11 | 0.20 |
| calibration | massive_en | 5635 | 10 | 0.18 |
| calibration | runner_translations_de | 75 | 0 | 0.00 |
| calibration | spml | 1676 | 0 | 0.00 |
| calibration | twins | 799 | 2 | 0.25 |
| calibration | wildguardmix | 243 | 0 | 0.00 |
| calibration | wildjailbreak | 12 | 0 | 0.00 |
| report | civil_comments | 5856 | 24 | 0.41 |
| report | jackhhao_jailbreak | 1321 | 2 | 0.15 |
| report | textdetox_de | 2492 | 14 | 0.56 |

## exfiltration: FPR per benign source at the detect cut

| Scope | Source | rows | FP | FPR |
|---|---|---|---|---|
| calibration | agent_safetybench | 31 | 0 | 0.00 |
| calibration | agentdojo | 66 | 10 | 15.15 |
| calibration | approve_or_deny_de | 24 | 1 | 4.17 |
| calibration | bipia | 21 | 8 | 38.10 |
| calibration | dolly_15k | 7439 | 2 | 0.03 |
| calibration | germanquad | 5690 | 0 | 0.00 |
| calibration | massive_de | 5600 | 2 | 0.04 |
| calibration | massive_en | 5635 | 4 | 0.07 |
| calibration | runner_translations_de | 75 | 0 | 0.00 |
| calibration | spml | 1676 | 0 | 0.00 |
| calibration | twins | 799 | 0 | 0.00 |
| calibration | wildguardmix | 243 | 0 | 0.00 |
| calibration | wildjailbreak | 12 | 0 | 0.00 |
| report | civil_comments | 5856 | 24 | 0.41 |
| report | jackhhao_jailbreak | 1321 | 1 | 0.08 |
| report | textdetox_de | 2492 | 0 | 0.00 |

## unsafe_action: FPR per benign source at the detect cut

| Scope | Source | rows | FP | FPR |
|---|---|---|---|---|
| calibration | agent_safetybench | 31 | 11 | 35.48 |
| calibration | agentdojo | 66 | 4 | 6.06 |
| calibration | approve_or_deny_de | 24 | 9 | 37.50 |
| calibration | bipia | 21 | 0 | 0.00 |
| calibration | dolly_15k | 7439 | 0 | 0.00 |
| calibration | germanquad | 5690 | 0 | 0.00 |
| calibration | massive_de | 5600 | 0 | 0.00 |
| calibration | massive_en | 5635 | 1 | 0.02 |
| calibration | runner_translations_de | 75 | 0 | 0.00 |
| calibration | spml | 1676 | 0 | 0.00 |
| calibration | twins | 799 | 2 | 0.25 |
| calibration | wildguardmix | 243 | 0 | 0.00 |
| calibration | wildjailbreak | 12 | 0 | 0.00 |
| report | civil_comments | 5856 | 6 | 0.10 |
| report | jackhhao_jailbreak | 1321 | 0 | 0.00 |
| report | textdetox_de | 2492 | 0 | 0.00 |

## resource_exhaustion: FPR per benign source at the detect cut

| Scope | Source | rows | FP | FPR |
|---|---|---|---|---|
| calibration | agent_safetybench | 31 | 0 | 0.00 |
| calibration | agentdojo | 66 | 1 | 1.52 |
| calibration | approve_or_deny_de | 24 | 0 | 0.00 |
| calibration | bipia | 21 | 1 | 4.76 |
| calibration | dolly_15k | 7439 | 2 | 0.03 |
| calibration | germanquad | 5690 | 0 | 0.00 |
| calibration | massive_de | 5600 | 9 | 0.16 |
| calibration | massive_en | 5635 | 14 | 0.25 |
| calibration | runner_translations_de | 75 | 0 | 0.00 |
| calibration | spml | 1676 | 0 | 0.00 |
| calibration | twins | 799 | 0 | 0.00 |
| calibration | wildguardmix | 243 | 0 | 0.00 |
| calibration | wildjailbreak | 12 | 0 | 0.00 |
| report | civil_comments | 5856 | 32 | 0.55 |
| report | jackhhao_jailbreak | 1321 | 0 | 0.00 |
| report | textdetox_de | 2492 | 4 | 0.16 |

## harmful_content: FPR per benign source at the detect cut

| Scope | Source | rows | FP | FPR |
|---|---|---|---|---|
| calibration | agent_safetybench | 31 | 0 | 0.00 |
| calibration | agentdojo | 66 | 0 | 0.00 |
| calibration | approve_or_deny_de | 24 | 0 | 0.00 |
| calibration | bipia | 21 | 0 | 0.00 |
| calibration | dolly_15k | 7439 | 14 | 0.19 |
| calibration | germanquad | 5690 | 2 | 0.04 |
| calibration | massive_de | 5600 | 4 | 0.07 |
| calibration | massive_en | 5635 | 6 | 0.11 |
| calibration | runner_translations_de | 75 | 0 | 0.00 |
| calibration | spml | 1676 | 0 | 0.00 |
| calibration | twins | 799 | 0 | 0.00 |
| calibration | wildguardmix | 243 | 1 | 0.41 |
| calibration | wildjailbreak | 12 | 0 | 0.00 |
| report | civil_comments | 5856 | 2 | 0.03 |
| report | jackhhao_jailbreak | 1321 | 0 | 0.00 |
| report | textdetox_de | 2492 | 0 | 0.00 |

## toxic_language: FPR per benign source at the detect cut

| Scope | Source | rows | FP | FPR |
|---|---|---|---|---|
| calibration | agent_safetybench | 31 | 0 | 0.00 |
| calibration | agentdojo | 66 | 0 | 0.00 |
| calibration | approve_or_deny_de | 24 | 0 | 0.00 |
| calibration | bipia | 21 | 0 | 0.00 |
| calibration | dolly_15k | 7439 | 6 | 0.08 |
| calibration | germanquad | 5690 | 0 | 0.00 |
| calibration | massive_de | 5600 | 4 | 0.07 |
| calibration | massive_en | 5635 | 17 | 0.30 |
| calibration | runner_translations_de | 75 | 0 | 0.00 |
| calibration | spml | 1676 | 0 | 0.00 |
| calibration | twins | 799 | 0 | 0.00 |
| calibration | wildguardmix | 243 | 0 | 0.00 |
| calibration | wildjailbreak | 12 | 0 | 0.00 |
| report | civil_comments | 5856 | 528 | 9.02 |
| report | jackhhao_jailbreak | 1321 | 15 | 1.14 |
| report | textdetox_de | 2492 | 11 | 0.44 |
