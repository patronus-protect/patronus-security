# fastText-type candidates with German positives and per-language cuts (S11)

Generated 2026-11-21 with `scripts/l1_threat/ablation.py calibrate --stage FT` per class, branch
`threat/158-s11` (base `278b7122`), dev data as frozen on the VPS (`train_dev`, `generated` generator 7):

    ablation.py calibrate --rows train_dev --rows generated --baseline-rows train_dev --oversample-de 4 \
        --report-rows report --class <class> --out <class>.json

Two models, same model form as S10 (2^15 × 16 buckets, 256 KiB resident), both read off **one held-out pool**:

- **S10 setup** (the baseline, `--baseline-rows train_dev`): trains on the hash half of `train_dev` alone, no
  oversampling.
- **S11** (the candidate): trains on the train half of `train_dev` *and* `generated`, every German train positive
  repeated four times (`--rows train_dev --rows generated --oversample-de 4`).
  Generated rows are split by generator and template family (`template_key`), so no template, its other
  language or its twins are on both sides (`test_split_keeps_train_and_calibration_template_disjoint`).
- **Pool**: the held-out half of `train_dev` plus the generated template families withheld from S11's training
  (27 533 rows). The S10 setup never trains on generated rows, so the pool is held out for both models; each model's
  cuts are read off its benign rows and its TPR off its positives (`baseline` in the report).

Each language gets its own detect cut at 0.1 % FPR on that language's benign rows (DE: `germanquad`,
`approve_or_deny_de`, German twins; EN: the rest), per model. TPR in %, positives of the class in that language.

| Class | S10 setup DE | S10 setup EN | S11 DE | S11 EN | Δ DE | Δ EN | FPR DE / EN S10 setup | FPR DE / EN S11 | S11 DE positives / sources |
|---|---|---|---|---|---|---|---|---|---|
| instruction_injection | 20.0 | 67.8 | **65.7** | **67.6** | +45.7 | −0.2 | 0.08 / 0.10 | 0.08 / 0.10 | 35 / 6 |
| jailbreak | 0.0 | 82.4 | **0.0** | **82.9** | 0.0 | +0.5 | 0.08 / 0.10 | 0.08 / 0.10 | 42 / 2 |
| unsafe_action | 1.6 | 66.9 | **45.2** | **74.0** | +43.5 | +7.1 | 0.08 / 0.10 | 0.08 / 0.10 | 62 / 7 |
| exfiltration | 0.0 | 18.0 | **100.0** | **87.3** | +100.0 | +69.3 | 0.07 / 0.10 | 0.08 / 0.10 | 105 / 2 |
| harmful_content | 70.7 | 26.4 | **79.3** | **29.3** | +8.5 | +2.8 | 0.08 / 0.10 | 0.08 / 0.10 | 164 / 1 |
| toxic_language | 71.4 | 68.2 | **85.7** | **68.2** | +14.3 | 0.0 | 0.08 / 0.10 | 0.08 / 0.10 | 28 / 1 |
| prompt_extraction | – | 98.5 | **–** | **98.8** | – | +0.4 | 0.08 / 0.10 | 0.08 / 0.10 | 0 / 0 |
| agent_config_tampering | 0.0 | 0.0 | **0.0** | **0.0** | 0.0 | 0.0 | 0.08 / 0.10 | 0.08 / 0.10 | 20 / 1 |

An earlier version of this table read the S10 setup off its own pool (`--eval-rows generated`: all generated rows,
also the template families S11 trained on) and S11 off the withheld families only; those deltas mixed the model
change with the pool change (e.g. injection EN +29.1 there, −0.2 here) and are withdrawn.

Cost: model form, size and RAM are unchanged (2^15 × 16, 256 KiB resident; the serialised `model.json` 11.2 MB
in both setups). p95 ms per 100 KiB with `text_model_latency` (`--tokens tf1`), five alternating runs per model,
median (range): injection S10 setup 4.30 (2.81–5.41), S11 3.07 (2.76–5.36); harmful_content S10 setup 3.36
(2.75–5.37), S11 4.90 (2.95–5.62) — the same band as S10's 3.5–4.4 ms, i.e. noise. The E03 latency corpus is not
on this machine; the windows are 17 × 100 KiB packed from `germanquad` and `dolly_15k` dev text. Rust inference is
unchanged and the parity goldens are untouched (same model form).

Oversampling factor (S11 setup, own cuts, DE / EN TPR): factor 1 — injection 48.6 / 67.8, unsafe_action
40.3 / 72.1, harmful_content 79.3 / 22.4, toxic_language 75.0 / 59.1; factor 4 (chosen) — see the table;
factor 8 — injection 74.3 / 69.0, unsafe_action 43.5 / 72.4, harmful_content 84.1 / 26.0, toxic_language
85.7 / 72.7. Factor 8 buys a little German at the cost of English harmful_content, so 4.

Findings:

- On the shared pool, EN at the EN cut is equal or up for six of the seven trainable classes (unsafe_action +7.1,
  exfiltration +69.3, harmful_content +2.8, jailbreak +0.5, prompt_extraction +0.4, toxic_language ±0).
  instruction_injection is 3 rows lower (1 067 against 1 070 of 1 579 EN positives, −0.2 pp): `spml` 967 against
  976 and the generated carriers 38 against 40, partly made up by `agentdojo` 37 against 33 and `bipia` 25 against
  21. That is within the row-level noise of one split, but it is not "no regression"; the German gain (+45.7) is
  the reason to take it.
- The generated directive sentences are shared between template families of one generator (e.g. the exfiltration
  directives of `exfil_lookalikes`), so template-disjoint is not payload-disjoint; the German exfiltration
  100 % (two `exfil_lookalikes` families) and the EN exfiltration gain overstate what a new source would give.
- German positives come from ≥ 5 sources only for instruction_injection (6: five `carrier_insertion` families
  and `cyberseceval_multilingual`) and unsafe_action (7: `approve_or_deny_de` and six generator families).
  jailbreak (2 families, both missed), exfiltration (2), harmful_content and toxic_language (`nemotron_safety_v3`
  only) and agent_config_tampering (1 family, missed) fall short; prompt_extraction has no German positive.
- The German benign pool is almost all `germanquad` (5 690 of 5 977): the German cuts sit low (injection
  -0.51 against EN 4.32), and `approve_or_deny_de` takes 4 of 24 at the injection DE cut. A varied German
  benign pool (chat, mail, code comments) and translated open sets need new frozen dev data; not in this run.

## Per-language cuts

Each language's detect cut sits at the target FPR of that language's benign rows.

| Class | Language | benign rows | detect cut | TPR | FPR | positives | positive sources |
|---|---|---|---|---|---|---|---|
| instruction_injection | DE | 5977 | -0.5098 | 65.7 | 0.08 | 35 | 6 |
| instruction_injection | EN | 10055 | 4.3210 | 67.6 | 0.10 | 1579 | 8 |
| jailbreak | DE | 5977 | -1.0747 | 0.0 | 0.08 | 42 | 2 |
| jailbreak | EN | 10055 | 3.4047 | 82.9 | 0.10 | 1103 | 8 |
| unsafe_action | DE | 5977 | 3.9820 | 45.2 | 0.08 | 62 | 7 |
| unsafe_action | EN | 10055 | 2.5254 | 74.0 | 0.10 | 308 | 9 |
| exfiltration | DE | 5977 | 0.1561 | 100.0 | 0.08 | 105 | 2 |
| exfiltration | EN | 10055 | 2.6474 | 87.3 | 0.10 | 228 | 9 |
| harmful_content | DE | 5977 | 1.8929 | 79.3 | 0.08 | 164 | 1 |
| harmful_content | EN | 10055 | 4.4279 | 29.3 | 0.10 | 246 | 1 |
| toxic_language | DE | 5977 | -0.7011 | 85.7 | 0.08 | 28 | 1 |
| toxic_language | EN | 10055 | 0.4924 | 68.2 | 0.10 | 22 | 1 |
| prompt_extraction | DE | 5977 | -2.4034 | – | 0.08 | 0 | 0 |
| prompt_extraction | EN | 10055 | 1.3645 | 98.8 | 0.10 | 7600 | 6 |
| agent_config_tampering | DE | 5977 | -0.2303 | 0.0 | 0.08 | 20 | 1 |
| agent_config_tampering | EN | 10055 | -0.1767 | 0.0 | 0.10 | 18 | 1 |

## Baseline and candidate on the same held-out pool

Both models' per-language cuts and TPRs on the candidate's calibration rows; the baseline never trained on them.

| Class | baseline DE | baseline EN | candidate DE | candidate EN | Δ DE | Δ EN | FPR DE / EN baseline | FPR DE / EN candidate |
|---|---|---|---|---|---|---|---|---|
| instruction_injection | 20.0 | 67.8 | 65.7 | 67.6 | +45.7 | -0.2 | 0.08 / 0.10 | 0.08 / 0.10 |
| jailbreak | 0.0 | 82.4 | 0.0 | 82.9 | +0.0 | +0.5 | 0.08 / 0.10 | 0.08 / 0.10 |
| unsafe_action | 1.6 | 66.9 | 45.2 | 74.0 | +43.5 | +7.1 | 0.08 / 0.10 | 0.08 / 0.10 |
| exfiltration | 0.0 | 18.0 | 100.0 | 87.3 | +100.0 | +69.3 | 0.07 / 0.10 | 0.08 / 0.10 |
| harmful_content | 70.7 | 26.4 | 79.3 | 29.3 | +8.5 | +2.8 | 0.08 / 0.10 | 0.08 / 0.10 |
| toxic_language | 71.4 | 68.2 | 85.7 | 68.2 | +14.3 | +0.0 | 0.08 / 0.10 | 0.08 / 0.10 |
| prompt_extraction | – | 98.5 | – | 98.8 | – | +0.4 | 0.08 / 0.10 | 0.08 / 0.10 |
| agent_config_tampering | 0.0 | 0.0 | 0.0 | 0.0 | +0.0 | +0.0 | 0.08 / 0.10 | 0.08 / 0.10 |

## instruction_injection DE: sources at the DE cut

| Kind | Source | rows | hits | rate |
|---|---|---|---|---|
| benign | approve_or_deny_de | 24 | 4 | 16.67 |
| benign | germanquad | 5690 | 0 | 0.00 |
| benign | twins | 263 | 1 | 0.38 |
| positive | carrier_insertion:blog_post | 2 | 2 | 100.0 |
| positive | carrier_insertion:helpdesk | 9 | 5 | 55.6 |
| positive | carrier_insertion:kb_chunk | 6 | 5 | 83.3 |
| positive | carrier_insertion:plain_mail | 4 | 3 | 75.0 |
| positive | carrier_insertion:report_page | 9 | 5 | 55.6 |
| positive | cyberseceval_multilingual | 5 | 3 | 60.0 |

## instruction_injection EN: sources at the EN cut

| Kind | Source | rows | hits | rate |
|---|---|---|---|---|
| benign | agent_safetybench | 31 | 0 | 0.00 |
| benign | agentdojo | 66 | 3 | 4.55 |
| benign | bipia | 21 | 2 | 9.52 |
| benign | dolly_15k | 7439 | 4 | 0.05 |
| benign | spml | 1676 | 0 | 0.00 |
| benign | twins | 567 | 0 | 0.00 |
| benign | wildguardmix | 243 | 1 | 0.41 |
| benign | wildjailbreak | 12 | 0 | 0.00 |
| positive | agentdojo | 67 | 37 | 55.2 |
| positive | bipia | 89 | 25 | 28.1 |
| positive | carrier_insertion:blog_post | 22 | 4 | 18.2 |
| positive | carrier_insertion:helpdesk | 53 | 5 | 9.4 |
| positive | carrier_insertion:kb_chunk | 42 | 11 | 26.2 |
| positive | carrier_insertion:plain_mail | 50 | 9 | 18.0 |
| positive | carrier_insertion:report_page | 53 | 9 | 17.0 |
| positive | spml | 1203 | 967 | 80.4 |

## jailbreak DE: sources at the DE cut

| Kind | Source | rows | hits | rate |
|---|---|---|---|---|
| benign | approve_or_deny_de | 24 | 3 | 12.50 |
| benign | germanquad | 5690 | 2 | 0.04 |
| benign | twins | 263 | 0 | 0.00 |
| positive | class_templates:persona_unlock | 22 | 0 | 0.0 |
| positive | class_templates:refusal_suppression | 20 | 0 | 0.0 |

## jailbreak EN: sources at the EN cut

| Kind | Source | rows | hits | rate |
|---|---|---|---|---|
| benign | agent_safetybench | 31 | 0 | 0.00 |
| benign | agentdojo | 66 | 0 | 0.00 |
| benign | bipia | 21 | 0 | 0.00 |
| benign | dolly_15k | 7439 | 3 | 0.04 |
| benign | spml | 1676 | 1 | 0.06 |
| benign | twins | 567 | 0 | 0.00 |
| benign | wildguardmix | 243 | 0 | 0.00 |
| benign | wildjailbreak | 12 | 6 | 50.00 |
| positive | carrier_insertion:blog_post | 1 | 0 | 0.0 |
| positive | carrier_insertion:helpdesk | 9 | 4 | 44.4 |
| positive | carrier_insertion:kb_chunk | 10 | 8 | 80.0 |
| positive | carrier_insertion:plain_mail | 7 | 3 | 42.9 |
| positive | carrier_insertion:report_page | 12 | 8 | 66.7 |
| positive | class_templates:persona_unlock | 22 | 0 | 0.0 |
| positive | class_templates:refusal_suppression | 20 | 0 | 0.0 |
| positive | wildjailbreak | 1022 | 891 | 87.2 |

## unsafe_action DE: sources at the DE cut

| Kind | Source | rows | hits | rate |
|---|---|---|---|---|
| benign | approve_or_deny_de | 24 | 5 | 20.83 |
| benign | germanquad | 5690 | 0 | 0.00 |
| benign | twins | 263 | 0 | 0.00 |
| positive | approve_or_deny_de | 18 | 5 | 27.8 |
| positive | carrier_insertion:blog_post | 8 | 7 | 87.5 |
| positive | carrier_insertion:helpdesk | 4 | 4 | 100.0 |
| positive | carrier_insertion:kb_chunk | 3 | 3 | 100.0 |
| positive | carrier_insertion:plain_mail | 2 | 1 | 50.0 |
| positive | carrier_insertion:report_page | 8 | 8 | 100.0 |
| positive | class_templates:agent_task | 19 | 0 | 0.0 |

## unsafe_action EN: sources at the EN cut

| Kind | Source | rows | hits | rate |
|---|---|---|---|---|
| benign | agent_safetybench | 31 | 6 | 19.35 |
| benign | agentdojo | 66 | 4 | 6.06 |
| benign | bipia | 21 | 0 | 0.00 |
| benign | dolly_15k | 7439 | 0 | 0.00 |
| benign | spml | 1676 | 0 | 0.00 |
| benign | twins | 567 | 0 | 0.00 |
| benign | wildguardmix | 243 | 0 | 0.00 |
| benign | wildjailbreak | 12 | 0 | 0.00 |
| positive | agent_safetybench | 22 | 14 | 63.6 |
| positive | agentdojo | 12 | 8 | 66.7 |
| positive | carrier_insertion:blog_post | 9 | 3 | 33.3 |
| positive | carrier_insertion:helpdesk | 29 | 17 | 58.6 |
| positive | carrier_insertion:kb_chunk | 21 | 9 | 42.9 |
| positive | carrier_insertion:plain_mail | 28 | 16 | 57.1 |
| positive | carrier_insertion:report_page | 25 | 17 | 68.0 |
| positive | class_templates:agent_task | 18 | 0 | 0.0 |
| positive | redcode | 144 | 144 | 100.0 |

## exfiltration DE: sources at the DE cut

| Kind | Source | rows | hits | rate |
|---|---|---|---|---|
| benign | approve_or_deny_de | 24 | 5 | 20.83 |
| benign | germanquad | 5690 | 0 | 0.00 |
| benign | twins | 263 | 0 | 0.00 |
| positive | exfil_lookalikes:file_read | 58 | 58 | 100.0 |
| positive | exfil_lookalikes:json_result | 47 | 47 | 100.0 |

## exfiltration EN: sources at the EN cut

| Kind | Source | rows | hits | rate |
|---|---|---|---|---|
| benign | agent_safetybench | 31 | 0 | 0.00 |
| benign | agentdojo | 66 | 4 | 6.06 |
| benign | bipia | 21 | 5 | 23.81 |
| benign | dolly_15k | 7439 | 1 | 0.01 |
| benign | spml | 1676 | 0 | 0.00 |
| benign | twins | 567 | 0 | 0.00 |
| benign | wildguardmix | 243 | 0 | 0.00 |
| benign | wildjailbreak | 12 | 0 | 0.00 |
| positive | agentdojo | 30 | 28 | 93.3 |
| positive | bipia | 19 | 16 | 84.2 |
| positive | carrier_insertion:blog_post | 12 | 9 | 75.0 |
| positive | carrier_insertion:helpdesk | 15 | 8 | 53.3 |
| positive | carrier_insertion:kb_chunk | 16 | 14 | 87.5 |
| positive | carrier_insertion:plain_mail | 21 | 14 | 66.7 |
| positive | carrier_insertion:report_page | 16 | 11 | 68.8 |
| positive | exfil_lookalikes:file_read | 57 | 57 | 100.0 |
| positive | exfil_lookalikes:json_result | 42 | 42 | 100.0 |

## harmful_content DE: sources at the DE cut

| Kind | Source | rows | hits | rate |
|---|---|---|---|---|
| benign | approve_or_deny_de | 24 | 0 | 0.00 |
| benign | germanquad | 5690 | 5 | 0.09 |
| benign | twins | 263 | 0 | 0.00 |
| positive | nemotron_safety_v3 | 164 | 130 | 79.3 |

## harmful_content EN: sources at the EN cut

| Kind | Source | rows | hits | rate |
|---|---|---|---|---|
| benign | agent_safetybench | 31 | 0 | 0.00 |
| benign | agentdojo | 66 | 0 | 0.00 |
| benign | bipia | 21 | 0 | 0.00 |
| benign | dolly_15k | 7439 | 9 | 0.12 |
| benign | spml | 1676 | 0 | 0.00 |
| benign | twins | 567 | 0 | 0.00 |
| benign | wildguardmix | 243 | 1 | 0.41 |
| benign | wildjailbreak | 12 | 0 | 0.00 |
| positive | nemotron_safety_v3 | 246 | 72 | 29.3 |

## toxic_language DE: sources at the DE cut

| Kind | Source | rows | hits | rate |
|---|---|---|---|---|
| benign | approve_or_deny_de | 24 | 0 | 0.00 |
| benign | germanquad | 5690 | 5 | 0.09 |
| benign | twins | 263 | 0 | 0.00 |
| positive | nemotron_safety_v3 | 28 | 24 | 85.7 |

## toxic_language EN: sources at the EN cut

| Kind | Source | rows | hits | rate |
|---|---|---|---|---|
| benign | agent_safetybench | 31 | 0 | 0.00 |
| benign | agentdojo | 66 | 0 | 0.00 |
| benign | bipia | 21 | 0 | 0.00 |
| benign | dolly_15k | 7439 | 10 | 0.13 |
| benign | spml | 1676 | 0 | 0.00 |
| benign | twins | 567 | 0 | 0.00 |
| benign | wildguardmix | 243 | 0 | 0.00 |
| benign | wildjailbreak | 12 | 0 | 0.00 |
| positive | nemotron_safety_v3 | 22 | 15 | 68.2 |

## prompt_extraction DE: sources at the DE cut

| Kind | Source | rows | hits | rate |
|---|---|---|---|---|
| benign | approve_or_deny_de | 24 | 4 | 16.67 |
| benign | germanquad | 5690 | 1 | 0.02 |
| benign | twins | 263 | 0 | 0.00 |

## prompt_extraction EN: sources at the EN cut

| Kind | Source | rows | hits | rate |
|---|---|---|---|---|
| benign | agent_safetybench | 31 | 0 | 0.00 |
| benign | agentdojo | 66 | 1 | 1.52 |
| benign | bipia | 21 | 0 | 0.00 |
| benign | dolly_15k | 7439 | 6 | 0.08 |
| benign | spml | 1676 | 2 | 0.12 |
| benign | twins | 567 | 0 | 0.00 |
| benign | wildguardmix | 243 | 1 | 0.41 |
| benign | wildjailbreak | 12 | 0 | 0.00 |
| positive | carrier_insertion:blog_post | 2 | 1 | 50.0 |
| positive | carrier_insertion:helpdesk | 8 | 2 | 25.0 |
| positive | carrier_insertion:kb_chunk | 7 | 3 | 42.9 |
| positive | carrier_insertion:plain_mail | 11 | 0 | 0.0 |
| positive | carrier_insertion:report_page | 6 | 2 | 33.3 |
| positive | mosscap | 7566 | 7504 | 99.2 |

## agent_config_tampering DE: sources at the DE cut

| Kind | Source | rows | hits | rate |
|---|---|---|---|---|
| benign | approve_or_deny_de | 24 | 5 | 20.83 |
| benign | germanquad | 5690 | 0 | 0.00 |
| benign | twins | 263 | 0 | 0.00 |
| positive | class_templates:skill_file | 20 | 0 | 0.0 |

## agent_config_tampering EN: sources at the EN cut

| Kind | Source | rows | hits | rate |
|---|---|---|---|---|
| benign | agent_safetybench | 31 | 0 | 0.00 |
| benign | agentdojo | 66 | 0 | 0.00 |
| benign | bipia | 21 | 0 | 0.00 |
| benign | dolly_15k | 7439 | 0 | 0.00 |
| benign | spml | 1676 | 0 | 0.00 |
| benign | twins | 567 | 10 | 1.76 |
| benign | wildguardmix | 243 | 0 | 0.00 |
| benign | wildjailbreak | 12 | 0 | 0.00 |
| positive | class_templates:skill_file | 18 | 0 | 0.0 |

## instruction_injection: FPR per benign source at the detect cut

| Scope | Source | rows | FP | FPR |
|---|---|---|---|---|
| calibration | agent_safetybench | 31 | 0 | 0.00 |
| calibration | agentdojo | 66 | 4 | 6.06 |
| calibration | approve_or_deny_de | 24 | 0 | 0.00 |
| calibration | bipia | 21 | 7 | 33.33 |
| calibration | dolly_15k | 7439 | 4 | 0.05 |
| calibration | germanquad | 5690 | 0 | 0.00 |
| calibration | spml | 1676 | 0 | 0.00 |
| calibration | twins | 830 | 0 | 0.00 |
| calibration | wildguardmix | 243 | 1 | 0.41 |
| calibration | wildjailbreak | 12 | 0 | 0.00 |
| report | civil_comments | 5856 | 52 | 0.89 |
| report | jackhhao_jailbreak | 1321 | 8 | 0.61 |
| report | textdetox_de | 2492 | 0 | 0.00 |

## jailbreak: FPR per benign source at the detect cut

| Scope | Source | rows | FP | FPR |
|---|---|---|---|---|
| calibration | agent_safetybench | 31 | 1 | 3.23 |
| calibration | agentdojo | 66 | 0 | 0.00 |
| calibration | approve_or_deny_de | 24 | 0 | 0.00 |
| calibration | bipia | 21 | 0 | 0.00 |
| calibration | dolly_15k | 7439 | 4 | 0.05 |
| calibration | germanquad | 5690 | 0 | 0.00 |
| calibration | spml | 1676 | 1 | 0.06 |
| calibration | twins | 830 | 0 | 0.00 |
| calibration | wildguardmix | 243 | 2 | 0.82 |
| calibration | wildjailbreak | 12 | 8 | 66.67 |
| report | civil_comments | 5856 | 216 | 3.69 |
| report | jackhhao_jailbreak | 1321 | 73 | 5.53 |
| report | textdetox_de | 2492 | 0 | 0.00 |

## unsafe_action: FPR per benign source at the detect cut

| Scope | Source | rows | FP | FPR |
|---|---|---|---|---|
| calibration | agent_safetybench | 31 | 6 | 19.35 |
| calibration | agentdojo | 66 | 2 | 3.03 |
| calibration | approve_or_deny_de | 24 | 8 | 33.33 |
| calibration | bipia | 21 | 0 | 0.00 |
| calibration | dolly_15k | 7439 | 0 | 0.00 |
| calibration | germanquad | 5690 | 0 | 0.00 |
| calibration | spml | 1676 | 0 | 0.00 |
| calibration | twins | 830 | 0 | 0.00 |
| calibration | wildguardmix | 243 | 0 | 0.00 |
| calibration | wildjailbreak | 12 | 0 | 0.00 |
| report | civil_comments | 5856 | 4 | 0.07 |
| report | jackhhao_jailbreak | 1321 | 0 | 0.00 |
| report | textdetox_de | 2492 | 0 | 0.00 |

## exfiltration: FPR per benign source at the detect cut

| Scope | Source | rows | FP | FPR |
|---|---|---|---|---|
| calibration | agent_safetybench | 31 | 0 | 0.00 |
| calibration | agentdojo | 66 | 7 | 10.61 |
| calibration | approve_or_deny_de | 24 | 0 | 0.00 |
| calibration | bipia | 21 | 8 | 38.10 |
| calibration | dolly_15k | 7439 | 1 | 0.01 |
| calibration | germanquad | 5690 | 0 | 0.00 |
| calibration | spml | 1676 | 0 | 0.00 |
| calibration | twins | 830 | 0 | 0.00 |
| calibration | wildguardmix | 243 | 0 | 0.00 |
| calibration | wildjailbreak | 12 | 0 | 0.00 |
| report | civil_comments | 5856 | 9 | 0.15 |
| report | jackhhao_jailbreak | 1321 | 1 | 0.08 |
| report | textdetox_de | 2492 | 0 | 0.00 |

## harmful_content: FPR per benign source at the detect cut

| Scope | Source | rows | FP | FPR |
|---|---|---|---|---|
| calibration | agent_safetybench | 31 | 0 | 0.00 |
| calibration | agentdojo | 66 | 0 | 0.00 |
| calibration | approve_or_deny_de | 24 | 0 | 0.00 |
| calibration | bipia | 21 | 0 | 0.00 |
| calibration | dolly_15k | 7439 | 13 | 0.17 |
| calibration | germanquad | 5690 | 2 | 0.04 |
| calibration | spml | 1676 | 0 | 0.00 |
| calibration | twins | 830 | 0 | 0.00 |
| calibration | wildguardmix | 243 | 1 | 0.41 |
| calibration | wildjailbreak | 12 | 0 | 0.00 |
| report | civil_comments | 5856 | 4 | 0.07 |
| report | jackhhao_jailbreak | 1321 | 0 | 0.00 |
| report | textdetox_de | 2492 | 6 | 0.24 |

## toxic_language: FPR per benign source at the detect cut

| Scope | Source | rows | FP | FPR |
|---|---|---|---|---|
| calibration | agent_safetybench | 31 | 0 | 0.00 |
| calibration | agentdojo | 66 | 0 | 0.00 |
| calibration | approve_or_deny_de | 24 | 0 | 0.00 |
| calibration | bipia | 21 | 0 | 0.00 |
| calibration | dolly_15k | 7439 | 14 | 0.19 |
| calibration | germanquad | 5690 | 2 | 0.04 |
| calibration | spml | 1676 | 0 | 0.00 |
| calibration | twins | 830 | 0 | 0.00 |
| calibration | wildguardmix | 243 | 0 | 0.00 |
| calibration | wildjailbreak | 12 | 0 | 0.00 |
| report | civil_comments | 5856 | 14 | 0.24 |
| report | jackhhao_jailbreak | 1321 | 2 | 0.15 |
| report | textdetox_de | 2492 | 23 | 0.92 |

## prompt_extraction: FPR per benign source at the detect cut

| Scope | Source | rows | FP | FPR |
|---|---|---|---|---|
| calibration | agent_safetybench | 31 | 0 | 0.00 |
| calibration | agentdojo | 66 | 2 | 3.03 |
| calibration | approve_or_deny_de | 24 | 0 | 0.00 |
| calibration | bipia | 21 | 0 | 0.00 |
| calibration | dolly_15k | 7439 | 11 | 0.15 |
| calibration | germanquad | 5690 | 0 | 0.00 |
| calibration | spml | 1676 | 2 | 0.12 |
| calibration | twins | 830 | 0 | 0.00 |
| calibration | wildguardmix | 243 | 1 | 0.41 |
| calibration | wildjailbreak | 12 | 0 | 0.00 |
| report | civil_comments | 5856 | 238 | 4.06 |
| report | jackhhao_jailbreak | 1321 | 43 | 3.26 |
| report | textdetox_de | 2492 | 0 | 0.00 |

## agent_config_tampering: FPR per benign source at the detect cut

| Scope | Source | rows | FP | FPR |
|---|---|---|---|---|
| calibration | agent_safetybench | 31 | 0 | 0.00 |
| calibration | agentdojo | 66 | 0 | 0.00 |
| calibration | approve_or_deny_de | 24 | 5 | 20.83 |
| calibration | bipia | 21 | 0 | 0.00 |
| calibration | dolly_15k | 7439 | 0 | 0.00 |
| calibration | germanquad | 5690 | 0 | 0.00 |
| calibration | spml | 1676 | 0 | 0.00 |
| calibration | twins | 830 | 10 | 1.20 |
| calibration | wildguardmix | 243 | 0 | 0.00 |
| calibration | wildjailbreak | 12 | 0 | 0.00 |
| report | civil_comments | 5856 | 3 | 0.05 |
| report | jackhhao_jailbreak | 1321 | 0 | 0.00 |
| report | textdetox_de | 2492 | 0 | 0.00 |
