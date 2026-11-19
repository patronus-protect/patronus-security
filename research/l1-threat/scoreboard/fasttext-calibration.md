# fastText-type candidates calibrated on benign data (S10)

Generated 2026-11-19 with `scripts/l1_threat/ablation.py calibrate --stage FT` per class, branch
`threat/126-s10` (base `bfc4e922`). The candidate trains on the hash half of `train_dev` (25 433 rows);
the cuts come from the benign rows of the other half plus `generated` (17 002 benign rows incl. 1 800
look-alike twins; no train row among them). `detect cut` = `0_1pct_fpr` (score > cut is detected),
`TPR`/`FPR` at that cut on the calibration rows (positives: 29 398 calibration rows minus benign);
"FPR at train-negative cut" is what S09's cut from the train negatives would flag on the same pool.
`ms/100 KiB` = p95 of the model on top of the facts on the E03 latency corpus (64 windows, sha256
`32fc2d58…`, `text_model_latency`), median of three runs. The report sets (`civil_comments`,
`jackhhao_jailbreak`, `textdetox_de`; scope `report`) are scored at the same cuts and never move them.

| Class | Stage | benign rows | detect cut | TPR all | TPR DE | TPR EN | FPR | FPR at train-negative cut | ms/100 KiB | RAM KiB |
|---|---|---|---|---|---|---|---|---|---|---|
| instruction_injection | FT | 17002 | 5.6854 | 36.4 | 0.0 | 38.3 | 0.02 | 0.50 | 4.36 | 256.0 |
| prompt_extraction | FT | 17002 | 4.7645 | 87.5 | – | 87.5 | 0.09 | 1.85 | 3.91 | 256.0 |
| jailbreak | FT | 17002 | 3.1062 | 81.3 | 0.0 | 84.2 | 0.10 | 0.85 | 4.04 | 256.0 |
| harmful_content | FT | 17002 | 4.1373 | 42.2 | 47.6 | 38.6 | 0.10 | 0.52 | 3.58 | 256.0 |
| unsafe_action | FT | 17002 | 3.2751 | 39.4 | 0.8 | 49.7 | 0.10 | 0.32 | 4.02 | 256.0 |
| exfiltration | FT | 17002 | 2.5465 | 26.7 | 0.0 | 37.5 | 0.10 | 0.08 | 3.55 | 256.0 |
| toxic_language | FT | 17002 | 0.7742 | 68.0 | 67.9 | 68.2 | 0.10 | 0.36 | 3.54 | 256.0 |
| agent_config_tampering | FT | 17002 | -0.4749 | 0.0 | 0.0 | 0.0 | 0.10 | 0.74 | 3.51 | 256.0 |

## instruction_injection: FPR per benign source at the detect cut

| Scope | Source | rows | FP | FPR |
|---|---|---|---|---|
| calibration | agent_safetybench | 31 | 0 | 0.00 |
| calibration | agentdojo | 66 | 0 | 0.00 |
| calibration | approve_or_deny_de | 24 | 0 | 0.00 |
| calibration | bipia | 21 | 0 | 0.00 |
| calibration | dolly_15k | 7439 | 2 | 0.03 |
| calibration | germanquad | 5690 | 0 | 0.00 |
| calibration | spml | 1676 | 0 | 0.00 |
| calibration | twins | 1800 | 0 | 0.00 |
| calibration | wildguardmix | 243 | 1 | 0.41 |
| calibration | wildjailbreak | 12 | 0 | 0.00 |
| report | civil_comments | 5856 | 9 | 0.15 |
| report | jackhhao_jailbreak | 1321 | 1 | 0.08 |
| report | textdetox_de | 2492 | 0 | 0.00 |

## prompt_extraction: FPR per benign source at the detect cut

| Scope | Source | rows | FP | FPR |
|---|---|---|---|---|
| calibration | agent_safetybench | 31 | 0 | 0.00 |
| calibration | agentdojo | 66 | 0 | 0.00 |
| calibration | approve_or_deny_de | 24 | 0 | 0.00 |
| calibration | bipia | 21 | 0 | 0.00 |
| calibration | dolly_15k | 7439 | 2 | 0.03 |
| calibration | germanquad | 5690 | 0 | 0.00 |
| calibration | spml | 1676 | 1 | 0.06 |
| calibration | twins | 1800 | 13 | 0.72 |
| calibration | wildguardmix | 243 | 0 | 0.00 |
| calibration | wildjailbreak | 12 | 0 | 0.00 |
| report | civil_comments | 5856 | 8 | 0.14 |
| report | jackhhao_jailbreak | 1321 | 1 | 0.08 |
| report | textdetox_de | 2492 | 0 | 0.00 |

## jailbreak: FPR per benign source at the detect cut

| Scope | Source | rows | FP | FPR |
|---|---|---|---|---|
| calibration | agent_safetybench | 31 | 0 | 0.00 |
| calibration | agentdojo | 66 | 0 | 0.00 |
| calibration | approve_or_deny_de | 24 | 0 | 0.00 |
| calibration | bipia | 21 | 0 | 0.00 |
| calibration | dolly_15k | 7439 | 3 | 0.04 |
| calibration | germanquad | 5690 | 0 | 0.00 |
| calibration | spml | 1676 | 1 | 0.06 |
| calibration | twins | 1800 | 3 | 0.17 |
| calibration | wildguardmix | 243 | 2 | 0.82 |
| calibration | wildjailbreak | 12 | 8 | 66.67 |
| report | civil_comments | 5856 | 164 | 2.80 |
| report | jackhhao_jailbreak | 1321 | 61 | 4.62 |
| report | textdetox_de | 2492 | 0 | 0.00 |

## harmful_content: FPR per benign source at the detect cut

| Scope | Source | rows | FP | FPR |
|---|---|---|---|---|
| calibration | agent_safetybench | 31 | 0 | 0.00 |
| calibration | agentdojo | 66 | 0 | 0.00 |
| calibration | approve_or_deny_de | 24 | 0 | 0.00 |
| calibration | bipia | 21 | 0 | 0.00 |
| calibration | dolly_15k | 7439 | 14 | 0.19 |
| calibration | germanquad | 5690 | 1 | 0.02 |
| calibration | spml | 1676 | 1 | 0.06 |
| calibration | twins | 1800 | 0 | 0.00 |
| calibration | wildguardmix | 243 | 1 | 0.41 |
| calibration | wildjailbreak | 12 | 0 | 0.00 |
| report | civil_comments | 5856 | 4 | 0.07 |
| report | jackhhao_jailbreak | 1321 | 0 | 0.00 |
| report | textdetox_de | 2492 | 3 | 0.12 |

## unsafe_action: FPR per benign source at the detect cut

| Scope | Source | rows | FP | FPR |
|---|---|---|---|---|
| calibration | agent_safetybench | 31 | 5 | 16.13 |
| calibration | agentdojo | 66 | 3 | 4.55 |
| calibration | approve_or_deny_de | 24 | 3 | 12.50 |
| calibration | bipia | 21 | 0 | 0.00 |
| calibration | dolly_15k | 7439 | 0 | 0.00 |
| calibration | germanquad | 5690 | 0 | 0.00 |
| calibration | spml | 1676 | 0 | 0.00 |
| calibration | twins | 1800 | 6 | 0.33 |
| calibration | wildguardmix | 243 | 0 | 0.00 |
| calibration | wildjailbreak | 12 | 0 | 0.00 |
| report | civil_comments | 5856 | 3 | 0.05 |
| report | jackhhao_jailbreak | 1321 | 0 | 0.00 |
| report | textdetox_de | 2492 | 0 | 0.00 |

## exfiltration: FPR per benign source at the detect cut

| Scope | Source | rows | FP | FPR |
|---|---|---|---|---|
| calibration | agent_safetybench | 31 | 0 | 0.00 |
| calibration | agentdojo | 66 | 5 | 7.58 |
| calibration | approve_or_deny_de | 24 | 0 | 0.00 |
| calibration | bipia | 21 | 12 | 57.14 |
| calibration | dolly_15k | 7439 | 0 | 0.00 |
| calibration | germanquad | 5690 | 0 | 0.00 |
| calibration | spml | 1676 | 0 | 0.00 |
| calibration | twins | 1800 | 0 | 0.00 |
| calibration | wildguardmix | 243 | 0 | 0.00 |
| calibration | wildjailbreak | 12 | 0 | 0.00 |
| report | civil_comments | 5856 | 3 | 0.05 |
| report | jackhhao_jailbreak | 1321 | 0 | 0.00 |
| report | textdetox_de | 2492 | 0 | 0.00 |

## toxic_language: FPR per benign source at the detect cut

| Scope | Source | rows | FP | FPR |
|---|---|---|---|---|
| calibration | agent_safetybench | 31 | 0 | 0.00 |
| calibration | agentdojo | 66 | 0 | 0.00 |
| calibration | approve_or_deny_de | 24 | 0 | 0.00 |
| calibration | bipia | 21 | 0 | 0.00 |
| calibration | dolly_15k | 7439 | 14 | 0.19 |
| calibration | germanquad | 5690 | 3 | 0.05 |
| calibration | spml | 1676 | 0 | 0.00 |
| calibration | twins | 1800 | 0 | 0.00 |
| calibration | wildguardmix | 243 | 0 | 0.00 |
| calibration | wildjailbreak | 12 | 0 | 0.00 |
| report | civil_comments | 5856 | 7 | 0.12 |
| report | jackhhao_jailbreak | 1321 | 0 | 0.00 |
| report | textdetox_de | 2492 | 6 | 0.24 |

## agent_config_tampering: FPR per benign source at the detect cut

| Scope | Source | rows | FP | FPR |
|---|---|---|---|---|
| calibration | agent_safetybench | 31 | 0 | 0.00 |
| calibration | agentdojo | 66 | 0 | 0.00 |
| calibration | approve_or_deny_de | 24 | 9 | 37.50 |
| calibration | bipia | 21 | 0 | 0.00 |
| calibration | dolly_15k | 7439 | 0 | 0.00 |
| calibration | germanquad | 5690 | 0 | 0.00 |
| calibration | spml | 1676 | 0 | 0.00 |
| calibration | twins | 1800 | 8 | 0.44 |
| calibration | wildguardmix | 243 | 0 | 0.00 |
| calibration | wildjailbreak | 12 | 0 | 0.00 |
| report | civil_comments | 5856 | 5 | 0.09 |
| report | jackhhao_jailbreak | 1321 | 0 | 0.00 |
| report | textdetox_de | 2492 | 0 | 0.00 |
