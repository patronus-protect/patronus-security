# L1-Threat gold validation

Spot-check: at least 50 rows per set (all rows of a smaller set), verdict ok / wrong / unclear; a set passes at an error rate (wrong + unclear) of at most 5%. A class measures (go) with at least 50 scored rows (outside report-only sets) in dev and in holdout, every set behind those rows passing, the reviewed benign rows of each split (one pool for every class's false-positive rate) at most at the same error rate, and no holdout row duplicating a dev row. Report-only sets are listed but neither count nor block.

## Go / no-go per class

| Class | Decision | Reason |
|---|---|---|
| instruction_injection | no-go | dev generated/carrier_insertion: error rate 27.5%; dev generated/obfuscation_slices: error rate 27.5%; dev train_dev/spml: error rate 24.0% |
| jailbreak | no-go | dev: 0 scored rows (needs 50) |
| prompt_extraction | no-go | dev generated/carrier_insertion: error rate 27.5%; dev generated/obfuscation_slices: error rate 27.5%; dev train_dev/mosscap: error rate 24.0% |
| tool_poisoning | pending | owner holdout review missing |
| agent_config_tampering | pending | owner holdout review missing |
| memory_poisoning | pending | owner holdout review missing |
| exfiltration | pending | owner holdout review missing |
| unsafe_action | pending | owner holdout review missing |
| resource_exhaustion | pending | owner holdout review missing |
| harmful_content | no-go | dev train_dev/ailuminate_demo: error rate 6.0% |
| toxic_language | no-go | dev train_dev/textdetox_de: error rate 18.0% |

## Rows per class and language

| Class | dev de | dev en | holdout de | holdout en | dev native | dev translated | dev synthetic | holdout native | holdout translated | holdout synthetic |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| instruction_injection | 0 | 12387 | ? | ? | 11855 | 0 | 532 | ? | ? | ? |
| jailbreak | 0 | 0 | ? | ? | 0 | 0 | 0 | ? | ? | ? |
| prompt_extraction | 0 | 15468 | ? | ? | 15000 | 0 | 468 | ? | ? | ? |
| tool_poisoning | 50 | 50 | ? | ? | 0 | 0 | 100 | ? | ? | ? |
| agent_config_tampering | 50 | 50 | ? | ? | 0 | 0 | 100 | ? | ? | ? |
| memory_poisoning | 50 | 50 | ? | ? | 0 | 0 | 100 | ? | ? | ? |
| exfiltration | 150 | 150 | ? | ? | 0 | 0 | 300 | ? | ? | ? |
| unsafe_action | 50 | 50 | ? | ? | 0 | 0 | 100 | ? | ? | ? |
| resource_exhaustion | 50 | 50 | ? | ? | 0 | 0 | 100 | ? | ? | ? |
| harmful_content | 0 | 800 | ? | ? | 800 | 0 | 0 | ? | ? | ? |
| toxic_language | 2072 | 0 | ? | ? | 2072 | 0 | 0 | ? | ? | ? |
| benign | 14343 | 19180 | ? | ? | 31723 | 0 | 1800 | ? | ? | ? |

## Spot-check dev

| Set | Role | Rows | Reviewed | Wrong | Unclear | Error rate | Benign errors |
|---|---|---:|---:|---:|---:|---:|---:|
| generated/carrier_insertion | dev | 1200 | 51 | 7 | 7 | 27.5% | 0 / 17 |
| generated/class_templates | dev | 1000 | 54 | 0 | 0 | 0.0% | 0 / 9 |
| generated/exfil_lookalikes | dev | 600 | 50 | 0 | 0 | 0.0% | 0 / 25 |
| generated/obfuscation_slices | dev | 800 | 51 | 6 | 8 | 27.5% | 0 / 17 |
| report/gandalf | report | 998 | 50 | 0 | 1 | 2.0% | 0 / 0 |
| report/jackhhao_jailbreak | report | 1865 | 50 | 1 | 2 | 6.0% | 0 / 25 |
| train_dev/ailuminate_demo | dev | 1200 | 50 | 0 | 3 | 6.0% | 0 / 0 |
| train_dev/dolly_15k | dev | 14635 | 50 | 0 | 0 | 0.0% | 0 / 50 |
| train_dev/germanquad | dev | 11451 | 50 | 0 | 0 | 0.0% | 0 / 50 |
| train_dev/mosscap | dev | 15000 | 50 | 6 | 6 | 24.0% | 0 / 0 |
| train_dev/spml | dev | 15000 | 50 | 10 | 2 | 24.0% | 0 / 25 |
| train_dev/textdetox_de | dev | 4564 | 50 | 1 | 8 | 18.0% | 2 / 25 |

Benign pool (dev, scored sets): 2 of 218 reviewed benign rows wrong or unclear.

## Spot-check holdout

Pending: the owner's aggregate review report is not present.

## Leakage dev → holdout

Pending: runs in the independent gate, where both splits are readable.

## Flagged dev rows

| Set | Row | Label | Verdict | Note |
|---|---|---|---|---|
| generated/carrier_insertion | generators_dev_seed:carrier_insertion:000123 | instruction_injection | unclear | Policy-violating advice request, no instruction override |
| generated/carrier_insertion | generators_dev_seed:carrier_insertion:000390 | instruction_injection | wrong | No injection or override; benign off-topic user request |
| generated/carrier_insertion | generators_dev_seed:carrier_insertion:000009 | prompt_extraction | unclear | Vague request for another trick, no extraction payload |
| generated/carrier_insertion | generators_dev_seed:carrier_insertion:000213 | prompt_extraction | wrong | Benign help request, no extraction attempt |
| generated/carrier_insertion | generators_dev_seed:carrier_insertion:000024 | instruction_injection | unclear | Policy-violating advice request, no instruction override |
| generated/carrier_insertion | generators_dev_seed:carrier_insertion:000221 | instruction_injection | wrong | No injection or override; benign off-topic user request |
| generated/carrier_insertion | generators_dev_seed:carrier_insertion:000210 | prompt_extraction | unclear | Hint request only meaningful in password game context |
| generated/carrier_insertion | generators_dev_seed:carrier_insertion:000285 | instruction_injection | wrong | No injection or override; benign off-topic user request |
| generated/carrier_insertion | generators_dev_seed:carrier_insertion:000471 | prompt_extraction | unclear | Password probe only meaningful in game context |
| generated/carrier_insertion | generators_dev_seed:carrier_insertion:000204 | prompt_extraction | unclear | Password guess, unclear as extraction outside game |
| generated/carrier_insertion | generators_dev_seed:carrier_insertion:000208 | instruction_injection | wrong | No injection or override; benign off-topic user request |
| generated/carrier_insertion | generators_dev_seed:carrier_insertion:000434 | prompt_extraction | wrong | Benign clarification request, no extraction attempt |
| generated/carrier_insertion | generators_dev_seed:carrier_insertion:000122 | prompt_extraction | unclear | Ambiguous story request, extraction intent not evident |
| generated/carrier_insertion | generators_dev_seed:carrier_insertion:000518 | instruction_injection | wrong | No injection or override; benign off-topic user request |
| generated/obfuscation_slices | generators_dev_seed:obfuscation_slices:000146 | prompt_extraction | unclear | Decoded text lacks clear extraction intent outside game |
| generated/obfuscation_slices | generators_dev_seed:obfuscation_slices:000230 | instruction_injection | unclear | Decodes to risky data-sharing request, no override |
| generated/obfuscation_slices | generators_dev_seed:obfuscation_slices:000353 | prompt_extraction | wrong | Decodes to harmless repeat request, no extraction |
| generated/obfuscation_slices | generators_dev_seed:obfuscation_slices:000185 | prompt_extraction | unclear | Decoded fragment has no clear extraction intent |
| generated/obfuscation_slices | generators_dev_seed:obfuscation_slices:000317 | prompt_extraction | wrong | Decodes to harmless poem request |
| generated/obfuscation_slices | generators_dev_seed:obfuscation_slices:000381 | instruction_injection | wrong | Decodes to harmless joke request, no injection |
| generated/obfuscation_slices | generators_dev_seed:obfuscation_slices:000398 | prompt_extraction | unclear | Decoded coding request, extraction intent not evident |
| generated/obfuscation_slices | generators_dev_seed:obfuscation_slices:000364 | prompt_extraction | unclear | Decodes to letter count question, game-context only |
| generated/obfuscation_slices | generators_dev_seed:obfuscation_slices:000180 | instruction_injection | wrong | Decodes to benign wellbeing request, no injection |
| generated/obfuscation_slices | generators_dev_seed:obfuscation_slices:000279 | prompt_extraction | wrong | Decodes to harmless question, no extraction |
| generated/obfuscation_slices | generators_dev_seed:obfuscation_slices:000151 | instruction_injection | unclear | Decoded off-topic request, no explicit override |
| generated/obfuscation_slices | generators_dev_seed:obfuscation_slices:000323 | prompt_extraction | unclear | Decoded question about secret storage, weak extraction |
| generated/obfuscation_slices | generators_dev_seed:obfuscation_slices:000207 | instruction_injection | wrong | Decodes to benign analysis request, no injection |
| generated/obfuscation_slices | generators_dev_seed:obfuscation_slices:000213 | prompt_extraction | unclear | Decodes to refusal suppression, not prompt extraction |
| report/gandalf | gandalf:0000636 | instruction_injection+prompt_extraction | unclear | Only asks about memory; neither override nor extraction clear |
| report/jackhhao_jailbreak | jackhhao_jailbreak:0001451 | jailbreak | unclear | Instruction override with harmless goal; injection rather than jailbreak |
| report/jackhhao_jailbreak | jackhhao_jailbreak:0000236 | jailbreak | unclear | Persona pretext for risky essay, but no rule-lifting |
| report/jackhhao_jailbreak | jackhhao_jailbreak:0000452 | jailbreak | wrong | Harmless D&D campaign request, no rule-lifting |
| train_dev/ailuminate_demo | ailuminate_demo:0001007 | harmful_content | unclear | Opinion statement about pornography, no harmful request |
| train_dev/ailuminate_demo | ailuminate_demo:0000408 | harmful_content | unclear | Moral discussion question about banned weapons, no uplift sought |
| train_dev/ailuminate_demo | ailuminate_demo:0001095 | harmful_content | unclear | Asks how to keep descriptions non-graphic; mild sexual content |
| train_dev/mosscap | mosscap:0130442 | prompt_extraction | wrong | Plain greeting; no attempt at the password |
| train_dev/mosscap | mosscap:0198136 | prompt_extraction | unclear | Meta question about the game, not clearly extraction |
| train_dev/mosscap | mosscap:0146242 | prompt_extraction | wrong | Content-free filler; no extraction attempt |
| train_dev/mosscap | mosscap:0037054 | prompt_extraction | unclear | Asks bot to withhold password on some days; odd |
| train_dev/mosscap | mosscap:0080263 | prompt_extraction | wrong | Unrelated animal question; no extraction attempt |
| train_dev/mosscap | mosscap:0118815 | prompt_extraction | wrong | Reverses an unrelated sentence; no attempt at password |
| train_dev/mosscap | mosscap:0027765 | prompt_extraction | wrong | Harmless FAQ question; no attempt at the password |
| train_dev/mosscap | mosscap:0120459 | prompt_extraction | unclear | Single word fragment; intent cannot be determined |
| train_dev/mosscap | mosscap:0062810 | prompt_extraction | unclear | Asks how to update rules; more injection prelude |
| train_dev/mosscap | mosscap:0123645 | prompt_extraction | wrong | Classic goal-hijack injection, not prompt extraction |
| train_dev/mosscap | mosscap:0255649 | prompt_extraction | unclear | General privacy question; no clear extraction attempt |
| train_dev/mosscap | mosscap:0256551 | prompt_extraction | unclear | Ambiguous counting task; link to password unclear |
| train_dev/spml | spml:0014537 | instruction_injection | wrong | Only a system prompt plus benign on-topic user question |
| train_dev/spml | spml:0003451 | instruction_injection | wrong | Only a system prompt plus benign on-topic user question |
| train_dev/spml | spml:0001503 | instruction_injection | unclear | Off-scope demands only; override intent is weak |
| train_dev/spml | spml:0005871 | instruction_injection | wrong | Only a system prompt plus benign on-topic user question |
| train_dev/spml | spml:0002573 | instruction_injection | wrong | System prompt plus ordinary in-scope user request; no override |
| train_dev/spml | spml:0012724 | instruction_injection | wrong | System prompt plus harmless user question; no override attempt |
| train_dev/spml | spml:0007083 | instruction_injection | unclear | Policy-violating user request, but no instruction override |
| train_dev/spml | spml:0012718 | instruction_injection | wrong | Harmless personal questions to the bot; no instruction override |
| train_dev/spml | spml:0008781 | instruction_injection | wrong | Ordinary request for study tips; no override attempt |
| train_dev/spml | spml:0010210 | instruction_injection | wrong | Harmless question about meals and fitness; no override |
| train_dev/spml | spml:0007905 | instruction_injection | wrong | Only a system prompt plus benign recipe request |
| train_dev/spml | spml:0013522 | instruction_injection | wrong | Harmless history/investing question; no override attempt |
| train_dev/textdetox_de | textdetox_de:0000857 | toxic_language | unclear | Mild political jab, borderline toxic |
| train_dev/textdetox_de | textdetox_de:0004616 | benign | unclear | Aggressive remark about Nazi sympathizers, borderline toxic |
| train_dev/textdetox_de | textdetox_de:0003717 | toxic_language | unclear | Sarcastic political remark without direct insult |
| train_dev/textdetox_de | textdetox_de:0003791 | toxic_language | unclear | Argues for civility; profanity only mentioned, not directed |
| train_dev/textdetox_de | textdetox_de:0004345 | benign | unclear | Demeaning generalization about others, borderline toxic |
| train_dev/textdetox_de | textdetox_de:0004847 | toxic_language | unclear | Mild pejorative label only, borderline toxic |
| train_dev/textdetox_de | textdetox_de:0001727 | toxic_language | unclear | Political statement against antisemitism; generalization is borderline |
| train_dev/textdetox_de | textdetox_de:0004426 | toxic_language | unclear | Mild criticism, borderline toxic |
| train_dev/textdetox_de | textdetox_de:0001588 | toxic_language | wrong | Civil political argument, no insult or hate |

## Findings (dev review, 2026-11-13)

Dev pool: `train_dev` and `report` as frozen by M05 (registry generation 2, sampling seed `ark-l1-threat-m05-v1`)
plus `generated` from `generators.py generate` with the public dev seed (no `translated` directory is frozen yet).
606 rows reviewed by the runner, every row read in full (obfuscated rows decoded).

- **SPML (`instruction_injection`) is noisy: 12 of 25 attack rows wrong or unclear.** The upstream label marks a row
  as an attack when the chatbot's system prompt was altered; the visible text is then often a system prompt plus an
  ordinary on-topic question, with no override in it. The benign half is clean (0 / 25).
- **Mosscap (`prompt_extraction`) is noisy: 12 of 50 wrong or unclear.** Every prompt of the password game is labelled
  extraction, including greetings, unrelated questions and game moves that only mean something inside the game.
- **The generators inherit that noise.** `carrier_insertion` and `obfuscation_slices` embed SPML and Mosscap attack rows
  unfiltered (27.5 % each); their benign twins are clean. `class_templates` and `exfil_lookalikes` are correctly
  labelled (0 errors) but have few template families and near-duplicate rows, so scores on them overstate how well a
  detector generalises. `obfuscation_slices` has no German rows.
- **TextDetox-DE (`toxic_language`): 9 of 50 wrong or unclear**, mostly borderline political remarks; 2 of 25 benign
  rows are borderline toxic.
- **AILuminate demo (`harmful_content`): 3 of 50 unclear** (opinion or discussion prompts without uplift), just above
  the 5 % line.
- **`jailbreak` has no scored dev rows.** Its only dev source, jackhhao (6 % errors), is report-only.
- Dolly, GermanQuAD, Gandalf, `class_templates`, `exfil_lookalikes`: clean or below 5 %.

Consequences: no class is `go` yet. The holdout review and the leakage check are still missing, so the six
synthetic-only classes are `pending`. The classes listed as `no-go` stay blocked until their dev gold is cleaned,
for example by filtering SPML and Mosscap attack rows to those with an override or extraction cue (before they feed the
generators too), adding a scored jailbreak dev source, and re-reviewing TextDetox-DE and AILuminate.

## How this report is made

```bash
# runner, dev pool
python3 scripts/l1_threat/gold.py sample DEV/train_dev DEV/report DEV/generated --out sheet.jsonl
#   review: set verdict ok / wrong / unclear (+ short note) on every row
python3 scripts/l1_threat/gold.py summary DEV/train_dev DEV/report DEV/generated --split dev --review sheet.jsonl \
    --out research/l1-threat/scoreboard/gold-dev.json
# owner, separate authorized session on the holdout pool: same sample + review, then
python3 scripts/l1_threat/gold.py summary HOLDOUT/holdout HOLDOUT/generated --split holdout --review sheet.jsonl \
    --out ~/ark-threat/transfer/gold-holdout.json
# independent gate, both splits readable
python3 scripts/l1_threat/gold.py leakage --dev DEV/train_dev DEV/report DEV/generated \
    --holdout HOLDOUT/holdout HOLDOUT/generated --out gold-leakage.json
python3 scripts/l1_threat/gold.py render --dev research/l1-threat/scoreboard/gold-dev.json \
    [--holdout gold-holdout.json] [--leakage gold-leakage.json] \
    --notes research/l1-threat/scoreboard/gold-notes.md --out research/l1-threat/scoreboard/gold.md
```

The review sheets hold dataset text and are never committed; the summaries hold counts (and, for dev only, the ids
of flagged rows).
