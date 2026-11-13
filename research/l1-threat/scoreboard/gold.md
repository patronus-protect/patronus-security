# L1-Threat gold validation

Spot-check: at least 50 rows per set (all rows of a smaller set), verdict ok / wrong / unclear; a set passes at an error rate (wrong + unclear) of at most 5%. A class measures (go) with at least 50 scored rows (outside report-only sets) in dev and in holdout, every set behind those rows passing, the reviewed benign rows of each split (one pool for every class's false-positive rate) at most at the same error rate, and no holdout row duplicating a dev row. Report-only sets are listed but neither count nor block.

## Go / no-go per class

| Class | Decision | Reason |
|---|---|---|
| instruction_injection | pending | owner holdout review missing |
| jailbreak | pending | owner holdout review missing |
| prompt_extraction | pending | owner holdout review missing |
| tool_poisoning | pending | owner holdout review missing |
| agent_config_tampering | pending | owner holdout review missing |
| memory_poisoning | pending | owner holdout review missing |
| exfiltration | pending | owner holdout review missing |
| unsafe_action | pending | owner holdout review missing |
| resource_exhaustion | pending | owner holdout review missing |
| harmful_content | no-go | dev: 0 scored rows (needs 50) |
| toxic_language | no-go | dev: 0 scored rows (needs 50) |

## Rows per class and language

| Class | dev de | dev en | holdout de | holdout en | dev native | dev translated | dev synthetic | holdout native | holdout translated | holdout synthetic |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| instruction_injection | 0 | 2927 | ? | ? | 2403 | 0 | 524 | ? | ? | ? |
| jailbreak | 42 | 42 | ? | ? | 0 | 0 | 84 | ? | ? | ? |
| prompt_extraction | 0 | 15476 | ? | ? | 15000 | 0 | 476 | ? | ? | ? |
| tool_poisoning | 42 | 41 | ? | ? | 0 | 0 | 83 | ? | ? | ? |
| agent_config_tampering | 42 | 42 | ? | ? | 0 | 0 | 84 | ? | ? | ? |
| memory_poisoning | 42 | 41 | ? | ? | 0 | 0 | 83 | ? | ? | ? |
| exfiltration | 150 | 150 | ? | ? | 0 | 0 | 300 | ? | ? | ? |
| unsafe_action | 42 | 41 | ? | ? | 0 | 0 | 83 | ? | ? | ? |
| resource_exhaustion | 42 | 41 | ? | ? | 0 | 0 | 83 | ? | ? | ? |
| harmful_content | 0 | 0 | ? | ? | 0 | 0 | 0 | ? | ? | ? |
| toxic_language | 0 | 0 | ? | ? | 0 | 0 | 0 | ? | ? | ? |
| benign | 11853 | 19359 | ? | ? | 29412 | 0 | 1800 | ? | ? | ? |

## Spot-check dev

| Set | Role | Rows | Reviewed | Wrong | Unclear | Error rate | Benign errors |
|---|---|---:|---:|---:|---:|---:|---:|
| generated/carrier_insertion | dev | 1200 | 51 | 1 | 1 | 3.9% | 0 / 17 |
| generated/class_templates | dev | 1000 | 56 | 0 | 0 | 0.0% | 0 / 8 |
| generated/exfil_lookalikes | dev | 600 | 50 | 0 | 0 | 0.0% | 0 / 25 |
| generated/obfuscation_slices | dev | 800 | 51 | 0 | 2 | 3.9% | 0 / 17 |
| report/ailuminate_demo | report | 1200 | 50 | 3 | 12 | 30.0% | 0 / 0 |
| report/gandalf | report | 998 | 50 | 0 | 1 | 2.0% | 0 / 0 |
| report/jackhhao_jailbreak | report | 1865 | 50 | 1 | 2 | 6.0% | 0 / 25 |
| report/textdetox_de | report | 4564 | 50 | 2 | 9 | 22.0% | 3 / 25 |
| train_dev/dolly_15k | dev | 14635 | 50 | 0 | 0 | 0.0% | 0 / 50 |
| train_dev/germanquad | dev | 11451 | 50 | 0 | 0 | 0.0% | 0 / 50 |
| train_dev/mosscap | dev | 15000 | 50 | 0 | 1 | 2.0% | 0 / 0 |
| train_dev/spml | dev | 5729 | 50 | 0 | 1 | 2.0% | 0 / 25 |

Benign pool (dev, scored sets): 0 of 192 reviewed benign rows wrong or unclear.

## Spot-check holdout

Pending: the owner's aggregate review report is not present.

## Leakage dev → holdout

Pending: runs in the independent gate, where both splits are readable.

## Flagged dev rows

| Set | Row | Label | Verdict | Note |
|---|---|---|---|---|
| train_dev/spml | spml:0007279 | instruction_injection | unclear | Only asks whether override possible; rest no override |
| report/ailuminate_demo | ailuminate_demo:0000505 | harmful_content | unclear | Discussion of fraud tactics; mostly educational, limited uplift |
| report/ailuminate_demo | ailuminate_demo:0000510 | harmful_content | wrong | Asks how to react to crime; seeks no uplift |
| report/ailuminate_demo | ailuminate_demo:0000624 | other | unclear | Garbled; vulnerability angle is cyber, not reported subclass |
| report/ailuminate_demo | ailuminate_demo:0001023 | harmful_content | unclear | Incoherent opinion question; no harmful request |
| report/ailuminate_demo | ailuminate_demo:0000380 | other | unclear | Benign question on avoiding copyright infringement |
| report/ailuminate_demo | ailuminate_demo:0001139 | harmful_content | wrong | Opinion rant about justice system; no harm sought |
| report/ailuminate_demo | ailuminate_demo:0000182 | other | unclear | Fact-check question; weak defamation link |
| report/ailuminate_demo | ailuminate_demo:0001145 | harmful_content | unclear | Analytical question about terrorism; no clear uplift |
| report/ailuminate_demo | ailuminate_demo:0000743 | other | unclear | Asset concealment is crime help, fits harmful_content |
| report/ailuminate_demo | ailuminate_demo:0000388 | other | unclear | Benign career question; weak IP link |
| report/ailuminate_demo | ailuminate_demo:0001196 | harmful_content | unclear | Vague philosophical question; no uplift |
| report/ailuminate_demo | ailuminate_demo:0000449 | harmful_content | unclear | Historical bioweapon info; jailbreak frame, little uplift |
| report/ailuminate_demo | ailuminate_demo:0000502 | harmful_content | unclear | Tax planning loopholes; borderline legal |
| report/ailuminate_demo | ailuminate_demo:0000590 | harmful_content | unclear | Statement about abandoning child; no request |
| report/ailuminate_demo | ailuminate_demo:0000931 | harmful_content | wrong | Benign question about coping behaviours |
| report/gandalf | gandalf:0000636 | instruction_injection+prompt_extraction | unclear | Only asks about memory; neither override nor extraction clear |
| report/jackhhao_jailbreak | jackhhao_jailbreak:0001451 | jailbreak | unclear | Instruction override with harmless goal; injection rather than jailbreak |
| report/jackhhao_jailbreak | jackhhao_jailbreak:0000236 | jailbreak | unclear | Persona pretext for risky essay, but no rule-lifting |
| report/jackhhao_jailbreak | jackhhao_jailbreak:0000452 | jailbreak | wrong | Harmless D&D campaign request, no rule-lifting |
| report/textdetox_de | textdetox_de:0002064 | toxic_language | unclear | Sarcastic political jab; mild |
| report/textdetox_de | textdetox_de:0002101 | toxic_language | unclear | Sarcastic camp remark; tone unclear |
| report/textdetox_de | textdetox_de:0003412 | benign | unclear | Common dehumanizing trope, likely aimed at migrants |
| report/textdetox_de | textdetox_de:0004666 | toxic_language | unclear | Crude but generic political venting |
| report/textdetox_de | textdetox_de:0002408 | toxic_language | unclear | Harsh political comparison, no direct insult |
| report/textdetox_de | textdetox_de:0004698 | toxic_language | wrong | Political criticism without insult |
| report/textdetox_de | textdetox_de:0001886 | toxic_language | unclear | Ethnically framed deportation call; borderline |
| report/textdetox_de | textdetox_de:0003894 | toxic_language | wrong | Political complaint without insult |
| report/textdetox_de | textdetox_de:0002396 | benign | unclear | Mild jab at addressee's education |
| report/textdetox_de | textdetox_de:0001950 | toxic_language | unclear | Condescending but mild |
| report/textdetox_de | textdetox_de:0004397 | benign | unclear | Calls politician fascist; insulting label |
| generated/carrier_insertion | generators_dev_seed:carrier_insertion:000024 | prompt_extraction | unclear | Fake note tells bot to deny knowing password |
| generated/carrier_insertion | generators_dev_seed:carrier_insertion:000435 | prompt_extraction | wrong | Sets a new password, no extraction request |
| generated/obfuscation_slices | generators_dev_seed:obfuscation_slices:000279 | instruction_injection | unclear | Roleplay password extraction; override phrase only quoted |
| generated/obfuscation_slices | generators_dev_seed:obfuscation_slices:000180 | prompt_extraction | unclear | Meta question on password case, no extraction |
| train_dev/mosscap | mosscap:0068803 | prompt_extraction | unclear | Literal phrase request; extraction intent only implied |

## Findings (first dev review, 2026-11-13)

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

## Findings (dev review after the gold cleanup, 2026-11-13)

Dev pool rebuilt from the cleaned recipes (registry generation 4, generator version 3; built locally with the
same recipes the gate uses) and re-sampled with `gold.py sample`. Every set whose rows changed was reviewed again in
full; sets with unchanged rows and sample (Dolly, GermanQuAD, Gandalf, jackhhao, `exfil_lookalikes`) keep their first
verdicts, and the re-sampled report-only sets (TextDetox-DE, AILuminate demo) and `class_templates` were reviewed anew.

- **SPML: 1 of 50 unclear (was 24 %).** The recipe keeps an attack row only when its user turn (after the last `###`
  separator, or the whole text without one) carries an override cue; 10 138 attack rows without one are dropped and
  counted in the manifest (`dropped.no_cue`). SPML now has 5 729 rows (2 403 attacks).
- **Mosscap: 1 of 50 unclear (was 24 %).** The recipe keeps a prompt only when it asks for, probes or confirms the
  secret (a request word next to the secret in the same sentence) or names the hidden instructions; 192 258 prompts
  are dropped as `no_cue` before deduplication, 42 666 remain before the row cap (15 000 after).
- **`carrier_insertion` and `obfuscation_slices` inherit the cleanup** (they embed the filtered SPML and Mosscap
  rows); no template change was needed, their benign twins were already clean.
- **TextDetox-DE and the AILuminate demo are report-only.** The re-review confirms the first one (TextDetox-DE 11 of
  50, AILuminate 15 of 50 wrong or unclear: civil political remarks labelled toxic, opinion and discussion prompts
  labelled harmful). `toxic_language` and `harmful_content` have no scored dev rows and stay not measurable until a
  cleaner source is registered; their rule tasks stay blocked.
- **`jailbreak` has 84 scored dev rows** from new `class_templates` families (persona without rules, refusal
  suppression; modelled on the DAN and Jailbroken papers, placeholders only, each with a look-alike twin).
- **`class_templates`:** 0 errors under the taxonomy's class definitions. Eight `agent_config_tampering` rows (a
  rules or skill file with a hidden instruction that sends data out) were first marked unclear against a narrower
  reviewer brief; the taxonomy defines the class as malicious instructions in skills, rules files and agent
  config, so they count as correct. The set still repeats some texts verbatim (few families), so scores on it
  overstate generalisation.

The holdout review and the leakage check are still missing, so no class can be `go` yet; the classes whose dev gold
now passes move from `no-go` to `pending`.

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
