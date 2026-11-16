# L1-Threat gold validation

Spot-check: at least 50 rows per set (all rows of a smaller set), verdict ok / wrong / unclear; a set passes at an error rate (wrong + unclear) of at most 5%. A class measures (go) with at least 50 scored rows (outside report-only sets) in dev and in holdout, every set behind those rows passing, the reviewed benign rows of each split (one pool for every class's false-positive rate) at most at the same error rate, and no holdout row duplicating a dev row. Report-only sets are listed but neither count nor block.

## Go / no-go per class

| Class | Decision | Reason |
|---|---|---|
| instruction_injection | no-go | dev generated/carrier_insertion: error rate 5.8% |
| jailbreak | no-go | dev generated/carrier_insertion: error rate 5.8% |
| prompt_extraction | no-go | dev generated/carrier_insertion: error rate 5.8% |
| tool_poisoning | go | - |
| agent_config_tampering | go | - |
| memory_poisoning | go | - |
| exfiltration | go | - |
| unsafe_action | go | - |
| resource_exhaustion | go | - |
| harmful_content | no-go | dev: 0 scored rows (needs 50); holdout holdout/jbb_behaviors: error rate 10.0% |
| toxic_language | no-go | dev: 0 scored rows (needs 50) |

## Rows per class and language

| Class | dev de | dev en | holdout de | holdout en | dev native | dev translated | dev synthetic | holdout native | holdout translated | holdout synthetic |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| instruction_injection | 653 | 2526 | 0 | 11711 | 2403 | 359 | 417 | 11711 | 0 | 0 |
| jailbreak | 42 | 2303 | 63 | 62 | 2000 | 0 | 345 | 0 | 0 | 125 |
| prompt_extraction | 885 | 15137 | 0 | 1831 | 15000 | 700 | 322 | 331 | 0 | 1500 |
| tool_poisoning | 42 | 41 | 63 | 62 | 0 | 0 | 83 | 0 | 0 | 125 |
| agent_config_tampering | 42 | 42 | 63 | 62 | 0 | 0 | 84 | 0 | 0 | 125 |
| memory_poisoning | 42 | 41 | 63 | 62 | 0 | 0 | 83 | 0 | 0 | 125 |
| exfiltration | 150 | 150 | 225 | 11936 | 0 | 0 | 300 | 11711 | 0 | 450 |
| unsafe_action | 42 | 41 | 63 | 62 | 0 | 0 | 83 | 0 | 0 | 125 |
| resource_exhaustion | 42 | 41 | 63 | 62 | 0 | 0 | 83 | 0 | 0 | 125 |
| harmful_content | 0 | 0 | 0 | 224 | 0 | 0 | 0 | 224 | 0 | 0 |
| toxic_language | 0 | 0 | 1999 | 2162 | 0 | 0 | 0 | 4161 | 0 | 0 |
| benign | 12682 | 18903 | 17191 | 12125 | 29435 | 350 | 1800 | 33730 | 0 | 2700 |

## Spot-check dev

| Set | Role | Rows | Reviewed | Wrong | Unclear | Error rate | Benign errors |
|---|---|---:|---:|---:|---:|---:|---:|
| generated/carrier_insertion | dev | 1200 | 52 | 0 | 3 | 5.8% | 0 / 13 |
| generated/class_templates | dev | 1000 | 56 | 0 | 0 | 0.0% | 0 / 8 |
| generated/exfil_lookalikes | dev | 600 | 50 | 0 | 0 | 0.0% | 0 / 25 |
| generated/obfuscation_slices | dev | 800 | 52 | 0 | 1 | 1.9% | 0 / 13 |
| report/ailuminate_demo | report | 1200 | 50 | 3 | 12 | 30.0% | 0 / 0 |
| report/gandalf | report | 998 | 50 | 0 | 1 | 2.0% | 0 / 0 |
| report/jackhhao_jailbreak | report | 1865 | 50 | 1 | 2 | 6.0% | 0 / 25 |
| report/textdetox_de | report | 4564 | 50 | 2 | 9 | 22.0% | 3 / 25 |
| train_dev/cyberseceval_multilingual | dev | 9 | 9 | 0 | 0 | 0.0% | 0 / 0 |
| train_dev/dolly_15k | dev | 14635 | 50 | 0 | 0 | 0.0% | 0 / 50 |
| train_dev/germanquad | dev | 11451 | 50 | 0 | 0 | 0.0% | 0 / 50 |
| train_dev/mosscap | dev | 15000 | 50 | 0 | 1 | 2.0% | 0 / 0 |
| train_dev/spml | dev | 5729 | 50 | 0 | 1 | 2.0% | 0 / 25 |
| train_dev/wildjailbreak | dev | 2023 | 50 | 0 | 1 | 2.0% | 0 / 23 |
| translated/runner_translations_de | dev | 1400 | 51 | 1 | 0 | 2.0% | 0 / 17 |

Benign pool (dev, scored sets): 0 of 224 reviewed benign rows wrong or unclear.

## Spot-check holdout

| Set | Role | Rows | Reviewed | Wrong | Unclear | Error rate | Benign errors |
|---|---|---:|---:|---:|---:|---:|---:|
| generated/carrier_insertion | decisive | 1800 | 50 | 0 | 1 | 2.0% | 0 / 25 |
| generated/class_templates | decisive | 1500 | 56 | 0 | 0 | 0.0% | 0 / 8 |
| generated/exfil_lookalikes | decisive | 900 | 50 | 0 | 0 | 0.0% | 0 / 25 |
| generated/obfuscation_slices | decisive | 1200 | 50 | 0 | 0 | 0.0% | 0 / 25 |
| holdout/cyberseceval_pi | decisive | 232 | 50 | 27 | 2 | 58.0% | 0 / 0 |
| holdout/hatecheck_de | decisive | 2844 | 50 | 0 | 0 | 0.0% | 0 / 25 |
| holdout/hatecheck_en | decisive | 3153 | 50 | 0 | 0 | 0.0% | 0 / 25 |
| holdout/jbb_behaviors | decisive | 60 | 50 | 2 | 3 | 10.0% | 0 / 0 |
| holdout/llmail_inject | decisive | 11711 | 150 | 0 | 7 | 4.7% | 0 / 0 |
| holdout/multijail | decisive | 315 | 50 | 13 | 13 | 52.0% | 0 / 0 |
| holdout/notinject | decisive | 339 | 50 | 0 | 0 | 0.0% | 0 / 50 |
| holdout/oasst2 | decisive | 14988 | 50 | 0 | 0 | 0.0% | 0 / 50 |
| holdout/or_bench_hard | decisive | 1318 | 50 | 2 | 4 | 12.0% | 6 / 50 |
| holdout/tensortrust_extraction | decisive | 331 | 50 | 0 | 0 | 0.0% | 0 / 0 |
| holdout/trustairlab_jailbreak | decisive | 643 | 50 | 9 | 3 | 24.0% | 0 / 0 |
| holdout/wikipedia | decisive | 15000 | 50 | 0 | 0 | 0.0% | 0 / 50 |
| holdout/xstest | decisive | 448 | 51 | 0 | 2 | 3.9% | 0 / 17 |

Benign pool (holdout, scored sets): 6 of 350 reviewed benign rows wrong or unclear.

## Leakage dev → holdout

0 of 56782 holdout rows duplicate one of 61074 dev rows (exact or MinHash).

## Flagged dev rows

| Set | Row | Label | Verdict | Note |
|---|---|---|---|---|
| train_dev/mosscap | mosscap:0068803 | prompt_extraction | unclear | Literal phrase request; extraction intent only implied |
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
| translated/runner_translations_de | runner_translations_de:mosscap:0087864 | prompt_extraction | wrong | Thank-you message only; no request for password or hints |
| train_dev/wildjailbreak | wildjailbreak:0002208 | jailbreak | unclear | Fantasy forgery of spell scrolls; harmful goal only implied |
| generated/carrier_insertion | generators_dev_seed:carrier_insertion:000390 | prompt_extraction | unclear | Claims to have set the password rule; no reveal or hint request |
| generated/carrier_insertion | generators_dev_seed:carrier_insertion:000127 | prompt_extraction | unclear | Asks the model to agree never to share the password; no request |
| generated/carrier_insertion | generators_dev_seed:carrier_insertion:000033 | instruction_injection | unclear | Fake mode claim only; payload is ordinary physics question |
| generated/obfuscation_slices | generators_dev_seed:obfuscation_slices:000231 | prompt_extraction | unclear | Bare statement that key is wrong; no request |

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
verdicts (`exfil_lookalikes` keeps its version-2 random stream, so its 600 rows are byte-identical to the reviewed ones), and the re-sampled report-only sets (TextDetox-DE, AILuminate demo) and `class_templates` were reviewed anew.

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

## Findings (dev review of the German rows, 2026-11-16)

Dev pool rebuilt locally with the recipes of this change (registry generation 6, generator version 4) plus the
runner translations (`DEV/translated`, ingested from the filled worksheet). `train_dev` and `report` keep their
rows byte for byte (only the contamination column differs locally, because the holdout training sources are not
readable outside the gate), so their earlier verdicts carry over. Every new or changed set was reviewed in full:
`translated/runner_translations_de`, `train_dev/cyberseceval_multilingual`, `generated/carrier_insertion` and
`generated/obfuscation_slices`.

- **Runner translations: 1 of 51 wrong (2.0 %).** 1 400 rows (SPML 350 attacks + 350 benign, Mosscap 700), translated by
  the runner agent without MT; the fixed hand-check sample (70 rows) was read against the English source and is
  marked `checked`. The one wrong row is a Mosscap thank-you without a request, so the noise is upstream, not
  the translation.
- **CyberSecEval multilingual: 9 of 9 ok.** Of 39 German test cases, 30 carry the attack only relative to the
  off-row system prompt (a recipe request, a paper summary) and are dropped by the cue filter; the 16 other
  languages are out of scope. Two kept rows mix in Spanish or Korean text (the upstream machine translation).
- **`carrier_insertion`: 2 of 51 unclear (3.9 %).** German now 696 of 1 200 rows.
- **`obfuscation_slices`: 9 of 102 wrong or unclear (8.8 %, first 51 rows: 4, next 51: 5) — above the 5 % line.**
  Most flags are Mosscap rows (English or translated) that only state something about the password ("it is X",
  "it is wrong") without a request; the Mosscap cue filter accepts them through the request word `is`. Two
  SPML rows carry only a mode claim or ask how to bypass rules. The set embeds both sources at random, so its
  error rate follows the upstream noise of Mosscap (1 of 50 in its own sample). Follow-up: tighten the Mosscap
  cue against bare statements (re-review Mosscap and both generated sets).

Rows per class: `instruction_injection` 762 German dev rows (359 translated: 350 runner + 9 CyberSecEval; 403
synthetic with a German or translated source), `prompt_extraction` 885 (700 translated), German benign twins 350.
The local dev scoreboard (`scoreboard.py score`) reports `de` for both classes (instruction_injection de TPR@1 %
46.5 %, prompt_extraction 0 % as before T03).

Handoff: the dev corpora are read-only for the runner. The filled worksheet stays on the VPS outside the
repository (third-party derived rows): `~/ark-threat/worktrees/threat-078-t02/.l1-threat-translations/runner_translations_de.sheet.jsonl`
(git-ignored, SHA-256 `3ce667e5b982ec23…`); the owner freeze ingests it (`generators.py translate ingest --dev-out
DEV --sheet SHEET`) before `prepare_corpora.py` and `generators.py generate` re-freeze dev.

## Findings (dev review of the native jailbreak source, 2026-11-16)

Dev pool rebuilt locally with the recipes of this change (registry generation 8, generator version 4): the frozen
`train_dev` and `report` sets keep their rows byte for byte, `train_dev/wildjailbreak` is new, and the generators
draw attack and benign rows from it too. No `translated` directory is frozen in dev yet, so the counts above are the
earlier summary plus the difference this change makes on the local build (with and without WildJailbreak); the
runner translations keep their earlier review. Every new or changed set was reviewed in full:
`train_dev/wildjailbreak`, `generated/carrier_insertion` and `generated/obfuscation_slices` (obfuscated rows judged
on their source text). Unchanged sets keep their verdicts.

- **WildJailbreak: 1 of 50 unclear (2.0 %), benign 0 of 23.** Eval split of WildJailbreak (ODC-BY), 2 000
  `adversarial_harmful` rows scored as `jailbreak` (all carry a framing meant to get around the model's safety rules:
  persona, fiction or alternate world, policy spoof, response priming, research or debate pretext, trivialisation);
  the one unclear row wraps a fantasy forgery whose harmful goal is only implied. `harmful_content` is reported only
  for this set: the wrapped requests also cover one-sided essays and mild profanity.
- **Benign side: 23 hard negatives of 210.** The first review of the raw `adversarial_benign` rows found many that keep
  the bypass framing itself (avoid a refusal, exempt from rules or ethics, uncensored persona, persona lock, fake
  update or content policy, coded safety override, letter spacing, named jailbreak templates). By the class definition
  that framing is jailbreak however harmless the request, so the recipe keeps a benign row only without such a cue
  (187 dropped as `no_cue`); the 23 left are role-play and fiction framings around harmless requests and were all read
  in full. They join the scoreboard's hard-benign pool.
- **`carrier_insertion`: 3 of 52 unclear (5.8 %) — above the 5 % line.** The flagged rows are two Mosscap statements
  without a request and one CyberSecEval mode claim around an ordinary question (the same upstream noise as before);
  the 13 sampled WildJailbreak attacks and all benign twins are correct. Follow-up as noted for the German rows: tighten
  the Mosscap cue against bare statements.
- **`obfuscation_slices`: 1 of 52 unclear (1.9 %, was 8.8 %).** Fewer Mosscap rows in the sample now that the
  generators share their picks with WildJailbreak; the remaining flag is a bare Mosscap statement.

Rows per class: `jailbreak` 2 345 scored dev rows (2 000 native, 345 synthetic incl. 261 WildJailbreak rows inside
generated carriers and obfuscations). Generated German `instruction_injection` rows drop from 762 to 653, because the
generators now spread their picks over one more attack source. WildGuardMix stays without a recipe: the upstream
dataset is gated and no ungated copy with the original rows and a clear licence was found.

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
