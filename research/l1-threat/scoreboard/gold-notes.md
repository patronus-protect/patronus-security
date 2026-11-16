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
