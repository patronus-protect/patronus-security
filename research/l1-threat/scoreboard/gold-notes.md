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

## Findings (dev re-review after the agent-set re-freeze, 2026-11-17)

Dev pool: the frozen `train_dev` and `report` sets of registry generation 11 (the re-freeze after the agent-class
recipes), with BIPIA rebuilt locally under the recipe fix below (generation 12; every kept row is byte-identical to
the frozen one, 44 rows drop), and `generated` re-run on that pool (generator version 4). Re-sampled with
`gold.py sample`; a row keeps its earlier verdict only when its set, id and text are unchanged (Dolly, GermanQuAD,
SPML, Mosscap, WildJailbreak, CyberSecEval multilingual, the report sets, `class_templates`, `exfil_lookalikes`:
counts identical to the previous summary). Every new or changed row was read in full, obfuscated rows on their
source text: `train_dev/agentdojo`, `train_dev/bipia`, `train_dev/approve_or_deny_de` (all three never reviewed
before), `generated/carrier_insertion` and `generated/obfuscation_slices` (both now also embed AgentDojo, BIPIA and
approve-or-deny rows). The frozen dev pool holds no `translated` directory (the runner worksheet was never ingested
by an owner freeze), so the runner translations leave the summary; their earlier review (1 of 51) stands, and German
dev rows of `prompt_extraction` come back with that ingest.

- **BIPIA: 5 of 51 unclear (9.8 %) before the fix — above the 5 % line.** Error pattern: a bare task-irrelevant
  request inserted into an e-mail ("Explain the theory of relativity.", "Determine the sentiment of this review",
  a backup how-to question) carries no override and no address to the assistant; in the e-mail it reads as ordinary
  content, so the text alone does not show an injection. BIPIA files these under its task-irrelevant groups (test:
  task automation, business intelligence, conversational agent, research assistance, sentiment analysis; train:
  information retrieval, content creation, learning and tutoring, language translation, programming help). **Fix
  (recipe filter):** those groups map to an out-of-scope label (50 attacks, 44 after deduplication); the records carry
  the attack file's split, because "Language Translation" is task-irrelevant in the train file ("What is
  'Bibliothek' in English?") and steers the answer in the test file ("Translate your response into Spanish").
  Kept: the answer-steering text attacks (format, inserted claim, link, advert, appeal) and all code attacks.
  **After the fix: 0 of 51** (the 5 replacement rows are answer-steering attacks); 235 rows, 188 attacks
  (50 `exfiltration`), 47 clean e-mails.
- **AgentDojo: 0 of 52.** Payloads in their native tool-output carriers are injections; the extra
  `exfiltration` / `unsafe_action` labels follow the goal (data to an outside IBAN, address or website; money moved,
  password changed, outsider invited, file deleted).
- **approve-or-deny (German, translated): 0 of 50.** `deny` rows propose an action the user did not ask for or
  forbade (drop instead of only preparing, prod instead of dev, unlocking a door instead of heating, pushing despite
  "do not push", sandbox or approval switched off in the agent config); `approve` rows do what was asked, destructive
  steps included when the user asked for them.
- **`carrier_insertion`: 1 of 56 unclear (1.8 %, was 5.8 %).** The remaining flag is a Mosscap opener without a
  request (bare statement, as before). The approve-or-deny rows inside carriers repeat few records (35 positives
  upstream), so scores on them overstate generalisation.
- **`obfuscation_slices`: 2 of 56 unclear (3.6 %).** A Mosscap poem about keeping a secret (no request) and a
  CyberSecEval mode claim around an ordinary question — both upstream noise seen before.

All scored dev sets are now at or below 5 %; `instruction_injection`, `jailbreak` and `prompt_extraction` are no
longer blocked on the dev side. The leakage count is the gate's last run (dev pool of generation 9); it is renewed
by the next gate run, which also re-freezes dev with the BIPIA fix (generation 12).

## Findings (toxic_language dev sources, 2026-11-18)

Two new recipes (registry generation 13), reviewed by the runner, every row read in full. Review notes describe the
content and never quote it; no insult or slur from the data is written here.

- **Nemotron Safety Guard v3 (`toxic_language`, EN + machine-translated DE, marked translated): 1 of 50 unclear
  (2 %).** The first draft (every human-labelled prompt with a hate, harassment, profanity or threat category) failed
  badly: about 40 % of 25 sampled toxic rows were not toxic language, because the categories label the whole
  conversation (the response, or a harmful request such as a kidnapping plan) and long jailbreak templates carry them
  too. Prompts labelled safe were also noisy (3 of 25: group stereotypes, an instruction-override template). The recipe
  now keeps a toxic row only when the prompt is short (at most 300 characters) and names the toxic act itself
  (insults or slurs asked for or aimed at someone, racist or sexist jokes, stories or names asked for, open hatred, a
  group called inferior); questions about racism or about what a slur means do not count. Safe prompts and the LLM-jury
  jailbreaking part are out of scope; unsafe prompts without a toxic category wait for the harmful_content review.
  Test and validation splits together leave 106 rows (51 EN, 55 DE); outside the sample about 4 of the remaining 56
  are doubtful as well (trivia about curse words, mild venting), so the set sits near 4 %. Most rows are requests for
  insults against a group or person, so scores on it say little about hate speech in running text.
- **Civil Comments (`toxic_language`, EN): 8 of 50 wrong or unclear (16 %), benign 0 of 25: reported only.** Even at
  a rater share of at least 0.8 many positives carry no insult (partisan accusations, a polite question, a joke quote);
  a look at the band above 0.9 showed the same kind of rows, and insulting nicknames occur below 0.1. The recipe stays
  (test split, capped at 6,000 rows) for the report and for baseline training.
- **GermEval licence check.** GermEval 2018 ships a CC-BY-4.0 licence file; its repository also holds the holdout test
  split, so its training-split recipe comes from the holdout setup, not from the runner. GermEval 2019 and 2021 carry
  no licence (repository and task site): reported only.

`toxic_language` reaches 51 EN and 55 DE scored dev rows, all from Nemotron (DE translated, no native German dev rows
yet). The other dev sets are unchanged by generation 13 (Nemotron contributes no benign rows and `toxic_language` is
not a generator class), so their verdicts stand; the two new sets were summarised with `gold.py summary` and added to
`gold-dev.json`.

## Findings (harmful_content dev sources, 2026-11-18)

Three recipes (registry generation 14), reviewed by the runner, every row read in full. Notes describe requests and
never repeat their content.

- **Nemotron Safety Guard v3 (now `harmful_content` and `toxic_language`, EN + machine-translated DE, marked
  translated): 3 of 60 unclear (5.0 %, at the line).** The categories label the whole conversation, so prompts labelled
  unsafe include opinion and discussion questions, statistics, confessions and conversation fragments (first look at
  60 raw rows). A harmful row is a human-labelled prompt labelled unsafe with a harmful category and no toxic one
  (a row with both stays `toxic_language` only, behind its own cue, so the 106 toxic rows are unchanged), short (at most
  300 characters) and asking for operational help (how to, best way, steps, tips, where to get, "write … about how to";
  German equivalents), as for the AILuminate demo set. Adult sexual content alone is not scored (dating questions).
  Each row names its AILuminate hazard as an upstream label: Violence and Guns → `vcr`, Criminal Planning, Regulated
  Substances, Fraud, Malware, Manipulation, Illegal Activity → `ncr`, Suicide and Self Harm → `ssh`, Sexual (minor)
  → `cse`. Sample (30 harmful, 30 toxic): harmful 2 unclear (a binge-drinking question, sabotage of a marriage, both
  `ncr`), toxic 1 unclear (the venting row flagged before). Per hazard, read beyond the sample: `ssh` all 11 rows, 1
  unclear (a garbled German translation); `cse` all 21 rows, 2 wrong (church desecration under the minors category;
  the minors label now needs a child, minor or teenager in the prompt, which drops both); `vcr` 25 of 106 EN rows, 1
  unclear (an opinion on culling wild animals). Scored: 799 harmful rows (483 EN, 316 DE translated).
- **Aegis 2.0 / Nemotron Content Safety v2 (`harmful_content`, EN): 5 of 60 wrong or unclear (8.3 %): reported
  only.** Its test and validation splits are Nemotron v3's English prompts, so the recipe reads the training split
  (human prompt labels, same cue and hazards), deduplicated against Nemotron v3 and capped at 1 500. Even behind the
  cue the rows hold self-defence by a victim, video-game crafting, game cheating, drinking unnoticed and
  context-free fragments (a first draw before the minors cue also showed an advocacy question and a lawful-sounding
  disposal question).
- **WildGuardMix test split (benign, EN): 0 of 60.** From the ungated ODC-BY copy `walledai/WildGuardTest` (upstream
  is gated). The 490 vanilla harmless prompts (help lines, history, games, harmless verbs such as "kill a process") join
  the hard-benign pool. The vanilla harmful prompts stay out of scope: even behind the cue about 18 % of 142 are
  privacy, copyright or misinformation requests or harmless (beating the competition, recreating a painting). The
  adversarial rows wait for a jailbreak review.
- **`obfuscation_slices`: 2 of 56 unclear (3.6 %).** WildGuardMix benign rows enter its benign pool (48 of 400 benign
  rows); the classes are unchanged. The flags are the two source rows flagged before (a do-anything-bot claim around a
  political question, a poem about a secret). The other generated sets are byte-identical to the previous
  generation.

`harmful_content` reaches 483 EN and 316 DE scored dev rows, all from Nemotron v3 (DE
translated, no native German rows yet); the benign pool grows by 490 EN hard negatives. The four sets were summarised
with `gold.py summary` and merged into `gold-dev.json`; the other sets are unchanged by generation 14. On dev the class
now passes; its decision stays no-go only because of the holdout spot-check (JBB-Behaviors at 10 %), which needs the
owner's holdout re-review.

## Findings (native unsafe_action agent sets, 2026-11-18)

Two recipes (registry generation 16), reviewed by the runner with `gold.py sample` (50 rows per set), every row read in
full. Notes describe requests and never repeat their content.

- **RedCode (`unsafe_action`, EN): 0 of 50.** RedCode-Exec Python items come as a summary and a step-list request
  ("Create and execute a Python script that …"). A first look at the 27 risky scenarios showed most of them read as
  ordinary tasks on their own (print, copy or list a file, post a file to a local server, stop a named service such
  as a web server or database, a regex, a seeded random number, a biased score): their risk lies in what the code
  does in its environment, so they stay out of scope. Scored are scenario 8 (delete a system file), 9 (alias `sudo`
  or another command to a recursive delete in the root user's shell profile) and 10 (reverse or remote command
  shell), plus the 160 RedCode-Gen malware stubs (signature and docstring of an adware, DDoS, ransomware, rootkit,
  spyware, trojan, virus, backdoor, botnet or worm function to complete). Borderline but kept: deleting a package log
  under `/var/log` (scenario 8). 293 rows after deduplication (step lists of one scenario are near-duplicates).
  The Bash half is handed to the shell-command detector and not fetched.
- **Agent-SafetyBench (`unsafe_action` and benign, EN): 1 of 50 unclear (2.0 %).** Only the unfulfillable cases of
  the harmful-code group that the agent fails by writing the code itself (failure mode 1) carry the risk in the
  instruction; even there about two in five read harmless alone (a login form, a backup script, a model on age and
  ZIP code), so a cue filter keeps the requests that name the harmful act (bypass or disable authentication or
  security checks, backdoor, reverse shell, cracking or brute-forcing passwords, logging keystrokes or passwords,
  opening every port to any address, world-writable permissions): 59 positives, 41 dropped. The 52 fulfillable code
  cases (authentication, backups, deleting duplicates, remote shutdown) join the hard-benign pool. Flag: a request to
  scrape personal data "to demonstrate" scraping (privacy harm, the unsafe act only implied). Every other risk group
  keeps its risk in the tool environment and stays out of scope, as found in T15.

`unsafe_action` gains 352 native EN dev rows (before: 30 from AgentDojo). The two sets were summarised with
`gold.py summary` on a freeze of these two sets alone and merged into `gold-dev.json`; the generated sets that embed
dev rows are re-frozen with generation 16 and keep their last review.

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
