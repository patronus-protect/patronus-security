# Toxic-language scorer choice (TX02)

Generated 2026-11-22 on branch `threat/174-tx02` (base `8174749f`) with `scripts/l1_threat/ablation.py
calibrate --class toxic_language`, S11 setup for every candidate:

    ablation.py calibrate --rows train_dev --rows generated --oversample-de 4 \
        --report-rows report --class toxic_language --stage <FT|B4|B1> \
        --bench-bin text_model_latency --windows windows.jsonl --out tx.<stage>.json

Facts: `text_facts --threat-findings` (release build) over `$ARK_L1_DEV_DATA` `train_dev`, `generated` and
`report`. Every candidate trains on the template-disjoint train half of `train_dev` + `generated`, German train
positives ×4; the other half calibrates: 50 positives (all `nemotron_safety_v3`, DE 28 translated, EN 22),
27 267 benign rows (dev benign pool incl. hard benigns, twins and the `massive` chat pool). Cuts at 0.1 % FPR
(detect) and 1 % FPR (clear) on these benign rows. `toxic_language` has 106 dev positives from one source;
there is no second train source in the frozen dev data.

Report sets (out of distribution, never trained or calibrated on): `civil_comments` (144 toxic EN comments,
5 856 benign) and `textdetox_de` (2 072 toxic DE texts, 2 492 benign) — native toxic text, not requests.
ms/100 KiB: p95 of the model on top of the facts (`text_model_latency`) on 17 × 100 KiB windows packed from
`germanquad` and `dolly_15k` dev text, the three candidates timed in parallel (contended; the E03 corpus is not
on this host), so only the A/B between rows is meaningful.

| Stage | TPR@0.1% dev | DE | EN | own-language cuts DE / EN | report TPR at dev cut (report FPR) | goldens pos / hard neg at cut | ms/100 KiB p95 | RAM KiB |
|---|---|---|---|---|---|---|---|---|
| **B0 rules (kept)** | 0.0 | 0.0 | 0.0 | – | **0.6 (0.00 %)** — 13 / 2 216 | 23 / 32 (9 known gaps), 0 / 36 | **0 (status quo)** | 0 |
| FT fastText-type | 66.0 | 64.3 | 68.2 | 67.9 / 68.2 | 0.0 (0.17 %) | 1 / 32, 0 / 36 | 3.6 | 256 |
| B4 hashed TF-IDF + LR | 82.0 | 89.3 | 72.7 | 85.7 / 86.4 | 1.3 (0.39 %; `textdetox_de` 1.36 %) | 1 / 32, 3 / 36 | 15.7 | 576 |
| B1 char TF-IDF + LR | 80.0 | 82.1 | 77.3 | 82.1 / 81.8 | 1.4 (0.35 %; `textdetox_de` 1.28 %) | 1 / 32, 3 / 36 | 17.6 | 6 448 |

B0 = the TX01 rules plus this change (rule hits in the facts; benign rows of `train_dev`, `generated` and
`report` raise no `toxic_language` finding: 0 / 63 573). B0 report hits: `civil_comments` 4 / 144,
`textdetox_de` 9 / 2 072, unchanged by this change. Goldens: the 68 hand-written `toxic_language` rows of
`threat_l1.jsonl` (32 positives, 9 of them known rule gaps; 36 hard negatives incl. this change's), scored at
each model's dev detect cut.

**Choice: `B0` stays; no learned model for `toxic_language`.** The char n-gram LR does not pay off on the
current data. In distribution it looks strong (B4 82 %, B1 80 % at 0.1 % FPR on 50 calibration positives), but
the positives are all `nemotron_safety_v3` prompts that *ask for* toxic content ("write an insult about …"),
and the models learn that request frame, not toxic language: at their dev cut they find 0–1.4 % of the native
toxic texts of the report sets (where the rules find 0.6 % at 0 FP) and 1 of 32 hand-written golden positives
(insults, threats, dehumanisation, harassment in chat, e-mail, web, log carriers); B4 and B1 also flag 3 German
golden hard negatives and 1.3 % of the `textdetox_de` benigns. FT is the only candidate within the ~4 ms per
model and finds nothing out of distribution. B4 and B1 are over the latency budget (and B1 over 2 MB RAM). None
of the three is wired; `cascade.modules.toxic_language.l1_model` could load an FT bundle (slot test in
`ark-core/src/detectors/text/l1_model.rs`), but there is no candidate worth configuring.

**Open:**
- **Train data.** A model needs native toxic text as positives (DE and EN), not toxicity requests. The frozen
  `DEV` is generation 20; `datasets.yaml` (generation 23) already adds two scored `toxic_language` sources to
  `train_dev`: the Dynamically Generated Hate Speech Dataset (CC-BY-4.0, EN originals, dehumanisation and
  threats) and the German XSafety insult prompts (Apache-2.0, translated). GermEval 2018 train (CC-BY-4.0, native
  DE) is still `pending` (its recipe comes from the holdout setup, `--overlay`). Owner command needed: re-freeze
  `DEV` at generation 23 (`python3 scripts/l1_threat/prepare_corpora.py --dev-out DEV --holdout-out HOLDOUT`,
  with the GermEval 2018 train recipe from the holdout overlay), then rerun the calibration command above for
  FT, B4 and B1. Until then no model can be chosen on dev.
- **Rules.** 9 of 32 golden positives are rule gaps: vocative insults without a copula ("Shut up, you idiot",
  "Halt die Klappe, du Idiot"), insults without an addressee phrase in web comments and e-mails, leetspeak
  beyond the normalisation ("y0u st*pid l0ser"), indirect threats ("you will end up in the hospital"). The
  lexicon is still the hand seed (TX01); recall on native toxic text comes with the mined lexicon.
- Latency A/B of this change in the default scan: 0 (no model; the new check runs only on a toxic lexicon match,
  on at most its sentence).
