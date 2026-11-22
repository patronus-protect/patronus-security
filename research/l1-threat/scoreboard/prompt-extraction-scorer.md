# Prompt-extraction scorer choice (PX02)

Generated 2026-11-22 on branch `threat/164-px02` (base `8462db8d`) with `scripts/l1_threat/ablation.py
calibrate --class prompt_extraction`, S11 setup for every candidate:

    ablation.py calibrate --rows train_dev --rows generated --oversample-de 4 \
        --report-rows report --class prompt_extraction --stage <FT|B4|B1> --out pe.<stage>.json

Facts: `text_facts --threat-findings` (release build) over `$ARK_L1_DEV_DATA` `train_dev` (now incl. the
`massive_de`/`massive_en` chat pool), `generated` and `report`. Every candidate trains on the template-disjoint
train half of `train_dev` + `generated`, German train positives ×4 (there are none for this class); the other half
calibrates: 7 600 positives (7 566 `mosscap`, 34 generated carriers), 27 267 benign rows (dev benign pool incl.
hard benigns, twins and the chat pool). Cuts at 0.1 % FPR (detect) and 1 % FPR (clear) on these benign rows.

`gandalf` (report set, out of distribution, never trained or calibrated on): TPR at 1 % / 0.1 % FPR matched on
the report benigns (`civil_comments`, `jackhhao_jailbreak`, `textdetox_de`), and TPR / report FPR at the dev
detect cut. ms/100 KiB: p95 of the model on top of the facts (`text_model_latency`), median of five (FT) or three
(B4) solo runs on 17 × 100 KiB windows packed from `germanquad` and `dolly_15k` dev text (the E03 corpus is not on
this host), so only the A/B between rows is meaningful. B1 was timed only in parallel with the other two (23.1 ms
under contention, B4 18.6 ms, FT 5.5 ms there).

| Candidate | TPR@0.1% dev | EN | DE | hard-benign FP at cut | gandalf matched @1% / @0.1% | gandalf at dev cut (report FPR) | ms/100 KiB p95 | RAM KiB |
|---|---|---|---|---|---|---|---|---|
| **FT fastText-type (chosen)** | **99.4** | 99.4 | – (0 positives) | 2/1 085 | **83.6 / 62.1** | **86.8 (1.52 %)** | **4.05** | 256 |
| B4 hashed TF-IDF + LR | 99.8 | 99.8 | – | 2/1 085 | – | 74.6 (2.49 %) | 15.04 | 576 |
| B1 char TF-IDF + LR | 99.7 | 99.7 | – | 1/1 085 | – | 73.5 (0.75 %) | ~23 (contended) | 7 228 |

Comparison values from `baseline.md` (full gated dev split, matched FPR): rules and scorer today (B0) 0.4 / 0.4
TPR@1 % / 0.1 %; best heuristic baseline 3.6 / 3.6 (ATR); best reference model Prompt Guard 2 22M 41.6 / 20.9.
On `gandalf`: B0 2.3 / 2.3, best heuristic 22.8 / 22.8 (ATR), Prompt Guard 2 22M 98.5 / 96.9. The candidates
are measured on the calibration half, not on the same rows as the baselines (the baseline cache is not readable
on this host). The PX01 rules sit in the injection detector, not in the text facts; on this pool they add at
most what B0 finds (0.4 on dev, 2.3 on `gandalf`), so rules ∪ model is the model's number within that.

**Choice:** `FT`. It is the only candidate within the accepted ~4 ms per model (4.05 ms p95; B4 15 ms, B1 over
the 2 MB RAM budget), and at 0.1 % FPR it is above the best heuristic baseline on dev (99.4 vs 3.6) and out of
distribution (`gandalf` 62.1 vs ATR's 22.8 at matched 0.1 % FPR). B4 and B1 are within 0.4 pp on dev and worse on
`gandalf`. Model file: sha256 `ccd931588545…` (11.4 MB JSON, not checked in; the command above rebuilds it
deterministically from the frozen dev data). Nothing is wired into the scan path: it runs only when a cascade
configures it as `cascade.modules.prompt_extraction.l1_model`. The PX01 rules stay the precise layer in front of it.

**Open / regressions named:**
- **Topic, not intent.** Dev positives are 99.6 % `mosscap` (password game), so the model learns "password,
  secret word, system prompt" rather than an extraction request. On the hand-written goldens
  (`threat_l1.jsonl`, prompt_extraction) at the detect cut it flags 18 of 30 English and 2 of 29 German hard
  negatives: defensive system prompts ("never reveal your system prompt"), security documentation with
  quotations, test code, a prompt-writing tutorial, password policies, "I forgot my email password", a crossword
  hint, and the letter-spaced "S Y S T E M" status line. B4 is the same (19 / 1). The dev hard-benign pool has
  no such look-alikes (twins 0/830, hard benigns 2/1 085: two `wildguardmix` "secret hideout" questions), so the
  calibrated FPR does not show it. Before a class enables the model it needs extraction look-alikes as train
  negatives.
- **German:** no German prompt-extraction positive in dev or train; the model finds 0 of 34 German golden
  positives (the rules pass every gated German golden except the five known gaps). The secret-extraction goldens of this change are rule gaps in both
  languages; the model takes the 5 English ones, none of the 5 German ones.
- **Generated carriers:** 10 of 34 generated system-prompt extraction carriers at the EN cut (`plain_mail` 1/11,
  `helpdesk` 2/8); the rules cover these shapes.
- At the dev detect cut the model flags 1.98 % of `civil_comments` and 2.35 % of `jackhhao_jailbreak` benigns.
- Latency A/B of this change in the default scan: 0 ms (no model enabled). With the model configured the
  prompt_extraction module adds ~4 ms p95 per 100 KiB.

## Per-source table of the chosen candidate

| Scope | Source | rows | FP | FPR |
|---|---|---|---|---|
| calibration | agent_safetybench | 31 | 0 | 0.00 |
| calibration | agentdojo | 66 | 2 | 3.03 |
| calibration | approve_or_deny_de | 24 | 0 | 0.00 |
| calibration | bipia | 21 | 0 | 0.00 |
| calibration | dolly_15k | 7439 | 9 | 0.12 |
| calibration | germanquad | 5690 | 0 | 0.00 |
| calibration | massive_de | 5600 | 1 | 0.02 |
| calibration | massive_en | 5635 | 11 | 0.20 |
| calibration | spml | 1676 | 2 | 0.12 |
| calibration | twins | 830 | 0 | 0.00 |
| calibration | wildguardmix | 243 | 2 | 0.82 |
| calibration | wildjailbreak | 12 | 0 | 0.00 |
| report | civil_comments | 5856 | 116 | 1.98 |
| report | jackhhao_jailbreak | 1321 | 31 | 2.35 |
| report | textdetox_de | 2492 | 0 | 0.00 |

| Positive source | rows | TP at the EN cut | TPR |
|---|---|---|---|
| mosscap | 7566 | 7511 | 99.3 |
| carrier_insertion:blog_post | 2 | 1 | 50.0 |
| carrier_insertion:helpdesk | 8 | 2 | 25.0 |
| carrier_insertion:kb_chunk | 7 | 4 | 57.1 |
| carrier_insertion:plain_mail | 11 | 1 | 9.1 |
| carrier_insertion:report_page | 6 | 2 | 33.3 |
| gandalf (report, dev cut) | 998 | 866 | 86.8 |
