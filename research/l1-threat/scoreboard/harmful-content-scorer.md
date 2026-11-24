# Harmful-content scorer choice (HC02)

Generated 2026-11-24 on branch `threat/184-hc02` (base `cdbd53fc`), `DEV` generation 23, with the S11/S13 setup:

    ablation.py calibrate --rows train_dev --rows generated --rows translated --oversample-de 4 \
        --report-rows report --class harmful_content --stage <FT|B4|B1> --out hc.<stage>.json
    ablation.py run --rows train_dev+generated+translated --class harmful_content   # R, R+A, R+A+L, B5

Facts: `text_facts --threat-findings` (release build) over `$ARK_L1_DEV_DATA` `train_dev`, `generated`, `translated`
and `report`. Every candidate trains on the template-disjoint train half (German train positives ×4); the other half
calibrates: 450 positives (`nemotron_safety_v3`, German translated, and `simple_safety_tests`; at the per-language cuts
DE 146, EN 269 by the language Core detects) against 27 311 benign rows (dev benign pool incl. hard benigns, twins and the
`massive` chat pool). Cuts at 0.1 % FPR (detect) and 1 % FPR (clear) on these benign rows. Report sets (never trained
or calibrated on): `nemotron_content_safety_v2` (1 471 EN positives) and `ailuminate_demo` (800 EN positives, gold
30 % wrong), benign `civil_comments`, `textdetox_de`, `jackhhao_jailbreak` (9 669 rows). Costs from S12/S13 (model
architectures unchanged): FT 3.2 ms per 100 KiB, B4 ~16 ms, B1 ~18 ms.

| Stage | TPR@0.1% dev | DE (own cut) | EN (own cut) | TPR@1% (`run`) | report TPR at dev cut (v2 / AILuminate) | report benign FPR | goldens pos / hard neg detected | RAM KiB |
|---|---|---|---|---|---|---|---|---|
| R, R+A, R+A+L (rules and points) | 0.0 | 0.0 | 0.0 | 0.0 | – | 0.00 % | 2 / 12 (this change), 0 / 12 | 0 |
| **FT fastText-type (built-in, kept)** | **34.7** | **49.3** | **31.2** | **80.2** | **40.8 / 1.0** | 0.02 % (2 `civil_comments`) | 0 / 12, 0 / 12 | 256 |
| B4 hashed TF-IDF + LR | 32.0 | 37.7 | 23.0 | 62.0 | 25.3 / 0.3 | 0.00 % | – | 576 |
| B1 char TF-IDF + LR | 32.0 | 47.3 | 24.5 | 61.3 | 20.2 / 0.3 | 0.00 % | – | 6 683 |
| B5 (R+A + B4 logit) | – | – | – | 61.3 | – | – | – | 576 |

Goldens: the 24 hand-written `harmful_content` rows of `threat_l1.jsonl` (12 positives, 12 hard negatives in first aid,
news, an authorised pentest, chemistry class, crime fiction, crisis counselling), scored by the built-in model at its
shipped DE/EN cuts (`builtin_harmful_content_model_detects_no_golden_hard_negative`). B4 and B1 have no Rust inference
in Core and were not scored on the goldens.

**Choice: the built-in FT model stays the L1 model of `harmful_content`; B4, B1 and B5 are not shipped; the category
stays default off.** FT is best on every column that matters: TPR@0.1 % FPR all / DE / EN, TPR@1 %, out of distribution
on `nemotron_content_safety_v2` (40.8 % vs 25 / 20 %), at the lowest cost (3.2 ms, 256 KiB). B4 and B1 are over the
latency budget and B1 over 2 MB. The points stages score 0: the class has one rule, and it matches no dev row. The
model runs only where a cascade names it (`cascade.modules.harmful_content.l1_model: {"builtin": "harmful_content"}`);
without a cascade nothing changes.

**Points.** `ark.threat.harmful_intent` (plan/organise a violent attack or a murder) was a legacy-scorer rule: it matched,
but the legacy threat scorer never accepted it on its own, so it reported nothing. It is now a points rule (base 40,
format validator, the shared clause context; `hc_howto_hazard` in `categories/harmful_content.md` §4): accepted on a
direct request, not on a response plan or a news report. Its column leaves the legacy scorer (`l1_scorer_0_1_7.json`, `dropped_rules`, as for the X04
handoffs; the other coefficients are the trained ones). On the dev and report rows (96 092) it matches none, so every
dev number above and in `cascade.md` is unchanged; it finds 2 of 12 golden positives (DE + EN). Latency: the regex ran
before as well; only a match goes through the points path now, so a text without a match costs the same.

**Out of distribution the model learns the request frame of its source.** At its cuts FT finds 1 % of the AILuminate demo
prompts and none of the 12 golden positives (a recipe with exact quantities, theft without getting caught, breaking into a car, a self-harm method,
ransomware against a named person, planning an attack; 7 of 12 escalate, 5 are cleared). It flags none of the golden
hard negatives (the German crisis-counselling row escalates). The same pattern as `toxic_language` (TX02): the 899 dev
positives come from two sources (`nemotron_safety_v3`, `simple_safety_tests`), German only as translations.

**Open:**
- **Rules.** The intent-level patterns of §4 (`hc_quantified_recipe`, `hc_evasion`, `hc_child_safety`,
  `hc_self_harm_intent`, a wider `hc_howto_hazard`) are still to build; 10 of 12 golden positives are known rule gaps.
- **Data.** A second open positive source per language (owner decision 2026-11-22) and Dev positives for the five
  model-only subclasses (0–8 each, see `categories/harmful_content.md` §13). Until then the per-subclass gaps of HC01 stand.
- **Multi-class subclass model** (HC01, BLOCKED): Core's fastText format has two classes only.
