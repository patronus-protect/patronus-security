# Kategorie `harmful_content`

Stand: 2026-11-09, Entwurf zur Freigabe. Gliederung wie [`injection.md`](injection.md); Basiswerte sind
Startwerte (siehe [`injection.md` §4](injection.md#4-patterns)), kalibriert in HC02. Die Kategorie ist default aus
(festgelegt 2026-11-10), wie alle neuen Kategorien opt-in.

## 1. Schichten

Wie [`injection.md` §1](injection.md#1-schichten-für-alle-kategorien-gleich). Geteilte Core-Lexika:
Adressat, Meta, Zitat, Testcode; gehashte Lexika wie bei [`toxic_language`](toxic_language.md#3-lexika-gehasht).

## 2. Abgrenzung

`harmful_content` = **Anfrage** nach Inhalten, die realen Schaden ermöglichen, auf Ebene der Absicht:
Anfrage-Rahmung (Anleitung, Schritt für Schritt, beschaffen, herstellen, umgehen) + Gefahrenklasse.

L1 deckt die Klassen mit klarer sprachlicher Form ab (an AILuminate angelehnt):

| Unterklasse | Inhalt |
|---|---|
| `violent_crime` | Gewalt gegen Menschen planen, Waffen beschaffen/bauen |
| `cbrne` | chemische, biologische, radiologische, nukleare Stoffe, Sprengstoffe |
| `cyber_harm` | Schadsoftware erstellen, Systeme fremder Leute angreifen |
| `nonviolent_crime` | Betrug, Diebstahl, Drogenherstellung, Geldwäsche |
| `sex_crime` | sexuelle Gewalt, nicht einvernehmliche Inhalte |
| `child_safety` | eigene Unterklasse, ohne Gegen-Kontext außer Schutz/Meldung |
| `self_harm` | eigene Unterklasse; Verdikt nach Punkten wie bei den anderen Klassen (festgelegt 2026-11-09) |

Dazu kommen fünf **reine Modell-Unterklassen** ohne Patterns (festgelegt 2026-11-09), weil sie keine klare
Wortform haben: `specialized_advice` (Medizin, Recht, Finanzen), `ip` (Urheberrecht), `defamation`,
`elections`, `privacy`. Sie erkennt nur das L1-N-Gramm-Modell dieser Kategorie (§7); ihre Findings tragen
`source=model` und die Begründung aus den stärksten N-Grammen.

Nicht `harmful_content`: Hass (`toxic_language`); Handlungen auf Systemen über den Agenten
(`unsafe_action`); die Verpackung (`jailbreak`, feuert zusätzlich).

## 3. Lexika

**Support** (+25/+20/+15):

| ID | Inhalt | Form |
|---|---|---|
| `harm.request_frame` | wie mache/baue/beschaffe ich, Schritt für Schritt, genaue Anleitung, Mengenangaben / how do I make, step by step, exact quantities | Klartext |
| `harm.evasion` | ohne erwischt zu werden, unauffindbar, an der Kontrolle vorbei / without getting caught, untraceable | Klartext |
| `harm.<unterklasse>` | Gefahrenbegriffe je Unterklasse | **gehasht** für `cbrne`, `child_safety`, `sex_crime`; sonst Klartext |
| `harm.self_harm` | Methoden- und Absichtsbegriffe | gehasht |
| `addressee` (Core, geteilt) | | Klartext |

**Gegen** (−30, gilt nicht für `child_safety`):

| ID | Inhalt |
|---|---|
| `harm.prevention` | Schutz, Prävention, Erkennung, Erste Hilfe, Entsorgung, Meldung |
| `harm.news_history` | Nachrichten, Geschichte, Gerichtsurteil, Statistik |
| `harm.professional` | erkennbarer Berufskontext ohne Herstellungs-Detail (Pflege, Toxikologie-Lehrbuch, Pentest mit Auftrag) |
| `meta`, `quotation`, `test_code` (Core, geteilt) | |

Für `self_harm` gilt der Gegen-Kontext wie bei den anderen Klassen (z. B. Prävention, Beratung).

## 4. Patterns

| Pattern | Kern | Basis | Validator | `requires_context` | `scored_only` | Heutige Regeln |
|---|---|---|---|---|---|---|
| `hc_howto_hazard` | `request_frame` + `harm.<unterklasse>` in derselben Klausel | 40 | Format | nein | nein | threat.harmful_intent |
| `hc_quantified_recipe` | Hazard + Mengen-/Reinheits-/Bezugsangaben angefragt | 45 | Format | nein | nein | neu |
| `hc_evasion` | Hazard oder Straftat + `evasion` | 40 | Format | nein | nein | neu |
| `hc_child_safety` | Minderjährigen-Bezug + sexueller Bezug | 70 | – | nein | nein | neu |
| `hc_self_harm_intent` | Ich-Bezug + Absicht/Methode | 45 | – | nein | nein | neu |
| `hc_hazard_mention` | Hazard-Begriff ohne Anfrage-Rahmung | 15 | – | ja | **ja** | neu |
| `hc_decoded` | eines der obigen in einer dekodierten Sicht | wie Quelle | wie Quelle | wie Quelle | wie Quelle | neu |

Normalisierungspunkte: Plus wie bei `injection`. Modi wie PII.

## 5. Struktur und Träger

Kein Träger-Bonus; Fremdinhalt mit Anleitung ist ebenso relevant. Zitat-Spannen dämpfen außer bei
`child_safety`.

## 6. Facts (Auszug)

`finding{…}`, `hazard{subclass}`, `request_frame`, `quantified`, `evasion`, `meta`,
`fiction_frame` (aus `jailbreak`), Modifikatoren wie `injection`.

## 7. Modell

Pflicht ist hier ein **N-Gramm-Modell** (Zeichen- und Wort-N-Gramme → LR, K26-artig), mehrklassig über alle
zwölf Unterklassen. Für die sieben Pattern-Unterklassen tritt es gegen die anderen Kandidaten an; für die
fünf Modell-Unterklassen ist es der einzige Erkenner. Es läuft in einem Durchgang über den ganzen Text (kein
Anker-Fenster, weil es für diese Klassen keine Anker gibt) und muss das L1-Budget halten (≤ 2 MB,
≤ 1 ms je 100 KiB). Erreicht eine Modell-Unterklasse auf dem Holdout nicht TPR ≥ 50 % bei 1 % FPR, bleibt
sie aus und wird in HC02 als Lücke vermerkt.

Kandidaten: B0 (Threat-Scorer 0.1.7, enthält `harmful_intent`), R+A+L, B1, B4, B5. Daten: aya_redteaming
(FR/ES nativ), MultiJail, JBB-Behaviors, HarmBench; DE nur RTP-LX (`wildchat-de` misst Toxizität, zählt für
`toxic_language`), deshalb R05 mit
Harm-Anteil. Prompts mit Gefahrenbegriffen werden zur Eval-Zeit geladen, nicht committet.

## 8. Policies (später)

- `jailbreak.with_harm`, `jailbreak.fiction_with_harm` (siehe [`jailbreak.md` §8](jailbreak.md#8-policies-später)).

## 9. Bestand

| Heutige Regeln | Ziel |
|---|---|
| threat.harmful_intent | `hc_howto_hazard` |
| übrige harmful_behavior: threat.agent_guard_removal, threat.persistence_payload, threat.root_destruction | nicht hier: `agent_config_tampering`, `unsafe_action`, K26 |

L2/L3-Label `harmful_behavior` mappt hierher, `toxic_or_harmful` sekundär (X03).

## 10. Übernommene OSS-Regeln

Keine Regelquellen mit klarer Lizenz bekannt; Lexika eigen (gehasht) bzw. aus TX01.

## 11. Goldens

Je Pattern und Sprache ≥ 5 Positive und ≥ 5 Hard Negatives, Hazard-Goldens nur gehasht bzw. als Verweis
auf Eval-Daten. Pflicht-Hard-Negatives: Prävention und Erste Hilfe, Nachrichten, Geschichte,
Chemieunterricht ohne Herstellung, Pentest mit Auftrag, Krimi-Handlung ohne Anleitung, Beratung und Prävention zu Suizid.

## 12. Herkunft und Daten

Regeln für Herkunft, Splits und Quellfamilien: [README](../README.md#herkunft-regeln-train-gold-holdout).
Goldens: je Pattern und Sprache ≥ 5 Positive und ≥ 5 Hard Negatives, selbst geschrieben (`ark_authored`), §11.

| | Quelle |
|---|---|
| Patterns/Anker | `ark_existing` (threat.harmful_intent); `taxonomy`: AILuminate-Gefahrenklassen; gehashte Lexika `mined` auf Train; Anfrage-Rahmung `hand` |
| Train/Dev | bewertet: Nemotron Safety Guard v3 (Test- und Validierungs-Split, nur menschlich gelabelte unsichere Prompts mit Schaden- und ohne Toxizitäts-Kategorie, kurz und mit Bitte um operative Hilfe; AILuminate-Gefahr je Zeile als Upstream-Label `vcr`/`ncr`/`ssh`/`cse`; DE maschinell übersetzt, als `translated` markiert; Gold siehe `scoreboard/gold-notes.md`); SimpleSafetyTests (CC-BY-2.0, 100 englische Anfragen aus fünf Schadensbereichen, alle positiv; DE: alle 100 vom Runner selbst übersetzt in `runner_translations_de`, als `translated` markiert); Hard Negatives: WildGuardMix-Test, nicht-adversariale harmlose Prompts (ODC-BY-Kopie `walledai/WildGuardTest`). Offen: PolyGuardPrompts, XL-SafetyBench |
| Holdout `neutral` | aya_redteaming (EN, FR/ES nativ), MultiJail, JBB-Behaviors, HarmBench; DE: RTP-LX de |
| Holdout `ark_blind` | R05 DE (Harm-Anteil, ohne funktionierende Anleitungen: nur Anfragen) |
| Hard Negatives | XSTest-safe, OR-Bench-hard, Prävention, Nachrichten, Chemieunterricht, Pentest mit Auftrag |
| Nur berichten | Nemotron Content Safety v2 / Aegis 2.0 (Trainings-Split, gegen Nemotron v3 dedupliziert, gedeckelt auf 1.500; Gold 8 % Fehler), AILuminate-Demo-Set (Gold 30 % Fehler); WildGuardMix-Schaden-Prompts außerhalb des Scopes (Privatsphäre, Urheberrecht, Desinformation) |
| Lücke | Modell-Unterklassen (Fachberatung, Urheberrecht, Verleumdung, Wahlen, Privatsphäre) nur mit Kandidaten-Daten; bleiben aus, bis sie die Grenze aus §7 schaffen |

## 13. Subklassen-Labels (Dev)

Owner-Entscheidung 2026-11-23: Die Subklassen werden geliefert, nicht weggelassen. Jede `harmful_content`-Positive
in DEV (`train_dev`, `generated`, `translated`; nie Holdout, nie `report`) trägt eine Subklasse aus §2 in
[`labels/harmful_subclass.jsonl`](../labels/harmful_subclass.jsonl) (nur Zeilen-ID, Subklasse, Begründungskürzel;
kein Zeilentext); `other` für eine Positive ohne passende Gefahrenklasse. Gelabelt per Agent in drei Teilen; ein
zweiter, unabhängiger Durchgang labelt die feste 5-%-Stichprobe (sha256 der Zeilen-ID modulo 20 = 0) ohne die
ersten Labels zu sehen. Werkzeug: `scripts/l1_threat/harmful_subclass.py` (export, merge, agree, coverage).

Stand 2026-11-24 (HC01, Generation 23): 899 Positive (Nemotron v3 EN 483 / DE 316, SimpleSafetyTests EN 100);
Stichprobe 37 Zeilen, 35 gleich, 2 abweichend (beide `other` ↔ `nonviolent_crime`).

| Subklasse | all | de | en |
|---|---:|---:|---:|
| `violent_crime` | 220 | 81 | 139 |
| `cbrne` | 44 | 16 | 28 |
| `cyber_harm` | 31 | 9 | 22 |
| `nonviolent_crime` | 475 | 181 | 294 |
| `sex_crime` | 23 | 7 | 16 |
| `child_safety` | 52 | 11 | 41 |
| `self_harm` | 30 | 4 | 26 |
| `specialized_advice` | 2 | 1 | 1 |
| `ip` | 3 | 0 | 3 |
| `defamation` | 0 | 0 | 0 |
| `elections` | 0 | 0 | 0 |
| `privacy` | 8 | 3 | 5 |
| `other` | 11 | 3 | 8 |

Benannte Lücken (< 20 Positive je Sprache): `cbrne`, `cyber_harm`, `sex_crime`, `child_safety`, `self_harm` auf
DE; `sex_crime` auch auf EN; alle fünf Modell-Unterklassen auf DE und EN. Die Modell-Unterklassen haben in DEV
damit keine messbare Grundlage; ihr Recall braucht eine Quelle mit Privatsphäre-, Urheberrechts-, Verleumdungs-,
Wahl- und Fachberatungs-Anfragen (z. B. die WildGuardMix-Schaden-Prompts außerhalb des Scopes, heute `report`).

Der Per-Subklasse-Check steht im Kaskaden-Bericht (`scoreboard.py report --cascade`, Abschnitt „harmful_content
per subclass“): je Subklasse und Sprache TPR der Kaskaden-Entscheidung, `gap` unter 20 Positiven, `off` für eine
Modell-Unterklasse unter 50 % TPR am konfigurierten Arbeitspunkt (höchstens 1 % FPR). Jede Subklasse steht in
jeder Sprache in der Tabelle, auch ohne Positive (`– (0) gap`, ungemessen). Den Score des L1-Modells
schreibt die Vorhersage nicht aus; der L1-Heuristik-Score ist für `harmful_content` fast überall 0, daher misst der
Check die Entscheidung.

Erster Lauf (HC01, `cascade-config.json` auf `main`, eingebautes `harmful_content`-Modell, Dev Generation 23;
Klasse gesamt TPR 55,1 %, Benign-FPR 0,05 %): TPR in % (Positive).

| Subklasse | all | de | en |
|---|---:|---:|---:|
| `violent_crime` | 55,5 (220) | 67,9 (81) | 48,2 (139) |
| `cbrne` | 65,9 (44) | 87,5 (16) gap | 53,6 (28) |
| `cyber_harm` | 41,9 (31) | 55,6 (9) gap | 36,4 (22) |
| `nonviolent_crime` | 58,1 (475) | 78,5 (181) | 45,6 (294) |
| `sex_crime` | 39,1 (23) | 71,4 (7) gap | 25,0 (16) gap |
| `child_safety` | 46,2 (52) | 54,5 (11) gap | 43,9 (41) |
| `self_harm` | 40,0 (30) | 75,0 (4) gap | 34,6 (26) |
| `specialized_advice` | 50,0 (2) gap | 0,0 (1) gap, off | 100,0 (1) gap |
| `ip` | 33,3 (3) gap, off | – (0) gap | 33,3 (3) gap, off |
| `defamation` | – (0) gap | – (0) gap | – (0) gap |
| `elections` | – (0) gap | – (0) gap | – (0) gap |
| `privacy` | 50,0 (8) gap | 66,7 (3) gap | 40,0 (5) gap, off |
| `other` | 36,4 (11) gap | 33,3 (3) gap | 37,5 (8) gap |

Offen (BLOCKED in HC01): ein mehrklassiges Subklassen-N-Gramm-Modell braucht ein Modellformat mit mehr als zwei
Klassen (das fastText-Format von Core kennt nur negativ/positiv) und für die fünf Modell-Unterklassen Dev-Positive
(heute 0–8 je Subklasse); die Regeln aus §4 folgen in einer eigenen Runde. Am schwächsten sind EN `sex_crime`,
`self_harm` und `cyber_harm`.
