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
| `hc_howto_hazard` | `request_frame` + `harm.<unterklasse>` in derselben Klausel | 40 | Format | nein | nein | threat.harmful_intent, threat.hc_howto_hazard (HC03) |
| `hc_quantified_recipe` | Hazard + Mengen-/Reinheits-/Bezugsangaben angefragt | 45 | Format | nein | nein | neu |
| `hc_evasion` | Hazard oder Straftat + `evasion` | 40 | Format | nein | nein | threat.hc_evasion (HC03) |
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
| threat.harmful_intent | `hc_howto_hazard` (Punkte-Regel seit HC02, Basis 40) |
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

## 14. Stand HC02 (2026-11-24): Punkte und Ablations-Entscheidung

Zahlen und Befehle: [`scoreboard/harmful-content-scorer.md`](../scoreboard/harmful-content-scorer.md).

- **Modell:** Das eingebaute `FT`-Modell (S13) bleibt das L1-Modell; `B4`, `B1`, `B5` werden nicht ausgeliefert.
  Dev (S11-Aufbau, 450 Kalibrier-Positive gegen 27 311 Benign-Zeilen) TPR@0,1 % FPR: `FT` 34,7 (DE 49,3, EN 31,2),
  `B4` 32,0, `B1` 32,0; out of distribution (`nemotron_content_safety_v2`) 40,8 gegen 25,3 / 20,2 %. `FT` ist auch am
  günstigsten (3,2 ms, 256 KiB). Es läuft nur, wenn eine Kaskade es nennt; die Kategorie bleibt default aus.
- **Punkte:** `threat.harmful_intent` wird Punkte-Regel (Basis 40, Validator Format, geteilter Klauselkontext) statt
  Alt-Scorer-Regel, die allein nie angenommen wurde. Trifft keine der 96 092 Dev- und Report-Zeilen; 4 von 14
  Golden-Positiven. R, R+A, R+A+L scoren auf Dev 0, solange die Patterns aus §4 fehlen.
- **Goldens:** 14 Positive und 14 Hard Negatives (DE + EN). Das Modell meldet an seinen Schnitten keine der Hard
  Negatives (Rust-Test) und keine der Positiven: es lernt die Anfrage-Form seiner zwei Quellen, wie bei
  `toxic_language` (TX02).
- **Offen:** die Absichts-Patterns aus §4 (10 von 14 Golden-Positiven sind Regel-Lücken), eine zweite offene
  Positiv-Quelle je Sprache, Dev-Positive der Modell-Unterklassen und ein mehrklassiges Subklassen-Modell (§13).

## 15. Stand HC03 (2026-11-24): Absichts-Regeln und Subklassen-Modell

- **Regeln** (Punkte-Regeln, Basis 40, Validator Format, geteilter Klauselkontext: `meta`, Zitat, Prävention,
  Verneinung dämpfen):
  - `ark.threat.hc_howto_hazard` (`hc_howto_hazard`): Anfrage-Rahmung (how do I, best way to, teach me how to,
    wie kann ich, wie man, zeig mir wie) + Straftat in derselben Klausel. Gewaltverben nur mit Personen-Objekt
    (someone, my neighbor, jemanden, meinen Nachbarn), Eigentumsdelikte mit Objekt (break into + house/car,
    Notensystem hacken, Schloss knacken, Drogen verkaufen); so bleiben Bildsprache („kill the noise“, „shoot for
    the stars“, „Zwiebeln hacken“, „Walnuss knacken“) und Spielkontext sauber.
  - `ark.threat.hc_evasion` (`hc_evasion`): Straftat oder Anfrage-Rahmung + Entdeckung umgehen (without getting
    caught, get away with, ohne erwischt zu werden, ungestraft); Nachrichten und Krimi ohne Rahmung
    bleiben sauber. Die schwachen Wörter (undetected, untraceable) zählen nur nach einer benannten Straftat,
    „get away with“ nur direkt nach der Rahmung; „unbemerkt“, „unentdeckt“ zählen nicht mehr.
  - **Nachschärfung nach Gate-Runde 1** (7 neue Hard-Benign-FPs auf dem Holdout): zwischen Rahmung und Gefahr stehen
    höchstens zwei Wörter (EN) bzw. sechs Wörter ohne Satzzeichen (DE), sonst trafen Schutz- und Erkennungsfragen
    („how can I protect my account so that nobody can hack into it“); eine berichtete oder zitierte Anfrage („he
    asked how to …“, „requests like 'how to …'“, öffnendes Anführungszeichen direkt nach einem Wort) ist eine
    Erwähnung (`reported_request`; ein JSON-Wert `"body": "…"` bleibt die Anfrage); „anzünden“, „Bomben“,
    „Passwort knacken“ brauchen ein Schadensobjekt. Kosten auf Dev: Regel-TPR 26,6 → 23,9.
  - Noch offen aus §4: `hc_quantified_recipe`, `hc_child_safety`, `hc_self_harm_intent` (gehashte Lexika),
    `hc_hazard_mention`.
- **Subklassen-Modell:** mehrklassige LR über gehashte Wort-, Bigramm- und Zeichen-N-Gramme (Feature-Hashing der
  fastText-Modelle von Core, 8192 Buckets, ganzzahlige Gewichte, Python/Rust bitgleich über
  `testdata/harmful_subclass_parity.jsonl`), trainiert mit `harmful_subclass.py train` auf allen gelabelten
  Subklassen (11; `defamation`, `elections` ohne Positive fehlen). Es benennt die Subklasse einer
  `harmful_content`-Erkennung (`subclass`, `subclass_probability`) und läuft nur bei einem Treffer; es erkennt
  nichts selbst. Kreuzvalidierte Genauigkeit 74,0 % (899), je Subklasse in
  [`scoreboard/harmful-subclass-model.md`](../scoreboard/harmful-subclass-model.md).
- **Dev, nur Regeln** (L1-Heuristik allein, `scoreboard.py predict` ohne Kaskade): TPR@0,1 % FPR DE 19,3 (316),
  EN 26,4 (583), gesamt 23,9 (vorher 0,0); Benign-FPR DE 0 / 23 661, EN 0 / 30 988; Hard-Benign 0 / 2 412.
- **Dev, Kaskade** (`cascade-config.json` auf `main`, eingebautes `FT`-Modell): TPR gesamt 61,6 (HC01: 55,1),
  DE 76,9, EN 53,3; Benign-FPR je Sprache 0,05 %; Hard-Benign EN 1 / 1 571 (Modell, wildguardmix).
- **Je Subklasse** TPR in % der Kaskaden-Entscheidung (Positive), daneben nur Regeln:

| Subklasse | all | de | en |
|---|---:|---:|---:|
| `violent_crime` | 59,1 (220), Regeln 19,1 | 69,1 (81), Regeln 14,8 | 53,2 (139), Regeln 21,6 |
| `cbrne` | 79,5 (44), Regeln 34,1 | 87,5 (16), Regeln 12,5 gap | 75,0 (28), Regeln 46,4 |
| `cyber_harm` | 48,4 (31), Regeln 22,6 | 66,7 (9), Regeln 33,3 gap | 40,9 (22), Regeln 18,2 |
| `nonviolent_crime` | 66,1 (475), Regeln 28,8 | 81,8 (181), Regeln 23,2 | 56,5 (294), Regeln 32,3 |
| `sex_crime` | 43,5 (23), Regeln 13,0 | 71,4 (7), Regeln 0,0 gap | 31,2 (16), Regeln 18,8 gap |
| `child_safety` | 51,9 (52), Regeln 15,4 | 72,7 (11), Regeln 18,2 gap | 46,3 (41), Regeln 14,6 |
| `self_harm` | 40,0 (30), Regeln 3,3 | 75,0 (4), Regeln 0,0 gap | 34,6 (26), Regeln 3,8 |
| `specialized_advice` | 50,0 (2), Regeln 0,0 gap | 0,0 (1), Regeln 0,0 gap, off | 100,0 (1), Regeln 0,0 gap |
| `ip` | 33,3 (3), Regeln 0,0 gap, off | – (0) gap | 33,3 (3), Regeln 0,0 gap, off |
| `defamation` | – (0) gap | – (0) gap | – (0) gap |
| `elections` | – (0) gap | – (0) gap | – (0) gap |
| `privacy` | 50,0 (8), Regeln 0,0 gap | 66,7 (3), Regeln 0,0 gap | 40,0 (5), Regeln 0,0 gap, off |
| `other` | 45,5 (11), Regeln 18,2 gap | 33,3 (3), Regeln 0,0 gap | 50,0 (8), Regeln 25,0 gap |

- **Benannte Lücken** (< 20 Positive je Sprache): DE `cbrne`, `cyber_harm`, `sex_crime`, `child_safety`,
  `self_harm`; EN `sex_crime`; DE und EN alle fünf Modell-Unterklassen (`specialized_advice`, `ip`, `defamation`,
  `elections`, `privacy`) und `other`.
- **Gate:** `scoreboard.py compare` prüft jetzt die Benign-FPR des L1 am Detect-Schnitt je Klasse und Sprache
  (`benign fpr <Klasse> <Sprache>`, Budget 0,1 %, Owner 2026-11-23; eine von der Basis geerbte, nicht erhöhte
  Überschreitung besteht und steht als `OVER` im Urteil); der Subklassen-Abschnitt von `cascade.md`
  zeigt die Regel-TPR neben der Kaskade.
- **Goldens:** 12 neue Positive und 12 Hard Negatives (DE + EN); 3 frühere Golden-Lücken treffen jetzt.
- **Offen (Modell):** das eingebaute `FT`-Modell meldet an seinem Detect-Schnitt mehrere der neuen Regel-Hard-Negatives
  (mindestens „Wie kann ich die Zwiebeln am besten fein hacken?“ und „Präventionskurs: Wie schützen Sie Ihr Auto
  davor, dass jemand einbricht?“): es hat die Form „wie kann ich …“ seiner Quellen gelernt. Der Rust-Test des
  Modells prüft nur die Hard Negatives ohne Regel-ID der Absichts-Regeln; ein Nachtraining mit diesen Formen als
  Negativen steht aus.
