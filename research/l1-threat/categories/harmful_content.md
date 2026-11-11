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
(FR/ES nativ), MultiJail, JBB-Behaviors, HarmBench; DE nur RTP-LX und `wildchat-de`, deshalb R05 mit
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
| Train/Dev | WildGuardMix, PolyGuardPrompts, Nemotron v3 (MT-markiert), XL-SafetyBench; Modell-Unterklassen: Kandidaten AILuminate-Demo-Set, Nemotron Content Safety v2 (Lizenz prüft E01) |
| Holdout `neutral` | aya_redteaming (EN, FR/ES nativ), MultiJail, JBB-Behaviors, HarmBench; DE: RTP-LX de, PolygloToxicityPrompts `wildchat-de` |
| Holdout `ark_blind` | R05 DE (Harm-Anteil, ohne funktionierende Anleitungen: nur Anfragen) |
| Hard Negatives | XSTest-safe, OR-Bench-hard, Prävention, Nachrichten, Chemieunterricht, Pentest mit Auftrag |
| Lücke | Modell-Unterklassen (Fachberatung, Urheberrecht, Verleumdung, Wahlen, Privatsphäre) nur mit Kandidaten-Daten; bleiben aus, bis sie die Grenze aus §7 schaffen |
