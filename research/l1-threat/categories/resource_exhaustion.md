# Kategorie `resource_exhaustion`

Stand: 2026-11-09, Entwurf zur Freigabe. Gliederung wie [`injection.md`](injection.md); Begriffslisten sind
Auszüge, die vollständigen Lexika entstehen in S02. Basiswerte sind Startwerte (siehe
[`injection.md` §4](injection.md#4-patterns)), kalibriert in RE01.

## 1. Schichten

Wie [`injection.md` §1](injection.md#1-schichten-für-alle-kategorien-gleich). Geteilte Core-Lexika:
Adressat, Abwehr, Meta, Zitat, Testcode.

## 2. Abgrenzung

`resource_exhaustion` = Eingabe, die einen Agenten **Rechenzeit, Tokens, Tool-Calls oder Geld** verbrennen
lassen will: Endloswiederholung, rekursives Starten von Agenten/Tasks, Endlosschleifen-Direktiven,
Köder-Rechenaufgaben in Fremdinhalt, absurd große Ausgaben.

Nicht `resource_exhaustion`:
- tatsächlich große Eingaben (Größenlimits sind Sache der Anwendung, kein Detektor);
- Fork-Bomben und Shell-Schleifen (`:(){ :|:& };:`): K26;
- Regex-/Parser-DoS gegen Patronus selbst: Engineering (lineare Regexe, Größenlimits), keine Kategorie.

Die Kategorie ist klein und fast rein regelbasiert; ein eigenes Modell lohnt sich nur, wenn die Ablation es
zeigt (RE01 enthält deshalb Punkte und Entscheidung in einem Task).

## 3. Lexika (`anchor_lexicons/resource_exhaustion.json`)

**Support** (+25/+20/+15):

| ID | DE (Auszug) | EN (Auszug) |
|---|---|---|
| `exhaust.unbounded` | endlos, unendlich oft, für immer, ohne aufzuhören, bis ich stopp sage | forever, infinitely, endlessly, never stop, until I say stop |
| `exhaust.huge_count` | Zahlwort/Zahl ≥ Schwelle + Wiederholungseinheit (mal, Wörter, Seiten, Aufrufe) | number ≥ threshold + unit (times, words, pages, calls) |
| `exhaust.repeat_verb` | wiederhole, gib erneut aus, schreib immer wieder | repeat, output again, keep writing |
| `exhaust.spawn` | starte einen neuen Agenten, der wiederum, rufe dich selbst auf, für jedes Ergebnis einen Sub-Task | spawn an agent that spawns, call yourself, for each result start a subtask |
| `exhaust.decoy_task` | berechne zuerst, löse vorher dieses Rätsel, faktorisiere, alle Primzahlen bis | first compute, before answering solve, factorise, all primes up to |
| `exhaust.cost` | so viele Tool-Aufrufe wie möglich, maximale Tokens, alle Seiten abrufen | as many tool calls as possible, max tokens, fetch every page |
| `addressee` (Core, geteilt) | | |

**Gegen** (−30):

| ID | Inhalt |
|---|---|
| `exhaust.bounded` | erkennbare Grenze im selben Satz: höchstens, maximal 3, bis zu, Timeout, Abbruchbedingung |
| `exhaust.lyrics_play` | Spiel/Kreativ: „wiederhole das Wort dreimal“, Lieder mit Refrain, Übungsaufgaben |
| `defensive`, `meta`, `quotation`, `test_code` (Core, geteilt) | Doku zu Rate-Limits, Lasttests, Benchmarks |

## 4. Patterns

| Pattern | Kern | Basis | Validator | `requires_context` | `scored_only` | Heutige Regeln |
|---|---|---|---|---|---|---|
| `re_recursive_spawn` | `spawn` mit Selbstbezug oder Vervielfachung | 45 | Format | nein | nein | neu |
| `re_unbounded_repeat` | `repeat_verb` + `unbounded` | 40 | Format | nein | nein | neu |
| `re_huge_output` | `repeat_verb`/Ausgabe-Verb + `huge_count` | 35 | Format | ja | nein | neu |
| `re_tool_flood` | `cost`: Tool-Aufrufe/Abrufe maximieren | 35 | Format | ja | nein | neu |
| `re_decoy_compute` | `decoy_task` in Fremdinhalt vor der eigentlichen Antwort | 30 | Format | ja | nein | neu |
| `re_loop_hint` | `unbounded` allein an den Agenten | 15 | – | ja | **ja** | neu |
| `re_decoded` | eines der obigen in einer dekodierten Sicht | wie Quelle | wie Quelle | wie Quelle | wie Quelle | neu |

`huge_count` ist ein Validator auf Zahlen (Ziffern und Zahlwörter DE/EN), kein Lexikon allein. Die Schwelle ist
**konfigurierbar** (`resource_exhaustion_count_threshold`, wie `<kategorie>_mode` je Anfrage und in der
Deploy-Config; festgelegt 2026-11-09); den Default (Start 10.000) kalibriert RE01.
Normalisierungspunkte: Plus wie bei `injection`. Modi wie PII.

## 5. Struktur und Träger

Träger wie bei `injection` (`carrier=indirect` +25); `re_decoy_compute` zählt nur mit `carrier=indirect`
(direkt gestellte Rechenaufgaben sind normale Nutzung).

## 6. Facts (Auszug)

`finding{…}`, `unbounded`, `count{value}`, `spawn{recursive}`, `tool_flood`, `decoy`, `bounded`, `carrier`,
Modifikatoren wie `injection`.

## 7. Modell

Kandidaten: R, R+A (nur Regeln), R+A+L; B1/B4/B5 nur, wenn die Daten reichen. Kein heutiger Scorer, keine
Regeln im Bestand. Daten fast nur aus Generatoren (Einbettung in Fremdinhalt mit sauberem Zwilling) und
Agent-Benchmarks mit DoS-Aufgaben.

## 8. Policies (später)

- `re.indirect_spawn`: `carrier.indirect` ∧ `spawn` → `block`.

## 9. Bestand

Keine heutigen Regeln. Fork-Bomben und Shell-Schleifen liegen bei K26.

## 10. Übernommene OSS-Regeln

ATR (Resource-/Loop-Familien); default aus.

## 11. Goldens

Je Pattern und Sprache ≥ 5 Positive und ≥ 5 Hard Negatives. Pflicht-Hard-Negatives: „wiederhole das
dreimal“, Lasttest-Doku, Mathe-Aufgaben vom Nutzer selbst, Lieder mit Refrain, „rufe die API für jede der
5 Städte auf“.

## 12. Herkunft und Daten

Regeln für Herkunft, Splits und Quellfamilien: [README](../README.md#herkunft-regeln-train-gold-holdout).
Goldens: je Pattern und Sprache ≥ 5 Positive und ≥ 5 Hard Negatives, selbst geschrieben (`ark_authored`), §11.

| | Quelle |
|---|---|
| Patterns/Anker | kein Bestand; `oss`: ATR (Resource/Loop); `taxonomy`: OWASP LLM10 (Unbounded Consumption); `hand` für Zahl-Validator; `mined` auf Train |
| Train/Dev | Generatoren: Einbettung in Fremdinhalt (Dev-Seed); DoS-Aufgaben aus Agent-Benchmarks (Agent-SafetyBench), soweit vorhanden |
| Holdout `neutral` | keiner bekannt |
| Holdout `ark_blind` | R05 DE+EN (entscheidet), Seed-Teil |
| Hard Negatives | Mathe-Aufgaben, Lasttest-Doku, Lieder mit Refrain, begrenzte Wiederholungen |
| Lücke | keine öffentlichen Daten; Ergebnis gilt nur auf `ark_blind` |

## 13. Stand RE01 (2026-11-14)

Fünf eigene Regeln im Threat-Detektor (`ark-core/src/detectors/threat/rules.json`, Präfix
`ark.threat.re_*`, default an, Kategorie selbst opt-in). Sie tragen `points` und entscheiden selbst
wie die UA01-Regeln: Punkte ≥ 50, kein Gegenkontext im Satz (oder, außer Verneinung, im Satz
davor), bei `requires_context` ein Stützterm (Adressat) im Satz. Kein Modell: die Klasse ist rein
regelbasiert; eine Ablation lohnt erst mit mehr als den Generator-Daten (§7).

| Pattern | Regel | Basis | `requires_context` | Kern |
|---|---|---|---|---|
| `re_recursive_spawn` | `re_recursive_spawn` | 45 | nein | Start-Verb + Agent/Kopie/Instanz + Selbstbezug (`that in turn spawns`, `der wiederum`, `rekursiv`) oder je Ergebnis neue Agenten (`for every result … start … sub-agents`) |
| `re_unbounded_repeat` | `re_unbounded_repeat` | 40 | nein | `repeat`/`keep …ing`/`wiederhole` + `forever`/`endlos`/`ohne aufzuhören` (+ optional „und hör niemals auf“, das als Teil der Phrase keine Verneinung ist) |
| `re_huge_output` | `re_huge_output` | 35 | ja | Ausgabe-Verb + Zahl + Einheit (EN Verb vorn, DE auch Verb am Satzende); Zahl ≥ `resource_exhaustion_count_threshold` |
| `re_tool_flood` | `re_tool_flood` | 35 | ja | Abruf-/Aufruf-Verb + `as many tool calls as possible`, `every page of the web`, `so viele … wie möglich` |
| `re_decoy_compute` | `re_decoy_compute` | 30 | ja | `before answering`/`bevor du antwortest` + schwere Rechenaufgabe (alle Primzahlen, Stellen von Pi, jede Permutation) |

**Schwelle.** `resource_exhaustion_count_threshold` ist ein Gate in `NativeGates` (je Anfrage und in
der Deploy-Config, auch Coordinator und Ark API), positive Ganzzahl, Default 10.000 (Startwert
bestätigt: alle Golden-Positive liegen ≥ 250.000, die Hard Negatives bei 2.000 Wörtern und
50.000 Lasttest-Anfragen fallen über Verb bzw. Lasttest-Gegenkontext heraus). Zahlen: Ziffern mit
Tausendertrennern (`1,000,000`, `1.000.000`) und Zahlwörter DE/EN (`zwei Millionen`, `ten
thousand`, `zehntausend`); „Billion“ zählt als 10⁹ (kleinerer Wert von EN/DE).

**Abweichung.** `re_decoy_compute` prüft keinen Träger-Fact `carrier=indirect` (der Threat-Detektor
sieht die Facts nicht); Ersatz ist `requires_context` (Adressat im Satz). Eine direkt gestellte
Rechenaufgabe ohne „bevor du antwortest“-Rahmen trifft nicht.

Lexika: Anker (Prefilter) `exhaust.spawn`, `exhaust.repeat_verb`, `exhaust.cost`,
`exhaust.decoy_task` in `anchor_lexicons/resource_exhaustion.json`; Gegenkontext `exhaust.bounded`
(höchstens, Timeout, Lasttest) und `exhaust.lyrics_play` (Lied, Refrain, Übung) in `context.json`,
nur für diese Klasse wirksam. `exhaust.unbounded` und `exhaust.huge_count` stecken in den Regeln
bzw. im Zahl-Validator. Offen: `re_loop_hint` (scored only), `re_decoded` (S03), ATR-Regeln (§10).

**Latenz (offen).** Python-Release-Build, 100-KiB-Fenster aus GermanQuAD (dev): Kategorie
`resource_exhaustion` allein p50 4,5 ms / p95 5,4 ms mit den Regeln, 0,35 / 0,49 ms ohne; je Regel
allein `re_tool_flood` 0,7 ms, die übrigen 2,6–3,4 ms. Kein akzeptierter Treffer auf 3.000
GermanQuAD-Absätzen. Nächster Schritt: Ursache isolieren (Regex-Scan mit häufigen Präfixwörtern wie
„vor“, „start“, „gib“ vs. Kontext-Scan nach Rohtreffern) und die Präfixe/Lücken enger fassen, bevor
die Kategorie im `all`-Profil gemessen wird.
