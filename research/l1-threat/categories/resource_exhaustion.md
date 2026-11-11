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
