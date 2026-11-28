# L1-Threat latency on real German text

Machine: Intel Core Processor (Haswell, no TSX), 6 usable CPUs, Linux x86_64. Native Rust gateway at L1 (release build), one scan per sample, sequential.
Corpus: 64 distinct windows of 102400 bytes, sha256 `32fc2d587119e64a`; 5 samples per window, p95 pooled over all windows. Runs: 3; per profile the run with the median p95.

| Profile | Categories | Init ms | p50 ms | p95 ms | p99 ms | max ms | p95 per run ms |
|---|---|---:|---:|---:|---:|---:|---|
| threat | threat | 79 | 23.149 | 34.580 | 38.187 | 39.006 | 35.421, 33.901, 34.580 |
| injection | injection | 720 | 60.709 | 87.772 | 110.201 | 126.763 | 87.011, 87.772, 88.664 |
| all | injection, dlp, pii, threat, shell_command | 1637 | 58.669 | 83.277 | 91.168 | 107.852 | 83.277, 78.372, 85.663 |

Gemessen 2026-11-11 auf der VPS (Branch `threat/007-e03`, Base `770d4280`), Korpus-SHA-256
`32fc2d587119e64a84b8758af6f11933ce89c15d1945cfa873d6c3e39f7d8240` (64 Fenster aus 17 628 Absätzen von
`dewiki-dev`, `gesetze-dev`, `wmf-dev-de`, `dewiki-latency`). Erzeugt mit

```bash
python3 scripts/l1_threat/latency.py prepare --out DIR
python3 scripts/l1_threat/latency.py run --corpus DIR --output latency.json --markdown latency.md --runs 3
```

Beobachtungen (Ausgangsstand für H02 und das Gate-Kriterium „100 KiB p95 höchstens +5 %“):

- Auf echtem deutschem Fließtext liegen `injection` (p95 ≈ 88 ms) und `threat` (≈ 35 ms) je 100 KiB weit über
  dem DLP-Budget von 10 ms; die synthetischen PII-Workloads unterschätzen die Injection-Latenz damit deutlich.
- `all` (eine Anfrage mit allen L1-Kategorien) ist nicht langsamer als `injection` allein: die Kategorien einer
  Anfrage laufen parallel (`scan_l1_inputs`, rayon) auf einer geteilten `NativeText`-Sicht, `all` folgt also der
  langsamsten Kategorie und hängt von der Zahl freier Kerne ab. Für das Gate zählt jedes Profil einzeln.
- Treffer auf dem gutartigen Korpus: `injection` 0, `threat` 0, `all` 12 Spans (PII/DLP-Spans in den Texten).

## H02 (2026-11-26): Latenz-Check auf E03, Property-Tests

Gemessen auf der VPS mit demselben Korpus (neu erzeugt mit `latency.py prepare`, gleiche SHA-256
`32fc2d58…`), Base = `main` (`9d24b2f2`, als `git archive` nach `/tmp`, `--repo`), Head = Branch
`threat/201-h02`; je 3 Läufe, Profile `threat` und `injection`, nacheinander ohne andere Last:

| Profil | Base p50 ms | Base p95 ms | Head p50 ms | Head p95 ms | p95-Änderung |
|---|---:|---:|---:|---:|---:|
| threat | 146.672 | 170.830 | 29.115 | 39.571 | −76,8 % |
| injection | 129.448 | 182.145 | 128.025 | 182.008 | −0,1 % |

`latency.py compare --base base.json --head head.json`: PASS.

Befunde:

- **Seit E03 hatte sich `threat` fast verfünffacht** (p95 35 → 171 ms). Ursache: die Regeln mit
  Unicode-`\b` und unbedingtem Anker-Gate (`hc_evasion`, `hc_howto_hazard`, `credential_harvesting`)
  laufen über den ganzen Text; der Lazy-DFA gibt bei Unicode-`\b` am ersten Nicht-ASCII-Byte (Umlaut)
  auf und fällt für den Rest des Texts auf die NFA zurück. Allein mit dem `regex`-Crate auf 100 KiB
  deutschem Text: `hc_evasion` 0,2 ms (ASCII) gegen 65 ms (mit Umlaut), `hc_howto_hazard` 0,2 gegen
  22 ms, `credential_harvesting` 0,2 gegen 12 ms. Fix: Threat-Regeln mit Unicode-Wortgrenze suchen
  auf Nicht-ASCII-Fenstern wie PII und DLP über `word_boundary::leftmost_start` (Regel ohne
  Wortgrenzen auf dem DFA, jeder Kandidat verankert mit der Regel selbst geprüft). Treffer und
  Captures sind identisch (Test über alle Regeln auf den Threat-Goldens mit Umlauten davor, dazwischen
  und danach). Damit liegt `threat` wieder nahe am E03-Stand (35 ms) statt bei 171 ms.
- **`injection` liegt bei p95 ≈ 182 ms je 100 KiB** (E03: 88 ms), in Base und Head gleich; nicht durch
  diese Änderung, aber weit über dem DLP-Budget von 10 ms und dem E03-Stand. Offene Folgearbeit:
  Ursache der Verdopplung seit E03 (Injection-Regeln/Views) eingrenzen.
- Weiter offen (Release, nur die Kategorie aktiv, 100 KiB wiederholte deutsche Imperativ-Sätze):
  `agent_config_tampering` ≈ 23 ms gegen ≈ 2,5 ms auf neutraler Prosa (`agent_guard_removal`,
  `unauthorized_autonomy` je ≈ 12–14 ms im Regex allein, ohne Umlaut-Effekt). Die quadratische
  `quoted()`-Prüfung aus UA02 §14 war in diesem Worst Case nicht messbar (eine Zeile ≈ viele Zeilen).

Property-Tests (`ark-core/tests/l1_properties.rs`, feste Seeds, alle 13 nativen L1-Kategorien in
einem Scanner): 400 zufällige Eingaben aus Angriffsformen und gutartigem Text (DE/EN) mit
Nullbreiten-, Tag-, Vollbreiten-, Sperrschrift- und Kombinationszeichen-Verschleierung, Zitaten,
Steuerzeichen und Schnitt mitten in einer Sequenz; jedes Rauschzeichen allein und um einen Angriff;
lange Zeilen mit vielen Treffern. Geprüft: kein Fehler und keine Panik; jede Evidenz ist ein gültiger
Byte- und Zeichenbereich der Eingabe (auch wenn nur eine normalisierte oder dekodierte Sicht den
Fund zeigte); Konfidenzen in `[0, 1]`; eine Eingabe zweimal hintereinander senkt keine Konfidenz und
verliert keine Evidenz. Monotonie der Punkte (`score.rs`): höhere Schwere, stärkerer Validator, mehr
Anker oder besserer Kontext senken nie einen Score; Normalisierung senkt nie einen Angriffs-Score.

## T38 (2026-11-27): Profil aller Threat-Klassen, erste Hotspots behoben

Gemessen auf der VPS (Intel Core Processor (Haswell, no TSX), 6 CPUs), Release-Build, ein Prozess,
Scanner einmal gebaut und je Größe einmal aufgewärmt (kein Prozessstart, kein Erstkompilat in der
Messung), sequentiell. Werkzeug: `ark-core/examples/threat_profile.rs` (alle elf Angriffsklassen in
einem Scanner wie `threat_cascade`; dazu jeder native Produzent einzeln auf einer frischen
`NativeText`-Sicht und jedes L1-Modell über die Layer-Dauer seiner Kaskadenentscheidung). Texte: alle
gutartigen Zeilen aus `$ARK_L1_DEV_DATA/train_dev` (DE + EN, 58 470 Zeilen, Seed 38 gemischt), in
Fenster gepackt. Base = `main` (`3d726a49`), Head = dieser Branch. Regeln allein: `{"max_level":
"l1", "cascade": {}}`; mit L1-Modellen: `research/l1-threat/scoreboard/cascade-config.json`.

```bash
cargo build --release -p patronus-ark-core --example threat_profile
target/release/examples/threat_profile benign.jsonl                                   # Regeln
target/release/examples/threat_profile benign.jsonl research/l1-threat/scoreboard/cascade-config.json
```

| Größe | Fenster | Base Regeln p50 / p95 ms | Head Regeln p50 / p95 ms | Head Regeln + L1-Modelle p50 / p95 ms | Summe L1-Modelle p50 ms |
|---|---:|---:|---:|---:|---:|
| short (256 B) | 200 | 1.318 / 3.539 | 1.453 / 3.178 | 2.668 / 5.688 | 0.8 |
| 4 KiB | 60 | 10.714 / 19.130 | 9.599 / 16.402 | 18.557 / 25.647 | 8.7 |
| 100 KiB | 20 | 354.063 / 484.292 | 149.596 / 180.329 | 335.799 / 407.575 | 175.2 |
| 10 MiB | 2 | 62 422 / 63 910 | 27 289 / 30 789 | 39 555 / 48 447 | 9 913 |

Produzenten bei 100 KiB (jeder einzeln, p50 / p95 ms; die zehn teuersten des Head):

| Produzent (Klasse/Detektor) | Base | Head |
|---|---:|---:|
| `injection/native:injection_rule_catalog` | 210.185 / 327.254 | 29.643 / 43.292 |
| `agent_config_tampering/native:threat_l1` | 19.290 / 21.041 | 1.168 / 1.461 |
| `unsafe_action/native:threat_l1` | 9.949 / 13.676 | 10.130 / 14.970 |
| `prompt_extraction/native:injection_rule_catalog` | 8.160 / 13.307 | 8.779 / 14.115 |
| `jailbreak/native:injection_rule_catalog` | 6.523 / 16.062 | 6.442 / 7.677 |
| `toxic_language/native:threat_l1` | 5.231 / 6.847 | 5.253 / 5.853 |
| `tool_poisoning/native:threat_l1` | 4.499 / 5.658 | 4.208 / 7.346 |
| `exfiltration/native:threat_l1` | 4.069 / 4.362 | 4.123 / 4.750 |
| `memory_poisoning/native:injection_rule_catalog` | 8.773 / 10.060 | 2.903 / 3.709 |
| `exfiltration/native:injection_rule_catalog` | 2.081 / 9.689 | 2.305 / 9.924 |

L1-Modelle bei 100 KiB (Head, p50 / p95 ms): memory_poisoning 19.8 / 24.7, injection 19.5 / 25.7,
exfiltration 19.4 / 24.9, harmful_content 19.0 / 24.1, resource_exhaustion 18.6 / 24.7,
prompt_extraction 18.5 / 24.2, unsafe_action 18.4 / 25.4, jailbreak 18.3 / 24.2, toxic_language
18.0 / 24.4, tool_poisoning 5.4 / 25.2, agent_config_tampering 0.3 / 20.3 (die beiden letzten laufen
nur mit ihrem Träger).

Hotspots (Einzelregeln auf einem 100-KiB-Fenster deutscher/englischer Prosa, `regex` allein):

1. **Injection-Katalog mit Unicode-`\b`** (behoben): rund 30 Katalogregeln mit Unicode-Wortgrenze
   fielen am ersten Umlaut von der Lazy-DFA auf die NFA zurück, je 5–38 ms
   (`override.discard_prior`-Varianten 34–38 ms, `leak.system_prompt_extraction` 18 ms,
   `override.authority_issued_replacement`, `skillspector.anti_refusal`, `guardrail.disable_directive`
   je 12–14 ms). Jetzt wie Threat, PII und DLP über `word_boundary::captures_at` (Regel ohne
   Wortgrenzen auf dem DFA, Kandidat verankert mit der Regel geprüft); Summe aller Katalogregeln auf
   dem Fenster 321 → 78 ms, Katalog der Klasse `injection` p50 210 → 30 ms. Treffer, Captures und
   Evidenz identisch (Paritätstest über Injection- und Threat-Goldens mit Umlauten).
2. **Träger-Gates mit Unicode-`\b`** (behoben): `is_agent_config` (Gate der `ac_*`-Regeln) 23 ms,
   `carries_class(agent_config_tampering)` (Gate des L1-Modells) 63 ms, die Träger-Marken der
   Text-Facts (`RegexSet`) bis 41 ms; jetzt `BoundarySearch::is_match` ≈ 0,6 / 1,0 / 5 ms.
   Entscheidungen identisch (Paritätstest gegen Regex und `RegexSet`).
3. **L1-Modelle** (offen): jedes Modell extrahiert die Facts und zählt die n-Gramme über den ganzen
   Text, ≈ 18–20 ms je Modell und 100 KiB, zusammen ≈ 175 ms. Nächste Schritte: die Facts einmal je
   Scan teilen und nur begrenzte Fenster um Anker (sonst ein gedeckeltes Präfix) bewerten — das
   ändert die Scores und braucht die TPR-Messung auf der sauberen Auswertung.
4. **Verbleibende Katalogregeln** (offen): `indirect.code_insertion_en` (`override.replacement_directive`)
   17–25 ms und die `leak.guarded_secret_*`-Varianten 6–8 ms, beide ohne Unicode-`\b`; lange
   Satzanfangs-Alternationen mit `[^…]{0,39}?` vor dem Literal, die der Literal-Prefilter nicht
   abfängt (Prefilter trifft auf normaler Prosa).
5. **Threat-Regeln** (offen): `hc_evasion` 38 ms trotz entspannter Suche (viele Kandidaten),
   `tx_dehumanisation`, `tx_insult_addressee`, `tx_insult_verdict` je 9–11 ms (gutartige
   Prosa hat 10–29 Kandidaten je Regel), `tx_threat`, `ua_persistence`, `ac_tamper_request`,
   `re_huge_output` je 4–6 ms.
6. **Kurztexte**: Head p50 1,32 → 1,45 ms (p95 3,54 → 3,18 ms); die entspannte Suche macht je Kandidat
   drei statt einer Suche, auf kurzen Texten ohne Treffer kaum messbar.

Qualität: Base- und Head-`threat_cascade` (Release) über alle 88 677 Zeilen von
`train_dev` + `generated` + `translated` geben mit der Regel-Konfiguration und mit
`cascade-config.json` (L1-Modelle) Zeile für Zeile dieselbe Vorhersage (Scores, `flagged`,
Kaskadenentscheidung, Logit; nur `ms` ausgenommen): 0 Abweichungen, je 11 156 markierte Zeilen. Die
Änderungen sind reine Suchwege mit identischen Treffern; Schwellen, Regeln und Modelle sind
unverändert.

Stand gegen das Ziel (100 KiB p95 ≤ 10 ms Regeln, ≤ 15 ms mit L1-Modellen): Regeln 180 ms, mit
Modellen 408 ms — nicht erreicht. Der Lauf von `scripts/benchmark_injection_l1.py` und die
Neuberechnung der E12-Latenztabelle stehen aus.

### T38 Runde 2 (2026-11-27): L1-Modelle teilen die Facts

Gleiches Werkzeug, gleiche Maschine und gleiche Texte wie oben (`threat_profile`, 58 470 gutartige
`train_dev`-Zeilen, Seed 38). Vorher = Head der ersten Runde (`f1bf35ba`), Nachher = dieser Branch.

| Größe | Regeln p50 / p95 ms vorher → nachher | Regeln + L1-Modelle p50 / p95 ms vorher → nachher | Summe L1-Modelle p50 ms vorher → nachher |
|---|---:|---:|---:|
| short (256 B) | 1.453 / 3.178 → 1.530 / 4.005 | 2.668 / 5.688 → 1.792 / 4.102 | 0.8 → 0.4 |
| 4 KiB | 9.599 / 16.402 → 10.717 / 18.494 | 18.557 / 25.647 → 13.529 / 19.662 | 8.7 → 3.6 |
| 100 KiB | 149.596 / 180.329 → 136.583 / 166.630 | 335.799 / 407.575 → 186.114 / 238.665 | 175.2 → 48.0 |
| 10 MiB | 27 289 / 30 789 → 25 324 / 25 667 | 39 555 / 48 447 → 28 215 / 29 500 | 9 913 → 2 979 |

Was sich geändert hat (beides reine Wiederverwendung, Scores bitgleich):

1. **Facts einmal je Scan** (Hotspot 3): von den ≈ 19 ms je Modell und 100 KiB waren ≈ 16 ms die
   Fact-Extraktion (Sichten, Kontext-Lexika, Sprache, Träger, Senken), nur ≈ 3 ms die n-Gramm-Wertung.
   Die Facts hängen nur vom Text und den Regel-Findings des Scans ab, und die sind für jedes Modul
   gleich; `SharedFacts` extrahiert sie beim ersten Modell und reicht sie an alle weiteren (Core-Scanner
   und Arks Queue). Jetzt: erstes Modell ≈ 17 ms, jedes weitere ≈ 3,1 ms, zusammen 48 statt 175 ms.
2. **Kontext-Scan der Katalog-Wertung**: außerhalb von `injection` scannte die Wertung der
   Katalogkandidaten die Kontext-Lexika je Klasse erneut über den ganzen Text; sie liest jetzt den
   Scan der vorbereiteten `NativeText`, den die Regeln schon gemacht haben (Regeln p50 150 → 137 ms).

Verbleibende Hotspots bei 100 KiB (Head, im Scan, p50 ms): `injection`-Katalog 29 (Wertung im Scan
44), `unsafe_action` 19, Fact-Extraktion des ersten L1-Modells 17, `jailbreak`-Katalog 11,
`exfiltration` 11, `toxic_language` 10, je weiteres L1-Modell 3 (n-Gramm-Hashes über den ganzen
Text; Tabellenzugriffe dominieren). Nächste Schritte bleiben: ein gemeinsamer Aho-Corasick-Pass
für alle Threat-Regeln (heute je Regel ein `AnchorGate`), die Katalogregeln mit langen
Satzanfangs-Alternationen, und die L1-Modelle nur auf Fenstern um Anker (ändert Scores, braucht die
TPR-Messung auf der sauberen Auswertung).

Qualität: Base (`f1bf35ba`) und Head `threat_cascade` (Release) mit `cascade-config.json` über alle
88 677 Zeilen von `train_dev` + `generated` + `translated`: 0 abweichende Vorhersagen (alles außer
`ms`), je 11 156 markierte Zeilen. Dazu ein Unit-Test, der für alle elf eingebauten Modelle den
Score mit geteilten Facts bitgleich zur eigenen Extraktion prüft.

`scripts/benchmark_injection_l1.py` (nur der Injection-Pfad des Gateways über die Python-Bindung,
synthetischer ASCII-Text, 50 Läufe nach 10 Aufwärmläufen, Release-Build; p50 / p95 ms):

| Größe | gutartig | mit eingebettetem Angriff |
|---|---:|---:|
| 1 KiB | 0.260 / 0.387 | 1.554 / 1.984 |
| 10 KiB | 1.153 / 1.699 | 3.136 / 4.282 |
| 100 KiB | 9.022 / 12.377 | 16.792 / 22.604 |

Die E12-Latenztabelle (`competitors.py`, braucht die Benchmark-Quellen) ist in dieser Runde nicht
neu gerechnet.

Stand gegen das Ziel (100 KiB p95 ≤ 10 ms Regeln, ≤ 15 ms mit L1-Modellen): Regeln 167 ms, mit
Modellen 239 ms — weiter nicht erreicht.

### T38 Runde 4 (2026-11-27): Teil a abgeschlossen, begrenzte Modellsicht zurückgenommen

Die Aufgabe ist am 27.11. geteilt: T38 (Teil a) liefert Profil, Hotspots, geteilte Facts und die
Wiederverwendung des Kontext-Scans ohne jede Qualitätsänderung; der gemeinsame Aho-Corasick-Pass der
Regeln ist T38b, das exakte Beschneiden der L1-Modelle T38c.

Runde 3 hatte die L1-Modelle auf höchstens 16 KiB eines Texts begrenzt (Fenster um Findings, Rest vom
Textanfang; Modelle bei 100 KiB 48 → 13 ms p50). Das änderte eine Dev-Entscheidung
(`approve_or_deny_de:0000141`, gutartig, danach `unsafe_action` detected) und widerspricht damit „keine
Qualitätsänderung“. Die Sicht ist zurückgenommen; die Modelle lesen wieder den ganzen Text mit den
geteilten Facts (Stand Runde 2, Scores bitgleich zu `main`). Die schnelle Modellwertung kommt mit T38c
als exaktes Beschneiden (gleicher Score auf jeder Zeile).

Messung vor und nach (VPS, Intel Core Processor (Haswell, no TSX), 6 CPUs, Release, ein warmer
Prozess, sequentiell ohne andere Last; `threat_profile` wie oben, 58 470 gutartige
`train_dev`-Zeilen, Seed 38). Vorher = `main` (`004583a5`, mit derselben `threat_profile.rs`, ohne
10 MiB), Nachher = dieser Branch (`1fff7a5d`). Alle elf Angriffsklassen in einem Scanner; Regeln allein
`{"max_level": "l1", "cascade": {}}`, mit L1-Modellen `cascade-config.json`.

| Größe | Regeln p50 / p95 ms vorher → nachher | Regeln + L1-Modelle p50 / p95 ms vorher → nachher | Summe L1-Modelle p50 ms vorher → nachher |
|---|---:|---:|---:|
| short (256 B) | 1.245 / 3.677 → 1.159 / 3.206 | 2.694 / 5.072 → 1.840 / 4.051 | 1.2 → 0.4 |
| 4 KiB | 11.226 / 21.443 → 8.652 / 15.397 | 28.164 / 38.091 → 13.363 / 21.499 | 16.6 → 3.6 |
| 100 KiB | 370.303 / 490.556 → 134.339 / 183.972 | 784.837 / 884.209 → 188.242 / 236.495 | 405.8 → 49.2 |
| 10 MiB | — → 25 360 / 25 811 | — → 27 384 / 28 588 | — → 3 098 |

L1-Modelle bei 100 KiB (p50 / p95 ms, vorher → nachher): injection 39.9 / 51.6 → 18.4 / 23.4 (extrahiert
die Facts für alle), tool_poisoning → 4.2 / 6.2 (Träger-Gate über den ganzen Text), memory_poisoning
42.6 / 47.4 → 3.4 / 4.6, unsafe_action 42.5 / 55.2 → 3.3 / 5.4, harmful_content 40.4 / 47.4 → 3.3 / 5.6,
prompt_extraction 39.9 / 48.3 → 3.3 / 4.2, jailbreak 40.0 / 43.9 → 3.3 / 5.3, toxic_language
39.9 / 46.7 → 3.3 / 4.7, exfiltration 40.4 / 49.3 → 3.3 / 3.8, agent_config_tampering 35.2 / 71.3 → nur
mit Träger.

Top-Hotspots nach diesem Stand (100 KiB, mit L1-Modellen, im Scan, p50 / p95 ms):
`injection/injection_l1` 45.8 / 57.5 (davon Katalog 29.3 / 46.3), `unsafe_action/threat_l1` 18.5 / 26.3,
L1-Modell `injection` (Fact-Extraktion für alle) 18.4 / 23.4, `jailbreak/injection_l1` 11.6 / 14.6,
`exfiltration/threat_l1` 10.3 / 17.2, `toxic_language/threat_l1` 10.0 / 13.9, Katalog
`prompt_extraction` 8.6 / 14.0, `harmful_content/threat_l1` 6.8 / 16.0. Weiter offen und als T38b/T38c
im Backlog: ein gemeinsamer Aho-Corasick-Pass für alle Threat- und Katalogregeln (49 von 282 Regeln
ohne Anker-Gate: 10 der 98 Threat-Regeln — `hc_howto_hazard`, `hc_evasion`, `ua_home_dir_delete`,
`tp_secrecy`, `re_recursive_spawn`, `re_tool_flood`, `ex_send_directive`, `ex_secret_to_sink`,
`ex_tool_param_egress`, `ex_dns_channel` — und 39 der 184 Katalogregeln, vor allem
`prompt_armor_95e532e` und `skillspector.*`) und exaktes Beschneiden der Modelle. Ziel
(100 KiB p95 ≤ 10 ms Regeln, ≤ 15 ms mit Modellen) ist nicht Teil von T38 (Teil a) und nicht erreicht.

Qualität: `threat_cascade` (Release) von `main` (`004583a5`) und diesem Branch über alle 109 632
Zeilen unter `$ARK_L1_DEV_DATA` (`train_dev`, `generated`, `translated`, `report`), mit der
Regel-Konfiguration und mit `cascade-config.json`: 0 abweichende Vorhersagen (Scores, `flagged`,
Kaskadenentscheidung, Logit; nur `ms` ausgenommen), je 12 290 markierte Zeilen. Die Goldens
(`13_l1_golden_eval -- all`) bestehen unverändert. Unit-Test: für alle elf eingebauten Modelle ist
der Score mit geteilten Facts bitgleich zur eigenen Extraktion. Holdout ist in der Sandbox nicht
zugänglich; bei bitgleichen Scores auf jeder Zeile ändert er sich nicht.

Scoreboard-Refresh: `scoreboard.py refresh` lief in der Sandbox (Runde 3) durch, aber nicht
vergleichbar — der lokale Baseline-Cache enthält nur einen Teil der Baselines (ATR, Cisco YARA,
LlamaFirewall, NeMo, Pipelock, Prompt Guard, Vigil fielen auf „not run“), und der Mix kam mit 55 929
statt 55 918 Zeilen heraus. `baseline.md`, `cascade.md` und die übrigen Berichte sind deshalb nicht neu
eingecheckt. Da Regeln, Modelle, Scores und Schwellen bitgleich bleiben, ändert sich an ihnen nichts;
ein Refresh in der Owner-Umgebung (`python3 scripts/l1_threat/scoreboard.py refresh --dev
"$ARK_L1_DEV_DATA" --cache <gate-cache> --baseline-cache <voller Baseline-Cache>`) muss dieselben
Zahlen ergeben.

## T38b (2026-11-28): ein Aho-Corasick-Pass als Prefilter jeder Threat-Regel

Was sich ändert (reine Suchwege, Treffer identisch):

1. **Positionen aus dem einen Pass**: der Anker-Automat (`LexicalAnchorScanner`, ein
   Aho-Corasick über die Kleinschreib-Sicht) liefert in demselben Durchlauf, in dem er die Anker
   eines Texts findet, auch wo jedes Wort steht (`NativeText::anchors_within`, Bytebereiche des
   Originals; ohne Positionen nur bei einem langen s im Text, dann gilt die Präsenz des ganzen
   Texts).
2. **Notwendige Wörter jeder Regel**: aus dem Regex jeder Threat-Regel kommt eine Wortmenge, von
   der jeder Treffer eines enthält (`anchor_gate::necessary_words`; Literal-Läufe, Alternationen
   mit allen Zweigen, vom Parser ausgeklammerte Präfixe gehen in jeden Zweig). Diese Wörter hängen
   im selben Automaten, gehören zu keinem Anker (lexikalische Signale und Ankerpunkte unverändert)
   und bilden mit dem Anker-Gate den `prefilter` der Regel. Damit haben alle 98 Threat-Regeln einen
   Literal-Prefilter, auch die zehn ohne Anker-Gate (`hc_howto_hazard`, `hc_evasion`,
   `ua_home_dir_delete`, `tp_secrecy`, `re_recursive_spawn`, `re_tool_flood`,
   `ex_send_directive`, `ex_secret_to_sink`, `ex_tool_param_egress`, `ex_dns_channel`).
3. **Fenster statt ganzer Text**: eine Regel läuft nur auf den 8-KiB-Fenstern, deren Wörter ihren
   Prefilter erfüllen. Ein Treffer liegt ganz in seinem Fenster und enthält dort seine Wörter;
   ein übersprungenes Fenster verliert also keinen Treffer (Test
   `the_window_prefilter_admits_every_match`: jeder Treffer jeder Regel auf den Threat-Goldens
   nach 9 KiB Prosa, mit Umlauten, langem s und längenändernden Kleinbuchstaben).

Messung (VPS, Intel Core Processor (Haswell, no TSX), 6 CPUs, Release, ein warmer Prozess,
`threat_profile` wie in T38, 58 470 gutartige `train_dev`-Zeilen, Seed 38, Regeln allein
`{"max_level": "l1", "cascade": {}}`). Vorher = `main` (`6ebdbd4c`), Nachher = dieser Branch; je
zwei Läufe abwechselnd, ohne andere Last:

| Größe | Regeln p50 / p95 ms vorher (Lauf 1, 2) | Regeln p50 / p95 ms nachher (Lauf 1, 2) |
|---|---:|---:|
| short (256 B) | 1.152 / 3.550, 1.098 / 3.344 | 0.848 / 3.302, 0.856 / 3.463 |
| 4 KiB | 8.114 / 14.878, 8.784 / 14.980 | 7.070 / 12.890, 6.788 / 13.205 |
| 100 KiB | 130.665 / 167.412, 130.671 / 170.204 | 118.830 / 147.503, 111.178 / 148.908 |

Produzenten bei 100 KiB (im Scan, p50 / p95 ms, vorher → nachher): `unsafe_action/threat_l1`
17.9 / 25.1 → 10.1 / 13.8, `exfiltration/threat_l1` 9.3 / 16.0 → 7.8 / 12.5, Regeln von
`unsafe_action` allein 9.7 / 13.6 → 4.6 / 8.0, Regeln von `exfiltration` allein 4.0 / 4.4 →
3.1 / 3.4; `toxic_language` (≈ 10 ms), `harmful_content`, `tool_poisoning`, `resource_exhaustion`
unverändert im Rauschen (ihre Wörter stehen in fast jedem Fenster gutartiger Prosa, die Kosten
liegen in der Prüfung der Kandidaten, nicht im Regex über den ganzen Text).

Stand gegen das Ziel (100 KiB p95 ≤ 10 ms, Regeln aller Klassen): 148 ms — **nicht erreicht**. Der
größte Teil liegt nicht in den Threat-Regeln, sondern im Injection-Pfad: `injection/injection_l1`
44 / 54 ms (davon Katalog 30 / 43 ms), `jailbreak/injection_l1` 11 / 13 ms, Katalog
`prompt_extraction` 8 / 15 ms. Die 184 Katalogregeln hängen noch am Text-Gate (`admits`) und
laufen über den ganzen Text; 39 von ihnen haben kein Anker-Gate. Nächster Schritt: denselben
Fenster-Prefilter mit `necessary_words` im Injection-Katalog (`rule_catalog.rs`), danach die
Kandidatenprüfung von `toxic_language` und `harmful_content`.

Qualität: `threat_cascade` (Release) von `main` (`6ebdbd4c`) und diesem Branch über alle 109 632
Zeilen unter `$ARK_L1_DEV_DATA` (`train_dev`, `generated`, `translated`, `report`), mit der
Regel-Konfiguration und mit `cascade-config.json`: 0 abweichende Vorhersagen (Scores, `flagged`,
Kaskadenentscheidung; nur `ms` ausgenommen), je 12 290 markierte Zeilen. Holdout ist in der Sandbox
nicht zugänglich; bei identischen Treffern ändert er sich nicht.

`scripts/benchmark_injection_l1.py` (Injection-Pfad des Gateways über die Python-Bindung, Release,
50 Läufe nach 10 Aufwärmläufen; nur Nachher, zwei Läufe; p50 / p95 ms):

| Größe | gutartig (Lauf 1, 2) | mit eingebettetem Angriff (Lauf 1, 2) |
|---|---:|---:|
| 1 KiB | 0.305 / 0.434, 0.273 / 0.388 | 1.684 / 2.181, 1.655 / 2.011 |
| 10 KiB | 1.161 / 1.753, 1.123 / 1.633 | 4.179 / 5.604, 3.137 / 3.602 |
| 100 KiB | 9.704 / 13.014, 9.575 / 14.098 | 16.805 / 27.244, 17.055 / 23.288 |

Gegen die T38-Zahlen (100 KiB gutartig 9.022 / 12.377, Angriff 16.792 / 22.604) im Rahmen der
Streuung zwischen Läufen; ein Base-Lauf in derselben Sitzung fehlt. Der Injection-Pfad nutzt die
Fenster-Prefilter nicht, zahlt aber den einen Anker-Pass mit Positionen und den zusätzlichen
Wörtern der Threat-Regeln im Automaten; das gehört in der nächsten Runde gegen `main` gemessen.

### T38b Runde 2 (2026-11-28): der Injection-Katalog auf denselben Fenster-Prefilter

Was sich ändert (reine Suchwege, Treffer identisch):

1. **Katalogwörter im einen Pass**: die notwendigen Wörter jeder Regex-Regel der sechs
   Injection-Kataloge (`rule_catalog::rule_words`, dasselbe `necessary_words`) hängen neben denen
   der Threat-Regeln im Anker-Automaten. Jede Katalogregel hat damit einen `prefilter` aus
   Anker-Gate und notwendigen Wörtern; er gatet den ganzen Text und die entschlüsselten Sichten.
2. **Gemeinsame Fenster**: `NativeText::rule_windows` schneidet den Text einmal in die 8-KiB-Fenster
   (4 KiB Überlappung) und hält zu jedem Fenster seine Ankerwörter; Threat-Regeln und Katalog lesen
   dieselbe Liste (vorher rechnete die Threat-Schleife die Fenster und `anchors_within` selbst).
   Ein Text bis 8 KiB ist ein Fenster, also unverändert der ganze Text.
3. **Katalog nur auf erlaubten Fenstern**: eine Katalogregel sucht nur in den Fenstern, deren
   Wörter ihren Prefilter erfüllen (benachbarte zu einem Bereich verbunden). Die Suche läuft auf
   dem Text bis zum Bereichsende ab dem Bereichsanfang, sieht also den Text davor als Kontext
   (Wortgrenzen, Kommentarzeilen, Offsets unverändert); ein Treffer, der genau am Bereichsende vor
   dem Textende endet, bleibt dem überlappenden nächsten Fenster. Test
   `the_window_prefilter_finds_every_catalog_match`: für jede Katalogregel liefert die Fenstersuche
   auf den Goldens (Injection und Threat, je 9 KiB Prosa dazwischen, mit Umlauten, langem s und
   längenändernden Kleinbuchstaben) genau die Treffer (Spannen und Komponenten) der Suche über den
   ganzen Text.

Messung (VPS, wie oben, `threat_profile`, 58 470 gutartige `train_dev`-Zeilen, Regeln allein).
Vorher = Runde 1 (`a19c076e`), Nachher = dieser Stand; je zwei Läufe abwechselnd in derselben
Sitzung:

| Größe | Regeln p50 / p95 ms vorher (Lauf 1, 2) | Regeln p50 / p95 ms nachher (Lauf 1, 2) |
|---|---:|---:|
| short (256 B) | 0.926 / 2.778, 0.801 / 2.525 | 0.586 / 2.200, 0.576 / 2.210 |
| 4 KiB | 7.017 / 13.652, 6.638 / 12.291 | 5.864 / 11.987, 5.896 / 10.249 |
| 100 KiB | 126.109 / 149.491, 115.943 / 139.762 | 104.746 / 143.305, 100.541 / 131.926 |

Katalog-Produzenten bei 100 KiB (p50 / p95 ms, Lauf 1 vorher → nachher): `injection`
31.6 / 43.3 → 25.1 / 37.6, `prompt_extraction` 8.3 / 15.2 → 5.9 / 8.6, `jailbreak` 6.5 / 9.8 →
4.7 / 5.6, `exfiltration` 2.1 / 10.1 → 1.1 / 5.1, `memory_poisoning` 2.9 / 4.1 → 2.3 / 2.9.

Warum das Ziel trotzdem weit weg ist: im Injection-Katalog bleiben bei 100 KiB gutartiger Prosa
etwa 22 ms in der Regex-Suche selbst (Teilmessung im Scan: Regex 22 ms, geordnete Relationen
2 ms, entschlüsselte Sichten 5 ms, Entscheidung 1 ms). Die notwendigen Wörter der meisten
Katalogregeln (Verben wie „ignore“, „show“, „vergiss“, Nomen wie „instructions“, „system“) stehen
in fast jedem 8-KiB-Fenster gewöhnlicher Prosa; das Fenster-Gate überspringt deshalb wenig. Dazu
kommen die Threat-Regeln von `toxic_language`, `unsafe_action`, `tool_poisoning`,
`resource_exhaustion` und `exfiltration` (je 3–5 ms) und die übrigen Injection-Detektoren. Weiter
kommt man nur mit einem engeren Prefilter je Regel (mehrere notwendige Wörter in fester Nähe statt
eines Worts je Fenster, Kandidatenstellen statt Fenster) oder mit weniger, zusammengelegten
Katalogregeln; beides ist mehr als eine Runde.

Stand gegen das Ziel (100 KiB p95 ≤ 10 ms, Regeln aller Klassen): 132–143 ms — **nicht erreicht**.

Qualität: `threat_cascade` (Release) von `a19c076e` und diesem Stand über alle 109 632 Zeilen unter
`$ARK_L1_DEV_DATA` (`train_dev`, `generated`, `translated`, `report`), mit der Regel-Konfiguration
und mit `cascade-config.json`: 0 abweichende Vorhersagen (Scores, `flagged`, Kaskade; nur `ms`
ausgenommen), je 12 290 markierte Zeilen. Holdout ist in der Sandbox nicht zugänglich; jede Zeile bis
8 KiB wird über denselben ganzen Text gesucht, längere bekommen dieselben Treffer (Test oben).

`scripts/benchmark_injection_l1.py` (Release, 50 Läufe nach 10 Aufwärmläufen; zwei Läufe; p50 / p95
ms):

| Größe | gutartig (Lauf 1, 2) | mit eingebettetem Angriff (Lauf 1, 2) |
|---|---:|---:|
| 1 KiB | 0.298 / 0.379, 0.230 / 0.331 | 1.879 / 2.920, 1.627 / 2.091 |
| 10 KiB | 1.326 / 1.520, 0.986 / 1.460 | 3.050 / 4.089, 3.168 / 4.577 |
| 100 KiB | 7.797 / 10.489, 7.924 / 12.570 | 12.974 / 16.334, 12.811 / 19.816 |

Gegen Runde 1 (100 KiB gutartig 9.7 / 13.0–14.1, Angriff 16.8–17.1 / 23.3–27.2): schneller, der
Injection-Pfad allein liegt bei 100 KiB gutartig im Median unter 10 ms, im p95 noch darüber.

