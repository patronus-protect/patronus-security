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
