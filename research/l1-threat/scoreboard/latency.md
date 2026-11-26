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
