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
