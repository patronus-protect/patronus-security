# Presidio-Baseline und ARK-Runner für L1-PII

`run_presidio.py` lässt Microsoft Presidio über normalisiertes Gold-JSONL laufen
(`patronus_ark.external_pii_eval normalize`, Felder `id`, `language`, `text`) und schreibt
Vorhersagen im Format, das `external_pii_eval evaluate --predictions` erwartet: pro `id` eine
Zeile mit `evidence_spans` (`label`, `start_char`, `end_char` in Code-Points, `score`,
`presidio_entity`, `recognizer`). Rohtext wird nicht dupliziert.

```bash
~/ark-l1/presidio-venv/bin/python scripts/l1_presidio/run_presidio.py \
  --profile tuned --input /tmp/gold.jsonl --output /tmp/presidio-tuned.jsonl
cd python && ../.venv/bin/python -m patronus_ark.external_pii_eval evaluate \
  --input /tmp/gold.jsonl --predictions /tmp/presidio-tuned.jsonl
```

## Profile

| Profil | Datei | Inhalt |
|---|---|---|
| `default` | `profiles/default.yaml` | `AnalyzerEngine()` unverändert: `en_core_web_lg`, englische Recognizer, Schwelle 0. Jede Zeile wird als `en` analysiert. |
| `tuned` | `profiles/tuned.yaml` | `en_core_web_lg` + `de_core_news_lg`, alle deutschen Recognizer, deutsche Kontextwörter, DACH-Telefonregionen, Lemma-Kontext-Enhancer mit Suffix-Fenster, Schwelle 0,4. Andere Sprachen als `en`. |

## Reproduzierbarkeit

- `requirements.txt` pinnt die komplette Umgebung (Python 3.12, `pip freeze` inkl. spaCy-Modelle
  per Wheel-URL und SHA-256). Weicht eine installierte Version ab, bricht der Runner mit Exit 2 ab.
- Neben der Ausgabe entsteht `<output>.meta.json` mit SHA-256 von Profil, Eingabe und Ausgabe,
  Paketversionen und der Sprachzuordnung, ohne Zeitstempel. Zwei Läufe sind byte-identisch.
- Presidio-Entitäten ohne Benchmark-ID heißen `presidio.<ENTITY>` und werden vom Evaluator
  ignoriert. Die vollständige Zuordnung folgt in E03 (`research/l1-pii/entity_map.yaml`).

## ARK im selben Format

`run_ark.py` lässt ARK PII-L1 über die Python-Bindings (`SecurityGateway(categories=["pii"],
max_level="l1")`, ohne Downloads) über dasselbe Gold-JSONL laufen. Zeilen tragen wie bei Presidio
`id`, `language` und `evidence_spans`; jeder Span hat `label` (Benchmark-ID), `ark_label`,
`start_char`/`end_char` in Code-Points und `score` (Span-Score der Engine). Meldet mehr als eine
Regel denselben Span, bleibt er einmal mit dem höchsten Score. ARK-Labels ohne Benchmark-ID heißen
`ark.<LABEL>` und werden nicht gewertet.

```bash
.venv/bin/python scripts/l1_presidio/run_ark.py --input /tmp/gold.jsonl --output /tmp/ark.jsonl
cd python && ../.venv/bin/python -m patronus_ark.external_pii_eval evaluate \
  --input /tmp/gold.jsonl --predictions /tmp/ark.jsonl
```

`<output>.meta.json` enthält SHA-256 von Eingabe, Ausgabe und nativem Modul (`build.native_sha256`)
sowie die Paketversion, ohne Zeitstempel. Zwei Läufe auf demselben Build sind byte-identisch.

Tests: `scripts/tests/test_l1_presidio_runner.py`, `scripts/tests/test_l1_ark_runner.py`. Die Tests gegen echtes Presidio laufen nur,
wenn `presidio_analyzer` installiert ist (z. B. in `~/ark-l1/presidio-venv`).
