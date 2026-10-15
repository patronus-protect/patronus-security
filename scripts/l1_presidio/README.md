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
- Presidio-Entitäten ohne Benchmark-ID in `PRESIDIO_OUTPUT_MAP` heißen `presidio.<ENTITY>` und
  werden vom Evaluator ignoriert. Die vollständige Zuordnung steht in
  `research/l1-pii/entity_map.yaml` (siehe unten).

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

## Entity-Mapping

`research/l1-pii/entity_map.yaml` ordnet jede Benchmark-ID die ARK-Labels (`entity_group` in
`pii.rs`), die Presidio-Entitäten der gepinnten Version und die Upstream-Labels der Korpora aus dem
`external_pii`-Manifest zu, jeweils mit Scope:

| Scope | Bedeutung |
|---|---|
| `shared` | ARK und Presidio per Muster; Grundlage für M1 und „keine Entität verliert“ |
| `ark_only` | nur ARK (z. B. BIC, CVV, Mitarbeiter-ID) |
| `presidio_only` | nur Presidio (z. B. URL, PESEL, USt-IdNr.); Kandidaten für A/C-Aufgaben |
| `semantic` | NER-Entitäten (Person, Ort, Organisation, NRP, Datum, Adresse); kein L1-Scope |

`entity_map.py` lädt und prüft die Datei:

```bash
python3 scripts/l1_presidio/entity_map.py check      # pii.rs, Manifest, ARK_OUTPUT_MAP, PRESIDIO_OUTPUT_MAP
~/ark-l1/presidio-venv/bin/python scripts/l1_presidio/entity_map.py check --presidio   # + Presidio-Registry
python3 scripts/l1_presidio/entity_map.py table      # Markdown-Übersicht
```

`check` endet mit Exit 1, wenn ein ARK-Label der Registry fehlt oder veraltet ist, ein Korpus-Label
vom Manifest abweicht oder eine Runner-Map der Tabelle widerspricht. Die Runner-Maps dürfen
Teilmengen bleiben, damit sich Vorhersagen bestehender Korpora nicht ändern; das Scoreboard (E06)
soll die Scopes aus `entity_map.yaml` lesen. Neue ARK-Labels brauchen einen Eintrag, sonst ist
`scripts/tests/test_l1_entity_map.py` rot.

## Korpora und Dev/Holdout-Split

`prepare_corpora.py` lädt Gretel Finance (alle sechs Test-Shards), OpenPII Nano und TAB (ECHR-Test)
in den Revisionen des `external_pii`-Manifests, prüft jede Datei gegen ihr SHA-256, normalisiert mit
`external_pii_eval` und teilt gruppenweise: Eine Gruppe (Gretel `expanded_type`, sonst das Dokument)
geht in den Holdout, wenn `sha256(seed:corpus:group)` unter dem Anteil 0,6 liegt. Seed
(`ark-l1-e04-split-v1`) und Anteil sind Konstanten; der Split hängt nur von den gepinnten Quellen ab.

```bash
python3 scripts/l1_presidio/prepare_corpora.py --dev-out DIR --holdout-out DIR   # [--sources DIR] [--offline]
python3 scripts/l1_presidio/prepare_corpora.py --check DIR
```

Jedes Zielverzeichnis enthält `<corpus>.jsonl` (Eingabe für `run_presidio.py`, `run_ark.py` und
`external_pii_eval evaluate`), `manifest.json` (Quellen mit URL und SHA-256, Zeilen, Gruppen,
Sprachen, Entitäten, SHA-256 jeder Datei) und zuletzt `.ready` mit dem SHA-256 des Manifests. Ein
Verzeichnis mit `.ready` ist eingefroren: Ein neuer Lauf muss es Byte für Byte reproduzieren, sonst
schreibt er nichts und endet mit Exit 1 (`--force` ersetzt es). Rohdaten landen im Cache
`--sources` (Standard `HOLDOUT/.sources`), nie im Dev-Verzeichnis; stdout nennt nur Dev-Zahlen.

Das Gate führt den Lauf einmal außerhalb der Agent-Sandbox aus (`~/ark-l1/data/dev`,
`~/ark-l1/holdout`); Agenten sehen nur Dev unter `$ARK_L1_DEV_DATA`. Nur Standardbibliothek:
Die Gretel-Parquet-Dateien liest ein minimaler Reader im Skript (Snappy, Dictionary/Plain,
Page v1/v2), weil das Presidio-Venv kein pyarrow hat. Er ist gegen pyarrow auf den gepinnten Shards
geprüft (`ARK_L1_CORPUS_SOURCES=<--sources> pytest scripts/tests/test_l1_prepare_corpora.py`);
die synthetischen Test-Shards erzeugt `scripts/fixtures/l1_corpora/make_gretel_fixture.py`.

## Synthetisches DE/EU-Goldset

`synth_goldset.py` erzeugt ein synthetisches Goldset mit sieben Dokumenttypen (Brief, Formular,
Rechnung, Arztbrief, JSON, CSV, Support-Ticket) auf Deutsch und Englisch. Es deckt jede Benchmark-ID
aus `entity_map.yaml` ab, über alle vier Scopes (je Split und Sprache mindestens 5 Spans). Werte
mit Prüfziffer sind gültig erzeugt: IBAN, Luhn, Steuer-ID, USt-IdNr., KVNR, RVNR, LANR,
ICAO-Prüfziffer, Codice Fiscale, PESEL, Aadhaar und weitere. Keiner von ihnen fällt durch einen
Presidio-Validator. Gedruckte Formen, die Presidios Regexe nicht kennen (Steuer-ID in Gruppen,
RVNR mit Leerzeichen, `IT`-Präfix, Thai-ID mit Bindestrichen), sind Absicht. Positive meiden
reservierte Platzhalter (RFC-2606/6761-Domains, NANP 555-01xx, Dokumentations-IPs). Nach der
Gold-Konvention aus T01 ([`research/l1-pii/README.md`](../../research/l1-pii/README.md)) wären sie
positiv; das Goldset bleibt eingefroren und führt sie auch nicht als Hard Negative.

```bash
python3 scripts/l1_presidio/synth_goldset.py --dev-out DIR                       # öffentlicher Dev-Seed
python3 scripts/l1_presidio/synth_goldset.py --dev-out DIR --holdout-out DIR     # [--holdout-seed-file F] [--force]
python3 scripts/l1_presidio/synth_goldset.py --check DIR
```

Zeilen folgen dem `external_pii_eval`-Schema (`entities` mit `start`/`end` in Code-Points, Korpus
`ark-synthetic-de-eu`, eine Gruppe je Dokument). Dazu kommen zwei Felder:

- `doc_type`: der Dokumenttyp.
- `hard_negatives`: Spans von Doppelgängern, die kein Detektor melden darf, z. B. Rechnungs-,
  Bestell- und Ticketnummern, Beträge, ICD-10, PZN, Versionen, UUIDs, Commit-Hashes,
  Gläubiger-IDs und Werte mit falscher Prüfziffer.

Die Zeilen sind direkt Eingabe für `run_presidio.py`, `run_ark.py` und `external_pii_eval evaluate`.

Dev und Holdout haben getrennte Seeds:

- **Dev:** Der Seed `DEV_SEED` ist öffentlich.
- **Holdout:** Der Seed ist geheim und steht in einer Datei (Standard `HOLDOUT/.seed`, Modus 0600).
  Fehlt sie, wird sie beim ersten Lauf aus `secrets` angelegt. Das Holdout-Manifest nennt nur ihren
  SHA-256.

Die Erzeugung hängt nur von Seed, Split und `GENERATOR_VERSION` ab. Ein SHA-256-Zählerstrom ersetzt
`random`, das Ergebnis hängt also nicht von der Python-Version ab. Der Test pinnt die Dev-Ausgabe je
Generator-Version.

Ausgabeverzeichnisse werden wie bei `prepare_corpora.py` eingefroren
(`ark-synthetic-de-eu.jsonl`, `manifest.json`, `.ready`). Ein neuer Lauf muss sie Byte für Byte
reproduzieren, sonst endet er mit Exit 1; `--force` ersetzt sie. Das Gate erzeugt beide Splits
einmalig nach `~/ark-l1/data/dev/synthetic` und `~/ark-l1/holdout/synthetic`, solange dort noch kein
`.ready` liegt. Später ändert ein Agent-Branch den eingefrorenen Holdout also nicht mehr. Ein neu
eingefrorener Holdout nach einer Generator-Änderung ist ein bewusster Handgriff (`--force`).

Tests: `scripts/tests/test_l1_synth_goldset.py`, `scripts/tests/test_l1_prepare_corpora.py`, `scripts/tests/test_l1_presidio_runner.py`, `scripts/tests/test_l1_ark_runner.py`,
`scripts/tests/test_l1_entity_map.py`. Die Tests gegen echtes Presidio laufen nur,
wenn `presidio_analyzer` installiert ist (z. B. in `~/ark-l1/presidio-venv`).
