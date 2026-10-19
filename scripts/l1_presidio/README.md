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
liest die Scopes aus `entity_map.yaml`. Neue ARK-Labels brauchen einen Eintrag, sonst ist
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
`~/ark-l1/holdout`); Agenten sehen nur Dev unter `$ARK_L1_DEV_DATA`.

### Familie `presidio_favored` (E12)

`--family presidio_favored` teilt zwei Quellen, die Presidio begünstigen (Fairness-Regel in
[`research/l1-pii/README.md`](../../research/l1-pii/README.md)), in eigene Verzeichnisse:

```bash
python3 scripts/l1_presidio/prepare_corpora.py --family presidio_favored \
  --dev-out DEV/presidio_favored --holdout-out HOLDOUT/presidio_favored   # [--sources DIR] [--offline]
```

| Korpus | Quelle | Zeilen |
|---|---|---|
| `presidio-evaluator-synth-v2` | `data/synth_dataset_v2.json` aus microsoft/presidio-research (MIT, Commit `7f568b6da8a5`) | 1500 synthetische englische Sätze; Gruppe = `template_id`; `TITLE`, `AGE`, `ZIP_CODE` haben keine Benchmark-ID, `DOMAIN_NAME` zählt als `pii.url` |
| `presidio-analyzer-recognizer-tests` | 74 Testdateien `presidio-analyzer/tests/test_*_recognizer.py` des Release-Tags 2.2.364 (MIT, Commit `779dbd286d5e`) | ein Fall je Zeile; Gruppe = SHA-256 des Texts |

Die Testdateien werden mit `ast` gelesen, nie importiert oder ausgeführt. Ein parametrisierter Test
liefert Fälle, wenn sein erstes Argument der analysierte Text ist (`text`, `iban`), er die erwartete
Anzahl (`expected_len`) und/oder Spans (`expected_positions`, `expected_position`, `expected_res`,
`expected_start`/`expected_end`) nennt, keine weiteren Aufruf-Parameter hat (z. B. `leniency`,
`deny_list`, `entity_num`) und nur den ohne Argumente gebauten Recognizer-Fixture der Datei nutzt
(Ausnahme, von Hand geprüft: `PhoneRecognizer` mit Standardregionen plus JP/CN). Werte müssen
Literale sein, auch Modulkonstanten und f-Strings daraus; berechnete Werte (z. B. Verhoeff-Ziffern
per Funktion) entfallen. Ein Positivfall ohne Spans zählt nur, wenn der Text der blanke Wert ist
(`("BO12345678A", 1)`). Die Entität kommt aus dem `entities`-Fixture oder der Spalte `entities`;
Fälle ohne Benchmark-ID (z. B. `DATE_TIME`) entfallen. Zusätzliche Felder je Zeile:

- `scored_entities`: die IDs, auf die der Test prüft. Das Scoreboard wertet die Zeile nur darauf.
- `hard_negatives`: bei Negativfällen (`expected_len` 0) ein Span über den ganzen Text mit
  `entity_type`; nur Vorhersagen dieser ID zählen als Hard-Negative-Treffer.
- `source_test`: `datei::test[index]` upstream.

Gleiche Fälle (Text und IDs) bleiben einmal; widersprechen sich zwei Tests für denselben Text und
dieselben IDs, entfallen beide. Das Manifest beider Splits trägt `"family": "presidio_favored"`;
das Manifest der neutralen Familie bleibt Byte für Byte wie in E04, damit der eingefrorene Split
reproduzierbar bleibt. Das Gate legt die Familie einmalig an (Schritt `presidio-favored-corpora`,
`~/ark-l1/data/dev/presidio_favored`, `~/ark-l1/holdout/presidio_favored`, Rohdaten in
`HOLDOUT/presidio_favored/.sources`). Gegen die echten Quellen prüft
`ARK_L1_CORPUS_SOURCES=<--sources> pytest scripts/tests/test_l1_prepare_corpora.py`. Nur Standardbibliothek:
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

## Scoreboard

`scoreboard.py gate` vergleicht den ARK-Build eines Checkouts mit seinem Basis-Commit auf allen
eingefrorenen Goldsets (Verzeichnisse mit `.ready`: `DIR/*.jsonl`, `DIR/synthetic/*.jsonl`):

```bash
VIRTUAL_ENV=$PWD/.venv python3 scripts/l1_presidio/scoreboard.py gate \
  --head . --base-sha origin/main --dev "$ARK_L1_DEV_DATA" --cache /tmp/scoreboard-cache
# Gate: zusätzlich --holdout ~/ark-l1/holdout, Cache ~/ark-l1/cache
python3 scripts/l1_presidio/scoreboard.py score --gold gold.jsonl --predictions presidio-tuned.jsonl
```

- **Metriken:** P/R/F1 exakt (gleiche ID, Start, Ende) und überlappend (Gold-Span gefunden, wenn
  eine Vorhersage derselben ID ihn überlappt; Vorhersage korrekt, wenn sie Gold derselben ID
  überlappt), je Entität, über alle L1-IDs, je Sprache (`de`, `en`, `other`), Korpus und Scope.
- **Scope:** aus `entity_map.yaml`. `semantic` zählt nicht. Ein Korpus mit Eintrag in der Map wird
  nur auf den IDs gewertet, die er annotiert (Gretel kennt keine Steuer-ID); Korpora ohne Eintrag
  (das synthetische DE/EU-Set) auf allen L1-IDs. ARK-Spans werden über `ark_label` gemappt,
  Presidio-Spans über `presidio_entity`; `ark.<LABEL>` aus `run_ark.py` zählt also mit.
- **Quellfamilien:** jeder Bucket auch je Familie (`family/<familie>`, `family_language/…`,
  `family_entity/…`, `family_language_entity/…`), Familie aus `source_families` in
  `entity_map.yaml`; ein Korpus ohne Familie ist ein Eingabefehler (Exit 2). Zeilen mit
  `scored_entities` (Recognizer-Tests) werden nur auf diesen IDs gewertet.
- **Hard Negatives:** jede L1-Vorhersage, die einen `hard_negatives`-Span überlappt; trägt der Span
  `entity_type`, nur Vorhersagen dieser ID.
- **Regression (Exit 1):** F1-Verlust > 0,5 pp (`--tolerance-pp`), exakt oder überlappend, für eine
  Entität, alle L1-IDs zusammen, eine Quellfamilie, `de` oder `en`, in Dev oder Holdout; oder ein neuer Treffer auf
  einem Hard Negative (gleiche Zeile, ID und Offsets wie in der Basis zählen nicht). Exit 2 =
  Eingabe- oder Infrastrukturfehler (unbekannter Commit, Build fehlgeschlagen, Vorhersagen passen
  nicht zum Gold).
- **Ausgabe:** stdout endet mit einer Zeile je Split (F1 exakt/überlappend gesamt, DE, EN, Δ zur
  Basis, Hard-Negative-FP) und darunter je Quellfamilie (gesamt, EN; `ark_authored` mit dem Hinweis,
  dass es keinen Meilenstein entscheidet), den Regressionen und `RESULT: PASS|REGRESSION`. Eine Tabelle je
  Entität gibt es nur für Dev; vom Holdout erscheinen nur Aggregate und Regressionen, nie
  Zeilen-IDs oder Text. `--json` schreibt den vollständigen Bericht (mit Holdout-Zeilen-IDs).
- **Head:** `run_ark.py` des Checkouts mit `--ark-python` (Standard `$VIRTUAL_ENV/bin/python`).
  Der Interpreter muss `patronus_ark` aus `HEAD/python` importieren (`maturin develop`), sonst
  Exit 2. Nach Rust-Änderungen also erst neu bauen.
- **Basis:** `git archive` des Commits, `cargo build --offline --locked --lib` des Python-Crates
  in den Cache (`CACHE/scoreboard/target`, inkrementell), Paket samt nativem Modul unter
  `CACHE/scoreboard/builds/<key>/`, Lauf mit `PYTHONPATH` auf diese Stufe. Geprüft wird, dass
  `run_ark.py` genau dieses Modul geladen hat.
- **Cache:** Vorhersagen liegen unter `CACHE/scoreboard/predictions/<source-key>/<sha256 der
  Eingabe>.jsonl`. Der Source-Key hasht die Git-Objekte von `Cargo.toml`, `Cargo.lock`,
  `rust-toolchain.toml`, `rust/`, `python/` und `run_ark.py`. Die Basis eines Stack-Laufs (der
  Done-Commit des vorigen Laufs) hat denselben Key wie der zuvor gegatete Head und wird nicht neu
  gebaut; ändert ein Lauf nur Skripte oder Doku, sind Head und Basis identisch. Ergebnisse je
  Commit: `CACHE/scoreboard/results/<sha>.json`. Ein Head mit uncommitteten Änderungen an diesen
  Pfaden wird gerechnet, aber nicht gecacht.

### M1 je Quellfamilie

`m1` vergleicht ARK- und Presidio-Vorhersagen, die unter denselben relativen Dateinamen wie das Gold
liegen (`run_ark.py` bzw. `run_presidio.py --profile tuned` je Datei):

```bash
python3 scripts/l1_presidio/scoreboard.py m1 --gold "$ARK_L1_DEV_DATA" \
  --ark /tmp/ark --presidio /tmp/presidio-tuned   # [--language en|de|all] [--metric exact|overlap] [--check] [--json F]
```

Je Familie und gemeinsamer (`shared`) Entität mit Gold in der Familie: F1(ARK) ≥ F1(Presidio)?
Standard: englische Zeilen, exakte Spans. Eine Familie hält, wenn das für jede solche Entität gilt
und es mindestens eine gibt; `M1: MET` nur, wenn `neutral` und `presidio_favored` je für sich
halten. `ark_authored` wird gedruckt, entscheidet aber nicht. `--check` endet mit Exit 1, wenn M1
nicht erfüllt ist; fehlende Vorhersagedateien sind Exit 2.

### Baseline-Bericht

`report` rechnet beliebig viele Engines auf denselben Gold-Dateien und schreibt Markdown-Tabellen
nach stdout (Grundlage von [`research/l1-pii/scoreboard/baseline.md`](../../research/l1-pii/scoreboard/baseline.md), E11):

```bash
python3 scripts/l1_presidio/scoreboard.py report --gold DEV \
  --engine ark=/tmp/ark --engine presidio-default=/tmp/presidio-default \
  --engine presidio-tuned=/tmp/presidio-tuned   # [--json F]
```

- je Quellfamilie und Engine: Zeilen, Gold, Vorhersagen, exakt P/R/F1, überlappend F1, EN- und
  DE-F1, Hard-Negative-Treffer (der Familie ihrer Zeile zugeordnet);
- je Korpus exakt P/R/F1 je Engine, je Familie und Entität mit Gold exakt F1 je Engine, jeweils
  bestes F1 fett;
- M1 der ersten Engine (ARK) gegen jede weitere: je Familie gehaltene gemeinsame IDs und die
  Entitäten darunter.

Die erste Engine ist immer ARK; mindestens zwei Engines, eindeutige Namen, fehlende
Vorhersagedateien sind Exit 2.

Im Gate (`ark-l1 gate`) läuft der Schritt mit dem Presidio-Venv, ohne Netz, mit Lesezugriff auf
Holdout und Checkout und Schreibzugriff nur auf den Cache; `VIRTUAL_ENV` zeigt auf das Gate-Venv,
in das der Schritt `python-ext` den Head installiert hat.

## Latenz

`latency.py` misst ARK PII-L1 und Presidio auf derselben Maschine und denselben festen Eingaben:
ein kurzer Satz sowie genau 4096 und genau 102400 UTF-8-Bytes Geschäftsprosa, je DE und EN, mit
PII in zwei von drei Absätzen (`WORKLOAD_VERSION`, im Test per SHA-256 gepinnt). Jede Engine läuft
in einem eigenen Prozess, ein Aufruf je Sample, nach Warmup:

| Engine | Messung |
|---|---|
| `ark` | Python-Bindings (`SecurityGateway(categories=["pii"], max_level="l1")`) eines Release-Builds des Checkouts, den `run` selbst baut und per `PYTHONPATH` lädt; Debug-Builds (ELF `.debug_*`) brechen mit Exit 2 ab |
| `ark-native` | Rust-Gateway über `rust/dev/l1_latency_workloads.rs` (`cargo build --release --example l1_latency_workloads`) |
| `presidio-default`, `presidio-tuned` | `run_presidio.py`-Profile im Presidio-Venv, Pins wie dort geprüft |

```bash
VIRTUAL_ENV=$PWD/.venv python3 scripts/l1_presidio/latency.py run \
  --presidio-python ~/ark-l1/presidio-venv/bin/python \
  --output latency.json --markdown latency.md [--engines ark ark-native] [--check-m4]
python3 scripts/l1_presidio/latency.py compare --base base.json --head head.json   # [--sizes …] [--tolerance-pct 10]
```

- **Samples:** 500 (kurz), 200 (4 KiB), 50 (100 KiB) je Sprache, `--samples-scale` skaliert. Nach
  10 Samples endet eine Eingabe, sobald `--budget-s` (60 s) verbraucht ist; Presidio braucht für
  100 KiB rund 10 s je Aufruf und kommt dort auf 10 Samples je Sprache.
- **Ausgabe:** p50/p95/p99/Mittel/Max in ms je Eingabe und je Größe (DE + EN gepoolt), Init-Zeit,
  Spans je Eingabe als Plausibilitätsprüfung, Maschine (CPU, nutzbare Kerne), Load vor/nach jeder
  Engine, SHA-256 von Eingaben, nativem Modul bzw. Binary. `--markdown` schreibt die Tabellen.
- **M4:** `m4` prüft jede ARK-Engine auf 100 KiB p95 ≤ 10 ms; `--check-m4` macht daraus Exit 1.
- **Regression:** `compare` vergleicht zwei Berichte derselben Maschine und derselben Eingaben
  (sonst Exit 2) und endet mit Exit 1, wenn das 100-KiB-p95 von `ark` um mehr als 10 % steigt
  (gemeinsame Akzeptanz im Backlog). Im Gate ist der Schritt noch nicht verdrahtet.
- Die L1-Pipeline hat keinen Ergebnis-Cache (nur L3), wiederholte Eingaben messen also den Scan.
  Ergebnis auf der VPS: [`research/l1-pii/scoreboard/latency.md`](../../research/l1-pii/scoreboard/latency.md).

Tests: `scripts/tests/test_l1_scoreboard.py`, `scripts/tests/test_l1_latency.py`, `scripts/tests/test_l1_synth_goldset.py`, `scripts/tests/test_l1_prepare_corpora.py`, `scripts/tests/test_l1_presidio_runner.py`, `scripts/tests/test_l1_ark_runner.py`,
`scripts/tests/test_l1_entity_map.py`. Die Tests gegen echtes Presidio laufen nur,
wenn `presidio_analyzer` installiert ist (z. B. in `~/ark-l1/presidio-venv`).
