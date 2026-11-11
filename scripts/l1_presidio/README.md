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
| `tuned` | `profiles/tuned.yaml` | `en_core_web_lg` + `de_core_news_lg`, alle deutschen Recognizer, jeder ab Werk abgeschaltete englische Recognizer einer `shared`-ID (T32), deutsche Kontextwörter, DACH-Telefonregionen, Lemma-Kontext-Enhancer mit Suffix-Fenster, Schwelle 0,4. Andere Sprachen als `en`. |

`tuned` ist die stärkste faire Presidio-Baseline (T32, entschieden 2026-11-02, Option a): Jeder
Recognizer, den Presidio 2.2.364 mit `enabled: false` ausliefert, läuft, wenn er Englisch oder
Deutsch unterstützt, in der gepinnten Version lädt und seine Entität in `entity_map.yaml` eine
`shared`-ID hat. Neben den UK- und DE-Recognizern sind das US NPI, CA SIN, SG NRIC/FIN, ZA ID,
AU ABN/ACN/TFN/Medicare, IN PAN/Aadhaar/Pass/GSTIN/Voter-ID sowie die UK-, IN- und NG-Kennzeichen.
Aus bleiben die Recognizer von `presidio_only`-IDs (`UsMbiRecognizer`, der in 2.2.364 ohnehin nicht
lädt, UK-Postleitzahl, NG NIN, PH TIN/UMID), solche anderer Sprachen (ES, KR, SE, TH, TR: das Profil
analysiert nur `en` und `de`) und die Modell-Recognizer mit fehlenden Abhängigkeiten
(`HuggingFaceNerRecognizer`, `BasicLangExtractRecognizer`). Geprüft von
`scripts/tests/test_l1_presidio_runner.py` (mit installiertem Presidio gegen dessen
`default_recognizers.yaml`). Wirkung auf Dev: `presidio_favored` exakt F1 tuned 71,3 → 77,6,
`neutral` 40,6 → 40,5, keine Hard-Negative-Treffer; M1 erreichbar 24/24 → 17/24 (Details in
[`research/l1-pii/README.md`](../../research/l1-pii/README.md), Abschnitt T32).

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
`ark.<LABEL>` und werden nicht gewertet. Standard ist der PII-Modus `strict` (jeder Span 1.0);
`--pii-mode balanced|recall` liefert die Modell-Scores (K02) und trägt den Modus als
`engine.pii_mode` in die Metadaten ein. Das Gate rechnet `strict` und `balanced` (T15).
`--gates DATEI` schaltet zusätzlich die `rules` einer Execution-Gates-Datei, etwa die Opt-in-Regeln für
blanke Werte aus [`docs/how-to/pii-bare-formats.gates.json`](../../docs/how-to/pii-bare-formats.gates.json)
(D-BARE); die Metadaten tragen sie als `engine.rules`, ein `pii_mode` in der Datei muss `--pii-mode`
gleichen. So entsteht die ARK-Engine `balanced-bare` der Meilensteine (M-RAW):
`run_ark.py --pii-mode balanced --gates docs/how-to/pii-bare-formats.gates.json …`.

```bash
.venv/bin/python scripts/l1_presidio/run_ark.py --input /tmp/gold.jsonl --output /tmp/ark.jsonl
cd python && ../.venv/bin/python -m patronus_ark.external_pii_eval evaluate \
  --input /tmp/gold.jsonl --predictions /tmp/ark.jsonl
```

`<output>.meta.json` enthält SHA-256 von Eingabe, Ausgabe und nativem Modul (`build.native_sha256`)
sowie die Paketversion, ohne Zeitstempel. Zwei Läufe auf demselben Build sind byte-identisch.

### L1 + L3 `dynamic-pii` (GLiNER)

`--dynamic-pii` ergänzt L1 um die L3-Pipeline `dynamic-pii` (GLiNER, Asset
`patronus-studio/gliner_small-v2.5-edge`, wird bei Bedarf geladen): ein zweites Gateway
`SecurityGateway(categories=["dynamic-pii"], max_level="l3", download_files=True)` scannt jede Zeile
nach L1. Labels und Schwellen: `--dynamic-pii-labels` (Standard `person,organization,location`),
`--dynamic-pii-threshold` (Standard 0,5) und `--dynamic-pii-label-threshold LABEL=X` (wiederholbar).
GLiNER-Spans tragen `dynamic_pii_label` und die Benchmark-ID aus `dynamic_pii` in `entity_map.yaml`;
ein Label ohne ID wird abgelehnt. Die Metadaten nennen Konfiguration, Label-Mapping und Maschine
unter `engine.dynamic_pii`.

`--latency PATH` (auch in `run_presidio.py`) schreibt die Wandzeit jeder Zeile (ARK: L1 plus L3) in
Nanosekunden je Sprache in eine eigene Datei (`ark-l1-row-latency-v1`); Vorhersagen und Metadaten
bleiben byte-identisch. `scoreboard.py ner` liest sie als `<Vorhersage-Stem>.latency.json`.

```bash
.venv/bin/python scripts/l1_presidio/run_ark.py --input gold.jsonl --output ner/gold.jsonl \
  --dynamic-pii --dynamic-pii-label-threshold person=0.8 --latency ner/gold.latency.json
```

Die GLiNER- und L3-Assets rechnen `MatMulInteger` mit U8S8, was auf x86_64 ohne VNNI (AVX2, z. B.
Haswell-VPS) sättigt. Seit #280 schreibt ARK die Gewichte dort beim Laden auf U8U8 um; Messungen auf
dem VPS brauchen einen Build ab diesem Stand (auf dem VPS: F1 wie auf arm64, ±0,3 pp).

`scoreboard.py ner` wertet die semantischen IDs mit `dynamic_pii`-Labels (PERSON, LOCATION,
ORGANIZATION) für ARK L1 + L3 gegen beide Presidio-Profile: rohes Gold, exaktes P/R/F1 je
Quellfamilie, Sprache (EN, DE) und ID sowie p50/p95 je Text aus den Latenzdateien.
`--ignore-inside entity.street_address` liefert die zweite Sicht: Vorhersagen innerhalb einer
annotierten Straßenadresse, die kein gewertetes Gold treffen, fallen für jede Engine gleich weg (das
Gold annotiert die Adresse, nicht die Stadt oder den Namen darin).

```bash
python3 scripts/l1_presidio/scoreboard.py ner --gold GOLD --engine ark-dynamic-pii=NER \
  --engine presidio-default=DEFAULT --engine presidio-tuned=TUNED --json ner.json
```

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

## M3-Zählung

`count_validated.py` zählt die prüfziffervalidierten Entitäten von ARK und Presidio 2.2.364 nach der
Zählregel in [`research/l1-pii/README.md`](../../research/l1-pii/README.md) (je Benchmark-ID und
Land, nur echte Prüfziffern). Grundlage ist der Abschnitt `checksums` in `entity_map.yaml`: jede
Validator-Funktion der `PII_PATTERNS`-Registry und jede Presidio-Entität mit `validate_result`,
eingestuft mit Verfahren oder `null` (nur Format).

```bash
python3 scripts/l1_presidio/count_validated.py count           # Tabelle je Einheit + M3-Zeile
python3 scripts/l1_presidio/count_validated.py count --json
python3 scripts/l1_presidio/count_validated.py check           # Einstufung vollständig?
~/ark-l1/presidio-venv/bin/python scripts/l1_presidio/count_validated.py check --presidio   # + Registry und Pin
```

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

### VAT-Goldsets (GOLD-VAT1, GOLD-VAT2)

Das E05-Goldset ist eingefroren; IDs, die die Entity-Map später bekam, erzeugt es nicht. Für die
USt-IdNr. schreibt derselbe Generator mit `--goldset` zwei eigene Goldsets, je mit eigenem Korpus
(Familie `ark_authored`), eigenem öffentlichem Dev-Seed (`VAT1_DEV_SEED`, `VAT2_DEV_SEED`), eigenem
geheimem Holdout-Seed und eigenem Verzeichnis. `ark-synthetic-de-eu` und das zuerst eingefrorene
`ark-synthetic-vat-1` bleiben dadurch bytegleich. Zusammen erzeugen die drei Goldsets jede ID der
Entity-Map außer `NOT_GENERATED` (DK CPR und NO fødselsnummer aus B-NORD).

| Goldset | Korpus | IDs |
|---|---|---|
| `vat-1` (GOLD-VAT1) | `ark-synthetic-vat-1` | AT, BE, BG, CH, CY, CZ, DK, EE, ES, FI, FR, GR, HR, HU |
| `vat-2` (GOLD-VAT2) | `ark-synthetic-vat-2` | IE, LT, LU, LV, MT, NL, NO, PL, PT, RO, SE, SI, SK, UK |

```bash
python3 scripts/l1_presidio/synth_goldset.py --goldset vat-1 --dev-out DIR --holdout-out DIR
python3 scripts/l1_presidio/synth_goldset.py --goldset vat-2 --dev-out DIR --holdout-out DIR
```

- **Aufbau:** je ID und Sprache (DE, EN) ein Dokument je Träger: Brief (Fließtext, mit und ohne
  Feldnamen), Formular (Schlüssel/Wert), JSON und CSV; je Goldset Dev 112 Zeilen (je Kombination
  eine), Holdout 224 (je Kombination zwei).
- **Positive:** je Dokument zwei prüfziffergültige Nummern in den gedruckten Formen der ARK-Regeln
  (`ATU 12345678`, `BE 0403.019.261`, `CHE-123.456.789`, `DK 13 58 56 28`, `EL…`/`GR…`,
  `NO 995 525 828 MVA`, `PL 856-734-62-15`, `GB 980 7806 84 001`, `XI…`, …), dazu die anderen
  vergebenen Formen: Nummern natürlicher Personen bei BG, CZ, ES, LT (zwölfstellig), NL (btw-id seit
  2020, MOD 97-10), PT und SE (Personnummer), die irische Form mit zweitem Buchstaben und die alte Form
  (`IE8D79739I`), britische Zweigstellen; je Split und ID mindestens 16, je Sprache mindestens 8.
  Firmen, Orte und Bearbeiter sind als `entity.*` annotiert, britische Postleitzahlen als
  `pii.uk.postcode` (wie in E05).
- **Hard Negatives** (`hard_negatives`, ohne `entity_type`, gelten also für jede L1-ID):
  `vat_check_digit` (dieselbe Form mit falschem Prüfzeichen), `vat_length` (eine Stelle kürzer als die
  kürzeste oder länger als die längste vergebene Form; RO nur länger, da CUI ab zwei Stellen gelten) und
  `vat_postcode` (Ländercode mit Postleitzahl, `DK-8000`, `CZ-602 00`, `NL-3011 AB`, `L-4123`, bei
  Malta `SLM 1549`); je Split, ID und Sprache mindestens 4 von jeder Art, beim Vereinigten Königreich
  ohne `vat_postcode`. In `vat-2` nimmt kein Hard Negative zufällig einen Wert an, den eine andere
  L1-Regel meldet (IBAN mit MOD 97, Kartennummer mit Luhn, deutsche Pass- und Ausweisnummer mit
  ICAO-Prüfziffer: `other_l1_value`), und ein falsches NL-Prüfzeichen trifft auch kein MOD 97-10.
- **Prüfung:** `scripts/tests/test_l1_synth_goldset.py` prüft jedes Positiv gegen die Python-Ports
  der Rust-Validatoren (`CHECKSUM_PORTS` in `scoreboard.py`) und jedes Hard Negative dagegen; die
  Dev-Ausgabe ist je Goldset und Generator-Version (`VAT1_GENERATOR_VERSION`,
  `VAT2_GENERATOR_VERSION`) gepinnt.
- **Gate:** Der Runner friert jedes Goldset wie E05 einmalig ein (Schritte `synthetic-goldset-vat-1`
  und `synthetic-goldset-vat-2`, `~/ark-l1/data/dev/synthetic-vat-N`, `~/ark-l1/holdout/synthetic-vat-N`,
  Seed in dessen `.seed`), erst nach Neuinstallation des Runners.

## Scoreboard

`scoreboard.py gate` vergleicht den ARK-Build eines Checkouts mit seinem Basis-Commit auf allen
eingefrorenen Goldsets (Verzeichnisse mit `.ready`: `DIR/*.jsonl`, `DIR/synthetic/*.jsonl`,
`DIR/synthetic-vat-1/*.jsonl`, `DIR/synthetic-vat-2/*.jsonl`), je Seite
in den PII-Modi `strict` und `balanced` (`run_ark.py --pii-mode`, Entscheidung T15 in
[`research/l1-pii/README.md`](../../research/l1-pii/README.md)):

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
- **Modi:** Head und Basis werden je Modus getrennt gewertet und verglichen; ein Build je Seite
  bedient beide Modi. `run_ark.py` muss den Modus in den Metadaten bestätigen (`engine.pii_mode`, bei
  `strict` fehlend), sonst Exit 2: ein Runner, der `--pii-mode` ignoriert, würde `strict` als
  `balanced` ausgeben. Meilensteine liest `m1`/`report` aus `balanced`.
- **Meilensteine im Gate (H05, M-RAW):** Vor der Zeile `RESULT` steht je Split und Meilenstein-Engine
  eine Zeile `milestones <split> (balanced|balanced-bare, raw gold, vs Presidio default and tuned): M1 … |
  M2 …` mit M1 (gehaltene gemeinsame IDs je entscheidender Familie, EN) und M2 (DE-Macro-F1 gegen Ziel)
  des Heads, je Profil (`vs default: …; vs tuned: …`); `MET` heißt, dass diese Engine gegen beide
  Profile hält, der Meilenstein ist erfüllt, wenn eine der beiden Zeilen `MET` zeigt. `balanced-bare`
  läuft als `run_ark.py --pii-mode balanced --gates docs/how-to/pii-bare-formats.gates.json` (die
  Metadaten müssen `engine.rules` tragen) und wird zusätzlich nach dem Inhalt des Profils gecacht.
  Für den Abschlussbericht in der Rohsicht (H05-2) stehen je Split davor eine Zeile `scores <split>
  (raw gold, …)` mit exaktem F1 (alle L1-IDs) und HN-FP-Zahl je Quellfamilie von `strict`,
  `balanced`, `balanced-bare`, `presidio-default` und `presidio-tuned`, danach eine Zeile `M1 gaps
  <split> (…)` mit den gemeinsamen IDs, bei denen eine Meilenstein-Engine unter einem Profil liegt
  (Familie, ID, F1 ARK `<` F1 Presidio; `none`, wenn keine).
  Presidio default und tuned laufen mit dem Interpreter des Gates (`run_presidio.py`, im Gate das Presidio-Venv) und wird je
  Runner, Profil und Eingabe-SHA-256 gecacht. So erreichen die Holdout-Meilensteine den Gate-Bericht
  (der Runner übernimmt das Ende einer grünen Scoreboard-Ausgabe), nur als Aggregat. Scheitert die
  Messung (lokal ohne Presidio im Interpreter), steht `not measured (<Fehlertyp>)` da; der Exit-Code
  ändert sich nie.
- **Regression (Exit 1):** F1-Verlust > 0,5 pp (`--tolerance-pp`), exakt oder überlappend, für eine
  Entität, alle L1-IDs zusammen, eine Quellfamilie, `de` oder `en`, in Dev oder Holdout, in `strict` oder
  `balanced`; oder ein neuer Treffer auf einem Hard Negative in einem der Modi (gleiche Zeile, ID und
  Offsets wie in der Basis zählen nicht). Exit 2 =
  Eingabe- oder Infrastrukturfehler (unbekannter Commit, Build fehlgeschlagen, Vorhersagen passen
  nicht zum Gold).
- **Ausgabe:** stdout endet mit einer Zeile je Modus und Split (`strict dev`, …, `balanced holdout`:
  F1 exakt/überlappend gesamt, DE, EN, Δ zur Basis, Hard-Negative-FP) und darunter je Quellfamilie
  (gesamt, EN; `ark_authored` mit dem Hinweis, dass es keinen Meilenstein entscheidet), den Regressionen
  (mit Modus und Split) und `RESULT: PASS|REGRESSION`. Eine Tabelle je Entität gibt es je Modus nur für
  Dev; vom Holdout erscheinen nur Aggregate und Regressionen, nie Zeilen-IDs oder Text. `--json` schreibt
  den vollständigen Bericht (`modes.<modus>.<split>`, mit Holdout-Zeilen-IDs).
- **Head:** `run_ark.py` des Checkouts mit `--ark-python` (Standard `$VIRTUAL_ENV/bin/python`).
  Der Interpreter muss `patronus_ark` aus `HEAD/python` importieren (`maturin develop`), sonst
  Exit 2. Nach Rust-Änderungen also erst neu bauen.
- **Basis:** `git archive` des Commits, `cargo build --offline --locked --lib` des Python-Crates
  in den Cache (`CACHE/scoreboard/target`, inkrementell), Paket samt nativem Modul unter
  `CACHE/scoreboard/builds/<key>/`, Lauf mit `PYTHONPATH` auf diese Stufe. Geprüft wird, dass
  `run_ark.py` genau dieses Modul geladen hat.
- **Cache:** Vorhersagen liegen unter `CACHE/scoreboard/predictions/<source-key>/<sha256 der
  Eingabe>.jsonl` (`strict`, Layout wie vor T15) bzw. `…/<source-key>/balanced/<sha256>.jsonl`. Der Source-Key hasht die Git-Objekte von `Cargo.toml`, `Cargo.lock`,
  `rust-toolchain.toml`, `rust/`, `python/` und `run_ark.py`. Die Basis eines Stack-Laufs (der
  Done-Commit des vorigen Laufs) hat denselben Key wie der zuvor gegatete Head und wird nicht neu
  gebaut; ändert ein Lauf nur Skripte oder Doku, sind Head und Basis identisch. Ergebnisse je
  Commit und Modus: `CACHE/scoreboard/results/<sha>.json` (`modes.<modus>.<split>`). Ein Head mit uncommitteten Änderungen an diesen
  Pfaden wird gerechnet, aber nicht gecacht.

### Rohe und erreichbare Sicht (M-RAW, T27)

`m1`, `m2` und `report` rechnen zwei Sichten: `raw` (alles Gold, entscheidet seit M-RAW) und
`attainable` (Diagnose). Die erreichbare
Sicht lässt für jede Engine gleich (ARK je Modus, Presidio je Profil) das Gold weg, das keine
Engine unter den geltenden Entscheidungen treffen soll, zusammen mit den Vorhersagen derselben ID,
die es überlappen (kein FN, kein FP; wie `IGNORED_GOLD`):

- Gold-Werte, die jeden Prüfziffer-Validator ihrer ID verfehlen (`row_validators`: IDs, deren Regeln
  alle einen Prüfziffer-Validator tragen, wie im Gold-Lücken-Bericht; Pass und Ausweis nur gegen den
  Validator des Ausstellerlandes, `country` in `checksums.ark`, und nur, wo die Zeile das Land nennt:
  Presidio-Recognizer-Tests `test_<land>_…_recognizer`; ein Pass aus Gretel oder Nano bleibt Gold);
- Gold-Werte unter einer festgehaltenen Entscheidung: `known_gaps` in
  [`entity_map.yaml`](../../research/l1-pii/entity_map.yaml), je Eintrag ID, Entscheidung, Grund und
  Bedingungen (`span`, `bare`, `rows`, `corpora`), geprüft von `entity_map.py check`.

Meilensteine (M1, M2) und die Untergrenze F1 ≥ 80 werden auf `raw` geurteilt, `attainable` steht als
Diagnose daneben (von T27 bis M-RAW war es umgekehrt). `gate` und `score` rechnen nur `raw`; die
Validatoren ändern sich dadurch nicht.

### M1 je Quellfamilie

`m1` vergleicht ARK- und Presidio-Vorhersagen, die unter denselben relativen Dateinamen wie das Gold
liegen (`run_ark.py --pii-mode MODUS [--gates …]` bzw. `run_presidio.py --profile default|tuned` je Datei):

```bash
python3 scripts/l1_presidio/scoreboard.py m1 --gold "$ARK_L1_DEV_DATA" \
  --ark strict=/tmp/ark-strict --ark balanced=/tmp/ark-balanced --ark balanced-bare=/tmp/ark-balanced-bare \
  --presidio default=/tmp/presidio-default --presidio tuned=/tmp/presidio-tuned \
  # [--language en|de|all] [--metric exact|overlap] [--check] [--json F]
```

`--ark ENGINE=DIR` ist wiederholbar (`strict`, `balanced`, `balanced-bare`, `recall`), `balanced` ist
Pflicht; `--presidio PROFIL=DIR` braucht `default` und `tuned`. Jede ARK-Engine wird gegen jedes Profil
gerechnet (`== Ark balanced vs presidio-tuned (milestone pair)`, andere Paare mit „reported, decides no
milestone“). Erst die Sicht `attainable` (`=== attainable gold (diagnostic, decides no milestone)`),
dann `raw` (`=== raw gold (milestone view, M-RAW)`). Die letzte Zeile
`M1: MET|NOT MET (raw gold; balanced: presidio-default holds, presidio-tuned …; balanced-bare: …)` und
`--check` folgen der rohen Sicht: erfüllt, wenn `balanced` oder `balanced-bare` gegen beide Profile hält
(`holding` im JSON nennt die tragende Engine); `--json` schreibt den rohen Bericht mit dem erreichbaren
unter `attainable`.

Je Familie und gemeinsamer (`shared`) Entität mit Gold in der Familie: F1(ARK) ≥ F1(Presidio)?
Standard: englische Zeilen, exakte Spans. Eine Familie hält, wenn das für jede solche Entität gilt
und es mindestens eine gibt; `M1: MET` nur, wenn `neutral` und `presidio_favored` je für sich
halten. `ark_authored` wird gedruckt, entscheidet aber nicht. `--check` endet mit Exit 1, wenn M1
nicht erfüllt ist; fehlende Vorhersagedateien sind Exit 2.

### M2 je Quellfamilie

`m2` liest dieselben Vorhersage-Verzeichnisse wie `m1` und prüft die M2-Regel (D-M2, Entscheidung
2026-10-21):

```bash
python3 scripts/l1_presidio/scoreboard.py m2 --gold "$ARK_L1_DEV_DATA" \
  --ark strict=/tmp/ark-strict --ark balanced=/tmp/ark-balanced --ark balanced-bare=/tmp/ark-balanced-bare \
  --presidio default=/tmp/presidio-default --presidio tuned=/tmp/presidio-tuned \
  # [--language de|en|all] [--metric exact|overlap] [--json F]
```

Je Familie: Macro-F1 = ungewichtetes Mittel des F1 über alle `shared`- und `ark_only`-IDs mit Gold auf
deutschen Zeilen der Familie (exakte Spans; für Presidio zählt eine `ark_only`-ID mit F1 0).
`presidio_only`-IDs mit Gold stehen als `excluded` in der Ausgabe und zählen erst, wenn
`entity_map.yaml` sie `shared` führt (ARK hat dann ein Label dafür); `semantic` zählt nie. `neutral`
hält bei Macro-F1(ARK) ≥ Macro-F1(Presidio) + 15 pp, `presidio_favored` bei Macro-F1(ARK) ≥
Macro-F1(Presidio), jeweils nur mit mindestens einer ID. `ark_authored` wird mit +15 pp gedruckt und
entscheidet nicht. Sichten, Engines und Profile wie bei `m1`; `M2: MET|NOT MET (raw gold; …)` und der
Exit-Code folgen der rohen Sicht: Exit 1, solange nicht `balanced` oder `balanced-bare` gegen beide
Profile auf beiden Familien hält (ohne Schalter), fehlende Vorhersagedateien sind Exit 2.

### Baseline-Bericht

`report` rechnet ARK je Engine und Presidio je Profil auf denselben Gold-Dateien und schreibt
Markdown-Tabellen nach stdout (Grundlage von [`research/l1-pii/scoreboard/baseline.md`](../../research/l1-pii/scoreboard/baseline.md), E11):

```bash
python3 scripts/l1_presidio/scoreboard.py report --gold DEV \
  --ark strict=/tmp/ark-strict --ark balanced=/tmp/ark-balanced --ark balanced-bare=/tmp/ark-balanced-bare \
  --presidio default=/tmp/presidio-default --presidio tuned=/tmp/presidio-tuned   # [--json F]
```

- je Quellfamilie und Engine: Zeilen, Gold, Vorhersagen, exakt P/R/F1, überlappend F1, EN- und
  DE-F1, Hard-Negative-Treffer (der Familie ihrer Zeile zugeordnet);
- je Korpus exakt P/R/F1 je Engine, je Familie und Entität mit Gold exakt F1 je Engine, jeweils
  bestes F1 fett (rohes Gold, dort gilt die Untergrenze F1 ≥ 80, M-RAW); die Entitätstabelle
  zusätzlich auf erreichbarem Gold als Diagnose (T27);
- M1 und M2 je Sicht, erst `raw` (entscheidet), dann `attainable`, je mit dem Urteil als fetter Zeile:
- M1 jeder ARK-Engine gegen jedes Profil: je Familie gehaltene gemeinsame IDs und die Entitäten
  darunter; `balanced` und `balanced-bare` zuerst, weitere Engines mit „²“ (entscheiden nicht);
- M2 jeder ARK-Engine gegen jedes Profil: je Familie Macro-F1 von ARK gegen das Ziel (Presidio + Marge)
  und die Zahl der IDs, Regel wie bei `m2`;
- Gold-Lücken je Korpus und Entität (T16), nur berichtet: Vorhersagen, die unter exakter Wertung FP
  sind und deren Wert einem annotierten Gold-Wert derselben ID an anderer Stelle der Zeile gleicht
  (Vergleich ohne umgebende Klammern, Anführungszeichen, Satzzeichen und `mailto:`, eine Überlappung mit
  diesem Gold-Span ist ein Grenzfehler und zählt nicht), sowie Gold-Werte, die jeden
  Prüfziffer-Validator ihrer ID verfehlen, mit der Zahl, die jede Engine exakt meldet. Die Validatoren je
  ID kommen aus der `PII_PATTERNS`-Registry und `checksums.ark` (wie bei `count_validated.py`), gerechnet
  wird mit den Python-Ports in `CHECKSUM_PORTS`. Geprüft werden nur IDs, deren Regeln alle einen
  Prüfziffer-Validator tragen (T31): hat eine ID daneben Format- oder Kontextregeln (heute
  `entity.passport_number`, `pii.identity_card_number`, `pii.financial_account_number`,
  `pii.crypto_wallet`, `pii.vin`), sagt ein verfehlter Validator nichts über den Gold-Wert, und ihre
  Spalten zeigen „–“ wie bei IDs ohne Validator. Ausnahme (T27): Pass und Ausweis werden gegen den
  Validator ihres Ausstellerlandes geprüft, wo die Zeile das Land nennt (Spalte „de: …“). Dazu je Korpus
  und Entität die Zahl der Gold-Werte unter einer `known_gaps`-Entscheidung. Rohe Metriken und Gate
  bleiben unverändert.

Engines heißen `ark-<engine>` und `presidio-<profil>`; `--ark balanced=DIR`, `--presidio default=DIR`
und `--presidio tuned=DIR` sind Pflicht, Namen eindeutig, fehlende Vorhersagedateien sind Exit 2.

### Zahlen der Capabilities-Seite

[`docs/reference/l1-capabilities.md`](../../docs/reference/l1-capabilities.md) liest die Gesamt- und
die Je-Entität-Tabelle von [`research/l1-pii/scoreboard/final-raw.md`](../../research/l1-pii/scoreboard/final-raw.md)
und die Tool- und Gruppentabelle von [`research/dlp/scoreboard/final.md`](../../research/dlp/scoreboard/final.md)
(`scripts/l1_capabilities_doc.py`); Latenz und NER-Ergebnisse stehen dort als Text. Die
Snapshots in `research/scoreboard/` sind Verlauf und speisen die Seite nicht mehr.

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
  --output latency.json --markdown latency.md [--engines ark ark-native] [--runs 5] [--check-m4]
python3 scripts/l1_presidio/latency.py compare --base base.json --head head.json   # [--sizes …] [--tolerance-pct 10]
```

- **Samples:** 500 (kurz), 200 (4 KiB), 50 (100 KiB) je Sprache, `--samples-scale` skaliert. Nach
  10 Samples endet eine Eingabe, sobald `--budget-s` (60 s) verbraucht ist; Presidio braucht für
  100 KiB rund 10 s je Aufruf und kommt dort auf 10 Samples je Sprache.
- **Ausgabe:** p50/p95/p99/Mittel/Max in ms je Eingabe und je Größe (DE + EN gepoolt), Init-Zeit,
  Spans je Eingabe als Plausibilitätsprüfung, Maschine (CPU, nutzbare Kerne), Load vor/nach jeder
  Engine, SHA-256 von Eingaben, nativem Modul bzw. Binary. `--markdown` schreibt die Tabellen.
- **Läufe:** `--runs N` (Standard 1) misst jede Engine N-mal im Wechsel mit einem Build; je Engine
  bleibt die Zeile des Laufs mit dem mittleren 100-KiB-p95 (bei geradem N der untere), `runs_p95_ms`
  hält das 100-KiB-p95 jedes Laufs.
- **M4** (Entscheidung T40): `m4` nimmt je ARK-Engine den Median der 100-KiB-p95 über die Läufe; M4
  hält, wenn er für `ark-native` ≤ 12 ms ist und mindestens fünf Läufe vorliegen. `ark`
  (Python-Bindings) steht daneben, entscheidet aber nicht. `--check-m4` macht aus „nicht erfüllt“
  Exit 1, also auch bei weniger als fünf Läufen.
- **Regression:** `compare` vergleicht zwei Berichte derselben Maschine und derselben Eingaben
  (sonst Exit 2) und endet mit Exit 1, wenn das 100-KiB-p95 von `ark` um mehr als 10 % steigt
  (gemeinsame Akzeptanz im Backlog). Im Gate ist der Schritt noch nicht verdrahtet.
- Die L1-Pipeline hat keinen Ergebnis-Cache (nur L3), wiederholte Eingaben messen also den Scan.
  Ergebnis auf der VPS: [`research/l1-pii/scoreboard/latency.md`](../../research/l1-pii/scoreboard/latency.md).

Tests: `scripts/tests/test_l1_scoreboard.py`, `scripts/tests/test_l1_latency.py`, `scripts/tests/test_l1_synth_goldset.py`, `scripts/tests/test_l1_prepare_corpora.py`, `scripts/tests/test_l1_presidio_runner.py`, `scripts/tests/test_l1_ark_runner.py`,
`scripts/tests/test_l1_entity_map.py`, `scripts/tests/test_l1_count_validated.py`. Die Tests gegen echtes Presidio laufen nur,
wenn `presidio_analyzer` installiert ist (z. B. in `~/ark-l1/presidio-venv`).
