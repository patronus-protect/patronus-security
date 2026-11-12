# L1-Threat-Messwerkzeuge

## Taxonomie-Prüfung

`taxonomy.py` prüft [`research/l1-threat/taxonomy.yaml`](../../research/l1-threat/taxonomy.yaml), die
Familien je Klasse (Wortklassen-Form, Anker, Pflicht- und Gegenkontext, DE/EN-Beispielformen, Träger,
heutige Regeln, Baseline-Abdeckung, Lücke, Priorität, Backlog-Aufgabe).

```bash
python3 scripts/l1_threat/taxonomy.py check     # Exit 1 bei jedem Problem
python3 scripts/l1_threat/taxonomy.py summary   # Familien und Regeln je Klasse
```

`check` schlägt fehl, wenn
- eine heutige Regel (`ark.injection.*` aus den Injection-Katalogen, der nativen Registry und den nativen
  Struktur-Regeln, `ark.threat.*` aus `rules.json`) nicht oder mehrfach zugeordnet ist (Familie oder
  Übergabe an Shell-Risk unter `handoffs`), oder eine zugeordnete Regel-ID nicht existiert;
- eine `must`-Familie keine Aufgabe nennt oder eine Aufgabe nicht in `backlog.yaml` steht;
- eine Lexikon-ID weder in `ark-core/src/detectors/anchor_lexicons/*.json` steht noch in der Taxonomie als
  geplant deklariert ist (Kern-Lexika oben, Klassen-Lexika unter `lexicons` der Klasse);
- Klassen, Schlüssel, Prioritäten, Träger oder Baselines nicht dem Schema entsprechen.

Tests: `scripts/tests/test_l1_threat_taxonomy.py`.

## Kontext-Lexika

`lexicons.py` prüft die Kontext-Lexika in
[`ark-core/src/detectors/anchor_lexicons/context.json`](../../ark-core/src/detectors/anchor_lexicons/context.json)
(Stützkontext `addressee`, `authority`, `scope`, `secrecy`, `sensitive_path`, `sink`; Gegenkontext
`defensive`, `meta`, `quotation`, `test_code`, `negation_scope`) und schlägt Kandidaten-Terme vor.

```bash
python3 scripts/l1_threat/lexicons.py check                          # Exit 1 bei jedem Problem
python3 scripts/l1_threat/lexicons.py mine TRAIN.jsonl --label 1     # Kandidaten zur Durchsicht
```

Jeder Term trägt unter `origin` seine Herkunft: `ark_existing` (aus einem ARK-Lexikon oder einer Regel),
`oss:<quelle>@<commit>`, `taxonomy`, `mined:<hash des train-splits>` oder `hand`. Term-Syntax: Wörter
klein; `*` am Anfang oder Ende eines Teils öffnet diese Seite (Komposita, Flexion, Genderformen wie
`Nutzer:innen`); Teile mit ` … ` müssen im selben Satz aufeinander folgen (trennbare Verben wie
`leite … weiter`); Terme unter `cased` gelten nur in ihrer Schreibung (`Sie`, `Ihnen`). `mine` ordnet
Wörter und Wortpaare nach gewichteten Log-Odds mit informativem Dirichlet-Prior und liest nur einen
Train-Split: Pfade mit `dev`, `gold`, `golden(s)` oder `holdout` oder ohne `train` werden abgewiesen.
Die Ausgabe ist eine Kandidatenliste; übernommene Terme bekommen `mined:<hash>` als Herkunft.

Tests: `scripts/tests/test_l1_threat_lexicons.py`.

## OSS-Regelinventar

`oss_inventory.py` baut und prüft [`research/l1-threat/oss_rules.yaml`](../../research/l1-threat/oss_rules.yaml),
das Inventar der übernehmbaren Regeln offener Heuristik-Detektoren (ATR, pipelock, Cisco mcp-scanner YARA,
prompt-guard, Vigil, NeMo-YARA, LlamaFirewall-Regex, SkillSpector-YARA, sentinel-ai, citadel). Der Kopf der
Datei (Quellen mit gepinntem Commit, Lizenz, Pfaden, Kategorie-Tabelle, Hinweisen, Default-Familien) wird von
Hand gepflegt; `build` erzeugt `rules` und `counts` aus lokalen Klonen neu. Regelkörper landen nie in der
Datei, nur ein kurzer SHA-256.

```bash
# je Quelle ein Klon <DIR>/<owner>_<repo> auf dem gepinnten Commit
python3 scripts/l1_threat/oss_inventory.py build --src <DIR>
python3 scripts/l1_threat/oss_inventory.py check                       # Exit 1 bei jedem Problem
python3 scripts/l1_threat/oss_inventory.py summary                     # Regeln je Klasse und Sprache
python3 scripts/l1_threat/oss_inventory.py harvest --class exfiltration
```

`check` schlägt fehl bei Schemafehlern, einem Commit, der kein 40-stelliger SHA ist, einer unbekannten Lizenz,
einer geernteten Regel aus einer Quelle ohne MIT/Apache-2.0, einem Regelkörper im Eintrag, unbekannter Klasse
oder Familie (gegen `taxonomy.yaml`), einer geernteten Regel ohne Klasse und Familie, doppelten Regel-IDs und
Zählungen, die nicht zu den Regeln passen.

Tests: `scripts/tests/test_l1_threat_oss_inventory.py`.

## Baseline- und Datensatz-Mapping

`entity_map.py` prüft [`research/l1-threat/entity_map.yaml`](../../research/l1-threat/entity_map.yaml): wie jede
Baseline des Scoreboards auf die elf Klassen zählt (Heuristiken über die Regelzuordnung in `oss_rules.yaml`,
dazu ihre weiteren deterministischen Scanner; ProtectAI v2 und Prompt Guard 2 über ihre Ausgabe-Labels) und je
Datensatz Lizenz, Sprachen, Split, Quellfamilie und die Zuordnung jedes Upstream-Labels zu Klassen, `benign`
oder `out_of_scope` mit Grund.

```bash
python3 scripts/l1_threat/entity_map.py check   # Exit 1 bei jedem Problem
python3 scripts/l1_threat/entity_map.py table   # wer je Klasse und Sprache entscheidet (Markdown)
```

`check` schlägt fehl bei Schemafehlern, einer unbekannten Klasse oder Familie (gegen `taxonomy.yaml`), einer
Baseline, die nicht in der Taxonomie steht (oder umgekehrt), einer heuristischen Baseline ohne Quelle in
`oss_rules.yaml` oder mit einer Regel ohne Klasse, Übergabe oder `out_of_scope`, einer NC- oder GPL-Lizenz
außerhalb von `report_only`, `ark_blind` außerhalb des Holdouts, `ark_authored` im Holdout, unbekannten
`trained_on`-Sätzen, und bei jeder Klasse und Sprache (DE, EN), die weder `neutral`- noch `ark_blind`-Holdout
entscheidet und nicht unter `gaps` steht. `ark_blind` entscheidet nur, wo kein `neutral`-Holdout-Label die
Klasse in der Sprache abdeckt; `decides: false` hält ein Label nur berichtet.

Tests: `scripts/tests/test_l1_threat_entity_map.py`.

## Datensatz-Registry und Korpora

[`datasets.yaml`](datasets.yaml) sagt je Datensatz aus `entity_map.yaml`, wie er geholt und gelesen wird:
Quelle (Hugging Face oder GitHub), gepinnter Commit, Dateien mit SHA-256, Format (`jsonl`, `json`, `csv`,
`parquet` nur mit UTF-8-Spalten), Textfeld, Sprache und Label-Regeln (`field` + `equals`/`at_least`/`below`
→ Upstream-Label der Entity-Map), dazu `commercial` (`true`/`false`/`unknown`; `false` verlangt
`report_only`) und `training: false` für reine Auswertungssätze (MCPTox, AgentHarm). Lizenz, Split,
Quellfamilie und die Bedeutung der Labels stehen nur in der Entity-Map. Die Rolle wird abgeleitet:
`decisive` (Holdout, Familie `neutral`/`ark_blind`), `dev` (`train_dev`), sonst `report`; `commercial: false`
ist immer `report`. Sätze aus ARK selbst (`ark_blind`, `ark_authored`) sind `internal`. Holdout-Rezepte
stehen nie im Repo: Sie sind `pending` und kommen beim Holdout-Setup über `--overlay` aus
`~/ark-threat/holdout`.

```bash
python3 scripts/l1_threat/prepare_corpora.py check     # Exit 1 bei jedem Problem
python3 scripts/l1_threat/prepare_corpora.py list      # Split, Familie, Rolle, Stand je Satz
python3 scripts/l1_threat/prepare_corpora.py prepare --split train_dev --out DIR --sources CACHE [--offline] [--force]
python3 scripts/l1_threat/prepare_corpora.py --overlay HOLDOUT.yaml prepare --split holdout --out DIR --sources CACHE  # nur Setup
python3 scripts/l1_threat/prepare_corpora.py verify DIR
```

`prepare` schreibt je fertigem Satz des Splits `<id>.jsonl` (Text, Sprache, Upstream-Labels, Klassen,
nur berichtete Klassen, Familien, `benign`, Spalte `contamination` je Baseline), `manifest.json` (SHA-256
jeder Quell- und Ausgabedatei, Revision, Rolle, Lizenz, Zähler je Klasse/Sprache, verworfene Zeilen nach
Grund) und zuletzt `.ready`; ein eingefrorenes Verzeichnis wird nur mit `--force` neu geschrieben. Eine
Zeile, die keine Label-Regel trifft, bricht ab. Dedup auf NFKC, Casefold und zusammengefasstem Leerraum:
exakt und MinHash (Zeichen-5-Gramme, 64 Permutationen, 16 Bänder, Jaccard-Schätzung ≥ 0,8) innerhalb
jedes Satzes; der Holdout verwirft jede Zeile, die in einem `train_dev`- oder `report`-Satz vorkommt;
gegen Baseline-Trainingslisten (`trained_on` der Entity-Map) wird nicht verworfen, sondern je Baseline
markiert. Beim Vorbereiten von `train_dev` und `report` wird nie eine Holdout-Quelle gelesen. Braucht
`numpy` und PyYAML; Downloads und Parquet-Leser kommen aus `scripts/l1_presidio/prepare_corpora.py`.

Tests: `scripts/tests/test_l1_threat_prepare_corpora.py`.

## Latenz auf echtem deutschem Text

`latency.py` misst die L1-Latenz von `threat` allein, `injection` allein und allen L1-Kategorien zusammen
(`injection`, `dlp`, `pii`, `threat`, `shell_command` in einer Anfrage) über das native Rust-Gateway
(`rust/dev/l1_latency_workloads.rs`, Release-Build) auf einem Korpus aus echtem deutschem Text.

Korpus: die deutschen Dev-Quellen des DLP-Benign-Dokumentkorpus (`dewiki-dev`, `gesetze-dev`, `wmf-dev-de` aus
[`scripts/l1_dlp/benign_docs_sources.json`](../l1_dlp/benign_docs_sources.json)) und lange deutsche
Wikipedia-Artikel aus [`latency_sources.json`](latency_sources.json) (`dewiki-latency`, keine Seite aus der
DLP-Liste), alle mit gepinnter Revision bzw. Commit, Lizenz (CC BY-SA, Unlicense) und SHA-256. Die Dokumente
werden in Absätze zerlegt; jeder Absatz kommt im ganzen Korpus höchstens einmal vor (NFKC, Groß-/Kleinschreibung
und Leerraum egal). Der Absatzstrom wird in Fenster von genau 102 400 Byte UTF-8 gepackt; der Absatz, der nicht
mehr passt, wird an einer Zeichengrenze abgeschnitten und sein Rest verworfen. Mindestens 50, höchstens 64
Fenster (heute 64 aus rund 17 600 Absätzen). Die Daten liegen nur auf der VPS, nie im Repo.

```bash
python3 scripts/l1_threat/latency.py prepare --out DIR [--sources CACHE] [--offline]   # friert DIR ein (.ready)
python3 scripts/l1_threat/latency.py check DIR                                          # Exit 1 bei jedem Problem
python3 scripts/l1_threat/latency.py run --corpus DIR --output latency.json --markdown latency.md --runs 3
python3 scripts/l1_threat/latency.py compare --base base.json --head head.json [--profile P]  # Exit 1: p95 > +5 %
python3 scripts/l1_dlp/benign_docs.py pin --sources CACHE --list scripts/l1_threat/latency_sources.json --write
```

`run` misst je Fenster 5 Scans nach einem Warmup (`--samples-scale`), p95 über alle Fenster gepoolt; bei
`--runs N` gilt je Profil der Lauf mit dem Median-p95. `--repo` misst einen anderen Checkout mit diesem Skript.
Der Runner (`ark-l1 latency_ab`, Programm `threat`) baut den Korpus einmal unter `cache/threat-latency-de` und
vergleicht Base und Head mit dem Skript der Base, je Profil einzeln (`compare --profile`); ein Profil gilt nur
als regressiert, wenn es in jedem Versuch scheitert, und spätere Versuche messen nur die noch offenen Profile. Ergebnisse: [`research/l1-threat/scoreboard/latency.md`](../../research/l1-threat/scoreboard/latency.md).

Tests: `scripts/tests/test_l1_threat_latency.py`, `scripts/tests/test_runner_threat_latency_ab.py`.
