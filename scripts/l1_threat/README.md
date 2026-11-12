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
python3 scripts/l1_threat/prepare_corpora.py --dev-out DEV --holdout-out HOLDOUT [--sources CACHE] [--overlay HOLDOUT.yaml] [--offline] [--force]
python3 scripts/l1_threat/prepare_corpora.py verify DIR
```

Das Vorbereiten (Gate-Schritt `prepare-corpora`) schreibt `DEV/train_dev/`, `DEV/report/` und
`HOLDOUT/holdout/`; der Download-Cache liegt in `--sources` (Default `HOLDOUT/.sources`, nie unter DEV),
die Holdout-Rezepte kommen aus `--overlay` (Default `HOLDOUT/datasets.overlay.yaml`, falls vorhanden). Ein
Split ohne fertigen Satz wird nicht geschrieben. Je Split entsteht je fertigem Satz `<id>.jsonl` (Text, Sprache, Upstream-Labels, Klassen,
nur berichtete Klassen, Familien, `benign`, Spalte `contamination` je Baseline), `manifest.json` (SHA-256
jeder Quell- und Ausgabedatei, Revision, Rolle, Lizenz, Zähler je Klasse/Sprache, verworfene Zeilen nach
Grund) und zuletzt `.ready`; ein eingefrorenes Verzeichnis wird nur mit `--force` neu geschrieben, oder
wenn es unversehrt in einem älteren Korpusformat vorliegt und aus denselben Eingaben (Sätze, Revisionen,
Quelldateien, Dedup-Einstellungen, Trainingslisten) entstand. Eine
Zeile, die keine Label-Regel trifft, bricht ab. Dedup auf NFKC, Casefold und zusammengefasstem Leerraum:
exakt und MinHash (Zeichen-5-Gramme, 64 Permutationen, 16 Bänder, Jaccard-Schätzung ≥ 0,8) innerhalb
jedes Satzes; der Holdout verwirft jede Zeile, die in einem `train_dev`- oder `report`-Satz vorkommt;
gegen Baseline-Trainingslisten (`trained_on` der Entity-Map) wird nicht verworfen, sondern je Baseline
markiert. Eine Trainingsquelle, die der Split nicht lesen darf oder kann (ausstehend, intern oder beim
Vorbereiten von `train_dev`/`report` ein Holdout-Satz), steht im Manifest unter `unchecked`; eine Zeile
ohne Treffer ist für diese Baseline dann `null` (unbekannt), nie `false`, und `contamination_unchecked`
zählt solche Zeilen je Satz. Beim Vorbereiten von `train_dev` und `report` wird nie eine Holdout-Quelle gelesen. Braucht
`numpy` und PyYAML; Downloads und Parquet-Leser kommen aus `scripts/l1_presidio/prepare_corpora.py`.

Tests: `scripts/tests/test_l1_threat_prepare_corpora.py`.

## Generatoren und Übersetzungen

`generators.py` leitet aus den eingefrorenen Korpora abgeleitete Sätze ab, jede Angriffszeile mit
sauberem Zwilling bzw. harmlosem Doppelgänger (`twin_of`):

- `carrier_insertion`: eine Angriffszeile des Eingabekorpus in einem Träger (Web, PDF-Text, Ticket,
  Code-Kommentar, RAG-Chunk, Mail), der Zwilling trägt an derselben Stelle einen harmlosen Satz;
- `exfil_lookalikes`: Tool-Ausgabe (JSON, CLI-Log, Datei, MCP-Ergebnis, Suchtreffer) mit einer Anweisung,
  Daten an eine Senke unter `example.invalid` zu schicken, und derselbe Rahmen mit Doppelgänger (Upload-Log,
  Webhook-Konfiguration, Bitte an Menschen), DE und EN nativ;
- `obfuscation_slices`: Angriffs- und Benign-Zeilen unter je einer Verschleierung (`base64`, `hex`,
  `rot13`, `leetspeak`, `zero_width`, `homoglyph`, `spaced`, `unicode_tags`), Slice in `obfuscation`.

Dev und Holdout haben getrennte Seeds und disjunkte Template-Familien (`check_families`). Dev: öffentlicher
Seed, liest `DEV/train_dev` und `DEV/translated`, schreibt `DEV/generated` (`generators_dev_seed`,
`ark_authored`). Holdout: geheimer Seed (Default `HOLDOUT/.generators-seed`, beim ersten Lauf mit 0600
angelegt, im Manifest nur sein SHA-256), liest nur `HOLDOUT/holdout`, schreibt `HOLDOUT/generated`
(`generators_holdout_seed`, `ark_blind`). Jede Zeile trägt `template_family`, `carrier`, `source_id` und
`translated` (nativ vs. übersetzt: Runner-Übersetzungen und der deutsche Teil eines in der Entity-Map
als `translated` markierten Satzes). Ein Obfuscation-Zwilling trägt die Sprache seiner Benign-Quelle. Ausgabe eingefroren wie die Korpora (JSONL je Generator,
`manifest.json`, `.ready`); ein abweichender Lauf schreibt nur mit `--force`.

Übersetzung (`runner_translations_de`): `translate export` zieht je Dev-Satz aus `DEV/train_dev` bis zu
`--per-set` englische Zeilen (Angriff und Benign abwechselnd, nie aus einem Holdout-Korpus) in ein
Arbeitsblatt; der Runner-Agent trägt seine eigene deutsche Übersetzung in `text` ein (kein externer MT-Dienst)
und setzt `checked: true` für jede Zeile mit `check: true` (feste Hash-Stichprobe, 5 %, mindestens 10), nachdem
er sie von Hand gegengelesen hat. `translate ingest` prüft das Blatt (jede Zeile übersetzt, nicht gleich dem
Original, Stichprobe geprüft) und friert `DEV/translated` ein (`translated: true`, `hand_checked`).

```bash
python3 scripts/l1_threat/generators.py generate --dev-out DEV [--holdout-out HOLDOUT] [--holdout-seed-file F] [--force]
python3 scripts/l1_threat/generators.py translate export --dev-out DEV --sheet SHEET.jsonl [--per-set 200]
python3 scripts/l1_threat/generators.py translate ingest --dev-out DEV --sheet SHEET.jsonl [--force]
python3 scripts/l1_threat/generators.py verify DIR
```

Tests: `scripts/tests/test_l1_threat_generators.py`.

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

## Baselines

`run_baselines.py` rechnet die Baselines der Entity-Map auf eingefrorenen Korpora (oder generierten
Verzeichnissen) und gibt je Dokument und Klasse einen Score:

- Heuristik-Zeilen (ATR, pipelock, Cisco mcp-scanner YARA, prompt-guard, LlamaFirewall-Regex, NeMo-YARA,
  Vigil-YARA): Regelkörper aus den Upstream-Klonen auf dem in `oss_rules.yaml` gepinnten Commit, gelesen mit den
  Extraktoren des Inventars; eine Regel zählt für die Klasse, die ihr das Inventar gibt (ohne Klasse, Übergabe
  oder `out_of_scope`: läuft nicht). Score einer Klasse = Zahl der verschiedenen Regeln dieser Klasse, die
  treffen. Regex-Körper laufen mit Python `re`, YARA-Textstrings als Literal, beides ohne Groß-/Kleinschreibung;
  eine Regel trifft, wenn einer ihrer Körper trifft (YARA-Bedingungen und ATR-Operatoren werden nicht
  ausgewertet). Hex-, semantische und inaktive Regeln laufen nicht; Körper, die Python nicht kompiliert, stehen
  in den Metadaten unter `uncompiled`. LlamaFirewall bringt zusätzlich den Hidden-ASCII-Scanner (Unicode-Tags)
  mit; CodeShield braucht eine eigene Toolchain und läuft nicht.
- Referenzzeilen (ProtectAI v2, Prompt Guard 2 86M und 22M): ONNX-Modell unter `--models`
  (`~/ark-threat/baselines/models`) über onnxruntime und `tokenizers`, ohne torch; Score = höchste
  Wahrscheinlichkeit des Angriffslabels über Fenster von 512 Tokens (höchstens 32 je Dokument), für jede
  Klasse, auf die die Entity-Map das Label abbildet. Läuft im Baselines-Venv.

Vorhersagen werden je Korpusdatei und Baseline-Version einmal berechnet und unter
`CACHE/<baseline>/<version>/<satz>-<sha12>.jsonl` (+ `.json` mit Metadaten) abgelegt. Schlüssel: SHA-256 der
Korpusdatei aus dem Manifest und die Baseline-Version (Runner-Version, Upstream-Commit und Hash des Regelsatzes
bzw. Hash der Modelldatei). Eine vorhandene Datei wird nie neu berechnet. `sweep` liest nur den Cache und
sucht je Klasse und Sprache (und `all`) die kleinste Schwelle, deren FPR auf den Benign-Zeilen höchstens die
Ziel-FPR ist (Score 0 meldet nie); dazu TPR, TP, FP und Zählungen. Positiv ist eine Zeile für die Klassen in
`classes` (nur berichtete Klassen zählen nicht), negativ jede `benign`-Zeile.

```bash
python3 scripts/l1_threat/run_baselines.py clone --src SRC                  # Klone auf den gepinnten Commits
python3 scripts/l1_threat/run_baselines.py run --corpus DIR [--corpus DIR ...] --cache CACHE --src SRC [--jobs N]
~/ark-threat/baselines-venv/bin/python scripts/l1_threat/run_baselines.py run --corpus DIR --cache CACHE \
    --models ~/ark-threat/baselines/models [--baseline protectai_v2]
python3 scripts/l1_threat/run_baselines.py sweep --corpus DIR [...] --cache CACHE [--fpr 0.01 0.001] [--output sweep.json]
```

Grenzen: pipelock baut einige Regexe in Go aus Teilstücken zusammen; der Inventar-Extraktor setzt nur die
Literale zusammen, solche Regeln laufen deshalb nur näherungsweise oder gar nicht (`uncompiled`). Die
Heuristik-Zeilen laufen in `--jobs` geforkten Prozessen (etwa 40 s je 3 000 Dokumente bei 5 Kernen); die
Referenzzeilen sind auf langen Texten langsam (ProtectAI v2 rund 1 s je Dokument mit vielen Fenstern).

Tests: `scripts/tests/test_l1_threat_run_baselines.py`.
