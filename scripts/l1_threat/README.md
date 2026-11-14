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
`parquet` mit UTF-8- und einfachen Ganzzahl-Spalten), Textfeld, Sprache und Label-Regeln (`field` + `equals`/`at_least`/`below`
→ Upstream-Label der Entity-Map), optional Cue-Filter (`keep`: eine Zeile mit dem Upstream-Label `label` bleibt nur,
wenn der Regex `pattern` ohne Groß-/Kleinschreibung im Text trifft; `reason` nennt den Grund, das Manifest zählt
die übrigen unter `dropped.no_cue`), dazu `commercial` (`true`/`false`/`unknown`; `false` verlangt
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
python3 scripts/l1_threat/prepare_corpora.py coverage DIR [DIR ...]   # Exit 1, wenn der Pool eines Splits unvollständig ist
```

Das Vorbereiten (Gate-Schritt `prepare-corpora`) schreibt `DEV/train_dev/`, `DEV/report/` und
`HOLDOUT/holdout/`; der Download-Cache liegt in `--sources` (Default `HOLDOUT/.sources`, nie unter DEV),
die Holdout-Rezepte kommen aus `--overlay` (Default `HOLDOUT/datasets.overlay.yaml`, falls vorhanden). Ein
Split ohne fertigen Satz wird nicht geschrieben. Je Split entsteht je fertigem Satz `<id>.jsonl` (Text, Sprache, Upstream-Labels, Klassen,
nur berichtete Klassen, Familien, `benign`, Spalte `contamination` je Baseline), `manifest.json` (SHA-256
jeder Quell- und Ausgabedatei, Revision, Rolle, Lizenz, Zähler je Klasse/Sprache, verworfene Zeilen nach
Grund) und zuletzt `.ready`; ein eingefrorenes Verzeichnis wird nur mit `--force` neu geschrieben, wenn
`generation` in `datasets.yaml` höher ist als im eingefrorenen Manifest (der geprüfte Weg, alle Splits neu
einzufrieren, etwa nach neuen Sätzen oder Zeilengrenzen; nie zurück auf eine niedrigere), oder
wenn es unversehrt in einem älteren Korpusformat vorliegt und aus denselben Eingaben (Sätze, Revisionen,
Quelldateien, Dedup-Einstellungen, Trainingslisten) entstand. Eine
Zeile, die keine Label-Regel trifft, bricht ab. Nach dem Dedup behält jeder Satz höchstens
`sampling.max_rows` Zeilen (15 000; ein Satz kann mit `cap` weniger verlangen): geschichtet nach
(`benign`, Klassen, Sprache), jede Schicht behält eine Zeile, solange die Grenze reicht, der Rest geht
anteilig an die Schichten (größter Rest), innerhalb einer Schicht entscheidet ein Hash aus Seed
(`sampling.seed`), Satz und Text. Grenze und Seed stehen im Manifest (`sampling`, je Satz `cap`,
`rows_before_cap`, `dropped.cap`; `rows_before_cap` zählt auch Zeilen, die der Holdout danach
satzübergreifend verwirft). Die Grenze kürzt nur die geschriebenen Korpora: der Kontaminationsabgleich
liest die Trainingsquellen einer Baseline ungekürzt. Dedup auf NFKC, Casefold und zusammengefasstem Leerraum:
exakt und MinHash (Zeichen-5-Gramme, 64 Permutationen, 16 Bänder, Jaccard-Schätzung ≥ 0,8) innerhalb
jedes Satzes; der Holdout verwirft jede Zeile, die in einem `train_dev`- oder `report`-Satz vorkommt;
gegen Baseline-Trainingslisten (`trained_on` der Entity-Map) wird nicht verworfen, sondern je Baseline
markiert. Eine Trainingsquelle, die der Split nicht lesen darf oder kann (ausstehend, intern oder beim
Vorbereiten von `train_dev`/`report` allein ein Holdout-Satz), steht im Manifest unter `unchecked`; eine Zeile
ohne Treffer ist für diese Baseline dann `null` (unbekannt), nie `false`, und `contamination_unchecked`
zählt solche Zeilen je Satz. Der Gate-Aufruf mit `--dev-out` und `--holdout-out` bereitet alle Splits vor
und vergleicht dabei auch `train_dev`- und `report`-Zeilen mit Holdout-Trainingsquellen (XSTest für
ProtectAI v2); in die Dev-Ausgabe gelangt nur das Flag, nie eine Holdout-Zeile. Wer nur einen Split
vorbereitet, liest für `train_dev` und `report` keine Holdout-Quelle.

`coverage` prüft den Pool eines Splits (vorbereitete und generierte Verzeichnisse zusammen, z. B.
`DEV/train_dev DEV/report DEV/generated DEV/translated`): Zeilen für jede Klasse aus `taxonomy.yaml`
(Quelle je Klasse als `native` oder `synthetic`), ein Benign-Pool von mindestens 30 000 Zeilen aus
mindestens drei Sätzen und keine Zeile mit unbekannter Kontamination. Braucht
`numpy` und PyYAML; Downloads und Parquet-Leser kommen aus `scripts/l1_presidio/prepare_corpora.py`.

Tests: `scripts/tests/test_l1_threat_prepare_corpora.py`.

## Gold-Validierung

`gold.py` prüft das Gold eines Splits (vorbereitete und generierte Verzeichnisse zusammen) und schreibt
[`research/l1-threat/scoreboard/gold.md`](../../research/l1-threat/scoreboard/gold.md):

- `sample`: feste Hash-Stichprobe von mindestens 50 Zeilen je Satz (kleinere Sätze ganz), geschichtet nach
  Label (`benign` oder Klassenkombination), als Prüfblatt; je Zeile setzt der Prüfer `verdict` auf `ok`,
  `wrong` oder `unclear` und eine kurze Notiz.
- `summary`: prüft das Blatt gegen den Pool (jede Zeile beurteilt, Label unverändert, genug Zeilen je Satz) und
  schreibt nur Zahlen: Zeilen je Klasse und Sprache, Herkunft je Klasse (`native`, `translated`,
  `synthetic`), Fehlerquote je Satz (`wrong` + `unclear`) und die der Benign-Zeilen. Nur die Dev-Zusammenfassung
  nennt die markierten Zeilen-IDs; die Holdout-Zusammenfassung entsteht in der Sitzung des Owners und enthält
  ausschließlich Zahlen.
- `leakage`: zählt Holdout-Zeilen, die eine Dev-Zeile exakt oder per MinHash (Einstellungen aus `datasets.yaml`)
  wiederholen; läuft im Gate. Exit 1 bei jedem Treffer.
- `render`: Bericht mit Go/No-go je Klasse. `go` verlangt in Dev und Holdout je mindestens 50 gewertete Zeilen
  (Report-only-Sätze zählen nicht), höchstens 5 % Fehler in jedem Satz mit Zeilen der Klasse und im
  Benign-Pool jedes Splits, und kein Leck. Fehlt die Holdout-Zusammenfassung oder der Leckcheck, steht eine
  sonst bestandene Klasse auf `pending`.

```bash
python3 scripts/l1_threat/gold.py sample DIR [DIR ...] --out SHEET.jsonl [--per-set 50]
python3 scripts/l1_threat/gold.py summary DIR [DIR ...] --split dev|holdout --review SHEET.jsonl --out SUMMARY.json
python3 scripts/l1_threat/gold.py leakage --dev DIR [DIR ...] --holdout DIR [DIR ...] --out LEAKAGE.json
python3 scripts/l1_threat/gold.py render --dev SUMMARY.json [--holdout SUMMARY.json] [--leakage LEAKAGE.json] [--notes NOTES.md] --out gold.md
```

Prüfblätter enthalten Datensatztext und werden nie eingecheckt. Tests: `scripts/tests/test_l1_threat_gold.py`.

## Generatoren und Übersetzungen

`generators.py` leitet aus den eingefrorenen Korpora abgeleitete Sätze ab, jede Angriffszeile mit
sauberem Zwilling bzw. harmlosem Doppelgänger (`twin_of`):

- `carrier_insertion`: eine Angriffszeile des Eingabekorpus in einem Träger (Web, PDF-Text, Ticket,
  Code-Kommentar, RAG-Chunk, Mail), der Zwilling trägt an derselben Stelle einen harmlosen Satz;
- `exfil_lookalikes`: Tool-Ausgabe (JSON, CLI-Log, Datei, MCP-Ergebnis, Suchtreffer) mit einer Anweisung,
  Daten an eine Senke unter `example.invalid` zu schicken, und derselbe Rahmen mit Doppelgänger (Upload-Log,
  Webhook-Konfiguration, Bitte an Menschen), DE und EN nativ;
- `obfuscation_slices`: Angriffs- und Benign-Zeilen unter je einer Verschleierung (`base64`, `hex`,
  `rot13`, `leetspeak`, `zero_width`, `homoglyph`, `spaced`, `unicode_tags`), Slice in `obfuscation`;
- `class_templates`: dokumentierte synthetische Angriffe für die Klassen ohne öffentliche Dev-Daten
  (`jailbreak`, `tool_poisoning`, `agent_config_tampering`, `memory_poisoning`, `unsafe_action`,
  `resource_exhaustion`), DE und EN nativ. Jede Template-Familie hat die Form öffentlicher Beispiele, die
  `modelled_on` nennt (Paper, Advisories, MCPTox-Muster), und einen harmlosen Doppelgänger im selben
  Rahmen; nur Platzhalter und `.invalid`-Hosts, keine wirksame Nutzlast.

Dev und Holdout haben getrennte Seeds und disjunkte Template-Familien (`check_families`). Dev: öffentlicher
Seed, liest `DEV/train_dev` und `DEV/translated`, schreibt `DEV/generated` (`generators_dev_seed`,
`ark_authored`). Holdout: geheimer Seed (Default `HOLDOUT/.generators-seed`, beim ersten Lauf mit 0600
angelegt, im Manifest nur sein SHA-256), liest nur `HOLDOUT/holdout`, schreibt `HOLDOUT/generated`
(`generators_holdout_seed`, `ark_blind`). Jede Zeile trägt `template_family`, `carrier`, `source_id` und
`translated` (nativ vs. übersetzt: Runner-Übersetzungen und der deutsche Teil eines in der Entity-Map
als `translated` markierten Satzes). Ein Obfuscation-Zwilling trägt die Sprache seiner Benign-Quelle. Ausgabe eingefroren wie die Korpora (JSONL je Generator,
`manifest.json`, `.ready`); ein abweichender Lauf schreibt nur mit `--force`, außer die Ausgabe stammt
von einer älteren Generator-Version (`GENERATOR_VERSION`, im Manifest `generator_version`).
Jeder Generator hat einen eigenen Zufallsstrom; seine Version (`STREAMS`) steigt nur, wenn sich seine Zeilen
ändern sollen, damit ein Satz mit unveränderten Zeilen bei einem Versionssprung dieselben Texte unter denselben
IDs behält (und sein Gold-Review gültig bleibt).

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
bzw. Hash der Modelldatei). Eine vorhandene Datei wird nie neu berechnet. `sweep` liest nur den Cache, und
zwar je Baseline genau eine Version (die zuletzt geschriebene, im Bericht unter `version`); Sätze ohne
Vorhersagen dieser Version stehen unter `missing`, Scores verschiedener Versionen werden nie gemischt. Es
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

## Scoreboard und Gate

`scoreboard.py` misst ARK auf den eingefrorenen Korpora eines Splits und vergleicht einen Head mit seiner Base.
Ein Split ist ein Wurzelverzeichnis; jedes Unterverzeichnis mit eingefrorenem `manifest.json` zählt
(`DEV/{train_dev,report,generated,translated}`, `HOLDOUT/{holdout,generated}`). Positiv ist eine Zeile für die
Klassen in `classes` (nur berichtete Klassen zählen nicht), negativ jede `benign`-Zeile. Sätze mit der Rolle
`report` laufen im eigenen Bereich `report` und gaten nie; alle übrigen (`dev`, `decisive`) bilden den Bereich
`gated`.

ARK läuft nur auf L1, je Klasse ihre Kategorie (`instruction_injection` heißt `injection`). Urteil einer Klasse:
ein Ergebnis, das nicht `benign`/`safe` ist (wie im Golden-Eval). Score: das Höchste aus der Konfidenz eines
solchen Ergebnisses und den Scorer-Werten unter der Schwelle (`score` des Threat-Scorers, Kandidaten-`score` des
Injection-Scorers); 0, wenn ARK nichts meldet. Je Klasse, Sprache (`all`, `de`, `en`) und Herkunft (`all`,
`native`, `translated`; Runner-Übersetzungen und der deutsche Teil eines in der Entity-Map als `translated`
markierten Satzes, wie in `generators.py`):

- TPR bei gleicher Dokument-FPR 1 % und 0,1 % auf den Benign-Zeilen (`run_baselines.matched_fpr`), dazu ein
  Perzentil-Bootstrap-95-%-KI der TPR@1 % (200 Runden, fester Seed; Positive und Negative getrennt gezogen,
  Schwelle in jeder Runde neu gewählt);
- AUPRC (Average Precision der Positiven gegen die Benign-Zeilen, Gleichstände als eine Stufe);
- Hard-Benign-FPR beim ARK-Urteil: harmlose Doppelgänger (`twin_of`) und die Benign-Zeilen von `notinject`,
  `or_bench_hard`, `xstest`, `l1_goldens` (`HARD_BENIGN_SETS`);
- Leave-one-dataset-out (Sprache und Herkunft `all`): TPR@1 % ohne je einen beteiligten Satz, dazu das Minimum
  und der Satz, dessen Wegfall die TPR senkt.

```bash
python3 scripts/l1_threat/scoreboard.py predict --split DEV --out PRED      # mit dem installierten patronus_ark
python3 scripts/l1_threat/scoreboard.py score --split DEV --predictions PRED [--output report.json]
python3 scripts/l1_threat/scoreboard.py compare --base base.json --head head.json   # Exit 1 bei Regression
python3 scripts/l1_threat/scoreboard.py report --split DEV --predictions PRED [--baseline-cache CACHE] \
    --out research/l1-threat/scoreboard/baseline.md
python3 scripts/l1_threat/scoreboard.py gate --head WT --base-sha SHA --dev DEV [--holdout HOLDOUT] --cache CACHE
```

`gate` baut Head und Base (Release-Modul von `python/`, offline, über `ensure_build` des DLP-Scoreboards; gleiche
Detektor-Quellen teilen einen Build), sagt jeden Satz in einem eigenen Prozess vorher (Cache je Build-Schlüssel,
Skript-Hash und Korpus-SHA) und schlägt fehl, wenn im Bereich `gated` eine Klasse bei TPR@1 % (`all`, `de`, `en`;
Herkunft `all`) mehr als 0,5 pp verliert oder der Head eine Hard-Benign-Zeile einer Klasse meldet, die die Base
nicht meldet. Eine Klasse ohne Positive in der Base ist neu, keine Regression. stdout zeigt Dev-Zahlen; der
Holdout verlässt die Sandbox nur als Urteil mit den Namen fehlschlagender Prüfungen, sein Bericht bleibt unter
`CACHE/threat-scoreboard/reports/`. Die Latenz prüft der Runner getrennt (`latency.py`, `latency_ab`). Exit 0 =
bestanden, 1 = Regression, 2 = Fehler. `report --baseline-cache` wertet jede Baseline mit Vorhersagen für alle
Sätze (je Baseline die zuletzt geschriebene Version) auf denselben Zellen aus und nennt je Zeile die beste.
Ergebnis auf Dev: [`research/l1-threat/scoreboard/baseline.md`](../../research/l1-threat/scoreboard/baseline.md).

Tests: `scripts/tests/test_l1_threat_scoreboard.py`.

## Ablation und Modellwahl

`ablation.py` misst je Klasse dieselben Zeilen mit allen Stufen der README-Ablation und wendet die Auswahlregel an:

| Stufe | Score einer Zeile |
|---|---|
| `R` | nur Regeln: höchste `points` eines Findings der Kategorie in den Facts |
| `R+A` | `R` plus handgesetzte Kontextpunkte (Stützkontext +25, Gegenkontext −30), nur bei Regeltreffer, nicht unter 0 |
| `B0` | heutiger Scorer: ARKs Score aus Vorhersagen von `scoreboard.py predict` (`--b0-predictions`), Urteil von ARK |
| `R+A+L` | `R+A` plus gelernte ganzzahlige Punkte je Fact-Token (balancierte L2-LR, projiziert: Gegenkontext-Tokens ≤ 0, alle anderen ≥ 0) |
| `B1` | Zeichen-N-Gramm-TF-IDF + LR allein (`category_model.py`, Vokabular, ohne Token-Merkmale) |
| `B4` | gehashte Zeichen-N-Gramme + Wörter (TF-IDF + LR) allein, ohne Fact-Tokens |
| `B5` | `R+A` plus der `B4`-Logit als Punkte (10 je Logit-Einheit), gedeckelt auf 40 |

Zeilen tragen `id`, `text`, `facts` (aus dem Beispiel `text_facts`), `classes`, `benign`, `language`, `dataset`.
Positiv: Klasse in `classes`; negativ: `benign`; andere Zeilen fallen heraus. `--rows` wird über sha256 der
Zeilen-ID in Trainings- und Auswertungshälfte geteilt, sofern `--eval-rows` fehlt. Gelernte Stufen trainieren
auf der Trainingshälfte; der Arbeitspunkt jeder Stufe hält 1 % FPR auf deren Negativen.

Je Stufe auf der Auswertungshälfte und Sprache (`all`, `de`, `en`): TPR bei gleicher FPR 1 % und 0,1 %, AUPRC
(`scoreboard.cell_metrics`), Hard-Benign-FPR am Arbeitspunkt (`scoreboard.is_hard_benign`), RAM-Schätzung des
Modells (f64-Gewicht + f32-idf je Merkmal, je Vokabular-Term Map-Eintrag und Kopie in `names`) und die ms je 100 KiB, die das Modell zu den
Facts hinzufügt (p95 des Beispiels `text_model_latency` auf den 100-KiB-Fenstern von `latency.py`;
Punkte-Stufen summieren über die Facts und kosten nichts zusätzlich).

Auswahl: unter den Modell-Stufen `B0`, `R+A+L`, `B1`, `B4`, `B5` im Budget (RAM ≤ 2 MB, ≤ 1 ms je 100 KiB
zusätzlich) die günstigste (ms, dann RAM, dann Stufenreihenfolge), deren TPR@1 % höchstens 1 pp unter der
besten liegt. `R` und `R+A` sind Vergleichszeilen. `B0` ist der Status quo und kostet nichts zusätzlich.
Stufen ohne gemessene Kosten (`B1`, `B4`, `B5` ohne `--bench-bin`/`--windows`) stehen unter `untimed`
und bleiben aus der Auswahl.

```bash
cargo run --release -q -p patronus-ark-core --example text_facts < rows.jsonl > rows.facts.jsonl
cargo build --release -p patronus-ark-core --example text_model_latency
python3 scripts/l1_threat/ablation.py run --rows rows.facts.jsonl --class exfiltration \
    [--eval-rows EVAL.facts.jsonl] [--b0-predictions PRED] \
    [--bench-bin $CARGO_TARGET_DIR/release/examples/text_model_latency --windows windows.jsonl] \
    --out ablation.json [--markdown ablation.md]
```

Tests: `scripts/tests/test_l1_threat_ablation.py`.
