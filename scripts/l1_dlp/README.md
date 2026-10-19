# L1-DLP-Messwerkzeuge

## Baseline-Runner gitleaks / TruffleHog / detect-secrets

`run_baselines.py` lässt eine der drei Baselines über DLP-JSONL laufen (Goldens, Carrier-Zeilen,
Benign-Code- oder Benign-Dokumentkorpus; Pflichtfelder `id` und `text`) und schreibt Vorhersagen
in einem einheitlichen Format. Ausgeführt wird er mit `~/ark-dlp/baselines-venv` (PyYAML und
detect-secrets).

```bash
PY=~/ark-dlp/baselines-venv/bin/python
$PY scripts/l1_dlp/run_baselines.py versions            # Pins prüfen (Exit 2 bei Abweichung)
$PY scripts/l1_dlp/run_baselines.py check-entity-map    # Namen in entity_map.yaml gegen die Tools
$PY scripts/l1_dlp/run_baselines.py run --tool gitleaks|trufflehog|detect-secrets \
    --input rows.jsonl --output preds.jsonl              # [--meta FILE] [--bin-dir DIR] [--detect-secrets-python PY]
```

**Gepinnte Versionen.** `PINS` im Skript: gitleaks 8.30.1 und TruffleHog 3.97.9 (Version und
SHA-256 des Binarys unter `~/ark-dlp/baselines/bin`), detect-secrets 1.5.0 (Paketversion im
Baseline-Venv). Die Versionen stimmen mit `research/dlp/entity_map.yaml` und
`~/ark-dlp/baselines/VERSIONS` überein. Weicht ein Tool ab, bricht `run` mit Exit 2 ab, bevor es
etwas schreibt. TruffleHog (AGPL) wird nur als unverändertes Binary ausgeführt.

**Profil.** Jedes Tool läuft im Default-Profil, einmal über alle Zeilen:

| Tool | Aufruf |
|---|---|
| gitleaks | `gitleaks dir ROOT --report-format json --report-path R --no-banner --no-color --exit-code 0` (Default-Config) |
| TruffleHog | `trufflehog filesystem ROOT --json --no-verification --no-update --no-color`, alle Detektoren |
| detect-secrets | `scan_file` je Datei mit `default_settings()`: alle Plugins, Default-Filter, ohne Verifikation (wie `detect-secrets scan --all-files`) |

Die Tools laufen mit minimaler Umgebung (`PATH`, eigenes `HOME`, `LC_ALL`), also ohne
`GITLEAKS_CONFIG`, Proxy oder Nutzer-Config. Netzwerk braucht keines. Jede Zeile `i` wird als
`ROOT/<i:06d>/<name>` in UTF-8 geschrieben. Der Name kommt aus `path` (Benign-Korpora, nur
relative Pfade ohne `..`), sonst aus dem Carrier-Feld `format` bzw. `code_language` (`.env`,
`config.yaml`, `main.tf`, `main.go` …), sonst `document.txt`. Das ist wichtig, weil gitleaks
Pfad-Allowlists und detect-secrets Dateityp-Filter und YAML/INI-Parser nach dem Namen wählen.

**Ausgabe.** Je Eingabezeile eine Zeile in Eingabereihenfolge, ohne Secret-Text:

```json
{"id": "…", "tool": "trufflehog", "evidence_spans": [{"start_char": 41, "end_char": 57,
  "rule_id": "Postgres", "label": "trufflehog.Postgres", "entities": ["credential.url_userinfo"],
  "groups": ["CREDENTIAL"], "normalization": ["url_password"]}]}
```

`start_char`/`end_char` sind Code-Points im Text der Zeile. `rule_id` ist die native Kennung
(gitleaks-`RuleID`, TruffleHog-`DetectorName`, detect-secrets-Plugin-Klasse). `entities` und
`groups` kommen aus `entity_map.yaml`. Ein TruffleHog-Detektor oder detect-secrets-Plugin kann
mehrere Entitäten haben, ein unbekannter Name hat `[]`. Gleicher Span und gleiche Regel
erscheinen einmal. Das Format passt zu `fp-per-mb`/`fp-report` (`evidence_spans` mit
`rule_id`). `<output>.meta.json` enthält Pins, installierte Versionen und Binary-SHA-256, den
Aufruf, SHA-256 von `entity_map.yaml`, Eingabe und Ausgabe, und Zähler: Funde je Regel, nicht
lokalisierbare Funde (`regel:decoder`), angewandte Normalisierungen und Regeln ohne Entität,
dazu `errors`: Dateien, an denen das Tool gescheitert ist (`id`, Dateiname, nur die
Ausnahmeklasse). detect-secrets' CLI bricht den ganzen Scan ab, wenn ein Plugin auf einer Datei
eine Ausnahme wirft (im Benign-Code-Dev-Split ein YAML-Datum, das der YAML-Transformer nicht
parsen kann); der Worker listet die Datei dort, verwirft ihre Teilfunde und scannt weiter wie
`latency.py`. Die Zeile bleibt in der Ausgabe, ohne Spans. Zeitstempel fehlen; zwei Läufe sind
byte-identisch.

**Span-Normalisierung auf den Wert.** Keines der Tools liefert Code-Point-Offsets. Der Runner
sucht deshalb den gemeldeten Wert im Text und normalisiert den Span auf den Wert, wie ihn die
ARK-Goldens annotieren (nur der Wert ohne Schlüsselnamen; bei Präfix-Tokens mit Präfix;
URL-Userinfo nur das Passwort; PEM-Schlüssel als ganzer Block).

| Tool | gemeldeter Wert | Position | Besonderheiten |
|---|---|---|---|
| gitleaks | `Secret` (Secret-Gruppe der Regel), gesucht innerhalb von `Match` | `StartLine`–`EndLine`, `StartColumn` als Hinweis | Spalten zählen UTF-8-Bytes und sind in 8.30.1 auf Zeile 1 um 1, sonst um 2 verschoben; gewählt wird das Vorkommen nächst der Spalte, in `Match` das letzte Vorkommen von `Secret`. Funde aus dekodiertem Text (Tag `decoded:base64`) sind nicht im Text und zählen als `unlocated`. `curl-auth-user` meldet `user:passwort` → Passwort (`user_password`). |
| TruffleHog | `Raw`, sonst `RawV2` (`raw_v2`) | `line` (keine Spalte) | erstes Vorkommen ab der Zeile. TruffleHog meldet einen Wert je Chunk und Detektor einmal; der gewählte Decoder ist nicht deterministisch und steht deshalb nicht in der Ausgabe. Connection-Strings (`Postgres`, `URI`, `MongoDB` …) → Passwort (`url_password`). TruffleHog normalisiert URIs (`Postgres` ergänzt den Default-Port `:5432`); steht `Raw`/`RawV2` so nicht im Text, wird `user:passwort@host` ohne Port gesucht und auf das Passwort verengt (`uri_password`), zuletzt ein `password`-Eintrag aus `SecretParts` (`secret_part`). JDBC-Strings (`jdbc:postgresql://user:pw@…`, `?password=`, `;password=`, Oracle `thin:user/pw@`) → Passwort (`jdbc_password`). Mehrteilige Funde (`AWS`: `Raw` ist nur die Key-ID, `RawV2` die Verkettung) werden aus `SecretParts` (sonst `RawV2` minus `Raw`) in je einen Fund pro Teil zerlegt, mit eigenem Label (`trufflehog.AWS.access_key_id` / `.secret_access_key`) und nur der passenden Entität. Dekodierte Werte ohne Textvorkommen zählen als `unlocated`. |
| detect-secrets | `secret_value` des Plugins | `line_number` | Plugins, deren Regex nur das Präfix fängt (`(ghp\|…)_…`, `glpat`), melden den ganzen Regex-Treffer. `PrivateKeyDetector` meldet den Header-Text → ganzer PEM-Block (`pem_block`) bzw. Header (`pem_header`). `JwtTokenDetector` endet wegen eines lazy Quantors vor der Signatur → bis zum Ende des Tokens (`regex_tail`). `BasicAuthDetector` meldet bereits das Passwort. Der Worker sucht den Wert selbst (gleiche Suche wie unten) und gibt nur Code-Point-Offsets aus, nie den Wert. |

Für alle Tools gilt danach:

1. **Suche** (`locate`): exakter Text auf den gemeldeten Zeilen, dann irgendwo im Dokument
   (`relocated`), dann mit beliebigem Leerraum oder `\n`/`\r`/`\t`-Escapes zwischen den
   Teilen (`whitespace`; umbrochene oder JSON-escapte PEM-Blöcke). Findet sich nichts, wird der
   Fund nicht ausgegeben und in `unlocated` gezählt.
2. **Trim** (`trim`): führende Leerzeichen, Anführungszeichen, `=` und `:` sowie nachgestellte
   Leerzeichen und Anführungszeichen fallen weg, ebenso ein `\` vor einem Anführungszeichen
   (escapte Strings in JSON/Notebooks). Base64-Padding (`=` am Ende) bleibt.
3. **URL-Userinfo** (`url_password`): `schema://user:passwort@…` → nur das Passwort.
4. **PEM** (`pem_block`/`pem_header`): Liegt der Span in einer `-----BEGIN …-----`-Zeile, wird
   er bis zur passenden `-----END …-----`-Zeile erweitert, ohne END-Zeile auf den Header.

Weitere Ungenauigkeiten der Tools bleiben stehen, damit Exact- und Overlap-Metrik sie
unterscheiden. Beispiele: detect-secrets' OpenAI-Regex endet 20 Zeichen nach `T3BlbkFJ`, und
High-Entropy-Strings schließen `PHPSESSID=` ein.

**Entity-Map-Prüfung.** `check-entity-map` prüft die TruffleHog-Namen in `entity_map.yaml` mit
`--include-detectors` gegen das gepinnte Binary und die detect-secrets-Plugins gegen das Paket.
Die gitleaks-IDs prüft `rust/tests/dlp_entity_map.rs` gegen das Inventar.

## ARK-Runner im selben Format

`run_ark.py` scannt dieselbe DLP-JSONL (`id`, `text`) über die Python-Bindings und schreibt
Vorhersagen im Format von `run_baselines.py`. Ausgeführt wird er mit dem ARK-Venv
(`maturin develop` in `.venv`), nicht mit dem Baseline-Venv.

```bash
.venv/bin/python scripts/l1_dlp/run_ark.py --input rows.jsonl --output ark.jsonl
    # [--meta FILE] [--enable-rule dlp_sql_statement …]
```

**Engine.** `SecurityGateway(categories=["dlp"], max_level="l1", download_files=False)` im
Default-Profil: Secret-Gruppen an, Content- und Dokumentklassen aus. `--enable-rule` schaltet
einzelne `dlp_*`-Regeln zusätzlich ein (unbekannte Regeln brechen ab). Gemessen werden alle
DLP-Produzenten der Kategorie (`native:dlp`, `sensitive_material`, `secret_transfer` …).

**Ausgabe.** Je Eingabezeile eine Zeile in Eingabereihenfolge, ohne Secret-Text:

```json
{"id": "…", "tool": "ark", "evidence_spans": [{"start_char": 41, "end_char": 57,
  "rule_id": "dlp_env_var_secret", "label": "ark.dlp_env_var_secret", "group": "CREDENTIAL",
  "entities": ["credential.secret_assignment"], "groups": ["CREDENTIAL"], "score": 1.0,
  "normalization": []}]}
```

Die Felder der Baselines sind gleich (`label` = `ark.<rule_id>`, `entities`/`groups` aus dem
`ark`-Feld von `entity_map.yaml`). `normalization` ist immer leer, weil ARK-Spans schon
Wert-Spans sind. Dazu kommen `group` (Entity-Gruppe der Engine, d. h. das Span-Label) und `score`
(Span-Score der Engine, 6 Nachkommastellen). Gleicher Span und gleiche Regel erscheinen einmal
mit dem besten Score.

**`rule_id`.** Evidence-Spans der Bindings tragen nur die Gruppe. Die Regel steht in den
`matched_rules` der Layer-Details desselben Scanner-Ergebnisses (Regel-ID und Byte-Bereich). Ein
Span bekommt die Regel mit demselben Byte-Bereich; passen mehrere (Überlappungen über Gruppen
hinweg oder von der Engine verworfene Treffer), gewinnt der erste Treffer, dessen Gruppe laut
Entity-Map dem Span-Label entspricht. Die Engine behält je Gruppe ebenfalls den ersten Treffer in
Regelreihenfolge. Ohne passende Gruppe gewinnt der erste Treffer. Ein Span ohne Treffer und ein
Scanner-Fehler brechen den Lauf ab, statt leere Vorhersagen zu schreiben.

**Metadaten.** `<output>.meta.json` enthält Schema, Engine-Profil (`enabled_rules`), SHA-256
des nativen Moduls und die Paketversion, SHA-256 von `entity_map.yaml`, Eingabe und Ausgabe,
und Zähler: Spans je Regel (`findings`) und Gruppe (`groups`), Regeln ohne Entität (`unmapped`)
und Spans, deren Engine-Gruppe nicht zur Entity-Map passt (`group_mismatch`, `regel:gruppe`).
Zeitstempel fehlen; zwei Läufe auf demselben Build sind byte-identisch.

## Benign-Code-Korpus (FP/MB)

`benign_code.py` baut den Benign-Code-Korpus, auf dem das Scoreboard FP/MB misst. Quelle sind
permissiv lizenzierte Repositories, jedes gepinnt auf einen Commit in
[`benign_code_repos.json`](benign_code_repos.json). Die Daten liegen nur auf der VPS, nie im Repo.

```bash
python3 scripts/l1_dlp/benign_code.py prepare --dev-out DIR --holdout-out DIR   # [--sources DIR] [--offline] [--force]
python3 scripts/l1_dlp/benign_code.py check DIR
python3 scripts/l1_dlp/benign_code.py fp-per-mb --corpus DIR --predictions FILE  # [--output FILE]
python3 scripts/l1_dlp/benign_code.py pin --sources DIR [--write]                # nach Änderung an Liste/Limits
```

**Auswahl der Repositories.** Erlaubt sind nur permissive SPDX-Lizenzen (MIT, Apache-2.0, BSD-2/3,
ISC, 0BSD, Unlicense, CC0-1.0, Zlib). Bei `OR` genügt eine permissive Alternative, bei `AND` müssen
alle Terme permissiv sein. Im Wurzelverzeichnis muss eine Lizenzdatei liegen; das Manifest nennt
sie. Secret-Scanner und ihre Regel- und Fixture-Repos (gitleaks, TruffleHog, detect-secrets,
Kingfisher, ggshield, Nosey Parker, secretlint …) sind ausgeschlossen. Der Loader prüft das über
Schlüsselwörter in URL und ID. Provider-SDKs mit Beispiel-Keys werden ebenfalls nicht aufgenommen.
Zusammen decken die Repos Lockfiles (npm, pnpm, Cargo, go.sum, Poetry, uv, Composer), minifiziertes
JS, SVG, base64 (Data-URIs, Notebook-Ausgaben) und Git-Logs ab; jeder Split hat jede Dokumentart.

**Split nach Repository.** Jeder Eintrag nennt seinen Split (`dev` oder `holdout`). Kein Repository
liefert Dokumente in beide Splits. Fehlt einem Split eine Dokumentart, bricht `prepare` ab.

**Dokumente.** Je Repository entsteht `<repo>.jsonl` mit Zeilen `id` (`<repo>:<pfad>`), `repo`,
`path`, `kind` und `text`. Mögliche Werte für `kind`:

| kind | Regel |
|---|---|
| `lockfile` | Dateiname aus `LOCKFILES` (z. B. `package-lock.json`, `Cargo.lock`, `go.sum`, `poetry.lock`) |
| `minified_js` | `.js/.mjs/.cjs` mit `.min.` im Namen oder längster Zeile ≥ 1000 und Ø ≥ 200 Zeichen/Zeile |
| `svg` | `.svg` |
| `base64` | sonstige Datei mit `base64,` + ≥ 64 base64-Zeichen oder einem Lauf ≥ 200 base64-Zeichen |
| `code` | alle übrigen Textdateien (Quellcode, Config, Doku) |
| `git_log` | ein Dokument `<repo>:@git-log`: `git log --format=fuller --name-status` der letzten 1500 Commits bis zum Pin, höchstens 4 MiB, an Commit-Grenzen gekürzt |

Nicht aufgenommen werden Binärdateien und Dateien, die kein UTF-8 sind, Dateien über 2 MiB sowie
Symlinks und Submodule. Ebenso fehlen Schlüssel- und Credential-Dateien (`.pem`, `.key`, `.p12`,
`.jks`, `id_rsa*`, `.env*`, `.npmrc`, `.netrc`, `credentials` …): Auch ein Testschlüssel ist
Schlüsselmaterial. Pro Repository und Dokumentart gilt ein Byte-Budget (`KIND_BUDGET_BYTES`, 2–4 MiB).
Die Dateien werden in der Reihenfolge `sha256(repo:pfad)` gewählt.

**Pins und Einfrieren.** `sha256` in der Liste pinnt das JSONL je Repository. Weicht ein Build ab,
etwa durch einen geänderten Commit oder eine geänderte Auswahlregel, endet `prepare` mit Exit 1.
`pin --write` setzt die Werte neu. Jedes Zielverzeichnis enthält:

- die JSONL-Dateien,
- `manifest.json` mit URL, Commit, Lizenz, Lizenzdatei, Split, SHA-256, Bytes sowie Dokumenten und
  Bytes je Dokumentart und Repository, dazu den Limits,
- zuletzt `.ready` mit dem SHA-256 des Manifests.

Ein Verzeichnis mit `.ready` ist eingefroren (wie in `scripts/l1_presidio/prepare_corpora.py`). Die
Git-Caches liegen unter `--sources` (Standard `HOLDOUT/.sources/benign_code`), nie im
Dev-Verzeichnis. stdout nennt nur Dev-Zahlen. Git läuft ohne System- und Nutzer-Config, mit festem
Log-Format und ohne Mailmap und Umbenennungserkennung. Ein zweiter Lauf aus frischen Klonen ist
byte-identisch. Im Gate friert `prepare_corpora.py` den Korpus unter `~/ark-dlp/holdout` ein.

**Metrik FP/MB.** Der Korpus gilt als secret-frei, deshalb ist jeder gemeldete Span ein FP.
`FP/MB = FP / (UTF-8-Bytes des Texts / 1 000 000)`. Ein Span zählt pro Dokument einmal, auch wenn
mehrere Regeln ihn melden. Vorhersagen sind JSONL mit `id` und `evidence_spans` (`start_char`,
`end_char`, `rule_id` oder `label`). Der Bericht nennt FP/MB gesamt, je `kind`, je Repository und
je Regel. Die Zahlen je Regel sind auf die Gesamtbytes normiert.

## Benign-Dokumentkorpus DE/EN (Content- und Dokumentklassen)

`benign_docs.py` baut den Benign-Dokumentkorpus. Auf ihm misst das Scoreboard die FP der Content-
und Dokumentklassen (Quellcode, SQL, Log, Business-Metrik, später HR, Recht, M&A, Exportkontrolle …)
auf deutschen und englischen Texten. Alle Texte sind öffentlich, gemeinfrei oder CC-lizenziert und
in [`benign_docs_sources.json`](benign_docs_sources.json) gepinnt. Die Daten liegen nur auf der
VPS, nie im Repo.

```bash
python3 scripts/l1_dlp/benign_docs.py prepare --dev-out DIR --holdout-out DIR   # [--sources DIR] [--offline] [--force]
python3 scripts/l1_dlp/benign_docs.py check DIR
python3 scripts/l1_dlp/benign_docs.py fp-report --corpus DIR --predictions FILE  # [--output FILE]
python3 scripts/l1_dlp/benign_docs.py pin --sources DIR [--write]                # nach Änderung an Liste/Limits
```

**Quellen.** Jede Quelle hat genau eine Sprache (`de`, `en`) und ein Genre:

| Genre | DE | EN |
|---|---|---|
| `prose` | Wikipedia-Artikel (CC BY-SA 4.0) | Wikipedia-Artikel (CC BY-SA 4.0) |
| `government` | Bundesgesetze aus `bundestag/gesetze` (Unlicense; amtliche Werke, § 5 UrhG) | 18F/GSA-Guides aus `18F/guides` (US-Bundeswerk, CC0) |
| `corporate` | Wikimedia Foundation: Richtlinien, Satzung, Vorstandsprotokolle, deutsche Übersetzungen (CC BY-SA 4.0) | dieselben Seiten im englischen Original (CC BY-SA 4.0) |

Die Artikel wurden bewusst gemischt: Orte, Geschichte und Wissenschaft, aber auch Unternehmen mit
Umsatzzahlen und Arbeits-, Datenschutz- und Wirtschaftsthemen (Betriebsrat, DSGVO, Insiderhandel,
Exportkontrolle). Gesetze und Richtlinien behandeln Arbeitsrecht, Datenschutz,
Geschäftsgeheimnisse, Außenwirtschaft und Vertraulichkeit, sind aber öffentlich. Seiten über
Passwörter oder Kryptografie mit Beispielwerten sind ausgeschlossen. Erlaubt sind nur CC0,
CC BY und CC BY-SA (3.0/4.0) sowie die Unlicense, nicht NC oder ND.

Zwei Quelltypen gibt es:

- `git`: Repository, Commit und Pfad-Globs (`.md`, `.markdown`, `.txt`). Geholt werden nur Baum und
  ausgewählte Blobs (`--filter=blob:none`, danach die Blobs gezielt), ohne Promisor-Remote, also
  ohne spätere Nachladung. Im Wurzelverzeichnis muss eine Lizenzdatei liegen. Ein YAML-Front-Matter
  am Anfang wird entfernt, sonst bleibt der Markdown-Text unverändert.
- `mediawiki`: Site und Seiten mit Titel und Revisions-ID. Revisionen sind unveränderlich. Der Titel
  jeder Revision wird über die API geprüft, der Wikitext über `index.php?action=raw&oldid=…` geholt
  (User-Agent mit Kontakt, 1 s Abstand, Backoff bei 429/5xx) und deterministisch zu Fließtext
  reduziert: Vorlagen, Tabellen, Einzelnachweise, Dateien, Kategorien, Kommentare und
  Übersetzungsmarker fallen weg, Links behalten ihren Text.

**Split nach Quelle.** Jede Quelle nennt ihren Split. Ein Repository darf mehrere Quellen mit
getrennten Pfaden liefern (Gesetze und 18F-Guides teilen sich nach Gesetz bzw. Kapitel). Ein
Dokument (Repo und Pfad oder Site und Titel) gehört zu genau einer Quelle. Derselbe Text darf nicht
in beiden Splits stehen, und Dev und Holdout nutzen unterschiedliche Wikimedia-Seiten (Dev:
Policies/Board, Holdout: Legal/Minutes), keine Übersetzungspaare über die Split-Grenze. Jeder
Split muss alle sechs Kombinationen aus Sprache und Genre enthalten, sonst bricht `prepare` ab.

**Dokumente.** Je Quelle entsteht `<quelle>.jsonl` mit Zeilen `id` (`<quelle>:<pfad|titel>`),
`source`, `lang`, `genre`, `license`, `url` (Permalink auf Commit bzw. Revision), `path` oder
`title` + `revid` und `text`. Dokumente unter 200 Zeichen oder über 1 MiB fallen weg. Je Quelle
gilt ein Budget von 4 MiB, gewählt in der Reihenfolge `sha256(quelle:id)`.

**Pins und Einfrieren.** Wie beim Benign-Code-Korpus: `sha256` je Quelle pinnt das JSONL, `pin
--write` setzt es neu. Jedes Zielverzeichnis enthält die JSONL-Dateien, `manifest.json` (Typ,
URL/Commit/Pfade bzw. Site und Seitenzahl, Lizenz, Lizenzdatei, Sprache, Genre, Split, SHA-256,
Dokumente, Bytes; Summen je Sprache, Genre und Kombination; Limits) und zuletzt `.ready`. Die
Caches liegen unter `--sources` (Standard `HOLDOUT/.sources/benign_docs`). stdout nennt nur
Dev-Zahlen. Im Gate friert `prepare_corpora.py` den Korpus unter `~/ark-dlp/holdout` ein.

**FP-Bericht.** Der Korpus gilt als frei von Secrets und vertraulichen Dokumenten. Jeder Span und
jedes markierte Dokument ist ein FP. Vorhersagen sind JSONL mit `id`, `evidence_spans`
(`start_char`, `end_char`, `rule_id` oder `label`) und optional `document_labels` für Klassen auf
Dokumentebene. Ein Dokument gilt als markiert, wenn es einen Span oder ein Label hat. `fp-report`
nennt FP/MB (Spans, je Dokument einmal) und `flagged_rate` (markierte Dokumente / Dokumente)
gesamt, je Sprache, Genre, Quelle und Regel. Die Werte je Regel beziehen sich auf alle Bytes und
Dokumente des Splits.

## Holdout einfrieren (Gate-Schritt `prepare-corpora`)

`prepare_corpora.py` baut alle Messkorpora für Dev und Holdout und friert sie ein. Der Runner ruft
das Skript im Gate auf, solange `~/ark-dlp/holdout/.ready` fehlt, und zwar mit dem Baseline-Venv
(nur Standardbibliothek und git, ohne natives Modul):

```bash
python3 scripts/l1_dlp/prepare_corpora.py --dev-out ~/ark-dlp/data/dev --holdout-out ~/ark-dlp/holdout
    # [--sources DIR] [--holdout-seed-file FILE] [--code-repos FILE] [--doc-sources FILE] [--offline] [--force]
python3 scripts/l1_dlp/prepare_corpora.py --check DIR
```

Jedes Zielverzeichnis bekommt drei Komponenten:

| Verzeichnis | Inhalt | Split |
|---|---|---|
| `benign_code/` | Benign-Code-Korpus (`benign_code.py prepare`) | nach Repository |
| `benign_docs/` | Benign-Dokumentkorpus DE/EN (`benign_docs.py prepare`) | nach Quelle |
| `synthetic/` | `carriers.jsonl`: Carrier-Zeilen aus `patronus_ark.dlp_synth.carriers` (Positive + Hard Negatives) | nach Template-Familie und Seed |

**Generator-Seed.** Dev nutzt den öffentlichen Seed `DEV_SEED` und nur die Dev-Familien. Der
Holdout nutzt nur die Holdout-Familien und einen geheimen Seed. Das Skript legt ihn beim ersten
Lauf als `HOLDOUT/.seed` an (Modus 0600, 32 Zufallsbytes hex); der 64-Bit-Carrier-Seed ist
SHA-256 des Tokens (erste 8 Bytes). Das Holdout-Manifest nennt nur `seed_sha256`, stdout nur
Dev-Zahlen. Ein kurzer Seed oder einer, der den Dev-Seed ergibt, bricht ab. Die Fixtures von
gitleaks und detect-secrets gehören nie zum Holdout.

**Manifest und Einfrieren.** Jede Komponente hat ihr eigenes `manifest.json` mit SHA-256 und
`.ready`. Das `manifest.json` des Zielverzeichnisses pinnt je Komponente Schema, SHA-256 des
Komponenten-Manifests und SHA-256 jeder JSONL. `synthetic/manifest.json` pinnt zusätzlich die
SHA-256 der Generator-Dateien (`carrier_templates.py`, `generators.json`, `rules.json` …), die
Familien und Zähler je Variante, Sprache, Format und Regel. Das oberste `.ready` (SHA-256 des
Manifests) entsteht zuletzt, nach allen Komponenten. Scheitert eine Komponente, fehlt es, und das
Gate versucht es beim nächsten Mal erneut. Ein Verzeichnis mit `.ready` ist eingefroren: Ein
weiterer Lauf muss es byte-identisch reproduzieren, sonst schreibt er nichts und endet mit Exit 1.
`--force` ersetzt es und nutzt die vorhandene Seed-Datei weiter. Die Caches liegen unter
`--sources` (Standard `HOLDOUT/.sources`), Seed und Caches dürfen nicht im Dev-Verzeichnis liegen.

**Zugriff.** Nur dieser Gate-Schritt schreibt den Holdout, und nur der Scoreboard-Schritt liest
ihn (ohne Netz, Ausgabe nur Exit-Code). Die Agent-Sandbox sperrt `~/ark-dlp/holdout` per
`InaccessiblePaths` (`research/l1-pii/runner/run.sh`, `PRIVATE` in `ark-l1`). Neue Regeln oder
Familien nach dem Einfrieren erscheinen erst nach einem bewussten `--force` des Betreibers im
Holdout.

## Externe Content-Goldens (nur Dev)

`external_content.py` baut aus den zugelassenen externen Quellen
(`python/patronus_ark/benchmark_data/external_dlp/manifest.json`) die Komponente `external/` des
Dev-Splits und bewertet Vorhersagen darauf. Wie Vorhersagen an Dokumentlabels hängen und welcher
Teil einer Datei zählt, legt
[`docs/research/dlp-external-content-contract-0.1.8.md`](../../docs/research/dlp-external-content-contract-0.1.8.md)
fest.

```bash
python3 scripts/l1_dlp/external_content.py prepare --out ~/ark-dlp/data/dev/external \
    --sources ~/ark-dlp/cache/external_sources          # [--offline] [--force]
python3 scripts/l1_dlp/external_content.py check DIR
python3 scripts/l1_dlp/external_content.py score --corpus DIR --predictions FILE   # [--output FILE]
```

| Datei | Zeilen | Gold |
|---|---|---|
| `gitleaks-go.jsonl` | 214 `.go`- und 13 `.md`-Dateien von gitleaks (MIT, gepinnter Commit) | `.go`: Dokumentlabel `content.source_code`, SQL-negativ; `.md`: Source-Code-negativ |
| `schemapile-sql.jsonl` | 10 SQL-Dateien aus SchemaPile-Perm (Archiv per SHA-256 und MD5 gepinnt) | `content.sql` je Datei, die ersten 250 Statements als exakte Evidenzspans |

Jede Zeile ist eine ganze Datei mit `document_labels`, `judged` (Klassen mit vollständigen
Dokumentlabels), `span_judged` (Klassen mit vollständigen Spans), `scope` (bewerteter Bereich,
bei der SQL-Datei, in der die Obergrenze greift, bis zum Ende des letzten ausgewählten Statements)
und `entities`. Ein Dokument bekommt ein Label nur über einen Evidenzspan dieser Klasse im Scope.
Spans hinter dem Scope zählen als `out_of_scope`, Spans nicht bewerteter Klassen als `unjudged`.
`PINNED_SHA256` pinnt beide JSONL. Ein abweichender Build wird nicht geschrieben, ein
eingefrorenes Verzeichnis (`.ready`) nur mit `--force` ersetzt.

Die Komponente gehört nur zum Dev-Split. Der Runner legt sie einmal an (Gate-Schritt
`external-corpora`, solange `~/ark-dlp/data/dev/external/.ready` fehlt, mit Netz). Das
Top-Manifest von `prepare_corpora.py` nennt sie nicht, darum bleibt ein schon eingefrorener
Dev-Split gültig. gitleaks enthält Secret-Regeln und Testwerte und ist deshalb kein neutraler
Code und kein Secret-Gold. Im Holdout lehnt das Scoreboard die Komponente ab.

## Scoreboard (Gate-Schritt `scoreboard`)

`scoreboard.py` bewertet Vorhersagen im gemeinsamen Format auf den eingefrorenen Korpora und
vergleicht im Gate den Head mit seiner Basis. Der Runner ruft es mit dem Baseline-Venv auf, ohne
Netz, mit Lesezugriff auf Holdout und Checkout und Schreibzugriff nur auf den Cache:

```bash
PY=~/ark-dlp/baselines-venv/bin/python
$PY scripts/l1_dlp/scoreboard.py gate --head WT --base-sha SHA --dev DIR --holdout DIR --cache DIR   # [--jobs N]
$PY scripts/l1_dlp/scoreboard.py score --split DIR --predictions FILE    # [--extended-predictions FILE] [--output FILE]
$PY scripts/l1_dlp/scoreboard.py compare --base REPORT --head REPORT     # [--tolerance-pp 0.5]
```

Exit-Codes: 0 = keine Regression, 1 = Regression, 2 = Fehler (Basis fehlt, Korpus verändert,
Build oder Scan gescheitert). Lokal geht `gate` auch ohne `--holdout`, z. B. mit
`--dev $ARK_L1_DEV_DATA --cache /tmp/sb`.

**Builds.** `gate` baut Head- und Basis-Commit selbst: `git archive` des Commits nach
`CACHE/scoreboard/src` (alle Dateien mit aktueller mtime, sonst hielte cargo alte Artefakte für
aktuell), dann `cargo build --release --locked --offline -p patronus-ark-python` mit eigenem
Target unter `CACHE/scoreboard/target`. Crate-Registry (`CARGO_HOME`) und ONNX-Runtime-Cache
(`XDG_CACHE_HOME`) der vorherigen Gate-Schritte werden nur gelesen. `CARGO_NET_OFFLINE` wird
dabei entfernt, weil `ort-sys` sonst seinen Binary-Cache ignoriert. Ein Build besteht aus dem
Python-Paket des Commits, dem nativen Modul und seiner `entity_map.yaml` und liegt unter
`CACHE/scoreboard/builds/<key>`. `key` ist SHA-256 über `git ls-tree` von `Cargo.toml`,
`Cargo.lock`, `rust-toolchain.toml`, `rust/`, `python/` und `research/dlp/entity_map.yaml`.
Ein Commit, der nur Backlog, Doku oder Skripte ändert, teilt also den Build seiner Basis. Behalten
werden die acht zuletzt genutzten Builds.

**Profile.** Jeder Build scannt jede Datei mit dem `run_ark.py` des Heads:

| Profil | Regeln | Korpora | bewertet |
|---|---|---|---|
| `default` | Auslieferungszustand: nur Secret-Gruppen (`provider_secret`, `generic_credential`, `key_material`) | Carrier, Benign-Code, Benign-Dokumente | Secret-Gruppen, FP/MB |
| `extended` | zusätzlich alle Opt-in-Regeln laut `taxonomy` der eigenen Entity-Map (Business-IDs, Content- und Dokumentklassen) | Carrier, Benign-Dokumente, externe Content-Goldens (nur Dev) | Opt-in-Gruppen auf Spans, Content-Klassen je Dokument, FP der Opt-in-Regeln auf Benign-Dokumenten |

Vorhersagen liegen unter `CACHE/scoreboard/predictions/<key>.jsonl`. Der Schlüssel enthält
Build, SHA-256 von `run_ark.py`, `run_baselines.py` und `scoreboard.py`, die Regeln und die
Eingabedatei. Ein Lauf auf demselben Build scannt nichts neu. Nach 14 Tagen ohne Nutzung werden
Vorhersagen gelöscht.

**Metriken je Split** (Bericht `score`, im Gate je Head und Basis):

- `synthetic.groups` und `synthetic.overall`: exakte Spans auf den Wert (`start`/`end` der
  Carrier-Entitäten) und Overlap, je `gold`, `predicted`, `precision`, `recall`, `f1`. Die Gruppe
  einer Vorhersage ist bei ARK das Span-Label (`group`), bei Baselines `groups` aus der
  Entity-Map (sonst `(unmapped)`). `overall` ist ungetypt: jeder Wert-Span zählt, egal mit
  welcher Gruppe. Overlap-Precision zählt Vorhersagen, die irgendeinen Gold-Span schneiden,
  Overlap-Recall Gold-Spans, die eine Vorhersage schneidet.
- `synthetic.providers`: dieselben Werte je Entität (`llm.openai.api_key` …, Vorhersage über
  `entities`), dazu `found` (Gold-Span exakt von irgendeiner Regel getroffen), `attributed`
  (davon mit der richtigen Entität), `rule_attributed` (mit der Generator-Regel `rule_id`) und
  `attribution`. `synthetic.attribution` fasst das über alle Provider zusammen.
- `synthetic.hard_negatives`: Jeder Wert-Span auf einer Hard-Negative-Zeile ist ein FP, gesamt,
  je Variante (`placeholder`, `env_ref`, `doc_example`, `test_key`) und Sprache, dazu die Liste
  der FP-Spans (Zeilen-ID und Offsets, kein Text).
- `synthetic.documents`: P/R/F1 je Content-Klasse auf Dokumentebene. Gold sind die
  `content_labels` der Zeile, Vorhersage ist jede Klasse, deren Regel in der Zeile einen Span
  meldet (Profil `extended`). Content-Spans zählen nie in den Span-Metriken.
- `benign_code`: FP/MB wie `benign_code.py fp-per-mb` (Profil `default`).
- `benign_docs.default`: FP-Bericht wie `benign_docs.py fp-report`; `benign_docs.extended`:
  derselbe Bericht für die Opt-in-Spans, dazu `by_class` mit markierten Dokumenten je Klasse.
- `external` (nur Dev, wenn `external/` existiert, sonst `null`): Bericht von
  `external_content.py score` auf dem `extended`-Lauf: Dokument-P/R/F1 je Content-Klasse gesamt
  und je Korpus, exakte und Overlap-P/R/F1 der SchemaPile-Statements, `out_of_scope`,
  `unjudged` und `labels_without_evidence`.

`score` nimmt eine Vorhersagedatei für alle Komponenten eines Splits; Zeilen ohne Vorhersage
gelten als leer, unbekannte IDs sind ein Fehler. So lassen sich auch die Ausgaben von
`run_baselines.py` bewerten (Dateien je Komponente aneinanderhängen).

**Regression.** `compare` prüft den Head gegen die Basis auf demselben Split. Eine Regression ist:

| Check | Regel |
|---|---|
| `f1.exact:<gruppe>`, `f1.overlap:<gruppe>`, `…:overall` | F1 sinkt um mehr als 0,5 pp (nur Gruppen mit Gold-Spans) |
| `f1.document:<klasse>` | Dokument-F1 einer Content-Klasse mit Gold sinkt um mehr als 0,5 pp |
| `f1.external.document:<klasse>`, `f1.external.exact:content.sql`, `f1.external.overlap:content.sql` | Dokument- bzw. Span-F1 auf den externen Content-Goldens sinkt um mehr als 0,5 pp (nur Dev) |
| `fp:benign_code`, `fp:benign_docs` | mehr FP als die Basis (Profil `default`; Bytes sind gleich, also FP/MB) |
| `flagged:benign_docs:<klasse>` | mehr markierte Benign-Dokumente; nur Klassen, die die Basis schon hat |
| `hard_negatives:new_fp` | ein FP-Span auf einem Hard Negative, der keinen FP-Span der Basis in derselben Zeile schneidet |
| `latency:100k_p95_ms` | 100-KiB-p95 des Heads > 1,10 × Basis + 0,25 ms (nur Dev, siehe [Latenz](#latenz-und-durchsatz)) |
| `latency:budget_100k_p95_ms` | Head über dem H03-Budget von 10 ms, obwohl die Basis darunter liegt |

Provider-Werte und Attribution werden berichtet, aber nicht gegated. Beide Seiten werden mit der
Taxonomie des Heads bewertet; das `extended`-Profil nutzt die Opt-in-Regeln der jeweils eigenen
Entity-Map. Die Latenz-Checks misst `latency.py` nach allen Vorhersagen auf den Dev-Workloads
(siehe unten); der Holdout spielt dafür keine Rolle.

**Ausgabe.** stdout nennt Head, Basis und Build-Schlüssel, die Dev-Tabelle (F1 je Gruppe und
Content-Klasse, Attribution, geänderte Provider), Dev-FP und Dev-Regressionen. Für den Holdout
steht dort nur `holdout: no regression` bzw. `holdout: regression`, und zuletzt
`scoreboard: PASS|FAIL`. Vor dem Dev-Urteil steht eine Zeile `dev latency: 100 KiB p95 … ms`
mit dem Durchsatz auf dem 10-MiB-Repo. Bei Erfolg übernimmt der Runner die letzten 15 Zeilen in den Gate-Bericht,
bei Misserfolg nur den Exit-Code. Die vollständigen Berichte beider Splits (Head, Basis, Checks)
liegen unter `CACHE/scoreboard/reports/<head>-<basis>/{dev,holdout}.json`, die Latenzmessung in
`latency.json`. Sie verlassen die Sandbox nicht.

## Latenz und Durchsatz

`latency.py` misst ARK gegen gitleaks, TruffleHog und detect-secrets auf vier Workloads und
liefert die 100-KiB-Checks des Scoreboard-Gates.

```bash
.venv/bin/python scripts/l1_dlp/latency.py bench --dev $ARK_L1_DEV_DATA \
    --detect-secrets-python ~/ark-dlp/baselines-venv/bin/python --output latency.json
    # [--tools ark,gitleaks,trufflehog,detect-secrets] [--sizes short,4k,100k,repo] [--rounds 5]
    # [--invocations 8] [--cpus 1] [--package BUILD/pkg] [--bin-dir DIR]
```

**Workloads.** Sie entstehen deterministisch aus einem eingefrorenen Dev-Split (Reihenfolge
`sha256(id)`), nie aus dem Holdout:

| Workload | Inhalt |
|---|---|
| `short` | 256 Carrier-Zeilen, wie sie sind (`.env`, YAML, CLI, Prosa …; Positive und Hard Negatives) |
| `4k` | 64 Dokumente mit genau 4 096 Byte UTF-8 |
| `100k` | 32 Dokumente mit genau 102 400 Byte UTF-8 |
| `repo` | ein Repository mit genau 10 MiB: Benign-Code-Dateien mit ihrem Pfad, je 64 KiB eine Carrier-Datei |

`4k` und `100k` bestehen aus 4-KiB-Blöcken, jeder mit einer Carrier-Zeile am Anfang und danach
Benign-Code (`kind: code`). Ein angeschnittenes Zeichen wird zu Leerzeichen, die Bytegrößen bleiben
exakt. Der Bericht nennt je Workload Dokumente, Bytes und einen Digest, nie Text.

**Messung.** Alle Prozesse laufen auf denselben CPUs (`--cpus`, Standard 1: die letzte erlaubte
CPU; `0` = ohne Pinning), auch Go-Tools mit eigener Parallelität.

| Tool | gemessen | Felder |
|---|---|---|
| ARK | in einem Worker-Prozess mit dem Modul des Builds (`--package`, sonst das installierte): `SecurityGateway(categories=["dlp"], max_level="l1").scan_category("dlp", text)` im Default-Profil, nach einem Warm-up | `p50/p95/p99/mean/max_ms` je Dokument, `mib_per_s` (Median-Runde), `end_to_end_mib_per_s` (plus ein Prozessstart), `startup_ms` (Import + Regelkompilierung) |
| gitleaks, TruffleHog | gepinntes Binary mit den Aufrufen von `run_baselines.py` (Default-Profil, TruffleHog `--no-verification`) | `startup_ms` (Median aus 3 Läufen auf einer leeren Datei), je Workload ein Lauf über alle Dokumente: `end_to_end_mib_per_s`, `mib_per_s` (abzüglich Start), `per_doc_ms`; dazu `invocation.p50/p95_ms`: ein Prozess je Dokument für die ersten `--invocations` Dokumente (inkl. Start) |
| detect-secrets | `scan_file` mit `default_settings()` je Datei in einem Prozess des Baseline-Venv (wie `scan --all-files`, aber einprozessig) | wie oben, dazu `errors` |

detect-secrets' CLI bricht den ganzen Scan ab, wenn ein Plugin auf einer Datei eine Ausnahme
wirft (im Dev-Repo ein YAML-Datum, das es nicht parsen kann). Der Worker zählt solche Dateien in
`errors` und scannt weiter. `mib_per_s` der Baselines ist eine Schätzung (Lauf minus Median-Start) und bei
`short`/`4k`, wo der Start den Lauf dominiert, unzuverlässig; maßgeblich ist dort `end_to_end_mib_per_s`. Die Pins prüft `bench` wie `run_baselines.py versions`. stdout zeigt
eine Markdown-Tabelle: Für ARK stehen dort die p50/p95 im Prozess, für die Baselines die p50/p95 je
Aufruf.

**Gate.** `scoreboard.py gate` ruft `gate_check` nach allen Vorhersagen auf. Teilen Head und Basis
einen Build, misst es nichts. Sonst laufen zwei Worker (Basis und Head) auf derselben CPU. Die
Runden wechseln sich ab (Basis, Head, Head, Basis …): `short` 2, `4k` 3, `100k` 16, `repo` 2.
Gegated wird nur die 100-KiB-p95 (`TOLERANCE` 10 %, `SLACK_MS` 0,25 ms gegen Timer-Rauschen,
`BUDGET_MS` 10 ms aus H03/M4). Das Budget greift erst, wenn die Basis es einhält. Fällt ein Check
durch, misst `gate_check` ein zweites Mal. Er scheitert nur, wenn er in beiden Messungen
durchfällt. Zwei identische Builds lagen auf der VPS in fünf Läufen zwischen −2,7 % und +7,0 %.
