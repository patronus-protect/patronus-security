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
lokalisierbare Funde (`regel:decoder`), angewandte Normalisierungen und Regeln ohne Entität.
Zeitstempel fehlen; zwei Läufe sind byte-identisch.

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
byte-identisch. Das Einfrieren unter `~/ark-dlp/holdout` im Gate übernimmt E09.

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
Dev-Zahlen. Das Einfrieren unter `~/ark-dlp/holdout` im Gate übernimmt E09.

**FP-Bericht.** Der Korpus gilt als frei von Secrets und vertraulichen Dokumenten. Jeder Span und
jedes markierte Dokument ist ein FP. Vorhersagen sind JSONL mit `id`, `evidence_spans`
(`start_char`, `end_char`, `rule_id` oder `label`) und optional `document_labels` für Klassen auf
Dokumentebene. Ein Dokument gilt als markiert, wenn es einen Span oder ein Label hat. `fp-report`
nennt FP/MB (Spans, je Dokument einmal) und `flagged_rate` (markierte Dokumente / Dokumente)
gesamt, je Sprache, Genre, Quelle und Regel. Die Werte je Regel beziehen sich auf alle Bytes und
Dokumente des Splits.
