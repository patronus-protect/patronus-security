# L1-DLP-Messwerkzeuge

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
