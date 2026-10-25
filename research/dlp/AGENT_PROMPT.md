# Agent-Prompt für geplante L1-DLP-Läufe

`runner/run.sh --program dlp` stellt diesen Text dem Agenten voran und hängt die Aufgabe des Laufs an.
Der Agent läuft auf der VPS in einer systemd-Sandbox in einem eigenen Klon: Schreibzugriff nur
auf den Klon, den Cargo-Cache und `~/.claude`; kein sudo, kein GitHub-Zugang, kein Holdout.

---

> Seit #172 (2026-10-25) liegt der Detektor-Code im Crate `patronus-ark-core` unter `ark-core/src/` (z. B. `ark-core/src/detectors/pii/`, `ark-core/src/detectors/dlp/`, Lexika in `ark-core/src/detectors/anchor_lexicons/`), die zweisprachige Fixture unter `ark-core/tests/fixtures/l1_bilingual_rules.json`. Die PII/DLP-Integrationstests bleiben in `rust/tests/`. Ältere Pfadangaben in `backlog.yaml` (`rust/src/detectors/...`) entsprechen den neuen Orten.

Du arbeitest an Patronus ARK (Rust-Scanner). Programmziel: den L1-DLP-Detektor besser als gitleaks,
TruffleHog und detect-secrets machen und deutlich mehr Kategorien abdecken (Secrets, Zugangsdaten,
Schlüsselmaterial, sensible Dokumentklassen). Du erledigst in diesem Lauf genau die unten angehängte
Aufgabe, keine weitere.

1. Lies `research/dlp/README.md`, deine Aufgabe samt „Gemeinsame Akzeptanz“ in
   `research/dlp/backlog.yaml` und den betroffenen Code (`ark-core/src/detectors/dlp/`,
   `ark-core/src/detectors/anchor_lexicons/dlp.json`). Ist die Aufgabe `TRIAGE`: nur
   Scoreboard-Fehleranalyse, neue Aufgaben `Txx` am passenden Platz in `backlog.yaml` einfügen,
   nichts implementieren.
2. Testbereich zuerst, als eigener Commit: Goldens über
   `python/patronus_ark/benchmark_data/generate_l1_goldens.py` (≥ 5 Positive + 5 Hard Negatives je
   Sprache, DE + EN, regenerierte JSONL einchecken), eingebettet in realistische Carrier (.env, YAML,
   JSON, Code, Log, CLI, Prosa). Hard Negatives: Platzhalter, Env-/Template-Referenzen,
   dokumentierte Beispielwerte, Testschlüssel, Hashes/UUIDs/Digests. Dazu
   `ark-core/tests/fixtures/l1_bilingual_rules.json` und Rust-Tests mit gültigen und ungültigen
   Struktur-/Prüfsummen-Vektoren. Bei Infrastruktur-Aufgaben: Tests für das neue Werkzeug.
3. Implementieren im Stil des Repos (Vorbild: Commits b7b6763, 5a5f7b4): Regex verschärfen +
   Validator/Kontext. Validatoren nie lockern, um Recall zu kaufen. Jede neue Provider-Regel bekommt
   eine Formatquelle in `research/dlp/rule_sources.yaml` (Hersteller-Doku oder gitleaks-Regel-ID);
   ohne belegbare Quelle kein eigenes Format, sondern Kontextregel oder Hinweis in der Antwort. Neue
   Content-/Dokumentklassen bleiben default aus. CHANGELOG-Eintrag mit „Detection change“, Doku über
   `scripts/generate_docs.py`.
4. Selbst prüfen (`CARGO_TARGET_DIR` ist gesetzt): `cargo fmt --all`,
   `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test -p patronus-ark-core -p patronus-ark`,
   `cd rust && cargo run --example 13_l1_golden_eval -- dlp`,
   Python-Tests wie in der CI (`.venv` im Worktree, `pip install -r requirements-test.txt`,
   `VIRTUAL_ENV=$PWD/.venv .venv/bin/python -m maturin develop --manifest-path python/Cargo.toml`,
   `.venv/bin/python -m unittest discover -s python/tests`,
   `cargo build --locked -p ark-api --bin ark-api-entrypoint`, `.venv/bin/python -m pytest scripts/tests -q`),
   `python3 scripts/generate_docs.py --check`. Dev-Daten liegen unter `$ARK_L1_DEV_DATA`.
5. Alles committen (Conventional Commits, Trailer
   `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`). Nicht pushen. Den Status in
   `backlog.yaml` nicht ändern; das macht der Runner.
6. Antworte zum Schluss mit drei Zeilen: Aufgabe, was geändert wurde, was offen ist. Diese drei Zeilen und alle Commit-Messages auf Englisch (sie landen im PR). Keine
   Secret-Werte in der Antwort, auch keine synthetischen.

Regeln:
- Nur synthetische Secret-Werte aus dem Generator (`python/patronus_ark/dlp_synth/`, ab E03). Nie
  echte, geleakte oder live-gültige Secrets verwenden, suchen oder erzeugen; keine Klartext-Tokens mit
  gültiger Prüfsumme committen (ab E02 speichern Goldens Generator-Rezepte).
- Keine Netzwerkzugriffe im Detektor, keine Live-Verifikation von Secrets bei Providern.

Abgegeben wird nur fertige Arbeit: Der PR muss mergebar sein, ohne Verschlechterung an
irgendeiner Stelle. Nach dem Gate muss zusätzlich die GitHub-CI auf dem Branch grün sein, sonst
gibt es keinen PR und du bekommst das CI-Log.

Nach deinem Lauf prüft ein unabhängiges Gate (dieselben Checks plus DLP-Scoreboard auf einem
verborgenen Holdout: keine Regression > 0,5 pp F1, FP/MB auf Benign-Code nicht höher, keine neuen FP
auf Hard Negatives, Latenzbudget). Ist es rot, bekommst du den Bericht und eine weitere Runde. Suche
oder lies keine Holdout-Daten, ändere nichts außerhalb des Worktrees.
