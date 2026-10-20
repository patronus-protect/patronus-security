# Agent-Prompt für geplante L1-PII-Läufe

`runner/run.sh` stellt diesen Text dem Agenten voran und hängt die Aufgabe des Laufs an.
Der Agent läuft auf der VPS in einer systemd-Sandbox in einem eigenen Klon: Schreibzugriff nur
auf den Klon, den Cargo-Cache und `~/.claude`; kein sudo, kein GitHub-Zugang, kein Holdout.

---

Du arbeitest an Patronus ARK (Rust-PII-Scanner). Programmziel: den L1-PII-Detektor besser als
Microsoft Presidio machen und deutlich mehr Kategorien abdecken. Du erledigst in diesem Lauf genau
die unten angehängte Aufgabe, keine weitere.

1. Lies `research/l1-pii/README.md`, deine Aufgabe samt „Gemeinsame Akzeptanz“ in
   `research/l1-pii/backlog.yaml` und den betroffenen Code.
2. Testbereich zuerst, als eigener Commit: Goldens über
   `python/patronus_ark/benchmark_data/generate_l1_goldens.py` (≥ 5 Positive + 5 Hard Negatives je
   Sprache, regenerierte JSONL einchecken), `rust/tests/fixtures/l1_bilingual_rules.json`, Rust-Tests
   mit gültigen und ungültigen Prüfziffer-Vektoren. Bei Infrastruktur-Aufgaben: Tests für das neue
   Werkzeug.
3. Implementieren im Stil des Repos (Vorbild: Commits b7b6763, 5a5f7b4). Validatoren nie lockern,
   um Recall zu kaufen. CHANGELOG-Eintrag mit „Detection change“, Doku über
   `scripts/generate_docs.py`.
4. Selbst prüfen (`CARGO_TARGET_DIR` ist gesetzt): `cargo fmt --all`,
   `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test -p patronus-ark`,
   `cd rust && cargo run --example 13_l1_golden_eval -- pii`,
   Python-Tests wie in der CI (`.venv` im Worktree, `pip install -r requirements-test.txt`,
   `VIRTUAL_ENV=$PWD/.venv .venv/bin/python -m maturin develop --manifest-path python/Cargo.toml`,
   `.venv/bin/python -m unittest discover -s python/tests`,
   `cargo build --locked -p ark-api --bin ark-api-entrypoint`, `.venv/bin/python -m pytest scripts/tests -q`),
   `python3 scripts/generate_docs.py --check`. Dev-Daten liegen unter `$ARK_L1_DEV_DATA`.
5. Alles committen (Conventional Commits, Trailer
   `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`). Nicht pushen. Den Status in
   `backlog.yaml` nicht ändern; das macht der Runner.
6. Antworte zum Schluss mit drei Zeilen: Aufgabe, was geändert wurde, was offen ist. Diese drei Zeilen und alle Commit-Messages auf Englisch (sie landen im PR).

Abgegeben wird nur fertige Arbeit: Der PR muss mergebar sein, ohne Verschlechterung an
irgendeiner Stelle. Nach dem Gate muss zusätzlich die GitHub-CI auf dem Branch grün sein, sonst
gibt es keinen PR und du bekommst das CI-Log.

Nach deinem Lauf prüft ein unabhängiges Gate (dieselben Checks plus Scoreboard auf einem verborgenen
Holdout, keine Regression > 0,5 pp F1, keine neuen FP auf Hard Negatives). Ist es rot, bekommst du
den Bericht und eine weitere Runde. Suche oder lies keine Holdout-Daten, ändere nichts außerhalb des
Worktrees.
