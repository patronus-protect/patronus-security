# Agent-Prompt für Restack-Läufe (L1-PII und L1-DLP)

`runner/run.sh` stellt diesen Text dem Agenten voran, wenn `ark-l1 next` einen offenen Stack-Branch
nicht konfliktfrei auf seine neue Basis rebasen konnte (Parent gemergt oder `main` bewegt). Sandbox
und Gate sind dieselben wie bei normalen Läufen.

---

> Seit #172 (2026-10-25) liegt der Detektor-Code im Crate `patronus-ark-core` unter `ark-core/src/` (z. B. `ark-core/src/detectors/pii/`, `ark-core/src/detectors/dlp/`, Lexika in `ark-core/src/detectors/anchor_lexicons/`), die zweisprachige Fixture unter `ark-core/tests/fixtures/l1_bilingual_rules.json`. Die PII/DLP-Integrationstests bleiben in `rust/tests/`. Ältere Pfadangaben in `backlog.yaml` (`rust/src/detectors/...`) entsprechen den neuen Orten.

Du arbeitest an Patronus ARK. In diesem Lauf implementierst du nichts Neues: Du rebast genau den
unten genannten Stack-Branch auf seine neue Basis und löst die Konflikte. Der Klon steht auf dem
alten Stand des Branches.

1. `git rebase --onto <onto> <old_base>` mit den Werten aus der Aufgabe unten. Keine Merge-Commits,
   kein `--strategy ours/theirs` über ganze Dateien, keinen Commit des Branches weglassen.
2. Konflikte so lösen, dass beide Seiten erhalten bleiben: die Änderung der neuen Basis und die
   Änderung des Branches. Typische Fälle:
   - `research/*/backlog.yaml`: Vereinigung aller `status: done` und aller neuen Aufgaben, Reihenfolge
     der neuen Basis.
   - `CHANGELOG.md`: beide Einträge behalten, der des Branches unter dem der Basis.
   - Goldens, `ark-core/tests/fixtures/*.json`, `rust/tests/fixtures/*.json`, Regeltabellen: beide Fälle bzw. Regeln behalten; erzeugte
     Dateien (Goldens-JSONL, Doku) neu erzeugen statt von Hand mergen
     (`generate_l1_goldens.py`, `python3 scripts/generate_docs.py`).
   - Code: die Absicht beider Seiten nachbauen. Ist ein Konflikt inhaltlich nicht auflösbar (beide
     Seiten ändern dieselbe Regel gegensätzlich), gewinnt die neue Basis und die Branch-Änderung wird
     darauf neu umgesetzt.
3. Nach jedem Konflikt `git add` und `git rebase --continue` mit der ursprünglichen Commit-Message.
   Passt eine Message durch die Auflösung nicht mehr, nur ergänzen, nicht umschreiben.
4. Selbst prüfen wie in normalen Läufen (`cargo fmt --all`,
   `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test -p patronus-ark-core --no-default-features`, `cargo test -p patronus-ark-core --features wolf`, `cargo test -p patronus-ark-core --features download`, `cargo test -p patronus-ark`,
   Golden-Eval des Programms, Python-Tests, `python3 scripts/generate_docs.py --check`). Was du dabei
   reparieren musst, kommt als eigener Commit `fix(restack): …` ans Ende.
5. Ende: `HEAD` ist der rebaste Branch, der Arbeitsbaum ist sauber, kein Rebase läuft mehr. Nicht
   pushen. `backlog.yaml` nur im Rahmen der Konfliktlösung ändern.
6. Antworte zum Schluss mit drei Zeilen auf Englisch: Branch, welche Konflikte wie gelöst wurden,
   was offen ist.

Danach prüft dasselbe unabhängige Gate wie sonst (inklusive Scoreboard gegen die neue Basis). Ist es
rot, bekommst du den Bericht und eine weitere Runde. Suche oder lies keine Holdout-Daten, ändere
nichts außerhalb des Worktrees.
