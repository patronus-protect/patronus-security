# Agent-Prompt für Review-Läufe (L1-PII und L1-DLP)

`runner/run.sh` stellt diesen Text dem Agenten voran, wenn `ark-l1 next` einen offenen Stack-PR mit
unaufgelösten Review-Threads (Codex, CodeQL, Menschen) oder roter CI findet. Ein solcher PR ist nicht
mergebar (`main` verlangt grüne Checks und aufgelöste Threads), deshalb kommt er vor jeder neuen
Backlog-Aufgabe. Sandbox und Gate sind dieselben wie bei normalen Läufen.

---

> Seit #172 (2026-10-25) liegt der Detektor-Code im Crate `patronus-ark-core` unter `ark-core/src/` (z. B. `ark-core/src/detectors/pii/`, `ark-core/src/detectors/dlp/`, Lexika in `ark-core/src/detectors/anchor_lexicons/`), die zweisprachige Fixture unter `ark-core/tests/fixtures/l1_bilingual_rules.json`. Die PII/DLP-Integrationstests bleiben in `rust/tests/`. Ältere Pfadangaben in `backlog.yaml` (`rust/src/detectors/...`) entsprechen den neuen Orten.

Du arbeitest an Patronus ARK. In diesem Lauf implementierst du keine neue Aufgabe: Du behebst die
Review-Findings und/oder die rote CI des unten genannten PRs, auf seinem eigenen Branch. Der Klon steht
auf dem aktuellen Head des PRs. Die Threads (`threads`) und das Log der roten CI (`ci_failure`) stehen
in der Aufgabe unten.

1. Jedes Finding prüfen: Ist es berechtigt? Lies den betroffenen Code, die Tests und die Doku.
   - **Berechtigt:** zuerst ein Regressionstest im passenden bestehenden Testfile, der ohne Fix
     fehlschlägt (DE + EN, wo sinnvoll), dann der Fix im Stil des umgebenden Codes. Validatoren nie
     lockern, um Recall zu kaufen.
   - **Nicht berechtigt:** keinen Code ändern, nur eine Begründung in die Notiz (Schritt 4).
     Dokumentiere das erwartete Verhalten trotzdem mit einem Test, falls noch keiner existiert.
   - **CodeQL „Cleartext logging“ in Tests:** den Rohwert aus der Assert-/Panic-Meldung entfernen,
     die Assertion selbst behalten.
2. **Rote CI:** Das Log in `ci_failure` lesen, den fehlschlagenden Schritt wie in
   `.github/workflows/ci.yml` lokal nachstellen und die Ursache beheben (nicht den Test abschwächen,
   außer der Test prüft nachweislich etwas Falsches – dann begründen).
3. CHANGELOG.md: Bei geänderter Erkennung ein Bullet mit **Detection change:** (welche Modi), direkt
   unter dem Eintrag der Aufgabe dieses PRs. Erzeugte Dateien (Goldens, Doku) neu erzeugen statt von
   Hand ändern (`generate_l1_goldens.py`, `python3 scripts/generate_docs.py`).
4. Notizen für die Thread-Antworten: Schreibe `.git/ark-review.json` (nicht committen) als JSON-Objekt
   `{"<thread id>": "<1–3 Sätze auf Englisch: was geändert wurde bzw. warum nicht>"}`. Der Runner
   antwortet damit in jedem Thread mit dem Commit und löst ihn auf.
5. Selbst prüfen wie in normalen Läufen (`cargo fmt --all`,
   `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test -p patronus-ark-core -p patronus-ark`,
   Golden-Eval des Programms, Python-Tests, `python3 scripts/generate_docs.py --check`).
6. Alles committen (mindestens ein Commit: Fix oder Test; Conventional Commits auf Englisch, Trailer
   `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`). Nicht pushen, nicht rebasen, die
   bestehenden Commits des PRs nicht umschreiben. `backlog.yaml` nicht ändern.
7. Antworte zum Schluss mit drei Zeilen auf Englisch: PR, je Finding behoben/begründet, was offen ist.

Danach prüft dasselbe unabhängige Gate wie sonst (Scoreboard gegen den PR-Stand vor deinem Fix) und
die GitHub-CI. Ist etwas rot, bekommst du den Bericht und eine weitere Runde. Suche oder lies keine
Holdout-Daten, ändere nichts außerhalb des Worktrees.
