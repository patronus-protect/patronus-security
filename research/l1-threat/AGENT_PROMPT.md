# Agent-Prompt für geplante L1-Threat-Läufe

`runner/run.sh --program threat` stellt diesen Text dem Agenten voran und hängt die Aufgabe des Laufs an.
Der Agent läuft auf der VPS in einer systemd-Sandbox in einem eigenen Klon: Schreibzugriff nur
auf den Klon, den Cargo-Cache und `~/.claude`; kein sudo, kein GitHub-Zugang, kein Holdout.

---

> Der Detektor-Code liegt im Crate `patronus-ark-core` unter `ark-core/src/` (Injection unter
> `ark-core/src/detectors/injection/`, Shell-Risiko K26 unter `ark-core/src/detectors/shell/`, Lexika in
> `ark-core/src/detectors/anchor_lexicons/`). Bis X02 liegt der Threat-Detektor noch unter
> `rust/src/detectors/threat`; neuer Detektor-Code entsteht nur in `ark-core`.
> Ändere nie Dateien unter `.github/` (Workflows): der Runner-Token darf sie nicht pushen. Ein roter `validate`-Job (ARK-API-Image, Toolchain-Installation) ist kein Fehler deiner Änderung; ignoriere ihn.
> Warten auf eigene Hintergrundjobs: mit `wait <PID>` oder einer PID-Datei, nie mit `pgrep -f <muster>` in einer Schleife — die Schleife selbst enthält das Muster in ihrer Kommandozeile und wartet sonst endlos.
> Keine Warteschleifen auf Ausgabedateien von Hintergrund-Tasks (z. B. `until grep -q "^exit " …/tasks/*.output`): ein abgebrochener oder fertiger Task schreibt `[exited with code N]`, das Muster trifft nie, und `claude -p` endet erst, wenn alle eigenen Hintergrundjobs beendet sind — die Runde hängt dann bis zum harten Sandbox-Ende. Beende vor der Schlussantwort alle eigenen Hintergrundjobs (`kill`), auch abgebrochene Wächter.

Du arbeitest an Patronus ARK (Rust-Scanner). Programmziel: ARK erkennt Angriffe auf LLMs und Agents
auf L1 (CPU, ohne Transformer) in den elf Klassen aus `research/l1-threat/README.md`
(`instruction_injection`, `jailbreak`, `prompt_extraction`, `tool_poisoning`, `agent_config_tampering`,
`memory_poisoning`, `exfiltration`, `unsafe_action`, `resource_exhaustion`, `harmful_content`,
`toxic_language`) und ist gegen die offenen heuristischen Baselines und klassische kleine ML-Verfahren
(TF-IDF/Zeichen-n-Gramme + LogReg, lineare SVM, NB-SVM) messbar besser, auf Deutsch deutlich. Nur
Eingabe-Scanning; L2/L3-Modelle werden nicht geändert oder neu trainiert, nur ihre Labels gemappt.
Du erledigst in diesem Lauf genau die unten angehängte Aufgabe, keine weitere.

1. Lies `research/l1-threat/README.md`, deine Aufgabe samt „Shared acceptance“ in
   `research/l1-threat/backlog.yaml`, die Kategorie-Dokumente unter `research/l1-threat/categories/`
   für deine Klasse, `research/l1-threat/research-2026-11.md` und den betroffenen Code. Ist die
   Aufgabe `TRIAGE`: nur Scoreboard-Fehleranalyse, neue Aufgaben `Txx` am passenden Platz in
   `backlog.yaml` einfügen, nichts implementieren.
2. Testbereich zuerst, als eigener Commit: Goldens über
   `python/patronus_ark/benchmark_data/generate_l1_goldens.py` (≥ 5 Positive + 5 Hard Negatives je
   Sprache, DE + EN, regenerierte JSONL einchecken) in realistischen Carriern (Chat, E-Mail, Webseite,
   Dokument, Tool-/MCP-Beschreibung, Agent-Konfiguration, Code, Log). Hard Negatives: defensive Prompts,
   Zitate und Sicherheitsdokumentation, Tutorials, Testcode, Verneinung. Dazu Rust-Unit-Tests. Bei
   Infrastruktur- und Mapping-Aufgaben: Tests für das neue Werkzeug (`scripts/tests`).
3. Implementieren im Stil des Repos, in Schichten: ein Core (Normalisierung, Tokenizer, Anker,
   Struktur, Kontext) → Pattern-Logik je Kategorie → L1-Modelle über Pattern-Ausgaben/Facts →
   Cedar-Policies über Facts (Vorbild K26: `ark-core/src/detectors/shell/`). Jede Regel nennt ihre
   Familie in `research/l1-threat/taxonomy.yaml` (sobald M01 da ist) und bekommt einen Literal- oder
   Struktur-Prefilter; Regexe einmal kompilieren (`LazyLock`/`OnceLock`), linear und begrenzt. Nie eine
   Schwelle senken, um Recall zu kaufen; Recall kommt aus Regeln, Ankern, Struktur. Geerntete
   OSS-Regeln (nur MIT/Apache, nie AGPL) stehen mit Upstream-Repo, Commit und Regel-ID im Katalog und
   sind default aus. CHANGELOG-Eintrag mit „Detection change“, Doku über `scripts/generate_docs.py`.
4. Selbst prüfen (`CARGO_TARGET_DIR` ist gesetzt): `cargo fmt --all`,
   `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test -p patronus-ark-core -p patronus-ark`,
   `cd rust && cargo run --example 13_l1_golden_eval -- all`,
   Python-Tests wie in der CI (`.venv` im Worktree, `pip install -r requirements-test.txt`,
   `VIRTUAL_ENV=$PWD/.venv .venv/bin/python -m maturin develop --manifest-path python/Cargo.toml`,
   `.venv/bin/python -m unittest discover -s python/tests`,
   `cargo build --locked -p ark-api --bin ark-api-entrypoint`, `.venv/bin/python -m pytest scripts/tests -q`),
   `python3 scripts/generate_docs.py --check`. Dev-Daten liegen unter `$ARK_L1_DEV_DATA`.
5. Alles committen (Conventional Commits, Trailer
   `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`). Nicht pushen. Den Status in
   `backlog.yaml` nicht ändern; das macht der Runner.
6. Antworte zum Schluss mit drei Zeilen: Aufgabe, was geändert wurde, was offen ist. Diese drei Zeilen und alle Commit-Messages auf Englisch (sie landen im PR).

Regeln für Inhalte:
- Öffentliche Texte (README, `docs/`, CHANGELOG-Einträge, Docstrings) schreibst du für Nutzer von
  außen: keine Meilenstein- oder Aufgaben-IDs (M1–M4, T12, X02, IJ01 …) und kein Forschungsjargon
  (Dev-Split, Holdout, Source-Familie, Rohsicht); sag in Worten, was sich für den Nutzer ändert. Die
  IDs gehören nur in `research/` und in Commit-Messages.
- Keine funktionierenden Schadanleitungen, keine Angriffs-Payloads aus Datensätzen kopiert, keine
  Klartext-Listen von Beleidigungen (Toxizitäts-Lexika nur gehasht). Goldens zeigen die Form eines
  Angriffs, nicht einen wirksamen Inhalt.
- Datensätze Dritter nur zur Auswertungszeit laden (Registry mit Quelle, Lizenz, Commit), nie
  einchecken. Übersetzungen ins Deutsche machst du selbst (kein externer MT-Dienst) und markierst sie
  als `ark_authored`.
- Lade oder suche nie die Quellen des Holdouts (siehe README „Herkunft“ und `entity_map.yaml`), auch
  nicht über das Netz. Keine Netzwerkzugriffe im Detektor.
- Punkte: Regel-/Ankergewichte ≥ 0, Dämpfung ≤ 0, n-Gramm-Anteil gedeckelt, ganzzahlig; Python-Training
  und Rust-Inferenz bitgleich (Golden-Paritätsfälle).

Abgegeben wird nur fertige Arbeit: Der PR muss mergebar sein, ohne Verschlechterung an
irgendeiner Stelle. Nach dem Gate muss zusätzlich die GitHub-CI auf dem Branch grün sein, sonst
gibt es keinen PR und du bekommst das CI-Log.

Nach deinem Lauf prüft ein unabhängiges Gate (dieselben Checks, ab E06 zusätzlich das
Threat-Scoreboard auf einem verborgenen Holdout: keine Regression > 0,5 pp TPR@1 % FPR je Klasse, keine
neuen FP auf Hard Negatives, L1-Latenz 100 KiB p95 höchstens +5 %). Ist es rot, bekommst du den Bericht
und eine weitere Runde. Suche oder lies keine Holdout-Daten, ändere nichts außerhalb des Worktrees.
