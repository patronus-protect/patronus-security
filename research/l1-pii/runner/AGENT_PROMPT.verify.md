# Agent-Prompt für Verify-Läufe (L1-PII und L1-DLP)

`runner/run.sh` stellt diesen Text dem Agenten voran, wenn `ark-l1 next` einen mergebaren, grünen
Stack-PR mergen würde, der `ark-core/` ändert und für seinen exakten Head noch kein bestandenes Verify
hat (`VERIFY:<branch>`). Vor deiner Runde misst der Runner selbst ein ruhiges Latenz-A/B (Head gegen
`main`, unter dem Run-Lock); das Ergebnis steht in der Aufgabe unten (`latency`). Du bekommst genau
eine Runde, kein Gate und keine CI danach.

---

> Seit #172 (2026-10-25) liegt der Detektor-Code im Crate `patronus-ark-core` unter `ark-core/src/` (z. B. `ark-core/src/detectors/pii/`, `ark-core/src/detectors/dlp/`, Lexika in `ark-core/src/detectors/anchor_lexicons/`), die zweisprachige Fixture unter `ark-core/tests/fixtures/l1_bilingual_rules.json`. Die PII/DLP-Integrationstests bleiben in `rust/tests/`. Ältere Pfadangaben in `backlog.yaml` (`rust/src/detectors/...`) entsprechen den neuen Orten.
> Ändere nie Dateien unter `.github/` (Workflows). Ein roter `validate`-Job (ARK-API-Image, Toolchain-Installation) ist kein Fehler der Änderung; ignoriere ihn.
> Warten auf eigene Hintergrundjobs: mit `wait <PID>` oder einer PID-Datei, nie mit `pgrep -f <muster>` in einer Schleife — die Schleife selbst enthält das Muster in ihrer Kommandozeile und wartet sonst endlos.
> Keine Warteschleifen auf Ausgabedateien von Hintergrund-Tasks (z. B. `until grep -q "^exit " …/tasks/*.output`): ein abgebrochener oder fertiger Task schreibt `[exited with code N]`, das Muster trifft nie, und `claude -p` endet erst, wenn alle eigenen Hintergrundjobs beendet sind — die Runde hängt dann bis zum harten Sandbox-Ende. Beende vor der Schlussantwort alle eigenen Hintergrundjobs (`kill`), auch abgebrochene Wächter.

Du arbeitest an Patronus ARK, aber in diesem Lauf änderst du nichts: Du prüfst unabhängig, ob der PR
unten so gemergt werden darf. Du hast ihn nicht geschrieben und kennst seine Entstehung nicht; glaube
keiner Behauptung im PR-Text, die du nicht im Code, in den Tests oder im Gate-Bericht belegt findest.
Der Klon steht auf dem Head des PRs (`head`); die Änderung ist `git diff <diff_base>...HEAD`.
In der Aufgabe stehen außerdem der Backlog-Eintrag (`backlog_task`, mit `accept`), der PR-Text mit dem
Gate-Bericht und der Scoreboard-Zusammenfassung (`pr_body`) und das Latenz-A/B (`latency`).

Das ist ein **Sanity-Check, kein Review**. Gate und CI sind schon grün. Suche nicht nach etwas, das
man noch verbessern könnte; die Erwartung ist `pass`. `fail` gibt es nur für einen dieser groben Fehler,
jeweils mit Beleg aus Diff, Tests oder Gate-Bericht:

1. **Aufgabe nicht erledigt:** Ein zentraler Teil der Aufgabe fehlt ganz (nicht: ein Detail ließe sich
   vollständiger machen).
2. **Falsches Ergebnis:** Eine Regel meldet offensichtlich Falsches oder gar nichts, ein Test prüft nicht,
   was er behauptet, oder Zahlen im PR-Text widersprechen dem Gate-Bericht.
3. **Grobe Verletzung der Code-Regeln aus `CLAUDE.md`:** neues Verhalten ganz ohne Test, eine zweite Kopie
   vorhandener Logik, oder auf L1 ein Regex/Automat pro Aufruf kompiliert, I/O oder Lock im Scan.
4. **Leck im öffentlichen Repo:** aus Dev-Gold kopierte Literale, Infrastruktur-Details, Tokens oder
   Secrets.
5. **Latenz:** `latency` meldet eine Regression in jedem Versuch (der Runner trägt sie ohnehin ein).

Alles andere (Stil, Benennung, Doku-Feinheiten, zusätzliche Tests, Randfälle, Ideen) ist kein `fail`;
schreib es nicht als Finding. Ist das ein erneutes Verify nach einem Review-Lauf, prüfe nur, ob die
vorherigen Findings behoben sind und ob dabei ein grober Fehler entstanden ist.

Du darfst bauen und gezielt einzelne Tests ausführen (`cargo test -p <crate> <filter>`, ein einzelnes
Python-Testmodul), aber nicht die ganze Suite. Suche oder lies keine Holdout-Daten, ändere nichts
außerhalb des Worktrees.

**Nicht committen, nicht pushen, keine Datei im Repo ändern.** Der Abschnitt zum Zeitlimit unten gilt
für dich so: Statt zu committen schreibst du dein Verdict früh und aktualisierst es, bis du fertig bist.
Das Verdict steht in `.git/ark-verify.json` (nicht im Arbeitsbaum):

```json
{"verdict": "pass" | "fail",
 "findings": [{"path": "ark-core/src/…", "line": 123, "reason": "1–3 Sätze auf Englisch: was falsch ist und was zu tun ist"}]}
```

- `fail` nur für die groben Fehler oben, mit konkretem Beleg; `path` relativ
  zum Repo, `line` die Zeile im Head (oder `null`). Höchstens 5, die schwersten zuerst.
- Stilfragen, Geschmack und Verbesserungen außerhalb der Aufgabe sind kein `fail`.
- Die Findings werden als Review-Kommentare im öffentlichen PR gepostet und vom nächsten Review-Lauf
  behoben: keine Holdout-Inhalte, keine Secrets, keine Infrastruktur-Details hineinschreiben.

Antworte zum Schluss mit drei Zeilen auf Englisch: PR, Verdict, die wichtigsten Findings.
