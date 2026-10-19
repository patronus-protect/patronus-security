# L1-PII: Presidio übertreffen

Stand: 2026-10-11. Aufgabenliste: [`backlog.yaml`](backlog.yaml). Agent-Prompt:
[`AGENT_PROMPT.md`](AGENT_PROMPT.md), Runner: [`runner/`](runner/).

## Ausgangslage

- `rust/src/detectors/pii/pii.rs`: 37 Regeln → 30 Labels, nur DE/EN, jeder Treffer `score: 1.0`.
- Hohe Präzision, schwacher Recall, weil viele Regeln einen Feldnamen direkt am Wert verlangen.
  Gretel-Finance (exact span F1): IP .97 · IBAN .83 · PAN .60 · Telefon .59 · SSN .54 · DOB .54 ·
  BIC .50 · Pass .44 · Username .08 · Führerschein 0.
- Fehlende Prüfziffern: KVNR, RVNR, Personalausweis/Pass (MRZ), LANR. Keine regionale Telefonprüfung.
- Kein gemessener Presidio-Vergleich. `13_l1_golden_eval` läuft nicht in CI; `12_l1_pii_fixture_eval`
  vergleicht Byte- mit Zeichen-Offsets.

## Definition „besser als Presidio“

Gemessen auf einem eingefrorenen Holdout, den der Agent nie sieht (nur auf der VPS unter `~/ark-l1/holdout`,
SHA-gepinnt). Presidio läuft in zwei Profilen: `default` und `tuned` (spaCy `en_core_web_lg` +
`de_core_news_lg`, Kontext-Enhancer, DE-Recognizer-Konfiguration).

| Meilenstein | Kriterium |
|---|---|
| M1 Parität EN | Je gemeinsamer Pattern-Entität: F1(ARK) ≥ F1(Presidio tuned) |
| M2 DE/EU | Macro-F1 ≥ Presidio tuned + 15 pp |
| M3 Breite | ≥ 3× so viele prüfziffervalidierte Entitäten wie Presidio |
| M4 Latenz | 100 KiB p95 ≤ 10 ms; Presidio auf derselben Maschine gemessen |
| Immer | FP auf Hard Negatives ≤ Presidio; keine Entität verliert > 0,5 pp F1 |

PERSON/LOCATION/ORG/NRP sind kein L1-Scope; dort tritt L1 + `dynamic-pii` (GLiNER L3) an.

Welche Entität zu welchem Kriterium zählt, legt [`entity_map.yaml`](entity_map.yaml) fest: jede
Benchmark-ID mit ARK-Labels, Presidio-Entitäten, Korpus-Labels und Scope (`shared` → M1/„Immer“,
`ark_only`, `presidio_only`, `semantic` → kein L1-Scope). Prüfung:
`python3 scripts/l1_presidio/entity_map.py check`.

## Gold-Konvention: Platzhalter-Werte

Entschieden am 2026-10-14 (T01, TRIAGE 2026-W42 Bucket 5): Reservierte Platzhalter sind PII und im
Gold **positiv**. Ein Text kann sie aus einer echten Vorlage, einem Test oder einem Leak übernommen
haben; ein Scanner sieht ihnen das nicht an.

- **E-Mail:** Adressen auf RFC-2606/6761-Namen (`example.com|net|org`, Subdomains davon, TLDs
  `.example`, `.invalid`, `.test`, `.localhost` mit mindestens einem Label davor) → `EMAIL`.
  Beispiele: `customer@example.com`, `mira.linden@kundenbeispiel.invalid`, `dev@app.localhost`.
- **Telefon:** NANP-Fiktivnummern `NXX-555-01xx` und `+1 000-000-0000` → `PHONE`.
- **Gegen-Kontext ändert das nicht:** „Template text“, „These are placeholders“ machen einen
  formgültigen Platzhalter nicht zum Hard Negative.
- **Die Form entscheidet weiterhin:** Hard Negatives bleiben Werte, die keine Werte des Labels sind:
  verschleiert (`user [at] example [dot] com`, `name @ domain . test`), maskiert (`+49 (0) XXX XXXXXXX`),
  Host ohne Domain-Suffix (`anna.beispiel@mailserver`), ungültige Ländervorwahl (`+00 0000000`).
  Bei Kennungen mit Validator (SSN-Bereich `000`, NINO-Präfix `BG`, Steuernummer `000/000/00000`)
  gilt, was der Herausgeber nie vergibt, weiter als negativ; Validatoren werden nicht gelockert.
- **Dokumentations-IPs** (`203.0.113.0/24`, `2001:db8::/32`) sind in `pii_l1` und der Rule-Fixture
  schon positiv und bleiben es.

Stand der Goldsets: `pii_l1`, `l1_bilingual_rules.json` und `demo_pii_dlp*` folgen der Konvention
(`cu-07` ist seit T01 positiv). Das synthetische E05-Goldset ist eingefroren und enthält keine
Platzhalter, weder als Positive noch in Hard-Negative-Spans. Durchgesetzt wird das von
`python/tests/test_l1_benchmark_data.py` (`PlaceholderGoldConventionTests`),
`scripts/tests/test_l1_synth_goldset.py` und `rust/tests/pii_l1.rs`
(`reserved_placeholder_values_are_gold_positives`). ARK meldet alle Platzhalter schon heute; eine
spätere regionale Telefonprüfung (Hebel 4) darf `+1 000-000-0000` und `555-01xx` nicht verwerfen.

## Hebel

1. Score-Stufen statt Feldnamenpflicht: prüfzifferstarke Werte ohne Kontext, formschwache nur mit
   gewichtetem Kontext (Nähe, Gegen-Kontext). Liefert echte Scores und P/R-Kurven.
2. Strukturbewusstsein: JSON-Keys, CSV-Header, Key-Value-Zeilen, Tabellenköpfe als Kontext.
3. Prüfziffern, die Presidio nicht hat (DACH/EU).
4. Regionale Telefonnummern über das Crate `phonenumber`.
5. Obfuskation über Normalisierung mit Offset-Rückabbildung.
6. Latenz: Rust ≈ 6 ms / 100 KiB.

## Ausführung: systemd-Timer auf der VPS → Stacked Branch

Eine Claude-Cloud-Routine kommt nicht auf die VPS (Port 22 aus der Cloud gesperrt). Deshalb plant
die VPS selbst: `ark-l1.timer` startet stündlich zur vollen Stunde `runner/run.sh`, `ark-dlp.timer`
zur halben Stunde `runner/run.sh --program dlp`. Beide teilen ein Lock; ist es belegt, entfällt der Lauf.

```
run.sh
  ark-l1 next     → Stack restacken, eine Aufgabe wählen, eigener Klon l1/NNN-<id> auf der Stack-Spitze
  claude -p       → in systemd-Sandbox (nur Klon + Cargo-Target beschreibbar, kein sudo/GitHub/Holdout)
  ark-l1 gate     → Agent-Commits als Bundle (sandboxed erzeugt) ins vertrauenswürdige Repo holen,
                    frischer Checkout; fmt/clippy/test, Golden-Eval, Python-Tests, Docs in einer
                    Sandbox ohne Credentials; Scoreboard (sobald E06 da ist) zusätzlich ohne Netz,
                    als einziger Schritt mit Lesezugriff auf den Holdout
  grün: ark-l1 publish → Status done per Plumbing, push aus dem vertrauenswürdigen Repo, Draft-PR
                    (idempotent; schlägt es fehl, holt der nächste Lauf nur das Publish nach)
  rot:  Gate-Bericht zurück an den Agenten, max. 3 Runden, danach ark-l1 block
```

- **Ein Lauf = eine Aufgabe.** Gewählt wird die erste Aufgabe ohne `status`, deren `deps` erledigt
  sind, die nicht blockiert ist und kein `needs_decision: true` trägt.
- **Testbereich zuerst** (siehe `AGENT_PROMPT.md`), danach Implementierung.
- **Stack:** Wird ein unterer PR gemergt, rebased `ark-l1 next` die übrigen Branches auf den neuen
  Parent und passt die PR-Basis an; der unterste Branch wird auf `main` rebased, sobald GitHub einen
  Konflikt mit `main` meldet. Lässt sich ein Rebase nicht konfliktfrei anwenden, wird er zur Aufgabe
  des Laufs (`RESTACK:<branch>`, Prompt `runner/AGENT_PROMPT.restack.md`): Der Agent löst die
  Konflikte, das Gate prüft wie sonst, `publish` pusht mit Lease auf den alten Head. Nach drei roten
  Runden bleibt der Stack mit `REBASE_CONFLICT` stehen, bis ein Mensch löst und `unblock` aufruft.
  Ab 15 offenen PRs pausiert der Timer, bis gemergt wird; Restack-Läufe laufen trotzdem.
- **Isolation:** Der Host führt nie Code oder Git-Konfiguration des Agenten aus. Git-Befehle im
  Agent-Klon (`status`, `bundle`, `rev-list`) laufen in der Sandbox; das gemeinsame `.git`, der
  Gate-Target, das Gate-Venv und der Scoreboard-Cache sind für den Agenten nicht beschreibbar bzw.
  unsichtbar. Der Runner läuft mit einem eigenen Venv (`~/ark-l1/runner-venv`, PyYAML gepinnt).
- **Runner ist kopiert, nicht verlinkt:** `runner/install.sh` installiert nach `~/ark-l1/bin`. Agent-
  Branches können das Gate nicht ändern; neue Runner-Versionen nur nach Review per Hand installieren.
- **Holdout** liegt unter `~/ark-l1/holdout`, für den Agenten per Sandbox unsichtbar. Erzeugt wird er
  zusammen mit Dev (`~/ark-l1/data/dev`) einmalig von `scripts/l1_presidio/prepare_corpora.py`
  (Gretel Finance, OpenPII Nano, TAB; gruppenweiser Split, 60 % Holdout, SHA-256-Manifest, `.ready`).
  Dazu kommt das synthetische DE/EU-Goldset aus `scripts/l1_presidio/synth_goldset.py` unter
  `…/synthetic/`: Dev mit öffentlichem Seed, Holdout mit geheimem Seed (`~/ark-l1/holdout/synthetic/.seed`),
  ebenfalls einmalig vom Gate erzeugt (Schritt `synthetic-goldset`, erst nach Neuinstallation des Runners).
- **Beobachten:** `~/ark-l1/bin/ark-l1 status`, Logs unter `~/ark-l1/logs/`, PR-Mails von GitHub.
  `ark-l1 unblock <ID>` gibt blockierte Aufgaben frei.
- Montags ist die erste Aufgabe `TRIAGE`: Scoreboard-Fehleranalyse → neue Backlog-Einträge.
- **Weitere Programme:** Derselbe Runner fährt mit `--program dlp` das L1-DLP-Programm
  ([`../dlp/README.md`](../dlp/README.md), Timer `ark-dlp.timer`, State unter `~/ark-dlp`). Beide
  Programme teilen sich einen Lauf-Lock; ohne `--program` gilt `pii`. Backlog-Einträge können mit
  `ext_deps: [<programm>:<id>]` auf Aufgaben warten, die im anderen Programm auf `main` erledigt sind.
  Für DLP legt der Gate-Schritt `external-corpora` die externen Content-Goldens einmalig unter
  `~/ark-dlp/data/dev/external` an (nur Dev, erst nach Neuinstallation des Runners).

## Reihenfolge

E (Messinfrastruktur) → K (Engine) → F (bestehende Regeln reparieren) → B (DACH/EU) → A
(Presidio-Parität) → C (über Presidio hinaus) → H (Härtung, Abschluss). 92 Aufgaben (inkl. TRIAGE-Einträge Txx), bei 2 Läufen/Tag
≈ 7–8 Wochen inkl. Review-Pausen.
