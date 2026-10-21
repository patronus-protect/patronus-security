# L1-PII: Presidio übertreffen

Stand: 2026-10-11. Aufgabenliste: [`backlog.yaml`](backlog.yaml). Agent-Prompt:
[`AGENT_PROMPT.md`](AGENT_PROMPT.md), Runner: [`runner/`](runner/).

## Ausgangslage

- `rust/src/detectors/pii/pii.rs`: 37 Regeln → 30 Labels, nur DE/EN, jeder Treffer `score: 1.0`.
- Hohe Präzision, schwacher Recall, weil viele Regeln einen Feldnamen direkt am Wert verlangen.
  Gretel-Finance (exact span F1): IP .97 · IBAN .83 · PAN .60 · Telefon .59 · SSN .54 · DOB .54 ·
  BIC .50 · Pass .44 · Username .08 · Führerschein 0.
- Fehlende Prüfziffern: KVNR, RVNR, Personalausweis/Pass (MRZ), LANR. Keine regionale Telefonprüfung.
- Kein gemessener Presidio-Vergleich (seit E11: [`scoreboard/baseline.md`](scoreboard/baseline.md), Dev, exact F1
  neutral ARK 52.7 vs. Presidio tuned 40.5, presidio_favored 45.7 vs. 71.4, M1 nicht erreicht). `13_l1_golden_eval` lief nicht in CI (seit E09 im CI-Job `rust`,
  PII und DLP); `12_l1_pii_fixture_eval` verglich Byte- mit Zeichen-Offsets (seit E08 durchgehend
  Zeichen-Offsets).

## Definition „besser als Presidio“

Gemessen auf einem eingefrorenen Holdout, den der Agent nie sieht (nur auf der VPS unter `~/ark-l1/holdout`,
SHA-gepinnt). Presidio läuft in zwei Profilen: `default` und `tuned` (spaCy `en_core_web_lg` +
`de_core_news_lg`, Kontext-Enhancer, DE-Recognizer-Konfiguration).

| Meilenstein | Kriterium |
|---|---|
| M1 Parität EN | Je gemeinsamer Pattern-Entität: F1(ARK) ≥ F1(Presidio tuned) |
| M2 DE/EU | Macro-F1 ≥ Presidio tuned + 15 pp |
| M3 Breite | ≥ 2× so viele prüfziffervalidierte Entitäten wie Presidio 2.2.364 (Zählregel unten: 35 → ≥ 70) |
| M4 Latenz | 100 KiB p95 ≤ 10 ms; Presidio auf derselben Maschine gemessen |
| Immer | FP auf Hard Negatives ≤ Presidio; keine Entität verliert > 0,5 pp F1 |

PERSON/LOCATION/ORG/NRP sind kein L1-Scope; dort tritt L1 + `dynamic-pii` (GLiNER L3) an.

## Fairness-Regel: Quellfamilien

Festgelegt mit E12. Gold, das ARK selbst geschrieben hat, begünstigt ARK; Gold aus Presidios eigenem
Werkzeug begünstigt Presidio. Deshalb trägt jede Gold-Quelle genau eine Familie
(`source_families` in [`entity_map.yaml`](entity_map.yaml), geprüft von `entity_map.py check`):

| Familie | Quellen | Rolle |
|---|---|---|
| `ark_authored` | `pii_l1`, `l1_bilingual_rules`, synthetisches E05-Goldset | wird berichtet, entscheidet **nie** einen Meilenstein |
| `neutral` | Gretel Finance, OpenPII Nano, TAB | entscheidet |
| `presidio_favored` | presidio-evaluator `synth_dataset_v2.json` (presidio-research, MIT, Commit `7f568b6`), Positiv-/Negativfälle der presidio-analyzer-Recognizer-Tests (MIT, Release 2.2.364) | entscheidet |

- **M1 gilt nur, wenn es auf `neutral` und auf `presidio_favored` je für sich hält:** auf jeder der
  beiden Familien je gemeinsamer Pattern-Entität mit Gold in der Familie F1(ARK) ≥ F1(Presidio tuned),
  exakte Spans, englische Zeilen. Ein Vorsprung auf der einen Familie gleicht keinen Rückstand auf der
  anderen aus; eine Familie ohne Gold für gemeinsame Entitäten erfüllt M1 nicht. Prüfung:
  `scoreboard.py m1` (siehe [`scripts/l1_presidio/README.md`](../../scripts/l1_presidio/README.md)).
- Für M2–M4 und „Immer“ gilt dieselbe Trennung: Ergebnisse auf `ark_authored` stehen im Bericht,
  zählen aber für kein Kriterium.
- Das Gate (`scoreboard.py gate`) rechnet Regressionen weiter auf allen Familien, zusätzlich je
  Familie gesamt; eine Verschlechterung auf `ark_authored` ist also weiterhin rot.
- Presidio-Gold wird nicht nachkorrigiert: Werte, die ein ARK-Validator ablehnt, bleiben Gold. Die
  Recognizer-Tests werden mit `ast` gelesen, nie ausgeführt. Übernommen werden nur Fälle gegen den
  Standard-Recognizer der Datei (Ausnahme: `PhoneRecognizer` mit zusätzlichen Regionen JP/CN) mit
  literalem Text und erwarteter Anzahl bzw. Spans; ein Fall ohne Spans nur, wenn der Text der blanke
  Wert ist. Ein Negativfall wird ein Hard Negative über den ganzen Text, aber nur für die Entität des
  Recognizers (`scored_entities`); andere Treffer im selben Text zählen dort weder als TP noch als FP.

Welche Entität zu welchem Kriterium zählt, legt [`entity_map.yaml`](entity_map.yaml) fest: jede
Benchmark-ID mit ARK-Labels, Presidio-Entitäten, Korpus-Labels und Scope (`shared` → M1/„Immer“,
`ark_only`, `presidio_only`, `semantic` → kein L1-Scope). Prüfung:
`python3 scripts/l1_presidio/entity_map.py check`.

## Zählregel M3: prüfziffervalidierte Entitäten

Entschieden am 2026-10-14 (T03, TRIAGE 2026-W42, Abschnitt Abdeckung). Das Ziel war 3× (≈ 120);
der Backlog kommt auf 60–80, deshalb gilt **2×**.

- **Einheit:** eine Benchmark-ID aus [`entity_map.yaml`](entity_map.yaml) je Land. Nationale
  Nummernsysteme zählen je Land einzeln (USt-IdNr. DE und IT sind zwei, Reisepass DE und UK auch);
  internationale Systeme (IBAN, Kartennummer, Krypto-Adresse) zählen einmal. Mehrere Regeln oder
  Recognizer derselben Einheit zählen einmal.
- **Nur echte Prüfziffern/Prüfsummen:** Luhn, ISO 7064, gewichtete Summen, Verhoeff,
  Kontrollbuchstaben, Base58Check. Reine Formprüfung zählt nicht: Länge, Alphabet, Präfix- oder
  Bereichsprüfung, Datum, Bezirks-/Provinztabellen, Domain-Lookup (z. B. Kennzeichen,
  Führerschein UK, GSTIN ohne Prüfzeichen, BSNR, SSN-Bereiche).
- **Presidio ist auf 2.2.364 gepinnt.** Gezählt werden die Pattern-Recognizer mit
  `validate_result`: 43, davon rechnen 35 eine Prüfziffer. M3 verlangt damit ≥ 70 ARK-Einheiten
  (die Entscheidung schätzte ≈ 80). Eine neue Presidio-Version ändert das Ziel erst, wenn der
  Pin bewusst angehoben wird.
- **Gleiche Regel für beide Seiten:** ARK wird je Validator-Funktion der `PII_PATTERNS`-Registry
  eingestuft, Presidio je Entität. Die Einstufung steht unter `checksums` in `entity_map.yaml`;
  `null` heißt „nur Format“.
- **Zählen:** `python3 scripts/l1_presidio/count_validated.py count` (Markdown, `--json`).
  `check` endet mit Exit 1, wenn ein Validator der Registry nicht eingestuft ist, eine Einstufung
  ungenutzt bleibt, ein Label oder eine Entität nicht in der Map steht oder ein Land der ID
  widerspricht; mit `--presidio` (im Presidio-Venv) zusätzlich, wenn die installierte Version vom
  Pin abweicht oder die `validate_result`-Recognizer nicht genau den eingestuften entsprechen.
  Eine Aufgabe, die einen Validator hinzufügt, stuft ihn dort ein, sonst ist
  `scripts/tests/test_l1_count_validated.py` rot.

Stand T03: ARK 3 (PAN/Luhn, IBAN/MOD 97-10, Steuer-ID), Presidio 35, beide gemeinsam 3. Die
DE-Validatoren für RVNR, KVNR, LANR, Pass/Ausweis prüfen heute nur die Form (siehe Ausgangslage).

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

Seit K06 meldet der Opt-in-Modus `recall` ausgeschriebene Formen (`[at]`, `ät`, `dot`, `punkt`) als
`EMAIL` mit `obfuscation: spelled_out`; Gold-Zeilen mit `pii_mode: recall` dürfen sie als Positiv führen.

Stand der Goldsets: `pii_l1`, `l1_bilingual_rules.json` und `demo_pii_dlp*` folgen der Konvention
(`cu-07` ist seit T01 positiv). Das synthetische E05-Goldset ist eingefroren und enthält keine
Platzhalter, weder als Positive noch in Hard-Negative-Spans. Durchgesetzt wird das von
`python/tests/test_l1_benchmark_data.py` (`PlaceholderGoldConventionTests`),
`scripts/tests/test_l1_synth_goldset.py` und `rust/tests/pii_l1.rs`
(`reserved_placeholder_values_are_gold_positives`). ARK meldet alle Platzhalter schon heute; eine
spätere regionale Telefonprüfung (Hebel 4) darf `+1 000-000-0000` und `555-01xx` nicht verwerfen.

## Gold-Hygiene: Nebenentitäten und Prüfziffern

Seit T02 (TRIAGE 2026-W42, Buckets 6 + 7) annotiert ein Positiv in `pii_l1` jede echte Entität im
Text, nicht nur den Ziel-Span (Generator: `also=(Label, Wert)`), z. B. die PAN neben CVV oder
Ablaufdatum. Gewertet wird weiter nur das Ziel-Label. `rust/tests/pii_gold_hygiene.rs` prüft, dass
jeder Gold-Wert einen Validator seines Labels besteht (Known Gaps nur bei Luhn, MOD-97 und
Steuer-ID, nach Rückbau der Obfuskation) und dass jeder weitere L1-Treffer auf einem Positiv Gold
ist oder als Detektor-FP gelistet ist (Telefonziffern mit gültiger Luhn-Summe, PAN in einer noch nicht
gemeldeten gruppierten Nicht-DE-IBAN). PAN in einer gültigen IBAN und die IBAN als
FINANCIAL_ACCOUNT_NUMBER sind seit T07 Sekundär-Evidenz und zählen dort nicht. Die sieben Luhn-ungültigen `credit_card`-Werte in
`dynamic_pii.jsonl` bleiben für L3 im Fixture, tragen `"checksum_valid": false` und zählen in
`12_l1_pii_fixture_eval` nicht. Validatoren bleiben unverändert.

## Capability-Goldens: Schema v2

Seit E10 folgt `pii_l1.jsonl` dem Golden-Schema v2 (Format in
[`benchmark_data/README.md`](../../python/patronus_ark/benchmark_data/README.md)): jede Zeile nennt
die `pii_*`-Regel (`rule_id`), den Carrier (`line`, `prose`, `json`, `yaml`, `xml`, `csv`, `kv`,
`table`), Schwierigkeits-Tags (`no_context`, `structured`, `obfuscated`, `ocr`) und `known_gap`.
Je Label und Sprache (DE/EN) gibt es mindestens 5 gegatete Positive und 5 Hard Negatives, jede der
37 Regeln hat ein gegatetes Positiv in beiden Sprachen und ein Hard Negative. `13_l1_golden_eval`
verlangt, dass die deklarierte Regel den Gold-Span meldet, und druckt die Abdeckung je `rule_id`
(DE | EN) sowie je Tag und Sprache. Bekannte Lücken (Stand E10: 89, v. a. JSON-/CSV-/Tabellen-Keys,
deutsches „ist“/„lautet“ nach dem Feldnamen, Zero-Width-/Full-Width-Zeichen) laufen mit, gaten aber
nicht; schließt eine Aufgabe (K04, K05, K06 …) eine Lücke, schlägt die Eval fehl, bis die Aufgabe
`known_gap` auf `false` setzt.
Seit K03 kann eine Zeile `pii_mode` (`balanced`/`recall`) nennen; die Eval scannt sie in diesem
Modus. So prüfen die Goldens die Kontext-Engine, deren Scores und Gegen-Kontext nur dort wirken.

## Kontext-Engine (K03)

Support- und Gegen-Kontext-Begriffe stehen im DE/EN-Lexikon `rust/src/detectors/anchor_lexicons/pii.json`;
`rust/src/detectors/pii/context.rs` ordnet die Lexikon-IDs den Labels zu (neue Sprachen wie in T26
kommen als Einträge dort hinzu). Gesucht wird beidseitig auf derselben Zeile, der nächste Begriff
entscheidet: Support gibt +25/+20/+15 (bis 16/32/48 Zeichen davor, 32 danach), ein echt näherer
Gegen-Kontext-Begriff (Bestell-, Rechnungs-, Sendungs-, Ticket-, Referenz-, Seriennummer) −30.
Feldgebundene Regeln behalten +25. Regeln mit `requires_context: true` melden nur mit Support, in
jedem Modus; die erste ist `pii_phone_de_national_proximity`. Spätere „mit Kontext“-Aufgaben (F06,
F07, F15, A03–A05, T08, T10, C05, C07, C08) setzen darauf auf. `strict` bleibt für alle übrigen
Regeln unverändert.

Seit T26 (TRIAGE 2026-W43 Bucket 12) tragen die Einträge der Anker-Regeln für Geburtsdatum, Kunden-
und Personalnummer, Kontonummer, CVV, US-SSN, Pass und Benutzername optionale Listen `fr`, `es`,
`it` und `nl`; Engine und Lexical-Anchor-Scanner lesen sie mit. Dieselben Feldnamen stehen in den
Regex der Regeln selbst, damit `strict` sie vor dem Wert und als Strukturschlüssel (K04) bindet.
Benutzernamen verlangen dort `:`, `=` oder `#`, ein CVV einen Kartenbezug im Feldnamen
(`code de sécurité de la carte`, nicht `code de sécurité`). `pii_l1` führt je Sprache 10 Positive
und 6 Hard Negatives; Validatoren sind unverändert.

## Kontextfreie Prüfziffernwerte (K05)

In `balanced` und `recall` braucht ein Wert, dessen Validator eine echte Prüfziffer rechnet, keinen
Feldnamen. IBAN und PAN meldet ARK ohnehin ohne Kontext; Regeln mit `scored_only: true` ergänzen die
blanke Form von Werten, die `strict` nur hinter ihrem Feldnamen meldet. `strict` führt sie nie aus
(Entscheidung K02). Sie sind ungebundene `checksum`-Regeln, erreichen ohne Kontext die
`balanced`-Schwelle und fallen hinter einem näheren Gegen-Kontext-Begriff unter beide Schwellen; der
Wert muss für sich stehen (nicht nach `+`, nicht in einer längeren Zahl, Spanne, Dezimalzahl oder
einem Schrägstrich-Pfad, keine Zifferngruppe ein Leerzeichen daneben). Die erste ist
`pii_steuer_id_de_context_free` (Basis 20: 0,55 blank, 0,80 mit „Steuer-ID ist“, 0,25 hinter
„Rechnungsnummer“) mit `validators::steuer_id_issued`: Prüfziffer plus BZSt-Ziffernverteilung. Die
B-/A-/C-Aufgaben mit neuen Prüfziffern (B01 ff.) hängen ihre kontextfreie Form auf dieselbe Weise an.
`rust/tests/pii_context_free.rs` verlangt für jedes Prüfziffer-Label eine kontextfreie Regel.

## Obfuskation (K06)

`rust/src/detectors/obfuscation.rs` baut eine normalisierte Sicht des Texts mit Byte-Abbildung
zurück auf das Original; die PII-Pipeline scannt sie zusätzlich, wenn sie etwas rückgängig macht,
und meldet nur Funde, in deren Original-Span eine Obfuskation liegt (Original-Offsets,
`matched_rules[].obfuscation`). In jedem Modus: Zero-Width-Zeichen zwischen zwei Wertzeichen,
Full-Width-Formen (Lauf mit Full-Width-Buchstabe/-Ziffer oder Full-Width-Trenner zwischen
ASCII-Alnum), entschärfte Trenner `[.]`, `(@)`, `{.}`, `[:]`. Nur in `recall` (−10 Punkte):
ausgeschriebene E-Mail-Trenner (`[at]`, `ät`, `dot`, `punkt`, ` @ `, ` . `) und zeichenweise
gesperrte Nummern (`D E 8 9 …`). Die Gold-Konvention T01 gilt damit für `strict` und `balanced`
unverändert; `recall` darf ausgeschriebene Adressen melden. Validatoren entscheiden auf dem
normalisierten Wert. DLP D04 kann dieselbe Sicht nutzen.

## Label-Überlappungen (K07)

`rust/src/detectors/pii/overlap.rs`: In `balanced` und `recall` ergibt ein Wert ein Label unter den
konkurrierenden Nummern-Labels (`COMPETING_LABELS`: IBAN, Karte, Kontonummer, Steuer-ID, Telefon).
Von zwei überlappenden Funden verschiedener Labels gewinnt nach dem ersten Kriterium, das sich
unterscheidet: IBAN, längerer Wert (Luhn-gültige Teilspanne einer IBAN oder einer `+49`-Nummer),
Kontext des eigenen Labels (Feldname, Strukturschlüssel, Support-Begriff in der Nähe), Prüfziffer,
höherer Score, frühere Regel. Ein Fund in einer gedruckten IBAN-Form (`DE64 7172 …`) weicht auch dann,
wenn deren Prüfziffer fehlschlägt. Der Verlierer verlässt `evidence_spans`, sein `matched_rules`-Eintrag
nennt `overlap` (`reason`, `yields_to`). `strict` behält beide Labels (Entscheidung T07); andere Labels
(EMAIL und USERNAME auf einem Wert) behalten ihre Überlappung. Validatoren unverändert.

Seit T07 (Entscheidung 2026-10-14) bleibt `strict` bitgleich in Spans, Klasse und Konfidenz, markiert
aber eine Karte (`CREDITCARD`) oder Kontonummer (`FINANCIAL_ACCOUNT_NUMBER`) innerhalb einer gemeldeten,
MOD-97-gültigen IBAN als Sekundär-Evidenz: `details.secondary_evidence` mit `label`, Byte-Offsets,
`reason` (`iban_value`, `iban_part`) und `primary_label`. Gewertet werden nur Primärfunde:
`13_l1_golden_eval`, `pii_gold_hygiene.rs` und `run_ark.py` (Scoreboard) lassen Sekundär-Evidenz weg.
Ein Hard Negative in `pii_l1` darf dafür andere echte Entitäten annotieren (`n(also=…)`, nie das
Ziel-Label); die Auswertung verlangt genau diese als Primärfunde. Ziffern einer IBAN-Form mit falscher
Prüfziffer bleiben in `strict` primär.

## Hebel

1. Score-Stufen statt Feldnamenpflicht: prüfzifferstarke Werte ohne Kontext, formschwache nur mit
   gewichtetem Kontext (Nähe, Gegen-Kontext). Liefert echte Scores und P/R-Kurven.
2. Strukturbewusstsein: JSON-Keys, CSV-Header, Key-Value-Zeilen, Tabellenköpfe als Kontext.
3. Prüfziffern, die Presidio nicht hat (DACH/EU).
4. Regionale Telefonnummern über das Crate `phonenumber`.
5. Obfuskation über Normalisierung mit Offset-Rückabbildung.
6. Latenz: gemessen mit `scripts/l1_presidio/latency.py` (E07, Ergebnis in
   [`scoreboard/latency.md`](scoreboard/latency.md)). Auf der VPS (2026-10-16, PII in zwei von drei
   Absätzen) liegt 100 KiB p95 bei 76 ms (Python-Bindings) bzw. 68 ms (nativ), DE ≈ 80 ms, EN
   ≈ 30 ms; Presidio braucht 10–10,5 s (≈ 135×). M4 ist damit offen; die Bindings kosten wenig,
   die Zeit liegt in den Regeln (DE-Regeln ≈ 2,7× EN).

## Ausführung: systemd-Timer auf der VPS → Stacked Branch

Eine Claude-Cloud-Routine kommt nicht auf die VPS (Port 22 aus der Cloud gesperrt). Deshalb plant
die VPS selbst, und nur die VPS: `ark-l1.timer` startet alle 2 Stunden zu geraden Stunden `runner/run.sh`,
`ark-dlp.timer` zu ungeraden Stunden `runner/run.sh --program dlp`. Beide teilen ein Lock; ist es belegt,
entfällt der Lauf.

```
run.sh
  ark-l1 next     → Stack restacken, eine Aufgabe wählen, eigener Klon l1/NNN-<id> auf der Stack-Spitze
  claude -p       → in systemd-Sandbox (nur Klon + Cargo-Target beschreibbar, kein sudo/GitHub/Holdout)
  ark-l1 gate     → Agent-Commits als Bundle (sandboxed erzeugt) ins vertrauenswürdige Repo holen,
                    frischer Checkout; dieselben Schritte wie .github/workflows/ci.yml (fmt/clippy/test,
                    Golden-Eval, Python-Tests, pytest scripts/tests, Docs) in einer Sandbox ohne
                    Credentials; Scoreboard (scoreboard.py gate, E06) zusätzlich ohne Netz, als einziger
                    Schritt mit Lesezugriff auf den Holdout, rot bei jeder Regression
  ark-l1 ci       → Status done per Plumbing, Branch pushen (noch ohne PR), auf die GitHub-CI warten
  grün: ark-l1 publish → PR öffnen, fertig zum Review (kein Draft); ohne grüne CI auf genau diesem
                    Commit verweigert publish (idempotent; der nächste Lauf holt CI/Publish nach)
  rot:  Gate- bzw. CI-Bericht zurück an den Agenten, max. 3 Runden, danach ark-l1 block
                    (ein Branch ohne PR wird dabei gelöscht)
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
  Sitzt ein Branch schon auf seinem neuen Parent (von außen rebased), trägt `next` nur die neue Basis
  ein. Lehnt GitHub den Restack-Push ab (Branch ändert `.github/workflows`, Token ohne `workflow`-Scope),
  meldet der Lauf `RESTACK_PUSH_ERROR` und hebt den Rebase unter `RESTACK_REF` auf; nach einem Push von
  außen (mit Lease) geht der Stack im nächsten Lauf weiter.
  Verweigert GitHub die neue PR-Basis (PR ist Teil eines nativen Stacks), zieht `next` den alten
  Basis-Branch nach, sofern er kein offener Stack-Branch mehr ist (Parent gemergt): Push mit Lease auf
  den neuen Parent (`MOVED_BASE`). Sonst behält der PR die ungesquashten Commits des Parents als Basis
  und meldet dauerhaft einen Konflikt. Scheitert der Push, steht `STALE_BASE_REF` im Log.
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
  Die Familie `presidio_favored` (E12) friert derselbe Skript mit `--family presidio_favored` getrennt
  nach `…/presidio_favored/` ein (Gate-Schritt `presidio-favored-corpora`, einmalig, erst nach
  Neuinstallation des Runners); Gruppen sind presidio-evaluator-Templates bzw. Testtexte.
  Dazu kommt das synthetische DE/EU-Goldset aus `scripts/l1_presidio/synth_goldset.py` unter
  `…/synthetic/`: Dev mit öffentlichem Seed, Holdout mit geheimem Seed (`~/ark-l1/holdout/synthetic/.seed`),
  ebenfalls einmalig vom Gate erzeugt (Schritt `synthetic-goldset`, erst nach Neuinstallation des Runners).
- **Scoreboard:** `scripts/l1_presidio/scoreboard.py gate` rechnet Head und Basis (exakt und
  überlappend, je Entität, DE/EN, je Quellfamilie, Hard-Negative-FP) auf Dev und Holdout; Exit 1 bei > 0,5 pp
  F1-Verlust oder neuem Hard-Negative-Treffer. Lokal mit `--dev "$ARK_L1_DEV_DATA"` ohne
  `--holdout`; Details in [`scripts/l1_presidio/README.md`](../../scripts/l1_presidio/README.md).
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
(Presidio-Parität) → C (über Presidio hinaus) → H (Härtung, Abschluss). 106 Aufgaben (inkl. TRIAGE-Einträge Txx), bei 2 Läufen/Tag
≈ 7–8 Wochen inkl. Review-Pausen.
