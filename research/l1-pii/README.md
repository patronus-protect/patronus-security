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

## Gold und Qualitätsuntergrenze (seit 2026-10-25)

- **Gold überall:** Jede implementierte Entität braucht Gold in mindestens einer Quellfamilie. Neue Entitäten bringen ihr Gold in derselben Aufgabe mit (synthetisch, prüfziffergültig, ≥ 10 Positive und ≥ 5 Hard Negatives je Entität, DE + EN). Lücken stehen auf der Seite `docs/reference/l1-capabilities.md` als „no gold“.
- **Gold für Entitäten nach dem E05-Freeze:** Das E05-Goldset bleibt bytegleich; nachgereichtes synthetisches Gold bekommt ein eigenes Goldset desselben Generators mit eigenem Korpus, eigenen Seeds und eigenem Verzeichnis (`--goldset`, Familie `ark_authored`). GOLD-VAT1: `ark-synthetic-vat-1` für die USt-IdNr. von AT, BE, BG, CH, CY, CZ, DK, EE, ES, FI, FR, GR, HR und HU; GOLD-VAT2: `ark-synthetic-vat-2` für IE, LT, LU, LV, MT, NL, NO, PL, PT, RO, SE, SI, SK und UK (Aufbau in [`scripts/l1_presidio/README.md`](../../scripts/l1_presidio/README.md)). Damit erzeugen die drei Goldsets zusammen jede ID der Entity-Map außer DK CPR und NO fødselsnummer aus B-NORD (`NOT_GENERATED`).
- **Untergrenze F1 ≥ 80:** Jede implementierte Entität mit Gold erreicht exakten F1 ≥ 80 auf jeder Familie mit Gold (PII: `balanced`; DLP: im Profil, in dem sie läuft, auch Opt-in). Darunter wird eine `Q-…`-Aufgabe angelegt; TRIAGE prüft das bei jeder Messung. Ausnahmen nur mit dokumentierter Entscheidung.

## Definition „besser als Presidio“

Gemessen auf einem eingefrorenen Holdout, den der Agent nie sieht (nur auf der VPS unter `~/ark-l1/holdout`,
SHA-gepinnt). Presidio läuft in zwei Profilen: `default` und `tuned` (spaCy `en_core_web_lg` +
`de_core_news_lg`, Kontext-Enhancer, DE-Recognizer-Konfiguration).

| Meilenstein | Kriterium |
|---|---|
| M1 Parität EN | Je gemeinsamer Pattern-Entität: F1(ARK) ≥ F1(Presidio tuned) |
| M2 DE/EU | Macro-F1 (DE-Zeilen, `shared` + `ark_only`) auf `neutral` ≥ Presidio tuned + 15 pp und auf `presidio_favored` ≥ Presidio tuned (Regel unten) |
| M3 Breite | ≥ 2× so viele prüfziffervalidierte Entitäten wie Presidio 2.2.364 (Zählregel unten: 35 → ≥ 70) |
| M4 Latenz | 100 KiB p95 ≤ 10 ms; Presidio auf derselben Maschine gemessen |
| Immer | FP auf Hard Negatives ≤ Presidio; keine Entität verliert > 0,5 pp F1 |

PERSON/LOCATION/ORG/NRP sind kein L1-Scope; dort tritt L1 + `dynamic-pii` (GLiNER L3) an.

## Messmodus und Gold-Lücken (T15, T16)

Entschieden am 2026-10-21 (TRIAGE 2026-W43, Abschnitt Modus und Buckets 13 + 14; umgesetzt in B-EVAL).

- **Meilensteine auf `balanced`:** M1–M3 und „Immer“ werden im PII-Modus `balanced` gemessen, dem
  Modus, der gegen Presidio tuned (kontextfreie Muster, Kontext hebt den Score, Schwelle 0,4) antritt.
  `strict` bleibt der Standard des Builds und wird weiter berichtet, entscheidet aber keinen Meilenstein.
  `scoreboard.py m1` und `report` drucken jeden übergebenen Modus und lesen das Urteil aus `balanced`.
- **Das Gate schützt beide Modi:** `scoreboard.py gate` rechnet Head und Basis in `strict` und in
  `balanced` und ist rot bei > 0,5 pp F1-Verlust (je Entität, alle L1-IDs, Familie, DE/EN, exakt oder
  überlappend) oder einem neuen Hard-Negative-Treffer in **einem** der beiden Modi. Ein Gewinn in einem
  Modus gleicht keinen Verlust im anderen aus.
- **`strict` ändert sich nur mit Absicht:** Die Ausgabe von `strict` (Spans, Klasse, Konfidenz) ändert
  sich nur dort, wo die Akzeptanz einer Aufgabe das ausdrücklich sagt; sonst bleibt sie bitgleich.
- **Gold-Lücken werden getrennt berichtet (Option a):** Die Wertung bleibt unverändert, die Korpora
  werden nie bearbeitet. `scoreboard.py report` zählt je Korpus und Entität und für jede Engine (ARK je
  Modus, Presidio je Profil) zwei Buckets: Vorhersagen, die unter exakter Wertung FP sind und deren Wert
  einem annotierten Gold-Wert derselben ID an anderer Stelle der Zeile gleicht (ohne umgebende Klammern,
  Anführungszeichen, Satzzeichen und `mailto:`; z. B. die nicht annotierte Kopie in
  `[x@y.com](mailto:x@y.com)`), und Gold-Werte, die keinen Prüfziffer-Validator ihrer ID bestehen (mit
  der Zahl, die jede Engine trotzdem exakt meldet). Kein Gate- oder Meilenstein-Wert ändert sich dadurch.
  Die Validatoren laufen als Python-Ports der Rust-Funktionen (`CHECKSUM_PORTS` in `scoreboard.py`); eine
  Aufgabe, die in `checksums.ark` einen Prüfziffer-Validator einstuft, portiert ihn dort, sonst ist
  `scripts/tests/test_l1_scoreboard.py` rot.
- **Unmögliche IBAN-Gold-Werte zählen nicht (B-IBAN, entschieden 2026-10-29):** ARK bleibt streng am
  SWIFT-IBAN-Register. Ein `pii.iban`-Gold-Span, dessen Wert ohne Leerzeichen das Register nicht besteht
  (Land im Register, genau dessen Länge, MOD-97), ist kein Gold: Er fehlt keiner Engine (kein FN), und
  Vorhersagen derselben ID, die ihn überlappen, zählen nicht als FP. Die Regel gilt für alle Engines
  (ARK je Modus, Presidio je Profil), Dev und Holdout, Gate, Meilensteine und den Gold-Lücken-Bericht
  (`IGNORED_GOLD` und `IBAN_REGISTRY_LENGTHS` in `scoreboard.py`). Betroffen sind vor allem von Faker
  erzeugte Werte (falsche Länge wie GB mit 21 Zeichen, Länder ohne IBAN wie PH, BD, AR, CO, TH).

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
- **M2 gilt nur, wenn es auf `neutral` und auf `presidio_favored` je für sich hält** (D-M2, entschieden
  am 2026-10-21): Macro-F1 = ungewichtetes Mittel des exakten F1 über alle `shared`- und `ark_only`-IDs
  mit Gold auf den deutschen Zeilen der Familie, gemessen in `balanced`. Auf `neutral` muss ARK
  Presidio tuned um ≥ 15 pp übertreffen, auf `presidio_favored` genügt Parität (≥ Presidio tuned):
  dort liegt tuned bei 87 und tuned + 15 pp über 100. Eine Mindestzahl an Gold je ID gibt es nicht;
  eine Familie ohne deutsches Gold für eine zählende ID erfüllt M2 nicht. `presidio_only`-IDs
  (Handelsregister, BSNR, PLZ, USt-IdNr. …) zählen nicht zum Mittel, bis `entity_map.yaml` sie
  `shared` führt, weil ARK sie erkennt; `semantic` zählt nie. Prüfung: `scoreboard.py m2` (Exit 1,
  solange nicht beide Familien halten).
- Für M3, M4 und „Immer“ gilt dieselbe Trennung: Ergebnisse auf `ark_authored` stehen im Bericht,
  zählen aber für kein Kriterium (M2 druckt `ark_authored` mit +15 pp, ohne Urteil).
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
DE-Validatoren für RVNR, KVNR, LANR, Pass/Ausweis prüften damals nur die Form (Prüfziffern seit F08
und B-DE1).

Stand B01: ARK 11, gemeinsam 5. Dazu kommen die USt-IdNr. von DE, AT, CH, FR, NL, BE, IT und ES, je
Land ein Label (`VAT_ID_DE` …) und ein Validator mit Prüfziffer (`rust/src/detectors/pii/vat.rs`), nur
in `balanced`/`recall` (scored-only wie K05). DE und IT sind `shared`, die übrigen sechs `ark_only`;
das eingefrorene E05-Goldset erzeugt die sechs neuen IDs nicht und bleibt bytegleich; ihr Gold kommt aus
den VAT-Goldsets von GOLD-VAT1 und GOLD-VAT2.

Stand B16: ARK 24, gemeinsam 7. Dazu kommen die USt-IdNr. von LU, LV, MT, PL, PT, RO, SE, SI, SK, NO
und GB, aufgebaut wie B01 (je Land ein Label und ein Validator mit Prüfziffer, scored-only, alle
`ark_only`). Nordirland (`XI`) teilt Label `VAT_ID_GB` und Validator mit GB und zählt mit GB als eine
Einheit (`pii.uk.vat_id`). Formen ohne bestätigte Prüfziffer bleiben draußen: lettische
Personenkennungen, slowakische Geburtsnummern, rumänische CNP und die britischen `GD`/`HA`-Nummern.

Stand F08: ARK 13, gemeinsam 7. Reisepass und Personalausweis DE prüfen die ICAO-9303-Prüfziffer
(7-3-1, `validators::de_passport_number`, `de_identity_card_number`): Serie `C F G H J K` bzw.
`L M N P R T V W X Y`, acht Zeichen plus Prüfziffer (Form von presidio-analyzer, `F12345671`) oder
MRZ-Form mit neun Zeichen plus Prüfziffer (`C01X00T478`), dazu die alte numerische Seriennummer
(zehn Ziffern, nur mit Dokumentbegriff). Nur in `balanced`/`recall` (scored-only wie K05); die
feldgebundenen Regeln behalten in jedem Modus die Formprüfung, weil eine gedruckte neunstellige
Seriennummer keine eigene Prüfziffer trägt. Ein blanker Wert eines Felds, das etwas anderes nennt
(`DEA-Nummer: …`, Spalte `driver_license_number`), bleibt stumm (`context::foreign_field`), und Pass-
und Ausweisfunde konkurrieren in den Score-Modi mit überlappenden Funden jedes anderen Labels
(`overlap::DOCUMENT_LABELS`): ein Feldname wie `Kundennummer` entscheidet. `Pass-Nr.` (Baseline P6) stand schon im K03-Lexikon (`pii.passport`)
und hebt jetzt den kontextfreien Wert auf 0,80; die `strict`-Regel kennt den Feldnamen weiter nicht
(B-PASS).

Stand F15: Führerschein DE, US und IT (Baseline P6) sind drei feldgebundene Regeln mit einem
gemeinsamen Feldteil (`rust/src/detectors/pii/driver_license.rs`): ein Führerschein-Feldname auf
DE, EN, IT, FR, ES oder NL vor dem Wert oder als Strukturschlüssel, Prosa wie „my driver's license
number is“, „of“, „lautet“ oder „è“ dazwischen. Der Wert entscheidet die Regel: elf Zeichen
(`pii_driver_license_number_de`), ein Format der US-Bundesstaaten (`validators::us_driver_license_number`,
Zifferngruppen auch mit Bindestrich, kein Datum) oder die Patente (`it_driver_license_number`). Keines
der Formate trägt eine Prüfziffer (M3 unverändert); ein Wert ohne Führerschein-Feldnamen bleibt in
jedem Modus negativ, auch die blanken Werte der presidio-analyzer-Tests (`H12234567`, `KO12345678X`).
Der UK-Führerschein (`MORGA657054SM9IJ`, 5 der 14 `presidio_favored`-Gold-Werte) kommt mit B-UK.

Stand B-SSN: US-SSN (T25, F07, Baseline P1) hat neben der feldgebundenen Regel zwei weitere:
`pii_ssn_us_proximity` meldet `AAA-GG-SSSS` (Bindestrich, Punkt oder Leerzeichen) und neun Ziffern
ohne Trenner in jedem Modus, wenn ein SSN-Begriff nah am Wert steht (`Social Security Number (SSN) …`,
`Als SSN ist … hinterlegt`) oder sein Strukturschlüssel ist (`"ssn":`, `ssn=`, `<SSN>`, CSV-Spalte);
`pii_ssn_us_context_free` meldet die gruppierte Form ohne Begriff nur in `balanced`/`recall` (Score
0,50, wie presidio-analyzer kontextfrei). Sie ist die einzige Formatregel unter den `scored_only`-Regeln:
Trenner und SSA-Bereiche ersetzen die Prüfziffer. Ohne Begriff verwirft sie zusätzlich die
Platzhalter, die presidio-analyzer in jedem Kontext verwirft (`validators::us_ssn_context_free`: eine
wiederholte Ziffer wie `111-11-1111`, die Zählfolge `123-45-6789`). Ein näherer Gegenkontext-Begriff (Bestell-, Referenz-,
Teilenummer) unterdrückt beide in jedem Modus. Der SSA-Validator ist unverändert; `987-65-4322` und
`219-09-9999` (presidio-analyzer-Tests) bleiben deshalb FN, ebenso neun blanke Ziffern ohne Begriff
(`078051121`). Damit liegt `presidio_favored` im Dev-Split höchstens bei 75,0 gegen tuned 88,9.
`context::stands_alone` lässt ein `+` nach Buchstabe oder `+` als EDIFACT-Trenner gelten
(`NAD+SU+341-33-4328`).

Stand B-UK: ARK 36, gemeinsam 8 (A07, Baseline P6, Kandidat C4). Die NHS-Nummer bekommt das Label
`NHS_NUMBER` und die Prüfziffer mod 11 (`validators::uk_nhs_number`, Gewichte 10…1; Prüfziffer 10
und eine wiederholte Ziffer sind ungültig); `pii.uk.nhs_number` ist jetzt `shared`. Zehn Ziffern in
Telefongruppen (3-3-4) bestehen mod 11 jedes elfte Mal, deshalb braucht `pii_nhs_number_uk` in jedem
Modus einen NHS-Begriff nah am Wert oder als Schlüssel und hat keine kontextfreie Form; in den
Score-Modi konkurriert `NHS_NUMBER` mit `PHONE` (K07), `strict` behält beide Labels. Die NINO-Regel
liest den Wert auch in Zweiergruppen (`AB 12 34 56 C`) und nach `NI number`, `NI No.`, `National
insurance no`, `NI-Nummer`, in jeder Schreibweise; `validators::uk_nino` ist unverändert, nie
vergebene Präfixe (`BG`, `NT`, `FQ`, `UV`) bleiben negativ. `pii_ni_uk_context_free` meldet eine
blanke NINO in einer Schreibweise (`hh 01 02 03 d`, `tw987654a`) nur in `balanced`/`recall` (0,50).
Der UK-Pass (neun Ziffern) und ein Pass aus zwei Buchstaben und sieben Ziffern (Irland, Japan;
`pii_passport_number_two_letters`) brauchen einen Pass-Begriff, der UK-Führerschein
(`MORGA657054SM9IJ`) ist feldgebunden (`pii_driver_license_number_uk`) und blank in den Score-Modi
(`…_context_free`, 0,50). NINO und UK-Führerschein sind damit neben der gruppierten SSN die
`scored_only`-Formatregeln: Vergaberegeln (Präfixe/Suffixe bzw. Nachname, Geburtsdatum, Initialen)
ersetzen die Prüfziffer. Dev `presidio_favored` balanced: Führerschein 62,5 → 95,2 (tuned 90,0),
NINO 0,0 → 66,7 exakt und 100,0 überlappend (tuned 100,0); exakt bleibt NINO unter tuned, weil
der Gold-Span ` YZ 61 48 68 B` das führende Leerzeichen aus Presidios Regex trägt (P10).

Stand B-APAC: ARK 42, gemeinsam 13 (A08, A10; NRIC/FIN prüft nur ARK). Sechs Labels mit Prüfziffer oder Prüfbuchstabe:
`AU_ABN` (mod 89), `AU_ACN` (mod 10), `AU_TFN` (mod 11), `AU_MEDICARE` (1-3-7-9 mod 10),
`SG_NRIC_FIN` (Prüfbuchstabe je Serie `S T F G M`) und `SG_UEN` (Prüfbuchstabe je Format A/B/C);
alle sechs IDs sind jetzt `shared`. In jedem Modus meldet je eine Regel den Wert mit einem Begriff
des Labels in der Nähe oder als Schlüssel (`pii_abn_au` …, `requires_context`). Kontextfrei in
`balanced`/`recall` (K05, 0,55) nur die Formen, deren Gestalt die Prüfziffer stützt: ABN 2-3-3-3,
Medicare 4-5-1, NRIC/FIN in Großbuchstaben, UEN Format B (Registrierungsjahr) und C (Entitätstyp).
ACN und TFN (neun Ziffern bestehen mod 10/11 jedes zehnte/elfte Mal), blanke Ziffernfolgen
(Bestellnummern `45…` im E05-Hard-Negative-Set) und UEN Format A (Form einer spanischen DNI) brauchen
wie die NHS-Nummer in jedem Modus den Begriff (`CONTEXT_BOUND_LABELS` in
`rust/tests/pii_context_free.rs`). `AU_ABN` konkurriert in den Score-Modi mit `STEUERID` (K07). Die
presidio-analyzer-Gold-Werte `G1122144L` und `B1234567Z` bestehen den NRIC-Prüfbuchstaben nicht und
bleiben FN; Presidio rechnet für NRIC/FIN keine Prüfziffer. Dev balanced: ABN 100,0, ACN 82,6,
TFN 91,9, Medicare 91,9, NRIC/FIN 95,7, UEN 96,3 (vorher 0); offen bleiben Werte in Pipe-Tabellen
ohne Randstriche und mehrspaltigen CSV-Zeilen, die die Struktur-Erkennung (K04) nicht liest.

Stand B-DE1: ARK 45, gemeinsam 16 (F10, F11, F12). Die feldgebundenen Regeln für KVNR,
Rentenversicherungsnummer und LANR rechnen jetzt die Prüfziffer statt nur der Form:
`validators::de_health_insurance_number` (§ 290 SGB V: Buchstabe als 01…26 und acht Ziffern,
Quersummen gewichtet 1-2, mod 10; nicht neun Nullen), `de_social_security_number` (VKVV § 4:
Geburtstag 01–31 oder 51–81, Monat 01–12, Buchstabe als 01…26, Quersummen gewichtet
2-1-2-5-7-1-2-1-2-1-2-1, mod 10) und `lanr` (KBV: sechs Ziffern gewichtet 4-9, die siebte ergänzt
auf zehn; nicht eine wiederholte Ziffer). Ihre Basispunkte sinken um die 20 Punkte, die die
Prüfziffer mehr gibt; die Scores in `balanced`/`recall` bleiben gleich. Kontextfrei in
`balanced`/`recall` (K05, 0,55): die RVNR blank oder in den Druckgruppen 2-6-1-3
(`pii_rentenversicherung_de_context_free`) und eine KVNR mit Großbuchstaben
(`pii_health_insurance_number_de_context_free`, mit `context::foreign_field` wie Pass und Ausweis).
Neun blanke Ziffern bestehen die LANR-Prüfziffer jedes zehnte Mal: `pii_physician_number_lanr_de_proximity`
verlangt einen LANR-Begriff in der Nähe oder als Schlüssel (`Arztnummer 987654401 auf dem Rezept`),
nur in den Score-Modi; LANR steht deshalb neben NHS, ACN und TFN in `CONTEXT_BOUND_LABELS`. Die BSNR
hat keine Prüfziffer: neues Label `FACILITY_NUMBER_BSNR` (`pii_facility_number_bsnr_de`, neun
Ziffern mit `validators::nine_digits`, den sie mit dem UK-Pass teilt, Lexikon `pii.facility_number`)
mit BSNR-Begriff in jedem Modus, keine M3-Einheit; `pii.de.bsnr` ist jetzt `shared`. Die blanken
BSNR-Werte der presidio-analyzer-Tests bleiben FN (Presidio meldet sie mit 0,2 ebenfalls nicht).
Alle 140 Gold-Werte der drei IDs in den Dev-Korpora bestehen die Prüfziffern; `X123456789` in
`dynamic_pii.jsonl` (L3) trägt `"checksum_valid": false`.

Stand B-NORD: ARK 49, gemeinsam 18 (B12, B13). Vier nordische Personennummern, je ein Label mit
Prüfziffer, alle beginnend mit dem Geburtsdatum: `SE_PERSONNUMMER` (Luhn, `YYMMDD-NNNC`, `+` ab dem
100. Geburtstag, 10 oder 12 Ziffern, samordningsnummer mit Tag + 60), `DK_CPR` (gewichtet
4-3-2-7-6-5-4-3-2-1 mod 11, Jahrhundert aus der 7. Ziffer), `NO_FODSELSNUMMER` (zwei Prüfziffern mod 11,
auch D- und H-Nummer) und `FI_PERSONAL_IDENTITY_CODE` (henkilötunnus, Kontrollzeichen mod 31,
Jahrhundertzeichen `-`/`Y`–`U`/`A`–`F`, Einzelnummer 002–999, auch temporäre ab 900). Geburten vor 1900
(HETU `+`, CPR und fødselsnummer mit 1800er-Bereich) gelten als ungültig. `pii.se.personnummer` und
`pii.fi.personal_identity_code` sind jetzt `shared`, `pii.dk.cpr` und `pii.no.fodselsnummer` neu und
`ark_only`. In jedem Modus meldet je eine Regel den Wert mit einem Begriff des Labels in der Nähe oder als
Schlüssel (`requires_context`; `Personnummer` stützt SE, DK und NO); kontextfrei in `balanced`/`recall`
(K05, 0,55) nur die gedruckten Formen `YYMMDD-NNNC`, `DDMMYY-SSSS`, `DDMMYY NNNKK` und die HETU mit
Jahrhundertzeichen. Blanke Ziffernfolgen und zwölf Ziffern mit Bindestrich (Zeitstempel `20241026-1529`)
brauchen den Begriff. **DK CPR zählt nur, wo die mod-11-Prüfung gilt:** `dk_cpr` verlangt sie; CPR-Nummern
ohne mod 11 (seit 2007 vergeben) bleiben FN, sonst wäre die Einheit reine Formprüfung. Die vier Labels
konkurrieren in den Score-Modi untereinander und mit `STEUERID` (K07). Gold für DK und NO gibt es bisher
nur in `pii_l1` und der Rule-Fixture; ein synthetisches Goldset fehlt (`NOT_GENERATED`).

Stand Q-DE (Qualitätsuntergrenze, 2026-10-25): Analyse der deutschen IDs, die der Snapshot 2026-10-24
auf `presidio_favored` unter F1 80 führt. Alle Gold-Werte dort sind blanke Werte aus den
presidio-analyzer-Tests, ohne Feldnamen. Der Snapshot liegt vor B-DE1; seitdem steht RVNR bei 100,0
und KVNR bei 80,0. Dev `presidio_favored` balanced, exakt, vorher → nachher:

- **KVNR 80,0 → 100,0.** `a123456780` trägt einen Kleinbuchstaben; die Prüfziffer zählt ihn wie den
  großen. `pii_health_insurance_number_de_context_free` liest den Buchstaben jetzt in beiden
  Schreibweisen wie der blanke Pass und Ausweis (F08); `context::foreign_field` bleibt.
- **Steuernummer 0,0 → 66,7.** Neu `pii_steuernummer_de_context_free`: die Schrägstrich-Gruppen der
  Länder (2/3/5, 3/3/5, 3/4/4: `21/815/08150`, `123/456/78901`, `133/8150/8159`) ohne Feldnamen, nur in
  `balanced`/`recall` (0,50, Format wie die gruppierte SSN; mit Begriff 0,75), still unter einem Feld,
  das einen anderen Wert nennt (`Aktenzeichen: …`). In keinem neutralen Dev-Korpus kommt die Form vor.
  **Entscheidung:** `0181508150000` bleibt FN. Presidios ELSTER-Muster nimmt einen Ländercode 01–16
  und elf Ziffern an; die echte 13-stellige Form ist Finanzamtsnummer (vierstellig, BW `28…`, BY `9…`,
  NW `5…` …), eine `0`, Bezirk, Unterscheidungsnummer und Prüfziffer. Den Wert gibt es so nicht, und
  13 blanke Ziffern sind ebenso oft ein Zeitstempel in Millisekunden (`1698234567890`) oder eine
  EAN-13. Die 13-stellige Form bleibt feldgebunden; Höchstwert 66,7.
- **LANR 50,0, Entscheidung B-DE1 bleibt.** `234567701` und `999999901` sind neun blanke Ziffern ohne
  LANR-Begriff; jede zehnte neunstellige Zahl besteht die Prüfziffer. Gemeldet wird weiter nur mit
  Begriff (`Arztnummer 987654401 …`); Höchstwert 50,0.
- **Steuer-ID 0,0, Validator bleibt.** Der einzige Gold-Wert `98765432106` hat in den ersten zehn
  Ziffern zehn verschiedene Ziffern; vergeben wird nur eine Verteilung mit genau einer doppelten oder
  dreifachen Ziffer (`validators::steuer_id_issued`, Hard Negative in `rust/tests/pii_context_free.rs`).
  Presidio prüft nur „höchstens dreimal“. Höchstwert 0,0 bei einem Gold-Wert.
- **USt-IdNr. DE 75,0, Validator bleibt.** `DE987654321` und `DE100000001` bestehen ISO 7064
  MOD 11,10 nicht; der Test upstream prüft Presidios Standardmodus ohne Prüfziffer („heuristic
  preserves recall“). Höchstwert 3 von 5, F1 75,0.

`strict` bleibt bitgleich. Auf `ark_authored` (Dev-Goldset E05, balanced) liegen alle sechs IDs über 80:
KVNR 100,0, LANR 98,1, RVNR 100,0, Steuer-ID 100,0, Steuernummer 94,2 → 98,1, USt-IdNr. DE 100,0.
Stand B-ACCT: ARK 50, gemeinsam 19 (A04, F14). Die ABA-Routing-Nummer (US) rechnet die Prüfziffer
(`validators::aba_routing_number`: Routing-Symbol 00–12, 21–32, 61–72 oder 80, Gewichte 3-7-1 mod 10,
nicht eine wiederholte Ziffer) und meldet `FINANCIAL_ACCOUNT_NUMBER`; die Einheit ist
`pii.financial_account_number` mit Land `us`, wie Presidios `ABA_ROUTING_NUMBER`. Neun blanke Ziffern
bestehen die Prüfziffer jedes zehnte Mal: `pii_aba_routing_number_us` verlangt in jedem Modus einen
Routing- oder Kontobegriff nah am Wert oder als Schlüssel (neues Lexikon `pii.bank_routing_number`:
`ABA`, `RTN`, `routing number`, `Routingnummer`, `numéro de routage` …), kontextfrei meldet nur
`pii_aba_routing_number_us_context_free` die gedruckte 4-4-1-Form (`0711-0130-7`, 0,55, nur
`balanced`/`recall`). Die feldgebundene Kontoregel kennt zusätzlich `BBAN`, `Bank Routing Number`,
`Routing-Nummer`, `ABA number`, `Acct No`/`Acct ID` und FR/ES/IT-Routing-Feldnamen, vor dem Wert und
als Strukturschlüssel (JSON `bban`, CSV `bank_routing_number`, XML `<AcctNumber>`, `<RoutingNumber>`,
`<AcctId>`, `numeroCuentaBancaria`); unter dem Feldnamen gilt wie bei `Kontonummer` nur die Form,
weil Gretels neunstelliges Konto- und Routing-Gold selten die Prüfziffer besteht (7 von 61 Dev-Werten). Die Kundennummer-Regel
nimmt `customer_id`/`customer-number` auch im Fließtext. Dev balanced, exakter F1: Kontonummer neutral
8,2 → 46,7 (tuned 12,5), presidio_favored 0,0 → 57,1 (tuned 0,0; die blanken neun Ziffern `121000358`
und die US-Kontonummer `945456787654` bleiben FN), Kundennummer neutral 46,7 → 51,1; Mitarbeiter-ID
und Benutzername unverändert. Offen (Q-FIN): Werte in SWIFT-MT-, FIX- und EDIFACT-Feldern ohne
Feldnamen, Feldnamen mit Zusatz (`Bank Routing Number for Direct Deposit:`) und nicht annotierte
Platzhalter (`Account Number: 123456789`), die Gretel nicht als Gold führt. Der Gold-Lücken-Bericht
(T16) wertet Konto-Gold jetzt mit dem ABA-Port und zählt BBANs dort als prüfzifferungültig.

Stand B-EU1: ARK 55, gemeinsam 19 (B09, B10, B11). Fünf Labels mit Prüfziffer, alle `ark_only`
(presidio-analyzer 2.2.364 kennt keine der Nummern): `FR_NIR` (`validators::fr_nir`, Schlüssel
97 − (13 Stellen mod 97), Korsika `2A`/`2B` als 19/18, dazu Geschlecht `1 2 3 4 7 8`, Monat
01–12, 20–42 oder 50–99 und Département ≠ 00), `FR_SIREN` (`fr_siren`, Luhn, nicht eine
wiederholte Ziffer), `FR_SIRET` (`fr_siret`, gültige SIREN und Luhn über 14 Stellen, La Poste
`356 000 000` per Quersumme mod 5), `NL_BSN` (`nl_bsn`, 11-Probe, die sie mit der alten btw-id
teilt) und `BE_NATIONAL_NUMBER` (`be_national_number`, Geburtsdatum mit BIS-Monat +20/+40,
laufende Nummer 001–998, 97 − (9 Stellen mod 97), ab 2000 mit vorangestellter 2). In jedem Modus
meldet je eine Regel den Wert mit einem Begriff des Labels in der Nähe oder als Schlüssel
(`pii_nir_fr` …, `requires_context`; Lexika `pii.fr_social_security_number`, `pii.fr_siren`,
`pii.fr_siret`, `pii.nl_citizen_service_number`, `pii.be_national_number` mit FR- und NL-Begriffen;
der NIR nimmt auch `pii.social_insurance_number`). Kontextfrei in `balanced`/`recall` (K05, 0,55)
nur die Formen, deren Gestalt die Prüfziffer stützt: der NIR in den Druckgruppen 1-2-2-2-3-3-2
oder als 15 Zeichen mit Geschlecht 1 oder 2 (zwei Prüfstellen, Monat und Département), die SIRET
in 3-3-3-5, die BSN in der Ausweisform `1234.56.782` und die Nationalregisternummer in der Kartenform
`85.07.30-033.28`. Die SIREN (neun Ziffern bestehen Luhn jedes zehnte Mal) steht wie ACN und TFN in
`CONTEXT_BOUND_LABELS`; blanke neun (BSN), elf (Nationalregisternummer, auch eine Steuer-ID) und
vierzehn Ziffern (SIRET) brauchen in jedem Modus den Begriff. `FR_NIR`, `FR_SIRET` und
`BE_NATIONAL_NUMBER` konkurrieren in den Score-Modi mit Karte bzw. Steuer-ID (K07). Gold steht in
`pii_l1` (DE, EN, FR, NL); das eingefrorene E05-Goldset erzeugt die fünf IDs nicht (`NOT_GENERATED`).

Stand Q-CONTACT (Qualitätsuntergrenze, 2026-10-25): Kontakt- und Kontofelder, die der Snapshot
2026-10-24 unter F1 80 führt. Die Lücken waren Feldwerte, die die feldgebundenen Regeln nicht banden:
`user=oeztuerk90` in Log- und Query-Zeilen (`user` nur mit `=`), ein Formular als Tabelle ohne
Randstriche (`Geburtsdatum | 21. Februar 1971`: neuer Struktur-Träger in `structure.rs`, ab zwei
Zeilen mit je einer Schlüssel- und einer Wertzelle, Schlüssel ohne Ziffer; er bindet jede
feldgebundene Regel und hebt auch ABN, NINO, Personnummer, LANR …), Geburtsdaten in ISO-Reihenfolge
(`1980-11-26`), nach `geb.`, `born on`, `date of birth of`, `DateOfBirth=`, einem geschützten
Leerzeichen oder `(e.g., …)`, mit Ordinaltag (`18th December 1983`) und den Monaten von FR/ES/IT/NL
(`26 de marzo de 1990`, `1er mars 1990`); `EMP821659` und `PN 201033` als Personalnummer, `ist`/
`lautet` und `(Personalnummer):`; `a customer ID of …`, `the customer with the ID …` und
`Kundennummer (z. B. …)`. Präziser: `login issues` ist keine Zuweisung, ein Name nach
`Account Name:` (`John Doe`, `ACME Inc.`) kein Konto (`context::continues_as_name`). Die
Datumsvalidatoren prüfen weiter den Kalender (`1985-02-30`, `31 de abril de 1990` bleiben negativ).
Dev balanced, exakt, vorher → nachher (strict gleich):

| Entität | neutral | presidio_favored | ark_authored |
|---|---|---|---|
| E-Mail | 68,8 → 68,8 | 100,0 | 100,0 |
| Telefon | 82,0 → 82,0 | 80,5 → 80,5 | 97,1 → 98,2 |
| Benutzername | 8,8 → 10,3 | – | 35,3 → 98,2 |
| Kundennummer | 51,1 → 60,9 | – | 98,9 → 99,5 |
| Personalnummer | 79,0 → 88,2 | – | 87,5 → 100,0 |
| Geburtsdatum | 66,7 → 67,0 | – | 71,4 → 99,7 |

Telefon lag auf `presidio_favored` schon vor Q-CONTACT über 80 (Snapshot 68,5). Vier Werte bleiben
auf `neutral` (Gretel Finance) unter 80, **Entscheidung:** Gold-Lücken, kein Regelproblem; Gretel
annotiert meist nur den einen eingesetzten Wert eines Dokuments, die Korpora werden nicht bearbeitet
(Option a, T16), und Funde werden nicht unterdrückt, um ungelabelte Werte zu treffen.

- **E-Mail 68,8.** Von 133 Markdown-Links `[x@y](mailto:x@y)` annotiert Gretel 103 gar nicht, 15 mit
  den eckigen Klammern im Span (`[x@y]`) und nur 13 beide Kopien; 250 der 283 FP sind diese
  Link-Adressen und ihre `mailto:`-Kopien. Presidio tuned liegt mit 67,9 gleichauf.
- **Benutzername 10,3.** 26 Gold-Werte; 27 der 29 FP sind Zellen einer `Username`-Spalte in CSV-
  Tabellen und `My username is vmccarthy`, die Gretel nicht annotiert. Die FN stehen ohne
  Benutzerfeld (`Customer: maarten_64`, `Hello nhanson`, EDIFACT `PER+FR+charlotte68`, FIX `56=…`).
- **Kundennummer 60,9.** Gretel führt Policen-, Produkt- und Steuernummern (`Policy Number:`,
  `Codice Fiscale:`, `Produktidentifikator:`), Fondsnamen und Werte ohne Kundenfeld (SWIFT `:33B:`,
  EDIFACT `RFF+ON:`) als `customer_id`; FP sind Werte unter `Klantnummer:`/`Customer ID:` und
  Kundenspalten, die Gretel nicht annotiert.
- **Geburtsdatum 67,0.** 37 FP, alle unter einem Geburtsdatum-Feld oder einer -Spalte: 24 in
  CSV-Tabellen, deren erste Zeile Gretel annotiert und die übrigen nicht, dazu `Geboortedatum:`-
  Zeilen ohne Gold. Ohne CSV-Bindung der ISO-Daten stünde `neutral` bei 75,0, ein Geburtsdatum in
  einer `date_of_birth`-Spalte bliebe aber unerkannt; die Spaltenbindung gilt wie für `TT.MM.JJJJ`.

Stand T29: ARK 55, gemeinsam 19. Die GB-BBAN (Bankcode aus vier Buchstaben, Sort Code, Konto:
`ZFJR88590163492773`) hat keine Prüfziffer (`validators::uk_bban`, nur Form, kein Konto aus Nullen
oder einer wiederholten Ziffer, M3 unverändert). `pii_bban_gb` meldet sie als
`FINANCIAL_ACCOUNT_NUMBER` in jedem Modus, wenn ein BBAN- oder Kontobegriff des K03-Lexikons nah am
Wert steht oder sein Strukturschlüssel ist (K04): `bank account number (BBAN) …`, `our bank account
number, …`, `… (BBAN)`, `Bankkonto des Mieters: …`, Schlüssel `bankkonto`, `bankingAccount`. Eine
kontextfreie Form gibt es nicht; blanke Werte und gleich geformte Codes hinter Bestell-, Referenz-,
Sendungs- oder VIN-Feldern bleiben negativ. Dev balanced, exakter F1: Kontonummer neutral 46,7 →
49,2 (4 neue TP, kein neuer FP); Kunden-, Mitarbeiter-ID und Benutzername unverändert. Von den
BBAN-förmigen FN auf Gretel bleiben Werte ohne Begriff (Adressen, SWIFT-MT-Tags, EDIFACT, XBRL),
der verschriebene Feldname `Mother' BBN:` und eine abgeschnittene CSV-Zeile offen.

Stand T30: ARK 55, gemeinsam 19 (M3 unverändert). Kfz-Kennzeichen DE und UK teilen einen Feldteil
(`ark-core/src/detectors/pii/licence_plate.rs`): DE/EN-Feldnamen vor dem Wert (`Kfz-Kennzeichen`,
`Kennzeichen`, `Number plate`, `licence plate`, `vehicle registration`, `car reg`, `My car,
registration …`), verbunden durch `:`, `|`, Tab, `is`, `ist`, `lautet`, `as` oder `on file is`,
oder als Strukturschlüssel (`kennzeichen`, `license_plate`, `licensePlate`, CSV-Kopf). Der DE-Wert
darf einen Bindestrich vor den Ziffern tragen (`K-MH-2476`) und das Suffix `E`/`H` und besteht eine
Formprüfung (`validators::de_licence_plate`: höchstens acht Zeichen ohne Trenner und Suffix, Nummer
ohne führende Null, FZV § 8); die UK-Form seit
2001 (`AB51 ABC`, `pii_vehicle_registration_uk`) braucht einen vergebenen Altersbezeichner
(`validators::uk_vehicle_registration`: 02–29, 51–79, wie presidio-analyzer). Beide sind reine
Formprüfungen ohne Bezirksliste (F16 bleibt zurückgestellt), deshalb bleibt ein Wert ohne
Kennzeichen-Feldnamen in jedem Modus negativ; ein allgemeines `registration number` nennt kein
Kennzeichen. Werte zählen nur in Großbuchstaben, wie gedruckt. Dev, exakter F1 in strict und
balanced: Kennzeichen `ark_authored` 34,8 → 100,0 (19 von 19), `presidio_favored` 0,0 → 9,1 (`My car
reg is AB51 ABC`), kein neuer FP. Die übrigen 20 `presidio_favored`-FN sind blanke Werte aus TR, IN,
NG und den alten UK-Formen (Präfix, Suffix) ohne Kennzeichen-Begriff und folgen der offenen
Entscheidung T27; `Plates: APP-456CV and KJA-999PZ` (NG) bleibt ebenfalls offen.

Stand B-LUHN: ARK 59, gemeinsam 22 (T13, T09; nur die Prüfziffer-Teile, die reinen Formteile
TR-Kennzeichen und US MBI fallen aus dem Programm). Vier Labels mit Prüfziffer, alle `shared`:
`SE_ORGANISATIONSNUMMER` (`validators::se_organisationsnummer`, dritte Ziffer ≥ 2, wo die
Personennummern den Geburtsmonat tragen, Luhn), `CA_SIN` (`ca_sin`, Luhn, erste Ziffer nicht 0 oder 8),
`TR_NATIONAL_ID` (`tr_national_id`, T.C. Kimlik No: keine führende Null, zehnte Ziffer 7 × ungerade
minus gerade Stellen mod 10, elfte Quersumme mod 10, zehn gleiche Ziffern ungültig) und `ZA_ID_NUMBER`
(`za_id_number`, Geburtsdatum, Staatsangehörigkeit 0–2, 8 oder 9, Luhn über 13 Stellen). Presidio
2.2.364 prüft die SIN nur per `invalidate_result`, deshalb zählt sie nicht als gemeinsame Einheit. In
jedem Modus meldet je eine Regel den Wert mit einem Begriff des Labels in der Nähe oder als Schlüssel
(`requires_context`; Lexika mit schwedischen, französischen, türkischen und Afrikaans-Begriffen);
kontextfrei in `balanced`/`recall` (K05, 0,55) die Organisationsnummer `NNNNNN-NNNN`, die SIN in
3-3-3-Gruppen mit Bindestrich und die südafrikanische ID-Nummer (13 Ziffern oder 6-4-3). Die SIN in
3-3-3-Gruppen mit Leerzeichen ist auch die Druckform von SIREN und BSN (bestehende Hard Negatives
`Vorgang 906 689 682`), blanke zehn, neun und elf Ziffern sind zu oft andere Nummern; sie brauchen in
jedem Modus den Begriff, die T.C. Kimlik No hat keine kontextfreie Form und konkurriert mit der
Steuer-ID (K07). Dev, exakter F1: `ark_authored` 100,0 für alle vier IDs in strict und balanced;
`presidio_favored` balanced Organisationsnummer 50,0, SIN 57,1, T.C. Kimlik No 66,7, ZA 100,0, Präzision
überall 100,0. Unter der Untergrenze 80 bleiben auf `presidio_favored` nur blanke Werte ohne Begriff
(`2120000142`, `130692544`, `130 692 544`, `79059236630`), die nach der Regel oben FN bleiben.
`pii_l1` führt dafür auch Zeilen in `sv` und `tr`, nur für die IDs des Landes.

Stand B-EU2: ARK 63, gemeinsam 22 (B06, B07, B14). Vier Labels mit Prüfziffer oder Prüfbuchstabe, alle
`ark_only` (presidio-analyzer 2.2.364 kennt keine der Nummern): `AT_SOCIAL_SECURITY_NUMBER`
(`validators::at_social_security_number`, Versicherungsnummer `LLLC DDMMYY`: Laufnummer ab 100, vierte
Ziffer gewichtet 3-7-9-5-8-4-2-1-6 mod 11, Rest 10 wird nie vergeben; das Datum wird nicht geprüft, weil
die Sozialversicherung bei erschöpften Laufnummern Tage über 31 und Monate über 12 vergibt),
`CH_AHV_NUMBER` (`ch_ahv_number`, AHVN13: Präfix 756 und EAN-13-Prüfziffer), `PT_NIF` (`pt_nif`) und
`IE_PPSN` (`ie_ppsn`, sieben Ziffern, Prüfbuchstabe mod 23, zweiter Buchstabe `A`/`B` gezählt, `W`/`T`/`X`
nicht). **PT NIF zählt getrennt von der USt-IdNr. PT (B16):** eigene ID `pii.pt.nif` und eigener
Validator; die Prüfung selbst ist mit `pt_vat_id` geteilt (`pt_nif_check`), ebenso der Prüfbuchstabe
von PPSN und irischer USt-IdNr. (`ie_check_letter`). Neun Ziffern nach `PT ` sind der Körper einer
USt-IdNr., keine NIF. In jedem Modus meldet je eine Regel den Wert mit einem Begriff des Labels in der
Nähe oder als Schlüssel (`requires_context`; Lexika mit DE-, FR-, IT- und PT-Begriffen, die AT- und
CH-Nummer auch mit `Sozialversicherungsnummer`); kontextfrei in `balanced`/`recall` (K05, 0,55) die
österreichische Nummer in der Druckform `NNNN DDMMYY` mit Kalenderdatum und die AHV-Nummer
`756.NNNN.NNNN.NN`. Zehn blanke Ziffern, 13 blanke Ziffern (eine EAN-13), die neun Ziffern der NIF
und sieben Ziffern mit Buchstabe (PPSN, auch eine Referenz) brauchen in jedem Modus den Begriff; NIF und
PPSN stehen in `CONTEXT_BOUND_LABELS`. Gold steht in `pii_l1` (DE, EN, dazu FR-Zeilen für die AHV- und
`pt`-Zeilen für die NIF); das eingefrorene E05-Goldset erzeugt die vier IDs nicht (`NOT_GENERATED`).
Dev-Scoreboard unverändert (kein Gold für die neuen IDs in den Dev-Korpora, keine neuen Funde).

Stand B-KR: ARK 66, gemeinsam 25 (A14, T12; nur die Prüfziffer-Teile). Drei Labels mit Prüfziffer,
alle `shared` mit dem gleichnamigen Recognizer von presidio-analyzer 2.2.364: `KR_RRN`
(`validators::kr_rrn`, 주민등록번호 `YYMMDD-GHHSSSC`: Geburtsdatum, Geschlechts- und Jahrhundertziffer
1–4, Regionalcode ≤ 95, Prüfziffer `(11 − Summe gewichtet 2…9, 2…5 mod 11) mod 10`), `KR_FRN` (`kr_frn`,
외국인등록번호, gleiche Form mit 5–8 und `(13 − …) mod 10`; geteilter Helfer `kr_registration_number`)
und `KR_BRN` (`kr_brn`, 사업자등록번호 `NNN-NN-NNNNN`, gewichtet 1-3-7-1-3-7-1-3-5 plus Zehner der neunten
Ziffer × 5, mod 10). Seit Oktober 2020 vergebene RRN tragen nach dem Regionalcode Zufallsziffern und
bestehen die Prüfung nur zufällig; Presidio meldet sie trotzdem (Prüfung liefert `None`), ARK nicht. In
jedem Modus meldet je eine Regel den Wert mit einem Begriff des Labels in der Nähe oder als Schlüssel
(Lexika mit EN-, DE- und koreanischen Begriffen); kontextfrei in `balanced`/`recall` (K05, 0,55) die
Bindestrich-Formen. 13 bzw. zehn blanke Ziffern brauchen in jedem Modus den Begriff. Führerschein und
Reisepass KR (T12, nur Form + Kontext) zählen nicht zu M3 und bleiben offen. Gold steht in `pii_l1`
(DE, EN, dazu `ko`-Zeilen) und im E05-Goldset (`ark_authored`), dazu die Recognizer-Tests
(`presidio_favored`, Sprache `ko`).

Stand A13: ARK 71, gemeinsam 29. Zwei Labels mit Prüfziffer: `PL_PESEL` (`validators::pl_pesel`, elf
Ziffern `YYMMDDZZZXC`, Geburtsdatum 1900–2100 mit dem Jahrhundert im Monat, Prüfziffer
`(10 − gewichtet 1-3-7-9 mod 10) mod 10`, `shared` mit dem Recognizer `PL_PESEL` von presidio-analyzer
2.2.364) und `PL_REGON` (`pl_regon`, neun Ziffern gewichtet 8-9-2-3-4-5-6-7 mod 11 oder vierzehn, deren
erste neun selbst eine REGON sind, gewichtet 2-4-8-5-0-9-7-3-6-1-2-4-8 mod 11; `ark_only`). Beide meldet je
eine Regel in jedem Modus mit einem Begriff des Labels in der Nähe oder als Schlüssel (Lexika mit EN-,
DE- und PL-Begriffen); blanke Ziffernfolgen nie, auch nicht in `balanced`/`recall`. Die NIP ist die
USt-IdNr. PL ohne Präfix und nutzt den B16-Validator `pl_vat_id` (keine Doppelzählung):
`pii_vat_id_pl_proximity` meldet die blanke NIP unter `VAT_ID_PL` mit einem USt- oder NIP-Begriff, nur in
`balanced`/`recall`, wie die blanke Partita IVA und CIF; nach `PL `/`PL-` bleibt sie Rumpf der USt-IdNr.
Gold steht in `pii_l1` (DE, EN, dazu `pl`-Zeilen), für PESEL auch im E05-Goldset (`ark_authored`) und in
den Recognizer-Tests (`presidio_favored`); die REGON erzeugt kein Goldset (`NOT_GENERATED`).

Stand B-ESIT: ARK 69, gemeinsam 28 (A11, A12). Drei Labels mit Kontrollbuchstabe, alle `shared` mit
dem gleichnamigen Recognizer von presidio-analyzer 2.2.364: `ES_NIF` (`validators::es_nif`, DNI/NIF,
acht Ziffern oder sieben eines alten DNI und der Kontrollbuchstabe mod 23), `ES_NIE` (`es_nie`, `X`/`Y`/`Z`
als 0/1/2, sieben Ziffern, derselbe Buchstabe; geteilter Helfer mit `es_vat_id`) und `IT_FISCAL_CODE`
(`it_fiscal_code`, 16 Zeichen, Monatsbuchstabe, Tag + 40 für Frauen, Omocodia, Kontrollbuchstabe über die
Tabellen für ungerade/gerade Stellen mod 26). In jedem Modus meldet je eine Regel den Wert mit einem
Begriff des Labels in der Nähe oder als Schlüssel (Lexika mit EN-, DE- und ES-/IT-Begriffen, jede
Schreibweise); kontextfrei in `balanced`/`recall` (K05, 0,55) die Werte in Großbuchstaben. NIF/NIE direkt
nach `ES `/`ES-` (NIF auch nach `CY `/`CY-`) bleiben der Rumpf der USt-IdNr. CIF und Partita IVA sind die USt-IdNr. von ES und IT ohne
Präfix und nutzen deren B01-Validatoren (keine Doppelzählung): `pii_vat_id_es_proximity` meldet die
blanke CIF unter `VAT_ID_ES` mit einem USt- oder CIF-Begriff, nur in `balanced`/`recall`, wie die blanke
Partita IVA (`pii_vat_id_it_proximity`, B01). Presidio meldet auch Codici fiscali mit falschem
Kontrollbuchstaben (`AAAAAA00B11C333N` der Recognizer-Tests), ARK nicht. Gold steht in `pii_l1` (DE,
EN, dazu `es`- und `it`-Zeilen) und in den Recognizer-Tests (`presidio_favored`).

Stand B02: ARK 24, gemeinsam 7. Dazu kommen die USt-IdNr. von BG, CY, CZ, DK, EE, EL, FI, HR, HU, IE
und LT, gleiche Struktur wie B01 (je Land ein Label `VAT_ID_BG` … und ein Validator mit Prüfziffer,
nur in `balanced`/`recall`), alle `ark_only`; Griechenland trägt im Label das MwSt.-Präfix `EL`, in
der ID den Ländercode (`pii.gr.vat_id`). Die Algorithmen folgen python-stdnum 2.2, strenger bei
Formen ohne Prüfziffer (neunstellige tschechische Geburtsnummer vor 1954) und bei Nullnummern.
`VAT_ID_HR` (elf Ziffern wie eine Steuer-ID) und `VAT_ID_LT` (zwölf Ziffern, mitunter kartenförmig)
konkurrieren nach K07 als längerer Wert. Das E05-Goldset erzeugt die elf IDs nicht; ihr Gold kommt aus den
VAT-Goldsets von GOLD-VAT1 und GOLD-VAT2.

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

## Gold-Konvention: IP-Spans (B-IP)

Festgelegt mit B-IP (T20 + Kandidat C1, TRIAGE 2026-W43 Bucket 5, Baseline P3/P9), wie das Gold der
presidio-analyzer-IP-Tests:

- **Ein Span je Adresse:** Eine IPv4-gemappte oder eingebettete IPv6-Adresse ist ein Span
  (`::ffff:10.0.0.1`, `64:ff9b::198.51.100.1`, `2001:db8:85a3::8a2e:192.168.0.1`), kein IPv4-Teilspan.
- **Zonen-ID und CIDR-Präfixlänge gehören in den Span:** `fe80::1%eth0`, `192.168.1.0/24`,
  `2001:db8::/32`, `2001:db8::%eth0/128`. Eine Präfixlänge außerhalb des Bereichs (IPv4 > 32,
  IPv6 > 128) gehört nicht dazu, die Adresse bleibt ein Span (`10.0.0.0/123` → `10.0.0.0`).
- **Kein Teiltreffer:** Eine ungültige Misch- oder Kettenform ergibt keinen Span, auch keinen
  Teilspan: `2001:db8::256.1.1.1` (Hard Negative P9), neun Gruppen, Doppelpunkt-Ketten aus SWIFT MT
  und EDIFACT (`:28C::52D:`, `:60F::61F::62F:`, `BGM+380:21:3::90:FRET`, `LIN+1::1:550:::EA:20`).
  Eine IPv6-Adresse beginnt nicht nach einer weiteren `:`-Gruppe, nach `.`, `-`, `+` oder einem
  Wortzeichen und endet nicht vor einer weiteren `:`- oder `.`-Gruppe; ein SWIFT-MT-Tag am
  Zeilenanfang (`:25:`, ` :52A:`) und ein Feldname (`IPv6:`, `inet6:`, `eth0:`) eröffnen den Wert.
  Endet das Wort vor dem `:` auf eine Hex-Folge aus drei oder mehr Zeichen mit einer Ziffer, ist
  diese Folge eine weitere `:`-Gruppe und das Wort kein Feldname (T28): `foo2001:db8::10.0.0.1`
  ergibt keinen Span, weder IPv6 noch den IPv4-Teil; der `presidio_favored`-Gold-Wert `10.0.0.1`
  dieser Zeile bleibt ein bekanntes FN.
- **Loopback und unspezifiziert bleiben negativ** (D-IP, 2026-10-21), auch gemappt und mit
  Präfixlänge: `::ffff:127.0.0.1`, `::ffff:0.0.0.0`, `::/0`, `::1/128`. Die neun
  `presidio_favored`-Gold-Werte dieser Art (`127.0.0.1`, `0.0.0.0`, `::` zweimal, `::1`,
  `::ffff:127.0.0.1`, `::ffff:0.0.0.0`, `::/0`, `::/128`) bleiben bekannte FN.

`validators::ip_address` prüft den ganzen Span (Präfixlänge, Zonen-ID nur bei IPv6). Der
Netzwerkdiagnose-Filter (`post_prediction.rs`) wertet private Adressen auch mit Zonen-ID, Präfixlänge
und in gemappter Form. Tests: `rust/tests/pii_ip_spans.rs`, Goldens `B_IP_SPAN_CASES` und `T28_IP_CASES`.

## Gold-Hygiene: Nebenentitäten und Prüfziffern

Seit T02 (TRIAGE 2026-W42, Buckets 6 + 7) annotiert ein Positiv in `pii_l1` jede echte Entität im
Text, nicht nur den Ziel-Span (Generator: `also=(Label, Wert)`), z. B. die PAN neben CVV oder
Ablaufdatum. Gewertet wird weiter nur das Ziel-Label. `rust/tests/pii_gold_hygiene.rs` prüft, dass
jeder Gold-Wert einen Validator seines Labels besteht (Known Gaps nur bei Luhn, MOD-97 und
Steuer-ID, nach Rückbau der Obfuskation) und dass jeder weitere L1-Treffer auf einem Positiv Gold
ist oder als Detektor-FP gelistet ist (bis B-PAN Telefonziffern mit gültiger Luhn-Summe und eine PAN in
einer noch nicht gemeldeten gruppierten Nicht-DE-IBAN; seitdem ist die Liste leer). PAN in einer gültigen IBAN und die IBAN als
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

## Kartennummern: IIN und Länge (B-PAN)

Seit B-PAN (T19 + F02, TRIAGE 2026-W43 Bucket 4, Baseline N1/P8) prüft `pii_credit_card` mit
`validators::payment_card`: Luhn (unverändert), dann IIN-Präfix und Länge einer Marke aus
`validators::CARD_IIN_RANGES` (Amex 34/37 mit 15, Diners 300–305/3095/36/38–39 mit 14–19, JCB 35 mit
16–19 sowie 1800/2131 mit 15, Mir 2200–2204, Mastercard 2221–2720 und 51–55 mit 16, Visa 4 mit 13/16/19,
Discover 6011/644–649/65, UnionPay 62, Maestro 50/56–69 mit 12–19, UATP 1 mit 15). JCB steht als `35`
in der Tabelle, weil Testkarten-Generatoren (presidio-evaluator) so erzeugen. 13 Ziffern, die mit einem
gültigen Datum YYMMDD beginnen (ZA-ID, KR-RRN), und Ziffern, die mit YYYYMMDD beginnen
(Zeitstempel), sind keine Karte. Dazu prüft die Regel die Lage: keine Karte direkt nach `+`
(`+44 20 1234 5678`, auch keine Teilspanne) und kein `-`/`_`-Segment eines Tokens (`xoxb-…-…`). Die
Prüfung gilt in jedem Modus; die kontextfreie Karte von `balanced` geht also durch dieselbe Tabelle.
Jeder Luhn-gültige PAN-Gold-Wert in `pii_l1`, der Rule-Fixture und den Dev-Korpora erfüllt sie
(`rust/tests/pii_card_precision.rs`). Der Gold-Lücken-Bericht (T16) wertet PAN-Gold seitdem mit
`payment_card`.

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

> **Seit 2026-10-23 flach und durchgehend.** Jede Aufgabe baut auf `main` auf (kein Stacking mehr);
> `publish` wartet bis zu 20 Minuten auf den automatischen Codex-Review und mergt den grünen PR noch im
> selben Lauf, wenn kein Thread offen ist. Offene Threads oder rote CI übernimmt der nächste Lauf als
> `REVIEW:<branch>` und mergt danach ebenso. Konflikte mit `main` löst `restack` (Rebase, sonst
> `RESTACK:<branch>`). Eine Aufgabe mit offenem PR wird nicht erneut gewählt. Während `ci` auf GitHub
> wartet und beim Publizieren gibt der Lauf das gemeinsame Lock frei, sodass das andere Programm schon
> arbeitet. Die Timer starten den nächsten Lauf 3 Minuten nach dem Ende des vorigen
> (`OnUnitInactiveSec=3min`); belegte Locks reihen ein. Die Beschreibung unten zu Stacks gilt nur noch
> für alte, gestapelte PRs.

Eine Claude-Cloud-Routine kommt nicht auf die VPS (Port 22 aus der Cloud gesperrt). Deshalb plant
die VPS selbst, und nur die VPS: `ark-l1.timer` startet alle 2 Stunden zu geraden Stunden `runner/run.sh`,
`ark-dlp.timer` zu ungeraden Stunden `runner/run.sh --program dlp`. Beide teilen ein Lock; ist es belegt,
wartet der Lauf ohne eigene Frist (systemd begrenzt Warten plus Lauf auf 24 Stunden) und startet direkt danach (seit 2026-10-21; vorher entfiel er, und ein
langer Lauf des einen Programms verdrängte mehrere Slots des anderen). So wechseln sich die Programme ab.

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
- **Auto-Merge** (entschieden 2026-10-21): Zu Beginn jedes Laufs merged `ark-l1 next` den untersten
  Stack-PR per Squash, wenn er auf `main` zielt, kein Draft ist, GitHub ihn als `MERGEABLE` meldet und
  seine CI vollständig grün ist (dieselben Checks wie `ark-l1 ci`) und kein Review-Thread offen ist
  (`main` verlangt aufgelöste Threads). Gemergt wird über `PUT …/pulls/{n}/merge-async` (Pflicht für
  GitHubs native Stacks); danach wartet der Runner, bis GitHub die PRs darüber auf `main` umgesetzt hat.
  Höchstens einer pro Lauf; der nächste folgt nach Restack und neuer CI. Abschalten:
  `ARK_L1_AUTO_MERGE=0` in der Service-Umgebung.
- **Review-Läufe** (seit 2026-10-23): Nach Auto-Merge und Restack prüft `ark-l1 next` den Stack von
  unten nach oben. Hat ein PR unaufgelöste Review-Threads (Codex, CodeQL, Menschen) oder rote CI, wird
  er zur Aufgabe des Laufs (`REVIEW:<branch>`, Prompt `runner/AGENT_PROMPT.review.md`), vor jeder neuen
  Backlog-Aufgabe. Rote CI mit Runner-/Toolchain-Fehler im Log (z. B. `failed to install component`)
  wird stattdessen einmal neu gestartet. Der Agent committet den Fix auf dem PR-Branch, Gate und CI
  prüfen wie sonst, `ci` pusht mit Lease auf den alten Head, `publish` antwortet in jedem Thread mit dem
  Commit (plus der Notiz des Agenten aus `.git/ark-review.json`) und löst ihn auf. Drei rote Runden
  blockieren `REVIEW:<branch>`; der PR bleibt dann bis `unblock` unmergebar, neue Aufgaben laufen weiter.
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
  Die VAT-Goldsets aus GOLD-VAT1 (`--goldset vat-1`) und GOLD-VAT2 (`--goldset vat-2`) frieren die Schritte
  `synthetic-goldset-vat-1` und `synthetic-goldset-vat-2` genauso nach `…/synthetic-vat-1/` bzw.
  `…/synthetic-vat-2/` ein (Holdout-Seed jeweils in dessen `.seed` unter `~/ark-l1/holdout/`), erst nach
  Neuinstallation des Runners.
- **Scoreboard:** `scripts/l1_presidio/scoreboard.py gate` rechnet Head und Basis in den PII-Modi
  `strict` und `balanced` (exakt und überlappend, je Entität, DE/EN, je Quellfamilie, Hard-Negative-FP)
  auf Dev und Holdout; Exit 1 bei > 0,5 pp F1-Verlust oder neuem Hard-Negative-Treffer in einem der
  beiden Modi (T15). Lokal mit `--dev "$ARK_L1_DEV_DATA"` ohne
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

Gekürzt am 2026-10-21 auf den kritischen Pfad zu M1–M4: Die offenen Aufgaben stehen in Laufreihenfolge
im Abschnitt „Critical path“ von `backlog.yaml`. Ähnliche Aufgaben sind zu Bündeln zusammengefasst
(`bundles: [...]`; aufgegangene Aufgaben tragen `status: bundled` und `into`), Aufgaben ohne
Meilenstein-Wirkung tragen `status: deferred` mit Grund. 35 offene Aufgaben, bei 2 Läufen/Tag
≈ 2,5–3 Wochen. Neue TRIAGE-Aufgaben nur, wenn sie einen Meilenstein bewegen.

Entscheidung vom 2026-10-24: Die Latenz (M4) kommt ans Ende, nach allen Regel-Aufgaben, weil jede neue Regel sie wieder verschiebt (gemessen 24.10.: 100 KiB p95 ≈ 150 ms, DE ≈ 155 ms); H03 steht deshalb direkt vor H06.

Entscheidungen vom 2026-10-21: M2 gilt auf beiden Familien (umgesetzt in D-M2, Regel oben; neutral: ≥ Presidio tuned + 15 pp;
`presidio_favored`: ≥ Presidio tuned). Loopback- und unspezifizierte Adressen (`127.0.0.1`, `::1`,
`0.0.0.0`, `::`) verwirft ARK in jedem Modus; ihre Gold-Werte auf `presidio_favored` bleiben eine
bekannte Lücke für M1 (IP).
