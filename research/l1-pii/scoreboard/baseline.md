# L1-PII-Baseline: ARK vs. Presidio (E11)

Stand: 2026-10-19, Base `l1/020-e12` (E01–E10, E12, T01, T02 erledigt; ARK-Quellen wie `e723240`, natives Modul
SHA-256 `87496da37aef…`, Paket 0.1.10, Release-Build, Modus `strict`). Presidio 2.2.364 in beiden Profilen
(`default`, `tuned`), Pins aus `scripts/l1_presidio/requirements.txt`. Nur Dev-Daten; der Holdout wurde nicht
angesehen. Die Tabellen ab [Anhang](#anhang-tabellen) erzeugt `scoreboard.py report` (Befehle unter
[Reproduktion](#reproduktion)); Fehler-Buckets und Kandidaten sind Handarbeit für die nächste TRIAGE.

## Datenlage

| Familie | Korpus | Dev-Zeilen | Gold (L1) | Manifest (`.ready`) |
|---|---|---:|---:|---|
| neutral | `gretel-synthetic-pii-finance` | 1931 | 1447 | `1c719a85…` |
| neutral | `ai4privacy-openpii-nano-1k` | 355 | 554 | `1c719a85…` |
| neutral | `tab` | 50 | 0 (nur semantisch) | `1c719a85…` |
| presidio_favored | `presidio-evaluator-synth-v2` | 570 | 138 | `dc48f425…` |
| presidio_favored | `presidio-analyzer-recognizer-tests` | 553 | 341 | `dc48f425…` |
| ark_authored | `ark-synthetic-de-eu` | 420 | 2869 | `b63d890e…` |

Die Familie `presidio_favored` lag auf der VPS noch nicht unter `$ARK_L1_DEV_DATA` (Gate-Schritt
`presidio-favored-corpora` steht aus). Der Dev-Split wurde lokal mit
`prepare_corpora.py --family presidio_favored` aus den gepinnten Quellen erzeugt; der dabei mit entstehende
Holdout-Split wurde ungelesen gelöscht. Erzeugt das Gate die Familie, muss das Dev-Manifest denselben
SHA-256 `dc48f425975b…` haben, sonst gelten die Zahlen dieser Familie nicht.

## Ergebnis auf einen Blick (exact span, L1-IDs)

| Familie | ARK P/R/F1 | Presidio default F1 | Presidio tuned P/R/F1 | HN-FP ARK / default / tuned |
|---|---|---:|---|---|
| neutral | 58.7 / 47.8 / **52.7** | 18.0 | 35.3 / 47.4 / 40.5 | 0 / 0 / 0 |
| presidio_favored | 87.6 / 30.9 / 45.7 | 63.7 | 92.1 / 58.2 / **71.4** | **2** / 7 / 0 |
| ark_authored ¹ | 83.6 / 25.4 / 39.0 | 19.1 | 56.7 / 36.4 / **44.3** | 2 / 867 / 158 |

¹ berichtet, entscheidet keinen Meilenstein (Fairness-Regel, E12).

- **Neutral:** ARK liegt gesamt 12 pp vor tuned, dank Präzision (58.7 vs. 35.3) bei gleichem Recall;
  `default` meldet 9259 Spans auf 2001 Gold (P 10.9).
- **Presidio-favored:** ARK verliert 26 pp, fast nur über Recall (30.9 vs. 58.2). Die Recognizer-Tests
  bestehen großteils aus blanken Werten ohne Feldnamen (`F12345671`, `987-65-4322`, `GB82 WEST …`), die
  ARK im Modus `strict` grundsätzlich nicht meldet. Auf `presidio-evaluator-synth-v2` liegt ARK nur 3.9 pp
  zurück (77.4 vs. 81.3), dort fehlen vor allem URL (`presidio_only`) und Telefonformate.
- **Hard Negatives:** Auf `presidio_favored` trifft ARK 2 Negativfälle, tuned keinen. Das Kriterium
  „Immer: FP auf Hard Negatives ≤ Presidio“ ist damit auf einer entscheidenden Familie verletzt (siehe
  Bucket P8, P9). Auf `ark_authored` 2 vs. 158 (bekannt aus TRIAGE W43, T21).

## Stand der Meilensteine

| Meilenstein | Stand (Dev) | Lücke |
|---|---|---|
| M1 Parität EN | **nicht erreicht**. neutral 3/9 gemeinsame IDs ≥ tuned, presidio_favored 4/12 | siehe nächste Tabelle |
| M2 DE/EU (Macro-F1 ≥ tuned + 15 pp) | neutral DE: ARK 44.6 vs. tuned 18.6 (+26.0 pp, 14 IDs, nur 161 Gretel-DE-Zeilen); presidio_favored DE: ARK 2.0 vs. tuned 87.0 (11 IDs, nur blanke DE-Prüfziffernwerte). Nicht erreicht, solange beide Familien zählen | P1 (blanke DE-Werte), Messmodus T15 |
| M3 Breite (Zählregel T03, 2×) | nicht gemessen, `count_validated.py` fehlt (T03) | T03 |
| M4 Latenz (100 KiB p95 ≤ 10 ms) | **nicht erreicht**: 76 ms Python, 68 ms nativ; Presidio ≈ 10,4 s ([`latency.md`](latency.md), E07) | Hebel 6 |
| Immer: HN-FP ≤ Presidio | **verletzt** auf presidio_favored (2 vs. 0); neutral 0 vs. 0 | P8, P9 |

Macro-F1 für M2 hier: Mittel des exakten F1 über alle L1-IDs mit DE-Gold in der Familie, einschließlich
`ark_only`/`presidio_only`. Eine verbindliche M2-Definition (welche IDs, welcher Modus) fehlt noch; das
ist ein Kandidat für die TRIAGE (C7).

### M1 je gemeinsamer Entität (EN, exact F1, ARK vs. tuned)

| Entität | neutral Gold | ARK | tuned | presidio_favored Gold | ARK | tuned | Buckets |
|---|---:|---:|---:|---:|---:|---:|---|
| Führerschein | 32 | 0.0 | 7.8 | 11 | 0.0 | 90.0 | P6, W43 (F15, A07) |
| Reisepass | 38 | 44.9 | 53.2 | 8 | 0.0 | 40.0 | P6, W43-10 (T24, A05) |
| Kreditkarte (PAN) | 37 | 45.8 | 49.1 | 49 | **98.0** | 91.1 | N1 (T19) |
| E-Mail | 171 | 57.0 | 57.0 | 16 | 93.8 | 100.0 | P7 (F05), W43-13 |
| Kontonummer | 79 | 1.9 | 13.2 | 5 | 0.0 | 0.0 | W43 (A04, T26) |
| IBAN | 26 | 96.3 | 96.3 | 66 | 63.9 | 100.0 | P2 (T05) |
| IP-Adresse | 48 | 87.9 | 92.2 | 41 | 56.8 | 96.2 | P3, P4, W43-5 (T20) |
| Telefon | 222 | **41.9** | 35.6 | 46 | 53.5 | 65.1 | P5 (T04, T18, F01) |
| US-SSN | 29 | 58.5 | 79.3 | 15 | 57.1 | 88.9 | P1, W43-11 (T25, F07) |
| UK-NINO | – | – | – | 3 | 0.0 | 100.0 | P6 |
| MAC, Kennzeichen | – | – | – | 6 / 16 | 100 / 0 | 100 / 0 | – |

Neu gegenüber TRIAGE W43: Auf **englischen** neutralen Zeilen (M1-Sicht) liegt ARK bei PAN unter tuned
(45.8 vs. 49.1), obwohl ARK über alle Sprachen vorn liegt (41.1 vs. 35.6). Ursache sind PAN-FP aus Bucket 4
von W43 (`+[44 20 1234 5678]`, Zeitstempel), also T19.

## Fehler-Buckets

### Neutral

Die Buckets 1–16 aus [TRIAGE 2026-W43](../triage/2026-W43.md) gelten unverändert. Seitdem hat sich keine
Detektor-Regel geändert, und die Zahlen je Korpus sind identisch (Gretel 49.8 / 36.3, Nano 62.3 / 57.3). Sie
sind dort Aufgaben zugeordnet (T16–T26, F01, F07, F15, A04, A05, A07). Hinzu kommt:

| # | Bucket | Belege (Dev) | Zuordnung |
|---|---|---|---|
| N1 | PAN-FP kosten M1 auf EN | Gretel EN: `+[44 20 1234 5678]` (3), `DTM+137:[202201010800]`; Nano: `0157-09-316-8811` | T19 (Priorität für M1) |

### Presidio-favored (neu)

| # | Bucket | Belege (Dev) | Zuordnung |
|---|---|---|---|
| P1 | Blanke Prüfziffernwerte ohne Feldnamen | Recognizer-Tests DE: KVNR 3, LANR 3, Steuernummer 2, Steuer-ID 1, RVNR 1, Pass 6, Ausweis 7 FN, alle von tuned gefunden (`B123456782`, `234567701`, `98765432106`, `F12345671`); US-SSN `987-65-4322`, `219-09-9999` (3) | K05 (balanced) und T15. In `strict` bleibt das per Entscheidung K02 aus |
| P2 | Gruppierte Nicht-DE-IBAN | 35 von 66 IBAN-FN (`AZ21 NABZ 0000 …`, `NL91 ABNA 0417 1643 00`, `CH93 0076 …`), alle von tuned gefunden | T05 (bestätigt, größter Einzelposten in der Familie) |
| P3 | IPv6-Spangrenzen | IPv4-gemappt/eingebettet `::ffff:10.0.0.1`, `64:ff9b::198.51.100.1` (6, ARK meldet nur den IPv4-Teil bzw. `::ffff:127`), Zonen-ID `fe80::1%eth0` (1), CIDR `192.168.1.0/24`, `2001:db8::/32` (8, ARK meldet die Adresse ohne Präfixlänge); dazu 12 FP aus diesen Teilspans | **Kandidat C1** |
| P4 | Loopback/unspezifiziert | `127.0.0.1`, `0.0.0.0`, `::1`, `::` (5): `validators::ip_address` verwirft sie absichtlich, Presidio-Gold zählt sie | **Kandidat C2** (needs_decision) |
| P5 | Telefonformate | presidio-evaluator: Durchwahl `345-899-3560x4587`, `+1-604-696-5272x565` (6; ARK schneidet bei `x` ab oder meldet nichts), `(579)888-3058` ohne Leerzeichen (2), `001-518-640-0854` (1), FR/BE/AT `01.84.17.61.18`, `0494 92 82 32` (4), blanke 10 Ziffern (2); Recognizer-Test JP `090-1234-5678` | Durchwahl **Kandidat C3**; Rest T04, T18, F01 |
| P6 | Pass-/Führerschein-/NINO-Varianten | Von tuned gefunden: UK-Führerschein `MORGA657054SM9IJ` (5), „my driver's license number is 6940579“ (4), US-Pass „my travel passport is A12803456“ (2), KR-Pass „My old passport M12345678“ (1), UK-NINO `tw987654a`, `hh 01 02 03 d` (3); `Pass-Nr.: F12345671` verfehlt ARK trotz Feldname (Regel kennt `Pass-Nr.` nicht). Blanke US/UK/ES/KR-Pässe (17) findet auch tuned nicht | A05, A07, F15, T10, T12, T24; NINO **Kandidat C4**, `Pass-Nr.` in K03-Lexikon |
| P7 | E-Mail mit IDN-TLD | `a@xn--d1acufc.xn--p1ai`: ARK schneidet nach `.xn` ab (1 FN + 1 FP) | F05 (IDN) |
| P8 | PAN-FP ohne gültige IIN | Hard Negative `1748503543012` (13 Ziffern, Luhn gültig, kein Kartenpräfix); presidio-evaluator `+[447700677662]` | T19 |
| P9 | IPv6-Teiltreffer auf ungültiger Adresse | Hard Negative `2001:db8::256.1.1.1`: ARK meldet `2001:db8::256` | **Kandidat C1** |
| P10 | Gold-Eigenheiten | NINO-Gold `[ YZ 61 48 68 B]` mit führendem Leerzeichen; SSN-Testfälle `078-051121`, `07805-1121`, `078051121` erwartet keine Engine | keine Aufgabe; wie T16 nur berichten |

Entitäten nur bei Presidio (`presidio_only`, z. B. URL 21 Gold, ITIN, Krypto-Wallets) stehen in den
Tabellen, sind aber kein M1-Kriterium; ihre Aufgaben stehen im A/B-Block.

## Kandidaten für die TRIAGE

Neue Einträge legt erst die TRIAGE an; dieser Bericht ordnet nur vor.

| # | Kandidat | Familie / Wirkung | Vorschlag |
|---|---|---|---|
| C1 | IPv6 im Strict-Modus: IPv4-gemappte/eingebettete Adressen als ein Span, Zonen-ID, CIDR-Präfixlänge im Span (Konvention festlegen), kein Teiltreffer auf ungültigen Mischformen | presidio_favored IP 56.8 → bis ≈ 90; behebt ein Hard-Negative-FP | precision-/recall-fix nach T20, deps E06 |
| C2 | Loopback und unspezifizierte Adressen (`127.0.0.1`, `::1`, `0.0.0.0`, `::`): Gold-Konvention wie T01 | 5 FN; Validatoren werden nicht ohne Entscheidung gelockert | needs_decision |
| C3 | NANP-Durchwahl `x123`/`ext. 123` im Telefonspan | presidio-evaluator 6 FN + Teil-FP | fix nach T18 |
| C4 | UK-NINO ohne Leerzeichen bzw. in Zweiergruppen (`hh 01 02 03 d`), Kleinschreibung bei explizitem Feldnamen | 3 FN, M1-ID mit Gold nur in presidio_favored | fix, deps K03 |
| C5 | Reihenfolge: T19 (PAN-Präzision) entscheidet zwei M1-Lücken (neutral EN PAN) und ein „Immer“-Kriterium; T05 ist der größte IBAN-Hebel auf presidio_favored | – | Priorisierung durch den Menschen |
| C6 | Messmodus: P1 zeigt, dass presidio_favored im Modus `strict` strukturell nicht zu gewinnen ist (blanke Werte) | M1, M2 | in T15 einfließen lassen |
| C7 | M2-Definition (IDs, Familien, Mindest-Gold) | M2 | needs_decision |
| C8 | Gate-Schritt `presidio-favored-corpora` ausführen, damit Dev und Holdout der Familie auf der VPS liegen | alle | Runner-Neuinstallation |

## Reproduktion

```bash
# presidio_favored-Dev (bis das Gate sie anlegt); Holdout-Ausgabe ungelesen löschen
python3 scripts/l1_presidio/prepare_corpora.py --family presidio_favored \
  --dev-out DEV/presidio_favored --holdout-out /tmp/unread --sources /tmp/sources && rm -rf /tmp/unread
# DEV = $ARK_L1_DEV_DATA (+ presidio_favored/); je Gold-Datei f (relativer Pfad):
.venv/bin/python scripts/l1_presidio/run_ark.py --input DEV/$f --output PRED/ark/$f
~/ark-l1/presidio-venv/bin/python scripts/l1_presidio/run_presidio.py --profile default \
  --input DEV/$f --output PRED/presidio-default/$f
~/ark-l1/presidio-venv/bin/python scripts/l1_presidio/run_presidio.py --profile tuned \
  --input DEV/$f --output PRED/presidio-tuned/$f
python3 scripts/l1_presidio/scoreboard.py report --gold DEV --engine ark=PRED/ark \
  --engine presidio-default=PRED/presidio-default --engine presidio-tuned=PRED/presidio-tuned
python3 scripts/l1_presidio/scoreboard.py m1 --gold DEV --ark PRED/ark --presidio PRED/presidio-tuned
```

## Anhang: Tabellen

Ausgabe von `scoreboard.py report` (Dev, exact span, Prozent).

### Overall per source family

| Family | Engine | Rows | Gold | Pred | Exact P | Exact R | Exact F1 | Overlap F1 | EN F1 | DE F1 | HN-FP |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| ark_authored ¹ | ark | 420 | 2869 | 872 | 83.6 | 25.4 | 39.0 | 39.7 | 37.9 | 40.0 | 2 |
| ark_authored ¹ | presidio-default | 420 | 2869 | 3666 | 17.0 | 21.7 | 19.1 | 19.4 | 21.8 | 16.7 | 867 |
| ark_authored ¹ | presidio-tuned | 420 | 2869 | 1838 | 56.7 | 36.4 | 44.3 | 44.8 | 32.9 | 53.4 | 158 |
| neutral | ark | 2336 | 2001 | 1630 | 58.7 | 47.8 | 52.7 | 60.3 | 49.6 | 51.9 | 0 |
| neutral | presidio-default | 2336 | 2001 | 9259 | 10.9 | 50.5 | 18.0 | 19.9 | 16.3 | 13.4 | 0 |
| neutral | presidio-tuned | 2336 | 2001 | 2690 | 35.3 | 47.4 | 40.5 | 44.0 | 37.8 | 32.9 | 0 |
| presidio_favored | ark | 1123 | 479 | 169 | 87.6 | 30.9 | 45.7 | 51.2 | 55.3 | 5.1 | 2 |
| presidio_favored | presidio-default | 1123 | 479 | 331 | 77.9 | 53.9 | 63.7 | 64.7 | 73.4 | 18.6 | 7 |
| presidio_favored | presidio-tuned | 1123 | 479 | 303 | 92.1 | 58.2 | 71.4 | 72.1 | 77.4 | 93.0 | 0 |

¹ ark_authored is reported and decides no milestone.

### Per corpus (exact P / R / F1)

| Corpus | Family | Rows | Gold | ark | presidio-default | presidio-tuned |
|---|---|---:|---:|---|---|---|
| ai4privacy-openpii-nano-1k | neutral | 355 | 554 | 88.7 / 48.0 / **62.3** | 37.4 / 48.7 / 42.4 | 71.1 / 48.0 / 57.3 |
| ark-synthetic-de-eu | ark_authored | 420 | 2869 | 83.6 / 25.4 / 39.0 | 17.0 / 21.7 / 19.1 | 56.7 / 36.4 / **44.3** |
| gretel-synthetic-pii-finance | neutral | 1931 | 1447 | 52.0 / 47.8 / **49.8** | 8.7 / 51.2 / 14.8 | 29.5 / 47.2 / 36.3 |
| presidio-analyzer-recognizer-tests | presidio_favored | 553 | 341 | 79.2 / 16.7 / 27.6 | 94.8 / 43.1 / 59.3 | 100.0 / 49.3 / **66.0** |
| presidio-evaluator-synth-v2 | presidio_favored | 570 | 138 | 93.8 / 65.9 / 77.4 | 63.1 / 80.4 / 70.7 | 82.2 / 80.4 / **81.3** |
| tab | neutral | 50 | 0 | 0.0 / 0.0 / 0.0 | 0.0 / 0.0 / 0.0 | 0.0 / 0.0 / 0.0 |

### Per entity (exact F1, best in bold)

| Family | Entity | Scope | Gold | ark | presidio-default | presidio-tuned |
|---|---|---|---:|---:|---:|---:|
| ark_authored | entity.driver_license_number | shared | 23 | 23.1 | 0.8 | **48.1** |
| ark_authored | entity.passport_number | shared | 24 | 28.6 | 6.6 | **54.5** |
| ark_authored | pii.applicant_id | ark_only | 24 | **58.8** | 0.0 | 0.0 |
| ark_authored | pii.au.abn | presidio_only | 18 | 0.0 | 0.0 | 0.0 |
| ark_authored | pii.au.acn | presidio_only | 24 | 0.0 | 0.0 | 0.0 |
| ark_authored | pii.au.medicare | presidio_only | 19 | 0.0 | 0.0 | 0.0 |
| ark_authored | pii.au.tfn | presidio_only | 20 | 0.0 | 0.0 | 0.0 |
| ark_authored | pii.ca.sin | presidio_only | 23 | 0.0 | 0.0 | 0.0 |
| ark_authored | pii.credit_card.cvv | ark_only | 27 | 0.0 | 0.0 | 0.0 |
| ark_authored | pii.credit_card.expiry | ark_only | 26 | 0.0 | 0.0 | 0.0 |
| ark_authored | pii.credit_card.pan | shared | 19 | 46.3 | **79.2** | **79.2** |
| ark_authored | pii.crypto_wallet | presidio_only | 21 | 0.0 | **100.0** | **100.0** |
| ark_authored | pii.customer_id | ark_only | 93 | **85.2** | 0.0 | 0.0 |
| ark_authored | pii.date_of_birth | ark_only | 144 | **66.7** | 0.0 | 0.0 |
| ark_authored | pii.de.bsnr | presidio_only | 50 | 0.0 | 0.0 | **65.0** |
| ark_authored | pii.de.commercial_register | presidio_only | 56 | 0.0 | 0.0 | **88.0** |
| ark_authored | pii.de.health_insurance_number | shared | 55 | 84.2 | 0.0 | **86.6** |
| ark_authored | pii.de.lanr | shared | 53 | **88.4** | 0.0 | 82.5 |
| ark_authored | pii.de.postal_code | presidio_only | 231 | 0.0 | 0.0 | **85.2** |
| ark_authored | pii.de.social_security_number | shared | 25 | **52.9** | 0.0 | 27.6 |
| ark_authored | pii.de.tax_id | shared | 27 | **61.5** | 0.0 | 32.4 |
| ark_authored | pii.de.tax_number | shared | 55 | 80.4 | 0.0 | **84.5** |
| ark_authored | pii.de.vat_id | presidio_only | 87 | 0.0 | 0.0 | **65.1** |
| ark_authored | pii.email | shared | 144 | **100.0** | **100.0** | **100.0** |
| ark_authored | pii.employee_id | ark_only | 27 | **61.5** | 0.0 | 0.0 |
| ark_authored | pii.es.nie | presidio_only | 26 | 0.0 | 0.0 | 0.0 |
| ark_authored | pii.es.nif | presidio_only | 26 | 0.0 | 0.0 | 0.0 |
| ark_authored | pii.fi.personal_identity_code | presidio_only | 28 | 0.0 | 0.0 | 0.0 |
| ark_authored | pii.financial_account_number | shared | 20 | 23.1 | 6.1 | **46.2** |
| ark_authored | pii.iban | shared | 81 | 68.3 | **100.0** | **100.0** |
| ark_authored | pii.identity_card_number | shared | 31 | 22.9 | 0.0 | **38.5** |
| ark_authored | pii.in.aadhaar | presidio_only | 22 | 0.0 | 0.0 | 0.0 |
| ark_authored | pii.in.gstin | presidio_only | 24 | 0.0 | 0.0 | 0.0 |
| ark_authored | pii.in.pan | presidio_only | 19 | 0.0 | 0.0 | 0.0 |
| ark_authored | pii.in.voter_id | presidio_only | 23 | 0.0 | 0.0 | 0.0 |
| ark_authored | pii.ip_address | shared | 84 | **100.0** | **100.0** | **100.0** |
| ark_authored | pii.it.fiscal_code | presidio_only | 23 | 0.0 | 0.0 | 0.0 |
| ark_authored | pii.it.vat_code | presidio_only | 28 | 0.0 | 0.0 | 0.0 |
| ark_authored | pii.kr.brn | presidio_only | 27 | 0.0 | 0.0 | 0.0 |
| ark_authored | pii.kr.frn | presidio_only | 23 | 0.0 | 0.0 | 0.0 |
| ark_authored | pii.kr.rrn | presidio_only | 24 | 0.0 | 0.0 | 0.0 |
| ark_authored | pii.license_plate | shared | 19 | 34.8 | 0.0 | **69.0** |
| ark_authored | pii.mac_address | shared | 22 | **100.0** | **100.0** | **100.0** |
| ark_authored | pii.ng.nin | presidio_only | 28 | 0.0 | 0.0 | 0.0 |
| ark_authored | pii.patient_id | ark_only | 22 | **62.5** | 0.0 | 0.0 |
| ark_authored | pii.ph.tin | presidio_only | 24 | 0.0 | 0.0 | 0.0 |
| ark_authored | pii.ph.umid | presidio_only | 24 | 0.0 | 0.0 | 0.0 |
| ark_authored | pii.phone | shared | 85 | **43.7** | 27.8 | 27.8 |
| ark_authored | pii.pl.pesel | presidio_only | 22 | 0.0 | 0.0 | 0.0 |
| ark_authored | pii.se.organisationsnummer | presidio_only | 20 | 0.0 | 0.0 | 0.0 |
| ark_authored | pii.se.personnummer | presidio_only | 19 | 0.0 | 0.0 | 0.0 |
| ark_authored | pii.sg.nric_fin | presidio_only | 21 | 0.0 | 0.0 | 0.0 |
| ark_authored | pii.sg.uen | presidio_only | 24 | 0.0 | 0.0 | 0.0 |
| ark_authored | pii.student_id | ark_only | 30 | **37.8** | 0.0 | 0.0 |
| ark_authored | pii.swift_bic | ark_only | 84 | **19.4** | 0.0 | 0.0 |
| ark_authored | pii.th.tnin | presidio_only | 24 | 0.0 | 0.0 | 0.0 |
| ark_authored | pii.tr.national_id | presidio_only | 21 | 0.0 | 0.0 | 0.0 |
| ark_authored | pii.uk.national_insurance_number | shared | 22 | 48.3 | 0.0 | **50.0** |
| ark_authored | pii.uk.nhs_number | presidio_only | 53 | 0.0 | **83.5** | 83.0 |
| ark_authored | pii.uk.postcode | presidio_only | 235 | 0.0 | 0.0 | 0.0 |
| ark_authored | pii.url | presidio_only | 20 | 0.0 | **8.2** | **8.2** |
| ark_authored | pii.us.itin | presidio_only | 22 | 0.0 | **86.3** | 58.1 |
| ark_authored | pii.us.mbi | presidio_only | 24 | 0.0 | 0.0 | 0.0 |
| ark_authored | pii.us.medical_license | presidio_only | 22 | 0.0 | **74.6** | 52.6 |
| ark_authored | pii.us.npi | presidio_only | 22 | 0.0 | 0.0 | 0.0 |
| ark_authored | pii.us.social_security_number | shared | 29 | 34.3 | 29.7 | **55.6** |
| ark_authored | pii.username | ark_only | 84 | **15.4** | 0.0 | 0.0 |
| ark_authored | pii.za.id_number | presidio_only | 23 | 0.0 | 0.0 | 0.0 |
| neutral | entity.driver_license_number | shared | 120 | 0.0 | 0.8 | **6.2** |
| neutral | entity.passport_number | shared | 98 | 26.5 | 18.7 | **38.4** |
| neutral | pii.credit_card.cvv | ark_only | 47 | 0.0 | 0.0 | 0.0 |
| neutral | pii.credit_card.pan | shared | 135 | **41.1** | 35.6 | 35.6 |
| neutral | pii.customer_id | ark_only | 90 | **33.0** | 0.0 | 0.0 |
| neutral | pii.date_of_birth | ark_only | 82 | **54.7** | 0.0 | 0.0 |
| neutral | pii.email | shared | 417 | 67.4 | **67.9** | **67.9** |
| neutral | pii.employee_id | ark_only | 75 | **57.1** | 0.0 | 0.0 |
| neutral | pii.financial_account_number | shared | 126 | 3.8 | 5.0 | **12.5** |
| neutral | pii.iban | shared | 70 | 80.6 | **81.6** | **81.6** |
| neutral | pii.ip_address | shared | 88 | 90.6 | **94.6** | **94.6** |
| neutral | pii.phone | shared | 504 | **53.6** | 36.7 | 36.7 |
| neutral | pii.swift_bic | ark_only | 79 | **38.5** | 0.0 | 0.0 |
| neutral | pii.us.social_security_number | shared | 44 | 45.6 | 21.4 | **66.7** |
| neutral | pii.username | ark_only | 26 | **5.1** | 0.0 | 0.0 |
| presidio_favored | entity.driver_license_number | shared | 14 | 0.0 | 15.2 | **78.3** |
| presidio_favored | entity.passport_number | shared | 29 | 0.0 | **60.5** | 51.3 |
| presidio_favored | pii.au.abn | presidio_only | 1 | 0.0 | 0.0 | 0.0 |
| presidio_favored | pii.au.acn | presidio_only | 3 | 0.0 | 0.0 | 0.0 |
| presidio_favored | pii.au.medicare | presidio_only | 1 | 0.0 | 0.0 | 0.0 |
| presidio_favored | pii.ca.sin | presidio_only | 5 | 0.0 | 0.0 | 0.0 |
| presidio_favored | pii.credit_card.pan | shared | 49 | **98.0** | 91.1 | 91.1 |
| presidio_favored | pii.crypto_wallet | presidio_only | 1 | 0.0 | **100.0** | **100.0** |
| presidio_favored | pii.de.bsnr | presidio_only | 5 | 0.0 | 0.0 | **57.1** |
| presidio_favored | pii.de.commercial_register | presidio_only | 1 | 0.0 | 0.0 | **100.0** |
| presidio_favored | pii.de.health_insurance_number | shared | 3 | 0.0 | 0.0 | **100.0** |
| presidio_favored | pii.de.lanr | shared | 3 | 0.0 | 0.0 | **100.0** |
| presidio_favored | pii.de.social_security_number | shared | 1 | 0.0 | 0.0 | **100.0** |
| presidio_favored | pii.de.tax_id | shared | 1 | 0.0 | 0.0 | **100.0** |
| presidio_favored | pii.de.tax_number | shared | 2 | 0.0 | 0.0 | **100.0** |
| presidio_favored | pii.de.vat_id | presidio_only | 5 | 0.0 | 0.0 | **100.0** |
| presidio_favored | pii.email | shared | 16 | 93.8 | **100.0** | **100.0** |
| presidio_favored | pii.es.nie | presidio_only | 5 | 0.0 | 0.0 | 0.0 |
| presidio_favored | pii.es.nif | presidio_only | 3 | 0.0 | 0.0 | 0.0 |
| presidio_favored | pii.fi.personal_identity_code | presidio_only | 14 | 0.0 | 0.0 | 0.0 |
| presidio_favored | pii.financial_account_number | shared | 5 | 0.0 | **66.7** | 0.0 |
| presidio_favored | pii.iban | shared | 66 | 63.9 | **100.0** | **100.0** |
| presidio_favored | pii.identity_card_number | shared | 11 | 16.7 | 0.0 | **84.2** |
| presidio_favored | pii.in.aadhaar | presidio_only | 4 | 0.0 | 0.0 | 0.0 |
| presidio_favored | pii.in.gstin | presidio_only | 3 | 0.0 | 0.0 | 0.0 |
| presidio_favored | pii.in.pan | presidio_only | 3 | 0.0 | 0.0 | 0.0 |
| presidio_favored | pii.in.voter_id | presidio_only | 3 | 0.0 | 0.0 | 0.0 |
| presidio_favored | pii.ip_address | shared | 41 | 56.8 | **100.0** | 96.2 |
| presidio_favored | pii.it.fiscal_code | presidio_only | 3 | 0.0 | 0.0 | 0.0 |
| presidio_favored | pii.it.vat_code | presidio_only | 1 | 0.0 | 0.0 | 0.0 |
| presidio_favored | pii.kr.brn | presidio_only | 2 | 0.0 | 0.0 | 0.0 |
| presidio_favored | pii.kr.frn | presidio_only | 3 | 0.0 | 0.0 | 0.0 |
| presidio_favored | pii.kr.rrn | presidio_only | 5 | 0.0 | 0.0 | 0.0 |
| presidio_favored | pii.license_plate | shared | 21 | 0.0 | 0.0 | 0.0 |
| presidio_favored | pii.mac_address | shared | 6 | **100.0** | **100.0** | **100.0** |
| presidio_favored | pii.ph.tin | presidio_only | 3 | 0.0 | 0.0 | 0.0 |
| presidio_favored | pii.ph.umid | presidio_only | 8 | 0.0 | 0.0 | 0.0 |
| presidio_favored | pii.phone | shared | 46 | 53.5 | **65.1** | **65.1** |
| presidio_favored | pii.pl.pesel | presidio_only | 3 | 0.0 | 0.0 | 0.0 |
| presidio_favored | pii.se.organisationsnummer | presidio_only | 3 | 0.0 | 0.0 | 0.0 |
| presidio_favored | pii.se.personnummer | presidio_only | 2 | 0.0 | 0.0 | 0.0 |
| presidio_favored | pii.sg.nric_fin | presidio_only | 3 | 0.0 | 0.0 | 0.0 |
| presidio_favored | pii.sg.uen | presidio_only | 4 | 0.0 | 0.0 | 0.0 |
| presidio_favored | pii.th.tnin | presidio_only | 6 | 0.0 | 0.0 | 0.0 |
| presidio_favored | pii.tr.national_id | presidio_only | 4 | 0.0 | 0.0 | 0.0 |
| presidio_favored | pii.uk.national_insurance_number | shared | 3 | 0.0 | 0.0 | **100.0** |
| presidio_favored | pii.uk.postcode | presidio_only | 4 | 0.0 | 0.0 | 0.0 |
| presidio_favored | pii.url | presidio_only | 21 | 0.0 | **77.8** | **77.8** |
| presidio_favored | pii.us.itin | presidio_only | 2 | 0.0 | **100.0** | **100.0** |
| presidio_favored | pii.us.mbi | presidio_only | 5 | 0.0 | 0.0 | 0.0 |
| presidio_favored | pii.us.npi | presidio_only | 5 | 0.0 | 0.0 | 0.0 |
| presidio_favored | pii.us.social_security_number | shared | 15 | 57.1 | **100.0** | 88.9 |
| presidio_favored | pii.za.id_number | presidio_only | 3 | 0.0 | 0.0 | 0.0 |

### M1 (ark vs each profile; EN rows, exact F1, shared ids with gold)

| Profile | M1 | neutral | presidio_favored | ark_authored ¹ |
|---|---|---|---|---|
| presidio-default | NOT MET | 5/9 (below: entity.driver_license_number, pii.credit_card.pan, pii.financial_account_number, pii.ip_address) | 4/12 (below: entity.driver_license_number, entity.passport_number, pii.email, pii.financial_account_number, pii.iban, pii.ip_address, pii.phone, pii.us.social_security_number) | 13/18 (below: entity.driver_license_number, entity.passport_number, pii.credit_card.pan, pii.iban, pii.us.social_security_number) |
| presidio-tuned | NOT MET | 3/9 (below: entity.driver_license_number, entity.passport_number, pii.credit_card.pan, pii.financial_account_number, pii.ip_address, pii.us.social_security_number) | 4/12 (below: entity.driver_license_number, entity.passport_number, pii.email, pii.iban, pii.ip_address, pii.phone, pii.uk.national_insurance_number, pii.us.social_security_number) | 11/18 (below: entity.driver_license_number, entity.passport_number, pii.credit_card.pan, pii.financial_account_number, pii.iban, pii.uk.national_insurance_number, pii.us.social_security_number) |
