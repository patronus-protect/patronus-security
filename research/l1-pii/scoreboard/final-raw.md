# L1-PII: Abschlussbericht M1–M4 in der Rohsicht (H05-2)

Stand: 2026-11-08, ARK-Quellen wie `main` `6263e090` (nach Q-RAW; die H05-2-Commits ändern nur das
Scoreboard), Paket 0.1.15, Release-Build. Presidio 2.2.364 in beiden Profilen, Pins aus
`scripts/l1_presidio/requirements.txt`. Urteil nach [`../README.md`](../README.md), Abschnitt M-RAW:
rohes Gold (kein Ausschluss über `known_gaps` oder Validatoren), exakte Spans, entscheidend sind die
Familien `neutral` und `presidio_favored`; ein Meilenstein gilt, wenn ARK `balanced` **oder**
`balanced-bare` (`balanced` mit dem Opt-in-Profil
[`docs/how-to/pii-bare-formats.gates.json`](../../../docs/how-to/pii-bare-formats.gates.json)) gegen
Presidio `default` **und** `tuned` hält. Löst für öffentliche Aussagen [`final.md`](final.md) (H05,
erreichbares Gold gegen tuned) ab.

## Ergebnis

| Meilenstein | Kriterium (roh, gegen default und tuned) | Dev (2026-11-08) | Holdout | Urteil |
|---|---|---|---|---|
| M1 Parität EN | je gemeinsamer ID F1(ARK) ≥ F1(Presidio), je Familie | `balanced`: neutral 9/9 + 9/9, presidio_favored 21/25 (default) + 13/25 (tuned); `balanced-bare`: neutral 9/9 + 8/9, presidio_favored 21/25 + 19/25 | Gate-Bericht, Zeilen `milestones holdout (balanced, …)`, `(balanced-bare, …)` und `M1 gaps holdout` | **nicht erreicht** (mit und ohne Bare-Profil) |
| M2 DE/EU | DE-Macro-F1 neutral ≥ Presidio + 15 pp, presidio_favored ≥ Presidio | `balanced-bare`: neutral 62,5 ≥ 39,2 / 36,2, presidio_favored 89,9 ≥ 6,6 / 87,0; `balanced`: presidio_favored 63,2 < 87,0 (tuned) | Gate-Bericht, Zeile `milestones holdout (balanced-bare, …)` | Dev **erreicht nur mit Bare-Profil** |
| M3 Breite | ≥ 2× prüfziffervalidierte Einheiten von Presidio (35 → 70) | ARK 83, Presidio 35, gemeinsam 33 | – (zählt Code, keine Daten) | erreicht |
| M4 Latenz | 100 KiB p95 ≤ 10 ms | nativ 9,774 ms, Python-Bindings 15,003 ms | – (feste Workloads) | erreicht (nativ, Entscheidung 2026-11-05) |
| Immer | HN-FP ≤ Presidio je Familie; keine Entität verliert > 0,5 pp | HN-FP `balanced` und `balanced-bare` neutral 0 / 0 / 0, presidio_favored 0 / 7 / 0 (ARK / default / tuned) | Gate (Regressionen, neue HN-FP; Zeile `scores holdout`) | Dev erreicht |

- **M1** hält auf `neutral` mit `balanced` gegen beide Profile, auf `presidio_favored` mit keiner
  Engine. Das Bare-Profil schließt gegen tuned ACN, CA SIN, Aadhaar, IN-PAN, Voter-ID und NPI (13/25 →
  19/25), kostet aber auf `neutral` die US-SSN (`pii_ssn_us_bare`: 46,9 gegen tuned 79,3, blanke
  Neunziffern in Gretel). Die Lücken je ID stehen unten; jede liegt unter einer festgehaltenen
  Entscheidung (`known_gaps` in [`../entity_map.yaml`](../entity_map.yaml)) oder an Gold mit ungültiger
  Prüfziffer (README, Q-RAW). Schließen ließen sie sich nur mit gelockerten Validatoren oder revidierten
  Entscheidungen. Nach T38 (Entscheidung 2026-11-09) lautet die öffentliche Aussage: **M1 ist nicht
  erreicht**, ohne „roh, außer …“. Das Opt-in-Kompatibilitätsprofil
  [`docs/how-to/pii-presidio-compat.gates.json`](../../../docs/how-to/pii-presidio-compat.gates.json)
  (Bare-Profil plus Loopback-/unspezifizierte IPs und von der SSA nie vergebene SSNs) hebt auf Dev
  IP auf 98,8 und US-SSN auf 92,9 und hält damit gegen tuned 22/25; GSTIN, NRIC/FIN (Gold mit ungültiger
  Prüfziffer) und NINO (Gold-Span mit Leerzeichen) bleiben offen. Es ist keine Engine des Urteils.
- **M2** hält gegen beide Profile nur mit `balanced-bare` (Steuer-ID, ELSTER-Steuernummer, LANR, BSNR
  blank, seit Q-RAW mit `validators::steuer_id_bare`). `balanced` allein hält gegen default, gegen tuned
  nicht (63,2 < 87,0). Eine öffentliche Aussage zu M2 lautet deshalb „mit Bare-Profil“.
- **M3** aus `python3 scripts/l1_presidio/count_validated.py count` (Zählregel T03), unverändert seit H05.
- **M4** aus [`latency.md`](latency.md) (H06, VPS; DE + EN gepoolt), unverändert seit H05: nativ
  9,774 ms, über die Python-Bindings 15,003 ms; Presidio default 13 634,6 ms, tuned 11 978,8 ms. Die
  Bare-Regeln sind standardmäßig aus und ändern die Latenz mit Standard-Gates nicht (D-BARE).
- **Immer:** `balanced-bare` meldet auf `ark_authored` (berichtet, entscheidet nicht) 80 HN-FP: die
  Hard Negatives der Goldens sind zum Teil absichtlich blanke gültige Werte, die das Opt-in-Profil
  meldet (D-BARE). Presidio default 1 134, tuned 228.

## M1-Lücken je ID (Dev, EN, exakter F1)

Ausgabe der Gate-Zeile `M1 gaps dev`, als Tabelle; „–“ heißt: die Engine hält gegen dieses Profil.

| Familie | ID | `balanced` | `balanced-bare` | Presidio default | Presidio tuned | Grund (README, `known_gaps`) |
|---|---|---:|---:|---:|---:|---|
| presidio_favored | `entity.passport_number` | 40,0 | 40,0 | 71,4 | – | blanke Nummern ohne Begriff |
| presidio_favored | `pii.financial_account_number` | 57,1 | 57,1 | 66,7 | – | blanke ABA-Routingnummern, blanke Kontonummer |
| presidio_favored | `pii.ip_address` | 86,1 | 86,1 | 100,0 | 96,2 | D-IP (Loopback/unspezifiziert), T28 |
| presidio_favored | `pii.us.social_security_number` | 75,0 | 80,0 | 100,0 | 88,9 | B-SSN (von `validators::us_ssn` abgelehnt) |
| presidio_favored | `pii.au.acn` | 0,0 | hält | – | 100,0 | blanke ACN (B-APAC) |
| presidio_favored | `pii.ca.sin` | 57,1 | hält | – | 88,9 | blanke SIN (B-LUHN) |
| presidio_favored | `pii.in.aadhaar` | 85,7 | hält | – | 100,0 | blanke Aadhaar (B-IN) |
| presidio_favored | `pii.in.pan` | 50,0 | hält | – | 80,0 | IN-PAN ohne Begriff (B-IN) |
| presidio_favored | `pii.in.voter_id` | 0,0 | hält | – | 50,0 | Voter-ID ohne Begriff (B-IN) |
| presidio_favored | `pii.us.npi` | 88,9 | hält | – | 100,0 | blanke NPI (A06) |
| presidio_favored | `pii.in.gstin` | 0,0 | 0,0 | – | 100,0 | Gold mit ungültiger Prüfziffer |
| presidio_favored | `pii.sg.nric_fin` | 50,0 | 50,0 | – | 80,0 | Gold mit ungültiger Prüfziffer |
| presidio_favored | `pii.license_plate` | 47,6 | 72,0 | – | 81,5 | UK-Präfix- und Kurzformen, IN ohne Trenner (T30) |
| presidio_favored | `pii.uk.national_insurance_number` | 66,7 | 66,7 | – | 100,0 | Gold-Span mit führendem Leerzeichen |
| neutral | `pii.us.social_security_number` | hält | 46,9 | – | 79,3 | `pii_ssn_us_bare` trifft blanke Neunziffern in Gretel |

Bei Pass, Kontonummer, IP und US-SSN liegen `balanced` und `balanced-bare` gegen default zurück, die
übrigen Zeilen nur gegen tuned.

## Holdout

Der Holdout liegt nur auf der VPS und ist für den Agenten unsichtbar. `scoreboard.py gate` rechnet den
Head je Split in der Rohsicht gegen Presidio default und tuned und druckt vor `RESULT` je Split vier
Aggregatzeilen (seit H05-2; die beiden `milestones`-Zeilen seit H05/Q-RAW):

```
scores <split> (raw gold, exact F1 in % on L1 ids/HN-FP per family): <family>: strict f/n, balanced f/n, balanced-bare f/n, presidio-default f/n, presidio-tuned f/n | …
milestones <split> (balanced, raw gold, vs Presidio default and tuned): M1 … | M2 …
milestones <split> (balanced-bare, raw gold, vs Presidio default and tuned): M1 … | M2 …
M1 gaps <split> (shared ids with Ark below Presidio, exact F1 in %): balanced vs default …, vs tuned …; balanced-bare vs default …, vs tuned …
```

Die Zeilen tragen nur Familien, Entitäts-IDs und Zahlen, keine Zeilen-ID und keinen Wert. Der Runner
übernimmt die letzten 15 Zeilen einer grünen Scoreboard-Ausgabe in den Gate-Bericht; die Holdout-Zahlen
von H05-2 stehen deshalb im Gate-Bericht des H05-2-PRs und in jedem späteren Gate-Bericht. Presidio läuft
auf dem Holdout je Profil einmal und wird je Runner, Profil und Eingabe-SHA-256 aus dem Cache gelesen.
M3 und M4 hängen nicht vom Holdout ab.

Auf Dev geben die Zeilen genau die Zahlen von `scoreboard.py report`, `m1` und `m2` wieder:

```
scores dev (raw gold, exact F1 in % on L1 ids/HN-FP per family): ark_authored: strict 75.2/0, balanced 88.2/0, balanced-bare 82.9/80, presidio-default 16.2/1134, presidio-tuned 42.8/228 | neutral: strict 69.6/0, balanced 70.0/0, balanced-bare 67.8/0, presidio-default 18.0/0, presidio-tuned 40.5/0 | presidio_favored: strict 65.4/0, balanced 78.7/0, balanced-bare 82.7/0, presidio-default 63.6/7, presidio-tuned 77.6/0
milestones dev (balanced, raw gold, vs Presidio default and tuned): M1 NOT MET (vs default: neutral 9/9, presidio_favored 21/25; vs tuned: neutral 9/9, presidio_favored 13/25 shared ids) | M2 NOT MET (macro-F1 vs default: neutral 63.0 >= 39.2, presidio_favored 63.2 >= 6.6; vs tuned: neutral 63.0 >= 36.2, presidio_favored 63.2 < 87.0)
milestones dev (balanced-bare, raw gold, vs Presidio default and tuned): M1 NOT MET (vs default: neutral 9/9, presidio_favored 21/25; vs tuned: neutral 8/9, presidio_favored 19/25 shared ids) | M2 MET (macro-F1 vs default: neutral 62.5 >= 39.2, presidio_favored 89.9 >= 6.6; vs tuned: neutral 62.5 >= 36.2, presidio_favored 89.9 >= 87.0)
M1 gaps dev (shared ids with Ark below Presidio, exact F1 in %): balanced vs default presidio_favored entity.passport_number 40.0 < 71.4, presidio_favored pii.financial_account_number 57.1 < 66.7, presidio_favored pii.ip_address 86.1 < 100.0, presidio_favored pii.us.social_security_number 75.0 < 100.0, vs tuned presidio_favored pii.au.acn 0.0 < 100.0, presidio_favored pii.ca.sin 57.1 < 88.9, presidio_favored pii.in.aadhaar 85.7 < 100.0, presidio_favored pii.in.gstin 0.0 < 100.0, presidio_favored pii.in.pan 50.0 < 80.0, presidio_favored pii.in.voter_id 0.0 < 50.0, presidio_favored pii.ip_address 86.1 < 96.2, presidio_favored pii.license_plate 47.6 < 81.5, presidio_favored pii.sg.nric_fin 50.0 < 80.0, presidio_favored pii.uk.national_insurance_number 66.7 < 100.0, presidio_favored pii.us.npi 88.9 < 100.0, presidio_favored pii.us.social_security_number 75.0 < 88.9; balanced-bare vs default presidio_favored entity.passport_number 40.0 < 71.4, presidio_favored pii.financial_account_number 57.1 < 66.7, presidio_favored pii.ip_address 86.1 < 100.0, presidio_favored pii.us.social_security_number 80.0 < 100.0, vs tuned neutral pii.us.social_security_number 46.9 < 79.3, presidio_favored pii.in.gstin 0.0 < 100.0, presidio_favored pii.ip_address 86.1 < 96.2, presidio_favored pii.license_plate 72.0 < 81.5, presidio_favored pii.sg.nric_fin 50.0 < 80.0, presidio_favored pii.uk.national_insurance_number 66.7 < 100.0, presidio_favored pii.us.social_security_number 80.0 < 88.9
```

## Gesamt je Familie (Dev, exact span, L1-IDs)

| Family | Engine | Rows | Gold | Pred | Exact P | Exact R | Exact F1 | Overlap F1 | EN F1 | DE F1 | HN-FP |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| ark_authored ¹ | ark-strict | 644 | 3331 | 2059 | 98.4 | 60.8 | 75.2 | 75.2 | 73.8 | 76.5 | 0 |
| ark_authored ¹ | ark-balanced | 644 | 3331 | 2633 | 99.9 | 79.0 | 88.2 | 88.2 | 87.8 | 88.6 | 0 |
| ark_authored ¹ | ark-balanced-bare | 644 | 3331 | 3013 | 87.3 | 79.0 | 82.9 | 82.9 | 83.2 | 82.7 | 80 |
| ark_authored ¹ | ark-recall | 644 | 3331 | 2633 | 99.9 | 79.0 | 88.2 | 88.2 | 87.8 | 88.6 | 0 |
| ark_authored ¹ | presidio-default | 644 | 3331 | 4359 | 14.3 | 18.7 | 16.2 | 16.5 | 18.4 | 14.3 | 1134 |
| ark_authored ¹ | presidio-tuned | 644 | 3331 | 2155 | 54.5 | 35.3 | 42.8 | 43.3 | 36.5 | 48.5 | 228 |
| neutral | ark-strict | 2336 | 1986 | 1863 | 71.9 | 67.4 | 69.6 | 71.7 | 69.2 | 69.8 | 0 |
| neutral | ark-balanced | 2336 | 1986 | 1868 | 72.2 | 67.9 | 70.0 | 72.1 | 69.8 | 69.8 | 0 |
| neutral | ark-balanced-bare | 2336 | 1986 | 1991 | 67.8 | 67.9 | 67.8 | 69.9 | 67.4 | 68.3 | 0 |
| neutral | ark-recall | 2336 | 1986 | 1868 | 72.2 | 67.9 | 70.0 | 72.1 | 69.8 | 69.8 | 0 |
| neutral | presidio-default | 2336 | 1986 | 9258 | 10.9 | 50.9 | 18.0 | 19.9 | 16.3 | 13.5 | 0 |
| neutral | presidio-tuned | 2336 | 1986 | 2690 | 35.2 | 47.7 | 40.5 | 44.1 | 37.8 | 33.5 | 0 |
| presidio_favored | ark-strict | 1123 | 478 | 234 | 99.6 | 48.7 | 65.4 | 65.7 | 75.1 | 14.6 | 0 |
| presidio_favored | ark-balanced | 1123 | 478 | 312 | 99.7 | 65.1 | 78.7 | 79.0 | 82.6 | 71.2 | 0 |
| presidio_favored | ark-balanced-bare | 1123 | 478 | 339 | 99.7 | 70.7 | 82.7 | 83.0 | 85.5 | 86.6 | 0 |
| presidio_favored | ark-recall | 1123 | 478 | 312 | 99.7 | 65.1 | 78.7 | 79.0 | 82.6 | 71.2 | 0 |
| presidio_favored | presidio-default | 1123 | 478 | 330 | 77.9 | 53.8 | 63.6 | 64.6 | 73.3 | 18.6 | 7 |
| presidio_favored | presidio-tuned | 1123 | 478 | 342 | 93.0 | 66.5 | 77.6 | 78.3 | 84.6 | 93.0 | 0 |

¹ ark_authored is reported and decides no milestone.

Gegenüber H05 ([`final.md`](final.md)) sind `strict`, `balanced` und beide Presidio-Profile auf Dev
unverändert; neu ist `balanced-bare` (D-BARE, Q-RAW).

### M1, raw gold, milestone view (each Ark engine vs each profile; EN rows, exact F1, shared ids with gold)

| Ark engine | Profile | M1 | neutral | presidio_favored | ark_authored ¹ |
|---|---|---|---|---|---|
| balanced | presidio-default | NOT MET | 9/9 | 21/25 (below: entity.passport_number, pii.financial_account_number, pii.ip_address, pii.us.social_security_number) | 49/49 |
| balanced | presidio-tuned | NOT MET | 9/9 | 13/25 (below: pii.au.acn, pii.ca.sin, pii.in.aadhaar, pii.in.gstin, pii.in.pan, pii.in.voter_id, pii.ip_address, pii.license_plate, pii.sg.nric_fin, pii.uk.national_insurance_number, pii.us.npi, pii.us.social_security_number) | 49/49 |
| balanced-bare | presidio-default | NOT MET | 9/9 | 21/25 (below: entity.passport_number, pii.financial_account_number, pii.ip_address, pii.us.social_security_number) | 49/49 |
| balanced-bare | presidio-tuned | NOT MET | 8/9 (below: pii.us.social_security_number) | 19/25 (below: pii.in.gstin, pii.ip_address, pii.license_plate, pii.sg.nric_fin, pii.uk.national_insurance_number, pii.us.social_security_number) | 47/49 (below: entity.driver_license_number, pii.us.social_security_number) |
| strict ² | presidio-default | NOT MET | 9/9 | 21/25 (below: entity.passport_number, pii.financial_account_number, pii.ip_address, pii.us.social_security_number) | 49/49 |
| strict ² | presidio-tuned | NOT MET | 8/9 (below: pii.us.social_security_number) | 9/25 (below: entity.driver_license_number, pii.au.abn, pii.au.acn, pii.au.medicare, pii.ca.sin, pii.in.aadhaar, pii.in.gstin, pii.in.pan, pii.in.voter_id, pii.ip_address, pii.license_plate, pii.sg.nric_fin, pii.uk.national_insurance_number, pii.us.npi, pii.us.social_security_number, pii.za.id_number) | 49/49 |
| recall ² | presidio-default | NOT MET | 9/9 | 21/25 (below: entity.passport_number, pii.financial_account_number, pii.ip_address, pii.us.social_security_number) | 49/49 |
| recall ² | presidio-tuned | NOT MET | 9/9 | 13/25 (below: pii.au.acn, pii.ca.sin, pii.in.aadhaar, pii.in.gstin, pii.in.pan, pii.in.voter_id, pii.ip_address, pii.license_plate, pii.sg.nric_fin, pii.uk.national_insurance_number, pii.us.npi, pii.us.social_security_number) | 49/49 |

**M1: NOT MET (balanced: presidio-default not met, presidio-tuned not met; balanced-bare: presidio-default not met, presidio-tuned not met)**

² reported; a milestone is met only if balanced or balanced-bare holds against presidio-default and presidio-tuned (M-RAW).

### M2, raw gold, milestone view (each Ark engine vs each profile; DE rows, exact macro-F1 over shared + ark_only ids with gold; Ark vs target = Presidio + margin)

| Ark engine | Profile | M2 | neutral | presidio_favored | ark_authored ¹ |
|---|---|---|---|---|---|
| balanced | presidio-default | MET | 63.0 vs 39.2 (24.2 + 15), 14 ids | 63.2 vs 6.6 (6.6 + 0), 11 ids | 98.4 vs 23.4 (8.4 + 15), 87 ids |
| balanced | presidio-tuned | NOT MET | 63.0 vs 36.2 (21.2 + 15), 14 ids | 63.2 vs 87.0 (87.0 + 0), 11 ids | 98.4 vs 32.5 (17.5 + 15), 87 ids |
| balanced-bare | presidio-default | MET | 62.5 vs 39.2 (24.2 + 15), 14 ids | 89.9 vs 6.6 (6.6 + 0), 11 ids | 95.4 vs 23.4 (8.4 + 15), 87 ids |
| balanced-bare | presidio-tuned | MET | 62.5 vs 36.2 (21.2 + 15), 14 ids | 89.9 vs 87.0 (87.0 + 0), 11 ids | 95.4 vs 32.5 (17.5 + 15), 87 ids |
| strict ² | presidio-default | MET | 63.3 vs 39.2 (24.2 + 15), 14 ids | 7.2 vs 6.6 (6.6 + 0), 11 ids | 63.0 vs 23.4 (8.4 + 15), 87 ids |
| strict ² | presidio-tuned | NOT MET | 63.3 vs 36.2 (21.2 + 15), 14 ids | 7.2 vs 87.0 (87.0 + 0), 11 ids | 63.0 vs 32.5 (17.5 + 15), 87 ids |
| recall ² | presidio-default | MET | 63.0 vs 39.2 (24.2 + 15), 14 ids | 63.2 vs 6.6 (6.6 + 0), 11 ids | 98.4 vs 23.4 (8.4 + 15), 87 ids |
| recall ² | presidio-tuned | NOT MET | 63.0 vs 36.2 (21.2 + 15), 14 ids | 63.2 vs 87.0 (87.0 + 0), 11 ids | 98.4 vs 32.5 (17.5 + 15), 87 ids |

**M2: MET (balanced: presidio-default holds, presidio-tuned not met; balanced-bare: presidio-default holds, presidio-tuned holds)**

² reported; a milestone is met only if balanced or balanced-bare holds against presidio-default and presidio-tuned (M-RAW).

presidio_only ids stay out of the macro average until entity_map.yaml marks them shared (D-M2).


## Reproduktion

```bash
# DEV = $ARK_L1_DEV_DATA; je Gold-Datei f (relativer Pfad):
.venv/bin/python scripts/l1_presidio/run_ark.py --pii-mode strict --input DEV/$f --output PRED/ark-strict/$f
.venv/bin/python scripts/l1_presidio/run_ark.py --pii-mode balanced --input DEV/$f --output PRED/ark-balanced/$f
.venv/bin/python scripts/l1_presidio/run_ark.py --pii-mode balanced --gates docs/how-to/pii-bare-formats.gates.json \
  --input DEV/$f --output PRED/ark-balanced-bare/$f
.venv/bin/python scripts/l1_presidio/run_ark.py --pii-mode recall --input DEV/$f --output PRED/ark-recall/$f
~/ark-l1/presidio-venv/bin/python scripts/l1_presidio/run_presidio.py --profile default --input DEV/$f --output PRED/presidio-default/$f
~/ark-l1/presidio-venv/bin/python scripts/l1_presidio/run_presidio.py --profile tuned --input DEV/$f --output PRED/presidio-tuned/$f
ENGINES="--ark strict=PRED/ark-strict --ark balanced=PRED/ark-balanced --ark balanced-bare=PRED/ark-balanced-bare \
  --ark recall=PRED/ark-recall --presidio default=PRED/presidio-default --presidio tuned=PRED/presidio-tuned"
python3 scripts/l1_presidio/scoreboard.py report --gold DEV $ENGINES
python3 scripts/l1_presidio/scoreboard.py m1 --gold DEV $ENGINES
python3 scripts/l1_presidio/scoreboard.py m2 --gold DEV $ENGINES
python3 scripts/l1_presidio/count_validated.py count
# Holdout: nur im Gate (ark-l1 gate → scoreboard.py gate --holdout ~/ark-l1/holdout)
```

## Anhang: je Entität (Dev, rohes Gold, exakter F1, entscheidende Familien)

| Family | Entity | Scope | Gold | ark-strict | ark-balanced | ark-balanced-bare | ark-recall | presidio-default | presidio-tuned |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|
| neutral | entity.driver_license_number | shared | 120 | **40.3** | **40.3** | 29.4 | **40.3** | 0.8 | 6.2 |
| neutral | entity.passport_number | shared | 98 | **68.5** | 68.0 | 68.0 | 68.0 | 18.7 | 38.2 |
| neutral | pii.credit_card.cvv | ark_only | 47 | **63.4** | **63.4** | **63.4** | **63.4** | 0.0 | 0.0 |
| neutral | pii.credit_card.pan | shared | 135 | **47.9** | **47.9** | **47.9** | **47.9** | 35.6 | 35.6 |
| neutral | pii.customer_id | ark_only | 90 | **60.9** | **60.9** | **60.9** | **60.9** | 0.0 | 0.0 |
| neutral | pii.date_of_birth | ark_only | 82 | **67.0** | **67.0** | **67.0** | **67.0** | 0.0 | 0.0 |
| neutral | pii.email | shared | 417 | **68.8** | **68.8** | **68.8** | **68.8** | 67.9 | 67.9 |
| neutral | pii.employee_id | ark_only | 75 | **88.2** | **88.2** | **88.2** | **88.2** | 0.0 | 0.0 |
| neutral | pii.financial_account_number | shared | 126 | 47.8 | **49.2** | **49.2** | **49.2** | 5.0 | 12.5 |
| neutral | pii.iban | shared | 55 | **91.7** | **91.7** | **91.7** | **91.7** | **91.7** | **91.7** |
| neutral | pii.ip_address | shared | 88 | **96.7** | **96.7** | **96.7** | **96.7** | 94.6 | 94.6 |
| neutral | pii.phone | shared | 504 | 82.0 | **82.1** | **82.1** | **82.1** | 36.7 | 36.7 |
| neutral | pii.swift_bic | ark_only | 79 | **73.4** | **73.4** | **73.4** | **73.4** | 0.0 | 0.0 |
| neutral | pii.us.social_security_number | shared | 44 | 50.8 | **68.5** | 36.0 | **68.5** | 21.4 | 66.7 |
| neutral | pii.username | ark_only | 26 | **10.3** | **10.3** | **10.3** | **10.3** | 0.0 | 0.0 |
| presidio_favored | entity.driver_license_number | shared | 14 | 52.6 | 83.3 | **88.0** | 83.3 | 15.2 | 78.3 |
| presidio_favored | entity.passport_number | shared | 29 | 29.4 | 55.0 | 55.0 | 55.0 | **60.5** | 51.3 |
| presidio_favored | pii.au.abn | shared | 1 | 0.0 | **100.0** | **100.0** | **100.0** | 0.0 | **100.0** |
| presidio_favored | pii.au.acn | shared | 3 | 0.0 | 0.0 | **100.0** | 0.0 | 0.0 | **100.0** |
| presidio_favored | pii.au.medicare | shared | 1 | 0.0 | **100.0** | **100.0** | **100.0** | 0.0 | **100.0** |
| presidio_favored | pii.ca.sin | shared | 5 | 33.3 | 57.1 | **100.0** | 57.1 | 0.0 | 88.9 |
| presidio_favored | pii.credit_card.pan | shared | 49 | **100.0** | **100.0** | **100.0** | **100.0** | 91.1 | 91.1 |
| presidio_favored | pii.crypto_wallet | shared | 1 | **100.0** | **100.0** | **100.0** | **100.0** | **100.0** | **100.0** |
| presidio_favored | pii.de.bsnr | shared | 5 | 57.1 | 57.1 | **100.0** | 57.1 | 0.0 | 57.1 |
| presidio_favored | pii.de.commercial_register | shared | 1 | 0.0 | **100.0** | **100.0** | **100.0** | 0.0 | **100.0** |
| presidio_favored | pii.de.health_insurance_number | shared | 3 | 0.0 | **100.0** | **100.0** | **100.0** | 0.0 | **100.0** |
| presidio_favored | pii.de.lanr | shared | 3 | 0.0 | 50.0 | **100.0** | 50.0 | 0.0 | **100.0** |
| presidio_favored | pii.de.social_security_number | shared | 1 | 0.0 | **100.0** | **100.0** | **100.0** | 0.0 | **100.0** |
| presidio_favored | pii.de.tax_id | shared | 1 | 0.0 | 0.0 | **100.0** | 0.0 | 0.0 | **100.0** |
| presidio_favored | pii.de.tax_number | shared | 2 | 0.0 | 66.7 | **100.0** | 66.7 | 0.0 | **100.0** |
| presidio_favored | pii.de.vat_id | shared | 5 | 0.0 | 75.0 | 75.0 | 75.0 | 0.0 | **100.0** |
| presidio_favored | pii.email | shared | 16 | **100.0** | **100.0** | **100.0** | **100.0** | **100.0** | **100.0** |
| presidio_favored | pii.es.nie | shared | 5 | 33.3 | **88.9** | **88.9** | **88.9** | 0.0 | 0.0 |
| presidio_favored | pii.es.nif | shared | 3 | 0.0 | **80.0** | **80.0** | **80.0** | 0.0 | 0.0 |
| presidio_favored | pii.fi.personal_identity_code | shared | 14 | 25.0 | **96.3** | **96.3** | **96.3** | 0.0 | 0.0 |
| presidio_favored | pii.financial_account_number | shared | 5 | 0.0 | 57.1 | 57.1 | 57.1 | **66.7** | 0.0 |
| presidio_favored | pii.iban | shared | 65 | **100.0** | **100.0** | **100.0** | **100.0** | **100.0** | **100.0** |
| presidio_favored | pii.identity_card_number | shared | 11 | 16.7 | 42.9 | 42.9 | 42.9 | 0.0 | **84.2** |
| presidio_favored | pii.in.aadhaar | shared | 4 | 0.0 | 85.7 | **100.0** | 85.7 | 0.0 | **100.0** |
| presidio_favored | pii.in.gstin | shared | 3 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | **100.0** |
| presidio_favored | pii.in.pan | shared | 3 | 50.0 | 50.0 | **80.0** | 50.0 | 0.0 | **80.0** |
| presidio_favored | pii.in.voter_id | shared | 3 | 0.0 | 0.0 | **80.0** | 0.0 | 0.0 | 50.0 |
| presidio_favored | pii.ip_address | shared | 41 | 86.1 | 86.1 | 86.1 | 86.1 | **100.0** | 96.2 |
| presidio_favored | pii.it.fiscal_code | shared | 3 | 0.0 | **50.0** | **50.0** | **50.0** | 0.0 | 0.0 |
| presidio_favored | pii.it.vat_code | shared | 1 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| presidio_favored | pii.kr.brn | shared | 2 | 0.0 | 66.7 | **100.0** | 66.7 | 0.0 | 0.0 |
| presidio_favored | pii.kr.frn | shared | 3 | 0.0 | **80.0** | **80.0** | **80.0** | 0.0 | 0.0 |
| presidio_favored | pii.kr.rrn | shared | 5 | 33.3 | **57.1** | **57.1** | **57.1** | 0.0 | 0.0 |
| presidio_favored | pii.license_plate | shared | 21 | 9.1 | 38.5 | 60.0 | 38.5 | 0.0 | **68.8** |
| presidio_favored | pii.mac_address | shared | 6 | **100.0** | **100.0** | **100.0** | **100.0** | **100.0** | **100.0** |
| presidio_favored | pii.ph.tin | presidio_only | 3 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| presidio_favored | pii.ph.umid | presidio_only | 8 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| presidio_favored | pii.phone | shared | 46 | 80.5 | **91.8** | **91.8** | **91.8** | 65.1 | 65.1 |
| presidio_favored | pii.pl.pesel | shared | 3 | 50.0 | 50.0 | **100.0** | 50.0 | 0.0 | 0.0 |
| presidio_favored | pii.se.organisationsnummer | shared | 3 | 0.0 | **50.0** | **50.0** | **50.0** | 0.0 | 0.0 |
| presidio_favored | pii.se.personnummer | shared | 2 | 66.7 | **100.0** | **100.0** | **100.0** | 0.0 | 0.0 |
| presidio_favored | pii.sg.nric_fin | shared | 3 | 0.0 | 50.0 | 50.0 | 50.0 | 0.0 | **80.0** |
| presidio_favored | pii.sg.uen | shared | 4 | 0.0 | **85.7** | **85.7** | **85.7** | 0.0 | 0.0 |
| presidio_favored | pii.th.tnin | presidio_only | 6 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| presidio_favored | pii.tr.national_id | shared | 4 | **66.7** | **66.7** | **66.7** | **66.7** | 0.0 | 0.0 |
| presidio_favored | pii.uk.national_insurance_number | shared | 3 | 0.0 | 66.7 | 66.7 | 66.7 | 0.0 | **100.0** |
| presidio_favored | pii.uk.postcode | presidio_only | 4 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| presidio_favored | pii.url | presidio_only | 21 | 0.0 | 0.0 | 0.0 | 0.0 | **77.8** | **77.8** |
| presidio_favored | pii.us.itin | presidio_only | 2 | 0.0 | 0.0 | 0.0 | 0.0 | **100.0** | **100.0** |
| presidio_favored | pii.us.mbi | presidio_only | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| presidio_favored | pii.us.npi | shared | 5 | 75.0 | 88.9 | **100.0** | 88.9 | 0.0 | **100.0** |
| presidio_favored | pii.us.social_security_number | shared | 15 | 57.1 | 75.0 | 80.0 | 75.0 | **100.0** | 88.9 |
| presidio_favored | pii.za.id_number | shared | 3 | 50.0 | **100.0** | **100.0** | **100.0** | 0.0 | **100.0** |
