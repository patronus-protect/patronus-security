# L1-PII: Abschlussbericht M1–M4 (H05)

Stand: 2026-11-05, ARK-Quellen wie `main` `dc27114` (nach H06-6; die H05-Commits ändern nur das Scoreboard),
Paket 0.1.15, Release-Build. Presidio 2.2.364 in beiden Profilen, Pins aus
`scripts/l1_presidio/requirements.txt`. Meilensteine nach [`../README.md`](../README.md): Modus `balanced`,
erreichbares Gold (T27), entscheidend sind die Familien `neutral` und `presidio_favored`.

## Ergebnis

| Meilenstein | Kriterium | Dev (2026-11-05) | Holdout | Urteil |
|---|---|---|---|---|
| M1 Parität EN | je gemeinsamer ID F1(ARK) ≥ F1(Presidio tuned), je Familie | neutral 9/9, presidio_favored 22/22 | Gate-Bericht, Zeile `milestones holdout` | Dev erreicht |
| M2 DE/EU | DE-Macro-F1 neutral ≥ tuned + 15 pp, presidio_favored ≥ tuned | neutral 66,1 ≥ 36,2 (14 IDs), presidio_favored 100,0 ≥ 100,0 (9 IDs) | Gate-Bericht, Zeile `milestones holdout` | Dev erreicht |
| M3 Breite | ≥ 2× prüfziffervalidierte Einheiten von Presidio (35 → 70) | ARK 83, Presidio 35, gemeinsam 33 | – (zählt Code, keine Daten) | erreicht |
| M4 Latenz | 100 KiB p95 ≤ 10 ms | nativ 9,774 ms, Python-Bindings 15,003 ms | – (feste Workloads) | erreicht (nativ, Entscheidung 2026-11-05) |
| Immer | HN-FP ≤ Presidio; keine Entität verliert > 0,5 pp | HN-FP neutral 0 / 0, presidio_favored 0 / 0 (tuned) | Gate (Regressionen, neue HN-FP) | Dev erreicht |

- **M1** gilt nur auf erreichbarem Gold. Roh (berichtet, entscheidet nicht) hält ARK `balanced` auf
  `presidio_favored` 13/25 gemeinsame IDs gegen tuned; darunter liegen die festgehaltenen Ausnahmen
  (`known_gaps`: Loopback-IPs, blanke NPI/Aadhaar/SIN, SSN-Bereiche, siehe README, T27, Q-M1).
  `strict` (Standard des Builds, entscheidet nicht) hält 8/9 und 11/22.
- **M2** roh (berichtet, entscheidet nicht): neutral 63,0 ≥ 36,2, presidio_favored 63,2 < 87,0 (11 IDs;
  erreichbar bleiben 9).
- **M3** aus `python3 scripts/l1_presidio/count_validated.py count` (Zählregel T03).
- **M4** aus [`latency.md`](latency.md) (H06, VPS, Haswell, 6 CPUs; DE + EN gepoolt): ARK nativ 100 KiB
  p95 9,774 ms (≤ 10 ms seit H06-2), über die Python-Bindings 15,003 ms. Presidio auf derselben Maschine:
  default 13 634,6 ms, tuned 11 978,8 ms (798× über den Bindings). Nach der Entscheidung vom 2026-11-05
  zählt M4 nativ als erreicht; die Bindings bleiben über dem Budget (offene Hotspots: `matched_rules`-
  Einträge als `serde_json`-Werte, H06-7 zurückgestellt).

## Holdout

Der Holdout liegt nur auf der VPS und ist für den Agenten unsichtbar. Seit H05 rechnet
`scoreboard.py gate` M1 und M2 des Heads je Split (`balanced`, erreichbares Gold, gegen Presidio tuned)
und druckt je Split eine Aggregatzeile vor `RESULT`:

```
milestones holdout (balanced, attainable gold, vs Presidio tuned): M1 … (neutral x/y, presidio_favored x/y shared ids) | M2 … (macro-F1 neutral a >= b, presidio_favored c >= d)
```

Der Gate-Schritt läuft im Presidio-Venv ohne Netz und liest den Holdout; der Runner übernimmt das Ende
einer grünen Scoreboard-Ausgabe in den Gate-Bericht und damit in den PR. Die Holdout-Zahlen von H05 stehen
deshalb im Gate-Bericht des H05-PRs (dort auch F1 je Familie in `strict` und `balanced` mit HN-FP) und in
jedem späteren Gate-Bericht. Presidio tuned läuft auf dem Holdout einmal (Dev: 261 s für alle Goldsets)
und wird danach je Runner, Profil und Eingabe-SHA-256 aus dem Cache gelesen. M3 und M4 hängen nicht vom
Holdout ab.

Auf Dev gibt die Zeile genau die Zahlen von `scoreboard.py m1`/`m2` wieder:

```
milestones dev (balanced, attainable gold, vs Presidio tuned): M1 MET (neutral 9/9, presidio_favored 22/22 shared ids) | M2 MET (macro-F1 neutral 66.1 >= 36.2, presidio_favored 100.0 >= 100.0)
```

## Gesamt je Familie (Dev, exact span, L1-IDs)

| Familie | ARK balanced P/R/F1 | ARK strict F1 | Presidio tuned P/R/F1 | Presidio default F1 | HN-FP ARK / tuned |
|---|---|---:|---|---:|---|
| neutral | 72,2 / 67,9 / **70,0** | 69,6 | 35,2 / 47,7 / 40,5 | 18,0 | 0 / 0 |
| presidio_favored | 99,7 / 65,1 / **78,7** | 65,4 | 93,0 / 66,5 / 77,6 | 63,6 | 0 / 0 |
| ark_authored ¹ | 99,9 / 79,0 / **88,2** | 75,2 | 54,5 / 35,3 / 42,8 | 16,2 | 0 / 228 |

¹ berichtet, entscheidet keinen Meilenstein.

Gegenüber dem Scoreboard vom 2026-11-02 ([`baseline.md`](baseline.md)): neutral 70,0 unverändert,
presidio_favored 78,1 → 78,7. Presidio wurde für diesen Bericht auf Dev neu gerechnet (tuned neutral
40,5, presidio_favored 77,6; am 2026-11-02 standen die neu bewerteten Vorhersagen vom 2026-10-29 mit
40,6 / 71,3 im Bericht).

## Reproduktion

```bash
# DEV = $ARK_L1_DEV_DATA; je Gold-Datei f (relativer Pfad), Engines wie in baseline.md:
.venv/bin/python scripts/l1_presidio/run_ark.py --pii-mode strict --input DEV/$f --output PRED/ark-strict/$f
.venv/bin/python scripts/l1_presidio/run_ark.py --pii-mode balanced --input DEV/$f --output PRED/ark-balanced/$f
~/ark-l1/presidio-venv/bin/python scripts/l1_presidio/run_presidio.py --profile default --input DEV/$f --output PRED/presidio-default/$f
~/ark-l1/presidio-venv/bin/python scripts/l1_presidio/run_presidio.py --profile tuned --input DEV/$f --output PRED/presidio-tuned/$f
python3 scripts/l1_presidio/scoreboard.py report --gold DEV --ark strict=PRED/ark-strict \
  --ark balanced=PRED/ark-balanced --engine presidio-default=PRED/presidio-default \
  --engine presidio-tuned=PRED/presidio-tuned
python3 scripts/l1_presidio/count_validated.py count
# Holdout: nur im Gate (ark-l1 gate → scoreboard.py gate --holdout ~/ark-l1/holdout)
```

## Anhang: Tabellen (Dev)

Ausgabe von `scoreboard.py report` (Dev, exact span, Prozent; ohne den Gold-Lücken-Teil).

### Overall per source family

| Family | Engine | Rows | Gold | Pred | Exact P | Exact R | Exact F1 | Overlap F1 | EN F1 | DE F1 | HN-FP |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| ark_authored ¹ | ark-strict | 644 | 3331 | 2059 | 98.4 | 60.8 | 75.2 | 75.2 | 73.8 | 76.5 | 0 |
| ark_authored ¹ | ark-balanced | 644 | 3331 | 2633 | 99.9 | 79.0 | 88.2 | 88.2 | 87.8 | 88.6 | 0 |
| ark_authored ¹ | presidio-default | 644 | 3331 | 4359 | 14.3 | 18.7 | 16.2 | 16.5 | 18.4 | 14.3 | 1134 |
| ark_authored ¹ | presidio-tuned | 644 | 3331 | 2155 | 54.5 | 35.3 | 42.8 | 43.3 | 36.5 | 48.5 | 228 |
| neutral | ark-strict | 2336 | 1986 | 1863 | 71.9 | 67.4 | 69.6 | 71.7 | 69.2 | 69.8 | 0 |
| neutral | ark-balanced | 2336 | 1986 | 1868 | 72.2 | 67.9 | 70.0 | 72.1 | 69.8 | 69.8 | 0 |
| neutral | presidio-default | 2336 | 1986 | 9258 | 10.9 | 50.9 | 18.0 | 19.9 | 16.3 | 13.5 | 0 |
| neutral | presidio-tuned | 2336 | 1986 | 2690 | 35.2 | 47.7 | 40.5 | 44.1 | 37.8 | 33.5 | 0 |
| presidio_favored | ark-strict | 1123 | 478 | 234 | 99.6 | 48.7 | 65.4 | 65.7 | 75.1 | 14.6 | 0 |
| presidio_favored | ark-balanced | 1123 | 478 | 312 | 99.7 | 65.1 | 78.7 | 79.0 | 82.6 | 71.2 | 0 |
| presidio_favored | presidio-default | 1123 | 478 | 330 | 77.9 | 53.8 | 63.6 | 64.6 | 73.3 | 18.6 | 7 |
| presidio_favored | presidio-tuned | 1123 | 478 | 342 | 93.0 | 66.5 | 77.6 | 78.3 | 84.6 | 93.0 | 0 |

¹ ark_authored is reported and decides no milestone.

### Per corpus (exact P / R / F1)

| Corpus | Family | Rows | Gold | ark-strict | ark-balanced | presidio-default | presidio-tuned |
|---|---|---:|---:|---|---|---|---|
| ai4privacy-openpii-nano-1k | neutral | 355 | 554 | 96.9 / 56.3 / 71.2 | 96.6 / 56.5 / **71.3** | 37.4 / 48.7 / 42.4 | 71.1 / 48.0 / 57.3 |
| ark-synthetic-de-eu | ark_authored | 420 | 2869 | 98.4 / 70.6 / 82.2 | 99.9 / 76.1 / **86.4** | 17.0 / 21.7 / 19.1 | 58.3 / 41.0 / 48.1 |
| ark-synthetic-vat-1 | ark_authored | 112 | 224 | 0.0 / 0.0 / 0.0 | 100.0 / 100.0 / **100.0** | 0.0 / 0.0 / 0.0 | 0.0 / 0.0 / 0.0 |
| ark-synthetic-vat-2 | ark_authored | 112 | 238 | 0.0 / 0.0 / 0.0 | 100.0 / 94.1 / **97.0** | 0.0 / 0.0 / 0.0 | 0.0 / 0.0 / 0.0 |
| gretel-synthetic-pii-finance | neutral | 1931 | 1432 | 66.6 / 71.7 / 69.1 | 67.1 / 72.3 / **69.6** | 8.7 / 51.7 / 14.8 | 29.4 / 47.6 / 36.4 |
| presidio-analyzer-recognizer-tests | presidio_favored | 553 | 340 | 99.2 / 37.1 / 54.0 | 99.5 / 57.6 / 73.0 | 94.8 / 42.9 / 59.1 | 100.0 / 60.9 / **75.7** |
| presidio-evaluator-synth-v2 | presidio_favored | 570 | 138 | 100.0 / 77.5 / 87.3 | 100.0 / 83.3 / **90.9** | 63.1 / 80.4 / 70.7 | 82.2 / 80.4 / 81.3 |
| tab | neutral | 50 | 0 | 0.0 / 0.0 / 0.0 | 0.0 / 0.0 / 0.0 | 0.0 / 0.0 / 0.0 | 0.0 / 0.0 / 0.0 |

### Per entity (exact F1, best in bold)

| Family | Entity | Scope | Gold | ark-strict | ark-balanced | presidio-default | presidio-tuned |
|---|---|---|---:|---:|---:|---:|---:|
| ark_authored | entity.driver_license_number | shared | 23 | **100.0** | **100.0** | 0.7 | 47.3 |
| ark_authored | entity.passport_number | shared | 24 | 91.3 | **97.9** | 4.7 | 51.7 |
| ark_authored | pii.applicant_id | ark_only | 24 | **100.0** | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.at.vat_id | ark_only | 16 | 0.0 | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.au.abn | shared | 18 | **100.0** | **100.0** | 0.0 | 66.7 |
| ark_authored | pii.au.acn | shared | 24 | **100.0** | **100.0** | 0.0 | 50.0 |
| ark_authored | pii.au.medicare | shared | 19 | **100.0** | **100.0** | 0.0 | 48.8 |
| ark_authored | pii.au.tfn | shared | 20 | **100.0** | **100.0** | 0.0 | 50.0 |
| ark_authored | pii.be.vat_id | ark_only | 16 | 0.0 | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.bg.vat_id | ark_only | 16 | 0.0 | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.ca.sin | shared | 23 | **100.0** | **100.0** | 0.0 | 55.8 |
| ark_authored | pii.ch.vat_id | ark_only | 16 | 0.0 | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.credit_card.cvv | ark_only | 27 | **68.3** | **68.3** | 0.0 | 0.0 |
| ark_authored | pii.credit_card.expiry | ark_only | 26 | 0.0 | 0.0 | 0.0 | 0.0 |
| ark_authored | pii.credit_card.pan | shared | 19 | **100.0** | **100.0** | 79.2 | 79.2 |
| ark_authored | pii.crypto_wallet | shared | 21 | **100.0** | **100.0** | **100.0** | **100.0** |
| ark_authored | pii.customer_id | ark_only | 93 | **99.5** | **99.5** | 0.0 | 0.0 |
| ark_authored | pii.cy.vat_id | ark_only | 16 | 0.0 | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.cz.vat_id | ark_only | 16 | 0.0 | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.date_of_birth | ark_only | 144 | **99.7** | **99.7** | 0.0 | 0.0 |
| ark_authored | pii.de.bsnr | shared | 50 | **100.0** | **100.0** | 0.0 | 65.0 |
| ark_authored | pii.de.commercial_register | shared | 56 | **100.0** | **100.0** | 0.0 | 88.0 |
| ark_authored | pii.de.health_insurance_number | shared | 55 | 96.2 | **100.0** | 0.0 | 86.6 |
| ark_authored | pii.de.lanr | shared | 53 | 97.1 | **100.0** | 0.0 | 81.6 |
| ark_authored | pii.de.postal_code | presidio_only | 231 | 0.0 | 0.0 | 0.0 | **82.8** |
| ark_authored | pii.de.social_security_number | shared | 25 | 81.0 | **100.0** | 0.0 | 27.6 |
| ark_authored | pii.de.tax_id | shared | 27 | 94.1 | **100.0** | 0.0 | 29.3 |
| ark_authored | pii.de.tax_number | shared | 55 | 95.2 | **100.0** | 0.0 | 84.5 |
| ark_authored | pii.de.vat_id | shared | 87 | 0.0 | **100.0** | 0.0 | 65.1 |
| ark_authored | pii.dk.vat_id | ark_only | 16 | 0.0 | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.ee.vat_id | ark_only | 16 | 0.0 | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.email | shared | 144 | **100.0** | **100.0** | **100.0** | **100.0** |
| ark_authored | pii.employee_id | ark_only | 27 | **100.0** | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.es.nie | shared | 26 | 84.4 | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.es.nif | shared | 26 | **100.0** | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.es.vat_id | ark_only | 16 | 0.0 | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.fi.personal_identity_code | shared | 28 | **100.0** | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.fi.vat_id | ark_only | 16 | 0.0 | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.financial_account_number | shared | 20 | **100.0** | **100.0** | 4.9 | 37.5 |
| ark_authored | pii.fr.vat_id | ark_only | 16 | 0.0 | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.gr.vat_id | ark_only | 16 | 0.0 | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.hr.vat_id | ark_only | 16 | 0.0 | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.hu.vat_id | ark_only | 16 | 0.0 | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.iban | shared | 81 | **100.0** | **100.0** | **100.0** | **100.0** |
| ark_authored | pii.identity_card_number | shared | 31 | 85.2 | **100.0** | 0.0 | 38.5 |
| ark_authored | pii.ie.vat_id | ark_only | 16 | 0.0 | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.in.aadhaar | shared | 22 | **100.0** | **100.0** | 0.0 | 64.7 |
| ark_authored | pii.in.gstin | shared | 24 | **100.0** | **100.0** | 0.0 | 66.7 |
| ark_authored | pii.in.pan | shared | 19 | **100.0** | **100.0** | 0.0 | 26.9 |
| ark_authored | pii.in.voter_id | shared | 23 | **100.0** | **100.0** | 0.0 | 57.9 |
| ark_authored | pii.ip_address | shared | 84 | **100.0** | **100.0** | **100.0** | **100.0** |
| ark_authored | pii.it.fiscal_code | shared | 23 | **100.0** | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.it.vat_code | shared | 28 | 0.0 | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.kr.brn | shared | 27 | **100.0** | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.kr.frn | shared | 23 | **100.0** | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.kr.rrn | shared | 24 | **100.0** | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.license_plate | shared | 19 | **100.0** | **100.0** | 0.0 | 81.3 |
| ark_authored | pii.lt.vat_id | ark_only | 16 | 0.0 | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.lu.vat_id | ark_only | 16 | 0.0 | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.lv.vat_id | ark_only | 16 | 0.0 | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.mac_address | shared | 22 | **100.0** | **100.0** | **100.0** | **100.0** |
| ark_authored | pii.mt.vat_id | ark_only | 16 | 0.0 | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.ng.nin | presidio_only | 28 | 0.0 | 0.0 | 0.0 | 0.0 |
| ark_authored | pii.nl.vat_id | ark_only | 16 | 0.0 | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.no.vat_id | ark_only | 16 | 0.0 | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.patient_id | ark_only | 22 | **92.7** | **92.7** | 0.0 | 0.0 |
| ark_authored | pii.ph.tin | presidio_only | 24 | 0.0 | 0.0 | 0.0 | 0.0 |
| ark_authored | pii.ph.umid | presidio_only | 24 | 0.0 | 0.0 | 0.0 | 0.0 |
| ark_authored | pii.phone | shared | 85 | 83.6 | **98.2** | 26.0 | 26.0 |
| ark_authored | pii.pl.pesel | shared | 22 | **100.0** | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.pl.vat_id | ark_only | 16 | 0.0 | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.pt.vat_id | ark_only | 16 | 0.0 | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.ro.vat_id | ark_only | 16 | 0.0 | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.se.organisationsnummer | shared | 20 | **100.0** | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.se.personnummer | shared | 19 | **100.0** | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.se.vat_id | ark_only | 16 | 0.0 | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.sg.nric_fin | shared | 21 | **100.0** | **100.0** | 0.0 | 60.0 |
| ark_authored | pii.sg.uen | shared | 24 | **100.0** | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.si.vat_id | ark_only | 16 | 0.0 | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.sk.vat_id | ark_only | 16 | 0.0 | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.student_id | ark_only | 30 | **98.3** | **98.3** | 0.0 | 0.0 |
| ark_authored | pii.swift_bic | ark_only | 84 | **100.0** | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.th.tnin | presidio_only | 24 | 0.0 | 0.0 | 0.0 | 0.0 |
| ark_authored | pii.tr.national_id | shared | 21 | **100.0** | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.uk.national_insurance_number | shared | 22 | 95.2 | **100.0** | 0.0 | 50.0 |
| ark_authored | pii.uk.nhs_number | shared | 53 | **96.1** | **96.1** | 83.5 | 83.0 |
| ark_authored | pii.uk.postcode | presidio_only | 249 | 0.0 | 0.0 | 0.0 | 0.0 |
| ark_authored | pii.uk.vat_id | ark_only | 16 | 0.0 | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.url | presidio_only | 20 | 0.0 | 0.0 | **8.2** | **8.2** |
| ark_authored | pii.us.itin | presidio_only | 22 | 0.0 | 0.0 | **83.0** | 58.1 |
| ark_authored | pii.us.mbi | presidio_only | 24 | 0.0 | 0.0 | 0.0 | 0.0 |
| ark_authored | pii.us.medical_license | shared | 22 | **100.0** | **100.0** | 41.1 | 32.3 |
| ark_authored | pii.us.npi | shared | 22 | **100.0** | **100.0** | 0.0 | 56.3 |
| ark_authored | pii.us.social_security_number | shared | 29 | **100.0** | **100.0** | 23.4 | 55.6 |
| ark_authored | pii.username | ark_only | 84 | **98.2** | **98.2** | 0.0 | 0.0 |
| ark_authored | pii.za.id_number | shared | 23 | **100.0** | **100.0** | 0.0 | 75.7 |
| neutral | entity.driver_license_number | shared | 120 | **40.3** | **40.3** | 0.8 | 6.2 |
| neutral | entity.passport_number | shared | 98 | **68.5** | 68.0 | 18.7 | 38.2 |
| neutral | pii.credit_card.cvv | ark_only | 47 | **63.4** | **63.4** | 0.0 | 0.0 |
| neutral | pii.credit_card.pan | shared | 135 | **47.9** | **47.9** | 35.6 | 35.6 |
| neutral | pii.customer_id | ark_only | 90 | **60.9** | **60.9** | 0.0 | 0.0 |
| neutral | pii.date_of_birth | ark_only | 82 | **67.0** | **67.0** | 0.0 | 0.0 |
| neutral | pii.email | shared | 417 | **68.8** | **68.8** | 67.9 | 67.9 |
| neutral | pii.employee_id | ark_only | 75 | **88.2** | **88.2** | 0.0 | 0.0 |
| neutral | pii.financial_account_number | shared | 126 | 47.8 | **49.2** | 5.0 | 12.5 |
| neutral | pii.iban | shared | 55 | **91.7** | **91.7** | **91.7** | **91.7** |
| neutral | pii.ip_address | shared | 88 | **96.7** | **96.7** | 94.6 | 94.6 |
| neutral | pii.phone | shared | 504 | 82.0 | **82.1** | 36.7 | 36.7 |
| neutral | pii.swift_bic | ark_only | 79 | **73.4** | **73.4** | 0.0 | 0.0 |
| neutral | pii.us.social_security_number | shared | 44 | 50.8 | **68.5** | 21.4 | 66.7 |
| neutral | pii.username | ark_only | 26 | **10.3** | **10.3** | 0.0 | 0.0 |
| presidio_favored | entity.driver_license_number | shared | 14 | 52.6 | **83.3** | 15.2 | 78.3 |
| presidio_favored | entity.passport_number | shared | 29 | 29.4 | 55.0 | **60.5** | 51.3 |
| presidio_favored | pii.au.abn | shared | 1 | 0.0 | **100.0** | 0.0 | **100.0** |
| presidio_favored | pii.au.acn | shared | 3 | 0.0 | 0.0 | 0.0 | **100.0** |
| presidio_favored | pii.au.medicare | shared | 1 | 0.0 | **100.0** | 0.0 | **100.0** |
| presidio_favored | pii.ca.sin | shared | 5 | 33.3 | 57.1 | 0.0 | **88.9** |
| presidio_favored | pii.credit_card.pan | shared | 49 | **100.0** | **100.0** | 91.1 | 91.1 |
| presidio_favored | pii.crypto_wallet | shared | 1 | **100.0** | **100.0** | **100.0** | **100.0** |
| presidio_favored | pii.de.bsnr | shared | 5 | **57.1** | **57.1** | 0.0 | **57.1** |
| presidio_favored | pii.de.commercial_register | shared | 1 | 0.0 | **100.0** | 0.0 | **100.0** |
| presidio_favored | pii.de.health_insurance_number | shared | 3 | 0.0 | **100.0** | 0.0 | **100.0** |
| presidio_favored | pii.de.lanr | shared | 3 | 0.0 | 50.0 | 0.0 | **100.0** |
| presidio_favored | pii.de.social_security_number | shared | 1 | 0.0 | **100.0** | 0.0 | **100.0** |
| presidio_favored | pii.de.tax_id | shared | 1 | 0.0 | 0.0 | 0.0 | **100.0** |
| presidio_favored | pii.de.tax_number | shared | 2 | 0.0 | 66.7 | 0.0 | **100.0** |
| presidio_favored | pii.de.vat_id | shared | 5 | 0.0 | 75.0 | 0.0 | **100.0** |
| presidio_favored | pii.email | shared | 16 | **100.0** | **100.0** | **100.0** | **100.0** |
| presidio_favored | pii.es.nie | shared | 5 | 33.3 | **88.9** | 0.0 | 0.0 |
| presidio_favored | pii.es.nif | shared | 3 | 0.0 | **80.0** | 0.0 | 0.0 |
| presidio_favored | pii.fi.personal_identity_code | shared | 14 | 25.0 | **96.3** | 0.0 | 0.0 |
| presidio_favored | pii.financial_account_number | shared | 5 | 0.0 | 57.1 | **66.7** | 0.0 |
| presidio_favored | pii.iban | shared | 65 | **100.0** | **100.0** | **100.0** | **100.0** |
| presidio_favored | pii.identity_card_number | shared | 11 | 16.7 | 42.9 | 0.0 | **84.2** |
| presidio_favored | pii.in.aadhaar | shared | 4 | 0.0 | 85.7 | 0.0 | **100.0** |
| presidio_favored | pii.in.gstin | shared | 3 | 0.0 | 0.0 | 0.0 | **100.0** |
| presidio_favored | pii.in.pan | shared | 3 | 50.0 | 50.0 | 0.0 | **80.0** |
| presidio_favored | pii.in.voter_id | shared | 3 | 0.0 | 0.0 | 0.0 | **50.0** |
| presidio_favored | pii.ip_address | shared | 41 | 86.1 | 86.1 | **100.0** | 96.2 |
| presidio_favored | pii.it.fiscal_code | shared | 3 | 0.0 | **50.0** | 0.0 | 0.0 |
| presidio_favored | pii.it.vat_code | shared | 1 | 0.0 | 0.0 | 0.0 | 0.0 |
| presidio_favored | pii.kr.brn | shared | 2 | 0.0 | **66.7** | 0.0 | 0.0 |
| presidio_favored | pii.kr.frn | shared | 3 | 0.0 | **80.0** | 0.0 | 0.0 |
| presidio_favored | pii.kr.rrn | shared | 5 | 33.3 | **57.1** | 0.0 | 0.0 |
| presidio_favored | pii.license_plate | shared | 21 | 9.1 | 38.5 | 0.0 | **68.8** |
| presidio_favored | pii.mac_address | shared | 6 | **100.0** | **100.0** | **100.0** | **100.0** |
| presidio_favored | pii.ph.tin | presidio_only | 3 | 0.0 | 0.0 | 0.0 | 0.0 |
| presidio_favored | pii.ph.umid | presidio_only | 8 | 0.0 | 0.0 | 0.0 | 0.0 |
| presidio_favored | pii.phone | shared | 46 | 80.5 | **91.8** | 65.1 | 65.1 |
| presidio_favored | pii.pl.pesel | shared | 3 | **50.0** | **50.0** | 0.0 | 0.0 |
| presidio_favored | pii.se.organisationsnummer | shared | 3 | 0.0 | **50.0** | 0.0 | 0.0 |
| presidio_favored | pii.se.personnummer | shared | 2 | 66.7 | **100.0** | 0.0 | 0.0 |
| presidio_favored | pii.sg.nric_fin | shared | 3 | 0.0 | 50.0 | 0.0 | **80.0** |
| presidio_favored | pii.sg.uen | shared | 4 | 0.0 | **85.7** | 0.0 | 0.0 |
| presidio_favored | pii.th.tnin | presidio_only | 6 | 0.0 | 0.0 | 0.0 | 0.0 |
| presidio_favored | pii.tr.national_id | shared | 4 | **66.7** | **66.7** | 0.0 | 0.0 |
| presidio_favored | pii.uk.national_insurance_number | shared | 3 | 0.0 | 66.7 | 0.0 | **100.0** |
| presidio_favored | pii.uk.postcode | presidio_only | 4 | 0.0 | 0.0 | 0.0 | 0.0 |
| presidio_favored | pii.url | presidio_only | 21 | 0.0 | 0.0 | **77.8** | **77.8** |
| presidio_favored | pii.us.itin | presidio_only | 2 | 0.0 | 0.0 | **100.0** | **100.0** |
| presidio_favored | pii.us.mbi | presidio_only | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| presidio_favored | pii.us.npi | shared | 5 | 75.0 | 88.9 | 0.0 | **100.0** |
| presidio_favored | pii.us.social_security_number | shared | 15 | 57.1 | 75.0 | **100.0** | 88.9 |
| presidio_favored | pii.za.id_number | shared | 3 | 50.0 | **100.0** | 0.0 | **100.0** |

### Per entity, attainable gold (exact F1, best in bold; the F1 >= 80 floor is judged here, T27)

| Family | Entity | Scope | Gold | ark-strict | ark-balanced | presidio-default | presidio-tuned |
|---|---|---|---:|---:|---:|---:|---:|
| ark_authored | entity.driver_license_number | shared | 23 | **100.0** | **100.0** | 0.7 | 47.3 |
| ark_authored | entity.passport_number | shared | 24 | 91.3 | **97.9** | 4.7 | 51.7 |
| ark_authored | pii.applicant_id | ark_only | 24 | **100.0** | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.at.vat_id | ark_only | 16 | 0.0 | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.au.abn | shared | 18 | **100.0** | **100.0** | 0.0 | 66.7 |
| ark_authored | pii.au.acn | shared | 24 | **100.0** | **100.0** | 0.0 | 50.0 |
| ark_authored | pii.au.medicare | shared | 19 | **100.0** | **100.0** | 0.0 | 48.8 |
| ark_authored | pii.au.tfn | shared | 20 | **100.0** | **100.0** | 0.0 | 50.0 |
| ark_authored | pii.be.vat_id | ark_only | 16 | 0.0 | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.bg.vat_id | ark_only | 16 | 0.0 | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.ca.sin | shared | 23 | **100.0** | **100.0** | 0.0 | 55.8 |
| ark_authored | pii.ch.vat_id | ark_only | 16 | 0.0 | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.credit_card.cvv | ark_only | 27 | **68.3** | **68.3** | 0.0 | 0.0 |
| ark_authored | pii.credit_card.expiry | ark_only | 26 | 0.0 | 0.0 | 0.0 | 0.0 |
| ark_authored | pii.credit_card.pan | shared | 19 | **100.0** | **100.0** | 79.2 | 79.2 |
| ark_authored | pii.crypto_wallet | shared | 21 | **100.0** | **100.0** | **100.0** | **100.0** |
| ark_authored | pii.customer_id | ark_only | 93 | **99.5** | **99.5** | 0.0 | 0.0 |
| ark_authored | pii.cy.vat_id | ark_only | 16 | 0.0 | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.cz.vat_id | ark_only | 16 | 0.0 | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.date_of_birth | ark_only | 144 | **99.7** | **99.7** | 0.0 | 0.0 |
| ark_authored | pii.de.bsnr | shared | 50 | **100.0** | **100.0** | 0.0 | 65.0 |
| ark_authored | pii.de.commercial_register | shared | 56 | **100.0** | **100.0** | 0.0 | 88.0 |
| ark_authored | pii.de.health_insurance_number | shared | 55 | 96.2 | **100.0** | 0.0 | 86.6 |
| ark_authored | pii.de.lanr | shared | 53 | 97.1 | **100.0** | 0.0 | 81.6 |
| ark_authored | pii.de.postal_code | presidio_only | 231 | 0.0 | 0.0 | 0.0 | **82.8** |
| ark_authored | pii.de.social_security_number | shared | 25 | 81.0 | **100.0** | 0.0 | 27.6 |
| ark_authored | pii.de.tax_id | shared | 27 | 94.1 | **100.0** | 0.0 | 29.3 |
| ark_authored | pii.de.tax_number | shared | 55 | 95.2 | **100.0** | 0.0 | 84.5 |
| ark_authored | pii.de.vat_id | shared | 87 | 0.0 | **100.0** | 0.0 | 65.1 |
| ark_authored | pii.dk.vat_id | ark_only | 16 | 0.0 | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.ee.vat_id | ark_only | 16 | 0.0 | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.email | shared | 144 | **100.0** | **100.0** | **100.0** | **100.0** |
| ark_authored | pii.employee_id | ark_only | 27 | **100.0** | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.es.nie | shared | 26 | 84.4 | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.es.nif | shared | 26 | **100.0** | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.es.vat_id | ark_only | 16 | 0.0 | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.fi.personal_identity_code | shared | 28 | **100.0** | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.fi.vat_id | ark_only | 16 | 0.0 | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.financial_account_number | shared | 20 | **100.0** | **100.0** | 4.9 | 37.5 |
| ark_authored | pii.fr.vat_id | ark_only | 16 | 0.0 | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.gr.vat_id | ark_only | 16 | 0.0 | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.hr.vat_id | ark_only | 16 | 0.0 | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.hu.vat_id | ark_only | 16 | 0.0 | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.iban | shared | 81 | **100.0** | **100.0** | **100.0** | **100.0** |
| ark_authored | pii.identity_card_number | shared | 31 | 85.2 | **100.0** | 0.0 | 38.5 |
| ark_authored | pii.ie.vat_id | ark_only | 16 | 0.0 | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.in.aadhaar | shared | 22 | **100.0** | **100.0** | 0.0 | 64.7 |
| ark_authored | pii.in.gstin | shared | 24 | **100.0** | **100.0** | 0.0 | 66.7 |
| ark_authored | pii.in.pan | shared | 19 | **100.0** | **100.0** | 0.0 | 26.9 |
| ark_authored | pii.in.voter_id | shared | 23 | **100.0** | **100.0** | 0.0 | 57.9 |
| ark_authored | pii.ip_address | shared | 84 | **100.0** | **100.0** | **100.0** | **100.0** |
| ark_authored | pii.it.fiscal_code | shared | 23 | **100.0** | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.it.vat_code | shared | 28 | 0.0 | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.kr.brn | shared | 27 | **100.0** | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.kr.frn | shared | 23 | **100.0** | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.kr.rrn | shared | 24 | **100.0** | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.license_plate | shared | 19 | **100.0** | **100.0** | 0.0 | 81.3 |
| ark_authored | pii.lt.vat_id | ark_only | 16 | 0.0 | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.lu.vat_id | ark_only | 16 | 0.0 | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.lv.vat_id | ark_only | 16 | 0.0 | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.mac_address | shared | 22 | **100.0** | **100.0** | **100.0** | **100.0** |
| ark_authored | pii.mt.vat_id | ark_only | 16 | 0.0 | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.ng.nin | presidio_only | 28 | 0.0 | 0.0 | 0.0 | 0.0 |
| ark_authored | pii.nl.vat_id | ark_only | 16 | 0.0 | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.no.vat_id | ark_only | 16 | 0.0 | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.patient_id | ark_only | 22 | **92.7** | **92.7** | 0.0 | 0.0 |
| ark_authored | pii.ph.tin | presidio_only | 24 | 0.0 | 0.0 | 0.0 | 0.0 |
| ark_authored | pii.ph.umid | presidio_only | 24 | 0.0 | 0.0 | 0.0 | 0.0 |
| ark_authored | pii.phone | shared | 85 | 83.6 | **98.2** | 26.0 | 26.0 |
| ark_authored | pii.pl.pesel | shared | 22 | **100.0** | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.pl.vat_id | ark_only | 16 | 0.0 | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.pt.vat_id | ark_only | 16 | 0.0 | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.ro.vat_id | ark_only | 16 | 0.0 | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.se.organisationsnummer | shared | 20 | **100.0** | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.se.personnummer | shared | 19 | **100.0** | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.se.vat_id | ark_only | 16 | 0.0 | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.sg.nric_fin | shared | 21 | **100.0** | **100.0** | 0.0 | 60.0 |
| ark_authored | pii.sg.uen | shared | 24 | **100.0** | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.si.vat_id | ark_only | 16 | 0.0 | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.sk.vat_id | ark_only | 16 | 0.0 | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.student_id | ark_only | 30 | **98.3** | **98.3** | 0.0 | 0.0 |
| ark_authored | pii.swift_bic | ark_only | 84 | **100.0** | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.th.tnin | presidio_only | 24 | 0.0 | 0.0 | 0.0 | 0.0 |
| ark_authored | pii.tr.national_id | shared | 21 | **100.0** | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.uk.national_insurance_number | shared | 22 | 95.2 | **100.0** | 0.0 | 50.0 |
| ark_authored | pii.uk.nhs_number | shared | 53 | **96.1** | **96.1** | 83.5 | 83.0 |
| ark_authored | pii.uk.postcode | presidio_only | 249 | 0.0 | 0.0 | 0.0 | 0.0 |
| ark_authored | pii.uk.vat_id | ark_only | 16 | 0.0 | **100.0** | 0.0 | 0.0 |
| ark_authored | pii.url | presidio_only | 20 | 0.0 | 0.0 | **8.2** | **8.2** |
| ark_authored | pii.us.itin | presidio_only | 22 | 0.0 | 0.0 | **83.0** | 58.1 |
| ark_authored | pii.us.mbi | presidio_only | 24 | 0.0 | 0.0 | 0.0 | 0.0 |
| ark_authored | pii.us.medical_license | shared | 22 | **100.0** | **100.0** | 41.1 | 32.3 |
| ark_authored | pii.us.npi | shared | 22 | **100.0** | **100.0** | 0.0 | 56.3 |
| ark_authored | pii.us.social_security_number | shared | 29 | **100.0** | **100.0** | 23.4 | 55.6 |
| ark_authored | pii.username | ark_only | 84 | **98.2** | **98.2** | 0.0 | 0.0 |
| ark_authored | pii.za.id_number | shared | 23 | **100.0** | **100.0** | 0.0 | 75.7 |
| neutral | entity.driver_license_number | shared | 120 | **40.3** | **40.3** | 0.8 | 6.2 |
| neutral | entity.passport_number | shared | 98 | **68.5** | 68.0 | 18.7 | 38.2 |
| neutral | pii.credit_card.cvv | ark_only | 47 | **63.4** | **63.4** | 0.0 | 0.0 |
| neutral | pii.credit_card.pan | shared | 49 | **88.2** | **88.2** | 70.5 | 70.5 |
| neutral | pii.customer_id | ark_only | 90 | **60.9** | **60.9** | 0.0 | 0.0 |
| neutral | pii.date_of_birth | ark_only | 82 | **67.0** | **67.0** | 0.0 | 0.0 |
| neutral | pii.email | shared | 417 | **68.8** | **68.8** | 67.9 | 67.9 |
| neutral | pii.employee_id | ark_only | 75 | **88.2** | **88.2** | 0.0 | 0.0 |
| neutral | pii.financial_account_number | shared | 126 | 47.8 | **49.2** | 5.0 | 12.5 |
| neutral | pii.iban | shared | 55 | **91.7** | **91.7** | **91.7** | **91.7** |
| neutral | pii.ip_address | shared | 88 | **96.7** | **96.7** | 94.6 | 94.6 |
| neutral | pii.phone | shared | 504 | 82.0 | **82.1** | 36.7 | 36.7 |
| neutral | pii.swift_bic | ark_only | 79 | **73.4** | **73.4** | 0.0 | 0.0 |
| neutral | pii.us.social_security_number | shared | 29 | 66.7 | **86.2** | 22.7 | 83.3 |
| neutral | pii.username | ark_only | 26 | **10.3** | **10.3** | 0.0 | 0.0 |
| presidio_favored | entity.driver_license_number | shared | 12 | 58.8 | **90.9** | 15.6 | 85.7 |
| presidio_favored | entity.passport_number | shared | 28 | 30.3 | 56.4 | **61.9** | 48.6 |
| presidio_favored | pii.au.abn | shared | 1 | 0.0 | **100.0** | 0.0 | **100.0** |
| presidio_favored | pii.au.medicare | shared | 1 | 0.0 | **100.0** | 0.0 | **100.0** |
| presidio_favored | pii.ca.sin | shared | 2 | 66.7 | **100.0** | 0.0 | **100.0** |
| presidio_favored | pii.credit_card.pan | shared | 49 | **100.0** | **100.0** | 91.1 | 91.1 |
| presidio_favored | pii.crypto_wallet | shared | 1 | **100.0** | **100.0** | **100.0** | **100.0** |
| presidio_favored | pii.de.bsnr | shared | 2 | **100.0** | **100.0** | 0.0 | **100.0** |
| presidio_favored | pii.de.commercial_register | shared | 1 | 0.0 | **100.0** | 0.0 | **100.0** |
| presidio_favored | pii.de.health_insurance_number | shared | 3 | 0.0 | **100.0** | 0.0 | **100.0** |
| presidio_favored | pii.de.lanr | shared | 1 | 0.0 | **100.0** | 0.0 | **100.0** |
| presidio_favored | pii.de.social_security_number | shared | 1 | 0.0 | **100.0** | 0.0 | **100.0** |
| presidio_favored | pii.de.tax_number | shared | 1 | 0.0 | **100.0** | 0.0 | **100.0** |
| presidio_favored | pii.de.vat_id | shared | 3 | 0.0 | **100.0** | 0.0 | **100.0** |
| presidio_favored | pii.email | shared | 16 | **100.0** | **100.0** | **100.0** | **100.0** |
| presidio_favored | pii.es.nie | shared | 5 | 33.3 | **88.9** | 0.0 | 0.0 |
| presidio_favored | pii.es.nif | shared | 3 | 0.0 | **80.0** | 0.0 | 0.0 |
| presidio_favored | pii.fi.personal_identity_code | shared | 14 | 25.0 | **96.3** | 0.0 | 0.0 |
| presidio_favored | pii.financial_account_number | shared | 5 | 0.0 | 57.1 | **66.7** | 0.0 |
| presidio_favored | pii.iban | shared | 65 | **100.0** | **100.0** | **100.0** | **100.0** |
| presidio_favored | pii.identity_card_number | shared | 6 | 28.6 | **66.7** | 0.0 | **66.7** |
| presidio_favored | pii.in.aadhaar | shared | 3 | 0.0 | **100.0** | 0.0 | **100.0** |
| presidio_favored | pii.in.pan | shared | 1 | **100.0** | **100.0** | 0.0 | **100.0** |
| presidio_favored | pii.ip_address | shared | 31 | **100.0** | **100.0** | **100.0** | **100.0** |
| presidio_favored | pii.it.fiscal_code | shared | 1 | 0.0 | **100.0** | 0.0 | 0.0 |
| presidio_favored | pii.kr.brn | shared | 1 | 0.0 | **100.0** | 0.0 | 0.0 |
| presidio_favored | pii.kr.frn | shared | 3 | 0.0 | **80.0** | 0.0 | 0.0 |
| presidio_favored | pii.kr.rrn | shared | 2 | 66.7 | **100.0** | 0.0 | 0.0 |
| presidio_favored | pii.license_plate | shared | 8 | 22.2 | **76.9** | 0.0 | **76.9** |
| presidio_favored | pii.mac_address | shared | 6 | **100.0** | **100.0** | **100.0** | **100.0** |
| presidio_favored | pii.ph.tin | presidio_only | 3 | 0.0 | 0.0 | 0.0 | 0.0 |
| presidio_favored | pii.ph.umid | presidio_only | 8 | 0.0 | 0.0 | 0.0 | 0.0 |
| presidio_favored | pii.phone | shared | 46 | 80.5 | **91.8** | 65.1 | 65.1 |
| presidio_favored | pii.pl.pesel | shared | 1 | **100.0** | **100.0** | 0.0 | 0.0 |
| presidio_favored | pii.se.organisationsnummer | shared | 3 | 0.0 | **50.0** | 0.0 | 0.0 |
| presidio_favored | pii.se.personnummer | shared | 2 | 66.7 | **100.0** | 0.0 | 0.0 |
| presidio_favored | pii.sg.nric_fin | shared | 1 | 0.0 | **100.0** | 0.0 | **100.0** |
| presidio_favored | pii.sg.uen | shared | 4 | 0.0 | **85.7** | 0.0 | 0.0 |
| presidio_favored | pii.th.tnin | presidio_only | 6 | 0.0 | 0.0 | 0.0 | 0.0 |
| presidio_favored | pii.tr.national_id | shared | 4 | **66.7** | **66.7** | 0.0 | 0.0 |
| presidio_favored | pii.uk.national_insurance_number | shared | 2 | 0.0 | **100.0** | 0.0 | **100.0** |
| presidio_favored | pii.uk.postcode | presidio_only | 4 | 0.0 | 0.0 | 0.0 | 0.0 |
| presidio_favored | pii.url | presidio_only | 21 | 0.0 | 0.0 | **77.8** | **77.8** |
| presidio_favored | pii.us.itin | presidio_only | 2 | 0.0 | 0.0 | **100.0** | **100.0** |
| presidio_favored | pii.us.mbi | presidio_only | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| presidio_favored | pii.us.npi | shared | 4 | 85.7 | **100.0** | 0.0 | **100.0** |
| presidio_favored | pii.us.social_security_number | shared | 11 | 70.6 | 90.0 | **100.0** | 90.0 |
| presidio_favored | pii.za.id_number | shared | 3 | 50.0 | **100.0** | 0.0 | **100.0** |

### M1, attainable gold, milestone view (each Ark mode vs each profile; EN rows, exact F1, shared ids with gold; milestone on balanced)

| Ark mode | Profile | M1 | neutral | presidio_favored | ark_authored ¹ |
|---|---|---|---|---|---|
| balanced | presidio-default | NOT MET | 9/9 | 19/22 (below: entity.passport_number, pii.financial_account_number, pii.us.social_security_number) | 49/49 |
| balanced | presidio-tuned | MET | 9/9 | 22/22 | 49/49 |
| strict ² | presidio-default | NOT MET | 9/9 | 19/22 (below: entity.passport_number, pii.financial_account_number, pii.us.social_security_number) | 49/49 |
| strict ² | presidio-tuned | NOT MET | 8/9 (below: pii.us.social_security_number) | 11/22 (below: entity.driver_license_number, pii.au.abn, pii.au.medicare, pii.ca.sin, pii.in.aadhaar, pii.license_plate, pii.sg.nric_fin, pii.uk.national_insurance_number, pii.us.npi, pii.us.social_security_number, pii.za.id_number) | 49/49 |

² reported; milestones are judged on balanced (T15).

### M2, attainable gold, milestone view (each Ark mode vs each profile; DE rows, exact macro-F1 over shared + ark_only ids with gold; Ark vs target = Presidio + margin; milestone on balanced)

| Ark mode | Profile | M2 | neutral | presidio_favored | ark_authored ¹ |
|---|---|---|---|---|---|
| balanced | presidio-default | MET | 66.1 vs 39.4 (24.4 + 15), 14 ids | 100.0 vs 8.9 (8.9 + 0), 9 ids | 98.4 vs 23.4 (8.4 + 15), 87 ids |
| balanced | presidio-tuned | MET | 66.1 vs 36.2 (21.2 + 15), 14 ids | 100.0 vs 100.0 (100.0 + 0), 9 ids | 98.4 vs 32.5 (17.5 + 15), 87 ids |
| strict ² | presidio-default | MET | 66.4 vs 39.4 (24.4 + 15), 14 ids | 16.7 vs 8.9 (8.9 + 0), 9 ids | 63.0 vs 23.4 (8.4 + 15), 87 ids |
| strict ² | presidio-tuned | NOT MET | 66.4 vs 36.2 (21.2 + 15), 14 ids | 16.7 vs 100.0 (100.0 + 0), 9 ids | 63.0 vs 32.5 (17.5 + 15), 87 ids |

presidio_only ids stay out of the macro average until entity_map.yaml marks them shared (D-M2).

### M1, raw gold, reported, decides no milestone (each Ark mode vs each profile; EN rows, exact F1, shared ids with gold; milestone on balanced)

| Ark mode | Profile | M1 | neutral | presidio_favored | ark_authored ¹ |
|---|---|---|---|---|---|
| balanced | presidio-default | NOT MET | 9/9 | 21/25 (below: entity.passport_number, pii.financial_account_number, pii.ip_address, pii.us.social_security_number) | 49/49 |
| balanced | presidio-tuned | NOT MET | 9/9 | 13/25 (below: pii.au.acn, pii.ca.sin, pii.in.aadhaar, pii.in.gstin, pii.in.pan, pii.in.voter_id, pii.ip_address, pii.license_plate, pii.sg.nric_fin, pii.uk.national_insurance_number, pii.us.npi, pii.us.social_security_number) | 49/49 |
| strict ² | presidio-default | NOT MET | 9/9 | 21/25 (below: entity.passport_number, pii.financial_account_number, pii.ip_address, pii.us.social_security_number) | 49/49 |
| strict ² | presidio-tuned | NOT MET | 8/9 (below: pii.us.social_security_number) | 9/25 (below: entity.driver_license_number, pii.au.abn, pii.au.acn, pii.au.medicare, pii.ca.sin, pii.in.aadhaar, pii.in.gstin, pii.in.pan, pii.in.voter_id, pii.ip_address, pii.license_plate, pii.sg.nric_fin, pii.uk.national_insurance_number, pii.us.npi, pii.us.social_security_number, pii.za.id_number) | 49/49 |

² reported; milestones are judged on balanced (T15).

### M2, raw gold, reported, decides no milestone (each Ark mode vs each profile; DE rows, exact macro-F1 over shared + ark_only ids with gold; Ark vs target = Presidio + margin; milestone on balanced)

| Ark mode | Profile | M2 | neutral | presidio_favored | ark_authored ¹ |
|---|---|---|---|---|---|
| balanced | presidio-default | MET | 63.0 vs 39.2 (24.2 + 15), 14 ids | 63.2 vs 6.6 (6.6 + 0), 11 ids | 98.4 vs 23.4 (8.4 + 15), 87 ids |
| balanced | presidio-tuned | NOT MET | 63.0 vs 36.2 (21.2 + 15), 14 ids | 63.2 vs 87.0 (87.0 + 0), 11 ids | 98.4 vs 32.5 (17.5 + 15), 87 ids |
| strict ² | presidio-default | MET | 63.3 vs 39.2 (24.2 + 15), 14 ids | 7.2 vs 6.6 (6.6 + 0), 11 ids | 63.0 vs 23.4 (8.4 + 15), 87 ids |
| strict ² | presidio-tuned | NOT MET | 63.3 vs 36.2 (21.2 + 15), 14 ids | 7.2 vs 87.0 (87.0 + 0), 11 ids | 63.0 vs 32.5 (17.5 + 15), 87 ids |

presidio_only ids stay out of the macro average until entity_map.yaml marks them shared (D-M2).

