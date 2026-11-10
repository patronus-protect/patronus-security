# L1-DLP: Abschlussbericht M1–M4 (H-FINAL = H05 + H06)

Stand: 2026-11-10, ARK-Quellen wie `main` `e6a32f4` (nach H03-3; H-FINAL ändert keinen Detektorcode),
Release-Build des Gates. Baselines gepinnt wie in [`baseline.md`](baseline.md): gitleaks 8.30.1,
TruffleHog 3.97.9 (`--no-verification`), detect-secrets 1.5.0. Kriterien nach
[`../README.md`](../README.md#definition-besser-als-der-stand-der-technik). ARK im Default-Profil
(`strict`, ausgelieferte Regeln), exakte Spans auf den Wert.

## Ergebnis

| Meilenstein | Kriterium | Dev (2026-11-10) | Holdout | Urteil |
|---|---|---|---|---|
| M1 Provider-Parität | je gemeinsamer Provider-Entität mit Gold Recall(ARK) ≥ max(gitleaks, TruffleHog); Code-FP/MB ≤ gitleaks | 20/20 Entitäten; Code-FP/MB 0,053 ≤ 0,212 | Gate-Bericht, Zeile `milestones holdout` | Dev erreicht |
| M2 Generische Secrets | `CREDENTIAL`-F1 ≥ beste Baseline + 20 pp | 100,0 ≥ gitleaks 23,7 + 20 | Gate-Bericht, Zeile `milestones holdout` | Dev erreicht |
| M3 Breite | ≥ 90 % gitleaks-Regeln gemappt; ≥ 150 Secret-Formate; ≥ 30 Offline-Strukturprüfungen; ≥ 20 Klassen ohne Secret-Scanner-Pendant | 41,0 % (91/222); 139 Regeln; 29; 16 | – (zählt Code, keine Daten) | verfehlt (0/4) |
| M4 Latenz | Durchsatz ≥ gitleaks; 100 KiB p95 ≲ 15 ms | Durchsatz 10,37 gegen 5,11 MiB/s; p95 warm 8,0 ms nativ / 8,6 ms Python, `latency.py` 16,6 ms (kalter Erstscan) | – (feste Dev-Workloads) | Durchsatz erreicht; p95 warm erreicht, kalt verfehlt |
| Immer | Code-FP/MB ≤ beste Baseline; keine Klasse > 0,5 pp schlechter; keine echten Secrets | Code-FP/MB 0,053 (gitleaks 0,212, TruffleHog 1,430, detect-secrets 36,283); Gate ohne Regression | Gate (Regressionen, neue HN-FP) | Dev erreicht |

- **M1** zählt die Entitäten aus `milestones.m1_entities`: Scope `shared`, Familie
  `provider_secret` oder `key_material` (generische Credentials gehören zu M2) und eine
  gitleaks-Regel oder ein TruffleHog-Detektor in der Entity-Map; bewertet werden die mit Gold im
  Split. ARK findet auf Dev jede der 20 Entitäten vollständig (Recall 100,0); die knappsten
  Abstände sind Anthropic, HuggingFace, xAI, Groq, Replicate, npm, GitHub, GitLab und Slack, wo
  TruffleHog oder gitleaks ebenfalls 100,0 erreicht. Bei Anthropic, OpenAI, HuggingFace, GCP API
  Key, npm und Stripe liegt gitleaks bei 94,2–95,0, beim PEM-Schlüssel bei 78,4.
- **M2** auf der Gruppe `CREDENTIAL` (Passwörter, Tokens, Connection-Strings, URL-Userinfo,
  CLI- und Prosa-Credentials in Config, CLI und DE/EN-Prosa; 320 Gold-Spans): ARK P/R 100,0/100,0;
  gitleaks 20,2/28,7 (F1 23,7), detect-secrets 7,1/37,8 (11,9), TruffleHog 10,5/12,5 (11,4).
- **M3** aus `python3 scripts/l1_dlp/milestones.py count` (Zählregel unten). Gegenüber dem
  Scoreboard vom 2026-11-02 (73/206 gemappt, 92 Secret-Regeln, 12 Offline-Prüfungen, 15 Klassen)
  wuchs jede Zahl; das Programm endete mit der Schlussphase vom 2026-11-09 vor den
  Breiten-Paketen (P05–P12, G05, G-HASH, C05, T26–T30 `deferred`), die M3 schließen sollten.
- **M4** aus [`latency.md`](latency.md) (H03-3, VPS, 6 vCPU, ein CPU je Prozess). Der Durchsatz
  liegt auf jedem Workload über gitleaks (100 KiB 11,68 gegen 0,55 MiB/s, Repo 10,37 gegen 5,11).
  Warm liegt der 100-KiB-p95 bei 8,0 ms (nativ) und 8,6 ms (Python-Bindings), also auch unter
  dem früheren Budget von 10 ms. `latency.py` misst 16,6 ms, weil der erste Scan jedes Dokuments
  in einem Prozess bis zu 23 ms braucht (Aufbau der Lazy-DFA-Zustände der prozessweiten
  Regel-Regexe); ein frischer Gateway in einem warmen Prozess bleibt unter 9,1 ms. Die Schleife
  endete am 2026-11-10 mit H03-3 (H03-4 `deferred`, rund 13 ms akzeptiert).

## Holdout

Der Holdout liegt nur auf der VPS und ist für den Agenten unsichtbar. Seit H-FINAL rechnet
`scoreboard.py gate` M1 und M2 des Heads je Split und druckt je Split eine Aggregatzeile direkt vor
`scoreboard: PASS|FAIL`:

```
milestones holdout (default profile, exact spans): M1 … (x/y shared entities with recall >= max(gitleaks, trufflehog); FP/MB benign code a <= gitleaks b) | M2 … (CREDENTIAL F1 c >= <tool> d + 20)
```

Dafür scannen die gepinnten Baselines im Gate die Carrier-Zeilen (alle drei Tools) und den
Benign-Code (gitleaks, für die FP/MB von M1), offline über `run_baselines.py`. Die Vorhersagen
liegen im Gate-Cache je Tool, Pin, `run_baselines.py`/Entity-Map und Eingabe-SHA-256 und werden
danach nur gelesen. Die Zeile enthält nur Zählungen und Raten, keine Entitäts- oder Zeilen-IDs; ein
Messfehler erscheint als `milestones holdout: not measured (<Fehlertyp>)` und lässt das Gate nicht
scheitern. Der Runner übernimmt die letzten 15 Zeilen eines grünen Scoreboards in den Gate-Bericht;
die Holdout-Zahlen von H-FINAL stehen deshalb im Gate-Bericht dieses PRs und in jedem späteren.
M3 und M4 hängen nicht vom Holdout ab.

Auf Dev gibt die Zeile genau die Zahlen der Tabelle oben wieder:

```
milestones dev (default profile, exact spans): M1 MET (20/20 shared entities with recall >= max(gitleaks, trufflehog); FP/MB benign code 0.053 <= gitleaks 0.2119) | M2 MET (CREDENTIAL F1 100.0 >= gitleaks 23.7 + 20)
```

## Gesamt (Dev, exakte Spans)

Eingefrorener Dev-Split (8 769 Carrier-Zeilen, 1 757 Wert-Spans, 7 012 Hard Negatives; 3 624
Benign-Code-Dateien, 37,8 MB; 253 Benign-Dokumente, 7,5 MB). Die Zeile `ark` enthält wie im Gate
auch die Opt-in-Gruppen aus dem `extended`-Lauf (Geschäftskennungen mit F1 18–50, siehe unten);
die Secret-Gruppen allein liegen bei F1 91,9–100,0.

| Tool | P | R | F1 | HN-FP (Spans) | Code-FP/MB |
|---|---:|---:|---:|---:|---:|
| ark | 91,3 | 85,5 | **88,3** | 144 | 0,053 |
| gitleaks | 49,1 | 53,4 | 51,1 | 974 | 0,212 |
| trufflehog | 63,2 | 36,4 | 46,2 | 326 | 1,430 ¹ |
| detect-secrets | 33,9 | 51,6 | 40,9 | 1 731 | 36,283 ¹ |

¹ Das Gate scannt den Benign-Code nur mit gitleaks (M1); TruffleHog und detect-secrets aus
[`baseline.md`](baseline.md) (2026-11-02, gleicher Korpus, gleiche Pins).

| Gruppe | Gold | ARK | gitleaks | TruffleHog | detect-secrets |
|---|---:|---:|---:|---:|---:|
| `API_KEY` | 320 | **100,0** | 46,5 | 99,5 | 12,6 |
| `CLOUD_KEY` | 200 | **100,0** | 49,1 | 32,6 | 32,9 |
| `PAYMENT_KEY` | 80 | **100,0** | 39,2 | 28,0 | 21,8 |
| `SECRET_TOKEN` | 360 | **100,0** | 47,6 | 71,7 | 45,5 |
| `CREDENTIAL` | 320 | **100,0** | 23,7 | 11,4 | 11,9 |
| `PASSWORD_HASH` | 40 | **91,9** | 0,0 | 0,0 | 0,0 |
| `PRIVATE_KEY` | 37 | **100,0** | 46,8 | 45,8 | 56,1 |
| `CRYPTO_KEY` | 80 | **100,0** | 0,0 | 0,0 | 0,0 |

Opt-in-Geschäftskennungen (`extended`, keine Baseline hat sie): Handelsregisternummer 50,0, BSNR
28,6, USt-IdNr. und die Record-/Projekt-/Organisations-IDs 18,2 (offen in `Q-DLP-BIZ1`/`-BIZ2`,
`deferred`). Alle 144 HN-FP stammen aus diesen Opt-in-Regeln (Handelsregisternummer 64, BSNR 16,
je 8 die übrigen acht); die Default-Regeln haben auf Dev 0 HN-FP (10 am 2026-11-02, H01 räumte den
Rest ab). Benign-Dokumente: 1 FP in 253 Dokumenten (0,133 FP/MB,
`dlp_sensitive_material`).

Der Dev-Split ist der vom 2026-10-29 eingefrorene; Carrier-Zeilen, die der Generator seitdem baut
(GOLD-D2-Entitäten u. a.), bewertet weder Dev noch Holdout (T19, `deferred`). Auf dem aktuellen
Generator liegen die in T24–T28 festgehaltenen Lücken (Hard-Negative-FP der generischen Stufe,
BIP39-Fenster, Provider ohne Regel, GCP-Service-Account-JSON, Schlüssel außerhalb ihrer
Schreibweise).

## M3: Zählregel und Zählung

`python3 scripts/l1_dlp/milestones.py count` liest `entity_map.yaml` und die `RuleMeta` jeder
DLP-Regel (Registry in `ark-core/src/detectors/dlp/rules/`, geparst wie für den Regelkatalog von
`scripts/generate_docs.py`); eine Regel ohne Entität bricht die Zählung ab.

- **gitleaks gemappt:** Regel-IDs der gepinnten Default-Config (`baselines.gitleaks.inventory`), deren
  Entität eine ARK-Regel hat; `baseline_only` und `out_of_scope` zählen nicht.
- **Secret-Formate:** ARK-Regeln der Secret-Familien (`provider_secret`, `generic_credential`,
  `key_material`); eine Regel = ein Format. Daneben die Zahl der Entitäten mit mindestens einer
  solchen Regel.
- **Offline-Strukturprüfungen:** Secret-Regeln mit Validator-Stärke `checksum` (CRC32,
  Base58Check, Bech32, BIP39) oder `structure` (JWT-Header, DER/PEM, JSON/INI-Struktur).
- **Klassen ohne Secret-Scanner-Pendant:** Entitäten der Familien `content_class` und
  `document_class` mit ARK-Regel und ohne gitleaks-, TruffleHog- oder detect-secrets-Eintrag
  (Google Cloud DLP ist kein Secret-Scanner und zählt nicht als Pendant).

| M3 count | ARK | target | verdict |
|---|---:|---:|---|
| gitleaks default rules mapped | 91/222 (41.0 %) | >= 90 % | MISSED |
| secret formats (rules / entities) | 139 / 111 | >= 150 | MISSED |
| offline structure checks | 29 (checksum 10, structure 19) | >= 30 | MISSED |
| content/document classes without a secret-scanner counterpart | 16 | >= 20 | MISSED |

M3 MISSED (0/4 counts reach their target). Von den 131 nicht gemappten gitleaks-Regeln gehören
die meisten zu `baseline_only`-Entitäten der zurückgestellten Provider-Pakete (P05–P12, T26);
11 Entitäten sind bewusst `out_of_scope` (Begründung je Eintrag in der Entity-Map).

## Coverage-Matrix

Entitäten je Familie (ohne `out_of_scope`), die das jeweilige Tool in der Entity-Map abdeckt
(`python3 scripts/l1_dlp/milestones.py matrix`; statisch, nicht gemessen):

| Family | Entities | ARK | gitleaks | TruffleHog | detect-secrets | Google DLP |
|---|---:|---:|---:|---:|---:|---:|
| business_identifier | 10 | 10 | 0 | 0 | 0 | 0 |
| content_class | 5 | 5 | 0 | 0 | 0 | 3 |
| document_class | 11 | 11 | 0 | 0 | 0 | 3 |
| generic_credential | 20 | 15 | 6 | 3 | 4 | 5 |
| key_material | 17 | 15 | 3 | 1 | 1 | 1 |
| provider_secret | 149 | 81 | 112 | 84 | 22 | 10 |
| **all** | 212 | 137 | 121 | 88 | 27 | 22 |

Microsoft Purview steht nicht in der Entity-Map; seine Sensitive Information Types sind nur
qualitativ eingeordnet (öffentliche SIT-Referenz, nicht gegen einen Tenant geprüft): Credential-SITs
vor allem für Azure- und Microsoft-Dienste plus wenige generische (allgemeines Passwort,
HTTP-Authorization-Header, Client-Secret/API-Key, X.509-Private-Key, symmetrischer Schlüssel),
Dokumentklassen über trainierbare Klassifikatoren (u. a. Quellcode, HR, Recht, Finanzen,
Verträge). Google Cloud DLP und Purview sind Cloud-Dienste; ein Messlauf würde Daten von der VPS
schicken und braucht eine Entscheidung (README, Baselines).

## Reproduktion

```bash
# Dev-Zeile und Gesamt-/Gruppentabellen: das Gate ohne Holdout (Head = Base baut einmal)
~/ark-dlp/baselines-venv/bin/python scripts/l1_dlp/scoreboard.py gate --head . --base-sha <main> \
    --dev $ARK_L1_DEV_DATA --cache /tmp/dlp-final
# M3 und Coverage-Matrix
python3 scripts/l1_dlp/milestones.py count
python3 scripts/l1_dlp/milestones.py matrix
# M4 (VPS, ruhige Maschine)
.venv/bin/python scripts/l1_dlp/latency.py bench --dev $ARK_L1_DEV_DATA --tools ark,gitleaks --rounds 3 --invocations 4
```
