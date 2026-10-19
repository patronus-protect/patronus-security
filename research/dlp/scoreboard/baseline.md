# DLP-Baseline-Bericht (E14): ARK vs. gitleaks / TruffleHog / detect-secrets

Stand: 2026-10-19. Gemessen auf Detektor-Stand `bbb5448` (Base von E14; E14 ändert keinen Detektor-
code). Alle Zahlen stammen aus dem **Dev-Split** (`$ARK_L1_DEV_DATA`, Manifest-SHA-256
`45f047dc6cc8…`). Der Holdout ist für den Agenten nicht lesbar; das Abschlussurteil auf dem Holdout
kommt mit H06. Lücken stehen am Ende als TRIAGE-Kandidaten; der Backlog wird erst im nächsten
`TRIAGE`-Lauf ergänzt.

## Datenlage und Reproduktion

| Komponente | Umfang | bewertet |
|---|---|---|
| `synthetic/carriers.jsonl` | 8 769 Zeilen: 1 757 Positive (1 757 Wert-Spans, davon 320 in Opt-in-Gruppen), 7 012 Hard Negatives (je ≈ 1 750 `placeholder`, `env_ref`, `doc_example`, `test_key`), DE + EN | Wert-Spans exakt + Overlap, HN-FP, Content-Klassen je Dokument |
| `benign_code/` | 3 624 Dateien, 37,8 MB aus 8 Repos (Code, Lockfiles, minified JS, SVG, base64, Git-Logs) | FP/MB |
| `benign_docs/` | 253 Dokumente, 7,5 MB DE/EN (Wikipedia, Gesetze, 18F, WMF) | FP/MB, markierte Dokumente je Opt-in-Klasse |
| `external/` | 227 gitleaks-Go-Dateien, 10 SchemaPile-SQL-Dateien (250 Statements) | Dokument-F1 Content, SQL-Spans |

Tools: gitleaks 8.30.1, TruffleHog 3.97.9 (`--no-verification`), detect-secrets 1.5.0 (Pins aus
`run_baselines.py versions`), ARK 0.1.10 im Default-Profil (Secret-Gruppen) und im
`extended`-Profil (alle Opt-in-Regeln laut Entity-Map). Ablauf:

```bash
PY=~/ark-dlp/baselines-venv/bin/python
for t in gitleaks trufflehog detect-secrets; do for c in synthetic benign_code benign_docs; do
  $PY scripts/l1_dlp/run_baselines.py run --tool $t --input IN/$c.jsonl --output PRED/$t.$c.jsonl; done; done
for c in synthetic benign_code benign_docs; do
  .venv/bin/python scripts/l1_dlp/run_ark.py --input IN/$c.jsonl --output PRED/ark.$c.jsonl; done
for c in synthetic benign_docs external; do   # RULES = --enable-rule je Opt-in-Regel der Entity-Map
  .venv/bin/python scripts/l1_dlp/run_ark.py --input IN/$c.jsonl --output PRED/ark.extended.$c.jsonl $RULES; done
$PY scripts/l1_dlp/baseline_report.py --dev $ARK_L1_DEV_DATA --predictions PRED --output-dir REPORTS
.venv/bin/python scripts/l1_dlp/latency.py bench --dev $ARK_L1_DEV_DATA \
    --detect-secrets-python $PY --output latency.json
```

`IN/<component>.jsonl` sind die aneinandergehängten JSONL-Dateien einer Komponente. Die ARK-Werte
stimmen mit dem Gate-Scoreboard überein (TRIAGE 2026-W43: exakt F1 35,0, P 23,2, R 71,4).
detect-secrets meldete eine Datei mit Plugin-Ausnahme (YAML-Datum, `errors` in der Meta, T05).

## Kurzfassung gegen die Meilensteine (Dev)

| Meilenstein | Stand | Urteil |
|---|---|---|
| M1 Provider-Parität | Recall ARK ≥ max(gitleaks, TruffleHog) für 21 von 22 gemeinsamen Entitäten mit Gold (Provider meist 100 %); Ausnahme `credential.secret_assignment` 37,5 gegen gitleaks 60,0 (siehe M2). FP/MB auf Benign-Code **10,17** gegen gitleaks **0,21** (TruffleHog 1,43, detect-secrets 36,28) | Recall erfüllt, FP/MB verfehlt (Faktor 48) |
| M2 Generische Secrets | CREDENTIAL F1 exakt ARK **22,0** gegen gitleaks 23,7, detect-secrets 11,9, TruffleHog 11,4. Ziel ≥ 43,7 (beste Baseline + 20 pp) | verfehlt; ARK liegt sogar unter gitleaks |
| M3 Breite | 26 von 206 gitleaks-Default-Regeln (ohne `out_of_scope`) haben eine ARK-Regel (12,6 %); 180 haben eine Backlog-Aufgabe. 37 Secret-Regeln, 0 mit Offline-Strukturprüfung. Content-/Dokumentklassen ohne Baseline-Pendant: 5 Content-Klassen + 10 Business-IDs (davon 3 laut F15 künftig PII) | verfehlt (Ziel 90 % / ≥ 150 / ≥ 30 / ≥ 20) |
| M4 Latenz | 100 KiB p95 **20,3 ms** (Budget 10 ms); Durchsatz 10-MiB-Repo 6,47 MiB/s Scan bzw. 4,90 MiB/s Ende-zu-Ende gegen gitleaks 5,40 / 4,07 | Durchsatz erfüllt, p95 verfehlt (Faktor 2) |
| Immer | FP/MB Benign-Code ≤ beste Baseline: verfehlt (s. M1). Benign-Dokumente: ARK 4 FP (0,53/MB), alle Baselines 0 | verfehlt |

Ungetypt über alle Carrier liegt ARK mit F1 35,0 hinter gitleaks (51,1), TruffleHog (46,2) und
detect-secrets (40,9), hat aber den höchsten Recall (71,4 gegen 53,4 / 36,4 / 51,6).
Präzision ist auf den Carriern vor allem eine Frage der Hard Negatives: auf 1 757 Gold-Spans kommen
7 012 HN-Zeilen. ARK meldet auf 2 809 davon 4 011 Spans; 3 734 davon liegen auf `doc_example`/
`test_key`-Zeilen (T06). Ohne HN-FP läge die exakte Präzision von ARK bei 1 255 / 1 399 = 89,7 %. Der ungetypte Recall
aller Tools zählt auch die 320 Opt-in-Gold-Spans mit, die im Default-Profil niemand meldet.

## Messwerte (Dev, `baseline_report.py`)

Legende: P/R/F1 in Prozent auf exakten Wert-Spans, ungetypt (`overall`) bzw. je Gruppe; Overlap =
irgendein Schnitt. Baseline-Spans tragen die Gruppen ihrer Regel aus `entity_map.yaml`. „–“ heißt:
das Tool meldet für diese Entität nichts (keine Regel oder Mapping auf eine andere Entität, z. B.
detect-secrets `KeywordDetector`). TruffleHog meldet AWS nur als Schlüsselpaar, deshalb „–“ bei
`cloud.aws.access_key_id` in Einzelwert-Carriern.

### Gesamt (Default-Profil, ungetypt)

| Tool | Gold | Pred | P | R | F1 exact | F1 overlap | HN-FP (Spans / Zeilen) | Code-FP | Code-FP/MB | Doku-FP | Doku-FP/MB |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| ark | 1757 | 5410 | 23.2 | 71.4 | 35.0 | 38.1 | 4011 / 2809 | 384 | 10.1699 | 4 | 0.5309 |
| gitleaks | 1757 | 1912 | 49.1 | 53.4 | 51.1 | 51.1 | 974 / 974 | 8 | 0.2119 | 0 | 0.0 |
| trufflehog | 1757 | 1013 | 63.2 | 36.4 | 46.2 | 46.3 | 326 / 323 | 54 | 1.4301 | 0 | 0.0 |
| detect-secrets | 1757 | 2676 | 33.9 | 51.6 | 40.9 | 42.3 | 1731 / 1655 | 1370 | 36.2832 | 0 | 0.0 |

### F1 je Secret-Gruppe

| Gruppe | Gold | ark F1 exact / overlap | gitleaks F1 exact / overlap | trufflehog F1 exact / overlap | detect-secrets F1 exact / overlap |
| --- | ---: | ---: | ---: | ---: | ---: |
| API_KEY | 320 | 50.0 / 50.0 | 46.5 / 46.5 | 99.5 / 99.8 | 12.6 / 23.3 |
| CLOUD_KEY | 200 | 48.9 / 48.9 | 49.1 / 49.1 | 32.6 / 32.6 | 32.9 / 32.9 |
| CREDENTIAL | 320 | 22.0 / 24.1 | 23.7 / 23.7 | 11.4 / 11.4 | 11.9 / 12.4 |
| CRYPTO_KEY | 80 | 12.3 / 12.3 | 0.0 / 0.0 | 0.0 / 0.0 | 0.0 / 0.0 |
| PASSWORD_HASH | 40 | 44.6 / 44.6 | 0.0 / 0.0 | 0.0 / 0.0 | 0.0 / 0.0 |
| PAYMENT_KEY | 80 | 50.0 / 50.0 | 39.2 / 39.2 | 28.0 / 28.0 | 21.8 / 21.8 |
| PRIVATE_KEY | 37 | 56.1 / 56.1 | 46.8 / 46.8 | 45.8 / 45.8 | 56.1 / 56.1 |
| SECRET_TOKEN | 360 | 46.9 / 46.9 | 47.6 / 47.6 | 71.7 / 71.7 | 45.5 / 45.5 |

### Hard Negatives je Variante

| Variante | Zeilen | ark FP / Zeilen | gitleaks FP / Zeilen | trufflehog FP / Zeilen | detect-secrets FP / Zeilen |
| --- | ---: | ---: | ---: | ---: | ---: |
| doc_example | 1749 | 1867 / 1267 | 567 / 567 | 101 / 100 | 756 / 718 |
| env_ref | 1757 | 126 / 124 | 0 / 0 | 47 / 47 | 0 / 0 |
| placeholder | 1757 | 151 / 151 | 8 / 8 | 77 / 76 | 260 / 260 |
| test_key | 1749 | 1867 / 1267 | 399 / 399 | 101 / 100 | 715 / 677 |

### Recall je Secret-Entität

| Entität | Scope | Gold | ark R exact (overlap) | gitleaks R exact (overlap) | trufflehog R exact (overlap) | detect-secrets R exact (overlap) |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| cloud.aws.access_key_id | shared | 40 | 100.0 (100.0) | 100.0 (100.0) | – | 100.0 (100.0) |
| cloud.aws.secret_access_key | shared | 40 | 60.0 (60.0) | – | – | 62.5 (62.5) |
| cloud.gcp.api_key | shared | 40 | 100.0 (100.0) | 95.0 (95.0) | – | – |
| cloud.gcp.oauth_access_token | shared | 40 | 100.0 (100.0) | – | 97.5 (97.5) | – |
| cloud.gcp.oauth_client_secret | shared | 40 | 100.0 (100.0) | – | – | – |
| comm.discord.bot_token | shared | 40 | 100.0 (100.0) | – | – | 100.0 (100.0) |
| comm.slack.token | shared | 40 | 100.0 (100.0) | 100.0 (100.0) | 100.0 (100.0) | 100.0 (100.0) |
| credential.csrf_token | shared | 40 | 25.0 (25.0) | – | – | – |
| credential.http_basic_auth | shared | 40 | 7.5 (7.5) | – | – | – |
| credential.http_bearer | shared | 40 | 7.5 (7.5) | 2.5 (2.5) | – | – |
| credential.password_assignment | shared | 40 | 12.5 (12.5) | – | – | 52.5 (52.5) |
| credential.password_hash | shared | 40 | 67.5 (67.5) | – | – | – |
| credential.secret_assignment | shared | 80 | 37.5 (50.0) | 60.0 (60.0) | – | 60.0 (60.0) |
| credential.session_cookie | shared | 40 | 7.5 (7.5) | – | – | – |
| credential.signed_url_signature | shared | 40 | 95.0 (95.0) | – | – | – |
| credential.url_query_secret | ark_only | 40 | 95.0 (95.0) | – | – | – |
| credential.url_userinfo | shared | 40 | 100.0 (100.0) | – | 100.0 (100.0) | 100.0 (100.0) |
| crypto.bitcoin.wif | ark_only | 40 | 100.0 (100.0) | – | – | – |
| crypto.ethereum.private_key | ark_only | 40 | 100.0 (100.0) | – | – | – |
| key.pem_private_key | shared | 37 | 100.0 (100.0) | 78.4 (78.4) | 29.7 (29.7) | 100.0 (100.0) |
| llm.anthropic.api_key | shared | 40 | 100.0 (100.0) | 95.0 (95.0) | 100.0 (100.0) | – |
| llm.groq.api_key | shared | 40 | 100.0 (100.0) | – | 100.0 (100.0) | – |
| llm.huggingface.token | shared | 40 | 100.0 (100.0) | 95.0 (95.0) | 100.0 (100.0) | – |
| llm.openai.api_key | shared | 120 | 100.0 (100.0) | 94.2 (94.2) | 98.3 (99.2) | 33.3 (61.7) |
| llm.replicate.api_token | shared | 40 | 100.0 (100.0) | – | 100.0 (100.0) | – |
| llm.xai.api_key | shared | 40 | 100.0 (100.0) | – | 100.0 (100.0) | – |
| payment.stripe.secret_key | shared | 40 | 100.0 (100.0) | 95.0 (95.0) | 32.5 (32.5) | 32.5 (32.5) |
| payment.stripe.webhook_secret | ark_only | 40 | 100.0 (100.0) | – | – | – |
| registry.npm.access_token | shared | 40 | 100.0 (100.0) | 95.0 (95.0) | 100.0 (100.0) | – |
| token.jwt | shared | 40 | 100.0 (100.0) | 100.0 (100.0) | 47.5 (47.5) | 100.0 (100.0) |
| vcs.github.fine_grained_pat | shared | 40 | 100.0 (100.0) | 100.0 (100.0) | 100.0 (100.0) | 0.0 (0.0) |
| vcs.github.token | shared | 40 | 100.0 (100.0) | 100.0 (100.0) | 100.0 (100.0) | 100.0 (100.0) |
| vcs.gitlab.pat | shared | 40 | 100.0 (100.0) | 100.0 (100.0) | 100.0 (100.0) | 100.0 (100.0) |

### Opt-in-Gruppen (nur ARK, Profil extended)

| Gruppe | Gold | ark F1 exact / overlap |
| --- | ---: | ---: |
| dlp.de.commercial_register_number | 32 | 50.0 / 50.0 |
| dlp.de.facility_number_bsnr | 32 | 28.6 / 28.6 |
| dlp.de.vat_id | 32 | 18.2 / 18.2 |
| dlp.organization_id | 32 | 18.2 / 18.2 |
| dlp.project_id | 32 | 18.2 / 18.2 |
| dlp.record.case_id | 32 | 18.2 / 18.2 |
| dlp.record.claim_id | 32 | 18.2 / 18.2 |
| dlp.record.contract_id | 32 | 18.2 / 18.2 |
| dlp.record.invoice_id | 32 | 18.2 / 18.2 |
| dlp.record.order_id | 32 | 18.2 / 18.2 |


### Benign-Code nach Dateiart (FP/MB)

| Art | MB | ARK | gitleaks | TruffleHog | detect-secrets |
|---|---:|---:|---:|---:|---:|
| code | 24,6 | 11,38 | 0,33 | 1,42 | 55,59 |
| lockfile | 3,4 | 25,01 | 0 | 0 | 0 |
| minified_js | 3,1 | 6,21 | 0 | 0 | 0 |
| git_log | 6,1 | 0,16 | 0 | 3,13 | 0,16 |
| base64 | 0,5 | 0 | 0 | 0 | 1,94 |
| svg | 0,1 | 0 | 0 | 0 | 0 |

### Attribution (exakt gefundene Gold-Werte mit richtiger Entität)

ARK 1 250 / 1 255 (99,6 %; richtige `rule_id` 1 242). gitleaks 621 / 938 (66,2 %), TruffleHog
640 / 640 (100 %), detect-secrets 464 / 906 (51,2 %). Bei den Baselines fehlen Zuordnungen vor
allem dort, wo eine generische Regel (`generic-api-key`, `KeywordDetector`,
`Base64HighEntropyString`) einen Provider-Wert meldet.

### Content-Klassen (ARK `extended`, Opt-in)

| Klasse | Korpus | Gold | Pred | P | R | F1 |
|---|---|---:|---:|---:|---:|---:|
| `content.source_code` | Carrier (Dokument) | 2 300 | 2 651 | 52,1 | 60,0 | 55,7 |
| `content.system_log` | Carrier (Dokument) | 456 | 0 | – | 0 | 0 |
| `content.source_code` | gitleaks Go (extern) | 214 | 216 | 98,6 | 99,5 | 99,1 |
| `content.sql` | SchemaPile + gitleaks Go (Dokument) | 10 | 12 | 83,3 | 100 | 90,9 |
| `content.sql` | SchemaPile (Statement-Spans exakt) | 250 | 198 | 100 | 79,2 | 88,4 |

Markierte Benign-Dokumente im `extended`-Profil: `content.source_code` 22 (alle 18F-Leitfäden mit
Markdown-Codeblöcken), `content.sql` 13 (9 Wikipedia/WMF, 4 18F), `content.business_metric` 1
(dewiki). Keine Baseline hat Content-Klassen.

## Latenz und Durchsatz (`latency.py bench`, eine CPU, Haswell-VPS)

| Tool | short p95 | 4 KiB p95 | 100 KiB p95 | 10-MiB-Repo Scan MiB/s | Ende-zu-Ende MiB/s | Start ms |
|---|---:|---:|---:|---:|---:|---:|
| ARK (im Prozess) | 0,31 ms | 0,88 ms | **20,33 ms** | 6,47 | 4,90 | 494 |
| gitleaks (je Aufruf) | 643 ms | 687 ms | 832 ms | 5,40 | 4,07 | 607 |
| TruffleHog (je Aufruf) | 2 431 ms | 2 681 ms | 2 544 ms | 7,04 | 2,64 | 2 364 |
| detect-secrets (je Aufruf) | 315 ms | 326 ms | 989 ms | 0,36 | 0,36 | 274 |

ARK misst im Prozess, die Baselines inklusive Prozessstart. Vergleichbar sind deshalb nur die
Durchsatzspalten. ARK skaliert linear (4 KiB → 100 KiB: 0,66 → 15,2 ms p50, ≈ 6,3 MiB/s); das
100-KiB-Budget aus H03 verlangt etwa das Doppelte. TruffleHog hat den höchsten reinen
Scan-Durchsatz, verliert ihn aber durch 2,4 s Startzeit.

## Statische Coverage-Matrix

### Secret-Baselines (aus `entity_map.yaml`)

| Inventar | gesamt | `shared` (ARK-Regel vorhanden) | `baseline_only` (Backlog-Aufgabe) | `out_of_scope` |
|---|---:|---:|---:|---:|
| gitleaks 8.30.1 Default-Regeln | 222 | 26 | 180 | 16 (öffentliche Client-IDs, Publishable/Test-Keys) |
| detect-secrets 1.5.0 Plugins | 27 | alle Plugins gemappt; Provider-Plugins teils `baseline_only` (PyPI, Telegram, Twilio, SendGrid, Mailchimp, Square, Cloudant) | | |
| TruffleHog 3.97.9 | nur ARK-nahe `DetectorType`-Namen (Binary UPX-gepackt, Inventar offline nicht lesbar) | | | |
| ARK `dlp_*` | 64 Regeln | 42 | 17 `ark_only` | 5 (Aktions-DLP/MCP) |

Die 180 `baseline_only`-gitleaks-Regeln verteilen sich auf P01–P12, F04/F09/F13 und G03–G05. M3
(≥ 90 % gemappt) verlangt, dass davon mindestens 160 eine ARK-Regel bekommen.

### Google Cloud DLP (Credential-Infotypes und `DOCUMENT_TYPE/*`, statisch)

| Infotype | ARK heute | Aufgabe |
|---|---|---|
| `AUTH_TOKEN` | `dlp_bearer_token`, `dlp_google_oauth_token` | F13, T11 |
| `AWS_CREDENTIALS` | `dlp_aws_access_key`, `dlp_aws_secret_key` | F05 |
| `AZURE_AUTH_TOKEN` | – | P03 |
| `BASIC_AUTH_HEADER` | `dlp_basic_auth` | F13, T11 |
| `ENCRYPTION_KEY` | – | C08 |
| `GCP_API_KEY` | `dlp_google_api_key` | T02 |
| `GCP_CREDENTIALS` (Service-Account-JSON) | – | P03 |
| `HTTP_COOKIE` | `dlp_session_cookie` | F13, T11 |
| `JSON_WEB_TOKEN` | `dlp_jwt_token` | F07 |
| `OAUTH_CLIENT_SECRET` | `dlp_gcp_client_secret` | T02 |
| `PASSWORD` | `dlp_password_assignment` | F11, G06 |
| `STORAGE_SIGNED_URL`, `STORAGE_SIGNED_POLICY_DOCUMENT` | `dlp_signed_url_signature` | F12 |
| `WEAK_PASSWORD_HASH` | `dlp_password_hash` | F14, G10 |
| `XSRF_TOKEN` | `dlp_csrf_token` | F13 |
| `SSL_CERTIFICATE` | – (öffentlich) | `out_of_scope` |
| `DOCUMENT_TYPE/R&D/SOURCE_CODE` | `content.source_code` | M18 |
| `DOCUMENT_TYPE/R&D/DATABASE_BACKUP` | `content.database_dump` | M20 |
| `DOCUMENT_TYPE/R&D/SYSTEM_LOG` | `content.system_log` | T13, M19 |
| `DOCUMENT_TYPE/R&D/PATENT` | – | M17 |
| `DOCUMENT_TYPE/HR/RESUME` | – | M06 |
| `DOCUMENT_TYPE/LEGAL/BRIEF`, `…/COURT_ORDER`, `…/PLEADING` | – | M05 |
| `DOCUMENT_TYPE/LEGAL/LAW`, `…/BLANK_FORM`, `DOCUMENT_TYPE/FINANCE/REGULATORY`, `…/SEC_FILING` | – (öffentlich) | `out_of_scope` |

Google DLP: 12 der 16 Credential-Infotypes haben ein ARK-Gegenstück. Offen sind Azure-Token und
GCP-Service-Account-Schlüssel (P03) sowie Schlüssel ohne Präfix (C08); `SSL_CERTIFICATE` bleibt
bewusst draußen. Von den 12 Dokumenttypen deckt
ARK 3 ab (alle opt-in), 5 sind geplant, 4 sind öffentlich und bleiben draußen.

### Microsoft Purview (Sensitive Information Types und Trainable Classifiers, statisch)

Quelle: die öffentliche Purview-Doku („Sensitive information type entity definitions“, Kategorie
Credentials, und die vortrainierten Trainable Classifiers). Die Namen sind gruppiert und in diesem
Lauf nicht online gegengeprüft. Vor H06 gegen die aktuelle Liste abgleichen und in
`entity_map.yaml` als eigene Spalte `purview` aufnehmen (siehe Kandidat TK-8).

| Purview-SIT (gruppiert) | ARK heute | Aufgabe |
|---|---|---|
| General password, User login credentials | `dlp_password_assignment`, `dlp_generic_credential_assignment` | F11, G02, G06 |
| Client secret / API key | `dlp_generic_credential_assignment`, `dlp_env_var_secret` | G02, G12 |
| Http authorization header | `dlp_bearer_token`, `dlp_basic_auth` | F13, T11 |
| X.509 certificate private key | `dlp_private_key_block` | F08 |
| General symmetric key | – | C08 |
| ASP.NET machine key (`validationKey`/`decryptionKey`) | – | keine (Kandidat TK-7) |
| Amazon S3 client secret access key | `dlp_aws_secret_key` | F05 |
| Google API key | `dlp_google_api_key` | T02 |
| GitHub personal access token | `dlp_github_token`, `dlp_github_pat` | F03 |
| Slack access token | `dlp_slack_token` | F09 |
| SQL Server / Azure SQL / Azure IaaS DB connection string | nur URL-Userinfo (`dlp_url_userinfo_password`) | G01 (ADO.NET `Password=`) |
| Azure Storage account key, Azure SAS, Microsoft Entra client secret | – | P03 |
| Azure DevOps PAT / app secret | – | P06 |
| Azure Databricks PAT | – | P12 |
| Azure Service Bus / Event Hub / IoT / Event Grid / SignalR / Cosmos DB / Redis / Batch / Container Registry / Function / Cognitive / Search / Maps / Bot / Logic App / Publish Settings / App-Service-Deployment-Kennwort | – | nur Teile in P03/G01 (Kandidat TK-7) |
| Bing Maps key | – | keine (P10 nur bei belegter Quelle) |

| Purview Trainable Classifier (gruppiert) | ARK heute | Aufgabe |
|---|---|---|
| Source code | `content.source_code` | M18 |
| Resume, Employee disciplinary action, HR | – | M06 |
| Legal affairs, Agreements | – | M05, M22 |
| Finance, Sales and revenue, Tax, Procurement | `content.business_metric` (teilweise) | M07, M10, M21 |
| Healthcare / Medical | – (Einzelwerte PII) | M12 |
| IP / Software product development files | – | M17 |
| Network design files | – | M14, M15 |
| Customer complaints, Threat, Harassment, Discrimination, Profanity | – | außerhalb DLP-L1 (Kommunikations-Compliance) |

Beide Cloud-Dienste haben keine Klassen für Einstufungsvermerke (VS-NfD, TLP), Ad-hoc-/
Insiderinformation, M&A-Projektnamen, Exportkontrolle und Krypto-Schlüsselmaterial (Seed-Phrasen,
xprv, Keystores). Das sind die M3-Hebel aus M02–M04, M07–M08, M16 und C01–C06. Ein Messlauf gegen
Google DLP oder Purview bleibt `needs_decision` (Kosten, Daten verlassen die VPS).

## Fehler-Buckets ARK (Default-Profil)

Die generierten Tabellen unten zählen je Regel. Zusammengefasst und den Aufgaben zugeordnet:

| # | Bucket | Belege (Dev) | Aufgabe |
|---|---|---|---|
| 1 | Beispiel-/Testwerte: jede Provider-Regel feuert auf allen 80 `doc_example`/`test_key`-Zeilen ihres Providers | 3 734 der 4 011 HN-FP | T06 |
| 2 | `dlp_btc_wif` ohne Base58Check und ohne Token-Grenze: trifft Teilstrings anderer Tokens und Lockfile-Digests | 1 054 HN-FP, 109 Benign-Code-FP (Lockfiles 25 FP/MB) | T01, F02 |
| 3 | Platzhalter und Variablenreferenzen in wertfangenden Regeln | 277 FP auf `placeholder`/`env_ref` (`env_var_secret` 120, `generic_credential_assignment` 102, `credential_in_url` 17 …) | T07 |
| 4 | Code-Ausdrücke als Wert in generischen Zuweisungen | 199 Benign-Code-FP (`generic_credential_assignment` 106, `password_assignment` 93) | T03 |
| 5 | Schlüsselformen: zusammengesetzte (`db_password`, `service_secret`), camelCase, typisierte (`: &str`, `: string`, `const string`), XML-`key`/`value`-Attribute, CI-`env:`, Log-`key=value` | 73 verfehlte Werte der sechs schlüsselgebundenen Regeln in Struktur-Carriern (ohne Prosa/Jupyter); gitleaks findet hier 60 % von `credential.secret_assignment`, detect-secrets 52,5 % von `credential.password_assignment` (ARK 37,5 / 12,5) | T09 (M2-kritisch) |
| 6 | Bearer/Basic/Session-Cookie außerhalb einer HTTP-Headerzeile | je 37 von 40 verfehlt | T11 |
| 7 | Span mit Anführungszeichen bzw. falscher Regel: `dlp_env_var_secret` greift `export`/`ENV`-Zeilen und Konstanten (`DB_PASSWORD = "…"`) samt Quote | 20 Grenzfehler (Shell, Dockerfile, Python, Java, Ruby je 4) | T08, K08 |
| 8 | Prosa-Carrier (Chat, Ticket, Mail) und Jupyter | 72 verfehlte Werte (18 je Format); keine Baseline findet sie | G06, T09 (escaped Quotes) |
| 9 | `dlp_url_userinfo_password` auf Test-URLs | 23 Benign-Code-FP, 91 HN-FP | T10 |
| 10 | GitHub-Testtokens ohne CRC32 | 15 Benign-Code-FP (`github_token` 12, `github_pat` 3) | F03 |
| 11 | `dlp_password_hash` in Prosa/JSON | 13 verfehlt | F14 |
| 12 | `dlp_aws_secret_key` ohne Schlüssel-Kontext in Prosa/HTTP/properties | 16 verfehlt | F05, T09 |
| 13 | `content.system_log` | 0 von 456 Log-Carriern | T13 |
| 14 | `content.source_code` verfehlt TypeScript, C# und Jupyter | je 230 bzw. 460 Carrier-Dokumente | M18 (TypeScript ergänzen, Kandidat TK-6) |
| 15 | SchemaPile: mysqldump-Direktiven (`/*!40101 SET …*/`, `SET NAMES`, `-- Dumping`, `UNLOCK TABLES`, `USE`) | 42 von 52 verfehlten Statements | M20 |

Neu und ohne Aufgabe: siehe Kandidaten TK-1 bis TK-9.

## TRIAGE-Kandidaten

Lücken ohne passende Aufgabe. Der nächste `TRIAGE`-Lauf entscheidet, ob daraus `Txx`-Aufgaben
werden und wo sie hinkommen. E14 ändert den Backlog nicht.

| ID | Typ | Lücke (Dev-Beleg) | Vorschlag | Platz / deps |
|---|---|---|---|---|
| TK-1 | precision-fix (opt-in) | `dlp_sql_multiline_statement` hält Prosa, die mit „select …“/„update …“ beginnt, für SQL: 13 Benign-Dokumente markiert (9 Wikipedia/WMF, 4 18F) | SQL-Struktur verlangen (`FROM`/`SET`/`INTO`/`VALUES`/`WHERE` mit Bezeichnern, Statement-Ende `;` oder Zeilenende), Prosa-Gegenkontext; dazu `ALTER TABLE` (10 von 52 verfehlten SchemaPile-Statements) | vor M20; deps E12. Akzeptanz: `flagged:benign_docs:content.sql` ≤ 1, SchemaPile-Span-F1 nicht niedriger |
| TK-2 | precision-fix (opt-in) | `dlp_source_code_python_rust_assignment` markiert TOML-, `.env`- und HCL-Konfiguration als Quellcode: 1 271 von 2 651 vorhergesagten Carrier-Dokumenten (TOML 460, env 450, HCL 360), Dokument-P 52,1 | Reine `key = value`-Zeilen ohne weitere Code-Struktur nicht als Quellcode werten (Sektionsköpfe `[x]`, `.env`-Zeilen, HCL-Blöcke als Gegenkontext) | vor M18; deps E12. Akzeptanz: Carrier-Dokument-P ≥ 90 ohne Recall-Verlust, gitleaks-Go-F1 unverändert |
| TK-3 | eval-infra | Die HN-Varianten `doc_example` und `test_key` sind dieselben Carrier mit anderem Markerwort (`EXAMPLE…` bzw. `TEST…`). Realistische Test- und Beispielformen fehlen: `sk_test_`/`rk_test_`, Testnet-WIF/`tprv`, herstellerdokumentierte Beispielwerte. T06 lässt sich damit überanpassen, und die Präzision zählt dieselbe Lücke doppelt | Generator/E04 um echte Test-/Sandbox-Präfixe und dokumentierte Beispielwerte je Provider erweitern (getrennte Holdout-Familien); Scoreboard zusätzlich mit Präzision nur auf Positiv-Zeilen | vor T06; deps E04 |
| TK-4 | perf | 100 KiB p95 20,3 ms bei 10 ms Budget (M4/H03). Welche Regeln das kosten, ist unbekannt | `latency.py profile`: Zeit je Regel/Prefilter auf dem 100-KiB-Workload, Bericht im Gate-Cache; Grundlage für K07, bevor P01–P12 rund 150 Regeln hinzufügen | vor K07; deps E11 |
| TK-5 | decision | `dlp_sensitive_material` (Aktions-DLP, laut Entity-Map `out_of_scope`) zählt in den Default-FP: 2 Benign-Code-FP, 1 Benign-Dokument („read the credentials“) | Entscheiden, ob das Scoreboard Aktions-DLP-Produzenten aus FP/MB herausnimmt oder die Regel Gegenkontext bekommt | `needs_decision` |
| TK-6 | Scope von M18 | `content.source_code` verfehlt alle TypeScript- und C#-Carrier (je 230) und alle Jupyter-Carrier (460); TypeScript fehlt in der Sprachliste von M18 | TypeScript/TSX in den Titel von M18 aufnehmen | M18 ergänzen |
| TK-7 | new-entity | Purview-Parität Azure: Service-Bus-, Event-Hub- und IoT-Connection-Strings (`SharedAccessKey=`), Cosmos DB `AccountKey=`, Redis `password=`, ASP.NET `<machineKey validationKey/decryptionKey>`; P03/G01 decken nur Storage, SAS, Entra und ADO.NET ab | Kontextregeln mit Microsoft-Doku als Formatquelle | nach P03, G01 |
| TK-8 | eval-infra | Purview steht nur in diesem Bericht, nicht in `entity_map.yaml` | Spalte `purview` (SIT-Namen, Trainable Classifiers) und Inventar wie `google_dlp`, Test in `rust/tests/dlp_entity_map.rs` | vor H06 |
| TK-9 | precision-fix (opt-in) | `content.business_metric` markiert veröffentlichte Kennzahlen („Umsatz von … Mio. EUR“ in dewiki) | Gegenkontext „veröffentlicht/Geschäftsbericht/laut“ in F16 aufnehmen | F16 ergänzen |

Priorität aus Sicht der Meilensteine: M2 hängt fast vollständig an T09 (Schlüsselformen) und T11.
Beide stehen hinter F11/T03/T04 bzw. F13. gitleaks liegt bei CREDENTIAL heute vorn, detect-secrets
beim Passwort-Recall. M1 (FP/MB) hängt an T01/F02 (Lockfiles, `btc_wif`), T03 und T10. Auf den
Carriern trägt T06 den größten Präzisionsgewinn.

## Grenzen dieser Messung

- Nur Dev-Split. Die Carrier-Familien von Holdout und Dev sind getrennt, deshalb können sich
  Format-Buckets (z. B. Schlüsselformen) auf dem Holdout anders verteilen.
- Die Werte sind synthetisch und decken nur die Provider der heutigen ARK-Regeln ab. Für die
  180 `baseline_only`-gitleaks-Regeln gibt es noch kein Gold; dort liegt ARK-Recall bei 0, und
  diese Lücke steht in der Coverage-Matrix, nicht in den F1-Tabellen.
- Baseline-Spans sind auf den Wert normalisiert (`run_baselines.py`). Restliche Grenzdifferenzen
  zeigt die Overlap-Spalte; detect-secrets meldet bei OpenAI oft nur Teilspans (exakt 33,3, Overlap
  61,7).
- TruffleHog läuft ohne Verifikation (L1 ist offline).
- Die Latenz wurde auf einer CPU der VPS gemessen; ARK als lokaler Release-Build desselben Commits.

## Anhang: generierte Tabellen

**Hard-Negative-FP je Regel und Variante**

| Regel | Variante | FP |
| --- | --- | ---: |
| dlp_btc_wif | doc_example | 527 |
| dlp_btc_wif | test_key | 527 |
| dlp_env_var_secret | doc_example | 129 |
| dlp_env_var_secret | test_key | 129 |
| dlp_env_var_secret | placeholder | 72 |
| dlp_generic_credential_assignment | env_ref | 67 |
| dlp_env_var_secret | env_ref | 48 |
| dlp_anthropic_key | doc_example | 40 |
| dlp_anthropic_key | test_key | 40 |
| dlp_aws_access_key | doc_example | 40 |
| dlp_aws_access_key | test_key | 40 |
| dlp_discord_token | doc_example | 40 |
| dlp_discord_token | test_key | 40 |
| dlp_eth_private_key | doc_example | 40 |
| dlp_eth_private_key | test_key | 40 |

**Verfehlte Gold-Spans je Regel (kein Overlap)**

| Regel | Anzahl |
| --- | ---: |
| dlp_basic_auth | 37 |
| dlp_bearer_token | 37 |
| dlp_session_cookie | 37 |
| dlp_env_var_secret | 27 |
| dlp_password_assignment | 27 |
| dlp_csrf_token | 25 |
| dlp_aws_secret_key | 16 |
| dlp_generic_credential_assignment | 13 |
| dlp_password_hash | 13 |
| dlp_signed_url_signature | 2 |

**Verfehlte Gold-Spans je Carrier-Format**

| Format | Anzahl |
| --- | ---: |
| code | 45 |
| chat | 18 |
| jupyter | 18 |
| mail | 18 |
| ticket | 18 |
| xml | 17 |
| json | 16 |
| ci_yaml | 12 |
| hcl | 12 |
| toml | 12 |
| yaml | 12 |
| log | 10 |
| properties | 8 |
| dockerfile | 6 |
| env | 6 |

**Grenzfehler je Regel (Overlap, aber nicht exakt)**

| Regel | Anzahl |
| --- | ---: |
| dlp_csrf_token | 5 |
| dlp_env_var_secret | 5 |
| dlp_generic_credential_assignment | 5 |
| dlp_password_assignment | 5 |

**Zusätzliche Spans auf Positiv-Zeilen je Regel**

| Regel | Anzahl |
| --- | ---: |

**Benign-Code-FP je Regel**

| Regel | FP | FP/MB |
| --- | ---: | ---: |
| dlp_btc_wif | 109 | 2.8868 |
| dlp_generic_credential_assignment | 106 | 2.8073 |
| dlp_password_assignment | 93 | 2.463 |
| dlp_env_var_secret | 30 | 0.7945 |
| dlp_url_userinfo_password | 23 | 0.6091 |
| dlp_github_token | 12 | 0.3178 |
| dlp_bearer_token | 3 | 0.0795 |
| dlp_github_pat | 3 | 0.0795 |
| dlp_jwt_token | 2 | 0.053 |
| dlp_sensitive_material | 2 | 0.053 |
| dlp_basic_auth | 1 | 0.0265 |
