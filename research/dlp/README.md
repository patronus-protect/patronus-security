# L1-DLP: gitleaks, TruffleHog und detect-secrets übertreffen

Stand: 2026-10-11. Aufgabenliste: [`backlog.yaml`](backlog.yaml). Ausführung über denselben
VPS-Runner wie [`../l1-pii/`](../l1-pii/README.md) (systemd-Timer → sandboxed Claude Code → Gate →
Stacked PR, erst bei grüner GitHub-CI), Branch-Präfix `dlp/`. Agent-Prompt: [`AGENT_PROMPT.md`](AGENT_PROMPT.md).

## Ausgangslage

- `rust/src/detectors/dlp/rules/` (seit K01 nach Familien getrennt: `providers`, `crypto`,
  `credentials`, `hashes`, `identifiers`, `content`; Registry-Reihenfolge in `rules/mod.rs`):
  59 Regex-Regeln, davon ca. 25 providergebundene Secret-Regeln (LLM, AWS/GCP, GitHub/GitLab/npm,
  Stripe, Slack, Discord, ETH/BTC, PEM). Dazu kommen generische Zuweisungen
  (Passwort, Token, Bearer/Basic, Cookie, URL-Userinfo), Business-/Record-IDs und Content-Klassen
  (Quellcode, SQL, Dump, Log/Stacktrace, Business-Metrik). Jeder Treffer hat `score: 1.0`.
  Seit K04 gilt das nur im Default-Modus `strict`: Die opt-in Modi `balanced`/`recall`
  (Gate `dlp_mode`) bewerten jeden Treffer mit dem PII-Score-Modell (Basis je Regel +
  Validator-Stärke + Feld-/Nähe-Kontext, Gegenkontext Hash/Prüfsumme/ID aus `dlp.json`); das
  Scoreboard meldet daraus P/R-Kurven.
  Seit K02 trägt jede Regel Metadaten v2 (`RuleMeta`: Provider, Validator-Stärke, Prefilter-Keywords,
  Entropie-Untergrenze, Formatquelle, live/test); `matched_rules` meldet sie, die Quellen stehen in
  [`rule_sources.yaml`](rule_sources.yaml).
  Seit K07 läuft vor den Regexen ein Prefilter: ein Aho-Corasick-Durchlauf über die Keywords aller
  Regeln, Wertläufe für die zwei Regeln ohne Literal (Discord, WIF) und Suche nur an den
  Keyword-Treffern, wo der Regex-Baum den Abstand begrenzt. Jedes Gate ist aus der Regex bewiesen;
  eine Regel ohne Keyword lässt `rust/tests/dlp_rule_prefilter.rs` scheitern.
  Seit K08 überlappen sich Secret-Spans nicht mehr: Bei mehreren Treffern auf einem Wert bleibt
  einer, nach Stufe Provider/Schlüssel > Token > Passwort-Hash > strukturelles Credential >
  generische Zuweisung. Ein Span, der nur Anführungszeichen ergänzt, weicht dem engeren Span
  derselben Stufe, ein Teilstring-Artefakt (WIF-förmiger Lauf in einem Stripe-Key oder JWT)
  dem Wert, in dem er liegt. Unterdrückte Treffer nennen in `matched_rules` den Gewinner
  (`suppressed_by`). Scannen DLP und PII denselben Text, gehört der Bereich eines Secret-Spans
  DLP; überlappende PII-Spans (URL-Passwort als E-Mail-Lokalteil) entfallen.
  Seit T01 haben die Präfix-Regeln (Provider-Token, ETH/WIF, JWT) eine Token-Grenze
  (`RuleMeta::boundary`): Vor und nach dem Wert steht kein `[A-Za-z0-9_]` und kein Zeichen des
  Provider-Alphabets, und der Wert liegt in keinem Base64-Blob. Escapes wie `\n` oder `%3D`
  begrenzen ein Token weiterhin.
  Seit F01 braucht `dlp_eth_private_key` Schlüsselkontext (`RuleMeta::context_gate`, in jedem
  Modus): einen Schlüsselbegriff auf der Zeile oder in bis zu fünf Zeilen darüber (private key,
  privkey, mnemonic, Schlüssel …; wallet, signer nur auf der Zeile oder als Bezeichner). Ein
  Begriff, der den Wert direkt bezeichnet (nur Trennzeichen dazwischen), entscheidet: tx hash,
  blockHash, Transaktionshash, Prüfsumme, topic, salt … verwerfen ihn. Ohne Bezeichner genügt
  ein Schlüsselbegriff im Kontext; ein Hash- oder ID-Wort an anderer Stelle im Satz verwirft
  nicht.
  Seit F02 prüft `dlp_btc_wif` Base58Check mit der WIF-Versionsbyte von Mainnet (`0x80`, `5…`,
  `K…`/`L…`) oder Testnet/Signet/Regtest (`0xef`, `9…`, `c…`), einen secp256k1-Skalar und das
  Kompressionsflag `0x01`. Testnet-Schlüssel haben Severity `test`. Die Regel wertet mit
  Prüfsummen-Stärke: Im Modus `balanced` bleibt ein WIF-Schlüssel ohne Kontext (0,65), ein
  näherer Prüfsummen-/Hash-Begriff verwirft ihn.
  Seit F03 prüft `dlp_github_token` die CRC32 der GitHub-Tokens: `ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_`
  und genau 36 Base62-Zeichen, die letzten sechs sind die CRC32 der ersten 30. `dlp_github_pat`
  nimmt `github_pat_` und genau 82 Zeichen. Die Regel wertet mit Prüfsummen-Stärke (0,90 ohne
  Kontext). Ein Token-förmiger Wert mit falscher CRC32 ist auch für generische Zuweisungen,
  URL- und Header-Regeln kein Secret.
  Seit F04 prüft `dlp_npm_token` die CRC32 wie bei GitHub: `npm_` und genau 36 Base62-Zeichen,
  die letzten sechs sind die CRC32 der ersten 30 (Prüfsummen-Stärke, 0,85 ohne Kontext). Ein
  `npm_`-Wert mit falscher CRC32 ist auch für generische Regeln kein Secret. `dlp_gitlab_pat`
  nimmt `glpat-` mit genau 20 Zeichen oder die routbare Form (Payload, Punkt, zwei Zeichen
  Version, sieben Zeichen Base36; aktuell `.01.`, zwei Base36-Längenziffern, sieben Base36-CRC32-Ziffern). `dlp_gitlab_token` deckt die übrigen dokumentierten
  GitLab-Präfixe ab (Deploy `gldt-`, Runner `glrt-`/`glrtr-` auch routbar, Workspace `glwt-` nur routbar, Runner-Registrierung
  `GR1348941`, Pipeline-Trigger `glptt-`, Feed `glft-`, Incoming Mail `glimt-`, Kubernetes-Agent
  `glagent-`, CI/CD-Job `glcbt-`, SCIM `glsoat-`, Feature-Flag-Client `glffct-`) mit den Längen
  der gitleaks-Regeln, `dlp_gitlab_oauth_secret` das OAuth-Anwendungs-Secret `gloas-` (`API_KEY`,
  Untertyp `secret_key`). Die Prüfwerte der routbaren GitLab-Tokens werden nicht verifiziert,
  weil GitLab den Algorithmus nicht dokumentiert.
  Seit F05 nimmt `dlp_aws_access_key` nur die Credential-Präfixe der IAM-Unique-ID-Tabelle
  (`AKIA`, `ASIA`, `ABIA`, `ACCA`, alt `A3T…`) mit genau 16 Base32-Zeichen; Gruppen-, Benutzer-,
  Rollen- und Policy-IDs (`AGPA`, `AIDA`, `AROA`, `ANPA` …) sind keine Zugangsdaten.
  `dlp_aws_secret_key` nimmt 40 Base64-Zeichen mit Groß- und Kleinbuchstaben als ganzen Lauf, und
  nur in strukturellem AWS-Kontext (`RuleMeta::context_gate`): nach einem AWS-Schlüsselnamen oder
  -Label (auch in Prosa bis zu zwei Zeilen weiter), direkt nach einer Access Key ID (SDK-Aufruf,
  Credentials-CSV, CLI) oder nach einem generischen `secret_key`/`secret-key`/`secretKey` mit
  AWS-Kontext in bis zu fünf Zeilen darüber oder zwei darunter (Access Key ID oder
  `access_key`-Schlüssel, Terraform `provider "aws"`/`backend "s3"`, `amazonaws.com`, `aws` als
  Namensteil). Hex-Digests, 41 Zeichen lange Läufe und einfarbige Werte sind kein Secret Key.
  Seit F-GEN1 brauchen die Werte der generischen Regeln Passwort-Ähnlichkeit
  (`RuleMeta::value_gate`, `rules/likeness.rs`): `dlp_password_assignment` und
  `dlp_generic_credential_assignment` verwerfen Code-Ausdrücke (Aufruf, Index-/Member-Zugriff,
  `Token::…`-Pfad, Typannotation wie `Option<&str>` oder `string|null`, `%s`), Schlüssel mit
  `:` am Ende, Pfade, eine Shell-Variable als Schlüssel (`$PWD:/work`), DE/EN-Wörterbuchwörter
  und Wortformen („Passwort ist falsch“), Credential-Namen in einer Namenskonvention
  (`GIT_PASSWORD`, `clientSecret`) und Test-Platzhalter (`"password"`, `"topSecret"`, `foo001`).
  Ein Wert mit Ziffer oder Sonderzeichen ist nie ein Wort; schwache echte Passwörter bleiben
  Treffer. `dlp_url_userinfo_password` verwirft Test-Zugangsdaten (`user:pass`, `user:secret`)
  und das Pseudo-Passwort `x-oauth-basic`; `dlp_url_userinfo_token` meldet das Token im
  Benutzernamen von `https://<token>:x-oauth-basic@…` (zwei Zeichenklassen, Entropie ≥ 3 Bit,
  keine Folgen/Wiederholungen).
  Seit F-GEN2 nehmen `dlp_password_assignment` und `dlp_generic_credential_assignment` einen
  Wert in Anführungszeichen bis zum schließenden Zeichen, mit Leerzeichen, `;`, `,` und `}` darin;
  ein Wert ohne Anführungszeichen endet weiter daran. `dlp_env_var_secret` meldet den Wert ohne
  Anführungszeichen und ohne `;`/`,` am Ende, auch nach `KEY:` in YAML/Compose-`environment`, und
  verwirft Code-Konstanten (`DATA_API_KEY = '.data-api'`, `AUTH_FLOW_PASSWORD = "password"`),
  Aufrufe, Index-Zugriffe und Pfade (`likeness::is_env_value`). Eine Regel kann ihren Wert in je
  einer Gruppe pro Schreibweise fangen (`"…"`, `'…'`, ohne); es zählt die erste beteiligte Gruppe
  ab `span_group`. Ein Wert mit Leerzeichen muss wie eine Passphrase aussehen, nicht wie eine
  Meldung („Bitte Passwort eingeben“, "too short"), ein Platzhalter oder eine Vorlage. Ein
  Anführungszeichen, das einen String schließt (`"Password:"),…` in minifiziertem Code), öffnet
  keinen Wert. Der Beispiel-Check (T06) zählt zusätzlich ein auf die Feldlänge gekürztes
  Markerwort am Wortende (`Eexampl0123!`) und behandelt einen generischen Wert aus mindestens
  32 Hex-Ziffern wie ein festes Format (`deadbeef…` ist ein Beispiel, `abcabcabcabc` bleibt ein
  schwaches echtes Passwort). Übergangslösung, bis K05 die Werte strukturell extrahiert.
  Seit T09 beginnen `dlp_password_assignment`, `dlp_generic_credential_assignment`,
  `dlp_csrf_token` und `dlp_password_hash` am Credential-Nomen ohne `\b`: zusammengesetzte
  (`db_password`, `service_secret`) und camelCase-Schlüssel (`dbPassword`, `ClientSecret`,
  `PasswordHash`) treffen, ein Nomen am Wortende (`mypassword`, `DBPASSWORD`) nicht
  (`RuleMeta::key_gate`, `likeness::key_shape`). Zwischen Schlüssel und Wert stehen auch das
  schließende Anführungszeichen eines Schlüssels (`"client_secret":`, `'password' =>`, escaped
  `\"…\":`), ein Index (`os.environ["DB_PASSWORD"] =`), ein String-Typ (`: &str =`, `: string =`)
  und XML `key="…" value="…"`; Werte in `\"…\"` (Notebook, JSON-String) zählen. Nach
  zusammengesetzten oder gequoteten Schlüsseln muss der Wert zu einem Feld passen: kein Bezeichner
  in Namenskonvention, kein Wort oder Name, keine Version (`^1.0.0`), kein Code, nach gequotetem
  Schlüssel oder `=>` nicht ohne Anführungszeichen. Cursor-/Handle-Tokens (`nextPageToken`,
  `continuation_token`) und Secret-Objekte (`existingSecret`, `tls_secret`) sind keine Credentials,
  ein an der Fanggrenze von 150 Zeichen abgeschnittener Wert auch nicht. Wortgrenzen der Schlüssel
  sind ASCII (`(?-u:\b)`), der Regex der generischen Regel läuft dadurch etwa 25-mal schneller.
  Übergangslösung, bis K05/G02 die Schlüssel strukturell lesen.
  Seit F-HTTP (F13 + T11) stehen `Bearer`, `Basic` und Session-Cookies nicht mehr nur in einer
  wörtlichen `Authorization:`- oder `Cookie:`-Zeile: Die Regeln treffen unter
  `authorization`/`proxy_authorization`-Schlüsseln in env/JSON/YAML/TOML/XML/Code, in Logs und
  allein in Chats, Tickets und Mails. Der Wert belegt dafür seine Art (`rules/http_auth.rs`):
  `Basic` nur, wenn das Base64 kanonisch ist und zu druckbarem `user-id:passwort` dekodiert
  (RFC 7617), mit gewähltem Passwort (kein Platzhalter, Stellvertreter oder Credential-Name, auch
  nicht in Leetspeak wie `user:p@ss`, nicht gleich der User-ID); `Bearer` nur als ausgestelltes
  Token (RFC 6750, ab 16 Zeichen, zwei Zeichenklassen, 3 Bit Entropie je Zeichen, keine
  Sequenz-/Wiederholungsläufe, kein Bezeichner). Ein gültiges JWT nach `Bearer` gehört `dlp_jwt_token`,
  ein Provider-Token seiner Provider-Regel. Session-Cookies von Servern und Frameworks
  (`JSESSIONID`, `PHPSESSID`, `ASP.NET_SessionId`, `connect.sid`, `laravel_session`,
  `__Host-`/`__Secure-`) zählen auch ohne `Cookie:`-Zeile, generische Namen (`session`,
  `sessionid`, `sid`) weiter nur darin; der Wert muss wie eine ausgestellte Session-ID aussehen.
  Das RFC-7617-Beispiel ist ein dokumentierter Beispielwert (K06).
  Seit K05 (Teil 1) lesen die generischen Schlüsselregeln (`dlp_env_var_secret`,
  `dlp_password_assignment`, `dlp_generic_credential_assignment`) Config-Zeilen strukturell
  (`dlp/config_keys.rs` auf der `key: value`/`key=value`-Grammatik von PII K04): env
  (`KEY=value`, `export KEY=value`), INI/properties (`key = value`, `app.db.password=…`) und
  HTTP-Header im Kopf einer Anfrage oder Antwort. Der Schlüssel bindet den Wert über dieselbe
  Schlüsselgrammatik und dasselbe Key-Gate wie die Regex; ein Wert ohne Anführungszeichen läuft bis
  zum Zeilenende oder Inline-Kommentar (`␣#`, `␣;`), mit `;`, `,`, `}` darin. Kein Config-Wert
  sind Werte mit Leerzeichen, Anführungszeichen oder Interpolation darin, mit `,`/`;` am Ende und
  env-Werte mit `;` (bleiben bei der Shell-Logik der Regex). Vor jeder Bindung durch einen
  Credential-Schlüssel, ob Regex oder Config-Zeile, verwirft der Wertform-Filter
  (`rules/value_shape.rs`) Formen, die kein Secret sind: UUIDs, Digests mit Algorithmus-Präfix
  in passender Länge (`sha256:`, `sha1-`, SRI, `h1:`), Hex-Digests nur unter einem Schlüssel, der
  einen Digest nennt (`hashed_password`, `SHA256_TOKEN`, `gehashtes_passwort`), ObjectIds
  (24 Hex mit Zeitstempel 2009–2040), Template- und Formatfelder, Variablenreferenzen,
  Wahrheitswerte und Null-Wörter (DE/EN), Zahlen, Pfade und URLs ohne Zugangsdaten. Hex unter
  einem einfachen Credential-Schlüssel bleibt ein Secret (OAuth-Client-Secrets, Flask/Rails-
  Secret-Keys). YAML/JSON/TOML folgen in K05B, HCL/XML in K05C.
  Seit K09 (Taxonomie v2) nennt jede Secret-Regel einen Untertyp ihrer Gruppe (`subtype` in
  `matched_rules`: `api_key`, `access_token`, `password`, `auth_url` …). Connection-Strings,
  Webhook-URLs, Auth-URLs, OTP-Secrets und Seed-Phrasen werden keine eigenen Gruppen, sondern
  Untertypen von `CREDENTIAL`, `SECRET_TOKEN` bzw. `CRYPTO_KEY` (Liste in
  [`entity_map.yaml`](entity_map.yaml), `subtypes`).
- Validatoren sind schwach: `is_secret_value` prüft nur Länge, Platzhalter und Env-Referenzen.
  Prüfsummen fehlen ganz: JWT-Struktur und PEM/DER (Base58Check für WIF seit
  K08/F02, GitHub CRC32 seit F03, npm CRC32 seit F04).
  Seit K03 liegen die Bausteine dafür in `rust/src/detectors/validators/` (CRC32-Base62,
  Base58Check, Bech32/Bech32m, Base64/DER, JWT-Header, Entropie, Zeichenklassen; auch für PII);
  angebunden werden sie regelweise in F01–F09.
- Bekannte Präzisionslücken: `dlp_eth_private_key` traf bis F01 jeden 0x-64-Hex-Wert, also auch
  Tx- und Block-Hashes. `dlp_btc_wif` validierte bis K08 die Prüfsumme nicht. `dlp_signed_url_signature`
  (`sig=`) und `dlp_credential_in_url` (`token=`) treffen auch Paginierungs- und CSRF-Parameter.
  `dlp_password_assignment` nahm bis F-GEN1 in Prosa beliebige Wörter („Passwort ist falsch“).
- Gemessen ist bisher nur Content: 214 Go-Dokumente aus gitleaks (Dokumentlabel) und 250
  SQL-Statements aus SchemaPile. Beide liegen als Dev-Komponente `external/` im Scoreboard
  (E12; Attach/Scope-Vertrag in
  [`docs/research/dlp-external-content-contract-0.1.8.md`](../../docs/research/dlp-external-content-contract-0.1.8.md)). Für Secrets gibt es **keine** externe Span-Ground-Truth. Die
  Fixtures von gitleaks und detect-secrets sind Erwartungswerte der Scanner selbst; TruffleHog steht
  unter AGPL (`benchmark_data/external_dlp/README.md`).
- Die Goldens (`dlp_l1.jsonl`) folgen seit E13 dem Golden-Schema v2: 537 Fälle, je Label und Sprache
  mindestens 5 Positive und 5 harte Negative, jede der 59 Regeln mit einem Positiv in DE und EN. Jede
  Zeile nennt `rule_id`, Carrier und Schwierigkeits-Tags (`carrier`, `no_context`, `encoded`, `split`,
  `prose`). 27 Positive sind als `known_gap` markiert (u. a. alle geteilten und 9 von 12 kodierten Secrets);
  `13_l1_golden_eval` meldet die Abdeckung je `rule_id` und Tag
  ([Schema](../../python/patronus_ark/benchmark_data/README.md#dlp-golden-schema-v2)).
- Der Baseline-Bericht [`scoreboard/baseline.md`](scoreboard/baseline.md) (E14) misst ARK auf dem
  Dev-Split gegen gitleaks, TruffleHog und detect-secrets und enthält die Coverage-Matrix gegen
  Google DLP und Purview, die Fehler-Buckets und TRIAGE-Kandidaten.

## Vergleichsbasis

| Bereich | Baseline | Profil | Lizenz / Nutzung |
|---|---|---|---|
| Provider-Secrets | **gitleaks** v8 (gepinnt) | Default-Config | MIT; Binary + Regeln als Coverage-Referenz |
| Provider-Secrets | **TruffleHog** v3 (gepinnt) | `--no-verification`, alle Detektoren | AGPL; nur als unverändertes Binary auf der VPS, kein Code/keine Daten im Repo |
| Generische Secrets | **detect-secrets** (gepinnt) | Default-Plugins inkl. Keyword + High-Entropy | Apache-2.0 |
| optional | Kingfisher (MongoDB) | Default | Apache-2.0; nur wenn der Aufwand gering bleibt |
| Dokumentklassen/Infotypes | **Google Cloud DLP** `DOCUMENT_TYPE/*` + Credential-Infotypes, **Microsoft Purview** SITs | Coverage-Matrix (statisch); Messlauf nur nach Freigabe | Cloud, kostenpflichtig, Daten verlassen die VPS → `needs_decision` |

Welche ARK-Regel welcher Baseline-Regel entspricht, steht in [`entity_map.yaml`](entity_map.yaml)
(Scopes `shared`, `ark_only`, `baseline_only`, `out_of_scope`; Test `rust/tests/dlp_entity_map.rs`).

TruffleHog-Verifikation (Live-Abfrage beim Provider) liegt nicht im L1-Scope: L1 arbeitet offline und
ohne Netz. Darum wird TruffleHog fair ohne Verifikation verglichen. Den verifizierten Modus nennt
das Scoreboard nur als Referenzzeile, und auch nur auf synthetischen Daten, wo er nichts verifizieren
kann.

## Definition „besser als der Stand der Technik“

Gemessen wird auf einem eingefrorenen Holdout. Der Agent sieht ihn nie: Er liegt nur auf der VPS
unter `~/ark-dlp/holdout`, ist für die Agent-Sandbox unzugänglich und SHA-gepinnt. Die Baselines laufen auf derselben Maschine.

| Meilenstein | Kriterium |
|---|---|
| M1 Provider-Parität | Für jeden gemeinsamen Provider-Typ gilt Recall(ARK) ≥ max(gitleaks, TruffleHog) bei FP/MB ≤ gitleaks |
| M2 Generische Secrets | F1 auf Passwort/Token/Connection-String in Config, CLI und DE/EN-Prosa ≥ bester Baseline + 20 pp |
| M3 Breite | ≥ 90 % der gitleaks-Default-Regeln gemappt. ≥ 150 Secret-Formate, davon ≥ 30 mit Offline-Strukturprüfung (CRC, Base58Check, Bech32, BIP39, DER, JWT). ≥ 20 Dokument-/Content-Klassen, die keine der Secret-Baselines hat |
| M4 Latenz | 100 KiB p95 ≤ 10 ms, Durchsatz ≥ gitleaks (gemessen auf der VPS mit `scripts/l1_dlp/latency.py`) |
| Immer | FP/MB auf dem Benign-Code-Korpus ≤ der besten Baseline. Keine Klasse verliert > 0,5 pp F1. Keine echten Secrets in Repo, Logs oder PRs |

Metriken:
- Secrets: exakte Spans auf den **Wert** (ohne Schlüsselnamen) als P/R/F1 je Entity-Gruppe und je
  Provider. Dazu Overlap-F1, Provider-Attribution (richtige `rule_id`), FP/MB auf echtem Benign-Code
  und FP auf Hard Negatives.
- Content/Dokumentklassen: P/R/F1 auf Dokumentebene je Klasse, Overlap der Evidenzspans und FP auf
  Benign-Dokumenten (DE+EN).

## Hebel gegenüber den Baselines

1. **Offline-Prüfsummen und Strukturprüfung** statt reiner Präfix-Regex: GitHub/npm CRC32,
   Base58Check, Bech32, BIP39-Checksumme, DER/ASN.1 im PEM-Body, JWT-Header-JSON, Längen- und
   Alphabet-Tabellen je Provider.
2. **Strukturbewusstsein für Konfigurationsformate**: `.env`, YAML, JSON, TOML, INI/properties, HCL,
   XML und HTTP-Header. Dazu CLI-Flags (`-p`, `--password`, `curl -u`, `mysql -p…`) und
   Connection-Strings je DB-Schema. Die Kernengine kommt aus dem PII-Plan (K02–K06), DLP ergänzt die
   Formatparser.
3. **DE/EN-Prosa**: „Das Passwort lautet …“, PIN/TAN, WLAN-Schlüssel, Zugangsdaten in Tickets und
   Mails. Keine der Baselines deckt das ab.
4. **Decoder-Pipeline** mit Offset-Rückabbildung: base64, hex, URL- und JSON-Escape, UTF-16, sowie
   zusammengesetzte Strings.
5. **Unterdrückung** dokumentierter Beispielwerte, Platzhalter, Testschlüssel und Variablenreferenzen.
   Das senkt FP/MB, die größte Schwäche von detect-secrets.
6. **Breite über Secrets hinaus**: Krypto-Schlüsselmaterial (Seed-Phrasen, xprv, Keystores),
   Passwort-Hashes (shadow, NTLM, Cisco, GPP), Klassifizierungsmarkierungen (VS-NfD, TLP),
   Dokumentklassen (HR, Recht, M&A, Insider, Exportkontrolle, Infrastruktur).

## Kategorien-Wellen

| Welle | Inhalt | Ziel |
|---|---|---|
| E | Messinfrastruktur: Generator, Benign-Korpus, Baseline-Runner, Scoreboard, Holdout | Messbarkeit |
| K | DLP-Engine: Module, Regel-Metadaten v2, Score/Kontext aus PII, Config-Parser, Allowlist, Prefilter | Fundament |
| F | Bestehende 59 Regeln reparieren (Präzision + Prüfsummen) | M1-Basis |
| P | Provider-Secrets in 12 Paketen (LLM, Hyperscaler, EU/DE-Cloud, DevOps, Observability, Kommunikation, Payment, SaaS, Identity, Daten) | M1, M3 |
| G | Generische Credentials: Config, CLI, Connection-Strings, Prosa, Hashes, OTP, Credential-Dateien | M2 |
| C | Krypto- und Schlüsselmaterial | M3 |
| D | Decoder und Obfuskation | M1/M2 Recall |
| M | Sensible Materialien und Dokumentklassen | M3 (über Secret-Scanner hinaus) |
| H | Härtung, Latenz, Doku, Abschlussbericht | M4 |

Reihenfolge: E → K01–K03 → F → P. Diese Schritte brauchen die PII-Engine nicht und laufen, während
PII K02–K06 baut. Danach folgen K04–K09 → G → C → D → M → H. Aufgaben mit `ext_deps` warten, bis die
PII-Aufgabe auf `main` gemergt ist.
Das sind 107 Aufgaben (plus 5 manuelle Setup-Schritte); bei 2 Läufen/Tag dauert es ≈ 8–9 Wochen inkl.
Review-Pausen.

## Ausführung (Unterschiede zu PII)

- Gleicher Runner wie PII (`research/l1-pii/runner/`), Programm über `--program dlp`
  (`run.sh --program dlp`, `ark-l1 --program dlp status|next|gate|publish|block|unblock`):
  Backlog `research/dlp/backlog.yaml`, Prompt `AGENT_PROMPT.md` (installiert als
  `~/ark-l1/bin/AGENT_PROMPT.dlp.md`), Branches `dlp/NNN-<id>`, PR-Label `ark-dlp`, State, Logs,
  Worktrees, Dev-Daten und Holdout unter `~/ark-dlp`, Golden-Eval `13_l1_golden_eval -- dlp`, Gate-
  Scoreboard `scripts/l1_dlp/{prepare_corpora,scoreboard}.py` mit `~/ark-dlp/baselines-venv` (gleiche
  Schnittstelle wie `scripts/l1_presidio/`). Klon, Cargo-Target und Gate-Venv teilen sich beide
  Programme unter `~/ark-l1`. Eigener Stack mit eigener Pause-Grenze (6 PRs). Die Sandbox sperrt
  Holdout und State beider Programme.
- **Kein gleichzeitiger Lauf**: ein gemeinsamer Lock `~/ark-l1/state/run.lock` für beide Programme
  (zwei Läufe mit je `MemoryMax=9G` passen nicht in 11 GB). `ark-dlp.timer` läuft versetzt zu PII
  (PII 07/15 Uhr, DLP 21/02 Uhr; ein Lauf dauert bis zu 3 × 90 min, ein belegter Lock überspringt
  den Lauf). Gemeinsam genutzte Dateien (`CHANGELOG.md`, `generate_l1_goldens.py`,
  `l1_bilingual_rules.json`, Rule-Catalog) lösen sich über Rebase auf `main`.
- Der Backlog muss auf `main` liegen: `next` liest ihn von der Stack-Spitze bzw. `origin/main`.
- **Abhängigkeiten zwischen Programmen**: `ext_deps: [pii:K03]` heißt, dass die PII-Aufgabe auf
  `main` gemergt sein muss. Ein offener PR im Stack reicht nicht. So wird die Score-/Kontext-Engine
  nicht doppelt gebaut.
- **Secret-sichere Goldens** (E02, entschieden: Generator-Rezepte): Gültige Prüfsummen-Tokens im Repo würden
  GitHub Push Protection und den eigenen Patronus-Hook auslösen. Deshalb speichern Goldens
  Generator-Rezepte (`{"gen": "github_pat_classic", "seed": 17}`) statt Klartextwerten und erzeugen
  die Werte erst zur Testzeit. Werte sind immer synthetisch. Echte, geleakte Secrets (z. B.
  SecretBench) werden nicht verwendet. Hard Negatives mit Beispiel-/Testwerten im Provider-Format
  speichern die `fill`-Variante des Rezepts (`{"gen": …, "seed": 0, "fill": "EXAMPLEKEY"}`, T06);
  Tests setzen Provider-Werte zur Testzeit aus Stücken zusammen (`concat!`/`format!`/`"".join`).
- **Holdout**: Der Generator nutzt einen getrennten Seed **und** getrennte Carrier-Template-Familien
  für Dev und Holdout. Der Benign-Code-Korpus wird nach Repository gesplittet. Die Fixtures von
  gitleaks und detect-secrets sind nur Dev-Smoke-Tests und nie Teil des Holdouts.
- **Defaults**: Neue Secret-Regeln (Gruppen `API_KEY` … `SECRET_TOKEN`) sind sofort aktiv. Neue
  Content- und Dokumentklassen sind standardmäßig aus. Sie werden erst über eine eigene Aufgabe mit
  `needs_decision` eingeschaltet.
- Montags läuft `TRIAGE` wie bei PII.

## Abgrenzung

- `secret_transfer`/`destructive_operation` (Aktions-DLP, Threat-Matches) gehören nicht zu diesem
  Programm. Nur Verweise auf sensible Pfade (`~/.aws/credentials`) kommen hier als Kontext hinein
  (G13).
- Personenbezogene Werte (IBAN, Ausweis, USt-IdNr. natürlicher Personen) gehören zu PII. Dubletten
  wie USt-IdNr., HR-Nummer und BSNR klärt F15.
- Keine Live-Verifikation von Secrets, kein Netzwerkzugriff im Detektor.
