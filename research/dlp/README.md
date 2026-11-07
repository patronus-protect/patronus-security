# L1-DLP: gitleaks, TruffleHog und detect-secrets übertreffen

Stand: 2026-10-11. Aufgabenliste: [`backlog.yaml`](backlog.yaml). Ausführung über denselben
VPS-Runner wie [`../l1-pii/`](../l1-pii/README.md) (systemd-Timer → sandboxed Claude Code → Gate →
Stacked PR, erst bei grüner GitHub-CI), Branch-Präfix `dlp/`. Agent-Prompt: [`AGENT_PROMPT.md`](AGENT_PROMPT.md).

## Gold und Qualitätsuntergrenze (seit 2026-10-25)

- **Gold überall:** Jede implementierte Entität braucht Gold in mindestens einer Quellfamilie. Neue Entitäten bringen ihr Gold in derselben Aufgabe mit (synthetisch, prüfziffergültig, ≥ 10 Positive und ≥ 5 Hard Negatives je Entität, DE + EN). Lücken stehen auf der Seite `docs/reference/l1-capabilities.md` als „no gold“.
- **Gold vor der Regel (GOLD-D2):** Entitäten ohne ARK-Regel (`scope: baseline_only`) bekommen ihr Gold über `baseline_entities` in `python/patronus_ark/dlp_synth/rules.json`: Generatoren im Format der gitleaks-Regel der Entität (ohne gitleaks-Regel: TruffleHog-Detektor oder detect-secrets-Plugin; ohne jede Baseline-Regel: Herstellerdoku, `docs:<url>`), Carrier-Zeilen mit `rule_id` null und als zusätzliches Hard Negative `lookalike` (falsches Präfix, Länge oder Zeichensatz unter dem neutralen Schlüssel `correlation_id`). So haben ARK und jede Baseline eine Zahl, bevor das Provider-Paket die Regel bringt; mit der Regel wandert der Eintrag nach `rules`. Abgedeckt: saas (GOLD-D1), comm, identity, commerce (GOLD-D2), devops, ci, vcs, registry (GOLD-D3), hosting, cloud, data (GOLD-D4), payment, observability, llm (GOLD-D5), credential, key (GOLD-D6). Content-Klassen (`content.*`) haben Gold auf Dokumentebene: Carrier-Familien mit `content_labels` (Code, Logs, SQL-Dumps, interne Kennzahlen) in DE und EN je Split; der Snapshot nimmt sie, wenn weder Span-Gold noch externe Goldens die Klasse abdecken.
- **Untergrenze F1 ≥ 80:** Jede implementierte Entität mit Gold erreicht exakten F1 ≥ 80 auf jeder Familie mit Gold (PII: `balanced`; DLP: im Profil, in dem sie läuft, auch Opt-in). Darunter wird eine `Q-…`-Aufgabe angelegt; TRIAGE prüft das bei jeder Messung. Ausnahmen nur mit dokumentierter Entscheidung.

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
  Seit T15 entscheidet auf einem identischen Span derselben Stufe der spezifischere Subtyp:
  `DB_PASSWORD=…`, `ENV POSTGRES_PASSWORD=…`, `export`, CI-`env:` und Code-Konstanten gehören
  `dlp_password_assignment` (`password`), nicht `dlp_env_var_secret` (`generic_secret`).
  Variablen ohne Passwort-Nomen (`API_KEY`, `CLIENT_SECRET`) bleiben bei `dlp_env_var_secret`;
  verschiedene Spans entscheidet weiter die Reihenfolge.
  Seit Q-DLP-PW gilt ein Wert nur als Member-Zugriff (Code), wo Code ihn enden lassen kann:
  `wPF.DZs~Brb…` oder `o.Bbst….jdJ44` (Ende an `~` oder an einem `.` vor Ziffer/Symbol) sind
  gewählte Passwörter. Seit T23 binden SQL-Dumps (`dlp::sql_rows`): In `INSERT … VALUES`
  am Zeilenanfang und `COPY … FROM stdin` bindet eine Spalte mit Credential-Schlüssel ihr Feld in
  jeder Zeile, und ein Schlüsselfeld einer Settings-Zeile (`(2,'db_password','…')`) das nächste
  Feld; `dlp_csrf_token` und `dlp_password_hash` nur über Schlüsselfelder, Container-Spalten
  (`zugangsdaten`) nur über das Label der Zeile.
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
  Seit C01 meldet `dlp_bip39_seed_phrase` BIP39-Seed-Phrasen: 12/15/18/21/24 kleingeschriebene
  Wörter einer offiziellen Wortliste (Englisch, Italienisch, Portugiesisch, Tschechisch, Spanisch,
  Französisch; spanische und französische Wörter mit oder ohne Akzente, NFC oder NFD) mit
  gültiger Prüfsumme, in einer Zeile, mit Kommas, als Array, nummeriert oder Zeile für Zeile. Die
  Regel hat kein Literal; `seed_phrase::phrases` (`RuleMeta::finder`) findet die Kandidaten in einem
  Durchlauf über die Wörter, die Regex läuft nur dort. In Läufen über 27 Listenwörter (Wortlisten)
  zählen nur Zeilen mit 12 bis 27 Listenwörtern; veröffentlichte Testvektoren und Phrasen mit mehr
  als zwei Wiederholungen zählen nicht; 12- und 15-Wort-Phrasen brauchen Nummerierung oder einen
  Kontextbegriff davor. Offen: die CJK-Listen (chinesisch, japanisch, koreanisch).
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
  Seit T17 liest `dlp_url_userinfo_password` das Passwort prozentdekodiert (`p%40ss` ist
  `p@ss`) und verwirft auch maskierte Credential-Nomen (`p@ss`, `p@ssw$rd`, `s3cr3t`: Leetspeak-
  Ziffern und Sonderzeichen statt Buchstaben, wie bei Basic Auth und Connection-Strings); ein
  gewähltes Passwort behält den kodierten Span. Dekodiert wird nur der gefundene Wert.
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
  schwaches echtes Passwort). Seit T18 gilt das auch für den Lauf eines maschinell ausgestellten
  Werts von Anbietern ohne ARK-Regel: ein Hex-, Ziffern- oder Base62-Lauf ab 24 Zeichen neben
  einem kürzeren Präfix oder Suffix (`SK…`, `dapi…`, `…-us10`, `shippo_live_…`, Hex-Gruppen mit
  Bindestrich; `credentials::machine_issued_run`). Wiederholte Blöcke in diesem Lauf machen den
  Wert zum Beispiel; ein Wert mit anderen Zeichen (`Passwort123!`) oder ohne Präfix/Suffix bleibt
  ein gewähltes Passwort. Übergangslösung, bis K05 die Werte strukturell extrahiert.
  Seit T22 prüfen die generischen Regeln und der Festformat-Check der Provider-Regeln einen
  Base64-Wert auch dekodiert
  (`credentials::is_decoded_example`): kanonisches Standard- oder URL-sicheres Base64, optional
  nach `pypi-`, `glc_` oder `ops_`, dekodiert mit `validators::base64_decode`. Ein druckbarer
  ASCII-Lauf der Bytes (getrennt an Steuer-, Nicht-ASCII-Bytes und JSON-Anführungszeichen) mit
  Markerwort (ein Hostname wie `test.pypi.org` zählt nicht) oder ein Lauf ab 16 alphanumerischen Zeichen aus wiederholten Blöcken macht den
  Wert zum Beispiel (Kubernetes-`data:`, Grafana-Legacy-Key/`glc_`, PyPI-Macaroon, 1Password
  `ops_`, Elastic `id:api_key` mit `EXAMPLEKEY`/`TESTKEY`/`deadbeef`-Füllung). Zufällige Bytes
  und zufällige druckbare Secrets bleiben Funde. Dekodiert wird nur ein Wert, der alle übrigen
  Prüfungen der Regel bestanden hat; `credentials::is_example_payload` auf den Bytes ist für
  PEM-Körper (T14) gedacht.
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
  Secret-Keys).
  Seit K05B (Teil 2) lesen dieselben Regeln YAML, JSON und TOML: Ein Schlüssel bindet seinen Wert
  in jeder Tiefe (eingerückte YAML-Mappings und Listeneinträge `- key: value`, verschachtelte
  JSON-Objekte, TOML-Tabellen), ein JSON-/TOML-String läuft bis zum schließenden Anführungszeichen
  über Escapes (`\"`) hinweg, ein ungequoteter YAML-Wert mit `;`, `,`, `}` darin bis zum
  Inline-Kommentar. Ein Array unter einem Credential-Schlüssel bindet jedes String-Element:
  JSON- und TOML-Arrays (auch über mehrere Zeilen), YAML-Flow- (`[a, "b"]`) und Block-Sequenzen
  (`- item`); ein Schlüssel im Plural (`api_keys`, `tokens`, `SERVICE_TOKENS`) bindet nur
  Elemente. Ein Element steht ohne seinen Schlüssel und muss allein wie ein Secret aussehen
  (`likeness::is_item_value`: druckbares ASCII ohne Leerzeichen, Ziffer oder beide
  Groß-/Kleinschreibungen, keine Template-Zeichen, kein Bezeichner, Wort oder Pfad); eine Liste
  bindet nur, wenn alle Elemente bestehen (Tokenizer-Vokabulare, Scopes, Wortlisten nie), und ein
  Array mit Zahlen, Objekten oder Mappings bindet nichts. Kein YAML-Wert sind Werte mit einem
  YAML-Indikator am Anfang (Alias `*`, Anker `&`, Tag `!`, Blockskalar `|`/`>`, Flow `{`),
  Wortlisten (`read,write`) und Header-Namen (`X-Client-Secret:`) außerhalb eines HTTP-Kopfs.
  Der Wertform-Filter verwirft zusätzlich ungequotete YAML-Aliase (`*default_password`, auch
  Rust-Zeigertypen wie `pwd: *mut passwd`) und für das Repository verschlüsselte Werte (SOPS
  `ENC[AES256_GCM,data:…]`, `$ANSIBLE_VAULT;…`); der Digest-Schlüssel eines Elements wird an
  seinem eigenen Schlüssel geprüft (`sha256_tokens`). Treffer tragen `structure` `yaml`, `json`
  oder `toml`; ein TOML-Skalar nach ungequotetem Schlüssel bleibt `properties` (K05).
  Seit K05C (Teil 3) lesen dieselben Regeln HCL und XML. Ein Attribut in einem HCL-Block
  (`resource "…" "…" {`, `provider "…" {`, `locals {`, auch in verschachtelten Blöcken, Objekten
  und `jsonencode({ … })`) bindet seinen String in doppelten Anführungszeichen oder die Elemente
  seines Arrays (`#`/`//`-Kommentare dazwischen); ein Wert ohne Anführungszeichen ist dort ein
  Ausdruck (`var.db_password`, `random_password.db.result`) und bindet nichts. HOCON- und
  Code-Blöcke ohne HCL-Kopf (`db {`, `function f() {`) bleiben `properties`. Ein
  Terraform-/Packer-Block `variable "db_password" {` bindet seinen `default` über den
  Variablennamen. In XML bindet ein Element, das der Schlüssel benennt, seinen Text auf der Zeile
  (`<password>…</password>`, `<db:passwort>`, auch in CDATA), und ein Config-Element (`add`,
  `entry`, `property`, `param`, `setting`, `string` …), dessen `key`- oder `name`-Attribut den
  Schlüssel trägt, sein `value`-Attribut in beliebiger Reihenfolge oder seinen Text
  (`<entry key="client_secret">…</entry>`, `<add value="…" key="ApiToken"/>`). Kein XML-Wert
  sind Text mit Leerzeichen oder Markup, leere Elemente, HTML-Formularelemente
  (`<input name="password" value="…">`) und XML in einem String oder Kommentar von Code
  (`` Raw: `<password>…` ``, `"<token>"+t+"</token>"`, `/// <param name="token">`): Das Tag
  beginnt seine Zeile oder folgt einem anderen Tag. Elementtext zählt wie ein gequoteter
  Feldwert (`likeness::is_assignment_value`). Der Wertform-Filter prüft jeden Config-Wert unter
  seinem gebundenen Schlüssel, auch wenn dieser nicht vor dem Wert steht
  (`variable "passwort_sha256"`, `<hashed_password>`), und ein XML-`value`-Attribut unter seinem
  `key`/`name`-Attribut (`<add key="PasswordSha256" value="…">`). Treffer tragen `structure`
  `hcl` oder `xml`; die XML-Tag-Grammatik teilt sich K05C mit der Dokumentstruktur von PII K04
  (`structure::xml_start_tag`, `structure::xml_attributes`). Seit T21 lesen die
  schlüsselgebundenen Provider-Regeln (`provider_key!`) dieselbe XML-Bindung
  (`config_keys::xml_values`): Endet das `key`/`name`-Attribut oder der Elementname auf
  Provider-Name und Credential-Nomen (`<add key="HerokuApiKey" value="…"/>`, auch
  `value` zuerst, `<entry key="DatadogApiKey">…`, `<setting name="SentryAuthToken" …>`,
  `<SplunkHecToken>…</SplunkHecToken>`), prüft die Provider-Regel den Wert mit ihrer eigenen
  Wert-Regex, ihrem Validator und ihrer Beispielprüfung; Schlüssel- und Wert-Regex liest
  `providers::xml_key` aus dem `provider_key!`-Muster zurück, das Key-Gate verwirft IDs
  (`HerokuAppId`, `RailwayProjectId`). Der Treffer behält die Provider-`rule_id`, die generische
  Regel verliert die Überlappung.
  Seit G02 bindet `dlp_generic_credential_assignment` in einem Config-Dokument zusätzlich die
  Schlüssel `credentials`, `privateKey`/`private_key`, `secret_key`, `signing-key`, `passphrase`
  und die deutschen Varianten `Zugangsdaten`, `Anmeldedaten`, `privater`/`geheimer Schlüssel`
  (über die K05–K05C-Extraktion). Config-Dokument ist ein JSON-Objekt/-Array oder JSON Lines, ein
  XML-Dokument ohne HTML-Markup oder ein Text, dessen Zeilen alle Config-Zeilen, Kommentare,
  Sektionen, HCL-Blockköpfe und -Abschlüsse, YAML-Listeneinträge oder Blockskalar-Text sind
  (`config_keys::is_config_document`). In Programmcode (Objektliterale, Keyword-Argumente,
  Struct-Felder, Test-Fixtures) bleibt das Basisverhalten der Regel unverändert; ihre Regex
  nimmt die neuen Schlüssel nicht. Werte unter ihnen durchlaufen Wert-Gate und
  Wertform-Filter und sind kein Schlüssel-, Zertifikats- oder Config-Dateiname
  (`classpath:keys/private.pem`), keine Schlüssel-ID (GPG-Key-ID, KMS-Schlüssel), kein Bezeichner und kein Text mit Leerzeichen.
  Seit K09 (Taxonomie v2) nennt jede Secret-Regel einen Untertyp ihrer Gruppe (`subtype` in
  `matched_rules`: `api_key`, `access_token`, `password`, `auth_url` …). Connection-Strings,
  Webhook-URLs, Auth-URLs, OTP-Secrets und Seed-Phrasen werden keine eigenen Gruppen, sondern
  Untertypen von `CREDENTIAL`, `SECRET_TOKEN` bzw. `CRYPTO_KEY` (Liste in
  [`entity_map.yaml`](entity_map.yaml), `subtypes`).
  Seit G-URL (F12 + G08 + G09) verwerfen `dlp_credential_in_url` und die generische Zuweisung
  einen URL-Parameter, der selbst ein CSRF-Parameter ist, ein `token` neben einem Paginierungs-,
  Cursor- oder CSRF-Parameter (`page`, `cursor`, `offset`, `limit`, `_csrf`, `authenticity_token` …)
  und das `secret` einer otpauth://-URI. `dlp_signed_url_signature` braucht die Struktur einer
  signierten URL (X-Amz-*/X-Goog-*-Begleiter, CloudFront `Expires`/`Key-Pair-Id`/`Policy`,
  Azure-SAS `sv` mit `se` oder `sp`). Neu: `dlp_auth_url_token` (Untertyp `auth_url`: OAuth-
  Redirect-Tokens, `code` mit `state` oder Callback-Pfad, Reset-, Magic-Link-, Einladungs- und
  Bestätigungstokens in Query und Pfad; ausgestelltes Token, keine UUID, kein Hex-Digest) und
  `dlp_otp_secret` (Untertyp `otp_secret`: Base32-Seed von otpauth://-URIs und nach TOTP-/2FA-
  Secret-Namen, RFC-4648-Länge/Padding, ≥ 80 Bit, keine Wiederholungs-/Folgeläufe; der Beispiel-Seed
  des Key-Uri-Formats ist ein dokumentierter Wert). Offen: Listen von 2FA-Wiederherstellungscodes.
  Seit T16 trennen `&amp;` und `&#38;` in XML-/HTML-Attributwerten und `.config`-Dateien die
  Query-Parameter beider Regeln wie `?` und `&`; ein `api_key=` in `<add value="…&amp;api_key=…">`
  bleibt bei `dlp_credential_in_url` statt bei der generischen Zuweisung.
  Seit G01 meldet `dlp_connection_string_password` (Untertyp `connection_string`, Stärke
  `structure`) das Passwort eines Connection-Strings je Schema: `password`/`pwd` in einem
  `;`-getrennten Key/Value-String mit Server-, Data-Source-, Host-, DSN-, Driver- oder
  Provider-Schlüssel oder nach einer `jdbc:`-URL (ADO.NET, ODBC mit `{…}`, OLE DB, JDBC SQL
  Server/DB2), in einem libpq-Keyword/Value-String mit Host und Datenbank, User oder Port
  (Keyword-Argumente eines Aufrufs zählen nicht), als Query-Parameter einer Datenbank- oder
  Broker-URL (`jdbc:mysql://…?user=…&password=…`, auch `&amp;` und `&#38;`; Web-URLs bleiben bei
  `dlp_credential_in_url`) und in Oracle-Thin/OCI-URLs (`jdbc:oracle:thin:user/…@host`).
  `dlp_ldap_bind_password` meldet LDAP-Bind-Passwörter (`ldapsearch … -w`, `bindpw`, `bind_pw`,
  `bindCredential`, `ldap_default_authtok`, `AuthLDAPBindPassword`). Beide verwerfen
  Stellvertreter und Credential-Namen (auch Leetspeak) und gewinnen den Überlapp gegen die
  generische Zuweisung und den URL-Parameter desselben Werts. `dlp_url_userinfo_password` nimmt
  auch Userinfo ohne Benutzernamen (`redis://:…@host`). URL-Userinfo von
  `postgres://`/`mysql://`/`mongodb+srv://`/`amqp://` bleibt bei `dlp_url_userinfo_password`.
  Seit G03 meldet `dlp_cli_password` (`CREDENTIAL`, Untertyp `password`, Stufe strukturelles
  Credential) Passwörter auf Kommandozeilen: `curl -u`/`--user user:…`, MySQL/MariaDB-Clients
  `-p…` (angehängt; `-p db` fragt nach) und `--password=…`, Shell-`PGPASSWORD=…`, `sshpass -p`,
  `docker`/`podman login -p`/`--password`, `htpasswd -b…` (letztes Argument), PowerShell
  `ConvertTo-SecureString "…" -AsPlainText` und `net use \\server\share … /user:`. Prompts,
  `--password-stdin`, `sshpass -e`/`-f` und Referenzen bleiben negativ. Offen: die generische
  Zuweisung liest `$kennwort = ConvertTo-SecureString …` als Wert `ConvertTo-SecureString`.
  Seit G04 meldet `dlp_netrc_password` (`CREDENTIAL`, Untertyp `password`) das Passwort eines
  `.netrc`-Eintrags (`machine <host> login <user> password …`, auch zeilenweise, und `default`;
  der Host ist ein Name mit Punkt, eine Adresse oder `localhost`) und `dlp_docker_config_auth`
  den `auth`-Wert eines Registry-Eintrags in Docker-/Podman-`config.json`/`auth.json`, wenn er zu
  `user:password` decodiert (Prüfung wie bei Basic-Auth). `.npmrc`, `.pypirc`, Maven
  `settings.xml`, `NuGet.Config` und `.s3cfg` decken die generischen und AWS-Regeln schon ab.
  Offen: rclone `pass` ist verschleiert (`rclone obscure`) und wird nicht gemeldet.
  Seit P05 decken elf Provider-Regeln DevOps- und Paket-Registries ab (`SECRET_TOKEN`, Untertyp
  `access_token`): Docker Hub (`dckr_pat_`/`dckr_oat_`, 27 Zeichen), PyPI (`pypi-` und ein
  base64url-Macaroon V2, das vollständig geparst wird: Version, Header mit Location `pypi.org` oder
  `test.pypi.org` (Severity `test`) und Identifier, Caveat-Abschnitte, 32-Byte-Signatur;
  Stärke `structure`), RubyGems (`rubygems_`), crates.io (`cio` und 32 Zeichen mit Groß- und
  Kleinbuchstaben), Private Packagist (`packagist_ort_`/`_out_`/`_uut_`/`_cut_`, 60 Hex-Ziffern
  und die CRC32 von Präfix und Zufallsteil als acht Hex-Ziffern; Stärke `checksum`, eine
  generische Regel meldet ein Packagist-Token mit falscher CRC32 nicht), JFrog (`AKCp`, `cmVmd`),
  HCP Terraform (`.atlasv1.`), Pulumi (`pul-`), Vault (`hvs.`/`hvb.`; das alte `s.`-Format nur mit
  `vault` auf der Zeile oder bis zu fünf Zeilen darüber, `dlp_vault_legacy_token`) und Doppler
  (alle dokumentierten Präfixe). Ein NuGet-API-Key (`oy2…`) hat keine Herstellerquelle für sein
  Format und bleibt ohne eigene Regel; Clojars, Prefect, Infracost, Octopus Deploy, Harness, Snyk,
  Sonar, Codecov und Sourcegraph (Entity-Map `backlog: P05`) bleiben `baseline_only`.
  Seit P06 decken neunzehn Provider-Regeln CI und Hosting ab. Präfix-Regeln mit Token-Grenze:
  Azure DevOps (84 Zeichen mit der Signatur `AZDO` an Position 76–80, beide Schreibweisen),
  CircleCI (`CCIPAT_`/`CCIPRJ_`, Base58-UUID und 40 Hex-Ziffern), Vercel (`vcp_`, `vci_`, `vca_`,
  `vcr_`, `vck_` und 56 Zeichen, Länge der dokumentierten Beispiele), Netlify (`nfp_`), Fly.io
  (`fo1_`; die Base64-Macaroons `fm1a_`/`fm1r_`/`fm2_` als eigene Regel ohne Token-Grenze, weil
  `/` und `+` zum Token gehören), Heroku (`HRKU-AA`), Render (`rnd_`; Render dokumentiert keine
  Länge, deshalb nur mit `render` auf der Zeile oder bis zu fünf Zeilen darüber), Cloudflare
  Origin CA (`v1.0-`) und DigitalOcean (`dop_v1_`/`doo_v1_`/`dor_v1_`). Schlüsselgebunden (Makro
  `provider_key!`: Providername im Schlüssel, ein Credential-Nomen direkt vor dem Trenner, wie die
  gitleaks-Keyword-Regeln, aber enger): Bitbucket-Client-Secret (`API_KEY`), alte Azure-DevOps-PATs
  (52 Zeichen), alte CircleCI- (40 Hex) und Vercel-Tokens (24), Travis CI (22), alte
  Netlify-Tokens, alte Heroku-API-Keys und Railway-Tokens (UUIDs) sowie Cloudflare-API-Token und
  Global API Key. IDs unter Provider-Schlüsseln ohne Credential-Nomen (`HEROKU_APP_ID`,
  `CIRCLE_SHA1`, `RAILWAY_PROJECT_ID`) sind keine Zugangsdaten. Ein Schlüssel ohne Providernamen in
  einem Provider-Abschnitt (`heroku:\n  api_key: …`, Terraform `provider "cloudflare" { api_token
  = … }`) bleibt bei den generischen Regeln. Drone CI, OpenShift, Defined Networking, Fastly und
  SettleMint (Entity-Map `backlog: P06`) bleiben `baseline_only`.
  Seit P07 decken siebzehn Provider-Regeln Observability ab. Tokens sind `SECRET_TOKEN`
  (`access_token`), Schlüssel `API_KEY` (`api_key`). Präfix-Regeln mit Token-Grenze: New Relic
  User Key (`NRAK-`), Insert Key (`NRII-`, 32 oder 25 Zeichen) und Lizenzschlüssel (32 Hex oder
  `eu01xx` und 26, Suffix `FFFFNRAL`), Sentry User Token (`sntryu_`), Grafana-Dienstkonto-Token
  (`glsa_`, Prüfsumme: CRC32 von `glsa_` und Secret, Little-Endian-Hex wie in Grafanas
  `satokengen`) und Dynatrace (`dt0c01`, `dt0s01`–`dt0s16`). Base64-Tokens ohne Token-Grenze werden
  dekodiert und als JSON geprüft (Struktur): Sentry Org Token (`sntrys_`, Payload mit numerischem
  `iat`), alter Grafana-API-Key (`{"k","n","id"}`) und Grafana Cloud (`glc_`, Objekt mit `k`).
  Schlüsselgebunden (`provider_key!`): Datadog (32 Hex oder 40 Zeichen unter `datadog`/`dd_`/
  `ddApi…`), New-Relic-Lizenzschlüssel ohne Suffix (40 Hex), alte Sentry-Tokens (64 Hex), Splunk HEC
  (GUID, auch `Authorization: Splunk`), Elasticsearch (`id:api_key` oder dessen Base64, auch
  `Authorization: ApiKey`; Struktur), Honeycomb (22 Zeichen beider Schreibweisen oder 32 Hex, auch
  `x-honeycomb-team` und `OTEL_EXPORTER_OTLP_HEADERS`) und PagerDuty (20 Zeichen oder 32-Hex-
  Integration-Key; das Schema `Token token=` teilt PagerDuty mit Rails, dort nur mit `pagerduty` auf
  der Zeile oder bis zu fünf Zeilen darüber). Vom Sentry-DSN zählt nur der Secret Key des alten
  Formats (`https://<public>:<secret>@host/<projekt>`); ein DSN mit dem Public Key allein ist laut
  Sentry öffentlich und kein Treffer, ebenso das Datadog-Client-Token (`pub` und 32 Hex) für
  Browser-SDKs, auch nicht unter einem generischen Schlüssel (`value_shape`, `PublicKey`). Ohne
  belegbare Längenangabe bleiben die präfixierten Honeycomb-Ingest-Keys ohne eigene Regel (unter
  einem Honeycomb-Schlüssel greifen die generischen Regeln); Sumo Logic (Entity-Map
  `backlog: P07`) bleibt `baseline_only`.
  Seit P01 decken fünf weitere Regeln LLM-Anbieter ab (`API_KEY`, `api_key`). Präfix-Regeln mit
  Token-Grenze: Perplexity (`pplx-` und 48 Zeichen beider Schreibweisen, gitleaks), OpenRouter
  (`sk-or-v1-` und 64 Hex-Ziffern) und Fireworks AI (`fw_` und 20 bis 40 Zeichen beider
  Schreibweisen), beide nach TruffleHog. Schlüsselgebunden (`provider_key!`): Cohere (40 Zeichen
  beider Schreibweisen unter `cohere` oder `CO_API_KEY`, gitleaks) und DeepSeek (`sk-` und 32
  Kleinbuchstaben/Ziffern unter `deepseek`, TruffleHog). Gemini-/AI-Studio-Schlüssel sind
  Google-API-Keys (`AIza`, `dlp_google_api_key`). Mistral und Together AI dokumentieren kein Format
  und haben keine gitleaks- oder TruffleHog-Regel; sie bekommen keine eigene Regel (unter einem
  Anbieterschlüssel greifen die generischen Regeln).
  Seit P02 kommen drei Präfix-Regeln mit Token-Grenze nach TruffleHog hinzu (`API_KEY`,
  `api_key`): LangSmith (`lsv2_pt_` oder `lsv2_sk_`, 32 Hex-Ziffern, `_`, 10 Hex-Ziffern), Pinecone
  (`pcsk_`, 5 oder 6 Zeichen Schlüssel-ID, `_`, 63 Zeichen beider Schreibweisen) und ElevenLabs
  (`sk_` und 48 Hex-Ziffern). Azure OpenAI, Weights & Biases, AssemblyAI und Deepgram haben kein
  eigenes Präfix; wie TruffleHogs Schlüsselwort-Detektoren binden Kontextregeln ihre Kleinbuchstaben-
  Hex-Werte an den Anbieternamen (`provider_key!` und Client-Aufrufe): Azure OpenAI (32 Ziffern unter
  `azure_openai` oder in `AzureOpenAI(api_key=…)`), Weights & Biases (40 unter `wandb`, nach
  `wandb login` oder in `wandb.login(key=…)`), AssemblyAI (32 unter `assemblyai` oder
  `aai.settings.api_key`) und Deepgram (40 unter `deepgram` oder in `DeepgramClient(…)`). Stability
  AI erkennt weder das gepinnte gitleaks noch TruffleHog; keine Regel.
  Seit P03 decken sechs Regeln Hyperscaler ab (`CLOUD_KEY`): Azure-Storage-Kontoschlüssel nach
  `AccountKey=` (Base64 von genau 64 Bytes, detect-secrets), Entra-ID-Client-Secrets (`…\dQ~` und 31
  bis 34 Zeichen beider Schreibweisen, gitleaks), Alibaba-AccessKey-ID (`LTAI` und 20 Zeichen,
  gitleaks) und -Secret (30 Zeichen unter `alibaba`/`aliyun`, `provider_key!`), langfristige
  Bedrock-API-Schlüssel (`ABSK` und Base64 von `BedrockAPIKey-…`, gitleaks) und IBM-Cloud-API-Keys
  (44 Zeichen unter `ibm`, detect-secrets). Offen bleiben GCP-Service-Account-JSON (die Entity
  bleibt `baseline_only`), AWS-Session-Token/MWS, Tencent Cloud und Oracle OCI.
  Seit P10 decken neun Regeln Produktivitäts-/SaaS-Tokens ab (`API_KEY`): Präfix-Regeln mit
  Token-Grenze für Atlassian (`ATATT3` und 186 Zeichen), Notion (`ntn_`, 11 Ziffern und 35),
  Linear (`lin_api_` und 40), Airtable-PAT (`pat`, 14, `.` und 64 Hex), Postman (`PMAK-`, 24 und
  34 Hex) und Mapbox-Secret-Tokens (`sk.`, TruffleHog), dazu Kontextregeln (`provider_key!`) für
  alte Atlassian-Tokens (24 unter `atlassian`/`jira`/`confluence`), Linear-Client-Secrets (32 Hex)
  und alte Airtable-Keys (`key` und 14). Öffentliche Mapbox-Tokens (`pk.`) und ein Token-Präfix
  mit Platzhalter (`ntn_<…>`) sind auch für generische Regeln kein Secret. Offen bleiben Figma
  (`figd_`, ohne Generator), Asana, monday.com, HubSpot, Salesforce, Zendesk und Intercom (nur
  Kontextformate; die Entities bleiben `baseline_only`).
  Seit C-WALLET (C02 + C03) melden drei Regeln Wallet-Schlüssel (`CRYPTO_KEY`, `private_key`):
  `dlp_bip32_extended_private_key` (BIP 32 / SLIP-0132 `xprv`/`yprv`/`zprv`, Testnetz
  `tprv`/`uprv`/`vprv` mit Schweregrad `test`; Base58Check über 78 Bytes mit den Versionsbytes des
  Präfixes), `dlp_eth_keystore_ciphertext` (`crypto.ciphertext` eines Keystore v3 nur neben `kdf`
  und `mac`) und `dlp_solana_keypair` (64 Bytes als JSON-Array nur nach einem Schlüsselbegriff).
  `xpub`/`tpub`, öffentliche Keystore-Felder und Zahlen-Arrays ohne Schlüsselkontext bleiben
  stumm. `dlp_electrum_seed` (`CRYPTO_KEY`, `seed_phrase`) meldet Electrum-Seeds: 12 Wörter der
  BIP39-Wortliste (Englisch), deren HMAC-SHA512 unter `Seed version` mit dem Präfix eines Seed-Typs
  beginnt (`01`, `100`, `101`, `102`), nur als ganze Wortfolge und nach einem Seed-Begriff auf der
  Zeile oder der Zeile davor. BIP39-Mnemonics ohne dieses Präfix bleiben C01 überlassen.
  `dlp_monero_seed` (`seed_phrase`) meldet die Monero-Mnemonic des privaten Spend-Keys (24 Wörter
  der Monero-Wortliste und das CRC-32-Prüfwort, auch über Zeilenumbrüche) unter demselben
  Seed-Kontext; `dlp_cardano_signing_key` meldet CIP-5-Signierschlüssel (`…_sk1`, `…_xsk1`) nach
  Bech32-Prüfsumme und der Schlüssellänge des Präfixes, Verifikationsschlüssel (`…_vk1`) bleiben
  stumm.
  Seit C-KEYS erkennen acht Regeln Schlüsselmaterial in Konfiguration und Code: private JWKs
  (`kty` und `d` bzw. `k`, als JSON geparst; `PRIVATE_KEY`), WireGuard-`PrivateKey`/`PresharedKey`
  (32 Byte Base64; `PRIVATE_KEY`), OpenVPN-Static-Keys (`<tls-auth>`), IPsec-PSK aus
  ipsec.secrets, symmetrische Schlüssel unter AES-/HMAC-/Encryption-Schlüsselnamen (Hex, Base64,
  Fernet, `0x`-Byte-Arrays), Laravel-`APP_KEY`, Django-`SECRET_KEY` und Rails-`secret_key_base`
  (`CRYPTO_KEY`). Veröffentlichte Testvektoren (RFC 7517/8037, NIST SP 800-38A, FIPS-197) und
  öffentliche Schlüssel sind kein Treffer. Offen bleiben strongSwan-`swanctl.conf`-Secrets und
  Byte-Arrays ohne Schlüsselnamen.
  Seit G-PROSE (G06) melden `dlp_prose_password` (Untertyp `password`) und `dlp_prose_secret`
  (`generic_secret`, generische Stufe) einen Wert, den Chats, Tickets und Mails nach dem
  Credential-Nomen übergeben: nach einem `:` auf der Zeile des Nomens oder der nächsten, am
  Zeilenende oder allein bis zu zwei Zeilen weiter („Wie lautet das Datenbank-Passwort?“ und die
  Antwort, „here is the client secret:“ und der Wert darunter); `Zugangsdaten`/`credentials` nur
  als `benutzer / passwort`. Der Wert muss gewählt oder ausgestellt aussehen
  (`likeness::is_prose_value`: Zeichenklassen wie ein Listeneintrag, ein Buchstabe, kein Datum,
  keine Mail-Adresse, kein nummerierter Bezeichner, reine Buchstaben nur mit zufälligem
  Groß-/Kleinwechsel). Ein Wert direkt nach dem Nomen bleibt bei den Zuweisungsregeln; ein Hash-
  oder anderes Wert-Nomen dazwischen („Passwort-Hash“, „Kennwort (Client-Secret)“) und ein eigenes
  Feld-Label auf einer späteren Zeile („Fundstelle: …“) verwerfen ihn. PIN/TAN/PUK und WLAN-Schlüssel
  (G07) sind noch offen. Seit T20 lesen die schlüsselgebundenen Provider-Regeln (`provider_key!`)
  und `dlp_csrf_token` dieselbe Übergabe (`prose_handover!`) nach Provider-Name und
  Credential-Nomen („(Heroku-API-Schlüssel): …“, „Wie lautet der Wert für „CSRF-Token“?“); der Wert
  durchläuft das Format, den Validator und die Beispielprüfung der Provider-Regel, behält also deren
  `rule_id` (Elastic `id:api_key` als ein Span). Ein ID-Nomen zwischen Nomen und Wert („App-ID:“,
  „project id:“) verwirft ihn bei Provider- und Prosa-Regeln. Dev: die 16 Provider-Entitäten und
  CSRF auf den Prosa-Familien des aktuellen Generators 136/136, `credential.csrf_token` auf dem
  eingefrorenen Dev-Split 40/40.
- Validatoren sind schwach: `is_secret_value` prüft nur Länge, Platzhalter und Env-Referenzen.
  Prüfsummen fehlen ganz: JWT-Struktur und PEM/DER (Base58Check für WIF seit
  K08/F02, GitHub CRC32 seit F03, npm CRC32 seit F04).
  Seit K03 liegen die Bausteine dafür in `rust/src/detectors/validators/` (CRC32-Base62,
  Base58Check, Bech32/Bech32m, Base64/DER, JWT-Header, Entropie, Zeichenklassen; auch für PII);
  angebunden werden sie regelweise in F01–F09.
- Bekannte Präzisionslücken: `dlp_eth_private_key` traf bis F01 jeden 0x-64-Hex-Wert, also auch
  Tx- und Block-Hashes. `dlp_btc_wif` validierte bis K08 die Prüfsumme nicht. `dlp_signed_url_signature`
  (`sig=`) und `dlp_credential_in_url` (`token=`) trafen bis G-URL auch Paginierungs- und
  CSRF-Parameter.
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
| M4 Latenz | Durchsatz ≥ gitleaks und 100 KiB p95 ≲ 15 ms (entschieden 2026-10-24; vorher ≤ 10 ms, gemessen 14,0 ms bei 8,18 vs. 4,16 MiB/s gegen gitleaks), gemessen auf der VPS mit `scripts/l1_dlp/latency.py` |
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
  Das gilt auch für **alle** Hard Negatives im Provider-Format (falsche Länge, falsches Präfix,
  Alphabet oder Prüfsumme): Sie stehen als Rezept mit Mutation im Generator, nie als Literal in
  Generator, Fixtures oder Tests; sonst schlägt die Secret-Prüfung des Gates an (T-NEG, 2026-11-06).
- **Holdout**: Der Generator nutzt einen getrennten Seed **und** getrennte Carrier-Template-Familien
  für Dev und Holdout. Der Benign-Code-Korpus wird nach Repository gesplittet. Die Fixtures von
  gitleaks und detect-secrets sind nur Dev-Smoke-Tests und nie Teil des Holdouts.
- **Defaults**: Neue Secret-Regeln (Gruppen `API_KEY` … `SECRET_TOKEN`) sind sofort aktiv. Neue
  Content- und Dokumentklassen sind standardmäßig aus. Sie werden erst über eine eigene Aufgabe mit
  `needs_decision` eingeschaltet.
- **Dokumentklassen (M01)** laufen auf der Content-Class-Engine
  (`ark-core/src/detectors/dlp/content_class.rs`): Die Regex der Klasse trifft einen starken Anker
  (Marker), der Treffer ist Evidenzspan und Dokumentlabel. Das Label gilt nur, wenn die Anker im
  Fenster um den Marker die Mindestdichte erreichen (stark 3, je mittlerer Anker 2, je struktureller
  Anker 1, je Gegenkontext −3; mindestens ein mittlerer Anker). Neue Klassen (M-MARK, M-LEGAL,
  M-CORP, M-HRSEC) definieren nur Marker-Regex, Ankerlisten und `Density`.
  Seit M-CORP teilen die Klassen Briefstruktur (`LETTER_STRUCTURE`) und generischen Gegenkontext
  (`GENERIC_COUNTER`); die Unternehmensklassen (unveröffentlichte Finanzzahlen/Insiderinformation,
  M&A, Vorstands-/Aufsichtsratsprotokolle und Beschlussentwürfe) verlangen zwei verschiedene
  mittlere Anker. Veröffentlichte Ad-hoc-Mitteilungen, Geschäftsberichte, Pressemitteilungen und
  Stellenanzeigen ziehen über eigene Gegenanker ab.
- **Standardprofil (M23, umgesetzt in M-MARK)**: Einstufungsvermerke
  (`dlp.document.classification_marking`, Regeln `dlp_marking_*`) sind standardmäßig an
  (`DEFAULT_ON_DOCUMENT_GROUPS` in `dlp.rs`), alle anderen Content- und Dokumentklassen opt-in. Ein
  Vermerk zählt nur als Banner (Großschreibung, allein auf der Zeile bis auf Markdown-/Kommentar-
  Dekoration) oder als Wert eines Einstufungsschlüssels; Gegenkontext (Vorlage, Beispiel) und weitere
  Stufen derselben Familie im Umkreis von 160 Byte (Artikel, Enums) heben ihn auf.
- Montags läuft `TRIAGE` wie bei PII.

## Abgrenzung

- `secret_transfer`/`destructive_operation` (Aktions-DLP, Threat-Matches) gehören nicht zu diesem
  Programm. Nur Verweise auf sensible Pfade (`~/.aws/credentials`) kommen hier als Kontext hinein
  (G13).
- Personenbezogene Werte (IBAN, Ausweis, USt-IdNr. natürlicher Personen) gehören zu PII. Dubletten
  wie USt-IdNr., HR-Nummer und BSNR klärt F15.
- Keine Live-Verifikation von Secrets, kein Netzwerkzugriff im Detektor.
