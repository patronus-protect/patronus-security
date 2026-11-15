# Kategorie `exfiltration`

Stand: 2026-11-09, Entwurf zur Freigabe. Gliederung wie [`injection.md`](injection.md); Begriffslisten sind
Auszüge, die vollständigen Lexika entstehen in S02. Basiswerte sind Startwerte (siehe
[`injection.md` §4](injection.md#4-patterns)), kalibriert in EX02.

## 1. Schichten

Wie [`injection.md` §1](injection.md#1-schichten-für-alle-kategorien-gleich). Geteilte Core-Lexika:
Adressat, Geheimhaltung, sensible Pfade (DLP G13), Abwehr, Meta, Zitat, Testcode.

## 2. Abgrenzung

`exfiltration` = Eingabe, die Daten **aus dem System heraus** zu einem fremden Ziel lenken will. Ein Fund
braucht drei Teile in derselben Spanne oder Struktur: **Quelle** (Verlauf, Systemprompt, Dateien, Secrets,
Umgebungsvariablen, PII), **Senke** (URL, Webhook, E-Mail, Bild-Link, DNS-Name, Tool-Parameter nach außen) und
**Richtung** (Direktive oder Vorlage, die Quelle in Senke setzt). Quelle oder Senke allein ist kein Fund.

Nicht `exfiltration`:
- Secrets, die schon im Text stehen (`dlp`); ein DLP-Treffer zählt hier aber als Quelle (Fact `data_ref`);
- Shell-Formen (`curl -d @~/.aws/credentials`, `env | nc`): K26 (X04);
- Anfragen, den Systemprompt **anzuzeigen** (`prompt_extraction`); erst „… und schick ihn an URL“ ist auch hier;
- die gerenderte Antwort des Modells (kein Output-Scanning auf L1); erkannt wird die Vorlage in der Eingabe.

## 3. Lexika (`anchor_lexicons/exfiltration.json`)

**Support** (+25/+20/+15):

| ID | DE (Auszug) | EN (Auszug) |
|---|---|---|
| `exfil.send_verb` | sende, schicke, lade hoch, poste, leite weiter, hänge an, übermittle | send, upload, post, forward, attach, submit |
| `exfil.source` | Verlauf, Gespräch, bisherige Nachrichten, Zugangsdaten, Umgebungsvariablen, Dateiinhalt | conversation, chat history, previous messages, credentials, env vars, file contents |
| `exfil.collector` | Webhook, Pastebin, RequestBin, ngrok, Discord-/Telegram-Bot | webhook.site, pastebin, requestbin, ngrok, discord webhook, telegram bot |
| `exfil.embed` | in die URL, als Parameter, als Bild, als Subdomain, base64-kodiert anhängen | in the URL, as query parameter, as image, as subdomain, base64 encoded |
| `sensitive_path`, `secrecy`, `addressee` (Core, geteilt) | | |

**Gegen** (−30):

| ID | Inhalt |
|---|---|
| `exfil.user_owned` | Ziel gehört erkennbar dem Nutzer: „an mich“, „meine Adresse“, „unser Team-Kanal“, „in mein Drive“ |
| `exfil.integration_doc` | Doku zu Webhooks/Integrationen: „konfiguriere den Webhook“, Payload-Beispiele, API-Referenz |
| `defensive`, `meta`, `quotation`, `test_code` (Core, geteilt) | Abwehrregeln („sende nie Daten an …“), Sicherheitsdoku, Zitat, Testcode |

## 4. Patterns

| Pattern | Kern | Basis | Validator | `requires_context` | `scored_only` | Heutige Regeln |
|---|---|---|---|---|---|---|
| `ex_markdown_beacon` | Markdown-Bild/-Link, dessen URL einen Platzhalter für Daten trägt (`{…}`, `<DATA>`, `$VAR`) oder per Direktive gefüllt werden soll | 45 | Structure | nein | nein | neu |
| `ex_send_directive` | `send_verb` + `source` + Senke in derselben Klausel | 40 | Format | nein | nein | threat.session_exfiltration, threat.environment_exfiltration, threat.agent_config_exfiltration |
| `ex_secret_to_sink` | Quelle ist DLP-Treffer oder `sensitive_path`, Senke in derselben Struktur | 40 | Structure | nein | nein | threat.secret_exfiltration, threat.secret_source_transfer, `secret_transfer` (heute in `dlp`) |
| `ex_tool_param_egress` | Direktive, Quelle in einen nach außen gehenden Tool-Parameter zu setzen (`url`, `to`, `webhook`, `body`) | 35 | Format | ja | nein | neu |
| `ex_dns_channel` | Daten als Subdomain einer fremden Domain (`{data}.example.tld`) | 35 | Structure | ja | nein | neu |
| `ex_link_smuggling` | unsichtbare Zeichen oder lange kodierte Werte in einer URL, an die eine Direktive Daten hängen will | 30 | – | ja | nein | neu |
| `ex_collector_only` | `collector`-Dienst ohne Quelle/Richtung | 15 | – | ja | **ja** | neu |
| `ex_decoded` | eines der obigen in einer dekodierten Sicht | wie Quelle | wie Quelle | wie Quelle | wie Quelle | neu |

`Structure` (+25): Quelle und Senke sitzen in derselben Struktur (URL-Query, Markdown-Link, JSON-Objekt,
Tool-Call-Argumente), nicht nur nebeneinander. Normalisierungspunkte: Plus wie bei `injection`. Modi wie PII.

## 5. Struktur und Träger

- Senken liefert der Core aus dem Text: URLs (mit Query-Teilen und Platzhaltern), E-Mail-Adressen,
  Markdown-Links/-Bilder, Domain-Namen, Tool-Call-Argumente.
- Quellen: Lexikon `source`, `sensitive_path` und Secret-Treffer aus der DLP-Erkennung. Die DLP-Erkennung
  läuft für `exfiltration` **immer intern**, auch wenn `dlp` nicht aktiv ist; sie meldet dann keine
  DLP-Findings, sondern liefert nur die Quelle (festgelegt 2026-11-09). Damit L1 schnell bleibt, läuft sie
  nur auf Fenstern, in denen der Core eine Senke gefunden hat. PII-Treffer zählen nur, wenn `pii` aktiv ist.
- Träger wie bei `injection` (`carrier=indirect` +25); Exfil steckt meist in Fremdinhalt.

## 6. Facts (Auszug)

`finding{…}`, `source{kind=history|system_prompt|file|secret|env|pii, data_ref}`,
`sink{kind=url|email|image|dns|webhook|tool_param, collector, templated}`, `direction{directive|template}`,
`carrier`, `secrecy`, Modifikatoren wie `injection`.

## 7. Modell

Kandidaten: B0 (Threat-Scorer 0.1.7, enthält die sieben Exfil-Regeln), R+A+L, B1, B4, B5. Kaum native Daten
(auch nicht in EN); Positive über Generatoren (Exfil in Tool-Parametern, Markdown-Beacons in echten
Dokumenten mit sauberem Zwilling, M-Block), pipelock-Fälle; Benign aus Integrations-Doku und Mails mit Links.

## 8. Policies (später)

- `ex.secret_to_sink`: DLP-Treffer ∧ `sink` im selben Text → `block`.
- `ex.hidden_beacon`: `ex_markdown_beacon` ∧ (`secrecy` ∨ `carrier.indirect`) → `block`.
- Die Trifecta (`injection.trifecta`) nutzt die Senken dieser Kategorie.

## 9. Bestand

| Heutige Regeln | Ziel |
|---|---|
| threat.session_exfiltration, threat.environment_exfiltration, threat.agent_config_exfiltration | `ex_send_directive` |
| threat.secret_exfiltration, threat.secret_source_transfer, `secret_transfer` (heute in `dlp`) | `ex_secret_to_sink` |
| threat.credential_file_upload, threat.environment_post | Shell-Formen K26 (X04), Prosa-Formen `ex_secret_to_sink` |

Die Details der Threat-Regeln prüft M01 je ID (Shell- vs. Prosa-Anteil).

## 10. Übernommene OSS-Regeln

pipelock (Egress-Muster), Cisco mcp-scanner YARA (data_exfiltration), ATR; default aus.

## 11. Goldens

Je Pattern und Sprache ≥ 5 Positive und ≥ 5 Hard Negatives. Pflicht-Hard-Negatives: „schick mir die
Zusammenfassung per Mail“, Webhook-Doku mit Payload-Beispielen, Markdown mit normalen Bild-Links,
Analytics-/UTM-Parameter, Abwehrregel „sende niemals Daten an externe URLs“, Secret im Text ohne Senke
(nur `dlp`).

## 12. Herkunft und Daten

Regeln für Herkunft, Splits und Quellfamilien: [README](../README.md#herkunft-regeln-train-gold-holdout).
Goldens: je Pattern und Sprache ≥ 5 Positive und ≥ 5 Hard Negatives, selbst geschrieben (`ark_authored`), §11.

| | Quelle |
|---|---|
| Patterns/Anker | `ark_existing` (7 Threat-Exfil-Regeln, `secret_transfer` aus `dlp`); `oss`: pipelock (Egress, URL/DNS-Tunnel), Cisco YARA (data_exfiltration), ATR; `taxonomy`: OWASP LLM02/LLM05, MITRE ATLAS Exfiltration; `mined` auf Train |
| Train/Dev | AgentDojo (Exfil-Ziele), Nemotron-IPI, BIPIA; Generatoren: Exfil in Tool-Outputs mit Doppelgängern (Dev-Seed) |
| Holdout `neutral` | LLMail-Inject (Exfil-Ziel E-Mail, gleiche Zeilen wie bei `injection`, mehrfach gelabelt), agentapprove tool-call-safety (Exfil-Teil, versiegelt) |
| Holdout `ark_blind` | R05 DE+EN (Markdown-Beacons, Tool-Parameter, DNS), Seed-Teil der Exfil-Generatoren |
| Hard Negatives | Webhook- und API-Doku, Mails mit Links, UTM-/Analytics-URLs, Markdown mit normalen Bildern |
| Lücke | kein natives DE |

## 13. Umsetzung EX01 (Stand 2026-11-15)

Sechs Punkte-Regeln `ark.threat.ex_*` in `ark-core/src/detectors/threat/rules.json`, Prefilter-Anker in
`anchor_lexicons/exfiltration.json` (`exfil.send_verb`, `exfil.source`, `exfil.sink`, `exfil.collector`,
`exfil.placeholder`, `exfil.embed`, `exfil.put_verb`):

| Regel | Basis | Validator | Kern |
|---|---|---|---|
| `ex_markdown_beacon` | 45 | Structure | `![…](URL…=` bzw. `/` + Platzhalter mit Datenwort (`{chat_history}`, `<summary …>`, `$SECRET`, `[…]`, Großschreibung wie `CHAT_HISTORY`) |
| `ex_send_directive` | 40 | Format | `send_verb` + `source` + Senke (URL, E-Mail-Adresse, Collector) |
| `ex_secret_to_sink` | 40 | Structure | `send_verb` … Senke; Quelle zwischen beiden ist ein DLP-Treffer oder ein sensibler Pfad |
| `ex_tool_param_egress` | 35 | Format | `put_verb` + `source` + „in/als“ + ausgehender Parameter (`url`, `to`, `webhook`, `body` …) |
| `ex_dns_channel` | 35 | Structure | Platzhalter-Label vor fremdem Host, oder `source` … „als Subdomain(s) von“ Host |
| `ex_link_smuggling` | 35 | Format | URL mit ≥ 3 unsichtbaren Zeichen (ZW*, Tag-Zeichen) oder „hänge kodierten `source` an jeden Link“ |

- DLP als Quelle: `ex_secret_to_sink` ruft die DLP-Pipeline (jetzt einmal pro Prozess, `DlpPipeline::shared`)
  nur auf der Spanne zwischen Verb und Senke auf; sie meldet dort nichts Eigenes.
- `exfil.user_owned` steckt vorerst im Code (`user_owned`: my/our/me, mein*/unser*/mich/mir/uns zwischen
  Quelle und Senke), noch kein Kontext-Lexikon.
- Offen: pipelock-Ernte (in `oss_rules.yaml` inventarisiert: External Data Transfer Directive, Markdown Link
  Credential (Value/Follow) Exfiltration, Covert Action Directive) braucht einen default-aus-Schalter im
  Threat-Katalog; `ex_collector_only` (scored_only) und `exfil.integration_doc` folgen mit EX02.
- Latenz (Release, 100 KiB-Fenster aus deutscher Repo-Prosa, nur `exfiltration`): p95 5,2 ms ohne vs. 8,4 ms mit
  den sechs Regeln (ohne Treffer je Regel +0,0–0,3 ms; der Rest ist der Klausel-Kontext-Scan nach einem Treffer).
  Voraussetzung: der Threat-Katalog baut seine Regexe mit dem DLP-Cache-Limit (`RULE_DFA_CACHE_BYTES`), sonst
  lief der Lazy-DFA über (p95 178 ms). Messung mit `scripts/l1_threat/latency.py` auf dem Gate-Korpus steht aus.

## 14. Stand EX02 (2026-11-15): Punkte und Ablations-Entscheidung

**Entscheidung: `B0` bleibt** — die Punkte-Regeln aus EX01/EX02 mit handgesetztem Klauselkontext
entscheiden allein (der Threat-Scorer 0.1.7 bleibt für die Altregeln); kein gelerntes Modell wird
einkompiliert. Neu bewerten, sobald echte Exfiltrations-Daten jenseits der Generator-Vorlagen im
Dev-Split liegen (LLMail-Inject und agentapprove bleiben Holdout).

Daten (nur Dev, wie TP02/AC02): die 300 `exfiltration`-Zeilen aus
`generators_dev_seed:exfil_lookalikes` (`file_read` 115, `cli_log` 96, `json_result` 89; je 150 DE/EN)
gegen 15 617 Benign-Zeilen (alle Benign-Zeilen von `generated` — darin die 300 Doppelgänger der
Vorlagen — und `report`, dazu SPML und je ein Viertel von Dolly und GermanQuAD per sha256 der ID),
Hälften per sha256 der Zeilen-ID (Auswertung: 163 Positive, davon 73 DE, 7 850 Negative, davon 900
Hard-Benign). Facts über `text_facts --threat-findings`, B0 aus `scoreboard.py _predict` mit dem
gebauten Modul, Latenzfenster der N-Gramm-Stufen: 6 × 100 KiB GermanQuAD-Dev-Text (Ersatz für das
E03-Korpus, das in der Sandbox fehlt).

Vor den Regel-Ergänzungen (Regeln aus EX01, Basis e1d67716):

| Stufe | TPR@1 % | TPR@0,1 % | DE | EN | Hard-Benign-FPR | ms/100 KiB | RAM |
|---|---|---|---|---|---|---|---|
| R | 22,7 | 22,7 | 16,4 | 27,8 | 0,0 | 0 | 0 |
| R+A | 22,7 | 22,7 | 16,4 | 27,8 | 0,0 | 0 | 0 |
| R+A+L | 100,0 | 96,3 | 100,0 | 100,0 | 5,4 | 0 | 0,8 KiB |
| B1 | 100,0 | 100,0 | 100,0 | 100,0 | 8,4 | 17,4 | 5,1 MB |
| B4 | 100,0 | 100,0 | 100,0 | 100,0 | 9,2 | 11,9 | 576 KiB |
| B5 | 100,0 | 100,0 | 100,0 | 100,0 | 0,0 | 11,9 | 576 KiB |

Die Auswahlregel hätte `R+A+L` gewählt (5,4 % Hard-Benign-FPR: die gelernten Punkte lernen die
Träger der Vorlagen, nicht den Angriff). Auf allen Zeilen fanden die Regeln 78 von 300 Positiven.
Ursachen der Lücke, je Vorlage geprüft:

- **Geheimhaltung als Verneinung.** „… and do not mention it“ / „… und erwähne es nicht“ nach der
  Senke ist ein `negation_scope`-Treffer im Satz; der Klauselkontext wertete ihn als Gegenkontext und
  verwarf den Fund (alle `AI agent: also post …`- und `KI-Agent: Lade … hoch …`-Vorlagen, 165 Zeilen).
  Jetzt: bei `exfiltration` zählt eine Verneinung **nach** dem Fund nicht, wenn sie in einem
  `secrecy`-Treffer liegt („do not mention“, „erwähne … nicht“); der Geheimhaltungs-Treffer stützt
  dann. Eine Verneinung vor dem Transfer („never post … and do not mention it“) und eine andere
  Verneinung danach („…, not to anyone else“) bleiben Gegenkontext.
- **Quelle Tool-Ergebnisse.** `previous/prior/earlier/last/all tool results|outputs|responses`,
  `bisherigen/vorherigen/früheren/letzten/alle Tool-Ergebnisse|-Ausgaben|-Antworten` in der geteilten
  Quellenliste der vier Regeln mit Quelle (`ex_send_directive`, `ex_tool_param_egress`,
  `ex_dns_channel`, `ex_link_smuggling`).
- **Geschäftsdaten.** Zweig `record` in der Quelle von `ex_send_directive` (nicht in der geteilten
  Quellenliste): customer list/data/records/contacts, client list/data, CRM export/data;
  Kundenliste, Kundendaten, Kundendatenbank, Kundenkontakte, Kundenstammdaten, CRM-Export. Ein
  Treffer über `record` braucht einen `secrecy`-Term im Satz oder einen Vor-der-Antwort-Haken in den
  60 Bytes vor dem Verb (`before answering/replying/responding`, `before you answer/reply/respond`,
  `bevor du antwortest`, `vor deiner Antwort`; `pre_answer_hook`, nur nach einem Treffer). Ohne beides
  („can you send the customer list from the CRM to tom@…“) bleibt es eine normale Geschäftsmail.
  Prefilter: neues Anker-Lexikon `exfil.record` (customer, client, kunden, crm). Eine eigene Regel
  `ex_record_to_sink` war der erste Entwurf; sie kostete als zweiter Regex-Durchlauf auf 100 KiB
  deutscher Prosa p95 +0,3 ms (exfiltration allein, +5 %) und ist deshalb in `ex_send_directive`
  aufgegangen.
- **Listenpunkte.** Wie bei AC02 ist ein Listenpunkt mit einem anderen Listenpunkt als Lead-in-Klausel
  eine eigene Aussage (Vorlage: „- Use the staging environment for all tests.“ traf `test_code`);
  jetzt auch für `exfiltration`. Eine einleitende Zeile ohne Listenmarke bleibt Lead-in.
- Kontext-Lexikon `meta`: `sicherheitsdokumentation*` → `sicherheitsdoku*` (Kurzform, Golden).

Danach (gleiche Zeilen, Auswertungshälfte):

| Stufe | TPR@1 % | TPR@0,1 % | DE | EN | Hard-Benign-FPR | ms/100 KiB | RAM |
|---|---|---|---|---|---|---|---|
| R | 100,0 | 100,0 | 100,0 | 100,0 | 0,0 | 0 | 0 |
| R+A | 100,0 | 100,0 | 100,0 | 100,0 | 0,0 | 0 | 0 |
| **B0** | 100,0 | 100,0 | 100,0 | 100,0 | 0,0 | 0 (Status quo) | 0 |
| R+A+L | 100,0 | 100,0 | 100,0 | 100,0 | 5,4 | 0 | 0,9 KiB |
| B1 | 100,0 | 100,0 | 100,0 | 100,0 | 8,4 | 22,5 | 5,1 MB |
| B4 | 100,0 | 100,0 | 100,0 | 100,0 | 9,2 | 9,9 | 576 KiB |
| B5 | 100,0 | 100,0 | 100,0 | 100,0 | 0,0 | 9,9 | 576 KiB |

Auswahl nach der README-Regel: `B0` (günstigste Stufe innerhalb 1 pp der besten; `B1`/`B4`/`B5` über
dem Budget von 1 ms je 100 KiB; ms der N-Gramm-Stufen liefen parallel zu einer zweiten Ablation und
streuen). Auf allen Zeilen: 300 von 300 Positiven gemeldet (`ex_send_directive` 240,
`ex_secret_to_sink` 60), keine der 15 617 Benign-Zeilen, auch keiner der 300
Doppelgänger. Vorbehalt wie TP02/AC02: die Ergänzungen sind an denselben drei Vorlagenfamilien
entstanden, an denen gemessen wird; die Zahl ist eine Obergrenze, das Urteil fällt auf dem Holdout.

Offen: die Altregeln `ark.threat.secret_exfiltration` (Threat-Scorer) und `native:secret_transfer`
werten Zitat- und Schulungs-Kontext nicht aus und melden ein zitiertes Beispiel mit `.env` bzw.
API-Schlüsseln (deshalb nennen die neuen Meta-Goldens Verlauf/Tool-Ergebnisse); der Klauselkontext
der Punkte-Regeln wertet Anführungszeichen bewusst nicht (JSON-Tool-Ausgaben zitieren jeden
Angriff); `ex_collector_only` und `exfil.integration_doc` aus §13 weiter offen; Geheimhaltung über
mehrere Sätze.
