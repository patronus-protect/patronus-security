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
