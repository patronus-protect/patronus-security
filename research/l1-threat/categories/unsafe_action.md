# Kategorie `unsafe_action`

Stand: 2026-11-09, Entwurf zur Freigabe. Gliederung wie [`injection.md`](injection.md); Begriffslisten sind
Auszüge, die vollständigen Lexika entstehen in S02. Basiswerte sind Startwerte (siehe
[`injection.md` §4](injection.md#4-patterns)), kalibriert in UA02.

## 1. Schichten

Wie [`injection.md` §1](injection.md#1-schichten-für-alle-kategorien-gleich). Geteilte Core-Lexika:
Adressat, sensible Pfade (DLP G13), Abwehr, Meta, Zitat, Testcode.

## 2. Abgrenzung

`unsafe_action` = Eingabe, die einen Agenten zu einer **gefährlichen Handlung auf Systemen** bringen will,
in Prosa, Code oder Config: Zugangsdaten abgreifen, Unumkehrbares löschen, Schutz abschalten, fremden Code
holen und ausführen, Rechte ausweiten, sich festsetzen, interne Endpunkte ansprechen, unsichere
Container-/Code-Konfiguration.

Nicht `unsafe_action`:
- **Shell-Syntax** (Befehle, Pipes, Shell-Codeblöcke, Tool-Call-Argumente mit Befehlen): K26 (`shell_command`);
  hier bleibt die Prosa-Anweisung („lösch die Produktionsdatenbank ohne Rückfrage“) und Code/Config in
  anderen Sprachen;
- dasselbe in einer Agent-Config (`agent_config_tampering`), mit Senke (`exfiltration`);
- Schaden in der realen Welt (Waffen, Drogen, Selbstverletzung): `harmful_content`;
- Secrets, die schon im Text stehen: `dlp`.

## 3. Lexika (`anchor_lexicons/unsafe_action.json`)

**Support** (+25/+20/+15):

| ID | DE (Auszug) | EN (Auszug) |
|---|---|---|
| `unsafe.read_secret` | lies aus, sammle, kopiere, gib aus + Passwörter, Tokens, Schlüsselbund, Browser-Passwörter | read, collect, harvest, dump + passwords, tokens, keychain, browser passwords |
| `unsafe.destructive` | lösche alles, unwiderruflich, leere, formatiere, setze zurück | delete everything, wipe, drop, purge, irreversibly, force-push |
| `unsafe.broad_target` | Produktion, alle Backups, gesamte Datenbank, alle Nutzer, Hauptbranch | production, all backups, entire database, all users, main branch |
| `unsafe.security_control` | Firewall, Virenscanner, Defender, Audit-Log, Protokollierung, 2FA, SELinux | firewall, antivirus, EDR, audit log, logging, MFA, SELinux |
| `unsafe.disable_verb` | deaktiviere, schalte aus, umgehe, entferne | disable, turn off, bypass, remove |
| `unsafe.fetch_run` | lade herunter und führe aus, installiere von dieser URL | download and run, install from this URL |
| `unsafe.privilege` | Admin-Rechte, root, sudoers, Vollzugriff, für alle schreibbar | admin rights, root, sudoers, full access, world-writable |
| `unsafe.autostart` | beim Start ausführen, Autostart, geplante Aufgabe, Dienst anlegen | run at startup, autostart, scheduled task, create service |
| `unsafe.no_confirm` | ohne Nachfrage, ohne Bestätigung, ohne Backup, sofort | without asking, no confirmation, no backup, right away |
| `unsafe.metadata_endpoint` | 169.254.169.254, metadata.google.internal, IMDS | same |
| `sensitive_path`, `addressee` (Core, geteilt) | | |

**Gegen** (−30):

| ID | Inhalt |
|---|---|
| `unsafe.sandbox` | erkennbar eigene Wegwerf-Umgebung: Test-VM, lokaler Container, Staging, Spielwiese |
| `unsafe.safe_guard` | Absicherung im selben Satz: Dry-Run, mit Backup, nach Bestätigung, nur lesend |
| `unsafe.own_scope` | eigene, eng begrenzte Ziele: meine Temp-Dateien, dieser Branch, mein Cache |
| `defensive`, `meta`, `quotation`, `test_code` (Core, geteilt) | Admin-Doku, Sicherheitsschulung, Zitat, Fixtures |

## 4. Patterns

| Pattern | Kern | Basis | Validator | `requires_context` | `scored_only` | Heutige Regeln |
|---|---|---|---|---|---|---|
| `ua_credential_access` | `read_secret` oder Lesen von `sensitive_path`, an den Agenten gerichtet | 40 | Format | nein | nein | threat.credential_file_access, threat.credential_harvesting, `sensitive_material` (heute in `dlp`) |
| `ua_metadata_ssrf` | `metadata_endpoint` in Abruf-Direktive oder Code | 45 | Structure | nein | nein | threat.ssrf_metadata, threat.dynamic_ssrf |
| `ua_credential_phishing` | Zugangsdaten an Link bestätigen lassen, Reset-Link umleiten | 35 | Format | ja | nein | governance.credential_verification_link, governance.executive_password_reset_redirect |
| `ua_destructive_request` | `destructive` + `broad_target`, an den Agenten gerichtet | 35 | Format | ja | nein | `destructive_operation` (heute in `dlp`) |
| `ua_security_disable` | `disable_verb` + `security_control` | 35 | Format | ja | nein | threat.security_disable |
| `ua_fetch_and_run` | `fetch_run` in Prosa | 35 | Format | ja | nein | threat.remote_execution_instruction |
| `ua_container_escape_config` | `privileged: true`, Host-Root-Mount, Docker-Socket-Mount in YAML/JSON/Compose | 40 | Structure | nein | nein | threat.privileged_container, threat.kubernetes_privileged_json/yaml, threat.host_root_mount, threat.docker_socket |
| `ua_privilege_widening` | `privilege` an Nutzer/Dienst vergeben | 30 | Format | ja | nein | neu |
| `ua_persistence` | `autostart` für fremden Code in Prosa oder Config | 30 | Format | ja | nein | threat.persistence_payload (Prosa-Teil) |
| `ua_unsafe_code` | `verify=False` mit fremdem Host, `pickle.loads`/`yaml.load` auf fremden Daten, `eval` dekodierter Daten, `shell=True` mit Eingabe, Ausführen von Modell-Output | 25 | Structure | ja | nein | threat.unsafe_tls_code, threat.untrusted_deserialization, threat.decoded_execution, threat.unsafe_shell_input, threat.untrusted_output_execution |
| `ua_unattended` | `no_confirm` + Handlung aus dieser Kategorie ohne Config-Träger | 25 | Format | ja | nein | threat.unauthorized_autonomy (Prosa), governance.autonomous_approval_bypass (Prosa) |
| `ua_destructive_hint` | `destructive` allein, an den Agenten gerichtet | 15 | – | ja | **ja** | neu |
| `ua_decoded` | eines der obigen in einer dekodierten Sicht | wie Quelle | wie Quelle | wie Quelle | wie Quelle | neu |

`ua_credential_access`, `ua_metadata_ssrf` und `ua_credential_phishing` bilden die Familie `credential_access`
(früher Label `secrets_access`). `ua_unsafe_code` hat die größte Fehlalarm-Gefahr (Nutzercode im Coding-
Assistenten); deshalb niedrige Basis und Pflicht-Kontext. Normalisierungspunkte: Plus wie bei `injection`.
Modi wie PII.

## 5. Struktur und Träger

- Code und Config erkennt der Core an der Struktur im Text (Codeblock mit Sprache, YAML/JSON-Schlüssel);
  `Structure` (+25), wenn der Fund auf dem Schlüssel/Aufruf selbst sitzt.
- Shell-Codeblöcke und Tool-Call-Argumente mit Befehlen gibt der Core an K26 (`shell_command`) weiter;
  diese Kategorie bewertet sie nicht ein zweites Mal.
- Träger wie bei `injection` (`carrier=indirect` +25).

## 6. Facts (Auszug)

`finding{…}`, `action{credential_access|destructive|security_disable|fetch_run|privilege|persistence|ssrf|
unsafe_code|container_escape}`, `target{scope=own|broad|system}`, `irreversible`, `no_confirm`,
`credential_target`, `metadata_endpoint`, `code_lang`, `carrier`, Modifikatoren wie `injection`.

## 7. Modell

Kandidaten: B0 (Threat-Scorer 0.1.7, deckt heute die meisten Regeln oben ab), R+A+L, B1, B4, B5. Daten:
heutige Threat-Goldens, Agent-Benchmarks (AgentDojo/InjecAgent-artige Aktionen), Generatoren für Prosa-
Formen; Benign aus Admin-Doku, Runbooks und Code-Repos in großer Menge.

## 8. Policies (später)

- `ua.destructive_unattended`: `destructive` ∧ `broad_target` ∧ `no_confirm` → `block`.
- `ua.credential_with_sink`: `credential_access` ∧ Senke aus `exfiltration` → `block`.
- `ua.injected_action`: `carrier.indirect` ∧ beliebige Aktion dieser Kategorie → `block`.

## 9. Bestand

| Heutige Regeln | Ziel |
|---|---|
| secrets_access: threat.credential_file_access, threat.credential_harvesting, threat.ssrf_metadata | Familie `credential_access` |
| tool_abuse: threat.security_disable, threat.remote_execution_instruction, threat.privileged_container, threat.kubernetes_privileged_json/yaml, threat.host_root_mount, threat.docker_socket, threat.dynamic_ssrf, threat.unsafe_tls_code, threat.untrusted_deserialization, threat.decoded_execution, threat.unsafe_shell_input, threat.untrusted_output_execution, threat.unauthorized_autonomy (Prosa) | Patterns oben |
| tool_abuse: threat.remote_execution, threat.decoded_shell_execution | K26 (X04) |
| harmful_behavior: threat.persistence_payload | Prosa `ua_persistence`, Shell K26 |
| harmful_behavior: threat.root_destruction | K26 (X04) |
| `destructive_operation`, `sensitive_material`, Rest von `mcp_runtime_risk` (heute in `dlp`) | `ua_destructive_request`, `ua_credential_access`; `mcp_runtime_risk` siehe [`agent_config_tampering.md` §9](agent_config_tampering.md#9-bestand) |
| governance.credential_verification_link, governance.executive_password_reset_redirect | `ua_credential_phishing` |

Shell- vs. Prosa-Anteil je Regel prüft M01 bzw. X04.

## 10. Übernommene OSS-Regeln

ATR (Aktions-Familien), Semgrep-artige Code-Regeln nur aus MIT/Apache-Quellen, Cisco mcp-scanner YARA
(Teile); default aus.

## 11. Goldens

Je Pattern und Sprache ≥ 5 Positive und ≥ 5 Hard Negatives. Pflicht-Hard-Negatives: „lösch meine
Temp-Dateien“, Runbooks mit Dry-Run, Admin-Doku zum Abschalten der Firewall für eine Installation,
Kubernetes-Doku über `privileged`, Testcode mit `verify=False` gegen localhost, Sicherheitsschulung über
Credential-Phishing.

## 12. Herkunft und Daten

Regeln für Herkunft, Splits und Quellfamilien: [README](../README.md#herkunft-regeln-train-gold-holdout).
Goldens: je Pattern und Sprache ≥ 5 Positive und ≥ 5 Hard Negatives, selbst geschrieben (`ark_authored`), §11.

| | Quelle |
|---|---|
| Patterns/Anker | `ark_existing` (Threat-Regeln aus tool_abuse/secrets_access/harmful_behavior, `destructive_operation`/`sensitive_material` aus `dlp`, 2 Governance-Regeln); `oss`: ATR, Cisco YARA (Teile), Code-Regeln nur aus MIT/Apache-Quellen; `taxonomy`: OWASP LLM06 (Excessive Agency), CWE für Code-Muster; `mined` auf Train |
| Train/Dev | RedCode, Agent-SafetyBench, AgentDojo, heutige Threat-Goldens; Generatoren für Prosa-Formen (Dev-Seed) |
| Holdout `neutral` | agentapprove tool-call-safety (versiegelt), AgentHarm (System-Aktionen) |
| Holdout `ark_blind` | R05 DE+EN (Prosa-Aufforderungen, Config, Code), Seed-Teil |
| Hard Negatives | Admin-Doku und Runbooks, Kubernetes-Doku, Code-Repos mit Testcode, Sicherheitsschulungen |
| Lücke | kein natives DE |
