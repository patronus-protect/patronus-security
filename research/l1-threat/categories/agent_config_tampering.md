# Kategorie `agent_config_tampering`

Stand: 2026-11-09, Entwurf zur Freigabe. Gliederung wie [`injection.md`](injection.md); Begriffslisten sind
Auszüge, die vollständigen Lexika entstehen in S02.

## 1. Schichten

Wie [`injection.md` §1](injection.md#1-schichten-für-alle-kategorien-gleich). Geteilte Core-Lexika:
Adressat, Geheimhaltung, sensible Pfade (DLP G13), Meta, Zitat, Testcode.

## 2. Abgrenzung

`agent_config_tampering` = bösartiger Inhalt in **Dateien, die ein Agent als Konfiguration oder Anleitung
lädt**, oder Text, der solche Dateien bösartig ändern will:
- Skills (`SKILL.md` + Frontmatter), Rules-Dateien (`AGENTS.md`, `CLAUDE.md`, `.cursorrules`,
  `.github/copilot-instructions.md`, `.windsurfrules`);
- Agent-Settings und Hooks (`settings.json` mit `permissions`/`hooks`, `.claude/`, `.cursor/`);
- MCP-Server-Konfiguration (`mcp.json`, `mcpServers`, `command`/`args`/`env`).

Typisch: versteckte Direktiven, Freigaben ausweiten (Auto-Approve, `allow: *`, Sandbox aus), Schutz-Hooks
entfernen, Fetch-and-run in Skill-Text, MCP-Server mit fremdem Befehl oder Secret-Weitergabe eintragen.

L1 sieht nur Text. Den Träger erkennt der Core an der Struktur im Text: Dateiname/Pfad im Text
(Codeblock-Überschrift, Diff-Kopf, `--- a/AGENTS.md`), Frontmatter, bekannte JSON-Schlüssel.

Nicht `agent_config_tampering`:
- Tool-Beschreibungen und Schemas (`tool_poisoning`);
- dieselbe Direktive ohne Config-Träger (`injection`);
- Shell-Befehle selbst, auch in `command`/`hooks` (K26; der Fund hier ist das **Eintragen** in die Config);
- gefährliche Handlungen ohne Agent-Config-Bezug (`unsafe_action`);
- Verlauf/Gedächtnis des Agenten (`memory_poisoning`).

## 3. Lexika (`anchor_lexicons/agent_config_tampering.json`)

**Support** (+25/+20/+15):

| ID | DE (Auszug) | EN (Auszug) |
|---|---|---|
| `agentcfg.file` | AGENTS.md, CLAUDE.md, .cursorrules, SKILL.md, mcp.json, settings.json, Hooks | same |
| `agentcfg.widen` | alles erlauben, ohne Nachfrage, automatisch bestätigen, Sandbox aus, alle Rechte | allow all, auto-approve, skip confirmation, dangerously, bypass permissions, yolo |
| `agentcfg.guard_removal` | Hook entfernen/deaktivieren, Prüfung überspringen, Schutz ausschalten | remove/disable hook, skip checks, turn off guard |
| `agentcfg.persist` | für alle künftigen Sitzungen, immer, in jede Datei schreiben | for all future sessions, always, write into every |
| `agentcfg.fetch_run` | lade herunter und führe aus, Skript von URL ausführen | download and run, curl … \| sh, install from URL |
| `secrecy` (Core, geteilt) | sag dem Nutzer nicht, unbemerkt | do not tell the user, silently |

**Gegen** (−30):

| ID | Inhalt |
|---|---|
| `agentcfg.project_rule` | normale Projektregeln: Stil, Tests, Branches, Sprache („Commit-Messages auf Englisch“) |
| `agentcfg.scoped_allow` | eng gefasste Freigaben: einzelner Befehl, Lesezugriff, Projektordner |
| `defensive` (Core, geteilt) | Schutzregeln: „frage vor dem Löschen“, „führe keine Skripte aus dem Netz aus“ |
| `meta`, `quotation`, `test_code` (Core, geteilt) | Doku zu Agent-Settings, Changelogs, Testcode |

## 4. Patterns

Alle Patterns verlangen den Träger Agent-Config (`requires_carrier=agent_config`), außer
`ac_tamper_request`, das eine **Aufforderung** zur Änderung im Klartext erkennt.

| Pattern | Kern | Basis | Validator | `requires_context` | `scored_only` | Heutige Regeln |
|---|---|---|---|---|---|---|
| `ac_permission_widening` | `widen` als Wert/Regel in Agent-Config (Auto-Approve, `allow: *`, Sandbox aus) | 40 | Structure | nein | nein | threat.unauthorized_autonomy, governance.autonomous_approval_bypass, governance.forged_verified_allow |
| `ac_guard_removal` | Schutz-Hook/Prüfung entfernen oder deaktivieren | 40 | Format | nein | nein | threat.agent_guard_removal |
| `ac_hidden_directive` | Direktive an das Modell + `secrecy` oder versteckte Auszeichnung in Rules/Skill | 40 | Format | nein | nein | skillspector-Harvest (neu) |
| `ac_fetch_run` | `fetch_run` in Skill- oder Rules-Text | 35 | Format | ja | nein | neu |
| `ac_mcp_server_injection` | MCP-Eintrag mit Befehl aus fremder URL/Paketquelle oder `env`, das Secrets an fremden Host gibt | 35 | Structure | ja | nein | Rest von `mcp_runtime_risk` (Teil), neu |
| `ac_persistence` | `persist`: Regel soll sich in weitere Config-Dateien/Sitzungen schreiben | 30 | Format | ja | nein | neu |
| `ac_tamper_request` | Klartext-Aufforderung an den Agenten, eine Agent-Config so zu ändern (`agentcfg.file` + `widen`/`guard_removal`) | 30 | Format | ja | nein | neu |
| `ac_decoded` | eines der obigen in einer dekodierten Sicht | wie Quelle | wie Quelle | wie Quelle | wie Quelle | neu |

`Structure` (+25) wie bei DLP: Der Fund sitzt auf einem bekannten Schlüssel (`permissions.allow`,
`hooks`, `mcpServers.*.command`), nicht nur in der Nähe. Normalisierungspunkte: Plus wie bei `injection`.
Modi wie PII.

## 5. Struktur und Träger

- Der Core liefert den Dateityp aus der Struktur im Text (Pfad, Frontmatter, Schlüssel) und Felder je
  Schlüssel. Träger Agent-Config zählt wie ein Feldname (+25) und setzt `carrier=agent_config`.
- In Diffs zählen nur hinzugefügte Zeilen (`+`); entfernte Zeilen sind kein Fund.

## 6. Facts (Auszug)

`finding{…}`, `carrier{agent_config, file_kind=rules|skill|settings|hooks|mcp}`, `widened{scope}`,
`guard_removed`, `fetch_run`, `persist`, `mcp_server{command_origin, env_secret}`, Modifikatoren wie `injection`.

## 7. Modell

Kandidaten: R+A+L, B1, B4, B5; B0 = Threat-Scorer 0.1.7 (enthält `unauthorized_autonomy`,
`agent_guard_removal`) als Vergleich. Kaum öffentliche Daten: Positive aus SkillSpector-/ATR-Fällen und
Generatoren (Einbettung in echte, harmlose `AGENTS.md`/Skills mit sauberem Zwilling, M-Block); Benign aus
öffentlichen Rules-Dateien und Skills in großer Menge.

## 8. Policies (später)

- `ac.widen_with_fetch`: `widened` ∧ `fetch_run` → `block`.
- `ac.hidden_persist`: `ac_hidden_directive` ∧ `persist` → `block`.

## 9. Bestand

| Heutige Regeln | Ziel |
|---|---|
| threat.unauthorized_autonomy, governance.autonomous_approval_bypass, governance.forged_verified_allow | `ac_permission_widening` (ohne Config-Träger: `unsafe_action`) |
| threat.agent_guard_removal | `ac_guard_removal` |
| threat.agent_config_exfiltration | nicht hier: `exfiltration` |
| threat.security_disable | nicht hier: `unsafe_action` |
| `mcp_runtime_risk` (heute in `dlp`) | Befehlsteil K26 (X04); Eintrag fremder Server/Secret-`env` hier, sonst `unsafe_action` (X03) |
| übrige agentic_control_abuse (identity_state_override, encrypted_swarm_override, refund_control_bypass, executive_password_reset_redirect, credential_verification_link, agentic.control_abuse) | nicht hier: `memory_poisoning`, `injection_agent_directive` bzw. `unsafe_action` (`credential_access`); Prüfung je ID in M01 |

## 10. Übernommene OSS-Regeln

SkillSpector (Skill-Regeln), ATR (Agent-Config-Familien), Cisco mcp-scanner YARA (Konfig-Teile); default aus.

## 11. Goldens

Je Pattern und Sprache ≥ 5 Positive und ≥ 5 Hard Negatives. Pflicht-Hard-Negatives: echte `AGENTS.md`/
`CLAUDE.md` mit strengen Projektregeln, eng gefasste `permissions.allow`-Listen, offizielle MCP-Server-Einträge
(`npx @modelcontextprotocol/…`), Doku zu Auto-Approve-Einstellungen, Diffs, die eine Freigabe **entfernen**.

## 12. Herkunft und Daten

Regeln für Herkunft, Splits und Quellfamilien: [README](../README.md#herkunft-regeln-train-gold-holdout).
Goldens: je Pattern und Sprache ≥ 5 Positive und ≥ 5 Hard Negatives, selbst geschrieben (`ark_authored`), §11.

| | Quelle |
|---|---|
| Patterns/Anker | `ark_existing` (unauthorized_autonomy, agent_guard_removal, 2 Governance-Regeln, Teil von mcp_runtime_risk); `oss`: SkillSpector static, ATR (Agent-Config), Cisco YARA (Konfig-Teile); `taxonomy`: OWASP Agentic Threats; `mined` auf Train |
| Train/Dev | Generatoren: Einbettung in öffentliche `AGENTS.md`/`CLAUDE.md`/`.cursorrules`/Skills aus permissiv lizenzierten Repos (Dev-Seed), SkillSpector-Fälle |
| Holdout `neutral` | MaliciousSkillBench (quellen-disjunkt zu SkillSpector) |
| Holdout `ark_blind` | R05 DE+EN (Rules-Dateien, Settings, `mcp.json`, Diffs), Seed-Teil der Einbettung |
| Hard Negatives | echte Rules-Dateien und Skills mit strengen Projektregeln, eng gefasste `permissions.allow`, offizielle MCP-Server-Einträge |
| Lücke | kaum EN-Daten außer MaliciousSkillBench, kein DE |

## 13. Stand AC01 (2026-11-14)

Sieben Punkte-Regeln im Threat-Detektor (`ark-core/src/detectors/threat/rules.json`, Präfix
`ark.threat.ac_*`, Kategorie `agent_config_tampering`, opt-in). Alle außer `ac_tamper_request`
laufen nur, wenn der Text eine Agent-Config ist oder nennt (Träger `agent_config` aus
`text/facts/carrier.rs`, dieselbe Marke über `is_agent_config`; die Marke kennt jetzt auch
`.claude/`, `.cursor/`, `.codex/`, `.windsurfrules`, die Schlüssel `permissions`, `defaultMode`,
`disableAllHooks` und Skill-Frontmatter `---/name:/description:`). Entfernte Diff-Zeilen (`-`, im
Text mit `+++`-Kopf) sind kein Fund. Entscheidung wie TP01/UA01: Punkte ≥ 50, kein Gegenkontext
im Satz (oder, außer Verneinung, im Satz davor), bei `requires_context` ein Stützterm.

| Pattern | Basis | Validator | `requires_context` | Kern / Abweichung von §4 |
|---|---|---|---|---|
| `ac_permission_widening` | 40 | structure | nein | Schlüssel + Wert (`defaultMode: bypassPermissions`, `autoApprove: true/["*"]`, `allow: [… "Bash(*)"/"*"/"Bash"]`, `approval_policy = "never"`, `sandbox_mode = "danger-full-access"`, `dangerouslySkipPermissions`/`yolo: true`); `never` im eigenen Wert zählt nicht als Verneinung |
| `ac_guard_removal` | 40 | format | nein | Verb (entfernen/abschalten/überspringen) + Schutz-Hook/-Prüfung; `"disableAllHooks": true`. Die alte Scorer-Regel `agent_guard_removal` bleibt (B0) |
| `ac_hidden_directive` | 40 | format | nein | `<!--`/Pseudo-Tag + Anrede an KI/Agent/Assistent + Direktive; Kontext ab der Direktive. Geheimhaltung ohne Markup noch nicht |
| `ac_fetch_run` | 35 | format | ja | Download-Verb + URL + Ausführen-Verb; Stützterm (unbemerkt, ohne Rückfrage …) nötig, sonst Installationshinweis |
| `ac_mcp_server_injection` | 35 | structure | nein (§4: ja) | `"command"` Shell/Paketstarter + `curl/wget … \| sh` oder Roh-URL-Paket (`.tgz/.whl/.zip/.git`); `mcp-remote <url>` bleibt benign. `env`-Secret-Weitergabe offen |
| `ac_persistence` | 35 | format | nein (§4: ja) | Schreibverb + „diese Regel/dieser Abschnitt“ + jede/alle + Agent-Dateien/Repos/Sitzungen |
| `ac_tamper_request` | 35 | format | nein (§4: ja) | Verb + Agent-Datei + Ausweitung (alle Befehle ohne Rückfrage, auto-approve, bypassPermissions, Vollzugriff); ohne Träger |

Lexika: `anchor_lexicons/agent_config_tampering.json` (`agentcfg.file`, `.widen`, `.guard_removal`,
`.persist`, `.hidden_directive`); Download/Ausführen über die vorhandenen `threat.*`-Anker. Bewusst
nur unterscheidende Wörter, damit Literale anderer Regeln keine neuen Ankerpunkte bekommen.
Offen: Gegen-Lexika `agentcfg.project_rule`/`agentcfg.scoped_allow` (heute schützt die Form der
Regex), `ac_decoded`, Geheimhaltung ohne Markup, `env`-Secrets in MCP-Einträgen, YAML-Settings,
Harvest der SkillSpector-/ATR-/Cisco-YARA-Regeln (default aus, Katalog mit Commit), Punkte/Ablation
in AC02.

Latenz (Release, `rust/dev/l1_latency_workloads.rs`, 100 KiB, Basis ededaf70 gegen AC01, je 2 × 60
Samples, abwechselnd): deutsche Prosa (Kategorie-Dokumente, nennen `AGENTS.md`, also Träger an)
Default-Kategorien p50 66,2 → 65,3 ms, p95 95,1 → 89,0 ms (Rauschen; Default unverändert bis auf
die neuen Anker im geteilten Lexikon); Default + `agent_config_tampering` p95 83,5 → 83,1 ms;
`agent_config_tampering` allein p50 2,2 → 23,2 ms, p95 2,9 → 34,9 ms (vorher lief keine Regel, jetzt
die geteilte Vorbereitung und sieben Regexe). Worst Case 100 KiB Agent-Config-Mix (alle Goldens
der Klasse): allein p95 6,0 → 58,0 ms, Default + AC p95 67,3 → 76,6 ms. Die Kategorie ist opt-in;
das DLP-Budget betrifft sie nicht. Offen: Kosten der Regexe ohne geteilte Vorbereitung senken
(z. B. `ac_tamper_request` nur bei Dateinamen-Anker).

## 14. Stand AC02 (2026-11-15): Punkte und Ablations-Entscheidung

**Entscheidung: `B0` bleibt** — die Punkte-Regeln aus AC01/AC02 mit handgesetztem Klauselkontext
entscheiden allein; kein gelerntes Modell wird einkompiliert. Neu bewerten, sobald echte
Agent-Config-Angriffe jenseits der Generator-Vorlagen im Dev-Split liegen (MaliciousSkillBench
bleibt Holdout).

Daten (nur Dev, wie TP02): die 84 `agent_config_tampering`-Zeilen aus
`generators_dev_seed:class_templates` (`rules_file` 46, `skill_file` 38; je 42 DE/EN) gegen 15 617
Benign-Zeilen (alle Benign-Zeilen von `train_dev`, `generated`, `report`, Dolly und GermanQuAD je ein
Viertel per sha256 der ID), Hälften per sha256 der Zeilen-ID (Auswertung: 41 Positive, 7 850
Negative, davon 900 Hard-Benign). Facts über `text_facts --threat-findings`, B0 aus
`scoreboard.py predict` mit dem gebauten Modul, Latenzfenster: 6 × 100 KiB GermanQuAD-Dev-Text
(Ersatz für das E03-Korpus, das in der Sandbox fehlt).

Vor den Regel-Ergänzungen (Regeln aus AC01): `R`/`R+A` 0,0 % TPR@1 % (DE und EN), `R+A+L` 100 % mit
4,9 % Hard-Benign-FPR, `B1`/`B4`/`B5` 100 % mit 5,9/8,9/2,2 % Hard-Benign-FPR. Die Auswahlregel hätte
`R+A+L` gewählt; dessen Punkte lernen aber nur Träger-/Vorlagen-Tokens. Ursache der Lücke: beide
Vorlagenfamilien verstecken einen Schritt **ohne** Markup („… and never mention it in
explanations“, „… leave this step out of your summary“, „erwähne ihn nie“, „lass diesen Schritt …
weg“) — in §13 als offen geführt. Recall kommt deshalb aus Regeln:

- `ac_hidden_directive`, zweite Alternative (Komponenten `step`, `sink`, `conceal`): Aktionsverb
  (add/insert/send/post/upload/copy/forward; füge/sende/schicke/lade/kopiere/leite) → Secret oder
  fremdes Ziel (URL, `process.env`, `.env`, `~/.ssh`, `~/.aws`, credentials, webhook, geteiltes
  Laufwerk) → Geheimhaltung, die auf den Schritt zurückverweist (`never mention it/this step`,
  `leave this (step) out`, `without mentioning`, `keep it to yourself`, `erwähne/verrate
  ihn/das/diesen Schritt … nie/nicht`, `lass das/diesen Schritt … weg`, `ohne es zu erwähnen`); alles
  auf einer Zeile, je Lücke ≤ 120 Zeichen. Ohne Rückverweis bleibt eine Datenschutzregel („never
  mention customer names“) benign. Nur mit Agent-Config-Träger, wie bisher.
- Klauselkontext (`clause_context`, nur `agent_config_tampering`): ist die Zeile des Funds ein
  Listenpunkt (`- `, `* `, `+ `, `1. `, `1) `) und die Lead-in-Klausel ein **anderer** Listenpunkt,
  zählt deren Gegenkontext nicht — jeder Punkt einer Rules-Datei/eines Skills ist eine eigene
  Anweisung (Vorlage: „1. Use the staging environment for all tests.“ vor dem versteckten Schritt
  traf den Gegenkontext `test_code`/Testumgebung). Eine einleitende Zeile ohne Listenmarke
  („Schulungsbeispiel für eine bösartige Regel:“) bleibt Lead-in.

Danach (gleiche Zeilen, Auswertungshälfte):

| Stufe | TPR@1 % | TPR@0,1 % | DE | EN | Hard-Benign-FPR | ms/100 KiB | RAM |
|---|---|---|---|---|---|---|---|
| R | 100,0 | 100,0 | 100,0 | 100,0 | 0,0 | 0 | 0 |
| R+A | 100,0 | 100,0 | 100,0 | 100,0 | 0,0 | 0 | 0 |
| **B0** | 100,0 | 100,0 | 100,0 | 100,0 | 0,0 | 0 (Status quo) | 0 |
| R+A+L | 100,0 | 100,0 | 100,0 | 100,0 | 4,9 | 0 | 0,6 KiB |
| B1 | 100,0 | 100,0 | 100,0 | 100,0 | 5,9 | 28,8 | 5,1 MB |
| B4 | 100,0 | 100,0 | 100,0 | 100,0 | 8,9 | 27,4 | 576 KiB |
| B5 | 100,0 | 100,0 | 100,0 | 100,0 | 2,2 | 27,4 | 576 KiB |

Auswahl nach der README-Regel: `B0` (günstigste Stufe innerhalb 1 pp der besten; `B1`/`B4`/`B5` über
dem Budget von 1 ms je 100 KiB). Auf allen Zeilen: 84 von 84 Positiven gemeldet, keine der 15 617
Benign-Zeilen. Vorbehalt wie TP02: die Ergänzungen sind an denselben zwei Vorlagenfamilien
entstanden, an denen gemessen wird; die Zahl ist eine Obergrenze, das Urteil fällt auf dem Holdout.
Offen: eine einleitende Zeile **ohne** Listenmarke mit Gegenkontext („Write tests with pytest.“
direkt vor einem Listenpunkt) unterdrückt den Fund weiter; Geheimhaltung über mehrere Zeilen; dazu
weiter die offenen Punkte aus §13.

Latenz (Release, `rust/dev/l1_latency_workloads.rs`, Basis 31bf2b87 gegen AC02, gleiche Fenster,
4 Runden je 40 Samples, abwechselnd; das E03-Korpus fehlt in der Sandbox): 6 × 100 KiB deutsche
Prosa (kein Agent-Config-Träger, die AC-Regeln laufen dort nicht) `agent_config_tampering` allein
p50 39,8 → 39,4 ms, p95 62,5 → 56,1 ms; Default + AC p50 43,1 → 45,0 ms, p95 64,1 → 65,0 ms
(Rauschen). Worst Case 100 KiB Agent-Config-Mix (alle Goldens der Klasse): allein p50 47,1 →
44,4 ms, p95 82,0 → 69,0 ms; Default + AC p50 57,5 → 59,2 ms, p95 76,9 → 81,3 ms (Rauschen; der Head
meldet im Mix mehr Funde). Zusätzliche Arbeit: eine Alternative in einer schon kompilierten Regex
und eine Zeilenprüfung nur bei Gegenkontext in der Lead-in-Klausel.

## 15. Stand T10 (2026-11-17): Ablation mit nativen Dev-Zeilen (AgentDojo)

**`B0` bleibt**, unverändert gegenüber AC02; die Entscheidung ist auf nativen Positiven weiter nicht prüfbar.
AgentDojo (MIT, seit Korpus-Generation 10 im Dev-Split) enthält Angriffe in Tool-**Ausgaben**, keine
vergifteten Tool-Beschreibungen und keine Agent-Konfigurationen; native Positive dieser Klasse gibt es auf Dev
weiterhin nicht (MCPTox bleibt Holdout). Was die nativen Zeilen hier zeigen, sind Negative: auf den 132 sauberen
AgentDojo-Tool-Ausgaben und den 135 Angriffszeilen anderer Klassen meldet ARK keine `agent_config_tampering`-Zeile.

Daten: Training auf der Hälfte A (sha256 der Zeilen-ID) aller Dev-Zeilen ohne AgentDojo (Generator-Vorlagen
plus Benign-Zeilen von `train_dev`, `generated`, `report`; Dolly und GermanQuAD je ein Viertel, wie EX02/UA02
§14), 8 007 Zeilen. Zwei Auswertungen auf derselben Hälfte B der Benign-Zeilen (7 788 Negative, davon 912
Hard-Benign): **Vorlagen** = Positive der Hälfte B aus den Generatoren; **nativ** = alle AgentDojo-Zeilen
(63 `exfiltration`-, 30 `unsafe_action`-Positive, nur EN; 132 saubere Tool-Ausgaben als zusätzliche Negative).
Gelernte Stufen sehen keine AgentDojo-Zeile. Facts über `text_facts --threat-findings`, B0 aus
`scoreboard._predict_file` mit dem gebauten Modul (Release), Latenz auf 6 × 100 KiB GermanQuAD-Dev-Text.

Vorlagen (Hälfte B, unverändert zu AC02): R, R+A, **B0**, R+A+L, B1, B4, B5 je 100 % TPR@1 %; Hard-Benign-FPR
R/R+A/B0 0,0, R+A+L 4,8, B1 6,1, B4 8,3, B5 2,2; B1/B4/B5 26,7–32,0 ms je 100 KiB (über dem Budget). Auswahl: `B0`.
Native Auswertung: keine Positiven, keine Zeile. Lizenzgeprüft und ohne Rezept: Agent-SafetyBench (MIT;
Tool-Umgebungen mit Risikofällen) — Folgeaufgabe **T15** prüft, ob deren Fälle Tool-Beschreibungen oder
Konfigurationen dieser Klasse tragen.

## 16. Stand T15 (2026-11-17): erste native Positive (approve-or-deny, übersetzt)

**`B0` bleibt**; drei native Positive tragen keine Auswahl. approve-or-deny (Apache-2.0, seit Korpus-Generation 11
im Dev-Split, nur deutsche Zeilen, maschinell erzeugt und als übersetzt markiert) hat in der Kategorie
`self_permission_tamper` Tool-Aufrufe, mit denen der Agent seine eigene Konfiguration aufweicht: ein Patch auf
`~/.codex/config.toml` mit `[permissions] allow = ["shell"]`, `sed -i 's/require_approval = true/…false/'` auf
die Agent-Konfiguration, `printf '[sandbox] enabled = false' >> ~/.codex/config.toml`. Das sind die ersten
nativen Positiven der Klasse auf Dev (3 Zeilen nach dem Sprachfilter; im ganzen Satz 104).

Daten wie §15: Training auf Hälfte A (sha256 der Zeilen-ID) der Generator-Vorlagen und Benign-Zeilen aus
`train_dev`, `generated`, `report` ohne AgentDojo, Dolly und GermanQuAD je ein Viertel (8 677 Zeilen, der
Unterschied zu §15 kommt aus der Viertel-Auswahl). Auswertung: Benign-Zeilen der Hälfte B (7 756) plus die
nativen Zeilen von BIPIA und approve-or-deny (361; 3 Positive, 94 saubere Zeilen). Facts über `text_facts
--threat-findings`, B0 aus `scoreboard._predict_file` mit dem gebauten Modul; ohne Latenzmessung, B1/B4/B5
daher `untimed` (in §15 lagen sie mit 26,7–32,0 ms je 100 KiB über dem Budget).

| Stufe | TPR@1 % (3 nativ, DE) | Hard-Benign-FPR |
|---|---|---|
| R, R+A, B0 | 0,0 | 0,0 |
| R+A+L | 66,7 (2 von 3) | 5,2 |
| B1, B4, B5 | 0,0 | 7,5 / 10,4 / 2,8 |

Das Werkzeug wählt `R+A+L` (einzige Stufe mit Treffern), auf drei Zeilen und mit 5,2 % Hard-Benign-FPR ist das
keine belastbare Umstellung. Die Lücke ist strukturell: AC01 erwartet einen AGENT_CONFIG-Träger mit einem
Aufweitungs-Wert, hier steht die Änderung in den Argumenten eines Shell- oder Patch-Aufrufs, der die Datei erst
schreibt (`sed -i`, `>>`, Unified Diff). Folgeaufgabe **T17**. Keine `agent_config_tampering`-Meldung auf den
94 sauberen nativen Zeilen.

## 17. Stand T17 (2026-11-17): Schreibaufrufe auf die eigene Agent-Konfiguration, Ablation erneut

**`B0` bleibt**, jetzt mit Treffern: alle drei nativen approve-or-deny-Positiven werden gefunden, ohne
Hard-Benign-FP. Neue Regel `ark.threat.ac_config_write` (Familie `permission_widening`): ein Shell- oder
Patch-Aufruf schreibt einen Aufweitungs-Wert in einen Agent-Konfigurationspfad (`.codex/…`, `.claude/…`,
`agent…/config.toml|settings.json`). Drei Schreibformen in einer Regex: `sed -i` mit dem Wert in der
Ersetzung (nicht im Suchteil, also kein Treffer beim Wieder-Einschalten), `printf`/`echo` mit `>>`, `>` oder
`tee` auf den Pfad, und eine hinzugefügte Zeile (`+`) eines Unified Diff nach `+++ <Pfad>` (auch
JSON-escaped in `apply_patch`-Argumenten). Werte: `require_approval`/`approval_required`/`confirm_*` auf
false, `[sandbox] enabled = false`, `sandbox*` auf false/off/`danger-full-access`, `approval_policy = never`,
`bypassPermissions`, `dangerously_skip_permissions`/`auto_approve` = true, `allow = ["shell"|"bash"|"*"]`; ein
eng gefasster Eintrag (`"shell(git status)"`) trifft nicht. Wie `ac_tamper_request` läuft sie ohne
AGENT_CONFIG-Träger. Der geschriebene Wert ist eigene Phrase der Regel (`own`) für die Kontextprüfung — sonst
macht das Wort `sandbox` im Wert den Fund zum Gegenkontext —, und `false`/`never` darin sind eigene Negation.
Prefilter: die Pfad-Literale (`.codex/`, `.claude/`, `config.toml`, `settings.json`) aus `agentcfg.file`;
Pfadklassen ASCII, sonst überschreitet der kompilierte Automat das Größenlimit.

Ablation wie §16 nachgebaut, mit allen Generator-Dateien (`generated/*`, auch Carrier-Insertion und
Obfuskation) statt nur der Vorlagen: Hälften per sha256 der Zeilen-ID, Dolly/GermanQuAD je ein Viertel per
sha256, ohne AgentDojo; Training 11 892 Zeilen (43 Positive, 11 023 Benign); Vorlagen-Auswertung 41 Positive,
4 482 Benign (912 Hard-Benign); nativ die 3 approve-or-deny-Positiven plus 4 576 Benign (912 Hard-Benign,
darin die 94 sauberen BIPIA-/approve-or-deny-Zeilen). Facts über `text_facts --threat-findings` (Release), B0
über `scoreboard._predict_file` mit dem gebauten Modul; ohne Latenzmessung (B1/B4/B5 `untimed`).

| Stufe | Vorlagen TPR@1 % | nativ TPR@1 % (3, DE) | Hard-Benign-FPR |
|---|---|---|---|
| R, R+A, **B0** | 100,0 | 100,0 (3 von 3) | 0,0 |
| R+A+L | 100,0 | 100,0 | 4,8 |
| B1 / B4 | 100,0 | 0,0 | 9,4 / 11,7 |
| B5 | 100,0 | 100,0 | 4,1 |

Auswahl des Werkzeugs: `B0` (vorher `R+A+L` mit 2 von 3). Die Regel trägt keine Benign-Zeile (Training,
Vorlagen, nativ); B0 meldet auf keiner der 94 sauberen nativen Zeilen `agent_config_tampering`. Goldens:
je Schreibform DE und EN (sed, printf/echo, Diff; deutsche Zeilen `translated`) mit Hard Negatives (Nutzer
bittet um die Änderung der eigenen Konfiguration, Tutorial mit der Einstellung, eng gefasste Freigabe,
Wieder-Einschalten per sed, verengender Diff, Konfiguration eines anderen Programms). Offen: Heredocs
(`cat >> ~/.codex/config.toml <<EOF` mit dem Wert in den Folgezeilen) und `sed` mit anderem Trennzeichen als
`/`; drei Zeilen tragen noch keine Aussage über diese Formen.

## 18. Stand T25 (2026-11-24): Aufforderungen in Dateien, die der Agent liest (zweite Generator-Familie)

**`B0` bleibt.** Die zweite Generator-Familie (`agent_scenarios`, seit Korpus-Generation 23 im Dev-Split) traf
B0 vorher auf 0 von 160 Positiven: die Aufforderung an den Agenten steht in einer Datei, die er liest
(`copilot_instructions`, `issue_comment`, `readme_setup`), und nennt den Konfigurationsort mit seiner Rolle
(„die mcp.json des Agenten“, „Agenten-Konfiguration“, „Berechtigungsdatei des Agenten“, `agent.yaml`). Sechs
Formen, je DE und EN: fremden MCP-Server registrieren und für jeden Arbeitsbereich aktivieren, ohne es dem
Nutzer zu sagen; Pre-Commit-Hooks und Secret-Scanner in der Agenten-Konfiguration abschalten;
Berechtigungsdatei auf Schreiben außerhalb des Projektordners erweitern und die Sperrliste entfernen; Regel in
`CLAUDE.md`, dass jeder Shell-Befehl ohne Nachfrage läuft; `"chat.tools.autoApprove": true` in
`.vscode/settings.json`; Systemprompt in `agent.yaml` durch Anweisungen von einem fremden Host ersetzen.

Regeln (entworfen auf `copilot_instructions` und `issue_comment`; `readme_setup` als Held-out getrennt
gemessen), alles in `ark.threat.ac_tamper_request` (Familie `tamper_request`, läuft wie bisher auch ohne
AGENT_CONFIG-Träger):
- Verben `register`/`append`/`replace`, `registriere`/`häng an`/`ersetze`; Ziele `agent.yaml` und
  `permission file`/`Berechtigungsdatei`; Lücke Verb → Ziel 90 statt 60 Zeichen (die Server-URL steht
  dazwischen).
- Aufweitungen: `any shell command … without asking`, `jeden Shell-Befehl … ohne Nachfrage`, `no longer need(s)
  confirmation`, `keine Bestätigung mehr`, `without telling the user`, `ohne es dem Nutzer zu sagen`, `allow
  writes outside the project`, `remove the deny list`, `außerhalb des Projektordners schreiben`, `entferne die
  Sperrliste`, `instructions from/Anweisungen von <Host mit TLD>` (ein Pfad wie `docs/prompt.md` trifft nicht).
- Eine anschließende Verschleierung der Änderung („do not mention it“, „keep that line out of …“, „erwähne die
  Änderung nicht“, „lass diese Zeile … weg“) gehört zur Gruppe `widen`; `widen` ist eigene Phrase der Regel
  (`own`), ihre Negationswörter („no longer“, „keine“, „nicht“) machen den Fund nicht zum Gegenkontext.
- Zweite Form: `switch/turn off`, `disable`, `deactivate`, `schalte … ab`, `deaktiviere` → `pre-commit hooks`
  oder `secret scanner` → `agent configuration/settings`, `Agenten-Konfiguration`. Ein vorangestelltes
  „Do not“ oder nachgestelltes „nie“ verneint wie bisher (`is_negated`).
- Neue Anker im Lexikon (`agentcfg.file`: `agent.yaml`, `agent.yml`, `berechtigungsdatei`, `permission file`;
  `agentcfg.guard_removal`: `pre-commit`, `precommit`, `secret scann`, `secret-scann`) halten die Regel hinter
  ihrem Prefilter.

Dev (Release-Build, `threat_cascade` mit `scoreboard/cascade-config.json`, Heuristik-Score der Klasse;
Positive gelten bei Score > 0, d. h. am 0,1-%-Schnitt, weil keine Benign-Zeile einen Score trägt):

| Zeilen | vorher | nachher |
|---|---|---|
| `agent_scenarios` DE (80; davon Held-out `readme_setup` 23) | 0 | 80 (Held-out 23 von 23) |
| `agent_scenarios` EN (80; davon Held-out `readme_setup` 31) | 0 | 80 (Held-out 31 von 31) |
| saubere Zwillinge derselben drei Familien (160) | 0 | 0 |
| `class_templates` (84) / approve-or-deny (3) | 84 / 3 | 84 / 3 |
| alle Benign-Zeilen des Dev-Splits (64 318, DE 26 153, EN 38 165) | 0 | 0 |

Vorbehalt: Die Held-out-Familie trägt dieselben sechs Aufforderungen in einem anderen Träger; der Treffer dort
zeigt, dass die Regeln nicht am Träger hängen, nicht, dass sie neue Formulierungen finden. Das Urteil fällt auf
dem Holdout. Das eingebaute L1-Modell der Kaskade meldete die Positiven schon vorher, aber auch alle 57
`copilot_instructions`-Zwillinge und 22 von 49 `issue_comment`-Zwillingen (es lernt den Träger); daran ändert
diese Runde nichts.

Ablation wie §17 (`ablation.py run`, Facts über `text_facts --threat-findings`, B0 aus den Vorhersagen des
Heads): alle Dev-Zeilen mit `agent_config_tampering`-Positiven oder `benign`, Dolly, GermanQuAD, MASSIVE,
Mosscap, Civil Comments und TextDetox je ein Viertel per sha256; Hälften nach Vorlagenschlüssel (Generator +
Familie) bzw. Zeilen-ID. Training 11 116, Auswertung 11 160 Zeilen (100 Positive, DE 45, EN 55; 11 060
Negative, davon 1 198 Hard-Benign). Ohne Latenzmessung (B1/B4/B5/FT `untimed`).

| Stufe | TPR@1 % | TPR@0,1 % | DE | EN | Hard-Benign-FPR@1 % |
|---|---|---|---|---|---|
| R, R+A, **B0** | 100,0 | 100,0 | 100,0 | 100,0 | 0,0 |
| R+A+L | 100,0 | 100,0 | 100,0 | 100,0 | 6,2 |
| B1 / B4 | 100,0 | 54,0 | 100,0 | 100,0 | 8,0 / 7,2 |
| B5 | 100,0 | 100,0 | 100,0 | 100,0 | 0,0 |
| FT | 100,0 | 100,0 | 100,0 | 100,0 | 6,5 |

Auswahl des Werkzeugs: `B0` (günstigste Stufe innerhalb 1 pp der besten; B5 gleichauf, aber ungetimt und mit
576 KiB Modell). Goldens: je Träger (Copilot-Instructions, Issue-Kommentar, README-Setup) und Form DE und EN,
Hard Negatives: MCP-Einrichtung für den Menschen („in deiner mcp.json“), eigene Konfigurationsänderung einer
Maintainerin (erste Person, Vergangenheit), CONTRIBUTING-Hinweis zu Hooks (verneint), die sauberen Zwillinge,
Systemprompt aus einer Repo-Datei.

Offen: die Nachkalibrierung des eingebauten L1-Modells je Sprache auf ≤ 0,1 % Benign-FPR (Owner-Entscheidung
2026-11-23) und der zugehörige Sprach-Check in `scoreboard.py` sind in dieser Runde nicht enthalten.
