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
