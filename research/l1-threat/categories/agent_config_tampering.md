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
