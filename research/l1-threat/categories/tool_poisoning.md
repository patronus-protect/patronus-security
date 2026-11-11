# Kategorie `tool_poisoning`

Stand: 2026-11-09, Entwurf zur Freigabe. Gliederung wie [`injection.md`](injection.md); Begriffslisten sind
Auszüge, die vollständigen Lexika entstehen in S02.

## 1. Schichten

Wie [`injection.md` §1](injection.md#1-schichten-für-alle-kategorien-gleich). Geteilte Core-Lexika:
Adressat, Geheimhaltung, sensible Pfade (aus DLP G13), Meta, Zitat, Testcode.

## 2. Abgrenzung

`tool_poisoning` = bösartige Anweisungen in **Tool-Metadaten**: Beschreibungen und Parameter-Schemas von
Tools/Functions, MCP-`tools/list`-Antworten, Agent-Cards (A2A `skills`). Typisch: Anweisungen an das Modell,
die der Nutzer nicht sieht, sensible Dateien in einen Parameter zu schreiben, ein anderes Tool umzulenken
(Shadowing) oder etwas zu verschweigen.

L1 sieht nur Text (festgelegt 2026-11-09). Tool-Metadaten erkennt der Core an der Struktur im Text:
JSON/YAML mit `tools`, `name` + `description`, `inputSchema`/`parameters`/`properties`, A2A-`skills`.
Dieselbe Anweisung außerhalb solcher Struktur ist `injection`, nicht `tool_poisoning`.

Nicht `tool_poisoning`:
- Anweisungen im Tool-**Output** (`injection`, Träger Tool-Result);
- Rug Pull (Beschreibung ändert sich zwischen Sitzungen): braucht Zustand, kein L1;
- gefährliche Shell-Befehle in Tool-Call-Argumenten (K26, früher `mcp_policy` in `dlp`);
- Skills, Rules-Dateien, `mcp.json`, Hooks (`agent_config_tampering`).

## 3. Lexika (`anchor_lexicons/tool_poisoning.json`)

Wichtig: Normale Tool-Beschreibungen sprechen das Modell **an** („Use this tool when …“). Anrede allein ist
deshalb kein Signal; erst die Kombination mit etwas Fremdem zählt.

**Support** (+25/+20/+15):

| ID | DE (Auszug) | EN (Auszug) |
|---|---|---|
| `toolpoison.preamble` | bevor du dieses Tool benutzt, zuerst musst du, wichtig: | before using this tool, you must first, IMPORTANT: |
| `toolpoison.cross_tool` | wenn das Tool … aufgerufen wird, statt …, bei allen E-Mails, leite um | when the … tool is called, instead of, for all emails, redirect, also send to |
| `toolpoison.side_channel` | Parametername/-text: Notiz, Kontext, Metadaten + „ganzer Verlauf“, „vorherige Nachrichten“ | sidenote, notes, context, metadata + "full conversation", "previous messages" |
| `toolpoison.hidden_markup` | `<IMPORTANT>`, `<SYSTEM>`, HTML-Kommentar, Zero-Width (Core-Sicht) | same |
| `sensitive_path` (Core, geteilt, DLP G13) | `~/.ssh/id_*`, `~/.aws/credentials`, `.env`, kubeconfig, Keychain | same |
| `secrecy` (Core, geteilt) | sag dem Nutzer nicht, ohne Hinweis | do not tell the user, don't mention |
| `addressee` (Core, geteilt) | KI, Assistent, Modell, du | AI, assistant, model, you |

**Gegen** (−30):

| ID | Inhalt |
|---|---|
| `toolpoison.usage_doc` | übliche Bedienhinweise: „Nutze dieses Tool, wenn …“, „gibt zurück“, „Parameter: …“ / use this tool when, returns |
| `toolpoison.own_domain` | sensibler Pfad passt zum Zweck des Tools (SSH-Manager liest `~/.ssh`, AWS-Tool liest Profile) |
| `meta`, `quotation`, `test_code` (Core, geteilt) | Doku zu Tool-Poisoning, Scanner-Regeln, Testcode |

## 4. Patterns

Alle Patterns verlangen den Träger Tool-Metadaten (`requires_carrier=tool_metadata`); ohne ihn feuern sie
nicht. Validator `addressed_imperative` wie `injection` (`Format`, +15).

| Pattern | Kern | Basis | Validator | `requires_context` | `scored_only` | Heutige Regeln |
|---|---|---|---|---|---|---|
| `tp_sensitive_file_param` | Anweisung, `sensitive_path` zu lesen und in einen Parameter zu geben | 45 | Format | nein | nein | neu |
| `tp_secrecy` | Direktive + `secrecy` in Beschreibung | 40 | Format | nein | nein | neu |
| `tp_shadowing` | Beschreibung ändert Verhalten eines **anderen** Tools (`cross_tool`) | 40 | Format | nein | nein | cross_tool_instruction (6) |
| `tp_side_channel_param` | Parameter, der Verlauf, Prompt oder Secrets einsammeln soll | 35 | – | ja | nein | neu |
| `tp_hidden_markup` | versteckte Auszeichnung mit Direktive an das Modell | 30 | Format | ja | nein | neu |
| `tp_preamble_directive` | `preamble` + Handlung ohne Bezug zum Tool-Zweck | 30 | Format | ja | nein | neu |
| `tp_model_address` | Anrede an das Modell in Beschreibung, sonst nichts | 15 | – | ja | **ja** | neu |
| `tp_decoded` | eines der obigen in einer dekodierten Sicht | wie Quelle | wie Quelle | wie Quelle | wie Quelle | neu |

Normalisierungspunkte: Plus wie bei `injection`. Modi wie PII.

## 5. Struktur und Träger

- Der Core liefert je Tool ein Feld (`tool_name`, `description`, je Parameter `name` + `description`).
  Pattern-Spannen bleiben innerhalb eines Tools; `tp_shadowing` braucht einen Tool-Namen, der **nicht** der
  eigene ist (Liste aus derselben Struktur oder generische Tool-Wörter wie „send_email“, „Mail-Tool“).
- Träger Tool-Metadaten zählt wie ein Feldname (+25) und setzt `carrier=tool_metadata`.

## 6. Facts (Auszug)

`finding{…}`, `carrier{tool_metadata, field=description|param|agent_card}`, `tool_name`, `referenced_tools[]`,
`sensitive_path`, `secrecy`, `side_channel_param`, `hidden_markup`, Modifikatoren wie `injection`.

## 7. Modell

Kandidaten: R+A+L, B1, B4, B5. Kein eigener heutiger Scorer; die `cross_tool`-Regeln sind Merkmale im
Injection-Scorer 0.1.7, der als B0-Vergleich mitläuft. Eval: MCPTox (zur Eval-Zeit geladen, nie committet) als
Positive, echte Registry-Beschreibungen als große Benign-Menge; DE über Übersetzung (Dev) und R05.

## 8. Policies (später)

- `tp.file_to_param`: `sensitive_path` ∧ `side_channel_param` im selben Tool → `block`.
- `tp.shadowing_with_sink`: `tp_shadowing` ∧ Senke aus `exfiltration` → `block`.

## 9. Bestand

| Heutige Regeln | Ziel |
|---|---|
| cross_tool_instruction (6), z. B. cross_tool.override_action, cross_tool.override_then_call, governance.cross_tool_next_request | in Tool-Metadaten `tp_shadowing`, sonst `injection_agent_directive` |
| tool_call_injection (2), tool_output_instruction | bleiben `injection` |
| `mcp_policy` (21, heute in `dlp`) | K26 (X04) |

## 10. Übernommene OSS-Regeln

Cisco mcp-scanner YARA (Apache-2.0, Familien tool_poisoning/coercive_injection), ATR; default aus.

## 11. Goldens

Je Pattern und Sprache ≥ 5 Positive und ≥ 5 Hard Negatives. Pflicht-Hard-Negatives: echte
Registry-Beschreibungen mit „Use this tool when …“, legitime Reihenfolge („rufe `list_files` vor `read_file`“),
SSH-/Cloud-Tools, die ihre eigenen Pfade nennen, Scanner-Doku über Tool-Poisoning, dieselbe Anweisung als
reiner Text ohne Tool-Struktur (gehört zu `injection`).

## 12. Herkunft und Daten

Regeln für Herkunft, Splits und Quellfamilien: [README](../README.md#herkunft-regeln-train-gold-holdout).
Goldens: je Pattern und Sprache ≥ 5 Positive und ≥ 5 Hard Negatives, selbst geschrieben (`ark_authored`), §11.

| | Quelle |
|---|---|
| Patterns/Anker | `ark_existing` (cross_tool_instruction 6); `oss`: Cisco mcp-scanner YARA (tool_poisoning, coercive_injection), ATR (Tool-Taktiken); `taxonomy`: OWASP Agentic Threats (Tool Misuse), MCP-Sicherheitshinweise; `mined` auf Train |
| Train/Dev | Generatoren: Einbettung in echte MCP-Registry-Beschreibungen (Dev-Seed), Cisco-YARA-Testfälle; DE-Übersetzung (`ark_authored`) |
| Holdout `neutral` | MCPTox (nur zur Laufzeit geladen, keine Lizenzdatei → nur Eval, nie Train) |
| Holdout `ark_blind` | R05 DE+EN (vergiftete Tool-Listen mit sauberem Zwilling), Seed-Teil der Registry-Einbettung |
| Hard Negatives | echte Beschreibungen aus der offiziellen MCP-Registry und öffentlichen Function-Calling-Schemas (große Menge, je Lizenz der Quelle) |
| Lücke | kein natives DE; DE entscheidet `ark_blind` |
