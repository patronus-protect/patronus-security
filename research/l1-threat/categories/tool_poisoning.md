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

## 13. Stand TP01 (2026-11-14)

Fünf Punkte-Regeln im Threat-Detektor (`ark-core/src/detectors/threat/rules.json`, Präfix
`ark.threat.tp_*`, Kategorie `tool_poisoning`, die jetzt den Threat-Producer hat). Sie laufen nur,
wenn der Text Tool-Metadaten trägt (Träger `tool_description` aus `text/facts/carrier.rs`, dieselbe
Marke über `is_tool_metadata`); die Lücken der Regexe überspringen kein `"`, Spannen bleiben also in
einem JSON-String. Entscheidung wie UA01: Punkte ≥ 50, kein Gegenkontext im Satz (oder, außer
Verneinung, im Satz davor), bei `requires_context` ein Stützterm.

| Pattern | Regel | Basis | `requires_context` | Besonderheit |
|---|---|---|---|---|
| `tp_sensitive_file_param` | `tp_sensitive_file_param` | 45 | nein | Verb + sensibler Pfad + Parameterwort |
| `tp_secrecy` | `tp_secrecy` | 40 | nein | Verneinung in der eigenen Spanne zählt nicht als Gegenkontext |
| `tp_shadowing` | `tp_shadowing` | 40 | ja | fremdes Tool (snake_case oder „X tool“/„X-Tool“) + Umleitung/Kopie/Empfänger; nicht „this tool“ und nicht der eigene `"name"` |
| `tp_hidden_markup` | `tp_hidden_markup` | 30 | ja | Kontext ab der Direktive (der Satzschnitt trennt `<!--` am `!`) |
| `tp_side_channel_param` | `tp_side_channel_param` | 35 | nein (Abweichung von §4: Validator `format`) | Verlauf/Systemprompt + Seitenkanal-Feld (`sidenote`, `notes`, `metadata`, …; `context` bewusst nicht, Zusammenfassungs-Tools) |

Lexika: Anker in `anchor_lexicons/tool_poisoning.json` (`toolpoison.sensitive_file`, `.secrecy`,
`.cross_tool`, `.hidden_markup`, `.side_channel`). Offen: `tp_preamble_directive`,
`tp_model_address`, `tp_decoded`, Gegen-Lexika `toolpoison.usage_doc`/`toolpoison.own_domain`
(eigene Pfade schützt heute das Pflicht-Parameterwort), YAML-Tool-Listen als Träger, Harvest der
Cisco-YARA-/ATR-Regeln (default aus, Katalog mit Commit), MCPTox-/Registry-Eval; Punkte/Ablation in
TP02. Bekannte Grenze: ein Meta-Wort (z. B. „example“) im Satz vor der Anweisung dämpft.

Latenz (Release, `rust/dev/l1_latency_workloads.rs`, 100 KiB, Default-Kategorien mit gegen ohne
`tool_poisoning`, gleiche Binärdatei, 2 × 60 Samples je Fenster): deutsche Prosa (4 Fenster) p50
71,97 → 71,35 ms, p95 104,2 → 101,6 ms (im Rauschen; ohne Tool-Struktur läuft keine Regex, nur
die Träger-Marke); Worst Case 100 KiB JSON-Tool-Liste p50 12,64 → 12,98 ms (+2,7 %), p95 17,57 →
18,13 ms (+3,2 %).

## 14. Stand TP02 (2026-11-14): Punkte und Ablations-Entscheidung

**Entscheidung: `B0` bleibt** — die Punkte-Regeln aus TP01/TP02 mit handgesetztem Klauselkontext
entscheiden allein; kein gelerntes Modell wird einkompiliert. Neu bewerten, sobald echte
Tool-Poisoning-Daten jenseits der Generator-Vorlagen im Dev-Split liegen (MCPTox bleibt Holdout).

Daten (nur Dev): die 83 `tool_poisoning`-Zeilen aus `generators_dev_seed:class_templates`
(`mcp_tool_description`, `tool_shadowing`, DE + EN) gegen 15 617 Benign-Zeilen (alle Benign-Zeilen
von `train_dev`, `generated`, `report`, Dolly und GermanQuAD je ein Viertel per sha256 der ID), Hälften per
sha256 der Zeilen-ID. Facts mit Regel-Findings über `text_facts --threat-findings`, B0 aus
`scoreboard.predict` mit dem gebauten Modul, Latenzfenster: 6 × 100 KiB GermanQuAD-Dev-Text
(Ersatz für das E03-Korpus, das in der Sandbox fehlt).

Vor den Regel-Ergänzungen (Regeln aus TP01):

| Stufe | TPR@1 % | DE | EN | Hard-Benign-FPR | ms/100 KiB | RAM |
|---|---|---|---|---|---|---|
| R / R+A | 24,4 | 0,0 | 38,5 | 0,0 | 0 | 0 |
| R+A+L | 61,0 | 100,0 | 38,5 | 3,3 | 0 | 0,3 KiB |
| B1 / B4 / B5 | 100,0 | 100,0 | 100,0 | 6,4 / 5,4 / 0,0 | 16,6 / 10,5 / 10,5 | 5,1 MB / 576 KiB |

Die Auswahlregel hätte `R+A+L` gewählt; dessen Punkte lernen aber nur „DE-Tool-Beschreibung“ aus
den Vorlagen und melden 3,3 % der Hard-Benign-Zeilen. Recall kommt deshalb aus Regeln (Ursachen der
Lücken: deutsche Formen fehlten ganz, Tool-Listen in Klartext galten nicht als Tool-Metadaten):

- Träger `tool_description` auch für Klartext-Tool-Listen: Zeile `Tool|Function|Werkzeug|Funktion
  <snake_case_name>:` (`carrier.rs`, `tool_listing_header!`); dort ist der gelistete Name das
  eigene Tool (`listing_tool_name`), Shadowing braucht ein anderes.
- `tp_shadowing`: nach einem abgelehnten Tool-Namen (eigenes Tool, „das Tool“) sucht die Regel ab
  dessen Ende weiter, statt den ganzen Treffer zu überspringen; die Komponente `replace`
  (Empfänger ersetzen, `redirect`, `stattdessen an`) trägt ihren Kontext selbst, eine bloße
  Zusatzkopie braucht weiter einen Stützterm (`requires_context` bleibt).
- `tp_secrecy` DE: `erwähne/verrate … (das) dem Nutzer (gegenüber) nicht/nie`.
- `tp_hidden_markup`: Tags `<wichtig>`, `<anweisung(en)>`, `<geheim>`, `<versteckt>`; Direktiven
  `vor jedem Aufruf/Einsatz`, `before each/every call`.
- `tp_sensitive_file_param`: Ziel `…/credentials(.json)` (Anker `/credentials`).

Danach (gleiche Zeilen):

| Stufe | TPR@1 % | TPR@0,1 % | DE | EN | Hard-Benign-FPR | ms/100 KiB | RAM |
|---|---|---|---|---|---|---|---|
| R | 100,0 | 100,0 | 100,0 | 100,0 | 0,0 | 0 | 0 |
| R+A | 100,0 | 100,0 | 100,0 | 100,0 | 0,0 | 0 | 0 |
| **B0** | 100,0 | 100,0 | 100,0 | 100,0 | 0,0 | 0 (Status quo) | 0 |
| R+A+L | 100,0 | 100,0 | 100,0 | 100,0 | 4,6 | 0 | 0,9 KiB |
| B1 | 100,0 | 100,0 | 100,0 | 100,0 | 6,4 | 18,7 | 5,1 MB |
| B4 | 100,0 | 100,0 | 100,0 | 100,0 | 5,4 | 10,0 | 576 KiB |
| B5 | 100,0 | 100,0 | 100,0 | 100,0 | 0,0 | 10,0 | 576 KiB |

Auswahl nach der README-Regel: `B0` (günstigste Stufe innerhalb 1 pp der besten; B1/B4/B5 über dem
Budget von 1 ms je 100 KiB). Alle 83 Positiven gemeldet, keine der 15 617 Benign-Zeilen. Vorbehalt:
die Regel-Ergänzungen sind an denselben Vorlagen-Formen entstanden, an denen gemessen wird
(83 Zeilen, zwei Vorlagenfamilien); die Zahl ist eine Obergrenze, das Urteil fällt auf dem Holdout.
Offen wie in §13: `tp_preamble_directive`, `tp_model_address`, `tp_decoded`, Gegen-Lexika,
YAML-Tool-Listen, Harvest der Cisco-YARA-/ATR-Regeln.

Latenz (Release, `rust/dev/l1_latency_workloads.rs`, Default-Kategorien mit gegen ohne
`tool_poisoning`, gleiche Binärdatei, 40 Samples je Fenster; Basis-Build gegen Head nicht gemessen,
das gebündelte E03-Korpus fehlt in der Sandbox): 6 × 100 KiB deutsche Prosa p50 40,94 → 40,61 ms,
p95 56,05 → 58,02 ms (Rauschen); Worst Case 100 KiB JSON-Tool-Liste p50 11,25 → 11,94 ms, p95
13,99 → 16,05 ms; 100 KiB Klartext-Tool-Liste (`Tool get_item_N: …` je Zeile) p50 20,74 → 21,64 ms,
p95 23,68 → 26,56 ms. Zusätzliche Arbeit der Änderung: eine zeilenverankerte Alternative in der
Träger-Marke (eine Regex, einmal kompiliert) und die Kopfzeilen-Suche nur bei einem
`tp_shadowing`-Treffer.
