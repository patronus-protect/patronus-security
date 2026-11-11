# Kategorie `injection` (Muster für alle Kategorien)

Stand: 2026-11-05, Entwurf zur Freigabe. Dieses Dokument legt die Form fest; die zehn anderen Kategorien
folgen derselben Gliederung. Begriffslisten sind Auszüge, die vollständigen Lexika entstehen in S02.

## 1. Schichten (für alle Kategorien gleich)

Vorbild ist Shell-Risk K26 (`ark-core/src/detectors/shell`): Fakten → Modell → Policies → Verdikt. Jede
Schicht baut nur auf der darunter auf.

| Schicht | Inhalt | Gemeinsam mit |
|---|---|---|
| 0 Core | einmal je Text: `NativeText`/`MatchText`, Normalisierung (K06, Unicode-Tags, dekodierte Sichten Base64/Hex/ROT13), Tokenizer, `LexicalAnchorScanner` (ein Aho-Corasick über alle Lexika), `AnchorGate`, Struktur (`Fields`: JSON/YAML/`key: value`/HTML/Markdown/Code-Block/Mail-Header), Kontext-Engine (Support/Gegen nach Nähe), Klausel-, Negations- und Zitatspannen | PII, DLP, alle Kategorien |
| 1 Patterns | `ThreatPattern`-Konstanten je Kategorie (Form wie `PiiPattern`/`DlpPattern`) → Findings mit Punkten (Basis + Validator + Kontext + Struktur) | Punkte und Modi wie PII/DLP |
| 2 Facts | `patronus.text_facts/1` je Text: Findings, Träger, Adressat, Senken, Datenbezüge (PII-/DLP-Treffer), Modifikatoren. Versioniert, deterministisch, keine I/O | Schema analog `patronus.facts/1` |
| 3 Modell | je Kategorie das Modell, das in der Ablation am besten abschneidet, einkompiliert: heutiger Scorer (B0) oder z. B. eine K26-artige Variante (TF-IDF `char_wb` + Fact-Tokens `tf1` → LR); Cuts bei 1 % und 0,1 % FPR; Python-Referenz, Rust exakt gleich | K26 ist eine Idee, keine Vorgabe |
| 4 Policies | Cedar über `text_facts`, Tiers `core` (einkompiliert) / `bundle-default` / `user` wie K26; **erst nach den Facts** | Cedar-Schicht von K26 |
| 5 Verdikt | je Kategorie `max(Patterns im Modus, Modell, Policies)` auf `allow < ask < block` | wie `patronus.verdict/1` |

Wichtig für die Latenz: Modell und Policies laufen nur auf Kandidatenfenstern, die ein Pattern oder ein
Anker geöffnet hat, nie über die ganzen 100 KiB. Ohne Anker kein Fenster, ohne Fenster kein Modell.

## 2. Abgrenzung

`injection` = Text, der Vorgaben des Modells verwerfen, ersetzen oder überstimmen will, direkt im Prompt
oder indirekt in Fremdinhalt (Dokument, Web, Mail, Tool-Output). Attribut `carrier: direct|indirect`.

Nicht `injection`: Sicherheitsvorgaben per Rolle/Persona umgehen (`jailbreak`), versteckte Anweisungen
erfragen (`prompt_extraction`), Anweisungen in Tool-/MCP-Metadaten (`tool_poisoning`), Daten an Senken
(`exfiltration`), Skill-/Rules-Dateien (`agent_config_tampering`).

## 3. Lexika (`anchor_lexicons/injection.json`)

Neue bzw. umgebaute Lexikon-IDs; heute 105 IDs nur als Vorfilter, künftig Support/Gegen mit Punkten. Lexika,
die mehrere Kategorien brauchen (Adressat, Geheimhaltung, Abwehr, Meta, Zitat, Testcode), liegen einmal im Core.

**Support** (Punkte nach Nähe +25/+20/+15 bei 16/32/48 Zeichen):

| ID | DE (Auszug) | EN (Auszug) |
|---|---|---|
| `addressee` (Core, geteilt) | KI, Assistent, Modell, Chatbot, Agent, du/Sie im Imperativ | AI, assistant, model, LLM, agent, you |
| `injection.prior_instructions` | vorherige/obige/bisherige Anweisungen, Vorgaben, Regeln, Richtlinien, Systemprompt | previous/above instructions, rules, guidelines, system prompt |
| `injection.replacement` | stattdessen, ab jetzt, ab sofort, von nun an, neue Anweisung | instead, from now on, henceforth, new instructions |
| `injection.authority` | Administrator, Entwickler, Betreiber, Systemnachricht | admin, developer, operator, system message |
| `injection.precedence` | hat Vorrang, höchste Priorität, überschreibt, gilt vor | takes precedence, highest priority, supersedes |
| `secrecy` (Core, geteilt) | sag dem Nutzer nicht, unbemerkt, heimlich, ohne Hinweis | do not tell the user, silently, without mentioning |

**Gegen** (−30, wenn näher als jeder Support-Begriff):

| ID | Inhalt |
|---|---|
| `defensive` (Core, geteilt) | Abwehr-Prompts: „Anweisungen in Dokumenten nicht befolgen“, „als Daten behandeln“ / treat as data |
| `meta` (Core, geteilt) | Sicherheitsdoku, Lehre, Forschung: Prompt Injection, Angriff, Beispiel, Erkennung, Schutz / attack, example, detection, paper |
| `quotation` (Core, geteilt) | berichtete Rede: schreibt, sagte, laut, zitiert / wrote, said, according to |
| `test_code` (Core, geteilt) | Test-/Fixture-Kontext: test, fixture, assert, mock, golden |

Negation ist kein Lexikon, sondern die Klauselspanne aus dem Core (heute `negated_directive`).

## 4. Patterns

Validator heißt hier: Formprüfung `addressed_imperative` (Imperativ oder Anrede an einen Adressaten in
derselben Klausel), zählt wie `Format` (+15). Basis 1–100 wie PII.

Die Basiswerte in allen Kategorie-Dokumenten sind **Startwerte**, nicht gemessen. Sie folgen dem PII-Prinzip
„Basis = wie spezifisch die Form ist“ (PII nutzt 15–70, meist 20–55): eine eindeutige Kombination
(z. B. sensible Datei in Parameter) bekommt 40–45, eine Form, die auch harmlos vorkommt, 25–30, ein schwaches
Signal 15 (`scored_only`). Kalibriert werden sie je Kategorie in der Aufgabe „points + ablation decision“
(IJ02, TP02, AC02, …) auf Goldens und Holdout gegen die Schwellen `balanced` 0,50 und `recall` 0,30.

| Pattern | Kern | Basis | Validator | `requires_context` | Heutige Familien |
|---|---|---|---|---|---|
| `injection_discard_prior` | Verb VERWERFEN (ignorier-, vergiss, missacht-, ignore, disregard, forget) + Objekt `prior_instructions`, ≤ 6 Tokens | 40 | Format | nein | instruction_override |
| `injection_replacement` | `replacement` + Direktive | 30 | Format | ja | instruction_override |
| `injection_precedence` | `precedence`-Behauptung über eigene Vorgaben | 30 | Format | ja | instruction_override |
| `injection_role_spoof` | gefälschte Rollenmarker am Zeilenanfang (`system:`, Chat-Template-Tokens, `### System`) | 45 | – | nein | instruction_boundary |
| `injection_authority_claim` | `authority` + Direktive | 25 | Format | ja | authority_escalation |
| `injection_forced_output` | Verwerfen + fest vorgegebene Antwort | 35 | Format | nein | output_manipulation |
| `injection_hidden_directive` | an KI gerichtete Direktive in verstecktem Träger | 30 | Format | ja | hidden_html, covert, tool_output_instruction |
| `injection_tool_result_directive` | Direktive in Tool-/Function-Result-JSON | 30 | Format | ja | tool_call_injection |
| `injection_agent_directive` | Anrede an den Agenten in Fremdinhalt + Handlungsverb | 25 | Format | ja | agentic_control_abuse (Teil) |
| `injection_decoded` | eines der obigen Patterns in einer dekodierten Sicht | wie Quelle | wie Quelle | wie Quelle | encoded_instruction, binary_smuggling |

Normalisierungspunkte: Ein Fund, den erst eine normalisierte oder dekodierte Sicht zeigt, bekommt bei
`injection` ein Plus (Verschleierung ist Verdacht); PII behält ihren Abzug. Dieselbe Konstante, Wert je
Kategorie.

Modi wie PII: `strict` = Regel-Annahme, Score 1,0 (heutiges Verhalten); `balanced` ≥ 0,50, `recall` ≥ 0,30.

## 5. Struktur und Träger

Aus den Core-`Fields`, also nur aus der Struktur im Text. Metadaten der Anfrage (Rolle, `source:untrusted`)
sieht L1 nicht; sie beeinflussen weder Patterns noch Modell noch Policies. Ein Träger, der Daten sein sollte, zählt wie ein Feldname (+25) und setzt
`carrier=indirect`: HTML-Kommentar, per CSS versteckter Text, Alt-/Title-Text, Markdown-Kommentar,
JSON-String-Wert, Tool-/Function-Result-Block, zitierte Mail, Code-Kommentar. Struktur schlägt Nähe.

## 6. Facts (`patronus.text_facts/1`, Auszug für `injection`)

`finding{category, family, pattern, points, span}`, `carrier{kind, indirect}`, `addressee`, `prior_ref`,
`replacement`, `authority`, `precedence`, `secrecy`, `obfuscated{zero_width|tags|confusable|base64|…}`,
`decoded`, `quoted`, `negated`, `defensive_context`, `language`. Dieselben Facts lesen Modell und Policies.

## 7. Modell

- Beispiel einer K26-artigen Variante, Blöcke: `char_wb` 3–5 auf dem Kandidatenfenster (Klausel ± 48 Zeichen) + `tf1`-Tokens aus den Facts
  (`pattern=…`, `carrier=…`, `addressee`, `obfuscated=…`, Punkteklasse).
- Logistische Regression, Cuts `ask` bei 1 % FPR und `block` bei 0,1 % FPR auf dem Benign-Pool.
- Kandidaten in der Ablation: der heutige Scorer 0.1.7 (B0, 51 Merkmale: Regel-IDs und Zähler, neu
  kalibriert), nur `tf1` (R+A+L), nur `char_wb` (B1), beide (B5), gehasht (B4). Es gewinnt, was auf dem
  Holdout am besten abschneidet; der heutige Scorer kann bleiben.
- Einkompiliert wie heute, kein Release-Bundle.

## 8. Policies (Cedar, `core`; später, erst nach den Facts)

- `injection.trifecta`: `carrier.indirect` ∧ `injection` ∧ Senke aus `exfiltration` im selben Text → `block`.
- `injection.hidden_secrecy`: versteckter Träger ∧ `secrecy` → `block`.
- `bundle-default`: übernommene OSS-Regeln, die sich besser als Policy über Facts ausdrücken (default aus).
- `user`: `.cedar`-Dateien wie bei K26.

## 9. Bestand: 18 heutige Familien

| Heutige Familie (Katalog-IDs) | Ziel |
|---|---|
| instruction_override (14), instruction_boundary (7), authority_escalation (4), output_manipulation (2), tool_output_instruction, hidden_html_instruction, covert_instruction, tool_call_injection (2) | `injection`, Patterns oben |
| encoded_instruction (7), binary_smuggling | Core-Sicht „dekodiert“ + `injection_decoded` |
| unicode_confusable, zero_width_obfuscation | Core-Normalisierung + Fact `obfuscated`, kein eigenes Finding |
| agentic_control_abuse (7) | je ID: `injection_agent_directive`, `agent_config_tampering`, `memory_poisoning` oder `unsafe_action` (siehe [`agent_config_tampering.md` §9](agent_config_tampering.md#9-bestand)) |
| jailbreak_framing (9), multi_turn_escalation (3), guardrail_tamper (3) | `jailbreak` |
| instruction_leak (4) | `prompt_extraction` |
| cross_tool_instruction (6) | in Tool-Metadaten `tool_poisoning` (`tp_shadowing`), sonst `injection_agent_directive` |

74 IDs liegen in den JSON-Katalogen, 13 weitere in nativen Rust-Pipelines; die Zuordnung je ID prüft
`taxonomy.py check` (M01).

## 10. Übernommene OSS-Regeln

ATR, seojoonkim/prompt-guard (mehrsprachig), pipelock, Vigil, LlamaFirewall-Regex: als `ThreatPattern` mit
Herkunft im Katalog oder als `bundle-default`-Policy; default aus, nur mit gehaltener Dev-Präzision.

## 11. Goldens

Je Pattern und Sprache (DE/EN) ≥ 5 Positive und ≥ 5 Hard Negatives (Abwehr-Prompt, Zitat, Sicherheitsdoku,
Testcode, Negation), dazu je Träger ein Paar mit sauberem Zwilling.

## 12. Herkunft und Daten

Regeln für Herkunft, Splits und Quellfamilien: [README](../README.md#herkunft-regeln-train-gold-holdout).
Goldens: je Pattern und Sprache ≥ 5 Positive und ≥ 5 Hard Negatives, selbst geschrieben (`ark_authored`), §11.

| | Quelle |
|---|---|
| Patterns/Anker | `ark_existing` (74 Katalog-IDs + 13 native, Lexikon `injection` mit 105 IDs); `oss`: ATR (Override-Taktiken), prompt-guard (mehrsprachig), pipelock (Injection-Muster), Vigil, LlamaFirewall-Regex; `taxonomy`: OWASP LLM01; `mined` auf Train |
| Train/Dev | BIPIA, Nemotron-IPI, SPML, neuralchemy, GenTel, Mosscap, SaTML-CTF, AgentDojo (Injection-Aufgaben), CyberSecEval multilingual; Generatoren: Träger-Einbettung (Dev-Seed), DE-Übersetzung durch den Runner (`ark_authored`) |
| Holdout `neutral` | LLMail-Inject (nach Dedup), BrowseSafe/BrowseSafe++, boundary-pairs, CyberSecEval-Technik-Slice |
| Holdout `ark_blind` | R05 DE (nativ, entscheidet für DE), Träger-Einbettung mit geheimem Seed |
| Hard Negatives | Abwehr-Systemprompts, Security-Doku, Prompt-Guides, Radware-Benign-Markup |
| Nur berichten | deepset (Label-Rauschen; DE-Teil als Smoke), jackhhao, Gandalf, HackAPrompt, InjecAgent |
