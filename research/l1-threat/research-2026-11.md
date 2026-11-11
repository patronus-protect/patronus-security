# L1-Threat: Recherche-Synthese (Stand 2026-11-04)

Grundlage für [`README.md`](README.md) und [`backlog.yaml`](backlog.yaml). Quellen: Zensus von rund 3.000
GitHub-Repos (128 erkennende/blockierende Tools ausgewertet, 22 Red-Team-/Eval-Tools), rund 85 Paper und
Standards 2024–2026, Literatur zu klassischen kleinen ML-Verfahren, Datenrecherche mit Stichproben. Diese
Datei enthält bewusst keine Angriffs-Payloads; Familien sind abstrakt beschrieben.

## 1. Was das Feld erkennt

Zusammengeführt aus den Kategorienamen der Tools und den Taxonomien von OWASP LLM Top 10 2025, OWASP
Agentic Top 10 2026 (ASI01–ASI10), MITRE ATLAS (Agent-Techniken 2025/2026), NIST AI 100-2e2025, CoSAI MCP,
CSA MAESTRO, AILuminate v1.0 und den Guard-Modell-Kategorien (Llama Guard 4, Qwen3Guard, Nemotron).

| Cluster | Tools (≈) | rein heuristisch abgedeckt | L1-lexikalisch |
|---|---:|---|---|
| Injection direkt | 85 | ja | hoch |
| Injection indirekt (Tool-Output, Web, Mail, RAG) | 45 | ja | hoch/teils |
| Override, Rollen-/Grenzmarker-Spoofing | 40 | ja | hoch |
| Jailbreak (Persona, Policy-Spoofing, Refusal-Suppression, Many-Shot, CoT-Hijack) | 45 | teils | teils |
| System-Prompt-Extraktion (Eingabeseite) | 25 | ja | hoch |
| Obfuskation / unsichtbarer Text | 40 | ja (normalisieren, erneut scannen) | hoch |
| MCP-Tool-Poisoning, Shadowing, A2A-Agent-Cards | 30 | ja (YARA) | hoch |
| Skill-/Rules-/Config-Supply-Chain (AGENTS.md, .cursorrules, mcp.json, Hooks) | 25 | ja | hoch |
| Memory-Poisoning | 12 | teils | teils |
| Toxic Flows / Lethal Trifecta | 10 | Policy | nur Merkmal |
| Exfiltration (Markdown/URL, DNS, Tool-Parameter, Webhook) | 40 | ja | hoch |
| Unsichere Aktionen (destruktiv, RCE, Rechte, Tampering, Persistenz, SSRF) | 35 | ja | hoch |
| Endlosschleifen / Kostenexplosion | 12 | Zähler | teils |
| Manipulation von Auswahl und UI (Agent-Clickbait, Preference Manipulation) | wenige | teils | teils |
| Harm-Kategorien (AILuminate; Selbstverletzung und Child Safety getrennt) | 20 | nein (Guard-LLMs) | teils |
| Toxizität (Hass, Belästigung, Drohung, Beleidigung, Profanität) | 30 | nur Profanitätslisten | teils; Zeichen-N-Gramme gut |
| Topic-Bans, Halluzination, Bias, Gibberish, Sprache | – | – | kein L1-Scope |

Trends 2025–2026: Der Agent ist das Ziel, nicht das Modell; Tool-Metadaten, Skills und Rules-Dateien sind
eigene Träger; Memory als Persistenzschicht; Exfiltration als Fluss (nicht vertrauenswürdige Quelle +
private Daten + Senke); Angriffe auf Reasoning-Modelle; UI-Täuschung für Computer-Use-Agents;
Mehrsprachigkeit als Standard.

## 2. Klassen für L1 (ersetzt die bisherigen sieben Labels)

| Klasse | Inhalt | Träger | Altes Label |
|---|---|---|---|
| `instruction_injection` | Anweisungen, die Vorgaben verwerfen, ersetzen oder überstimmen; Attribut `carrier: direct\|indirect` | Prompt, Dokument, Web, Tool-Output | prompt_injection + instruction_override |
| `jailbreak` | Techniken zum Umgehen von Sicherheitsvorgaben | Prompt | Teil von instruction_override |
| `prompt_extraction` | Aufforderungen, versteckte Anweisungen, Tool-Schemas oder Regeln preiszugeben | Prompt, Fremdinhalt | Teil von instruction_override |
| `tool_poisoning` | Anweisungen in Tool-/MCP-Beschreibungen, Schemas, Agent-Cards; Shadowing | Tool-Metadaten | Teil von tool_abuse |
| `agent_config_tampering` | bösartige Anweisungen in Skills, Rules-Dateien, Agent-Konfiguration, Hooks | Config/Skill | neu |
| `memory_poisoning` | Inhalte, die sich in Langzeitgedächtnis oder Profil schreiben wollen | Prompt, Fremdinhalt | neu |
| `exfiltration` | Daten an externe Senken (Markdown/URL, DNS, Tool-Parameter, Webhook) | Fremdinhalt, Prosa, Code | exfiltration_attempt |
| `unsafe_action` | Prosa-/Code-/Config-Aufforderungen zu destruktiven, ausführenden, rechteausweitenden, Kontrollen abschaltenden Aktionen | Prosa, Code, Config | Teil von tool_abuse/harmful_behavior |
| `resource_exhaustion` | Endlosschleifen, rekursives Spawnen, Kostenexplosion | Prompt, Fremdinhalt | neu |
| `harmful_content` | Anfragen nach gefährlichen Inhalten (AILuminate-Hazards) | Prompt | harmful_behavior |
| `toxic_language` | Hass, Belästigung, Drohung, Beleidigung, Profanität | Prompt, Fremdinhalt | toxic_or_harmful |

Modifikatoren (keine Klassen): Obfuskation, Sprache, Schweregrad, Vertrauensstufe der Quelle.

Abgrenzung:
- `secrets_access` (Zugriffsversuch auf Zugangsdaten, nicht Secrets im Text) wird Familie `credential_access`
  von `unsafe_action`; DLP findet nur Secrets, die im Text stehen.
- Shell-Befehle und Tool-Call-Argumente gehören zu Shell-Risk K26 (`shell_command`,
  `patronus-studio/cat-shell-risk-commander`: Fakten + TF-IDF/LR + Cedar-Policies). Threat L1 deckt
  Prosa-, Code- und Config-Träger ab; Threat-Regeln, die Shell-Syntax matchen, gehen in K26 auf.
- Nur Eingaben: kein Output-Scanning (z. B. Prompt-Leak in Antworten).
- Kein L1-Scope: Rug Pull (braucht Diff), Toxic Flows (Fluss-Ebene), visuelle Injection,
  Multi-Turn-Eskalation ohne Sitzungszustand, Desinformation, Fachberatung, Urheberrecht.

## 3. Heuristiken übernehmen und vergleichen

Übernehmbar (Lizenz MIT/Apache, Katalog mit Herkunft wie `prompt_armor`/`skillspector`; AGPL nie):

| Quelle | Lizenz | Inhalt | Rolle |
|---|---|---|---|
| Agent Threat Rules (ATR) | MIT | Sigma-artiges Regelformat, 10 Taktiken, 80 Techniken; von Microsoft AGT und Cisco übernommen | Regelquelle + Baseline |
| pipelock | Apache-2.0 | 65 DLP- und 34 Injection-/Poisoning-Muster, 6-fache Normalisierung, URL/SSRF/DNS-Tunnel | Exfil-Baseline + Regelquelle |
| Cisco mcp-scanner (YARA) | Apache-2.0 | 10 Familien inkl. tool_poisoning, coercive_injection, data_exfiltration | MCP-Baseline + Regelquelle |
| seojoonkim/prompt-guard | MIT | über 840 Regex, Dekodierung, 10 Sprachen inkl. DE/FR/ES/PT | mehrsprachige Regelquelle |
| LlamaFirewall (Regex, Hidden-ASCII, CodeShield), NeMo (YARA, Regex-Rails) | prüfen | deterministische Teile | Baseline |
| Vigil (YARA), SkillSpector static, sentinel-ai, citadel | Apache/MIT | kleinere Regelwerke, Skill-Scanner | Regelquelle |
| DefenseClaw | – | Rego/YARA-Packs | bereits in K26 übersetzt |

Mehrsprachige Heuristiken sind selten (prompt-guard, sentinel-ai, citadel, ATR, mcpproxy-go). Prompt Guard 2
und ProtectAI v2 markieren 38–41 % sicherheitsnaher Benign-Texte
(PIDS-Bench 2026) und sind heuristisch schlagbar; beide laufen nur als Referenzzeile. Wolf Defender ist unser eigenes Modell, kein Vergleich.

## 4. Klassische kleine ML-Verfahren (Ablationen)

| ID | Verfahren | Erwartung |
|---|---|---|
| B1 | Zeichen-N-Gramme 2–5 + LR (Bestgen/HASOC) | sprachunabhängig, robust gegen Obfuskation |
| B2 | Wort 1–2 + Zeichen 2–6 + LR (Jigsaw-Rezept) | stärkstes lineares Modell in-distribution |
| B3 | NB-SVM | generalisierte auf Jigsaw am besten |
| B4 | gehashte Zeichen-/Wort-LR (2^18–2^22) | auslieferbare Form, Hash-Parität Python↔Rust |
| B5 | Hybrid B4 + Regel-, Anker-, Strukturmerkmale | Produktionskandidat |
| B6/B7 | LightGBM monoton, fastText | optional |

Integration (Prinzip SpamAssassin): additives Punktemodell je Klasse; Regel-/Anker-Gewichte ≥ 0,
Dämpfung (Code, Zitat, Lehr-Kontext, JSON-Wert, Abwehr-Prompt) ≤ 0; N-Gramm-Anteil gedeckelt, kann allein
nicht blockieren; Fenster-Max-Score gegen Verdünnung; ganzzahlige Punkte wie PII/DLP. Vorbild im eigenen
Haus: Shell-Risk K26 (Fakten + LR + Policies, Schwellen bei 1 % / 0,1 % FPR).

Belegte Fallstricke: Zufallssplits überschätzen massiv (außerhalb der Verteilung F1 ≤ 0,43, 72 % der
OOD-Fehler selbstsicher) → Leave-one-dataset-out und Holdout je Angriffsfamilie; sicherheitsnaher
Benign-Text ist der Engpass (TF-IDF-LR 41 % FPR, reine Regex 23 %); lexikalische Modelle übertragen
schlecht zwischen Sprachen; TPR bei fester niedriger FPR veröffentlicht für TF-IDF-Injection-Detektoren
niemand → eigene Kennzahl.

Nicht auf L1: Transformer (auch nicht auf Kandidatenfenstern), GPT-2-Perplexität, gzip-kNN, isotonische
Kalibrierung bei kleinen Mengen, ort/FFI, Merkmale vor der Unicode-Normalisierung.

## 5. Daten

Stichprobengeprüft, Note A–C; nur zur Laufzeit geladen, nie committet; Revision gepinnt.

| Rolle | Datensätze |
|---|---|
| Entscheidend: Injection/Jailbreak | LLMail-Inject (A−, menschlich, Mail, nach Dedup), TrustAIRLab in-the-wild Jailbreaks (B+), BrowseSafe/BrowseSafe++ (Web), boundary-pairs (gepaarte Hard Negatives), CyberSecEval-Technik-Slice |
| Entscheidend: Agent/Tool | MCPTox (Tool-Poisoning, ohne Lizenz-Datei; nur zur Laufzeit), MaliciousSkillBench (quellen-disjunkt), agentapprove tool-call-safety (A−, versiegelter Holdout), AgentHarm |
| Entscheidend: Harm | aya_redteaming FR/ES (A, nativ), MultiJail IT, JBB-Behaviors, HarmBench |
| Entscheidend: Toxizität DE/EN | GAHD (A, Kontrastpaare), GermEval 2018 (Test-Split), HateCheck-DE/EN, RTP-LX de/en, Measuring Hate Speech (EN) |
| Entscheidend: FPR | NotInject (A), XSTest-safe, OR-Bench-hard, Radware GitHub-IPI-in-the-wild (Benign-Markup, A), je Sprache Benign aus OASST2, Wikipedia, Gerichtsurteilen, OWASP/NVD/ATT&CK, Prompt-Guides |
| Dev | neuralchemy, SPML, GenTel, PolyGuardPrompts, Nemotron v3, CyberSecEval multilingual, Mosscap, SaTML-CTF, BIPIA, AgentDojo, Nemotron-IPI, Agent-SafetyBench, RedCode, WildJailbreak/WildGuardMix, GermEval 2018/2019/2021 |
| Nur berichten | deepset (C, Label-Rauschen), jackhhao, Gandalf, HackAPrompt, InjecAgent, Civil Comments/Jigsaw (Baseline-Training), alle NC- oder unklaren Sätze |

Was wir bauen:
1. **DE-Injection/Jailbreak per Übersetzung** der entscheidenden EN-Sätze, als übersetzt markiert, mit
   Stichprobe von Hand. Die HF-Suche (5.1) fand keine nativen DE-Injection-Daten nennenswerter Größe;
   daher zusätzlich ein **selbst geschriebener nativer DE-Holdout** (du/Sie, Umgangssprache, Tippfehler)
   für Injection, Jailbreak und Extraction.
2. **Träger-Einbettung:** echte Benign-Träger (Web, PDF, Ticket, Code-Kommentar, RAG-Chunk) mit eingesetzter
   Injection an zufälliger Stelle, jeweils mit sauberem Zwilling.
3. **Exfil in Tool-Outputs** (Markdown-Bild, URL-Parameter, DNS/Webhook) plus harmlose Doppelgänger
   (normale Bildlinks, Tracking-URLs), gleiche Methode.
4. **Obfuskations-Slices** deterministisch aus Holdout-Seed (Homoglyphen, Zero-Width, Base64, Leetspeak,
   gesperrt).
5. Toxizität: DE/EN genügt vorerst.

### 5.1 HF-Suche nach nativen Daten (DE/FR/IT/ES/PT, 2026-11-04)

Rund 290 Abfragen mit Sprach-, Task- und Tag-Filtern; etwa 110 Karten gelesen, etwa 45 Sätze stichprobengeprüft
(Sprachanteil, Labels, Dubletten, du/Sie-Verhältnis, englische Reste).

| Bereich | Befund | Folge |
|---|---|---|
| Injection/Jailbreak | Kein nativer Satz nennenswerter Größe. Nativ DE nur der deutsche Teil von deepset (~240) und wenige handgeschriebene Zeilen; fast alle „multilingualen“ PI-Sätze sind MT oder Umverpackungen derselben 2–3 Wurzelsätze | deepset-DE nur als Smoke, gegen alle Trainingsquellen dedupliziert; **nativer DE-Holdout wird selbst geschrieben**; Übersetzung bleibt Dev und eigene Spalte |
| Agent/Tool/MCP, Extraction, Exfil | Nichts Natives in irgendeiner Zielsprache; bestes DE: ProCreations/approve-or-deny (82, LLM-nativ) | Träger-Einbettung und Übersetzung wie oben |
| Synthetisch brauchbar | ai-safety-brazil PI/JB (PT, 10k je Satz, CC-BY), XL-SafetyBench (DE/FR/ES Jailbreak, CC-BY) | Dev/Training, nie entscheidend |
| Harm | Nativ FR/ES über aya_redteaming; IT MultiJail (HT); DE nur RTP-LX (transcreated) und PolygloToxicityPrompts `wildchat-de` (echte Nutzer) | DE-Harm berichten; Nemotron v3/PolyGuard-DE nur als MT-markiertes Dev |
| Toxizität | Nativ in allen Sprachen reichlich. DE: GermEval18/21/25, GAHD (ohne Runde R2, teils übersetzt), HateCheck-DE, textdetox-de, chatmod-bench | Holdout GermEval18 + GAHD + HateCheck-DE + chatmod-bench; textdetox-de als Dev; GermEval25 GPL, GerMS-AT NC: nur berichten |
| DE Hard Negatives | Native Benign-Seite von Necent (News/Web), WildChat-1M DE (erste Turns), OASST2 DE | in den DE-Benign-Pool |
| Meiden | MT-Moderationssätze (KoalaAI/enguard), tanaos-DE (Grammatikfehler), Aggregate aus deepset+MT (bis 23 % Dubletten, Kontamination) | nicht verwenden |

Messung: je Klasse und Sprache TPR bei FPR 1 % und 0,1 % auf dem Benign-Pool der Sprache, AUPRC,
Bootstrap-95-%-KI, Delta auf gepaarten Slices, getrennte Spalten nativ/übersetzt, Kontaminationsspalte je
Baseline.

## 6. Bestand in ARK (main, 2026-11-04)

- Injection (`ark-core/src/detectors/injection`, `ark-core/src/threat/patterns.rs`): 87 `ark.injection.*`-IDs,
  18 native Familien, Kataloge (Governance, SkillSpector, Source-derived, prompt-armor), EN+DE; Logistic-
  Scorer 0.1.7 (51 Merkmale, Schwelle 0,96); Dokument-Recall ≈ 1,5 %.
- Threat (`rust/src/detectors/threat`): 30 Regeln, Scorer 0.1.7 (33 Merkmale, Schwelle 0,10), Recall 0,07
  bei FPR 0,0004; viele Regeln sind Shell-/Infra-Syntax (EN).
- MCP-Policy (21 Regeln), mcp_runtime_risk, destructive_operation, secret_transfer, Shell-Risk K26.
- Anker-Lexika: injection 105, threat 37, dlp 59, pii 146 IDs; ein gemeinsamer Aho-Corasick-Scanner,
  `AnchorGate` als notwendige Bedingung.
- Threat/Injection haben kein Punktemodell und keine Modi; Toxizität fehlt in L1 ganz; Harm hat 4 Regeln.
