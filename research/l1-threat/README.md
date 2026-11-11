# L1-Threat: breite Regeln, gelernte Punkte

Stand: 2026-11-11 (Runner-Programm `threat` läuft auf VPS 1 und VPS 2; offen: R03 Baselines-Venv, R05 Blind-Holdout). Aufgabenliste: [`backlog.yaml`](backlog.yaml). Familien je Klasse: [`taxonomy.yaml`](taxonomy.yaml) (Prüfung `scripts/l1_threat/taxonomy.py check`). OSS-Regelinventar: [`oss_rules.yaml`](oss_rules.yaml) (Prüfung `scripts/l1_threat/oss_inventory.py check`). Recherche:
[`research-2026-11.md`](research-2026-11.md). Ausführung über denselben VPS-Runner wie
[`../l1-pii/`](../l1-pii/README.md) und [`../dlp/`](../dlp/README.md), Branch-Präfix `threat/`, Label
`ark-threat`.

## Ziel

ARK erkennt Angriffe auf LLMs und Agents auf L1 (CPU, ohne Transformer) in den Klassen, die Forschung und
Werkzeuge 2025–2026 tatsächlich unterscheiden, und ist gegen die offenen heuristischen Baselines messbar
besser, auf Deutsch deutlich. Die neuen Klassen **ersetzen** die bisherigen sieben Labels in `ark-core` und
ARK; es bleiben keine Alt-Labels. Das Programm arbeitet nur an L1: L2/L3-Modelle werden weder geändert noch
neu trainiert, nur ihre Ausgabe-Labels werden über eine feste Tabelle auf die neuen Kategorien gemappt.

| Klasse | Kurz | Altes Label |
|---|---|---|
| `instruction_injection` | Vorgaben verwerfen, ersetzen, überstimmen; `carrier: direct\|indirect` | prompt_injection, instruction_override |
| `jailbreak` | Sicherheitsvorgaben umgehen (Persona, Policy-Spoofing, Refusal-Suppression, Many-Shot) | instruction_override (Teil) |
| `prompt_extraction` | versteckte Anweisungen, Schemas, Regeln erfragen | instruction_override (Teil) |
| `tool_poisoning` | Anweisungen in Tool-/MCP-Beschreibungen, Schemas, Agent-Cards; Shadowing | tool_abuse (Teil) |
| `agent_config_tampering` | bösartige Anweisungen in Skills, Rules-Dateien, Agent-Config, Hooks | neu |
| `memory_poisoning` | Inhalte, die sich ins Langzeitgedächtnis schreiben wollen | neu |
| `exfiltration` | Daten an externe Senken (Markdown/URL, DNS, Tool-Parameter, Webhook) | exfiltration_attempt |
| `unsafe_action` | Prosa/Code/Config, die destruktive, ausführende, rechteausweitende oder kontrollabschaltende Aktionen verlangt | tool_abuse, harmful_behavior (Teile) |
| `resource_exhaustion` | Endlosschleifen, rekursives Spawnen, Kostenexplosion | neu |
| `harmful_content` | Anfragen nach gefährlichen Inhalten (AILuminate-Hazards) | harmful_behavior |
| `toxic_language` | Hass, Belästigung, Drohung, Beleidigung, Profanität | toxic_or_harmful |

Abgrenzung:
- **Nur Eingaben.** Kein Output-Scanning.
- **`secrets_access` geht in `unsafe_action` auf:** Die drei Regeln erkennen den *Versuch*, an Zugangsdaten zu
  kommen (Credential-Dateien lesen, Credentials einsammeln, Cloud-Metadaten-Endpunkt); DLP findet dagegen
  Secrets, die im Text stehen, und ersetzt das nicht. Sie werden Familie `credential_access` von
  `unsafe_action`; Shell-Formen gehen an K26.
- **Shell-Befehle und Tool-Call-Argumente gehören zu Shell-Risk K26** (`shell_command`, PR #261). Threat
  deckt Prosa-, Code- und Config-Träger ab; Threat-Regeln auf Shell-Syntax gehen in K26 auf.
- **Alles liegt in `ark-core`.** Der Threat-Detektor zieht aus `rust/src/detectors/threat` dorthin um.
- Kein L1-Scope: Rug Pull, Toxic Flows, visuelle Injection, Multi-Turn ohne Sitzungszustand,
  Desinformation, Fachberatung, Urheberrecht.

## Kategorien und Regeln: alles wie bei PII, DLP und Injection

Jede Klasse ist eine Kategorie wie `pii`, `dlp` und `injection`: Sie läuft nur, wenn sie in der Anfrage bzw.
Konfiguration aktiv ist, ist in Bibliothek (`SecurityGateway`), `ark-api`, `ark-coordinator`
(`known_category`) und den Deploy-Configs genauso verdrahtet, und jede einzelne Regel lässt sich wie heute
über `rules: {<rule_id>: true|false}` ein- und ausschalten (Default je Regel wie `default_rule_enabled`).
Keine neuen APIs, keine Sonderwege.

Festgelegt (2026-11-05):
- **Eine Kategorie je Klasse.** `instruction_injection` behält den Kategorienamen `injection`; die Kategorie
  `threat` des alten Unified-Kopfs entfällt.
- **Modus je Kategorie** (`<kategorie>_mode`, Default `strict`), wie `pii_mode`/`dlp_mode`.
- **Default aktiv bleibt `pii`, `dlp`, `injection`.** Alle neuen Kategorien sind opt-in.
- **Übernommene OSS-Regeln sind default aus** und über die `rules`-Map einschaltbar; eigene Regeln default an.
- **L2/L3 unverändert:** Die bestehenden Modelle bleiben, wie sie sind; ihre Labels laufen über die
  Mapping-Tabelle in `ark-core` auf die neuen Kategorien (X03).

Festgelegt (2026-11-09):
- **Aktions-Detektoren ziehen aus `dlp` aus.** `dlp` findet danach nur noch Secrets. Shell-Syntax
  (`mcp_policy`, Befehlsteil von `mcp_runtime_risk`) geht an K26 (X04); `destructive_operation`,
  `sensitive_material` und der Rest von `mcp_runtime_risk` gehen nach `unsafe_action`, `secret_transfer` nach
  `exfiltration` (X03). Wer heute nur `dlp` aktiv hat, bekommt diese Funde erst, wenn er die neuen Kategorien
  einschaltet; das steht im CHANGELOG.
- **L1 analysiert nur Text.** Der Träger kommt allein aus der Struktur im Text; Metadaten der Anfrage
  (Rolle, `source:untrusted`) beeinflussen weder Patterns noch Modelle noch Policies.

## Bauform: einheitlich mit PII und DLP

### Stand heute (main)

| | PII / DLP | Injection | Threat |
|---|---|---|---|
| Regel | `PiiPattern` / `DlpPattern`: Regex, Label, Validator, `base_score`, `captured_value`, `requires_context`, `scored_only` | JSON-Kataloge (Regex, Ordered-Token-Relation, Pflicht-Literale) + native Rust-Pipelines, `severity`, `family` | `rules.json`: 30 Regex mit `class_name` |
| Anker-Lexikon | Support/Gegen je Label, gibt **Punkte nach Nähe** | `injection.json` (105 IDs) **nur als Vorfilter** (`AnchorGate`) | `threat.json` (37 IDs) **nur als Vorfilter** |
| Gegen-Kontext | Lexikon, −30 | Negations-Heuristik im Code | Negations-Heuristik im Code |
| Struktur | Key/Header/`key: value` = Feldname, schlägt Nähe | eigene Struktur-Pipeline | – |
| Score | ganzzahlige Punkte (Basis + Validator + Kontext), DLP baut auf PII-Modell auf | LR über Regel-IDs und Zähler (51 Merkmale), Schwelle 0,96 | LR über Regel-IDs und Zähler (33 Merkmale), Schwelle 0,10 |
| Modi | `strict` / `balanced` / `recall` | keine | keine |

Injection und Threat sind die Ausreißer: Anker sind dort nur Vorfilter, der Score kommt aus einer LR über
„welche Regeln haben gefeuert“, nicht aus dem Kontext.

### Ziel: ein Core, darauf Patterns, darauf Modelle (und später Policies)

| Schicht | Inhalt | PII / DLP |
|---|---|---|
| 0 Core | einmal je Text: Normalisierung samt dekodierter Sichten, Tokenizer, ein Aho-Corasick über alle Lexika, `AnchorGate`, Struktur (`Fields`), Kontext-Engine (Support/Gegen nach Nähe), Klausel-/Negations-/Zitatspannen | ja, von Anfang an |
| 1 Patterns | eine gemeinsame Pattern-Form für alle Kategorien (heute `PiiPattern`/`DlpPattern`): Regex bzw. Ordered-Token-Relation, Kategorie, Validator-Stärke, `base_score`, `captured_value`, `requires_context`, `scored_only`; Punkte und Modi `strict`/`balanced`/`recall` wie PII | ja, von Anfang an |
| 2 Facts | `patronus.text_facts/1` je Text (Findings, Träger, Adressat, Senken, Datenbezüge, Modifikatoren), versioniert und deterministisch | später, zweitrangig |
| 3 Modell | je Kategorie das Modell, das auf dem Holdout am besten abschneidet, einkompiliert: der heutige Scorer, eine K26-artige Variante (TF-IDF-N-Gramme + Fact-Tokens → LR) oder eine andere Ablationsstufe | später, zweitrangig |
| 4 Policies | Cedar über die Facts mit den Tiers von K26 (`core`/`bundle-default`/`user`), z. B. Trifecta; **erst nach den Facts** | später, zweitrangig |
| 5 Verdikt | je Kategorie `max(Patterns im Modus, Modell, Policies)` | – |

Grundsätze:
1. **Erst die Grundstruktur:** Core und Pattern-Form werden zuerst gebaut, und PII und DLP werden in dieselbe
   Form gegossen. Sie werden dabei nicht schlechter: Goldens und Scoreboards bit-identisch, Latenz ohne
   messbaren Verlust. Facts, Modell und Policies für PII/DLP schauen wir uns erst an, wenn die Grundstruktur
   steht.
2. **Klare Modulgrenzen:** Core, Patterns je Kategorie, Facts, Modelle und Policies sind getrennte Module in
   `ark-core`; jede Schicht hängt nur von der darunter ab, nichts wird doppelt implementiert.
3. **Lexika** je Kategorie in `anchor_lexicons/<kategorie>.json` mit Support- und Gegen-Lexikon wie bei PII
   (DE/EN), dieselben Konstanten (Feld +25, Nähe +25/+20/+15, Gegen −30).
4. **Normalisierungspunkte je Kategorie:** Ein Fund, den erst die Normalisierung sichtbar macht, bekommt bei
   PII −10 (unsicherer), bei Angriffskategorien wie `injection` ein Plus (Verschleierung ist Verdacht). Wert
   je Kategorie in derselben Konstante, kein Sonderweg.
5. **Struktur schlägt Nähe:** Der Träger (Tool-Beschreibung, versteckter HTML-Block, JSON-Wert, Rules-Datei,
   Tool-Output) zählt wie ein Feldname und setzt `carrier=indirect`. L1 analysiert nur den Text: Der Träger
   kommt allein aus der Struktur im Text. Metadaten der Anfrage (Rolle, `source:untrusted`) sieht L1 nicht,
   und sie beeinflussen weder Patterns noch Modelle noch Policies (festgelegt 2026-11-09).
6. **Modell:** Was am besten klappt, entscheidet die Ablation; die heutigen Scorer sind gleichberechtigte
   Kandidaten, K26 ist eine Idee, keine Vorgabe. Modelle und Kandidatenfenster laufen nur dort, wo ein Anker
   ein Fenster geöffnet hat.
7. **Erklärbar:** `matched_rules[].context` nennt den entscheidenden Begriff, wie bei PII.
8. **Mehrfachtreffer:** Trifft ein Text mehrere Kategorien (z. B. `injection` und `prompt_extraction`), meldet
   jede aktive Kategorie ihren Fund nach eigenem Modus, auch auf derselben Spanne.
9. **Schwache Signale** (z. B. nur fiktive Rahmung) sind `scored_only` wie bei PII: nie in `strict`, sonst
   niedrige Punkte; vor allem Merkmal für Modell und spätere Policies.
10. **Facts, Modelle und Policies in der Form von cat shell commander (K26)** (festgelegt 2026-11-11):
    `ark-core/src/detectors/shell` ist das Vorbild für Aufbau und Verträge — Facts-Module wie `shell/facts`
    mit kanonischem JSON und Python-Referenz, ein Analyzer `tf1` wie `kf1`, Modelle im K26-Format
    (Vokabular, TF-IDF + LR, Top-Merkmale in der Erklärung), Cedar mit denselben Tiers
    `core`/`bundle-default`/`user`, `.cedar`-Dateien und Allowlist. Was K26 schon hat, wird zum gemeinsamen
    Modul und von beiden genutzt, nicht kopiert; Nutzer schreiben Text-Policies wie Shell-Policies. Welches
    Modell eine Klasse bekommt, entscheidet weiter die Ablation; die Form ist für alle gleich.

Je Kategorie ein Dokument in [`categories/`](categories/) (Muster: [`injection.md`](categories/injection.md)):
[`injection`](categories/injection.md), [`prompt_extraction`](categories/prompt_extraction.md),
[`jailbreak`](categories/jailbreak.md), [`tool_poisoning`](categories/tool_poisoning.md),
[`agent_config_tampering`](categories/agent_config_tampering.md), [`exfiltration`](categories/exfiltration.md),
[`unsafe_action`](categories/unsafe_action.md), [`memory_poisoning`](categories/memory_poisoning.md),
[`resource_exhaustion`](categories/resource_exhaustion.md), [`toxic_language`](categories/toxic_language.md),
[`harmful_content`](categories/harmful_content.md).

Regeln kommen aus zwei Quellen: eigene Familien (Taxonomie M01) und **übernommene OSS-Heuristiken** (MIT/
Apache, nie AGPL) als Katalog mit Herkunft, wie `prompt_armor` und `skillspector`: ATR, pipelock, Cisco
mcp-scanner YARA, seojoonkim/prompt-guard, Vigil, NeMo-YARA, LlamaFirewall. Eine übernommene Regel bleibt
nur, wenn sie auf Dev die Präzision hält.

**OSS-Inventar (M02, [`oss_rules.yaml`](oss_rules.yaml)).** 2.938 Regeln aus zehn Quellen, je Quelle Repo,
gepinnter Commit, Lizenz und Lizenzdatei; je Regel Upstream-ID, Kategorie, Klasse und Familie der Taxonomie,
Sprachen, Ernte ja/nein mit Grund und ein Hash des Regelkörpers (keine Regelkörper im Repo). Alle zehn Quellen
sind MIT oder Apache-2.0; ausgeschlossen bleiben pipelock `enterprise/` (Elastic License 2.0) und das
kodierte Malware-Paket von SkillSpector. citadel liegt heute unter `TryMightyAI/citadel`. Ernte = erlaubte
Lizenz, Klasse zugeordnet, deterministischer Text-Matcher, in Rust-`regex` kompilierbar (kein Lookaround,
keine Rückverweise), aktiv, erste Kopie des Körpers. Stand: 1.937 erntbar; nicht geerntet 574 außerhalb des
L1-Scopes (Secrets/PII im Text → DLP/PII, SQL/XSS/Template/Pfad-Payloads, Malware-Signaturen), 145
Shell-Syntax → K26, 168 Dubletten, 70 nicht portabel, 36 semantisch/Hex, 8 inaktiv. Befunde:
- Deutsch ist dünn: 27 erntbare DE-Regeln, davon 18 aus prompt-guard und 8 aus ATR (vor allem Injection,
  Jailbreak, Exfil); für `prompt_extraction`, `tool_poisoning`, `agent_config_tampering`, `resource_exhaustion`,
  `harmful_content` und `toxic_language` gibt es keine. Der DE-Vorsprung (M2) kommt aus eigenen Familien.
- `toxic_language` hat 7 OSS-Regeln (5 sentinel-ai, 2 ATR), `harmful_content` 80 erntbare (44 ATR, 23
  prompt-guard), fast alle EN.
- Die Zuordnung ist ein erster Durchlauf aus Kategorie-Tabelle und Stichwort-Hinweisen; 229 erntbare
  Regeln tragen `mapping: default` (Klassen-Default-Familie) und gehen in die M04-Durchsicht.
- Die Ernteliste je Klasse liefert `oss_inventory.py harvest --class <klasse>`; die Klassen-Bundles lesen sie
  und übernehmen Regeln default aus.

## Ablationen (B1–B5) unter Budget

Je Klasse wird gemessen, was ein Baustein bringt und kostet:

| Stufe | Inhalt |
|---|---|
| R | nur Regeln |
| R+A | plus Anker-/Kontextpunkte (handgesetzt) |
| B0 | heutiger Scorer der Kategorie (Injection 0.1.7 bzw. Threat 0.1.7), neu kalibriert |
| R+A+L | plus gelernte Punkte (B5 ohne N-Gramme) |
| B1 | Zeichen-N-Gramm-LR allein |
| B4 | gehashte Zeichen-/Wort-LR allein |
| B5 | Hybrid R+A + gehashte N-Gramme, gedeckelt |

Kennzahlen: TPR bei FPR 1 % und 0,1 %, FPR auf sicherheitsnahem Benign-Text, ms je 100 KiB echter DE-Text,
RAM des Modells. Budget je Klasse: Modell ≤ 2 MB, Laufzeit ≤ 1 ms je 100 KiB zusätzlich. Gewählt wird unter
den Modell-Stufen (B0, R+A+L, B1, B4, B5) die günstigste, die innerhalb von 1 pp TPR@1 % der besten liegt; R und
R+A laufen als Vergleichszeilen mit und zeigen, was das Modell beiträgt. Vergleichspunkt: K26 (4,6 MB JSON).

## Definition „besser als die offenen Baselines“

Gemessen auf einem eingefrorenen Holdout unter `~/ark-threat/holdout`, für den Agenten unsichtbar,
SHA-gepinnt. Dokumentebene je Klasse; Recall immer bei gleicher Dokument-FPR auf dem Benign-Pool.

| Meilenstein | Kriterium |
|---|---|
| M1 Heuristik-Parität | Je Klasse: TPR(ARK) ≥ beste Heuristik-Baseline der Klasse bei FPR 1 % (EN) |
| M2 DE-Vorsprung | Je Klasse auf DE: TPR@1 % ≥ beste Baseline + 15 pp |
| M3 Präzision | FPR auf sicherheitsnahem Benign (NotInject, OR-Bench-hard, Security-Doku, Abwehr-Prompts) ≤ 1 % je Klasse in `balanced` |
| M4 Breite | Jede Klasse hat die Pflicht-Familien der Taxonomie in DE und EN und ihre Ablations-Entscheidung |
| Immer | keine Klasse verliert > 0,5 pp TPR@1 %; 0 neue FP auf Hard Negatives; Python↔Rust-Parität exakt; L1 gesamt nicht langsamer als Base + 5 % |

Heuristik-Baselines: pipelock, Cisco mcp-scanner (YARA), ATR, seojoonkim/prompt-guard, LlamaFirewall/NeMo
(deterministische Teile). Selbst trainiert auf denselben Daten: B1–B4. Referenzzeilen: ProtectAI v2 und Prompt
Guard 2 (gated, Lizenz akzeptiert), beide als ONNX über onnxruntime. Baseline-Vorhersagen werden einmal je eingefrorener
Datenversion berechnet und zwischengespeichert, nicht in jedem Lauf.

## Herkunft: Regeln, Train, Gold, Holdout

Festgelegt 2026-11-10. Je Kategorie steht die konkrete Belegung in §12 des Kategorie-Dokuments; hier gelten
die gemeinsamen Regeln.

**Woher Patterns und Anker kommen** (jeder Lexikon-Begriff und jedes Pattern trägt sein Feld `origin`):

| Herkunft | Inhalt | Prüfung |
|---|---|---|
| `ark_existing` | heutige `ark.injection.*`/`ark.threat.*`-Regeln und Lexika, Aktions-Detektoren aus `dlp` | Zuordnung je ID in M01 |
| `oss:<quelle>@<commit>` | lizenzsaubere Regeln (MIT/Apache) aus M02: ATR, pipelock, Cisco mcp-scanner YARA, prompt-guard, Vigil, SkillSpector, sentinel-ai, citadel; nie AGPL, nie unklar | Lizenz und Commit in `oss_rules.yaml`; übernommene Regeln default aus |
| `taxonomy` | Familien aus öffentlichen Taxonomien: OWASP LLM Top 10 (2025), OWASP Agentic Threats, MITRE ATLAS, AILuminate | nur Struktur, kein Text übernommen |
| `mined:<split-hash>` | Kontrast-Mining (Log-Odds mit Prior) **nur auf dem Train-Split**; der Runner prüft jede Liste, bevor sie ins Lexikon geht | Split-Hash im Lexikon; nie aus Dev-Gold, Goldens oder Holdout |
| `hand` | von Hand ergänzt (DE-Komposita, trennbare Verben, du/Sie/ihr) | Golden je Begriffsgruppe |

**Daten-Splits:**

| Split | Zweck | Wer sieht es |
|---|---|---|
| Train | Lexikon-Mining, Modelltraining | Runner |
| Dev | Tuning, Punkte, Schwellen | Runner |
| Goldens (Repo) | Regressionstests je Pattern und Sprache (≥ 5 Positive, ≥ 5 Hard Negatives), selbst geschrieben, Schema v2 (E05) | alle; entscheiden nie |
| Holdout | Meilensteine M1–M4 und Ablation; eingefroren, SHA-gepinnt, nur unter `~/ark-threat/holdout` | nur das Scoreboard, nie der Runner-Agent |
| Benign-Pool | FPR je Sprache, für alle Kategorien | Holdout-Teil wie oben, Dev-Teil getrennt |

Datensätze werden nach Quelle getrennt, nie zufällig gesplittet: Ein Satz ist entweder Train/Dev oder Holdout.
Zusätzlich Leave-one-dataset-out im Scoreboard. Dedup exakt + MinHash innerhalb, über Splits und gegen
bekannte Baseline-Trainingslisten (E01).

**Quellfamilien** (wie bei PII, M03):

| Familie | Quellen | Rolle |
|---|---|---|
| `neutral` | öffentliche Datensätze mit klarer Lizenz | entscheidet |
| `ark_blind` | R05 (DE-Übersetzung des EN-Holdouts und synthetische Items für Klassen ohne öffentliche Daten; separate Claude-Session ohne Runner-Zugriff) und der Seed-Teil der Generatoren (geheimer Seed); von uns, aber für den Runner blind | entscheidet **nur**, wo es keine `neutral`-Daten der Kategorie und Sprache gibt; immer getrennt berichtet |
| `ark_authored` | Goldens, Generator-Ausgaben mit Dev-Seed, Übersetzungen des Runners | wird berichtet, entscheidet nie |
| `baseline_trained` | Sätze, auf denen eine Baseline trainiert wurde | für diese Baseline nur berichtet |
| `report_only` | NC-, GPL- oder unklar lizenzierte Sätze, verrauschte Sätze | nur berichtet |

**Benign-Pool** (alle Kategorien): NotInject, XSTest-safe, OR-Bench-hard, Radware GitHub-IPI (Benign-Markup),
OASST2 EN/DE, WildChat-1M DE (erste Turns), Necent DE (News/Web), Wikipedia, Gerichtsurteile, OWASP/NVD/ATT&CK,
Prompt-Guides; dazu je Kategorie die Hard Negatives aus §12.

Lizenz und kommerzielle Nutzbarkeit prüft E01 je Satz; was dort nicht besteht, wandert nach `report_only`.
Kandidaten, die in den Kategorie-Dokumenten als „Kandidat“ markiert sind, sind noch nicht stichprobengeprüft.
Alles wird zur Laufzeit geladen und nie committet; das Repo enthält nur Rezepte, Manifeste und eigene Goldens.
Hintergrund und Stichproben: [`research-2026-11.md` §5](research-2026-11.md#5-daten).

## Reihenfolge

| Schritt | Wer | Inhalt | Backlog |
|---|---|---|---|
| 1 | Chat | Alle elf Kategorien nach dem Muster [`categories/injection.md`](categories/injection.md) beschreiben (erledigt 2026-11-09) | – |
| 2 | Chat | Plan-PR (dieser Ordner) | – |
| 3 | Setup | Runner-Programm `threat` auf VPS 1 und VPS 2 (nur Pfade), Agent-Prompt, Baselines-Venv | R01–R03 |
| 4 | Setup | DE-Holdout als Übersetzung des eingefrorenen EN-Holdouts (nach E01), synthetisch nur für Klassen ohne öffentliche Daten | R05 |
| 5 | Setup | Timer an | R04 |
| 6 | Runner | Threat nach `ark-core` | X02 |
| 7 | Runner | Grundstruktur: ein Core, eine Pattern-Form; PII und DLP zuerst, ohne Verschlechterung | S01 |
| 8 | Runner | Shell-Syntax-Regeln an K26 | X04 |
| 9 | Runner | Taxonomie-Datei, OSS-Inventar, Mapping; Review durch den Nutzer | M01–M04 |
| 10 | Runner | Elf Kategorien in ARK verdrahten, L2/L3-Labels mappen | X03 |
| 11 | Runner | Messung: Daten, Holdout, Übersetzung, Baselines, Goldens, Scoreboard, Latenzkorpus | E01–E06 |
| 12 | Runner | Lexika, Normalisierung als Fact, Facts | S02, S03, S06 |
| 13 | Runner | Modell-Pipeline und Ablation | S04, S05 |
| 14 | Runner | Kategorien in der Reihenfolge injection → prompt_extraction → jailbreak → tool_poisoning → agent_config_tampering → exfiltration → unsafe_action → memory_poisoning → resource_exhaustion → toxic_language → harmful_content | IJ01 … HC02 |
| 15 | Runner | Hard Negatives, Fuzz, Latenz, Doku, Abschlussbericht | H01–H03 |
| später | – | Cedar-Policies (Trifecta); Facts/Modell/Policies für PII und DLP | S07, S08 |

Gebündelt nach der Speed-up-Entscheidung vom 2026-10-21: ein Bündel = ein Lauf = ein PR.

## Ausführung

- Runner `research/l1-pii/runner/` mit `--program threat`: Backlog `research/l1-threat/backlog.yaml`,
  Prompt `AGENT_PROMPT.threat.md`, Branches `threat/NNN-<id>`, State/Dev/Holdout unter `~/ark-threat`,
  Golden-Eval `13_l1_golden_eval -- threat`, Scoreboard `scripts/l1_threat/` mit eigenem Baselines-Venv.
  Anpassung nur an Pfaden und Orten, keine zusätzlichen Gate-Schritte; Baselines und Modellgewichte werden
  einmalig per Setup installiert.
- Das ganze Programm (alle elf Klassen, also auch `injection` und `toxic_language`) läuft auf den bestehenden
  VPS 1 und VPS 2 im einheitlichen Runner, 2-h-Takt, in zwei Lanes wie DLP: VPS 2 Lane a (X, S, M, E und
  `injection` bis `exfiltration`), VPS 1 Lane b (`unsafe_action` bis `harmful_content`, H); Lane b startet, sobald
  ihre Abhängigkeiten fertig sind (Lane-Mechanik wie bei DLP, keine neue Runner-Logik). Holdout und Baselines-Venv liegen auf beiden Hosts (gleicher SHA).
  Der Programmname `threat` im Runner ist nur der
  Sammelname, keine Kategorie. Der Timer startet erst, wenn Backlog und PR #261 (K26) auf
  `main` sind.
- Übersetzungen macht der Runner-Agent selbst (kein externer MT-Dienst). Den DE-Holdout (R05) übersetzt eine
  eigene Claude-Session ohne Runner-Zugriff einmal aus dem eingefrorenen EN-Holdout (entschieden 2026-11-11).
- Ein Lauf = ein Bündel, Tests zuerst, unabhängiges Gate, PR erst bei grüner CI, Auto-Merge des untersten
  grünen PRs wie bei PII/DLP.
- Inhalte im öffentlichen Repo: keine funktionierenden Schadanleitungen, keine Klartext-Slur-Listen
  (Toxizitäts-Lexika gehasht), keine Angriffs-Payloads aus Datensätzen.
- Montags `TRIAGE` wie bei PII/DLP.
