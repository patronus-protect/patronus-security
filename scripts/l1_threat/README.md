# L1-Threat-Messwerkzeuge

## Taxonomie-Prüfung

`taxonomy.py` prüft [`research/l1-threat/taxonomy.yaml`](../../research/l1-threat/taxonomy.yaml), die
Familien je Klasse (Wortklassen-Form, Anker, Pflicht- und Gegenkontext, DE/EN-Beispielformen, Träger,
heutige Regeln, Baseline-Abdeckung, Lücke, Priorität, Backlog-Aufgabe).

```bash
python3 scripts/l1_threat/taxonomy.py check     # Exit 1 bei jedem Problem
python3 scripts/l1_threat/taxonomy.py summary   # Familien und Regeln je Klasse
```

`check` schlägt fehl, wenn
- eine heutige Regel (`ark.injection.*` aus den Injection-Katalogen, der nativen Registry und den nativen
  Struktur-Regeln, `ark.threat.*` aus `rules.json`) nicht oder mehrfach zugeordnet ist (Familie oder
  Übergabe an Shell-Risk unter `handoffs`), oder eine zugeordnete Regel-ID nicht existiert;
- eine `must`-Familie keine Aufgabe nennt oder eine Aufgabe nicht in `backlog.yaml` steht;
- eine Lexikon-ID weder in `ark-core/src/detectors/anchor_lexicons/*.json` steht noch in der Taxonomie als
  geplant deklariert ist (Kern-Lexika oben, Klassen-Lexika unter `lexicons` der Klasse);
- Klassen, Schlüssel, Prioritäten, Träger oder Baselines nicht dem Schema entsprechen.

Tests: `scripts/tests/test_l1_threat_taxonomy.py`.

## OSS-Regelinventar

`oss_inventory.py` baut und prüft [`research/l1-threat/oss_rules.yaml`](../../research/l1-threat/oss_rules.yaml),
das Inventar der übernehmbaren Regeln offener Heuristik-Detektoren (ATR, pipelock, Cisco mcp-scanner YARA,
prompt-guard, Vigil, NeMo-YARA, LlamaFirewall-Regex, SkillSpector-YARA, sentinel-ai, citadel). Der Kopf der
Datei (Quellen mit gepinntem Commit, Lizenz, Pfaden, Kategorie-Tabelle, Hinweisen, Default-Familien) wird von
Hand gepflegt; `build` erzeugt `rules` und `counts` aus lokalen Klonen neu. Regelkörper landen nie in der
Datei, nur ein kurzer SHA-256.

```bash
# je Quelle ein Klon <DIR>/<owner>_<repo> auf dem gepinnten Commit
python3 scripts/l1_threat/oss_inventory.py build --src <DIR>
python3 scripts/l1_threat/oss_inventory.py check                       # Exit 1 bei jedem Problem
python3 scripts/l1_threat/oss_inventory.py summary                     # Regeln je Klasse und Sprache
python3 scripts/l1_threat/oss_inventory.py harvest --class exfiltration
```

`check` schlägt fehl bei Schemafehlern, einem Commit, der kein 40-stelliger SHA ist, einer unbekannten Lizenz,
einer geernteten Regel aus einer Quelle ohne MIT/Apache-2.0, einem Regelkörper im Eintrag, unbekannter Klasse
oder Familie (gegen `taxonomy.yaml`), einer geernteten Regel ohne Klasse und Familie, doppelten Regel-IDs und
Zählungen, die nicht zu den Regeln passen.

Tests: `scripts/tests/test_l1_threat_oss_inventory.py`.

## Baseline- und Datensatz-Mapping

`entity_map.py` prüft [`research/l1-threat/entity_map.yaml`](../../research/l1-threat/entity_map.yaml): wie jede
Baseline des Scoreboards auf die elf Klassen zählt (Heuristiken über die Regelzuordnung in `oss_rules.yaml`,
dazu ihre weiteren deterministischen Scanner; ProtectAI v2 und Prompt Guard 2 über ihre Ausgabe-Labels) und je
Datensatz Lizenz, Sprachen, Split, Quellfamilie und die Zuordnung jedes Upstream-Labels zu Klassen, `benign`
oder `out_of_scope` mit Grund.

```bash
python3 scripts/l1_threat/entity_map.py check   # Exit 1 bei jedem Problem
python3 scripts/l1_threat/entity_map.py table   # wer je Klasse und Sprache entscheidet (Markdown)
```

`check` schlägt fehl bei Schemafehlern, einer unbekannten Klasse oder Familie (gegen `taxonomy.yaml`), einer
Baseline, die nicht in der Taxonomie steht (oder umgekehrt), einer heuristischen Baseline ohne Quelle in
`oss_rules.yaml` oder mit einer Regel ohne Klasse, Übergabe oder `out_of_scope`, einer NC- oder GPL-Lizenz
außerhalb von `report_only`, `ark_blind` außerhalb des Holdouts, `ark_authored` im Holdout, unbekannten
`trained_on`-Sätzen, und bei jeder Klasse und Sprache (DE, EN), die weder `neutral`- noch `ark_blind`-Holdout
entscheidet und nicht unter `gaps` steht. `ark_blind` entscheidet nur, wo kein `neutral`-Holdout-Label die
Klasse in der Sprache abdeckt; `decides: false` hält ein Label nur berichtet.

Tests: `scripts/tests/test_l1_threat_entity_map.py`.
