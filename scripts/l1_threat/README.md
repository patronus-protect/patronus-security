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
