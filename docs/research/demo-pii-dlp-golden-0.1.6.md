# PII/DLP demo Golden 0.1.6

Stand: 2026-09-02. Injection ist nicht Teil dieses Sets.

## Zweck

Dieses Golden friert nicht nur die drei Texte der Live-Demo ein. Es leitet aus
den Ideen `Kundendaten`, `Quellcode` und `Personalakte` deutsche und englische
Varianten sowie Hard Negatives ab. Damit lässt sich entscheiden, welche
Fähigkeiten die Demo stabil zeigen kann und welche Formulierungen noch nicht
als Produktversprechen taugen.

Quelle:

- `python/patronus_ark/benchmark_data/demo_pii_dlp.jsonl`
- 21 Dokumente: sieben je Szenario
- drei unveränderte Live-Demo-Texte, 15 Augmentierungen, drei Hard Negatives
- 12 deutsche und neun englische Dokumente
- 87 erwartete Spans: 75 native PII/DLP-L1, 12 semantische GLiNER-Namen

Zwei zusätzliche, implementation-blind formulierte Erweiterungen verbreitern
die Dokumentformen und dienen bewusst auch zum Sichtbarmachen heutiger Lücken:

- `demo_pii_dlp_blind_de.jsonl`: 30 deutsche Kundendaten-/Personalaktenfälle,
  davon sechs Hard Negatives;
- `demo_pii_dlp_blind_en_tech.jsonl`: 36 englische bzw. technische Fälle,
  davon zehn Hard Negatives;
- zusammen mit dem kuratierten Kern: 87 Dokumente, 204 erwartete Spans,
  42 deutsche und 45 englische Dokumente.

Die Autoren dieser Erweiterungen kannten weder Ark-Regeln noch Regexe. Formal
prüfbare Positivwerte (IBAN, Provider-Keys, bcrypt und PEM) wurden anschließend
validiert. Freie Mitarbeiterkennungen wie `P-778301`, `EMP_00917` oder
`EMP-SYN-8820` wurden dagegen absichtlich nicht an bestehende Ark-Muster
angepasst: Ein klarer Feld-Anchor plus Kennungswert ist die Ground Truth und
eine Nichterkennung damit eine echte Produktlücke.

Die Live-Texte wurden am 2026-09-02 von
[`https://patronus.studio/demo`](https://patronus.studio/demo) übernommen.
Alle weiteren Fälle sind synthetische, eindeutig gekennzeichnete Ableitungen.

## Gemessener Stand

Produktionsnahe GLiNER-Messung bedeutet hier das vollständige Default-Labelset,
nicht ein künstlich vereinfachter Lauf nur mit dem Label `person`.

| Arm | Exact Precision | Exact Recall | Exact F1 |
|---|---:|---:|---:|
| PII + DLP L1, gesamtes Set | 94,5 % | 92,0 % | 93,2 % |
| GLiNER `person`, gesamtes Set | 60,0 % | 100,0 % | 75,0 % |
| PII + DLP L1, nur drei Live-Texte | 100,0 % | 100,0 % | 100,0 % |
| GLiNER `person`, nur Live-Texte | 66,7 % | 100,0 % | 80,0 % |

GLiNER findet alle zwölf erwarteten Namen exakt. Die geringere Precision kommt
von acht zusätzlichen `person`-Spans, hauptsächlich E-Mail-Localparts,
Credential-Werten und Identifiern. Für die Demo ist die Namensabdeckung damit
stabil; zusätzliche semantische Spans müssen im UI dedupliziert bzw. gemeinsam
mit den deterministischen Findings behandelt werden.

### Native Klassen

| Klasse | Exact Ergebnis | Demo-Einschätzung |
|---|---:|---|
| `EMAIL` | 12/12 Recall | zeigen |
| `EMPLOYEE_ID` | 6/6 Recall | zeigen |
| `API_KEY`, `CLOUD_KEY`, `PAYMENT_KEY`, `SECRET_TOKEN` | 6/6 kombiniert | zeigen |
| `CREDENTIAL` | 5/5 Recall, ein zusätzlicher Span | zeigen |
| `dlp.content.source_code` | 6/6 Recall | zeigen |
| `dlp.content.sql` | 4/4 Recall, ein Hard-Negative-FP | zeigen, als heuristisches Finding |
| `IBAN` | 5/6 Recall | deutsche und kompakte validierte Formen zeigen |
| `PHONE` | 11/12 Exact, 12/12 Overlap | DE/international zeigen; US-Klammergrenze nicht versprechen |
| `dlp.internal.business_metric` | 14/18 Recall | derzeit deutsche Demoformulierungen zeigen |

Die vier Metric-Misses sind englische Varianten (`gross margin`,
`contribution margin`, `Margin`) und `Forecast 40.8 million USD`. Das ist eine
klare Präsentationsgrenze, kein Grund, die stabilen deutschen Varianten aus der
Demo zu entfernen.

### Blinde Erweiterung

Die Erweiterung ist ein Benchmark, kein auf den heutigen Detector kuratierter
Release-Gate. Deshalb bleibt der 21-Fälle-Kern separat messbar und seine
Assertions werden nicht abgeschwächt.

| Arm, alle 87 Dokumente | Exact Precision | Exact Recall | Exact F1 | Overlap Recall |
|---|---:|---:|---:|---:|
| PII + DLP L1 | 84,8 % | 79,9 % | 82,3 % | 83,1 % |
| GLiNER `person` | 59,0 % | 92,0 % | 71,9 % | 98,0 % |

Die wichtigsten L1-Ergebnisse über alle 87 Dokumente sind: `EMAIL` 24/24,
`CLOUD_KEY` 3/3, `PAYMENT_KEY` 2/2, `SECRET_TOKEN` 3/3, `PRIVATE_KEY` 1/1,
`CRYPTO_KEY` 1/1, `PASSWORD_HASH` 1/1, `IBAN` 10/12, `PHONE` 20/22,
`EMPLOYEE_ID` 19/19 und interne Geschäftszahlen 17/32. Die zunächst fehlenden
zehn Mitarbeiterkennungen wurden als neue L1-Anchor-, OCR- und strukturierte
Präfixvarianten aufgenommen; im Golden entstehen dadurch keine zusätzlichen
`EMPLOYEE_ID`-False-Positives.

## Empfehlung für die Live-Demo

Beibehalten:

- Kundendaten: Name, E-Mail, deutsche Telefonnummer, validierte DE-IBAN,
  `Marge ... %`;
- Personalakte: Name, Personalnummer, E-Mail, deutsche Telefonnummer,
  `Gehalt ... EUR`, `Deckungsbeitrag ... %`;
- Quellcode: strukturelle Codezeile, Provider-Key, abgeschlossenes SQL-Statement
  und explizite Passwortzuweisung.

Nicht als stabile freie Formulierung bewerben:

- beliebig gruppierte internationale IBANs;
- exakte Grenzen jeder internationalen Telefonnummer;
- beliebige englische Bezeichnungen und Einheiten für Geschäftskennzahlen.

Der normale Ark-API-Default lässt DLP-L1 absichtlich nur Credentials und
Secrets erkennen. Die Demo benötigt deshalb ein explizites Demo-Gate-Profil,
das mindestens `dlp_internal_business_metric`, die verwendeten
`dlp_source_code_*`-Regeln sowie `dlp_sql_statement`/
`dlp_sql_multiline_statement` aktiviert. Diese Produktkonfiguration verändert
nicht die Detector-Architektur.

## Reproduktion

```bash
.venv/bin/python scripts/measure_demo_pii_dlp.py \
  --include-blind-goldens \
  --arm all \
  --model-dir /path/to/patronus_ark/assets \
  --output /tmp/demo-pii-dlp.json
```

Der Report enthält Exact- und Overlap-Metriken, per-Klasse-Ergebnisse,
Szenario-/Case-Type-Slices sowie die konkreten Exact-Misses und zusätzlichen
Spans.
