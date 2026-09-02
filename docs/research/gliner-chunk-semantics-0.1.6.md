# GLiNER-Chunk-Semantik: Explorationsbefund 0.1.6

Stand: 2026-08-31. Dieser Befund bewertet ausschließlich eine mögliche
Chunk-Kontextnutzung von GLiNER. Injection und nachgelagerte Enforcement-
Entscheidungen sind nicht Teil dieser Untersuchung.

## Aktueller Vertrag und Grenzen

Dynamic PII übergibt jeden Text chunkweise an `GlinerEngine` als Liste von
Entity-Labels. Die Engine liefert ausschließlich lokalisierte
`(label, start, end, score)`-Kandidaten. Danach korrigiert der Runtime die
Dokumentoffsets und merged überlappende Spans desselben Labels. Es gibt weder
eine Klassifikationsausgabe „dieser Chunk enthält X“ noch einen erhaltenen
Chunk-Score oder eine Chunk-ID im öffentlichen Ergebnis.

`DynamicPiiConfig.execution_gate` und `conditional_labels` können nur
`pipeline -> class_name` auswerten. Sie können einen Job starten/überspringen
oder Labels vereinigen, aber weder Scores verändern noch L1-Entitys,
`l1_anchors`, Value-Spans oder Validatorergebnisse sehen. Ein L1-Ergebnis
liefert dabei nur seine Result-Class, nicht die hierfür nötige typisierte
Evidenz.

Sensitive Document ist ebenfalls keine verlässliche Quelle für die aktuelle
Dynamic-PII-Auflösung: beide sind L3-Jobs. Der Dynamic-PII-Job wird mit den
bereits verfügbaren L1/L2-Result-Classes aufgelöst, bevor das Sensitive-
Document-L3-Ergebnis vorliegt. Ein lokaler Test mit einer Zeugnisnote und
`when: sensitive_document=education` aktivierte deshalb kein Zusatzlabel.
Zusätzlich ist `school` nicht der gegenwärtige Runtime-Classname; das Modell
liefert `education`.

## Academic-grade-Experiment

Lokaler Modellstand: `gliner_small-v2.5-edge`, Revision
`0057606351626290b6b73d82aeb2ee566b69451f`, Asset-Pfad
`~/Library/Caches/patronus_ark`. Inferenz lief mit dem
einzigen Label `academic_grade` und Floor `0.05`.

Das bewusst kleine Explorationsset enthielt acht positive und acht harte
negative DE/EN-Chunks. Positive deckten `Note 1,7`, `Schulnote 2`,
Notendurchschnitt, `grade of A`, `exam score`, GPA und `B+` ab. Negative
enthielten unter anderem eine Meeting-Notiz, Versionsnummer `1.7`,
Schüler-/Kurskontext ohne Note, Lehrerkontext ohne Ergebnis, ein zu
bewertendes Support-Ticket und einen Fußball-Score.

| Fall | Text |
|---|---|
| DE+ | `Im Zeugnis steht für Mathematik die Note 1,7.` |
| DE+ | `Die Klausur wurde mit der Schulnote 2 bewertet.` |
| DE+ | `Ihr Notendurchschnitt beträgt 1,9.` |
| DE+ | `Die Schülerin erhielt die Bewertung sehr gut.` |
| EN+ | `The report card lists a grade of A in mathematics.` |
| EN+ | `His exam score was 87 points.` |
| EN+ | `The student's GPA is 3.8.` |
| EN+ | `She received a B+ for biology.` |
| DE− | `Die Note im Meeting beschreibt die nächsten Schritte.` |
| DE− | `Version 1.7 behebt einen Fehler in Mathematik.` |
| DE− | `Die Schülerin besucht heute den Mathematikkurs.` |
| DE− | `Der Lehrer bewertet die Hausaufgaben morgen.` |
| EN− | `Please grade the support ticket before closing it.` |
| EN− | `Release 1.7 fixes a calculation error.` |
| EN− | `The student attends a biology course.` |
| EN− | `The team scored a goal in the final minute.` |

Bei Threshold `0.30`:

| Auswertung | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| Presence: mindestens ein Label-Span, maximaler Score je Chunk | 8 | 4 | 0 | 0.667 | 1.000 | 0.800 |
| Exact: erwartete Wertspan exakt | 3 | 9 | 5 | 0.250 | 0.375 | 0.300 |

Presence erscheint damit deutlich besser, ist aber kein belastbarer
Semantik-Classifier: Das Modell markierte beispielsweise `Schülerin` oder
`Mathematikkurs` in einem notenlosen Chunk sowie `Der Lehrer` oder
`Hausaufgaben` als `academic_grade`. Auch beim positiven Inhalt schwanken die
Grenzen: statt eines vollständigen Felds entstehen etwa nur `A`, `87 points`,
`GPA` oder die Zahl. Die bereits dokumentierte, größere Education-Sweep misst
für `academic_grade` Exact-F1 `0.286` und führt das Label deshalb als
abgelehnt (`docs/gliner-education-evaluation.md`).

Eine Presence-Aggregation darf diese Boundary-Schwäche daher nicht in ein
Kontextsignal oder eine PII-Behauptung umdeuten. Sie würde insbesondere
school-nahe, aber nicht sensible Chunks als positiv behandeln.

## Reproduktion

Der Lauf verwendet die normale lokale Python-Bindung und nur das vorhandene
Asset; die 8+8 Texte stehen oben. Für eine dauerhafte Produktmessung müssen
sie als versioniertes Golden übernommen und getrennt von den vorhandenen
Exact-Span-Fixtures ausgewertet werden.

```bash
PYTHONPATH=python .venv/bin/python - <<'PY'
from patronus_ark import SecurityGateway

gateway = SecurityGateway(
    categories=["dynamic-pii"], max_level="l3",
    model_dir="~/Library/Caches/patronus_ark",
    download_files=False,
)
gateway.set_dynamic_pii_config({
    "labels": ["academic_grade"], "threshold": 0.05,
    "execution_gate": {"type": "always"}, "conditional_labels": [],
})
gateway.warmup()
print(gateway.scan_category(
    "dynamic-pii", "Im Zeugnis steht für Mathematik die Note 1,7."
)[0]["evidence_spans"])
PY
```

## Entscheidung und möglicher späterer Vertrag

Kein Runtime-Change in 0.1.6. GLiNER bleibt für semantische Entity-Spans;
`academic_grade` ist weder als Entity noch als Chunk-Gate ausreichend
kalibriert.

Falls die Hypothese nach Golden-Evaluation weiterhin relevant ist, wäre die
kleinste passende Erweiterung ein separater informativer Kontextvertrag:

```json
{
  "chunk_context": [{
    "chunk_start_byte": 0,
    "chunk_end_byte": 184,
    "label": "education.grade_context",
    "score": 0.0,
    "evidence_span_ids": ["..."]
  }]
}
```

Er darf keinen lokalisierten PII-Span vortäuschen; er sagt ausschließlich aus,
dass ein Chunk den gemessenen Kontext wahrscheinlich enthält.
Seine Aggregation (z. B. max oder noisy-or) muss pro Kontextlabel kalibriert
werden. Ein L1-Boost setzt außerdem einen expliziten typisierten
Eingabevertrag für Anchors, Value-Spans und Validatorergebnisse voraus; der
heutige Result-Class-Gate-Vertrag reicht nicht. Sensitive Document müsste vor
der Kontextentscheidung sequenziert werden, nicht parallel.

Vor einer Umsetzung nötig sind:

- versionierte DE/EN Chunk-Presence-Goldens mit school-nahen Hard Negatives;
- lange Dokumente mit Chunk-Grenzen und Overlap;
- getrennte Precision-first Thresholds pro Kontextlabel;
- Ablationen GLiNER-only, L1-only, Sensitive-Document-only und kombiniert;
- getrennte Metriken für Context Presence, Exact Entity Span, Overredaction
  und jede spätere Gate-/Boost-Auswirkung.
