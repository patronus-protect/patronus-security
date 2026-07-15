# GLiNER education PII evaluation

Measured on 2026-07-15 with `gliner_small-v2.5`. This is an exploratory,
German-heavy evaluation, not a production benchmark. The fixtures contain five
positive exact-span examples per NER label plus ten shared hard negatives. The
document indicator uses 15 positive and 15 hard-negative German documents.

## Sources

- [TorchSight Beam training data](https://huggingface.co/datasets/torchsight/beam-training-data)
  (Apache-2.0): synthetic student records with student ID, enrollment, major,
  GPA, disciplinary record, financial aid, and academic standing.
- [Cleanlab student grades](https://huggingface.co/datasets/Cleanlab/student-grades)
  (MIT): synthetic student IDs, exam scores, notes, and letter grades.
- [Student Performance](https://huggingface.co/datasets/krishal07/student-performance)
  (CC0-1.0): synthetic school performance, GPA, attendance, demographic, and
  socioeconomic fields.

The checked-in examples are German, structure-preserving synthetic adaptations;
they do not contain real student data.

## Exact-span NER sweep

| Canonical label | Threshold | Precision | Recall | F1 | Decision |
|---|---:|---:|---:|---:|---|
| `parent_or_guardian` | 0.80 | 1.000 | 1.000 | 1.000 | promising |
| `applicant_identifier` | 0.35 | 0.625 | 1.000 | 0.769 | promising, threshold is low |
| `degree_program` | 0.60 | 0.667 | 0.800 | 0.727 | promising |
| `research_participant_identifier` | 0.55 | 0.667 | 0.800 | 0.727 | promising |
| `student_identifier` | 0.65 | 0.750 | 0.600 | 0.667 | acceptable |
| `academic_grade` | 0.60 | 0.500 | 0.200 | 0.286 | reject |
| `exam_result` | 0.80 | 0.000 | 0.000 | 0.000 | reject |
| `financial_aid` | 0.80 | 0.000 | 0.000 | 0.000 | reject as one span |

`financial_aid` frequently found the aid type and amount as separate spans. A
future experiment should test `financial_aid_type` and `financial_aid_amount`
instead of treating the complete phrase as one entity. Grades and exam results
also have unstable boundaries and are better candidates for a document signal
or structured-field detector than exact-span NER.

## Binary document indicator

The document score is the maximum GLiNER span score for one semantic label.
Threshold selection minimizes false negatives while enforcing a maximum false
positive rate of 10%.

The best single label was `personenbezogene_bildungsakte` at threshold 0.50:

- precision: 0.875
- recall: 0.467
- false-positive rate: 0.067
- false-negative rate: 0.533
- F1: 0.609

English and German prompt-label ensembles, concrete education-entity ensembles,
and conjunction with a separate identity signal did not improve recall under
the 10% false-positive constraint.

If the false-positive limit is relaxed, `individual_student_record` reaches:

| Threshold | Precision | Recall | FPR | FNR | F1 |
|---:|---:|---:|---:|---:|---:|
| 0.50 | 0.733 | 0.733 | 0.267 | 0.267 | 0.733 |
| 0.40 | 0.722 | 0.867 | 0.333 | 0.133 | 0.788 |

Conclusion: GLiNER contains a useful education-record signal, but it is not a
safe standalone blocker. At a high-recall operating point it could route roughly
one third of hard-negative documents into a more precise classifier. A dedicated
document classifier or the semantic-indicator experiment described in
`OPEN_TODO.md` remains the better production path.

## Reproduction

```bash
.venv/bin/python scripts/sweep_gliner_pii.py \
  --model-dir /path/to/models \
  --fixture python/patronus_security/benchmark_data/education_pii_threshold_sweep.jsonl \
  --output /tmp/gliner_education_ner_sweep.json

.venv/bin/python scripts/sweep_gliner_document_indicator.py \
  --model-dir /path/to/models \
  --output /tmp/gliner_education_document_indicator.json
```
