# GLiNER education PII evaluation

Measured on 2026-07-15 with `gliner_small-v2.5`. This is an exploratory,
German-heavy evaluation, not a production benchmark. The fixtures contain five
positive exact-span examples per NER label plus ten shared hard negatives.

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
| `exam_result` | 0.20 | 0.143 | 0.200 | 0.167 | reject |
| `financial_aid` | — | 0.000 | 0.000 | 0.000 | reject as one span |

## Runtime mapping

The five accepted labels are enabled for `sensitive_documents: school` with
their isolated-sweep thresholds:

| Canonical label | Runtime threshold |
|---|---:|
| `student_identifier` | 0.65 |
| `applicant_identifier` | 0.35 |
| `research_participant_identifier` | 0.55 |
| `parent_or_guardian` | 0.80 |
| `degree_program` | 0.60 |

Canonical API labels retain underscores. The runtime presents them to GLiNER
with spaces and restores the canonical label on output. The thresholds are the
measured isolated optima; combined-label benchmark results should be tracked
separately if the school bundle changes.

`financial_aid` frequently found the aid type and amount as separate spans. A
future experiment should test `financial_aid_type` and `financial_aid_amount`
instead of treating the complete phrase as one entity. Grades and exam results
also have unstable boundaries and are better candidates for a structured-field
detector than exact-span NER.

## Reproduction

```bash
.venv/bin/python scripts/sweep_gliner_pii.py \
  --model-dir /path/to/models \
  --fixture python/patronus_security/benchmark_data/education_pii_threshold_sweep.jsonl \
  --output /tmp/gliner_education_ner_sweep.json
```
