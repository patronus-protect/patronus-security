# Externe PII-Corpora

Dieser Ordner enthält nur Manifest und zwei handgeschriebene Schema-Fixtures,
keine externen Rohdaten. Die Fixtures sind nicht als Benchmark-Ergebnis oder
als Auszug aus AI4Privacy zu interpretieren.

Das Manifest pinnt die tatsächlich geprüften Revisionen und SHA-256-Werte des
OpenPII-Nano-Train-Splits sowie des TAB-Test-Splits. Die Dateien bleiben lokal;
`--verify-source` verweigert eine abweichende Revision:

```bash
cd python
../.venv/bin/python -m patronus_ark.external_pii_eval normalize \
  --corpus ai4privacy-openpii-nano-1k \
  --input /absolute/path/openpii-nano/data/train.jsonl \
  --verify-source \
  --output /private/tmp/openpii.ark.jsonl
# Ark-Result-JSONL enthält pro id evidence_spans wie aus dem Python-Wrapper.
../.venv/bin/python -m patronus_ark.external_pii_eval evaluate \
  --input /private/tmp/openpii.ark.jsonl \
  --predictions /absolute/path/ark-results.jsonl
```

TAB wird ohne Vortransformation aus dem offiziellen Standoff-JSON normalisiert:

```bash
../.venv/bin/python -m patronus_ark.external_pii_eval normalize \
  --corpus tab --input /absolute/path/echr_test.json \
  --verify-source --output /private/tmp/tab-test.ark.jsonl
```

TAB vereinigt identische Entity-Spans aller Annotatoren deterministisch und
nimmt gemäß Manifest nur `DIRECT`/`QUASI`, nicht `NO_MASK`, in das
privacy-orientierte Gold auf. OpenPII ist synthetisch; TAB besteht aus realen,
manuell annotierten englischen ECHR-Fällen.

Gretel wird aus dem `data/`-Ordner des gepinnten Hugging-Face-Snapshots
normalisiert. Der Adapter erwartet alle sechs gepinnten Test-Parquet-Dateien
und prüft jede einzeln. Dafür ist nur für diesen lokalen Ingest `pyarrow`
erforderlich:

```bash
cd python
../.venv/bin/python -m patronus_ark.external_pii_eval normalize \
  --corpus gretel-synthetic-pii-finance \
  --input /absolute/path/gretel-snapshot/data \
  --verify-source --output /private/tmp/gretel.ark.jsonl
../.venv/bin/python -m patronus_ark.external_pii_eval select \
  --corpus gretel-synthetic-pii-finance --input /private/tmp/gretel.ark.jsonl \
  --cap 250 --output /private/tmp/gretel.selection.json
```

Gretel ist Apache-2.0-lizenziert und vollständig synthetisch. Seine
Annotationen wurden automatisiert erzeugt und nur stichprobenartig geprüft;
es ist damit Format-/Boundary-Gold, kein Ersatz für TAB als reales Gold.
`select` schreibt kein Rohtext-Duplikat: das Manifest enthält nur Corpus,
Revision, Seed, Template-/Dokumentgruppe, Dokument-ID und ausgewählte
Offset-Spans. Gretel nutzt `expanded_type` als Templategruppe; andere Adapter
verwenden eine Dokumentgruppe.

Die Prediction-Datei muss jeden Gold-`id` exakt einmal enthalten. Nicht
gemappte Upstream-Labels werden vor dem Vergleich bewusst ausgeschlossen; die
verwendete Label- und Lizenzzuordnung bleibt im Manifest nachvollziehbar.

Vor jedem Ingest müssen Upstream-Revision, Lizenz und Zugang in einem
run-spezifischen Report notiert werden. Nicht lizenzierte oder restriktive
Korpora (z. B. n2c2, BigCode, ältere AI4Privacy-Varianten) werden weder hier
noch in abgeleiteten Fixtures eingecheckt.
