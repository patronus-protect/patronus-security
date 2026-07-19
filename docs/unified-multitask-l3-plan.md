# Unified Multi-Task L3 Integration Plan

## Implementierungsstand

Der Library-Umbau ist umgesetzt:

- `L3Strategy::{Dedicated, Multi}` ist global im Rust- und Python-Gateway
  konfigurierbar; Default bleibt `dedicated`.
- Die sieben kanonischen Classifier-Pipelines sind `injection`,
  `sensitive_document`, `tool_class`, `tool_action`, `tool_tags`, `routing`
  und `threat`.
- Multi-Warmup lädt ausschließlich das revisionsgepinnte Unified-L3-Bundle;
  Dedicated-Warmup lädt die pipeline-spezifischen L3-Bundles.
- Der L3-Worker coalesced Promotes atomar pro Request, hält
  `Running`/`Completed`/`Failed`, cached alle Head-Outputs und führt nur die
  abonnierten Heads als logische Pipeline-Ergebnisse zurück.
- Das Result-Schema enthält `label_scores`, einschließlich unabhängiger
  Sigmoid-Scores für `tool_tags`.
- GLiNER bleibt ein eigener Worker-Runtime-Weg und wartet weiterhin auf
  logische Pipeline-Ergebnisse, nicht auf eine sichtbare Unified-Pipeline.
- Der konkrete INT8/UINT4-Graph wurde mit der im Projekt gebundenen
  Rust-ORT-Version auf CPU geladen und mit allen sieben Heads ausgeführt.

Noch offene Release-Gates sind keine weiteren Architekturänderungen:

- die noch zu liefernden L1-Heuristiken und sieben finalen L2-Exports;
- die bestehende per-Pipeline-Qualitätsevaluation der quantisierten Variante;
- Smoke-Tests der tatsächlich freigegebenen Accelerator Execution Provider.

## Ziel

Die Security-Lib soll fuer die sieben klassifizierenden Security-Pipelines zwei
alternative L3-Strategien unterstuetzen:

- `dedicated`: Jede Pipeline verwendet ihr eigenes L3-Modell.
- `multi`: Alle sieben Pipelines verwenden die Heads eines gemeinsamen
  Unified-Multi-Task-L3-Modells.

L1 und L2 bleiben pipeline-spezifisch. Insbesondere bleiben die sieben
eigenstaendigen L2-Modelle, deren Ausfuehrung, Predictions und
Promotion-Entscheidungen unveraendert.

Im Multi-Modus startet der erste L2-Promote einer Request sofort den gemeinsamen
L3-Run. Weitere Promotes derselben Request duerfen keine weiteren physischen
Unified-Inferenzen erzeugen. Sie werden entweder an den laufenden Run angehaengt
oder nach dessen Abschluss aus dem bereits vorliegenden Multi-Head-Ergebnis
bedient.

GLiNER bleibt ein separates L3-Modell mit unveraendertem fachlichem Verhalten.

## Modell und Heads

Unified-Modell:

- Repository:
  `patronus-studio/lion-warden-ai-security-classifier`
- Gepinnte Revision:
  `9bcc55dcf955cda68c171524cd242ada9f5547d4`
- ONNX-Artefakt:
  `onnx/int8_int4_embeddings/model.onnx`
- Modellgroesse: 96.190.356 Bytes
- Trainingslaenge: 256 Tokens
- ONNX IR: 8
- ONNX Opset: 21
- Microsoft-Domain-Opset: 1
- Quantisierung:
  - INT8 fuer die quantisierten MatMuls
  - UINT4 fuer die Embeddings
  - `com.microsoft::GatherBlockQuantized` fuer den Embedding-Lookup

Erforderliche Repository-Dateien fuer den Multi-L3-Runtime-Weg:

- `onnx/int8_int4_embeddings/model.onnx`
- `onnx/quantization_manifest.json`
- `config.json`
- `tokenizer.json`
- `tokenizer_config.json`

Der ONNX-Graph ist self-contained und besitzt keine externen Initializer-Dateien.

Graph-Inputs:

| Name | Typ | Shape |
|---|---|---|
| `input_ids` | INT64 | `[batch, sequence]` |
| `attention_mask` | INT64 | `[batch, sequence]` |

Graph-Outputs:

| Head | Tensor | Typ | Shape |
|---|---|---|---|
| `injection` | `injection_logits` | FLOAT | `[batch, 1]` |
| `sensitive_document` | `sensitive_logits` | FLOAT | `[batch, 7]` |
| `tool_class` | `tool_class_logits` | FLOAT | `[batch, 14]` |
| `tool_action` | `tool_action_logits` | FLOAT | `[batch, 6]` |
| `tool_tags` | `tool_tags_logits` | FLOAT | `[batch, 3]` |
| `routing` | `routing_logits` | FLOAT | `[batch, 5]` |
| `threat` | `threat_logits` | FLOAT | `[batch, 7]` |

Der Graph wurde mit ONNX Runtime 1.27.0 auf dem CPU Execution Provider
erfolgreich geladen und mit einem `[1, 256]`-Input ausgefuehrt. Alle sieben
Outputs hatten die erwartete Shape und endliche `float32`-Werte. Fuer die von
der Rust-Bindung verwendete ORT-Version und jeden freigegebenen Execution
Provider bleibt ein eigener Runtime-Smoke-Test erforderlich.

Das vorhandene `metrics/quantization_metrics.json` enthaelt noch keine
Qualitaetsauswertung, weil der Quantisierungslauf mit `--skip-eval` ausgefuehrt
wurde. Vor der Freigabe wird deshalb die bestehende per-Pipeline-Evaluation
einmal explizit mit dieser INT8/UINT4-Variante ausgefuehrt. Das ist ein
Modell-Release-Gate, kein Umbau der Benchmark-Architektur.

Heads:

| Pipeline | Head | Typ |
|---|---|---|
| `injection` | `injection` | Binary |
| `sensitive_document` | `sensitive_document` | Softmax, 7 Klassen |
| `tool_class` | `tool_class` | Softmax, 14 Klassen |
| `tool_action` | `tool_action` | Softmax, 6 Klassen |
| `tool_tags` | `tool_tags` | Multi-Label BCE, 3 Tags |
| `routing` | `routing` | Softmax, 5 Klassen |
| `threat` | `threat` | Softmax, 7 Klassen |

Zusaetzliche, nicht im Unified-Modell enthaltene Pipelines:

- `pii`
- `dlp`
- `dynamic_pii` mit GLiNER als Modellprovider

## Grundentscheidungen

- Pipeline und physisches L3-Modell werden voneinander getrennt.
- Die L3-Strategie betrifft ausschliesslich L3.
- L1 bleibt pipeline-spezifisch.
- L2 bleibt pipeline-spezifisch.
- Jede Pipeline besitzt weiterhin ein eigenes L2-Modell und eine eigene
  Promotion-Entscheidung.
- Es gibt keinen Barrier und kein Warten auf alle L1-/L2-Ergebnisse.
- Der erste Promote startet L3 sofort.
- Spaetere Promotes derselben Request verwenden denselben Unified-Run.
- Nicht promotete Heads erzeugen keine sichtbaren L3-Pipeline-Resultate.
- Das Unified-Modell darf intern trotzdem alle Head-Outputs berechnen und
  zwischenspeichern.
- GLiNER bleibt physisch und fachlich separat.
- Im Dedicated-Modus bleibt die heutige Ausfuehrungssemantik mit einzelnen
  L3-Modellen bestehen.
- Im Multi-Modus werden keine dedizierten L3-Modelle geladen oder ausgefuehrt.

## Nicht-Ziele

- Kein Umbau des NTDB-L2-Executors.
- Keine Aenderung der L2-Promotion-Thresholds oder Operating Points.
- Keine stage-driven Ausfuehrung von L1, L2 und L3.
- Kein gemeinsames L2-Modell fuer die sieben Pipelines.
- Keine Aenderung der fachlichen GLiNER-Gates.
- Keine neue Telemetriearchitektur.
- Keine neuen Scheduling-Prioritaeten pro Unified-Head.
- Nicht promotete Heads werden nicht opportunistisch als L3-Resultate
  veroeffentlicht.

## Pipeline-Migration

Die neue Pipeline-Taxonomie ist unabhaengig von der gewaehlten L3-Strategie.

Zu migrieren beziehungsweise zu entfernen:

- `user_intent` wird durch `routing` und `threat` ersetzt.
- `tool_classifier` als gemeinsame Produktpipeline wird durch `tool_class`,
  `tool_action` und `tool_tags` ersetzt.
- Die alten Tool-Unterbereiche `prompt`, `execution` und `description` werden
  nicht als neue Pipeline-Namen weitergefuehrt.
- Das alte kombinierte Tool-Klassenschema wird nicht als kanonisches
  Ergebnisschema weitergefuehrt.
- `sensitive_documents` wird auf den kanonischen Pipeline-/Head-Namen
  `sensitive_document` migriert.

Alte native Scanner koennen als interne L1-Detektoren der passenden neuen
Pipeline erhalten bleiben. Sie sollen nicht allein wegen historischer
Datei- oder Typnamen als eigene oeffentliche Pipelines bestehen bleiben.

## Globale L3-Konfiguration

### Multi-Strategie

```yaml
l3:
  strategy: multi

  multi:
    model: patronus-studio/lion-warden-ai-security-classifier
    revision: 9bcc55dcf955cda68c171524cd242ada9f5547d4
    onnx_path: onnx/int8_int4_embeddings/model.onnx
    bindings:
      injection: injection
      sensitive_document: sensitive_document
      tool_class: tool_class
      tool_action: tool_action
      tool_tags: tool_tags
      routing: routing
      threat: threat
```

Im Multi-Modus:

- wird genau ein Unified-Classifier-Runtime registriert;
- werden die dedizierten L3-Classifier nicht geladen;
- bleibt GLiNER als eigener Runtime registriert;
- routet jede Pipeline ihren Promote auf den konfigurierten Unified-Head.

### Dedicated-Strategie

```yaml
l3:
  strategy: dedicated

  dedicated:
    injection:
      model: <injection-l3-model>
      revision: <pinned-revision>
    sensitive_document:
      model: <sensitive-document-l3-model>
      revision: <pinned-revision>
    tool_class:
      model: <tool-class-l3-model>
      revision: <pinned-revision>
    tool_action:
      model: <tool-action-l3-model>
      revision: <pinned-revision>
    tool_tags:
      model: <tool-tags-l3-model>
      revision: <pinned-revision>
    routing:
      model: <routing-l3-model>
      revision: <pinned-revision>
    threat:
      model: <threat-l3-model>
      revision: <pinned-revision>
```

Im Dedicated-Modus:

- verwendet jede Pipeline wieder ihr eigenes L3-Modell;
- erzeugt jeder Promote wie bisher einen eigenen physischen L3-Job;
- bleibt der bestehende pipeline-/modellbezogene Cache-Weg erhalten;
- bleibt das bestehende Scheduling der einzelnen Modelle aktiv.

Die Konfiguration muss beim Warmup validieren, dass jede aktivierte
klassifizierende Pipeline genau eine passende L3-Bindung besitzt.

## Aktueller L3-Vertrag

Der aktuelle Worker modelliert einen Promote als vollstaendigen physischen
L3-Job:

```text
L2 result with l3_pending
  -> L3JobSpec
       category
       model
       text
       one fallback
  -> queue
  -> one model inference
  -> one SecurityScanResult
```

Diese 1:1-Kopplung bleibt fuer `dedicated` gueltig, ist fuer `multi` aber nicht
ausreichend.

## Neuer logischer Promote-Vertrag

L2 soll weiterhin dieselbe Promotion-Entscheidung treffen. An der Grenze zum
Worker wird ein Promote jedoch als logisches Abonnement beschrieben:

```rust
struct L3Promotion {
    promotion_id: u64,
    request_id: RequestId,
    pipeline: PipelineId,
    head: HeadId,
    text: String,
    fallback: SecurityScanResult,
    execution: ScanExecution,
    candidate_spans: Vec<ByteSpan>,
}
```

Der Worker entscheidet anhand der konfigurierten Strategie:

```text
dedicated
  -> aus L3Promotion einen eigenen L3JobSpec erzeugen

multi
  -> Promotion an request-lokalen Unified-Run uebergeben
```

Die L2-Seite muss weder auf andere Pipelines warten noch deren
Promotion-Entscheidungen kennen.

## Multi-Strategie: Request-lokale State Machine

Der Worker benoetigt pro Unified-Run einen atomar verwalteten Zustand:

```rust
enum UnifiedRunState {
    Running {
        subscribers: HashMap<HeadId, Vec<PromotionContext>>,
    },
    Completed {
        outputs: UnifiedModelOutput,
        metadata: L3ExecutionMetadata,
    },
    Failed {
        failure: L3ExecutionFailure,
    },
}
```

`UnifiedModelOutput` enthaelt die Outputs aller sieben Heads.

### Promote trifft auf keinen Run

```text
1. Running-State atomar eintragen.
2. Promotion als ersten Subscriber registrieren.
3. Genau einen physischen Unified-L3-Job queuen.
4. Inferenz sofort starten, sobald der Scheduler den Job auswaehlt.
```

### Promote trifft auf einen laufenden Run

```text
1. Promotion als Subscriber des passenden Heads registrieren.
2. Pending-State der logischen Pipeline erhalten.
3. Keinen weiteren physischen Job queuen.
4. Nach Abschluss den passenden Head-Output zurueckfuehren.
```

### Promote trifft auf einen abgeschlossenen Run

```text
1. Passenden Head aus UnifiedModelOutput lesen.
2. Head-Output mit dem L2-Fallback der Promotion kombinieren.
3. Pipeline-L3-Resultat unmittelbar veroeffentlichen.
4. Keine weitere Inferenz ausfuehren.
```

### Promote trifft auf einen fehlgeschlagenen Run

```text
1. Gespeicherten Fehler beziehungsweise Timeout wiederverwenden.
2. Den individuellen L2-Fallback degradieren.
3. Keine zweite Unified-Inferenz fuer dieselbe Request starten.
```

## Run-Key und Lebensdauer

Ein Unified-Run muss mindestens ueber folgende Werte identifiziert werden:

```text
request_id
model identity and revision
input identity
execution backend/profile
```

`request_id` allein darf nur verwendet werden, wenn der Request-Vertrag
garantiert, dass eine Request genau einen identischen Eingabetext besitzt.

Der `Running`, `Completed` oder `Failed` State muss bis zum terminalen Ende der
Request erhalten bleiben. Dadurch kann auch ein spaeter L2-Promote kein zweites
Unified-Model-Inference ausloesen.

Das Erzeugen des ersten Runs und das Registrieren weiterer Subscriber muss
unter demselben Lock beziehungsweise ueber eine atomare Entry-Operation
erfolgen. Zwei gleichzeitig eintreffende erste Promotes duerfen nicht zwei
physische Jobs erzeugen.

## Physische und logische Completion

Im Multi-Modus gibt es zwei getrennte Einheiten:

- einen physischen Unified-L3-Run;
- null bis sieben logische L3-Promotions.

Der physische Job ist nur einmal pending. Fuer Request-Completion und GLiNER
muessen aber weiterhin die logischen Pipeline-Promotions sichtbar bleiben.

Beispiel:

```text
physical run:
  unified-model/request-42

logical promotions:
  injection/promotion-1
  threat/promotion-2
  tool_action/promotion-3
```

Wenn der Run abgeschlossen ist, werden alle bis dahin registrierten
Subscriber einzeln abgeschlossen. Spaeter eintreffende Promotes werden aus
dem Completed-State sofort abgeschlossen.

Die Request darf erst terminal werden, wenn alle zu ihr gehoerenden
L1-/L2-Arbeiten und logischen L3-Promotions abgeschlossen sind. Der physische
Unified-Job darf nicht als Ersatz fuer die logischen Pending-States verwendet
werden.

## Chunking und Candidate Spans

Im Dedicated-Modus bleibt die bestehende pipeline-spezifische Chunk- und
Candidate-Span-Logik erhalten.

Im Multi-Modus muss ein abgeschlossener Unified-Run auch spaetere Promotes
anderer Heads bedienen koennen. Deshalb darf der erste Promote den Run nicht
auf ausschliesslich head-spezifische Candidate Spans begrenzen.

Multi-Strategie:

- tokenisiert den Request-Text einmal;
- erzeugt die fuer das Unified-Modell erforderlichen 256-Token-Chunks;
- fuehrt diese Chunks als gemeinsamen Batch beziehungsweise gemeinsamen Run
  aus;
- speichert die Head-Outputs fuer alle Chunks;
- aggregiert sie head-spezifisch gemaess dem Runtime-Vertrag.

Damit kann ein spaeter Promote jeden Head aus demselben Run bedienen.

Diese Anpassung liegt ausschliesslich im L3-Worker beziehungsweise im
Unified-Runtime-Weg. Die L2-Modelle und deren Candidate-Span-Ausgabe bleiben
unveraendert.

## Unified ONNX Runtime-Vertrag

Das konkrete Unified-ONNX-Artefakt besitzt bereits stabile benannte Inputs und
Outputs. Die Security-Lib implementiert dafuer einen eigenen
`UnifiedOnnxClassifier`; der vorhandene `OnnxTextClassifier` bleibt fuer
dedizierte Single-Output-Modelle bestehen.

Der neue Runtime-Typ liest Outputs strikt nach Tensorname. Er darf nicht wie
der bestehende Single-Output-Weg den ersten Tensor mit einer passenden Groesse
auswaehlen.

Der minimale Head-Vertrag kann zunaechst als gepinnter Rust-Spec zusammen mit
dem Asset-Spec implementiert werden. Beim Laden wird er gegen `config.json`,
`onnx/quantization_manifest.json` und die tatsaechlichen Session-I/Os
validiert. Ein weiteres generisches Modellformat ist fuer diesen Schnitt nicht
notwendig.

Erforderliche globale Angaben:

- Modell-ID
- gepinnte Revision
- ONNX-Datei
- Tokenizer-Dateien
- maximale Sequenzlaenge
- Input-Tensornamen
- Output-Tensornamen
- unterstuetzte Execution Provider
- Precision beziehungsweise Quantisierung
- erwartete ONNX-/Microsoft-Opsets

Erforderliche Angaben pro Head:

- Pipeline-ID
- Head-ID
- Output-Tensorname
- Head-Typ
- Aktivierung
- Labels in stabiler Reihenfolge
- Thresholds
- Safe-/Fallback-Klasse, sofern relevant
- Chunk-Aggregationsstrategie

Beispiel:

```yaml
heads:
  injection:
    pipeline: injection
    output: injection_logits
    type: binary
    activation: sigmoid
    labels: [benign, injection]

  sensitive_document:
    pipeline: sensitive_document
    output: sensitive_logits
    type: softmax
    labels:
      - legal
      - hr
      - finance
      - internal_and_tech
      - source_code
      - marketing
      - other

  tool_tags:
    pipeline: tool_tags
    output: tool_tags_logits
    type: multilabel
    activation: sigmoid
    labels:
      - source:sensitive
      - source:untrusted
      - sink:external
```

Der Rust-Runtime-Code darf die Head-Typen, Labels und Tensor-Mappings nicht
implizit aus historischen Pipeline-Namen ableiten.

Der vorhandene `onnx/quantization_manifest.json` liefert Modelltyp,
Variantenpfad und Head-zu-Output-Mapping. `config.json` liefert die
Label-Reihenfolge. Aktivierung, Thresholds und Chunk-Aggregation werden durch
den gepinnten Security-Lib-Head-Spec vervollstaendigt, solange diese Angaben
nicht selbst Bestandteil des Modellmanifests sind.

## ONNX-Runtime-Kompatibilitaet

Das ausgewaehlte Modell benoetigt wegen der UINT4-Embeddings den Microsoft-Op
`GatherBlockQuantized`. Die Modellintegration beginnt deshalb mit einem
Rust-Smoke-Test ueber exakt den Runtime-Weg, den spaeter auch der Worker nutzt.

Pflichtpruefungen:

- Session mit `ort` 2.0.0-rc.12 aus dem Projekt laden.
- `[1, 256]` auf CPU ausfuehren.
- alle sieben Outputs namentlich und mit exakter Shape validieren.
- Tokenizer-Input mit `input_ids` und `attention_mask` ausfuehren.
- Verhalten der konfigurierten Accelerator-Provider pruefen.
- CPU-Fallback fuer nicht unterstuetzte UINT4-Ops explizit verifizieren oder
  den betroffenen Provider fuer dieses Modell ablehnen.

Wenn die gebundelte ORT-Version `GatherBlockQuantized` nicht unterstuetzt, ist
ein ORT-Upgrade der erste notwendige Implementierungsschritt. Ein stiller
Fallback auf die groessere INT8-Variante ist nicht Teil der gewaehlten
Multi-Strategie.

## Result-Schema

Das aktuelle einzelne `class_name`-/`confidence`-Schema reicht fuer
`tool_tags` nicht aus.

Zieltyp:

```rust
enum HeadOutput {
    SingleLabel {
        label: String,
        confidence: f64,
        scores: Vec<LabelScore>,
    },
    MultiLabel {
        labels: Vec<LabelScore>,
    },
}

struct LabelScore {
    label: String,
    confidence: f64,
    matched: bool,
}
```

Ein physisches Unified-Ergebnis:

```rust
struct UnifiedModelOutput {
    heads: HashMap<HeadId, HeadOutput>,
}
```

Ein logisches Pipeline-Result wird nur fuer einen tatsaechlich erfolgten
Promote erzeugt:

```text
UnifiedModelOutput[subscriber.head]
  + subscriber.fallback
  -> SecurityScanResult for subscriber.pipeline
```

Nicht promotete Head-Outputs bleiben intern und werden nicht als
Pipeline-Result veroeffentlicht.

## Strategieabhaengiger Cache

### Dedicated

Der bestehende Cache-Weg bleibt grundsaetzlich erhalten:

```text
dedicated model + input/chunk + execution profile
  -> one classifier result
```

### Multi

Der Multi-Cache speichert alle Head-Outputs:

```text
unified model revision + input/chunk + execution profile
  -> UnifiedModelOutput
```

Zusaetzlich existiert der request-lokale Run-State:

- `Running` coalesced parallele Promotes.
- `Completed` bedient spaetere Promotes.
- `Failed` verhindert unkontrollierte Wiederholungen innerhalb derselben
  Request.

Der bestehende globale Decision Cache und der request-lokale Run-State haben
unterschiedliche Aufgaben:

- Decision Cache: Wiederverwendung fertiger Modellentscheidungen.
- Run-State: Synchronisation und Deduplication einer aktiven Request.

## Scheduling

### Multi

Der Scheduler kennt im Multi-Modus nur die physischen L3-Workloads:

- Unified Classifier
- GLiNER

Die sieben Heads sind keine separaten Scheduler-Workloads.

- Der erste Promote queued den Unified-Job.
- Weitere Promotes erzeugen keine Scheduler-Eintraege.
- Die Laufzeitkosten werden dem Unified-Modell zugerechnet.
- Ein Fehler oder Timeout des Runs wird auf die Subscriber-Fallbacks
  zurueckgefuehrt.

### Dedicated

Im Dedicated-Modus bleibt das bestehende Scheduling der einzelnen L3-Modelle
aktiv.

## GLiNER-Verhalten

Das fachliche GLiNER-Verhalten bleibt unveraendert.

GLiNER verwendet fuer seine Gates:

- das L2-Resultat einer Pipeline, wenn diese nicht promotet;
- das finale L3-Head-Resultat einer Pipeline, wenn diese promotet;
- die finalen L2-/L3-Resultate der anderen referenzierten Pipelines.

Beispiel:

```text
injection: L3 pending
threat: L2 benign
routing: L2 tool_operation_request
```

GLiNER wartet nur auf das finale logische `injection`-Resultat. Dass dieses aus
einem Unified-Run stammt, ist fuer die Gate-Entscheidung nicht sichtbar.

Implementierungsanforderung:

- Pending- und Gate-State bleiben pipeline-/head-bezogen.
- Der physische Unified-Job darf nicht als fachliche Pipeline `unified`
  erscheinen.
- Nicht promotete Unified-Head-Outputs duerfen die L2-Ergebnisse nicht
  ueberschreiben.

## Assets und Warmup

Asset-Auswahl und Runtime-Registrierung werden strategieabhaengig.

### Multi

Zu laden:

- `onnx/int8_int4_embeddings/model.onnx`
- `onnx/quantization_manifest.json`
- `config.json`
- `tokenizer.json`
- `tokenizer_config.json`
- GLiNER, wenn `dynamic_pii` aktiviert ist
- die aktivierten L2-Packages wie bisher

Nicht zu laden:

- dedizierte L3-Classifier

### Dedicated

Zu laden:

- konfigurierte dedizierte L3-Modelle pro aktiver Pipeline
- GLiNER, wenn `dynamic_pii` aktiviert ist
- die aktivierten L2-Packages wie bisher

Nicht zu laden:

- Unified-L3-Modell

Readiness muss nur die Assets und Runtimes der aktiven Strategie pruefen.

## Telemetrie und Benchmarks

Die bestehende Telemetrie bleibt konzeptionell erhalten:

- L2-Latenz pro Pipeline
- L3-Queue-Wait
- L3-Inferenzdauer
- GLiNER-Latenz
- Peak RSS
- finale Pipeline-Resultate

Erforderliche Anpassungen:

- Modellnamen und Asset-Erwartungen aktualisieren.
- Multi-Tests duerfen fuer mehrere Promotes derselben Request nur eine
  physische Unified-Inferenz erwarten.
- Dedicated-Tests erwarten weiterhin einzelne L3-Inferenzen.
- Bestehende Pipeline-Qualitaetsmetriken auf die neuen sieben Pipelines und
  Klassen umstellen.

Es werden fuer diesen Umbau keine neuen Produktmetriken oder
Coalescing-Metriken eingefuehrt.

## Implementierungsschritte

### Phase 0: Runtime-Gate fuer das konkrete Modell

- Revision `9bcc55dcf955cda68c171524cd242ada9f5547d4` pinnen.
- INT8/UINT4-Graph ueber die Rust-ORT-Bindung laden.
- `[1, 256]` auf CPU ausfuehren.
- sieben benannte Outputs und Shapes validieren.
- CPU-Fallback beziehungsweise Ablehnung pro Accelerator-Provider festlegen.

Verifikation:

- Der spaetere Worker-Runtime-Weg kann das konkrete Modell ohne Python laden
  und ausfuehren.
- Ein nicht unterstuetzter `GatherBlockQuantized`-Pfad scheitert bereits beim
  Warmup mit einer klaren Readiness-Fehlermeldung.

### Phase 1: Pipeline- und Konfigurationsvertrag

- Neue sieben Pipeline-IDs einfuehren.
- Alte Pipeline-Taxonomie migrieren beziehungsweise entfernen.
- `L3Strategy` mit `Dedicated` und `Multi` einfuehren.
- YAML-/Python-/Rust-Konfiguration abbilden.
- Pipeline-zu-Head-Bindings validieren.
- Request-spezifische Level- und Model-Gates mit der globalen Strategie
  kombinieren.

Verifikation:

- Dieselben Pipelines lassen sich mit beiden Strategien konfigurieren.
- Ungueltige oder fehlende Bindings schlagen beim Konfigurationsaufbau fehl.

### Phase 2: Unified ONNX Runtime

- Gepinnten `UnifiedModelSpec` und die sieben `HeadSpec`s definieren.
- `UnifiedOnnxClassifier` fuer die konkreten benannten Inputs und Outputs
  implementieren.
- Specs gegen `config.json`, `onnx/quantization_manifest.json` und die
  Session-I/Os validieren.
- Binary-, Softmax- und Multi-Label-Heads unterstuetzen.
- Alle Head-Outputs in einem `UnifiedModelOutput` zurueckgeben.
- Head-spezifische Chunk-Aggregation implementieren.

Verifikation:

- Ein ONNX-Run liefert alle sieben erwarteten Outputs.
- Labels und Tensor-Dimensionen werden gegen das Manifest validiert.
- `tool_tags` liefert unabhaengige Label-Scores.

### Phase 3: Logische L3-Promotions

- `L3Promotion` als logische Worker-Eingabe einfuehren.
- Dedicated Adapter auf den bestehenden `L3JobSpec` abbilden.
- Request-Registry um logische Pending-Promotions erweitern.
- Physische Jobs und logische Promotions klar trennen.

Verifikation:

- Dedicated verhaelt sich wie vor dem Umbau.
- Ein Promote kann weiterhin sofort nach seinem L2-Ergebnis starten.

### Phase 4: Unified Run Orchestration

- Request-lokalen `UnifiedRunState` implementieren.
- Erste Promotion startet genau einen Job.
- Parallele Promotions registrieren Subscriber.
- Completed Run bedient spaetere Promotions.
- Failed Run degradiert alle Subscriber ohne zweite Inferenz.
- Run-State bis zum Request-Terminalzustand erhalten.

Verifikation:

- Zwei zeitgleiche erste Promotes erzeugen genau eine Inferenz.
- Ein Promote waehrend der Inferenz erzeugt keine zweite Inferenz.
- Ein Promote nach der Inferenz verwendet den gespeicherten Head-Output.
- Nicht promotete Heads erzeugen kein Resultat.

### Phase 5: Strategieabhaengiger Cache

- Dedicated Cache unveraendert weiterverwenden.
- Unified Cache auf `UnifiedModelOutput` umstellen.
- In-flight Deduplication ueber `UnifiedRunState` sicherstellen.
- Cache-Keys um Strategie, Modellrevision und Execution Profile ergaenzen.

Verifikation:

- Cache-Eintraege der beiden Strategien kollidieren nicht.
- Spaete Promotions einer Request treffen den Completed-State.
- Eine fehlgeschlagene Request startet nicht pro Head erneut.

### Phase 6: GLiNER-Integration

- Pending-State weiterhin pro logischer Pipeline fuehren.
- GLiNER-Gates mit L2- oder finalem L3-Head-Resultat versorgen.
- Sicherstellen, dass der physische Unified-Job nicht als Gate-Pipeline
  erscheint.

Verifikation:

- L2 ohne Promote kann GLiNER wie bisher triggern.
- Ein promoted Head haelt nur seine eigene finale Gate-Entscheidung offen.
- Andere L2-Ergebnisse bleiben sofort fuer GLiNER verfuegbar.

### Phase 7: Assets und Warmup

- Unified Asset Spec und Revision-Pinning einfuehren.
- Dedicated Asset Specs auf die neue Pipeline-Taxonomie abbilden.
- Nur die aktive L3-Strategie herunterladen und registrieren.
- Readiness strategieabhaengig berechnen.
- Obsolete Asset-Pfade und Modellbindungen entfernen.

Verifikation:

- Multi-Warmup benoetigt keine dedizierten L3-Assets.
- Dedicated-Warmup benoetigt kein Unified-Modell.
- GLiNER kann in beiden Strategien parallel registriert werden.

### Phase 8: API, Tests und Dokumentation

- Result-Schema um Multi-Label-Ausgaben erweitern.
- Python-Bindings aktualisieren.
- README, Usage, Rust- und Python-API-Dokumentation aktualisieren.
- Benchmarks auf neue Pipeline-Namen und Modelltopologien umstellen.
- Alte Pipeline- und Gate-Aliase entfernen oder klar befristet deprecaten.

Verifikation:

- Alle neuen Pipeline-Resultate sind stabil serialisierbar.
- Multi und Dedicated besitzen getrennte Integrationstests.
- Bestehende L1-/L2-Tests bleiben unveraendert beziehungsweise werden nur auf
  neue Pipeline-Namen angepasst.

## Erforderliche Worker-Tests

### Multi-Run startet sofort

```text
injection L2 promotes
other L2 models are still running
expected:
  unified inference is queued immediately
```

### Parallele Promotes

```text
injection promotes
threat promotes concurrently
expected:
  one physical unified inference
  one injection L3 result
  one threat L3 result
```

### Promote waehrend aktiver Inferenz

```text
injection starts unified inference
tool_action promotes before inference completes
expected:
  tool_action subscribes
  no second inference
  both results are published after completion
```

### Promote nach abgeschlossener Inferenz

```text
injection starts and completes unified inference
routing promotes later
expected:
  routing reads completed routing head
  no second inference
```

### Nicht promoteter Head

```text
injection promotes
threat returns final L2 result without promote
expected:
  unified model computes threat internally
  public threat result remains L2
  no threat L3 result is published
```

### Unified Timeout

```text
injection and threat subscribe
unified run times out
expected:
  both receive their own degraded L2 fallback
  later tool_action promote receives the same run failure
  no retry inference for the request
```

### Dedicated Regression

```text
strategy = dedicated
injection and threat promote
expected:
  two physical L3 jobs
  existing dedicated cache and scheduling behavior
```

### GLiNER Gate

```text
injection promotes
routing returns final L2 result
dynamic_pii references both
expected:
  routing is immediately available
  dynamic_pii waits only for final injection head
  physical unified job is never exposed as a pipeline result
```

## Akzeptanzkriterien

- Die sieben neuen klassifizierenden Pipelines besitzen jeweils eigene
  L1-/L2-Ausfuehrung und eigene L2-Promotion.
- `dedicated` verwendet pro promoted Pipeline ein einzelnes L3-Modell.
- `multi` verwendet fuer beliebig viele Promotes derselben Request genau einen
  physischen Unified-L3-Run.
- Der erste Promote startet den Unified-Run ohne Barrier.
- Parallele und spaetere Promotes werden auf den laufenden beziehungsweise
  abgeschlossenen Run gemappt.
- Nur tatsaechlich promotete Heads erzeugen sichtbare L3-Pipeline-Resultate.
- L3-Fehler und Timeouts fallen pro Subscriber auf dessen L2-Resultat zurueck.
- `tool_tags` kann als Multi-Label-Resultat dargestellt werden.
- GLiNER behaelt sein bestehendes Gate-Verhalten.
- L2-Ausfuehrung und L2-Modellstruktur bleiben unveraendert.
- Asset-Download, Warmup, Readiness und Cache folgen der gewaehlten
  L3-Strategie.
- Der gepinnte INT8/UINT4-Graph laeuft ueber die Rust-ORT-Bindung auf CPU und
  besitzt ein definiertes Verhalten fuer jeden freigegebenen Accelerator.
- Die quantisierte Variante besteht vor Freigabe die bestehende
  per-Pipeline-Qualitaetsevaluation.
- Obsolete Pipeline-Namen und Modellbindungen sind end-to-end aus Code,
  Konfiguration, Tests und Dokumentation entfernt.
