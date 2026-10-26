# Ark Core nächste Integrationsrunde

Status: geplant, 2026-10-26. Arbeitsbranch: `bv/core-next-round`.

Dieser Branch bündelt die nächsten Verbesserungen am synchronen Ark Core aus
Respan und zwei weiteren OSS-Integrationen. Er ist ein gemeinsamer Arbeitsstrang,
kein Release-Branch. Der erste festgelegte Umfang ist konfigurierbare
Wolf-Fensterung mit Overlap und echtem ONNX-Batching. Weitere Änderungen werden
erst anhand konkreter Integrationsanforderungen aufgenommen.

## Ausgangspunkt und Ziel

Core 0.1.13 verarbeitet Wolf mit höchstens 254 Inhaltstokens plus BOS/EOS,
Overlap 0 und Batchgröße 1. Diese Werte sind im Wolf-Pfad fest eingebaut.
Der gemeinsame Tokenizer besitzt zwar eine Overlap-Hilfsfunktion, der
Wolf-Runner verwendet sie derzeit nicht.

Wolf Defender Small dokumentiert einen Kontext von 2048 Tokens. Das vorhandene
lokale INT8/INT4-Modell konfiguriert `max_position_embeddings: 8192`; dieser
Architekturwert ist von dem dokumentierten Einsatzprofil zu unterscheiden.
Die tatsächlichen vorhandenen FP16- und INT8/INT4-Exporte werden mit Rust und
ONNX Runtime geprüft. Es gibt keine automatische Umstellung auf HF `main`,
keinen neuen Modell-Pin und keine neue Pflicht für ein Bundle-Manifest.

Modellreferenz:
<https://huggingface.co/patronus-studio/wolf-defender-prompt-injection-small>

## Gemeinsame Verantwortung im Core

| Verantwortung | Zuständigkeit |
|---|---|
| Optionen, Defaults und semantische Prüfung | Core |
| Tokenisierung, Fenster, Overlap und Restfenster | Core |
| Padding, Attention-Masken, Batch-Aufbau und Output-Zuordnung | Core |
| Modellvorbereitung, Precision-Auswahl, Warmup und wiederverwendbare Session | Core |
| Rohlogits, Smooth Max, Wahrscheinlichkeit und Entscheidungsschwelle | Core |
| Abbruch, Deadline, Fortschritt und typisierte Fehler | Core |
| Auswahl von Nachrichten/Feldern und deren Herkunft | jeweiliger Adapter |
| Blockieren, Maskieren und Abbildung auf das Host-Ergebnisformat | jeweiliger Adapter |
| Request-Zulassung, Queue und Host-Lifecycle | Ark bzw. jeweiliger Adapter |

Das normale Ark-Crate und Respan bauen keine zweite Wolf-Fenster-, Batch- oder
Aggregationslogik auf. Der dedizierte Wolf-Pfad des normalen Ark delegiert an
denselben Core-Runner. Die Ausführungsregeln anderer Modelle und der L2-Pipelines bleiben unverändert.
Der gemeinsame synchrone ONNX-Klassifikator wird als Implementierung in den Core
verschoben; Ark behält seinen Lazy-/Queue-Adapter und den bisherigen öffentlichen Pfad.

## Geplante Ausführungsoptionen

Ein gemeinsamer Core-Typ, vorläufig `WolfExecutionOptions`, enthält:

| Option | Bedeutung | Kompatibler Default |
|---|---|---:|
| `window_tokens` | Maximale Sequenzlänge einschließlich BOS/EOS | 256 |
| `overlap_tokens` | Inhaltstokens, die ins nächste Fenster übernommen werden | 0 |
| `batch_size` | Maximale Zahl von Dokumentfenstern pro ONNX-Aufruf | 1 |

Beispiel eines neuen Profils: `window_tokens = 2048`,
`overlap_tokens = 256`, `batch_size = 4`. Es verarbeitet bis zu 2046
Inhaltstokens pro Fenster mit einem Schritt von 1790 Inhaltstokens und bis zu
vier Fenstern pro Modellaufruf. Batchgröße bezeichnet Fenster, nicht Requests.

Semantische Prüfungen liegen einmal im Core: mindestens ein Inhaltstoken,
Overlap kleiner als die Inhaltskapazität, positive Batchgröße, geprüfte
Größenarithmetik sowie die konkret ermittelten Eingabegrenzen der Exporte.
Die bestehende 64-Token-Grenze der generischen Tokenizer-Hilfsfunktion ist
keine neue Grenze für die konfigurierbare Wolf-Ausführung.

## API und Kompatibilität

- Neue Optionen über zusätzliche Konstruktoren oder Builder übergeben;
  bestehende Aufrufe von `Scanner::new` und `WolfRunner::new` verwenden Defaults.
- Bestehende öffentliche Konfigurations-Structs nicht einfach um neue
  Pflichtfelder ergänzen: bisherige Rust-Struct-Literale müssen kompilieren.
- Alte TOML-/JSON-Konfigurationen und vorhandene lokale Assets bleiben nutzbar.
- Das normale Ark bekommt dieselben Einstellungen für seinen dedizierten
  Wolf-Pfad, ohne einen eigenen Algorithmus einzuführen.
- Respan reicht den Core-Options-Typ weiter. Eine separate Gruppe wie
  `[plugins.ark.wolf_execution]` ermöglicht dies ohne Nachbau des Core-Schemas.
  Die endgültige Einbindung wird gegen die vorhandenen öffentlichen APIs geprüft.
- Bestehende Ergebnisfelder und die Trennung von nativen Scores und
  Wolf-Wahrscheinlichkeit bleiben erhalten.

## Umsetzung in nachvollziehbaren Schritten

1. **Vorhandene Exporte konkret prüfen.** Modellidentitäten und ONNX-Achsen
   festhalten; FP16 und INT8/INT4 mit 2048 Tokens und Batchgrößen 1, 2 und 4
   tatsächlich inferieren. Die Modellinferenz erfolgt ausschließlich mit Rust
   und ONNX Runtime, ohne PyTorch oder erneuten Export.
2. **Begrenzte Fensterbildung.** Den bestehenden Tokenstrom nutzen, den
   konfigurierten Overlap behalten und am Ende kein zusätzliches Fenster aus
   ausschließlich bereits geprüftem Overlap erzeugen. Fenster und Batches
   schrittweise bereitstellen, ohne das ganze Dokument in einer Chunk-Liste
   zu halten.
3. **Echtes Batching.** Fenster im Batch mit passenden Masken auffüllen,
   einen Rohlogit pro tatsächlicher Zeile auslesen und letzte kleinere Batches
   verarbeiten. Padding-Zeilen dürfen nicht in die Dokumentaggregation eingehen.
4. **Eine Dokumententscheidung.** Alle tatsächlichen Fenster über dieselbe
   stabile inkrementelle LogSumExp-Aggregation zusammenführen: normalisiertes
   Smooth Max mit Temperatur 0.1, anschließend Sigmoid und die konfigurierte
   Wahrscheinlichkeitsschwelle. Textfelder und Dokumente bleiben getrennt.
5. **Laufzeitverträge erhalten.** Session-Wiederverwendung, Abbruch laufender
   ORT-Aufrufe, Deadlines, Fortschritt und Fehlerverhalten auch mit Batches
   erhalten. Ein abgebrochener oder unvollständiger Scan ergibt keinen sauberen
   Erfolgsbericht. Der Fortschritt zählt Fenster, nicht ONNX-Aufrufe.
6. **Ark und Adapter anschließen.** Optionen durchreichen, vorhandene
   Default-Aufrufe absichern und Respan-Konfiguration, Beispiele sowie
   request-lokale Wiederverwendung an das Ausführungsprofil anbinden.

## Prüfungen und Abnahmekriterien

- Default-Profil liefert unveränderte Tokenfenster, Rohlogits, Fensterzahlen
  und Dokumentergebnisse; bestehende Goldens werden nicht abgeschwächt.
- Fenstergrenzen, exakter Overlap, Restfenster, leere/kurze Eingaben,
  UTF-8- und interne Tokenizer-Grenzen werden abgedeckt.
- Für jedes Exportformat werden dieselben Fenster sequenziell und gebatcht
  verglichen, einschließlich unterschiedlicher Längen, Padding und Batch-Resten.
  Numerische Toleranzen werden pro Präzision ausgewiesen; zwischen FP16 und
  INT8/INT4 wird keine Gleichheit der Klassifikationswerte unterstellt.
- Smooth Max bleibt unabhängig von der Aufteilung identischer Fenster auf
  Batches. Fenstergröße und Overlap dürfen die Dokumentbewertung verändern.
- Lange Texte mit Angriffen an Fenstergrenzen werden geprüft.
- Core und normales Ark liefern bei gleichen Assets, Optionen und Eingaben
  dieselben Wolf-Ergebnisse.
- Respan-Tests prüfen Quellen, Maskierung, Tool-Loops, Fallbacks, Wiederverwendung,
  Überlast, Abbruch und Fehler mit den neuen Einstellungen über `mockllm`.
- Gemessen werden Warmup, warme Latenz und Speicher für das Default-Profil
  sowie 2048-Token-Profile mit Overlap und mehreren Batchgrößen. Tokenpuffer
  sind begrenzt; ORT-Arbeitsspeicher wird am konkreten Profil gemessen und
  nicht pauschal als linear oder konstant über alle Profile bezeichnet.
- L1-only-Build, Rust-1.88-Verbraucher, Clippy, Lizenzen und Paketierung bleiben
  Teil der relevanten Prüfungen. GPU-Backends gelten erst nach echten Tests
  als für die neuen Profile verifiziert.

## Weitere OSS-Integrationen

| Bereich | Bekannter Bedarf | Nächster Schritt |
|---|---|---|
| Wolf-Ausführung | Fenster, Overlap und Batchgröße konfigurierbar | obige Core-Arbeit |
| Respan | öffentliche Optionen verwenden, bestehende Guard-Verträge erhalten | Adapter nachziehen |
| OSS-Integration 2 | Repository und Anforderungen noch offen | konkrete Schnittstelle und Reproduktion aufnehmen |
| OSS-Integration 3 | Repository und Anforderungen noch offen | konkrete Schnittstelle und Reproduktion aufnehmen |

Neue Punkte werden mit Herkunft, reproduzierbarem Problem, Zuständigkeit und
Abnahmekriterium ergänzt. Gemeinsam benötigte Scanner-Funktionalität gehört
in den Core; host-spezifische Protokolle und Policies bleiben im Adapter.
Aus unbekannten Anforderungen entsteht vorab kein allgemeines Framework.

## Branch, PRs und Release

`bv/core-next-round` bleibt der gemeinsame Arbeitsbranch für diese Runde.
Änderungen werden nach Problem getrennt committed; neue Integrationsfunde
werden in diesem Plan nachgeführt. Fremde lokale Änderungen bleiben erhalten.

Respan PR #67 verwendet bis zur Veröffentlichung einer passenden Core-Version
weiter die veröffentlichte 0.1.13. Lokale Integrationsprüfungen dürfen einen
temporären Pfad-Override nutzen; der öffentliche Adapter erhält keine
Abhängigkeit auf einen Entwurfs-PR oder einen lokalen Checkout.

Releaseumfang und Versionsnummer werden nach den tatsächlich fertigen
Verbesserungen festgelegt. Entwicklungs-PRs werden zuerst nach Main gemergt;
ein Release-Branch entsteht anschließend aus Main. Dieser Plan beauftragt
keinen Push, keine neue PR-Erstellung und keinen Release.


## Implementierungsstand und lokale Nachweise (2026-10-26)

Umgesetzt auf `bv/core-next-round`, ohne Push, neue PR oder Release:

- `WolfExecutionOptions` im Core, auch ohne Wolf-Feature deserialisierbar.
  Neue Konstruktoren `WolfRunner::new_with_options`,
  `Scanner::new_with_wolf_options` und `Scanner::warmup_with_wolf_options`.
  Bestehende öffentliche Konfigurations-Struct-Literale bleiben gültig.
- Streaming-Fenster, Overlap, echte ONNX-Batches, Masken, Restbatches,
  zeilenweise Logit-Zuordnung, Abbruch und Fortschritt liegen einmal im Core.
  Die Implementierung ist in `wolf/windows.rs` und `wolf/inference.rs` aufgeteilt.
- Ark reicht Optionen aus `ScanExecution`/`SecurityGateway` durch. Session-Reuse
  und Entscheidungscache unterscheiden die Ausführungsprofile. Die generischen
  L2-/anderen Modellpfade behalten ihre bestehende Fensterung.
- Respan reicht lokal `[plugins.ark.wolf_execution]` an denselben Core weiter.
  README, Konfigurationstests und echte mockllm-Tests decken dies ab. Der
  veröffentlichte Respan-PR und dessen veröffentlichte Core-Abhängigkeit wurden
  nicht verändert. Lokale Prüfungen verwenden ausschließlich den CLI-Override:
  `--config 'patch.crates-io.patronus-ark-core.path="/Users/benediktveith/Apps/patronus-ark-standalone/ark-core"'`.
  Bei Clippy gehört dieser Schalter hinter `cargo clippy`.

### Funktionale Prüfungen

| Prüfung | Ergebnis |
|---|---|
| Core L1 ohne Wolf | 172 Tests grün |
| Core mit Wolf und Download | 210 Tests grün; 5 explizite Modelltests standardmäßig ignoriert |
| Core Laufzeit-/Fehlertests | 13 Tests grün; inkl. Masken, Zeilen, Restbatches, Default-Kompatibilität, Exportgrenzen, Abbruch und aktiver ONNX-Terminierung |
| Ark Entscheidungscache | 2 gezielte Tests grün |
| Ark Lazy-Wolf-Loader | 1 Test grün; neue Profile, Session-Reuse, Profilwechsel |
| FP16 echte Dokumentprofile | 256/0, 256/64, 2048/256 jeweils Batch 1/2/4 grün |
| INT8/INT4 echte Dokumentprofile | dieselben 9 Profile grün; quantisierungsbedingte Score-Differenzen ausdrücklich erfasst |
| Unabhängiger direkter ORT-Vergleich | FP16 und INT8/INT4, vier verschieden lange Zeilen; Rohlogits stimmen mit Core innerhalb 1e-6 überein |
| Respan mit Wolf | 27 Unit- und 24 Integrationstests grün |
| Respan mit echten lokalen Modellen | 4 E2E-/Modelltests grün; FP16, INT8/INT4, beide Clientformate, Tool-Folgeschritte, lange Texte und wiederholte Calls |
| Respan ohne Wolf | 22 native Unit- und 2 Beispieltests grün |
| Clippy | Core, Ark und Respan mit `-D warnings` grün |

Die vier bestehenden Downloader-Tests benötigen lokale Loopback-Ports. Sie
wurden nach dem Sandbox-Bind-Fehler mit erlaubten lokalen Sockets erfolgreich
wiederholt. Keine Python-/PyTorch-Inferenz, kein Re-Export, kein Docker,
kein Modellwechsel und keine neue Pin-Pflicht.

### Getestete bestehende Modellartefakte

Diese Identitäten dokumentieren die geprüften Dateien; sie sind keine neuen
Installationsanforderungen. Die beiden Artefakte werden jeweils gegen sich
selbst geprüft, nicht als identische Gewichte unterschiedlicher Präzision behandelt.

| Export | SHA-256 |
|---|---|
| `/private/tmp/ark-wolf-rust-bundle-final/onnx/onnx_fp16/model_fp16.onnx` | `f81eccd747b4fe9b077fb37c7ddbe0571c5b21e544e84fa95cc8bcbff9cd1332` |
| `/private/tmp/ark-wolf-memory-ab/assets-int8/onnx/int8_int4_embeddings/model.onnx` | `a6c77496152e458c072e4787f872192af0449a427359d1afbfa1d4d6b116a305` |

### Relevante Modellbeobachtung

Der quantisierte Export enthält 90 `DynamicQuantizeLinear`- und 90
`MatMulInteger`-Knoten. Seine Aktivierungsskalen hängen vom gesamten jeweiligen
Tensor ab. Unterschiedliche Batchzusammensetzung und Padding können deshalb
Logits ändern. Die anfängliche pauschale Logit-Toleranz 0.05 für Batch-1-Parität
wurde durch diesen echten Modelltest widerlegt. Die Implementierung wurde
anschließend zusätzlich gegen unabhängig konstruierte direkte ORT-Aufrufe
geprüft: Die Zeilenlogits stimmen überein. Es wird keine allgemeine
Batch-1-Gleichheit des quantisierten Exports behauptet.

In der gemischten Dokumentprobe beträgt die maximale gemessene quantisierte
Batch-Abweichung 0.8341 beim Logit und 0.001868 bei der Wahrscheinlichkeit.
Diese Wahrscheinlichkeitsabweichung ist eine Beobachtung für diese Probe,
keine universelle Fehlergrenze. Der Probentest hält für diese feste Probe
0.005 ein; synthetische und direkte ORT-Tests prüfen die Ausführung unabhängig
davon. FP16 liefert in derselben Dokumentprobe bei unverändertem Fensterprofil
für alle drei Batchgrößen identische Dokumentlogits.

Auch größere Fenster sind ein anderes Kalibrierungsprofil: In dieser einen
Probe mit eingebetteter Angriffsanweisung sinkt die Wahrscheinlichkeit beim
FP16-Artefakt von 0.9990 (256/0/1) auf 0.8267 (2048/256/1), beim quantisierten
Artefakt von 0.9967 auf 0.003324. Das ist kein Qualitätsbenchmark, zeigt aber
konkret, weshalb längerer Kontext und Batchgröße keine Zusage unveränderter
Detektionsqualität erhalten. Default 256/0/1 und callerbestimmte Schwellen
bleiben erhalten; produktive Profile brauchen passende Evaluierung.


### Isolierte RAM-/Latenz-Piloten

Vier getrennte Prozesse nacheinander, macOS arm64, CPU, ORT 1/1 Threads,
Spinning aus, Rust-Debug-Build, alle drei nativen Kategorien an, Parallelität 1.
Je drei kurze und drei lange Scans; lange Eingabe 17.220 Byte. Dies sind kleine
lokale Piloten, keine Produktions-SLAs oder belastbaren Tail-Latenzschätzungen.
`Warm` ist RSS nach dem kurzen Vorlauf, `final` nach den langen Scans;
dies sind Messpunkte, keine Peak-RSS-Messung. Die große Konfiguration erlaubt
vier Zeilen, diese konkrete lange Eingabe erzeugt aber nur zwei Fenster.

| Export | Fenster/Overlap/Batch | Konstruktion | RSS warm / final | Kurz p50 / p95 | Lang p50 / p95 | Fenster lang |
|---|---|---:|---:|---:|---:|---:|
| fp16 | 256/0/1 | 14.17 s | 616.2 / 378.1 MiB | 68.3 / 74.1 ms | 6.94 / 7.13 s | 10 |
| fp16 | 2048/256/4 | 19.01 s | 651.6 / 817.4 MiB | 131.5 / 132.7 ms | 20.48 / 20.78 s | 2 |
| int8_int4 | 256/0/1 | 7.58 s | 351.6 / 358.2 MiB | 14.5 / 14.7 ms | 2.13 / 2.13 s | 10 |
| int8_int4 | 2048/256/4 | 10.49 s | 303.2 / 685.8 MiB | 28.6 / 33.6 ms | 11.01 / 13.69 s | 2 |

Befehl je Profil:
`cargo run -p patronus-ark-core --features wolf --example wolf_benchmark -- BUNDLE 0.8 WINDOW OVERLAP BATCH 3`.
Die bestehenden Präzisionen wurden über ihre getrennten Asset-Verzeichnisse
und `PATRONUS_L3_PRECISION` gewählt. Rohmessungen:
`/tmp/core-next-benchmark-{fp16_default,fp16_large,int8_default,int8_large}.json`.
Die größeren Fenster erlauben keinen pauschalen Durchsatz- oder RAM-Vorteil;
der tatsächliche Einsatz muss zum gewählten Modellprofil passen.


## Nachprüfung: Ark verwendet Core (2026-10-26)

Die Prüfung der tatsächlichen Aufrufpfade hat einen unnötigen Rest gefunden:
Ark erzeugte für dediziertes Wolf noch Tokenchunks und einen L3-Chunk-Plan,
obwohl Wolf im Core anschließend den Originaltext vollständig verarbeitet.
Diese Vorverarbeitung ist entfernt. Ein Wolf-Job verwendet jetzt
`L3WorkerInput::Text`; das zusätzliche `source_text`-Feld des Workers entfällt.
L2-/Multihead-Jobs behalten ihren erforderlichen ursprünglichen Token-Handoff.

Zusätzlich ist der allgemeine synchrone `OnnxTextClassifier` aus
`rust/src/ml/onnx.rs` nach `ark-core/src/ml/text_classifier.rs` verschoben.
Die vorhandene Klassifikator-Implementierung einschließlich Logit-Auslesen und
Softmax wurde ohne Algorithmusänderung übernommen (normalisierter Quellvergleich
gegen HEAD: identisch, abgesehen von der nötigen Sichtbarkeit der Raw-Methoden).
Der alte öffentliche Ark-Typ ist ein Re-Export desselben Core-Typs. Aus der
Ark-Datei sind 316 bisherige Zeilen entfernt; neue Zeilen darin betreffen unter
anderem Kompatibilitäts-/Regressionstests und die bereits geplanten Optionen.

Auch BOS/EOS, Padding und Attention-Masken werden nur noch einmal über
`ark_core::ml::tokenizer::assemble_batch_inputs` aufgebaut. Sowohl der normale
Klassifikator als auch Wolf verwenden diesen Helfer. Wolf übernimmt die fertigen
Puffer direkt in die ORT-Tensoren, ohne zusätzliche Kopien; Token-Type-Puffer
werden nur angelegt, wenn das Modell sie tatsächlich benötigt.
Die Wolf-Schwellenprüfung/-entscheidung wurde ebenfalls im Core vereinheitlicht:
Ark ruft `WolfRunner::set_threshold` auf, statt die Wahrscheinlichkeit selbst
noch einmal gegen eine Schwelle zu prüfen. Schwellenänderungen behalten dieselbe
Session; ungültige Schwellen ändern den bisherigen Wert nicht.

| Funktionalität | Einzige Implementierung | Ark-Seite |
|---|---|---|
| PII-/DLP-Detektoren und Validatoren | Core `detectors` | Re-Export |
| PI-L1-Producer/Ensemble | Core `injection_l1`/Detektoren | vorhandene Ergebnis-Konvertierung und Aufruf |
| mmBPE/Tokenizer-Cache | Core `ml` | Re-Export |
| BOS/EOS, Padding, Attention-Masken | Core `ml::tokenizer` | Klassifikator delegiert an Core |
| Synchroner allgemeiner ONNX-Klassifikator | Core `ml::text_classifier` | Re-Export; Lazy-Session-/TTL-Adapter bleibt |
| Wolf-Fenster, Overlap, Batch, Logits, Smooth Max | Core `wolf` | Originaltext und Optionen durchreichen |
| Wolf-Asset-Vorbereitung | Core `warmup` | vorhandene Delegation |
| Queue, Promotion, L2, Multihead, Host-Ergebnisse | Ark | eigene Host-/Modellfunktionen; keine zweite Wolf-Ausführung |

Gezielte Nachprüfung: 14 Core-Laufzeittests, 11 Tokenizer-Tests, 4 Ark-Loader-/
Klassifikator-Tests, 7 Direct-L3-Tests, 2 ursprüngliche Token-Handoff-E2Es,
ein Wolf-Lifecycle-Test und ein neuer Worker-Dokument-Handoff-Test grün.
Die echte FP16-/INT8-INT4-Inferenz ist nach dem gemeinsamen Pufferaufbau erneut
gegen unabhängig gebaute direkte ORT-Aufrufe grün geprüft (Rohlogits innerhalb 1e-6). Die frühere 9-Profil-Matrix
und RAM-/Latenz-Piloten oben wurden vor dieser Bereinigung gemessen; sie werden
nicht als neue Messung des bereinigten Codes ausgegeben.

Die LoC-Summe des ganzen Branches umfasst neue Konfiguration, Tests,
Dokumentation und die gewachsenen Fenster-/Batchfunktionen. Sie ist deshalb
weiter positiv. Der Produktionscode ist jetzt tatsächlich in Richtung Core
verschoben, statt im Ark-Klassifikator erhalten und daneben neu implementiert.
