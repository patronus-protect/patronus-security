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
denselben Core-Runner. Andere Modelle, L2-Pipelines und deren Ausführungsregeln
bleiben außerhalb dieses Umbaus.

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
