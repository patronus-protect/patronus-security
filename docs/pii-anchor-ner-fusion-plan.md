# PII-L1 auf vorhandener Injection-Mechanik: Entity-Liste, Goldens und Umsetzung

Status: Architektur-, Referenz- und Implementierungsstand, 2026-08-31. PII-L1 und DLP-L1 sind als getrennte Domains implementiert; die externe Corpus-Evaluation ist mit OpenPII Nano und TAB reproduzierbar begonnen. Dynamic PII/GLiNER-Fusion bleibt nachgelagert. Website-Schutzregeln sind weiterhin nur eine Produktgruppierung und steuern nicht die Detector-Architektur.

## 0. Implementierungsstand

Umgesetzt sind:

- 28 namentlich getrennte PII-L1-Capabilities für direkte und Anchor-gebundene Werte;
- 14 sichtbare PII-Anchor-Familien (`person_identity`, `person_role`, `contact`, `address`, `date_of_birth`, `person_identifier`, `account_identifier`, `payment_card`, `financial_identifier`, `government_identifier`, `vehicle_identifier`, `medical`, `special_category`, `employment_compensation`) mit 351 expliziten DE/EN-Hauptalternativen als strukturierte `l1_anchors`, ohne daraus Findings zu erfinden;
- sieben sichtbare DLP-Anchor-Familien (`credentials_secrets`, `auth_header_cookie`, `business_record_identifier`, `internal_business_metric`, `source_code_config`, `sql_database_dump`, `system_log_stacktrace`) mit 13 getrennten lexikalischen/strukturellen Regexen und rund 260 DE/EN-Alternativen;
- DLP-L1 für Provider-Secrets, generische Credentials, Private Keys, Tokens, Connection Strings, deutsche Business-/Record-Identifier, interne Kennzahlen, Source Code, SQL, Dumps und Systemlogs;
- Value-only-Capture-Spans, UTF-8-sichere Byte-/Char-Offsets und koexistierende DLP-Spans für beispielsweise Source Code plus enthaltenes Secret;
- direkte Ausführung der einmal kompilierten Einzelregexe für PII/DLP. Der Injection-eigene `RegexSet`-Prefilter bleibt ausschließlich in seinem bereits bewährten Rule Catalog; er wird nicht als gemeinsame PII/DLP-Abstraktion verwendet;
- 52 PII-Tests und 49 DLP-Tests mit namentlichen Capability-, Validator-, Negative-, Span-, Overlap-, Anchor- und Sammelregressionen; außerdem die bestehenden Native- und vollständigen Injection-Source-/Catalog-Goldens;
- zwei neue reproduzierbare L1-Golden-Sets mit 255 Fällen: 140 PII-Fälle für alle 28 Labels und 115 DLP-Fälle für alle 23 Labels, jeweils drei Positive plus zwei harte Negative je Label.

Noch nicht als abgeschlossen zu behaupten sind:

- regel-ID-genaue Golden-Abdeckung aller derzeit 36 PII- und 59 DLP-Patterns sowie der fünf
  separaten DLP-Heuristiken; die eingecheckten 255 Fälle decken die 28/23 Output-Labels als
  Capability-Regression ab, nicht jede alternative Provider-/Formatregel;
- weitere freigegebene Corpus-Adapter und gemessene Exact-Span-Metriken über OpenPII Nano und den TAB-Ingest hinaus, insbesondere für CodE, n2c2, Gretel und BigCode sowie GLiNER auf TAB;
- vollständige landesspezifische Checksummen für jede deutsche Dokument-/Versicherungskennung;
- regionbasierter Telefonnummern-Parse auf dem Niveau von libphonenumber;
- die eigentliche Confidence-Fusion zwischen `l1_anchors` und GLiNER-Spans.

Die lokalen `v4.1_run`-/`sensitive_current`-Daten bleiben wertvolle Dokument- und Hard-Negative-Quellen, sind aber ohne zusätzliche Spanannotation kein fertiges PII-Golden-Set.

### 0.1 Aktuelle gemessene Evidenz

Der reproduzierbare Evaluator `rust/examples/12_l1_pii_fixture_eval.rs` prüft `dynamic_pii.jsonl` gegen die echten öffentlichen `native:pii`-Spans. Das vorhandene Fixture enthält 133 Texte und 233 annotierte Spans; 78 Spans gehören zu derzeit auf L1 gemappten Labels. Nach Ergänzung ausgeschriebener deutscher und englischer Geburtsdaten lautet das Ergebnis am 2026-08-30: 70 TP, 0 FP, 8 FN, Exact-Span Precision 1,0000, Recall 0,8974 und F1 0,9459. Die acht verbleibenden Abweichungen sind sieben nicht Luhn-valide PANs im Fixture und eine US-Führerscheinnummer außerhalb des aktuellen DE-Formats. Diese Abweichungen werden nicht durch Abschwächung der Validatoren kaschiert.

`pii_l1.jsonl` enthält 140 Capability-Fälle (84 positive Exact-Spans, 56 harte Negative; 74 DE/66 EN). `dlp_l1.jsonl` enthält 115 Capability-Fälle (69 positive Exact-Spans, 46 harte Negative; 57 DE/58 EN). `rust/examples/13_l1_golden_eval.rs` validiert beide Dateien end-to-end gegen `native:pii` und `native:dlp`; Stand 2026-08-30 werden 84/84 und 69/69 positive Spans exakt getroffen und 56/56 sowie 46/46 harte Negative verworfen. Zusammen mit `dynamic_pii.jsonl` stehen 388 PII-/DLP-nahe Records und 386 annotierte positive Spans bereit. Diese Zahlen dürfen wegen unterschiedlicher Aufgaben und Labelräume nicht zu einer einzelnen Modellmetrik vermischt werden.

`dynamic_pii_threshold_sweep.jsonl` (85 Texte) und `education_pii_threshold_sweep.jsonl` (50 Texte) besitzen keine Entity-Spans und sind daher keine Exact-Span-Goldens. `sensitive_document.jsonl` enthält 699 Dokumente, aber ebenfalls keine PII-/DLP-Spans. Die neuen L1-Sets sind Capability-Regressionen, kein Ersatz für externe Corpus-Holdouts.

Der Release-Latenzbenchmark `rust/examples/11_l1_pii_dlp_latency.rs` wurde nach der breiten PII-/DLP-Anchor-Erweiterung auf einem Apple M1 mit 16 GB ausgeführt. Er erzeugt exakt 102.400 Byte große Inputs und misst benignen Text sowie ein Finding am Dateiende. Reiner PII-Detector: benign p50/p95/p99 6,259/6,399/6,998 ms, Match 5,820/6,389/6,423 ms. Reiner DLP-Detector: benign 3,772/4,284/4,319 ms, Match 4,641/4,772/4,886 ms. Über den Gateway-Pfad: PII benign 6,336/6,453/6,492 ms, PII Match 6,400/6,521/6,595 ms, DLP benign 5,132/5,265/5,333 ms und DLP Match 5,561/5,705/5,761 ms. Gegenüber dem vorherigen kleineren Inventar steigt der PII-Gateway-p50 auf 100 KiB um rund 1,6 ms und der DLP-Gateway-p50 um rund 3,5 ms. Beide bleiben lokal unter 7 ms p99; die Zahlen sind eine Momentaufnahme, kein SLA, und sollten in CI weiter beobachtet werden.

### 0.2 Wie ein Anchor aktuell aussieht

Ein ausgegebener PII-Anchor ist ein lokalisierter Fakt, kein Finding:

```json
{
  "kind": "anchor",
  "anchor_kind": "lexical",
  "category": "date_of_birth",
  "strength": "strong",
  "text": "Geburtsdatum",
  "start_byte": 18,
  "end_byte": 30,
  "start_char": 18,
  "end_char": 30
}
```

Daneben existieren feldgebundene Anchors direkt in Value-Regeln, etwa `Personalnummer: <value>`, `BIC: <value>`, `password = <value>` oder `Authorization: Bearer <value>`. Bei ihnen wird nur der geprüfte Wert als Finding-Span ausgegeben. DLP gibt passende Kontextmarker inzwischen ebenfalls als separate `l1_anchors` aus, darunter Assignments/Environment-Namen, HTTP-Header, Source-/Config-Marker, SQL-/Dump-Strukturen und Stacktraces. Diese Facts bleiben auch dort nicht blockierend.

Die Begriffe bleiben getrennt:

- **direct value detector:** Form und Validator reichen aus, beispielsweise E-Mail, Mod-97-IBAN oder providerpräfixierter Token;
- **lexical anchor:** Feld- oder Kontextwort; allein niemals Finding;
- **structural anchor:** Syntax oder Anordnung wie `key = value`, Header, Code-Fence oder SQL-Clause-Folge;
- **validator:** Prüfziffer, Kalender, Shape, Placeholder-/Allowlist- oder Entropietest.

Presidios Pattern + Context + Validation/Invalidation und Googles Candidate + Hotword + Proximity + Likelihood Adjustment belegen genau diese Trennung. Gitleaks ergänzt für Secrets Keyword-Vorfilter, begrenzte Zuweisungsstruktur, Secret-Capture, Entropie, Stopwords und Allowlists.

### 0.3 Referenz- und datenbasiert abgeleitete Anchors

Bereits als sichtbare Anchor-Facts ergänzt wurden:

| Familie | starke oder mittlere Beispiele | schwache Beispiele, nur Boost/Kombination |
|---|---|---|
| Person/Rolle | `Patientenname`, `Kundenname`, `Mitarbeitername` | `Patient`, `Bewerber`, `Mitarbeiter`, `customer`, `member` |
| Kontakt | `E-Mail-Adresse`, `Telefonnummer`, `Mobilnummer`, `emergency contact` | `Tel`, `Mobil`, `Fax` |
| Adresse | `Wohnanschrift`, `Meldeanschrift`, `Rechnungsadresse`, `shipping address`, `PO box` | `Ort`, `city`, `street`, `ZIP` |
| Geburt | `Geburtsdatum`, `Geb.-Dat`, `date of birth`, `birth date`, `DOB` | `geboren`, `born on`, `birthday` |
| Personenkennungen | `Personalnummer`, `Kundennummer`, `MRN`, `Matrikelnummer`, `Applicant ID` | keine blanke `ID` oder `number` |
| Account/Karte/Finanzen | `Benutzerkennung`, `CVV`, `Kartenprüfziffer`, `BIC`, `Depot-Nr`, `brokerage account number` | `login` beziehungsweise `security code` nur typisiert |
| Behördenkennungen | `Steuer-ID`, `KVNR`, `LANR`, `Passnummer`, `SSN`, `NINO` | `Ausweisnummer` nur mit passendem Value |
| Fahrzeug | `amtliches Kennzeichen`, `vehicle registration number`, `license plate` | `registration` allein nicht enthalten |
| Medizin | `Patientenakte`, `medical record`, `clinical note`, `Laborergebnis` | `Behandlung`, `Therapie`, `Symptom` |
| Vergütung/HR | `Gehaltsabrechnung`, `Personalakte`, `Payroll`, `Payslip` | `Gehalt`, `Bonus`, `compensation`, `RSU` |

Weitere, noch nicht blind zu aktivierende PII-Kandidaten ergeben sich aus Referenzen und lokalen aggregierten Vorkommen:

- KVNR: `Krankenkasse`, `Gesundheitskarte`, `eGK`, `GKV`, `Versichertenkarte`;
- LANR/BSNR: `Arztnummer`, `Vertragsarzt`, `KBV`, `Betriebsstätte`, `Praxisnummer`, `Praxisstandort`; nur zusammen mit 9-stelligem Kandidaten und Entity-spezifischer Validierung;
- Steuer/Ausweis: `St.-Nr`, `Steuerbescheid`, `BZSt`, `Dokumentennummer`, `nPA`, `KBA`, `Feld 5`; generische `Seriennummer` bleibt schwach;

DLP deckt nun bereits `credential/creds`, `Zugangsdaten`, verbreitete Secret-Environment-Namen, Auth-/Cookie-Header, Code-/Config-/Container-/Kubernetes-Marker, SQL-/Dump-Signaturen und Python-/Java-/Rust-/Go-Stacktraces als sichtbare Facts ab. Sie sind Discovery-/Fusionsevidenz; die blockierenden DLP-Findings bleiben unverändert an ihre Value-/Strukturregeln gebunden.

Die lokalen `sensitive_current`-Discovery-Zahlen stützen besonders `medical record` (1.801 Dokumenttreffer, davon 1.800 Medical), `medication` (696/686 Medical), `Personalnummer` (65/64 HR), `Aktenzeichen` (41/40 Legal), `EBITDA` (51/48 Finance) und strukturell `apiVersion:` (43/43 Source Code). Das sind Discovery-Zahlen, keine Span-Goldens und keine Qualitätsmetrik. Breite Wörter wie `name`, `city`, `function`, `class`, `secret`, `budget` und `bonus` bleiben deshalb schwach und lösen allein weder Finding noch Gate aus.

## 1. Klare Reihenfolge

Das Vorhaben hat fünf einfache Schritte:

1. **Endliche PII-L1-Liste festschreiben:** jede Entity wird namentlich aufgeführt und als `direct`, `anchor + value` oder `anchor_only` markiert. Keine Sammelbegriffe wie „weitere Identifier“.
2. **Goldens zuordnen:** vorhandene externe Span-Datensätze werden für Entity-Recall/Boundary genutzt; kleine eigene Tests prüfen Validatoren, Anchors, Relationen und harte Negative.
3. **Vorher Tests grün:** die vorhandenen Injection-Tests und alle anderen betroffenen Tests müssen vor der Änderung grün sein.
4. **PII-L1 implementieren:** vorhandene Injection-Mechanik für Pattern, Context/Anchor und Relation direkt wiederverwenden. Nur wenn dabei konkrete Duplikation entsteht, wird die betroffene kleine Utility geteilt.
5. **Nachher alles grün:** dieselben Injection-Tests plus die neuen PII-Goldens müssen grün sein. Danach kann Dynamic PII/GLiNER auf den tatsächlich verbleibenden Lücken aufbauen.

Es gibt keinen separaten „Injection einfrieren“-Prozess, kein Baseline-Artefakt und kein vorab zu bauendes Evidence-Framework. Website-Schutzregeln sind ein Produkt-/Renderingbegriff und keine Eingabe in die L1-Architektur.

Weitere verbindliche Entscheidungen:

- `ark-api` ist Rust/Axum. Python enthält Mapping-, Benchmark- und Wrappercode, ist aber nicht die Sprache des HTTP-Runtimes.
- Kein Presidio-Runtime-Dependency. Bewährte Muster und Testideen dürfen übernommen werden.
- „Mechanik teilen“ bedeutet aktuell den kleinen nativen Vertrag für kompiliertes Pattern, Value-Capture, Validator, exakte UTF-8-Offsets, Details und Overlap-Verhalten. Der Injection Rule Catalog mit seinen geordneten Relationen bleibt unverändert und wird erst dann weiter verallgemeinert, wenn PII eine wirklich gleichartige Relation benötigt.
- Injection behält öffentliche Modellnamen, Candidate-IDs, Findings, Scores, Sortierung, Gates und Fehlersemantik.
- PII und DLP behalten ihre öffentlichen Ergebnisse `native:pii` und `native:dlp` auf denselben gemeinsamen Primitiven.
- Credentials, Secrets, Quellcode, SQL, Logs, Dumps, interne Kennzahlen und reine Business-Identifier gehören in `native:dlp_l1`, nicht in PII. Überlappende PII- und DLP-Spans dürfen koexistieren.
- `anchor_only` ist ein typisierter interner Fakt und niemals automatisch ein Finding. Bei Namen, freien Adressen, Diagnosen und besonderen Kategorien kann L1 deshalb nützlich sein, ohne die Entity selbst zu behaupten.
- Eine valide IBAN oder E-Mail kann direkt akzeptieren; `88231` benötigt Anchor und Relation.
- Weitere Capabilities werden nur mit namentlicher ID, Betriebsart und eigener Golden-Abdeckung ergänzt.

## 2. Wir erfinden die Struktur nicht neu

Die Architektur ist durch erfolgreiche Systeme und Forschung belegt:

- Google Sensitive Data Protection kombiniert Pattern, Checksum/Prüflogik, Hotwords in definierter Nähe, geordnete Likelihood-Adjustments und Exclusion Rules. Das entspricht Value + Validator + Anchor + Relation + Adjustment. Googles Source-Code-, SQL-, Log-, Backup- und Secret-InfoTypes bestätigen zugleich die DLP-Zuordnung.
- Presidio trennt Pattern-Ausgangsscore, Regex oder positive Wörterliste, Kontext-Boost, `validate_result`, `invalidate_result`, Allow-List, Threshold und Decision Explanation. Dieses Datenmodell ist als Referenz nützlich, auch ohne Presidio zu integrieren. Presidio nennt eine positive Treffervokabelliste missverständlich `deny_list`; Ark übernimmt diesen Namen nicht.
- Gitleaks kombiniert Keyword-Prefilter, Regex, `secretGroup` als redigierbaren Teil, Entropie nur auf diesem Teil, Allowlist/Stopwords und mehrteilige `required`-Regeln mit Zeilen-/Spaltenrelationen. Jede Built-in Rule besitzt TP-/FP-Testvektoren.
- BigCode StarPII nutzte bei Keys und Passwörtern Triggerkontext wie `key`, `auth` oder `pwd`, um Modelltreffer zu qualifizieren.
- CodE Alltag kombiniert für reale deutsche E-Mails NER mit Regexen und zeigt die Bedeutung domänennaher deutscher Daten.
- TAB trennt Entity-Erkennung von der Maskierungsentscheidung (`DIRECT`, `QUASI`, `NO_MASK`) und annotiert zusätzlich vertrauliche Attribute und Koreferenz.

Ark übernimmt daraus die einfache Regelstruktur für PII-L1 und setzt sie mit den bereits vorhandenen Injection-Bausteinen um. DLP bleibt fachlich getrennt.

## 3. Begriffe und Verträge

### Value Signal

Ein lokalisierter Wertkandidat, etwa E-Mail, IBAN, begrenzter Identifier, Geldbetrag oder Secret. Ein Value Signal behauptet noch nicht immer eine Entity: E-Mail und checksum-valide IBAN sind stark; eine bloße Ziffernfolge nicht.

### Anchor

Ein lokalisierter Bedeutungsindikator wie `Personalnummer`, `Geburtsdatum`, `Gehalt`, `Diagnose`, `api_key` oder `Marge`. Ein Anchor allein ist im Regelfall kein Finding.

### Relation

Eine überprüfte Verbindung zwischen Evidenzen, nicht nur gemeinsame Anwesenheit in einem großen Fenster:

- `label_before_value`, `value_before_label`
- `assigned_with_colon`, `assigned_with_equals`
- `introduced_by_copula`
- `same_line`, `same_clause`, `same_table_row`, `same_list_item`
- `newline_continuation`, `same_code_statement`
- `overlaps`, `contains`, `contained_by`
- `distance_tokens(n)`, `distance_bytes(n)`

### Validator

Ein typbezogener Test, etwa IBAN Mod-97, Luhn, valides Kalenderdatum, Länderlänge, Provider-Präfix, Telefonnummernparse oder Template-Ausschluss.

### Finding

Ein Finding enthält den erkannten PII-Wert und dessen Start/Ende. Anchors und Validatoren entscheiden nur, ob dieser Wert ausgegeben wird. Bei `Personalnummer: 88231` ist deshalb `88231` der Finding-Span; `Personalnummer` ist lediglich unterstützender Kontext.

## 4. Ist-Zustand in Ark

### Injection L1

Injection besitzt bereits Rule Catalog, RegexSet-Prefilter, exakte Lokalisierung, `ordered_relation`, strukturelle Komposition, UTF-8-sichere Offsets, Clause-/Window-Segmentierung, Features, Provenance, Candidate-Gruppierung und einen kalibrierten Scorer. `candidate_only` bleibt sichtbar, beeinflusst aber weder Acceptance noch Scoring und darf akzeptierte Candidates nicht verbinden. Öffentlich entsteht genau ein `native:injection_l1`-Resultat.

Relevante Dateien:

- `rust/src/detectors/injection/signal.rs`
- `rust/src/detectors/injection/candidate.rs`
- `rust/src/detectors/injection/token_relations.rs`
- `rust/src/detectors/injection/rule_catalog.rs`
- `rust/src/detectors/injection/structural.rs`
- `rust/src/detectors/injection/scorer.rs`
- `rust/src/pipeline/security/injection_l1.rs`

### Dynamic PII / GLiNER

`rust/src/ml/dynamic_pii.rs` chunked den Text, führt GLiNER mit aktivierten Labels und der niedrigsten konfigurierten Inferenzschwelle aus, filtert danach pro Label, korrigiert Dokumentoffsets und führt schließlich ein globales score-first Overlap-Merge aus.

`rust/src/dynamic_pii.rs` unterstützt Basislabels, label-spezifische Schwellen, `Always`/`IfResultIn`/`IfNoResult`, bedingte Labels, maximal 30 mögliche Labels und request-lokale Auflösung einer globalen Konfiguration.

Stand nach der Runtime-Bereinigung:

- Ohne explizite API-YAML verwendet die Rust-Runtime das kleine Core-Bundle `organization`, `date`, `person`, `city`, `country`. Es fragt `person` nicht gleichzeitig mit `first_name`/`last_name` ab. Der globale Threshold bleibt mangels gemeinsamen Holdouts unverändert bei `0.5`.
- `python/patronus_ark/gliner_category_map.py` bleibt Referenz-/Benchmarkcode; es verdrahtet seine Bundles nicht automatisch in die Rust-Runtime.
- `education` ist die kanonische Dokumentklasse, `school` bleibt Kompatibilitätsalias, und ein eigenes `medical`-Bundle ist vorhanden.
- Overlap-Merges deduplizieren nur noch konkurrierende Spans desselben Labels. Überlappende Hypothesen verschiedener Labels bleiben bis zu einer späteren entity-aware Fusion erhalten.
- Der kontextfreie Cross-Text-Entity-Cache speist keine Live-Evidenz mehr. Nur exakt text-, label- und thresholdgebundene Chunk-Candidates werden wiederverwendet.
- Der First-Entity-Callback publiziert ausschließlich ein nicht autoritatives `provisional`-Event. Das vollständige Resultat bleibt maßgeblich.
- Mehrere erkannte Entity-Typen bleiben in `evidence_spans`, `label_scores` und `details.entity_types` erhalten; der kompatible skalare Result-Wert lautet `entities`.
- Mehrere Dokument-/Tool-Kontexte bilden im Python-Mapping eine geordnete Union statt einer Intersection.
- Der vorhandene Conditional-Label-Resolver sieht weiterhin nur `pipeline -> result class`, keine L1-Entity, Anchor-ID, Value-Spans, Validatorergebnisse oder PII-Candidates. Für die gewünschte Fusion reicht der bestehende Vertrag daher noch nicht.
- AI4Privacy bleibt korrekt als synthetische Quelle dokumentiert, nicht als reales Corpus.

Die vorhandenen Messungen zeigen außerdem: `country` ist brauchbar; `city` hat begrenzten Recall; `date_of_birth`, `first_name` und `last_name` erreichen hohe Precision nur mit sehr niedrigem Recall. `national_id_number`, `postal_code`, `state_or_region` und `password` sind bewusst unmapped. `passport_number`, `street_address`, `username` und `driver_license_number` regressieren auf breiteren Daten. Kleine Einzel-Label-Sweeps sind daher kein Produktionsbeleg für kombinierte Bundles.

## 5. Mechanik teilen, kein neues Framework bauen

PII verwendet die bereits vorhandene Injection-Idee:

```text
Pattern findet Value oder Anchor
→ vorhandene Context-/Segmentlogik begrenzt die Suche
→ geordnete Relation verbindet Anchor und Value
→ optionaler Validator akzeptiert oder verwirft
→ ausgegeben wird der eigentliche PII-Wert
```

Dafür wird zunächst kein `rust/src/evidence/`-Subsystem und kein universeller Candidate-Typ eingeführt. Die PII-Regeln dürfen die vorhandenen Span-, Token-Relations- und Segmentierungshelfer direkt verwenden. Falls dafür ein privater Injection-Helfer zugänglich gemacht oder in eine kleine gemeinsame Utility verschoben werden muss, geschieht nur diese konkrete Änderung.

Intern benötigt eine PII-Regel lediglich:

- Entity-ID;
- erkannter Value mit Start/Ende;
- optional erkannter Anchor;
- optional Relation und Validatorergebnis;
- Entscheidung Finding oder nur Anchor-Fakt.

Der relevante Span ist normalerweise einfach der Value-Treffer. Ein zusätzlicher Candidate Span oder mehrere Provenance-Schichten werden erst eingeführt, wenn ein konkreter Testfall sie benötigt. Injection-Scoring, Gruppierung, `candidate_only` und Wireformat bleiben unangetastet.

Google nutzt dafür Pattern, Hotword und Likelihood/Exclusion; Presidio Pattern, Context, Validation/Invalidation und Score. Ark benötigt in der ersten Version keine allgemeinere Abstraktion als diese bewährte Regelstruktur.

## 7. Getrennte L1 Capability Registry

Die Registry ist die fachliche Quelle der Wahrheit. Jede Capability benötigt vor Implementierung stabile ID, Domain, Modus, Matcher, Anchors, erlaubte Relationen, Validatoren, negative Evidenz, Candidate-/Actionable-Span-Vertrag, Golden-Coverage und Status. Zulässige Domains sind:

| Domain | Erlaubtes Ergebnis |
|---|---|
| `PII-L1` | eigenständiges personenbezogenes Finding |
| `DLP-L1` | eigenständiges Secret-, Content- oder Business-DLP-Finding |
| `anchor_only` | interner Evidence-Fakt; niemals allein actionable |
| `semantic/defer` | Entity wird erst durch NER/GLiNER oder späteren Resolver behauptet |

Der Mechanikvertrag folgt den Referenzen:

```text
matcher evidence
+ optional anchor evidence
+ explicit relation
+ validator result
- negative evidence
= domain candidate

domain acceptance = PII-L1 finding | DLP-L1 finding | anchor-only fact
finding span      = erkannter Value/Secret
```

### 7.1 PII-L1: direkt oder formal stark

Die PII-L1-Liste ist für diesen Plan geschlossen. Sie umfasst genau die Capabilities in 7.1 und 7.2; ein generisches `national_id`, `other_identifier` oder später still ergänzter Identifier existiert nicht.

| Capability | Value-Matcher / Anchor | Validator und negative Evidenz | Actionable Span | Primäre Referenzen/Gold |
|---|---|---|---|---|
| `pii.email` | RFC-nahe Mailbox; Mail-Anchor optional | Local-/Domain-/IDNA-Policy; Maskierungen/Templates getrennt | Adresse | Presidio/Google; OpenPII, CodE, n2c2 |
| `pii.phone` | international direkt, national mit Telefon-/Mobil-/Fax-Anchor | regionbasierter Parse; Build-, Rechnungs-, Versionsnummern | Nummer inkl. Durchwahl | Presidio PhoneRecognizer/Google; OpenPII, CodE, n2c2 |
| `pii.ip_address` | echter IPv4-/IPv6-Parser; IP-/Host-Anchor optional | Range; public/private/local als Policy-Metadatum; Versionsnegative | IP | Presidio/Google; Parservektoren, BigCode nur Cross-Domain |
| `pii.mac_address` | 6-Octet-Formate | Separator/Länge; Hash-/Hexnegative | MAC | Presidio/Google; generierte Formatmatrix |
| `pii.credit_card.pan` | 12–19 Ziffern mit Separatoren | Luhn, Issuer-Präfix/-Länge, Gleichziffern-/Timestampnegative | PAN | Presidio/Google; OpenPII, Presidio Synth, eigene Mutationen |
| `pii.credit_card.cvv` | 3–4 Ziffern, CVV/CVC-Anchor zwingend | Länge, Feldrelation, optional PAN/Expiry-Koexistenz | CVV | Google; eigene Anchor-Minimal-Pairs |
| `pii.credit_card.expiry` | `MM/YY` oder `MM/YYYY`, Expiry-Anchor zwingend | valider Monat/Jahresbereich; allgemeine Datumsnegative | Datum | Google; eigene Anchor-Minimal-Pairs |
| `pii.iban` | länderspezifische Struktur | Landcode/-länge, Mod-97, mutierte Prüfsummen | IBAN | Presidio IbanRecognizer/Google; CodE/Gretel/eigene Vektoren |
| `pii.swift_bic` | 8/11 Zeichen, BIC/SWIFT-Anchor | Bank-/Land-/Locationstruktur; Wortnegative | nur Code | Google; Gretel/eigene Vektoren |

IP und MAC werden wie bei Presidio/Google technisch erkannt. Ob eine Server-, private oder lokale Adresse tatsächlich redigiert wird, entscheidet eine spätere Policy; diese Entscheidung darf den Parser-Goldstandard nicht verfälschen.

### 7.2 PII-L1: Anchor–Value–Relation oder Locale-Bundle

| Capability | Anchors und Relation | Value / Validator | Pflichtnegative / Goldquellen |
|---|---|---|---|
| `pii.employee_id` | Personalnummer, Mitarbeiter-ID; Assignment/Table Row | Tenantformat oder begrenzter Identifier | Ticket, Build, Kostenstelle; lokale HR-Beispiele/OpenPII |
| `pii.customer_id` | Kundennummer, Debitor, Customer ID; Assignment | Tenantformat/Dictionary | Bestellung, Rechnung, Artikel; lokale CRM-Beispiele |
| `pii.patient_id` | Patientennummer, MRN; Assignment/Column | Tenant-/Klinikformat | Fall-, Lab-, Geräte-ID; n2c2/lokale Medical-Beispiele |
| `pii.student_id` | Matrikel-, Schüler-, Studenten-ID | Institutionsformat | Kurs-, Modul-, Prüfungs-ID; Kaggle/OpenPII/AP9-Minimal-Pairs |
| `pii.applicant_id` | Bewerbernummer, Bewerber-ID | Recruiting-/Tenantformat | Stellen-, Ausschreibungs-, Vorgangs-ID; OpenPII/lokale HR-Minimal-Pairs |
| `pii.username` | Benutzer, Login, Username, Account | Handle/Identifier | Code-Symbol, Host/Paket; CodE/Kaggle/OpenPII |
| `pii.date_of_birth` | Geburtsdatum, geboren am, DOB | valides Kalenderdatum, weiche Altersplausibilität | Frist-, Vertrags-, Rechnungsdatum; TAB/CodE/OpenPII/n2c2 |
| `pii.financial_account_number` | Kontonummer, Depotnummer | land-/institutsspezifisch | Rechnung, Bestellung, Telefon; Google/eigene Beispiele |
| `pii.de.tax_id` | Steuer-ID, IdNr | ISO 7064 MOD 11,10 und Formregeln | USt-ID, Steuernummer, Telefon; Presidio/Google/OpenPII |
| `pii.de.tax_number` | Steuernummer, Steuer-Nr. | bundeseinheitliches 13-stelliges Schema beziehungsweise Länderformat | Rechnungs-/Kundennummer; BZSt/eigene Beispiele; kann natürliche Person oder Organisation betreffen |
| `pii.de.social_security_number` | SV-/Rentenversicherungsnummer | Struktur und Prüfziffer | Versicherungs-/Aktennummer; Presidio/OpenPII |
| `pii.de.health_insurance_number` | Versichertennummer, KVNR | land-/kassenspezifisch | Mitglieds-/Vertragsnummer; Presidio/n2c2/OpenPII |
| `pii.de.physician_number_lanr` | LANR, lebenslange Arztnummer | 9 Stellen, Prüfziffer/Fachgruppenteil | BSNR, Patient-/Fallnummer; KBV |
| `pii.de.passport_number` | Reisepass, Passnummer | Alphabet, Länge, MRZ/Prüfziffer | beliebige Produkt-/Dokumentcodes; Presidio/Google/OpenPII |
| `pii.de.identity_card_number` | Personalausweis, Ausweisnummer | Alphabet, Länge, MRZ/Prüfziffer | Dokument-/Vorgangscodes; Presidio/Google/OpenPII |
| `pii.de.driver_license_number` | Führerschein/Fahrerlaubnis | Positions-/Alphabetregeln | Kunden-/Seriennummer; Presidio/Google/OpenPII |
| `pii.de.vehicle_registration_plate` | Kennzeichen/Kfz/Fahrzeugbezug | Ortskürzel, Format, Saison/E/H | Initialen+Zahl, Datei/Version; Presidio/eigene Goldens |
| `pii.us.social_security_number` | SSN/Social Security Number | Area-/Group-/Serialregeln | bekannte ungültige/Testbereiche; Presidio/Google |
| `pii.uk.national_insurance_number` | NINO/National Insurance Number | Präfix-/Suffixregeln | Produktcodes; Presidio/Google |

Presidios deutsche Recognizer für Steuer-ID, Steuernummer, Pass, Ausweis, Sozial-/Krankenversicherung, Kfz, Handelsregister, PLZ, LANR, BSNR, USt-ID und Führerschein waren Referenzen bei der Auswahl. Die Zuordnung ist dabei explizit: Steuernummer und LANR sind PII-Capabilities; USt-ID, Handelsregisternummer und BSNR sind DLP-Capabilities, weil sie regelmäßig Organisation beziehungsweise Betriebsstätte statt einer natürlichen Person identifizieren. Keine davon bleibt als unbenannter Sammel-Identifier offen.

### 7.3 DLP-L1: Secrets und Credentials

| Capability | Matcher / Komposition | Validator und negative Evidenz | Actionable Span | Referenz/Gold |
|---|---|---|---|---|
| `dlp.provider_api_key` | Providerpräfix, Länge, Alphabet | Providerformat; Docs-, Example-, Redacted-Werte | nur Key | Google Secrets; Gitleaks Provider-TP/FP; Ark DLP |
| `dlp.aws_credentials` | Access-Key und Secret werden derzeit unabhängig erkannt | Präfix/Alphabet/Länge; eine `required`-Pair-Relation bleibt Hardening | jeweiliger Value | Gitleaks AWS; Google `AWS_CREDENTIALS` |
| `dlp.generic_credential_assignment` | api/auth/credential/key/password/secret/token + Assignment + RHS | Länge, Alphabetmix, optionale Entropie; public_key, api_version, key_length, csrf_token, Env/Placeholder | nur RHS | Gitleaks generic; Ark DLP/Postfilter |
| `dlp.password_assignment` | password/passwd/pwd + Feld/Zuweisung | nicht leer; Hash/Policy/Env/Redaction unterscheiden; niedrige Entropie darf echtes schwaches Passwort nicht retten | nur Passwort | Google/Gitleaks; eigene Minimal Pairs |
| `dlp.auth_token` | Bearer/OAuth/access-/refresh-token | Encoding, Länge, Entropie; Typname/Env/Redaction | Token | Google/Gitleaks |
| `dlp.basic_auth` | Basic-Header oder credentialed URL | Base64 zu `user:password`, leere/Placeholder ausschließen | Credential oder Passwort nach Policy | Google |
| `dlp.jwt` | drei Base64url-Segmente | derzeit Shape/Segmentgrenzen; Header-/Payload-JSON-Parsing bleibt Hardening | JWT | Google; Ark plus Mutationen |
| `dlp.oauth_client_secret` | client_secret/oauth + Assignment | Provider-/Längen-/Entropieregeln; client_id/Env negativ | Secret | Google/Gitleaks |
| `dlp.private_key` | vollständiger PEM/OpenSSH-Block | derzeit Begin-/End-Shape; identischer Typ und parsebarer Container bleiben Hardening | kompletter Private-Key-Block | Google/Gitleaks; generierte Schlüssel |
| `dlp.encryption_key_or_keyset` | Key-/Keyset-Feld + Base64/Hex/JSON | Länge, Entropie, Schema; Key IDs/Public Keys negativ | Value/Keyset | Google |
| `dlp.database_connection_string` | DB-Scheme oder KV-String + Credentialfelder | URI/KV-Parse, Passwort vorhanden; credentiallos/Env negativ | Passwort, optional URI nach Policy | Gitleaks/Google; generierte DSNs |
| `dlp.url_credential` | sensitiver Queryparameter + Value | Mindestwert, nicht redacted/placeholder | nur Query-Value | vorhandenes Ark DLP plus Goldens |
| `dlp.signed_url` | Signatur-/Credentialparameter | derzeit URL-Shape; Providerbindung und erforderliche Parameterkombination bleiben Hardening | URL | Google; eigene Composite-Goldens |
| `dlp.session_cookie` | Cookie-/Set-Cookie-Header + Sessioncookie | Syntax, Länge/Entropie; Analytics-/Literalnegative | nur Cookie-Value | Google |
| `dlp.xsrf_token` | X-CSRF-/X-XSRF-Header oder Feldanchor + Token | Syntax, Länge/Entropie; Literalnegative | nur Token | Google |
| `dlp.crypto_private_key` | WIF-/Chainformat | derzeit Alphabet/Länge; Base58Check bleibt Hardening | Private Key | Presidio/Gitleaks; Ark-Regex erweitern |
| `dlp.weak_password_hash` | Hashsyntax + Dump-/Passwordfeld | Algorithmus/Salt/Länge; Commit-/Paketchecksum negativ | Hash | Google/Gitleaks |

Gitleaks ist hier die operative Hauptreferenz: `keywords` sind nur Prefilter, `regex` lokalisiert das Konstrukt, `secretGroup` definiert den actionable Span, und Entropie gilt nur für diesen Secretteil. Ark soll dieses Prinzip übernehmen, nicht einfach den gesamten Ausdruck `API_KEY=...` redigieren.

### 7.4 DLP-L1: Content und Business Data

| Capability | strukturelle Evidenz | Actionable Span | Golden-Quelle |
|---|---|---|---|
| `dlp.source_code_block` | Fence/`pre`, Diff oder typische Blockstruktur | engster kohärenter Block | Google Source Code; permissive Sprachkorpora, BigCode nur nach Zugang |
| `dlp.source_code_statement` | einzelnes typisiertes Import-, Declaration-, Assignment- oder Aufrufkonstrukt | Statement | sprachstratifizierte Parser-/Heuristikgoldens |
| `dlp.sql_statement` | SQL-Verb mit der für das Verb notwendigen Clause-/Terminatorstruktur | Statement | Google SQL; SQL-Corpora plus Prosa-Negative |
| `dlp.system_log` | wiederholte Timestamp/Level/Logger/Stackframe-Komponenten | Log-/Traceblock | Google System Logs; permissive Logs/synthetische Varianten |
| `dlp.database_backup` | Dumpheader + mehrere DDL-/DML-/Recordstrukturen | Dumpblock/Dokument | Google Database Backup; eigene strukturierte Goldens |
| `dlp.config_secret_assignment` | Configsyntax + Secretanchor + Value | nur Secret; Config als Candidate-Evidence | Gitleaks-TP/FP und eigene Templates |
| `dlp.internal_business_metric` | Marge, DB, Umsatz, Forecast, EBIT(DA) + Geld/Prozent/Zahl in Feld-/Tabellenrelation | derzeit vollständige Anchor-Value-Relation | lokale echte Dokumentbeispiele plus Minimal Pairs |
| `dlp.de.vat_id` | USt-ID/USt-IdNr. + Länderformat | USt-ID | BZSt/Presidio; identifiziert regelmäßig einen Marktteilnehmer, nicht zwingend eine natürliche Person |
| `dlp.de.commercial_register_number` | Handelsregister/HRB/HRA + Registercode | Registernummer | Presidio; Unternehmensdokumente |
| `dlp.de.facility_number_bsnr` | BSNR/Betriebsstättennummer | 9-stellige Betriebsstättenkennung | KBV; identifiziert Praxis/MVZ statt Arztperson |
| `dlp.record.case_id` | Fallnummer/Fall-ID + begrenzter Identifier | Fallkennung | Medical/Support/Legal-Beispiele |
| `dlp.record.contract_id` | Vertragsnummer/Vertrags-ID + Identifier | Vertragskennung | Vertragsdokumente |
| `dlp.record.claim_id` | Schadennummer/Claim-ID + Identifier | Schadenkennung | Versicherungsdokumente |
| `dlp.record.order_id` | Bestellnummer/Order-ID + Identifier | Bestellkennung | Commerce-Dokumente |
| `dlp.record.invoice_id` | Rechnungsnummer/Invoice-ID + Identifier | Rechnungskennung | Rechnungsdokumente |
| `dlp.project_id` | Projektnummer/Projekt-ID + Identifier | Projektkennung | interne Projektdokumente |
| `dlp.organization_id` | Unternehmenskennung/Company-ID + Identifier | Organisationskennung | Unternehmensdokumente |

Source Code ist damit ausdrücklich heuristisch lösbar, aber als DLP. Ein blankes Wort wie `class`
oder `SELECT` reicht nicht. Ein einzelnes typisiertes Konstrukt wie `const client = new Client();`,
`from pathlib import Path` oder `SELECT … FROM …;` ist dagegen bereits ein DLP-Finding; die
Hard-Negatives sichern die Abgrenzung zu gleichlautender Prosa.

### 7.5 `anchor_only` und `semantic/defer`

| Capability | L1-Fakt | Warum kein autonomes L1-Finding | Spätere Quelle |
|---|---|---|---|
| `anchor.person_name_field` | Name, Vorname, Nachname, Ansprechpartner, Anrede | beliebiger Feldtext ist nicht sicher eine Person | GLiNER/NER bestätigt Namensspan |
| `anchor.address_field` | Adresse, Straße, Wohnort, PLZ, Liefer-/Rechnungsadresse | einzelne Komponente ist keine sichere personenbezogene Adresse | strukturierter Resolver oder NER |
| `anchor.medical_field` | Diagnose, Anamnese, Medikation, ICD, Patient | Anchor ist weder Diagnose noch Patientendatum | Medical NER/Code-Resolver |
| `anchor.special_category_field` | Religion, Politik, Gewerkschaft, Behinderung, sexuelle Orientierung usw. | besonders schädliche falsche Zuschreibung | NER plus Personen-/Attributrelation |
| `anchor.salary_field` | Gehalt, Brutto, Vergütung | allgemeines Gehaltsband ist nicht automatisch PII; als interne Kennzahl bereits DLP | erst mit Personen-/Employment-Relation PII-Facet |
| `entity.person_name`, `entity.street_address`, `entity.organization`, `entity.location` | L1 liefert Feld-/Formatfeatures | lexikalisch offen, mehrsprachig und mehrdeutig | TAB, CodE, German Legal NER, GermEval |
| `entity.medical_condition`, `entity.special_category_attributes` | L1 liefert Feldanchor und ggf. Code | Freitext, Negation und Zuschreibung brauchen Semantik | n2c2/TAB/Medical Corpora |

### 7.6 Verbleibende Runtime-Lücken

Der gemeinsame `NativeRegexDetector` trägt Pattern, optionalen Value-Capture, Validator, exakte Offsets, Details und Overlap-Verhalten. PII gibt typisierte lexikalische Anchor-Facts aus. Verbleibende Lücken:

- PII-Anchors besitzen Kategorie und Stärke, aber noch keine kalibrierte richtungsabhängige Proximity-/Relationsauswertung mit Dynamic PII;
- DLP besitzt feldgebundene und strukturelle Anchors, gibt sie aber noch nicht als separates Anchor-Inventar aus;
- Telefon hat keinen echten Regionenvalidator; JWT und Crypto-Keys sind überwiegend Shape-basiert;
- landesspezifische Checksummen fehlen für einen Teil der Dokument-/Versicherungskennungen;
- die neuen 255 Capability-Goldens decken Regeln und harte Negative ab; OpenPII Nano liefert einen ersten externen nativen PII-Baseline-Lauf, während GLiNER-/TAB-Metriken, weitere Corpus-Holdouts und Cross-Domain-Fehlermatrizen ausstehen.

Bereits bereinigt sind die GLiNER-Ausgabe und das frühe Streaming: alle erkannten Typen werden als `label_scores` und `entity_types` ausgegeben, überlappende Hypothesen verschiedener Labels bleiben erhalten, und der erste Entity-Preview ist ausdrücklich `Provisional`. Die frühere textübergreifende Entity-Wiederverwendung wurde entfernt; der sichere Chunk-Cache bleibt bestehen.

Lokale Belege: `rust/src/detectors/pii/pii.rs`, `rust/src/detectors/pii/validators.rs`, `rust/src/detectors/dlp/dlp.rs`, `rust/src/detectors/mod.rs`, `rust/src/post_prediction.rs` und `rust/tests/native_detectors.rs`.

### 7.7 Tests pro Capability

Jede Capability braucht genau die Tests, die ihre Regel belegen:

- valide und invalide Values für den Validator;
- Finding mit passendem Anchor, falls dieser erforderlich ist;
- kein Finding ohne Anchor beziehungsweise mit gebrochener Relation;
- typische Verwechslungen als Hard Negatives;
- korrekter Finding-Span und UTF-8-Offset.

## 8. Website-Schutzregeln sind nachgelagert

Dieser Abschnitt dokumentiert nur das spätere Website-Mapping. Er definiert weder L1-Capabilities noch Acceptance, Scoring, Golden Sets oder Modulgrenzen. Änderungen an Website-Begriffen dürfen L1 nicht verändern.

Die Live-Demo auf `https://patronus.studio/demo` zeigt derzeit:

| UI-Schutzregel | interner Schlüssel | Demo-Findings |
|---|---|---|
| Kundendaten | `personal_and_contact_data` | Name, E-Mail, Telefon, Personal-/Kundennummer, Adresse, Geburtsdatum |
| Zahlungsdaten | `payment_data` | IBAN, Zahlungskarte, später weitere Bankdaten |
| Interne Kennzahlen | `internal_metrics` | Marge, Gehalt, Deckungsbeitrag und andere interne Metrik-Werte |
| Zugangsdaten | `credentials` | API-Keys, Tokens, Passwörter und Secrets |
| Quellcode | `source_code` | Code- und SQL-Statements/-Blöcke |
| Prompt Injection | `prompt_injection` | bestehende Injection-Pipeline |

`Kundendaten` umfasst in der Personalakte auch Mitarbeiterdaten. Kurzfristig bleibt die Website kompatibel; intern verwenden wir `personal_and_contact_data`. Langfristig sollte die UI „Personen- & Kontaktdaten“ heißen oder eine HR-Regel erhalten.

Verifizierter Demo-Count-Vertrag:

- Kundendatenfall: 3 Kundendaten, 1 Zahlungsdatum, 1 interne Kennzahl;
- Quellcodefall: 2 Quellcode-Spans, 2 Zugangsdaten;
- Personalakte: 4 Kundendaten, 2 interne Kennzahlen.

## 9. Erste qualifizierbare L1-Scheibe

Die Umsetzung betrifft zunächst nur PII-L1:

| Reihenfolge | Capabilities | Grund |
|---|---|---|
| P1 | `pii.email`, `pii.iban`, `pii.credit_card.pan` | starke Validatoren, externe Spans und Mutationsgoldens |
| P2 | `pii.phone`, `pii.ip_address`, `pii.mac_address` | parserbasierte Werte mit klaren Grenzfällen |
| P3 | `pii.employee_id`, `pii.customer_id`, `pii.date_of_birth` | erste Anchor–Value–Relationen in realen Texten |
| P4 | alle übrigen, in 7.1 und 7.2 bereits namentlich aufgeführten PII-Capabilities | dieselbe Mechanik, jeweils mit eigenem Validator-/Anchor-Test |

Freie Personennamen und vollständige unstrukturierte Adressen sind nicht Teil von PII-L1. L1 liefert dafür nur die in 7.5 benannten Anchors. Die DLP-Capabilities aus 7.3 und 7.4 dokumentieren lediglich die korrekte fachliche Zuordnung und werden nicht in die PII-Implementierung hineingezogen.

## 10. Endliche Identifier-Liste und Zuordnung

Die vorherige pauschale Ausschlussliste war falsch. „Nicht immer personenbezogen“ heißt nicht „nicht erkennen“.

- LANR identifiziert laut KBV einen Arzt oder Psychotherapeuten und gehört deshalb in PII.
- Die deutsche Steuernummer kann laut BZSt natürlichen Personen oder Unternehmen/Organisationen zugeteilt werden. Ark erkennt sie als eigene Capability und kennzeichnet die mögliche Subjektart als Kontextmetadatum.
- USt-ID, Handelsregisternummer und BSNR identifizieren grundsätzlich Unternehmen beziehungsweise Betriebsstätten und gehören primär in DLP/Business.
- Fall-, Vertrags-, Schaden-, Bestell- und Rechnungsnummer identifizieren einen Datensatz oder Vorgang. Sie gehören als Record-Identifier in DLP; bei Bindung an eine natürliche Person können sie zusätzlich personenbezogen sein.
- Projektnummer und Unternehmenskennung bleiben Business-DLP.

Damit sind auch diese Identifier namentlich festgelegt. Es gibt weiterhin keinen generischen Auffang-Identifier.

Diagnosen, Gesundheitszustände, Medikamente, Religion, politische/gewerkschaftliche Zugehörigkeit, Behinderung, sexuelle Orientierung, Leistungsbeurteilung und Strafbezug bleiben semantische Folgeaufgaben. L1 kann dafür Anchors lokalisieren, soll aber ohne strukturierten Value kein autonomes Finding erzeugen.

## 11. Negative Evidenz

Jede Familie erhält eigene Hard Negatives:

| Familie | Pflichtfälle |
|---|---|
| Identifier | Build/Ticket mit gleicher Zahl, Definition ohne Wert, `[REDACTED]`, leerer Tabellenkopf, Anchor und Zahl in verschiedenen Sätzen |
| Telefon/Adresse | Rechnungsnummer, PLZ, Hex-Speicheradresse, IP/URL-Adresse, technische Zahl |
| Person | Werktitel, Märchenfigur, Firma, Produkt, Algorithmus, Code-Symbol, Copyrightkontext als eigene Policy |
| Geld/Metrik (DLP) | Begriff ohne Wert, Definition, öffentlicher Rabatt/Preis, Statuscode, Version, Stellenband versus individuelles Gehalt |
| Credentials (DLP) | `${PASSWORD}`, `<your-token>`, `[REDACTED]`, leere Zuweisung, Variablenname ohne Wert; `changeme` nicht pauschal allowlisten |
| Quellcode (DLP) | Keyword-Erklärung, „Code of Conduct“, einzelnes Syntaxwort, JSON-artige Prosa, SQL ohne Pflicht-Clause |

## 12. Dynamic PII/GLiNER: offene Folgephase, nicht Teil der ersten Umsetzung

Die folgenden Punkte sind recherchierte Hypothesen und Ist-Befunde. Sie werden nicht zusammen mit der L1-Vereinheitlichung implementiert. Ein eigener GLiNER-Entwurf beginnt erst, wenn L1 Registry, Golden Sets, Injection-Parität und PII-L1-Qualifikation abgeschlossen sind.

### Fusionsmatrix

| L1-Evidenz | GLiNER | Ergebnis |
|---|---|---|
| harter direkt validierter Value | kein Span | L1-Finding akzeptieren |
| Anchor + Value + Relation | kein Span | entity-spezifisch akzeptieren, wenn kalibriert |
| kompatibler Candidate | gleicher/überlappender Span | fusionieren; validierter Value bevorzugt als Actionable Span |
| kompatibler Anchor | Span in zulässiger Nähe | moderater, gedeckelter Boost |
| inkompatibler Anchor | Span | kein Boost; konkurrierende Entity behalten |
| harter Validatorfehler | beliebiger Span | formale Entity ablehnen; Modellhypothese diagnostisch behalten |
| starke negative Evidenz | Span | Penalty, `NO_MASK` oder Ablehnung nach kalibrierter Policy |

Entity-Empfehlung:

- E-Mail, IBAN, Karte, Telefon und bekannte Secret-Formate bleiben L1-autorativ; GLiNER bringt wenig Nutzen.
- Employee/Customer/Student/Applicant/Case IDs: L1 Anchor+Value ist primär; GLiNER kann bestätigen, darf aber keinen checksum-/formatfehlerhaften Value retten.
- Person, Adresse und Geburtsdatum: Hybrid, wobei Anchor-Nähe hilft und L1 präzisere Boundaries ersetzen darf.
- Salary/Business Metric: zunächst DLP-L1; der Anchor trägt die Fachbedeutung. Gehalt erhält erst bei belegter Personen-/Employment-Relation zusätzlich ein PII-Facet, nicht durch GLiNER allein.
- Medical und besondere Kategorien: GLiNER primär, L1-Anchors als Label-Aktivierung/Boost/Negative Evidence.
- Source Code, SQL und Credentials: eigene heuristische DLP-Domain, nicht vom GLiNER-Personenmodell abhängig.

### Gate-Matrix

| Signal | Execution Gate | Label-Aktivierung | Score-Prior/Boost | Empfehlung |
|---|---:|---:|---:|---|
| harter validierter L1-Value | nein | optional passende Hybridlabels | ja, spanlokal | L1 darf allein finden |
| struktureller L1-Candidate | nein | ja | ja | keine zirkuläre Sperre |
| Anchor ohne Value | nein | ja, enges Bundle | ja, nur bei Relation | Anchor allein kein Finding |
| Sensitive-Document-Klasse | nein | ja | kleiner Prior | Unsicherheit/Fallback beachten |
| Tool-Klasse | nein | ja | kleiner Prior | Pipeline-Ergebnis normalisieren |
| Kostenprofil explizit | experimentell | ja | — | nur mit Recall-Budget/Fallback |

Regeln:

- Ein kleiner Satz Core Labels läuft unabhängig von Dokument-/L1-Gates.
- Context Labels werden additiv aktiviert; sie ersetzen Core Labels nicht.
- Bei fehlender, unbekannter, unsicherer oder verspäteter Dokumentklasse läuft ein Fallback-Bundle.
- Ein L1-Candidate darf nicht die einzige Voraussetzung für genau das GLiNER-Label sein, das seinen fehlenden Value erkennen soll.
- Sensitive Documents sind Bundle/Prior, kein Hard Gate. Fehlklassifikation als `other` darf medizinische oder HR-PII nicht unsichtbar machen.
- Bis per-request Dynamic-PII-Konfiguration oder ein versioniertes Runtime-Registry-Artefakt existiert, bleibt der erweiterte Gateplan in `ark-api` global statisch.
- Tool- und Dokumentkontexte werden als priorisierte Union positiver Labelvorschläge behandelt, nicht als Intersection.

Der dafür benötigte interne Fact-Vertrag darf nicht über `SecurityScanResult.class_name` simuliert werden:

```text
kind: anchor | value | candidate | negative
entity_type
rule_id
confidence
validator_result
span
actionable_span
relations[]
```

Diese Facts gehen intern in den Dynamic-PII-Resolver und in die spanlokale Fusion. Sie sind nicht automatisch öffentliche Findings.

### Empfohlene additive Bundles

Das Privacy-Core-Bundle bleibt klein und vermeidet konkurrierende Ober-/Unterlabels. Insbesondere nicht gleichzeitig `person + first_name + last_name`, `location + city + country + street_address` oder `date + date_of_birth` abfragen, solange Bundle-Konkurrenz und Merge nicht gemessen sind.

| Kontext | additive Labels |
|---|---|
| Core | `person`, `street_address`, `city`, `country`, `date_of_birth` |
| `hr` | `employee_identifier`, `job_title`, `salary`; besondere Kategorien policyabhängig |
| `finance` | `legal_party`, `accounting_period`; formale Personen-IDs weiter über L1 |
| `legal` | `legal_party`, `case_number`, `court`, `law_or_regulation` |
| `education` | `student_identifier`, `applicant_identifier`, `research_participant_identifier`, `parent_or_guardian`, `degree_program` |
| `medical` | `medical_record_number`, `health_insurance_number`, `medical_condition`, `medication` |
| `internal_and_tech` | `username`; Secrets bleiben DLP/L1 |
| `source_code` | Core nicht pauschal abschalten; zusätzliche PII-Labels nur kontextabhängig |
| `marketing` | keine zusätzlichen PII-Labels; Product/Brand/Campaign sind Protected Content, nicht automatisch PII |
| `other`/unbekannt/degraded | Core plus konfiguriertes Fallback-Bundle |

`contract`, `court`, `product`, `brand`, `campaign` und `accounting_period` können geschützte Geschäftsinformationen sein, gehören aber nicht ohne Weiteres in die PII-Taxonomie.

### Score- und Merge-Vertrag

```text
raw_model_score       unveränderte GLiNER-Ausgabe
score_adjustments[]   anchor_nearby, same_line, validator_pass,
                      document_prior, template_penalty, ...
adjusted_score        kalibrierte Kombination
acceptance_threshold  entity- und Bundle-spezifisch
```

Boosts werden auf Development-Daten gelernt oder per Grid Search festgelegt und auf source-/template-disjoint Holdout geprüft. Sie sind gedeckelt. Vor der Fusion bleiben alle Modellhypothesen erhalten. Erst entity-aware wird entschieden:

- gleiches Label + hohe Überlappung: deduplizieren;
- Parent/Child-Labels wie `person` versus `first_name`/`last_name`: nach Registry-Policy gruppieren;
- unterschiedliche Labels: grundsätzlich behalten;
- L1 validiert präziseren Value: Actionable Span ersetzen, Originalspan als Modellevidenz behalten;
- UI-Redaction: über Protection Policy auflösen, nicht im Modell-Runtime.

## 13. Lokaler Bestand: `sensitive_current`, base v4.1 und AP9

AP9 ist nur ein Teil des aktuellen Sensitive-Corpus. Der exportierte Stand liegt unter:

```text
/Users/benediktveith/Documents/Apps/Patronus-Datasets/ntdb/artifacts/export/sensitive_current
```

Dieser Ordner enthält das exportierte 9-Klassen-Modell, Reports und Manifeste, nicht nur AP9 und nicht die ursprünglichen Rohdokumente. Das `training_manifest.json` belegt als Trainingsbasis:

```text
base v4.1
+ AP9 sensitive intents
+ AP9 documents_final
```

Der tatsächlich assemblierte Sensitive-Datensatz unter `ntdb/artifacts/unified_sensitive_v41_all_sensitive_aps_l2_chunk384/data/` enthält:

| Split | Gesamt | base v4.1 | AP9 Dokumente | AP9 Intents |
|---|---:|---:|---:|---:|
| Train | 20.653 | 12.642 | 3.600 | 4.411 |
| Validation | 2.067 | 1.577 | 450 | 40 |
| Test | 2.926 | 1.468 | 450 | 1.008 |

Die neun Dokumentklassen sind `legal`, `hr`, `finance`, `internal_and_tech`, `source_code`, `marketing`, `other`, `education` und `medical`.

Die ursprünglichen base-v4.1-Zeilen liegen unter `v4.1_run/base_training/`. Der separate Quelldatensatz `patronus-document-classifier-dataset` dokumentiert 13.000 Dokumente, davon 7.844 real und 5.156 synthetisch, mit per-row Provenienz- und Lizenzfeldern. Damit existieren sehr wohl echte sensitive Dokumente. Sie wurden in der ersten Analyse zu wenig berücksichtigt.

Wichtig bleibt die Aufgabenabgrenzung: `sensitive_current` und base v4.1 besitzen Dokumentklassen-Gold, aber nicht automatisch PII-L1-Span-Gold. Echte Dokumente sind deshalb hochwertige **Annotationsquellen**, nicht ungeprüft fertige PII-Goldens. Die breite Span-Ground-Truth kommt aus den externen PII-Corpora in Abschnitt 15; lokale Daten ergänzen die Patronus-Domänen und realen Anchor–Value-Kontexte.

Empfohlene Nutzung der echten base-v4.1-Dokumente: geeignete Dokumente mit geklärter interner Nutzung auswählen, darin die erwarteten PII-Entity-Spans markieren und als normale Testbeispiele verwenden. Reale Texte bleiben intern, falls Lizenz oder Personenbezug eine Veröffentlichung ausschließen.

### AP9 als zusätzlicher Kontextbestand

`v4.1_run/ap9/documents_final/` enthält zusätzlich 4.500 akzeptierte Dokumente: je 2.250 `education` und `medical`; pro Klasse 1.800 Train, 225 Validation und 225 Benchmark. Die Normalizer entfernen dort bewusst Namen, IDs, Adressen, Datumsfelder, Kosten und weitere Identifikatoren.

AP9 ist daher besonders geeignet für:

- deidentifizierte medizinische und Education-Hard-Negatives;
- Anchor-Mining ohne implizite Value-Wahrheit;
- kontrollierte valide/invalide PII-Injektionen;
- source-disjointe Minimal Pairs.

Damit ergänzen sich die Bestände: base v4.1 liefert reale sensitive Dokumentkontexte zur Annotation; AP9 liefert kontrollierte/deidentifizierte Kontexte und source-disjointe Erweiterungen.

## 14. Vorhandene Ark-Daten

| Datei | Umfang | Nutzen | Grenze |
|---|---:|---|---|
| `dynamic_pii.jsonl` | 133 Texte, 233 Spans | Smoke-/Regression | viele Speziallabels nur einmal; synthetisch |
| `dynamic_pii_threshold_sweep.jsonl` | 85 Texte | Einzellabel-Exploration | 5 Positive je 15 Labels, nur 10 gemeinsame Negative |
| `education_pii_threshold_sweep.jsonl` | 50 Positive plus kleine Negativbasis | Education-Exploration | kein Produktionsbenchmark |
| `sensitive_document.jsonl` | 699 Dokumente | Dokumentkontext/Pre-Annotation | keine PII-Spans; Provenienz teilweise nicht rekonstruierbar |
| Demo-Goldens | wenige Szenarien | Produkt-, Count-, Span- und Renderingvertrag | zu klein für Gütemaße |

Keine aktuelle Fixture-F1 darf als Release-F1 für die neue Fusion berichtet werden.

## 15. Externe Datenquellen

Externe PII-Korpora sind ein tragender Teil der Goldens, nicht bloß optionale Ergänzung zu `sensitive_current`. Ihre vorhandenen Entity-Spans werden direkt auf die Ark-Entity-IDs gemappt und für End-to-End-Recall und Boundaries verwendet. Sie müssen nicht nachträglich mit Arks internen Anchors oder Relationen annotiert werden. Diese Mechanik wird mit kleinen eigenen Regeltests geprüft.

| Quelle | Daten und Annotation | Ark-Rolle | Lizenz/Nutzung |
|---|---|---|---|
| TAB | 1.268 reale englische ECHR-Fälle; Character-Offsets, Entity, `DIRECT`/`QUASI`/`NO_MASK`, vertrauliche Attribute, Koreferenz | wichtigster offener Real-Text-Holdout für semantische PII und Reidentifikationskontext | Repo MIT |
| CodE Alltag pS / 2.0 | reale deutsche E-Mails; öffentlich u. a. 800 pseudonymisierte Spender-E-Mails; ursprüngliche Kategorien inkl. Name, Username, Datum, Passwort, IDs/IP/IBAN, Adresse, E-Mail, Telefon, URL | deutsche Kommunikationskontexte und Hard Negatives; pS nur mit eigener einfacher Spanannotation | pS CC BY-SA 4.0; ursprüngliches Standoff-Gold offenbar nicht öffentlich |
| CodE Privacy Tagger | 15 Kategorien; Modell auf pseudonymisierten E-Mails mit manuellen/automatischen Labels | Taxonomie-, Baseline- und Fehlermusterreferenz, kein eigenständiges Gold | Code MIT; Modell-/Datenbedingungen getrennt prüfen |
| German Legal NER | 66.723 Sätze, 2,157 Mio. Tokens, 53.632 Entities aus realen deutschen Entscheidungen | deutscher Semantic-/Boundary-Test | Lizenzwiderspruch CC BY 4.0 vs. CC BY-NC-SA 4.0; quarantänisieren |
| GermEval 2014 | >31.000 deutsche Sätze, >590.000 Tokens, verschachtelte BIO-Namenentitäten | allgemeiner NER-/Boundary-Sanity-Test und Hard Negatives | CC BY 4.0 |
| AI4Privacy Open 500K | synthetisch, 8 Sprachen inkl. Deutsch, exakte Offsets/BIO, ca. 464k Train-Zeilen plus Split | breites Format-, Boundary-, Locale- und Context-Gold; template-disjoint | CC BY 4.0 |
| AI4Privacy OpenPII 1M | 1.428.143 synthetische Texte, 23 europäische Sprachen, >10 Mio. Annotationen, 19 Typen | kommerziell besser nutzbare breite synthetische Basis | CC BY 4.0 |
| AI4Privacy 300K/400K | synthetische mehrsprachige Spans | nur Zusatzvergleich nach schriftlicher Freigabe | Custom License: nichtkommerziell/keine Redistribution oder Derivate ohne Erlaubnis |
| Presidio Research | Template-/Fake-Value-Generator, exakte Offsets, Evaluator, template-disjoint Splits | Generator-, Schema-, Error-Analysis- und Splitreferenz | Repo MIT; Generatorquellen separat manifestieren |
| Gretel Synthetic PII Finance | ca. 56k synthetische Volltexte, 7 Sprachen inkl. Deutsch, Finance/Vertrag/Support/XML/SWIFT, Character-Spans | Finance-/Formular-/XML-Anchor-Quelle; vor Goldaufnahme Label-/Overlap-Audit | Apache 2.0 |
| i2b2/n2c2 2014 | 1.304 reale klinische Records, 28.867 doppelt annotierte und surrogierte PHI-Spans | starker versiegelter Clinical-Holdout für Name, MRN, Account, Health Plan, Kontakt, Adresse, Datum/Alter | Registrierung/DUA, keine Redistribution |
| Learning Agency/Kaggle PII | ca. 22.000 reale Student Essays, PII surrogiert, BIO für Name, E-Mail, Username, ID, Telefon, URL, Adresse | Education-Holdout und realistische FP-Domäne | Competition Rules; Unternehmensnutzung juristisch prüfen |
| BigCode StarPII | ca. 12,1k Codezeilen/20.961 Secrets in 31 Programmiersprachen; Name, E-Mail, IP, Key, Passwort, Username | primär separater DLP-Golden-Track; PII nur Cross-Domain-Interferenz | gated/restricted |
| BRONCO150 | reale, manuell anonymisierte und verwürfelte deutsche Onkologiebriefe; Diagnose/Therapie/Medikation, kein ursprüngliches PHI-Gold | Medical Hard Negatives, Anchor-Mining, Overredaction; kein PII-Span-Gold | Anfrage/akademische DUA |
| MAPA | EU-Taxonomie für 24 Sprachen, 19/117 hierarchische Entity-Typen | multilingual-administrative Taxonomiereferenz; Corpus erst nach Artefakt-/Lizenzprüfung | Modelllizenz ist nicht automatisch Corpuslizenz |
| PANORAMA / SPIA | 384.789 synthetische Online-Texte aus konsistenten Profilen; SPIA annotiert Teilmengen subject-level | Profile-/Co-occurrence-/Reidentifikationstest, nicht primär formales L1-Gold | CC BY 4.0 für PANORAMA; SPIA-Revision/Lizenz pinnen |

### Capability-genaue Corpus-Zuordnung

| Familie | Primäre externe Goldquellen | Was tatsächlich Gold ist |
|---|---|---|
| E-Mail/Telefon | OpenPII, CodE, Kaggle, n2c2 | vorhandener Value Span; eigene Regeltests prüfen optionale Anchors |
| Karte/IBAN/BIC | OpenPII, Presidio Synth, Gretel, eigene Checksumvektoren | vorhandener Value Span plus eigene Validator-Tests |
| Steuer-/Sozial-/Ausweis-/Versicherungs-/Patienten-/Mitarbeiter-ID | OpenPII, n2c2, Kaggle, CodE-UFID, lokale HR-/Medical-Beispiele | vorhandener Value Span; eigene Positive/Negative prüfen Anchorpflicht |
| Adresse | OpenPII, CodE, Kaggle, n2c2, TAB | Komponenten-/Entity-Spans für NER; keine L1-Acceptance daraus ableiten |
| Person | TAB, CodE, Kaggle, n2c2, German Legal NER, GermEval | semantischer Value Span; L1 liefert häufig nur Anchor-Fakt |
| Geburtsdatum/Alter | TAB, CodE, OpenPII, n2c2 | Datum/Alter-Span; PII-Bedeutung erst mit typisiertem Kontext |
| Ort/Organisation/Beruf/Demografie | TAB, German Legal NER, GermEval, n2c2 | `semantic/defer`, kein autonomes Regex-Gold |
| Keys/Passwörter/Tokens/Source-Code-Credentials | BigCode, Gitleaks-Regeltests, lokale Source-Code-Daten | ausschließlich DLP-Track |
| Medical-/Education-Kontext ohne PII | BRONCO, AP9, lokale deidentifizierte Dokumente | Hard Negative und Overredaction, nicht PII-Value-Gold |

Restriktive Daten werden nicht eingecheckt. Ein kleiner Quellenkatalog hält URL/Revision, Lizenz, lokalen Pfad und Label-Mapping fest. Metriken werden pro Corpus und Entity berichtet.

## 16. Goldformat

Für Ark-eigene L1-Regeltests reicht ein kleines Format:

```json
{
  "id": "pii-de-hr-000001",
  "text": "Personalnummer: 88231",
  "language": "de",
  "entities": [{
    "entity_type": "pii.employee_id",
    "start": 16,
    "end": 21
  }],
  "expected_anchors": ["employee_id"]
}
```

`expected_anchors` ist nur bei Anchor-Regeln nötig. Negative Beispiele haben eine leere `entities`-Liste. Die Relation wird durch das Beispiel selbst geprüft: Ein passendes Minimal Pair verschiebt Anchor und Value etwa in verschiedene Sätze und erwartet kein Finding. Externe Corpora behalten ihr eigenes Format und werden über einfache Label-Adapter ausgewertet.

## 17. Benchmarkprogramm

### A. Injection bleibt grün

Vor der ersten Änderung laufen die vorhandenen Injection-Tests. Nach jeder Änderung laufen dieselben Tests erneut. Nur wenn heute relevantes Verhalten ungetestet ist, wird dafür ein normaler Regressionstest ergänzt. Es gibt kein separates Freeze-Artefakt.

### B. Validatoren

Pro formalem PII-Typ werden repräsentative gültige Werte, ungültige Länge/Alphabet/Checksum und relevante Schreibvarianten getestet. Vorhandene Presidio-/Spezifikationsvektoren dienen als Vorlage. Eine willkürliche feste Fallzahl ist kein Abnahmekriterium.

### C. Strukturelle Candidates

Pro Anchor-Regel reichen zunächst wenige gezielte Positive und Hard Negatives über die tatsächlich unterstützten Relationen: Doppelpunkt/Zuweisung, gleiche Zeile beziehungsweise Tabellenzeile und geordnete Nähe. Minimal Pairs entfernen den Anchor, brechen die Relation oder ersetzen den Value durch einen ähnlich aussehenden Fremd-Identifier.

### D. Breite synthetische PII-Span-Goldens

AI4Privacy Open 500K/OpenPII 1M, Presidio-Synth und nach Audit Gretel Finance liefern exakte Value-Spans und Format-/Locale-Breite. Splits bleiben upstream-konform beziehungsweise template-/prompt-/seed-/profile-disjoint. Die alten AI4Privacy-300K/400K sind keine notwendige Basis und werden ohne schriftliche kommerzielle Freigabe nicht verwendet.

### E. Reale und pseudonymisierte externe PII-Corpora

TAB als offener Real-Text-Holdout, CodE-Alltag als deutscher Kommunikationskorpus und nach Lizenzklärung German Legal NER. GermEval bleibt Boundary-Kontrolle. n2c2 und gegebenenfalls Learning Agency sind lizenzierte Holdouts. Ergebnisse werden getrennt pro Corpus und Entity berichtet.

### F. Reale sensitive Ark-Dokumente

Aus base v4.1 beziehungsweise den nachvollziehbaren Quellen hinter `sensitive_current` werden gezielt reale Beispiele als normale PII-Testfälle annotiert. Dokumentlabels werden nicht als PII-Spans interpretiert. Es ist kein separates Overlay-Schema nötig.

### G. AP9 und BRONCO

Deidentifizierte Medical-/Education-Dokumente sind False-Positive-/Overredaction-Gold, Anchor-Mining-Kontext und Träger kontrollierter span-genauer Minimal Pairs. Ihre Dokument- oder Medical-Entity-Labels werden nicht als PII-Spans interpretiert.

### H. Separater DLP-Track

Gitleaks-Regeltests, Ark-DLP-Regressionsdaten, Provider-/Formatvektoren und strukturierte Source-Code-/SQL-/Log-Daten bilden eine eigene Suite. BigCode/StarPII wird nur nach Zugang und als DLP-Holdout verwendet. DLP-Ergebnisse werden nicht in PII-F1 eingerechnet.

## 18. Splits

Vorhandene Corpus-Splits werden beibehalten. Bei selbst erzeugten Daten bleiben Varianten desselben Templates oder Dokuments im selben Split. Restriktive Corpora werden nur über lokale Adapter geladen.

## 19. Metriken

Berichtet werden Exact-Span Precision/Recall/F1 pro Entity und Corpus sowie die Ergebnisse der capability-spezifischen Hard Negatives. Für Anchor-only-Regeln wird geprüft, dass der Anchor gefunden wird, aber kein PII-Finding entsteht. Injection hat kein neues Metriksystem: seine vorhandenen Tests müssen einfach grün bleiben.

## 20. Umsetzungs- und Evaluationsreihenfolge

1. **Erledigt:** endliche PII-/DLP-Capabilities und Betriebsart (`direct`, `anchor + value`, `anchor_only`) festlegen.
2. **Erledigt:** direkte und Anchor-gebundene PII-Regeln, DLP-Regeln, Validatoren und exakte Spans implementieren.
3. **Erledigt:** granulare Capability-, Negative-, Offset-, Overlap- und bestehende Injection-Goldens grün halten.
4. **Erledigt:** lokale span-genaue `pii_l1`-/`dlp_l1`-Capability-Sets mit 255 Fällen, Generator, Schematests und End-to-End-Rust-Evaluator anlegen.
5. **Erledigt (erste externe DLP-Content-Quellen):** `python/patronus_ark/benchmark_data/external_dlp/` pinnt Gitleaks (MIT, Commit und Lizenz-SHA) und normalisiert 214 Go-Dateien als deterministische positive `dlp.content.source_code`-Dokumente; 13 Markdown-Dateien derselben Revision bilden die getrennte Document-FPR-Kontrolle. Es entstehen bewusst keine Whole-File-Exact-Spans und keine Span-F1-Behauptung. SchemaPile-Perm ergänzt 250 deterministisch ausgewählte, semikolonbeendete SQL-**Quellgrenzen**; das ist abgeleitetes Content-Gold, keine menschliche DLP-Annotation und noch kein gemeldeter End-to-End-Span-Score. Wegen der enthaltenen Secret-Regeln und Testwerte ist Gitleaks außerdem keine neutrale Secret-Recall-Evidenz. ProwlBench ist bewusst außerhalb des Manifests und der Zielabdeckung. Externe Secret-, Log-, Dump- sowie Business-Identifier-Goldens bleiben offen.
6. **Begonnen:** `python/patronus_ark/external_pii_eval.py` normalisiert OpenPII-JSONL,
   TAB-Standoff, die sechs gepinnten Gretel-Testshards und kontrollierte Offset-JSONL-Exporte auf stabile Ark-IDs und misst
   Exact-Span-Metriken getrennt nach Corpus, Sprache, Scope und Entity. Das
   Quellenmanifest und bewusst winzige Schema-Fixtures liegen unter
   `python/patronus_ark/benchmark_data/external_pii/`; externe Rohdaten bleiben
   außerhalb des Repositories und werden über Revision plus SHA-256 verifiziert. Ein textfreies Auswahlmanifest cappt reproduzierbar und template-/dokumentgruppenatomar auf höchstens 250 Spans je Corpus und Metrikklasse.
7. **Begonnen:** `scripts/evaluate_internal_pii_spans.py` wertet kontrollierte, hashgebundene `verified_span`-/`verified_no_pii`-Sidecars aus. `scripts/build_local_l1_preannotation.py` hat aus 5.938 repräsentativ gescannten lokalen Dokumenten 4.274 eindeutige L1-Span-Kandidaten und 2.034 Anchor-only-Reviewkandidaten erzeugt. Diese bleiben bis zur menschlichen Prüfung ausdrücklich kein Gold.
8. **Begonnen:** OpenPII Nano liefert 900 Dokumente/4.222 gemappte Spans, TAB 127 Dokumente/5.516 `DIRECT`-/`QUASI`-Spans und Gretel 5.141 synthetische Finanzdokumente mit 19 gemappten Ark-Metrikklassen. Die erste native OpenPII-Messung im corpusgedeckten `pii.*`-Scope erreicht über 1.046 Goldspans Precision 0,7568, Recall 0,6099 und F1 0,6755; DE F1 0,7227, EN F1 0,7197. Der gemeinsame Vertrag und die Klassenmatrix stehen in `docs/research/pii-dlp-benchmark-contract-0.1.6.md`. GLiNER-/Fusion-Läufe bleiben offen; Regeln werden nur anhand nachvollziehbarer Fehler nachgeschärft.
9. **Danach:** `l1_anchors` mit Dynamic PII/GLiNER fusionieren und Boosts/Gates auf dem Holdout kalibrieren.

## 21. Offene Entscheidungen für weitere Corpus- und GLiNER-Läufe

- Länderumfang für Telefon-, Ausweis-, Steuer- und Versicherungsvalidatoren;
- welche externen Corpora sofort lokal verfügbar und lizenzrechtlich nutzbar sind;
- welche realen base-v4.1-Dokumente als normale PII-Testbeispiele annotiert werden;
- interne Aufbewahrung, Zugriff und Pseudonymisierung realer sensitive Goldens;
- CodE-Nutzung und German-Legal-Lizenzklärung; OpenPII Nano und TAB sind bereits gepinnt ingestiert;
- Verzicht auf alte AI4Privacy 300K/400K oder separate schriftliche Freigabe;
- klinische Zugänge für spätere externe Evaluation.

## 22. Referenzen

Externe Quellen:

- Google Custom InfoType Rules: <https://docs.cloud.google.com/sensitive-data-protection/docs/creating-custom-infotypes-rules>
- Google Custom InfoTypes: <https://docs.cloud.google.com/sensitive-data-protection/docs/creating-custom-infotypes>
- Google InfoTypes: <https://docs.cloud.google.com/sensitive-data-protection/docs/concepts-infotypes>
- Google vollständige InfoType-Referenz: <https://docs.cloud.google.com/sensitive-data-protection/docs/infotypes-reference>
- Google InspectConfig: <https://docs.cloud.google.com/sensitive-data-protection/docs/reference/rest/v2/InspectConfig>
- BZSt Identifikationsnummern: <https://karriere.bzst.de/DE/Unternehmen/Identifikationsnummern/identifikationsnummern_node.html>
- BZSt zur Steuernummer für natürliche Personen und Organisationen: <https://www.bzst.de/DE/Unternehmen/Intern_Informationsaustausch/DAC6/Datenuebertragung/datenuebertragung_node.html>
- KBV Arztnummer/LANR: <https://hub.kbv.de/spaces/AWS/pages/173179583/9.8.2%2BANR>
- KBV LANR- und BSNR-Definitionen: <https://update.kbv.de/ita-update/SMCB/KBV_ITA_VGEX_Anforderungskatalog_SMC-B.pdf>
- Presidio Analyzer: <https://microsoft.github.io/presidio/analyzer/>
- Presidio Supported Entities: <https://github.com/data-privacy-stack/presidio/blob/main/docs/supported_entities.md>
- Presidio Default Recognizers: <https://github.com/data-privacy-stack/presidio/blob/main/presidio-analyzer/presidio_analyzer/conf/default_recognizers.yaml>
- Presidio PatternRecognizer: <https://github.com/data-privacy-stack/presidio/blob/main/presidio-analyzer/presidio_analyzer/pattern_recognizer.py>
- Presidio PatternRecognizer Tests: <https://github.com/data-privacy-stack/presidio/blob/main/presidio-analyzer/tests/test_pattern_recognizer.py>
- Presidio AnalyzerEngine: <https://github.com/data-privacy-stack/presidio/blob/main/presidio-analyzer/presidio_analyzer/analyzer_engine.py>
- Presidio PhoneRecognizer: <https://github.com/data-privacy-stack/presidio/blob/main/presidio-analyzer/presidio_analyzer/predefined_recognizers/generic/phone_recognizer.py>
- Presidio IbanRecognizer: <https://github.com/data-privacy-stack/presidio/blob/main/presidio-analyzer/presidio_analyzer/predefined_recognizers/generic/iban_recognizer.py>
- Presidio Research: <https://github.com/data-privacy-stack/presidio-research>
- Gitleaks: <https://github.com/gitleaks/gitleaks>
- Gitleaks Generic Credential Rule: <https://github.com/gitleaks/gitleaks/blob/master/cmd/generate/config/rules/generic.go>
- Gitleaks AWS Rules und TP/FP-Vektoren: <https://github.com/gitleaks/gitleaks/blob/master/cmd/generate/config/rules/aws.go>
- Gitleaks Config/Required Rules: <https://github.com/gitleaks/gitleaks/blob/master/config/config.go>
- Gitleaks Detection Engine/Tests: <https://github.com/gitleaks/gitleaks/tree/master/detect>
- GLiNER: <https://arxiv.org/abs/2311.08526>
- BigCode `pii-lib`: <https://github.com/bigcode-project/pii-lib>
- BigCode Governance Card: <https://huggingface.co/datasets/bigcode/governance-card/blob/main/README.md>
- TAB: <https://github.com/NorskRegnesentral/text-anonymization-benchmark>
- German Legal NER: <https://arxiv.org/abs/2003.13016> und <https://github.com/elenanereiss/Legal-Entity-Recognition>
- CodE Alltag: <https://github.com/codealltag/CodEAlltag_pS>, <https://aclanthology.org/2022.lrec-1.79/>, <https://github.com/codealltag/privacy_tagger>
- AI4Privacy Open 500K: <https://huggingface.co/datasets/ai4privacy/open-pii-masking-500k-ai4privacy>
- AI4Privacy OpenPII 1M: <https://www.ai4privacy.com/datasets/pii-masking-1m/>
- AI4Privacy 400K und restriktive Lizenz: <https://www.ai4privacy.com/datasets/pii-masking-400k/> und <https://huggingface.co/datasets/ai4privacy/pii-masking-400k/blob/099f04a447ff76b26d45cdaea80d11573c4670a7/license.md>
- Gretel Synthetic PII Finance: <https://huggingface.co/datasets/gretelai/synthetic_pii_finance_multilingual>
- n2c2 2014: <https://portal.dbmi.hms.harvard.edu/projects/n2c2-2014/> und <https://pmc.ncbi.nlm.nih.gov/articles/PMC4989908/>
- Learning Agency PII: <https://www.kaggle.com/competitions/pii-detection-removal-from-educational-data/data>
- BigCode StarPII: <https://huggingface.co/bigcode/starpii>
- BRONCO150: <https://www2.informatik.hu-berlin.de/~leser/bronco/index.html>
- MAPA: <https://github.com/PangeanicAI/MAPA-EU-Project>
- PANORAMA: <https://huggingface.co/datasets/srirxml/PANORAMA>
- SPIA: <https://github.com/maisonOP/spia>
- GermEval 2014: <https://sites.google.com/site/germeval2014ner/data>
- GDPR: <https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32016R0679>

Repository-Evidenz:

- `rust/src/detectors/injection/`
- `rust/src/pipeline/security/injection_l1.rs`
- `rust/src/detectors/pii/pii.rs`
- `rust/src/detectors/pii/validators.rs`
- `rust/src/detectors/dlp/dlp.rs`
- `rust/src/detectors/mod.rs`
- `rust/tests/native_detectors.rs`
- `rust/src/dynamic_pii.rs`
- `rust/src/ml/dynamic_pii.rs`
- `rust/src/post_prediction.rs`
- `python/patronus_ark/gliner_category_map.py`
- `python/patronus_ark/benchmark_data/README.md`
- `docs/gliner-education-evaluation.md`

Lokale Daten-Evidenz:

- `/Users/benediktveith/Documents/Apps/Patronus-Datasets/ntdb/artifacts/export/sensitive_current/training_manifest.json`
- `/Users/benediktveith/Documents/Apps/Patronus-Datasets/ntdb/artifacts/export/sensitive_current/FINAL_REPORT.md`
- `/Users/benediktveith/Documents/Apps/Patronus-Datasets/ntdb/artifacts/unified_sensitive_v41_all_sensitive_aps_l2_chunk384/data/assembly_report.json`
- `/Users/benediktveith/Documents/Apps/Patronus-Datasets/v4.1_run/base_training/`
- `/Users/benediktveith/Documents/Apps/Patronus-Datasets/v4.1_run/ap9/README.md`
- `/Users/benediktveith/Documents/Apps/Patronus-Datasets/v4.1_run/ap9/documents_final/assembly_report.json`
- `/Users/benediktveith/Documents/Apps/Patronus-Datasets/v4.1_run/ap9/education/README.md`
- `/Users/benediktveith/Documents/Apps/Patronus-Datasets/v4.1_run/ap9/medical/README.md`
- `/Users/benediktveith/Documents/Apps/Patronus-Datasets/patronus-document-classifier-dataset/README.md`

## 23. Nächster Schritt

Die lokale L1-Basis ist implementiert und durch Capability-Goldens abgesichert; OpenPII Nano und TAB bilden den ersten reproduzierbaren externen Bestand. Als Nächstes folgen ein fest konfigurierter GLiNER-Baseline-Lauf auf den semantischen OpenPII-/TAB-Spans, weitere lizenzierte PII-/DLP-Corpora sowie kontrollierte Spanannotation repräsentativer `sensitive_current`-/v4.1-Beispiele. Erst wenn diese Vergleichsbasis belastbar ist, werden Anchor-Proximity, Kombinationen, Gates und GLiNER-Boosts implementiert und auf getrennten Development-/Holdout-Splits kalibriert. Injections bestehende Tests müssen vor und nach jeder gemeinsamen Mechanikänderung grün bleiben.
