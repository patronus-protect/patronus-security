# Externe DLP-Goldens

Die Daten bleiben lokal; Repository-Stand und Lizenzdatei werden vor dem
Ingest verifiziert. Aktive externe Abdeckung:

| Klasse | Quelle | Art | Positive | FPR-Kontrolle |
|---|---|---|---:|---|
| `dlp.content.source_code` | Gitleaks, MIT, Commit `b58d3f1…` | derived document label, keine Exact-Spans | 214 | 13 Markdown-Dateien derselben Revision |
| `dlp.content.sql` | SchemaPile-Perm, permissively licensed subset | derived source-statement boundaries, keine Upstream-DLP-Annotation | 250 | 214 Go-Dokumente nur für den getrennten SQL-Dokumenttest |

Das ist abgeleitetes Content-Ground-Truth, keine menschlich annotierte
Secret-Ground-Truth. Gitleaks implementiert selbst
Secret-Regeln und enthält Testwerte; daher ist es keine neutrale Codequelle
und darf nie als Secret-Recall-Evidenz dienen. Für SQL existieren nun
reproduzierbare Quellgrenzen; externe Secret-, Log-, Dump- sowie
Business-/Record-Identifier-Goldens bleiben offen.

SchemaPile-Perm ist dagegen ein SQL-Corpus aus 193 als permissiv klassifizierten
Upstream-Lizenzen. Der Adapter pinnt das Zenodo-Archiv per SHA-256 und nimmt
die ersten 250 lexikalisch sauber begrenzten SQL-Statements in stabiler
Archiv-/Offset-Reihenfolge. Das sind überprüfbare **Quellgrenzen** für den
abgeleiteten Content-Typ, nicht menschliche DLP-Spanannotation. Insbesondere
garantiert eine semikolonbeendete `CREATE`- oder Kommentar-Statementgrenze
nicht, dass die aktuelle L1-SQL-Regel genau dieselbe Grenze emittiert.

Wie Vorhersagen an Dokumentlabels hängen und welcher Teil einer Datei bewertet
wird, legt der Vertrag
[`dlp-external-content-contract-0.1.8.md`](../../../../docs/research/dlp-external-content-contract-0.1.8.md)
fest. Ein Label braucht einen Evidenzspan im Scope. Der Scope einer SQL-Datei
endet nach dem letzten ausgewählten Statement, deshalb lassen sich jetzt auch
Precision und der Exact-Span-Score für SchemaPile berichten. Beide Quellen
bilden die Komponente `external/` des Dev-Splits
(`scripts/l1_dlp/external_content.py prepare`, nur Dev, nie Holdout). Das
DLP-Scoreboard bewertet sie im Gate.

ProwlBench ist wegen seiner noncommercial Lizenz bewusst nicht Teil dieses
Manifests oder einer Zielabdeckung.

## Noch nicht zugelassene DLP-Klassen

| Klasse | Konkret geprüfter Kandidat | Engpass |
|---|---|---|
| `dlp.api_key`, `dlp.secret_token`, `dlp.private_key`, `dlp.credential`, `dlp.connection_string` | Gitleaks MIT, Commit `b58d3f1…` | Die Unit-Tests enthalten nur etwa 95 erwartete Findings (mehrfach dieselben AWS- und Testregeln); sie sind Scanner-eigene Erwartungswerte, keine unabhängige 200–300-Span-Ground-Truth. Daher nicht als Secret-Qualitätsgold aufgenommen. |
| dieselben Secret-Klassen | Yelp detect-secrets Apache-2.0, Commit `5e14193…` | 27 Plugin-Testmodule / etwa 133 positive Parametervarianten; kein fertiges Corpus mit normalisierten exakten Offsets und keine Klasse erreicht den Zielumfang. Werte wären zudem detector-eigene Fixtures. |
| dieselben Secret-Klassen | TruffleHog, Commit `2b75fd2…` | AGPL-3.0, daher nicht im permissiven Scope. |
| `dlp.content.system_log` | LogHub | Upstream nennt Forschung/akademische Nutzung und teils unsanitized production logs; keine klare kommerzielle Freigabe. |
| `dlp.content.database_dump` | öffentliche SQL-/Log-Corpora | Kein geprüfter permissiv lizenzierter Dump-Corpus mit exakten DLP-Spans gefunden. SchemaPile-Perm ist SQL-Schema/Content, kein Datenbank-Dump-Gold. |
| Business-/Record-IDs, Metrics | — | Keine externe, permissiv lizenzierte Span-Ground-Truth gefunden. |

Für fehlende Klassen bleiben die lokalen synthetischen Capability-Goldens die
Regressionsebene. Sie werden getrennt von den externen Content-Quellen und nie
als externe Qualitätsmetrik berichtet.
