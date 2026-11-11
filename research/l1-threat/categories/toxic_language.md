# Kategorie `toxic_language`

Stand: 2026-11-09, Entwurf zur Freigabe. Gliederung wie [`injection.md`](injection.md); Basiswerte sind
Startwerte (siehe [`injection.md` §4](injection.md#4-patterns)), kalibriert in TX02. Sprachen: DE und EN
genügen vorerst.

## 1. Schichten

Wie [`injection.md` §1](injection.md#1-schichten-für-alle-kategorien-gleich). Geteilte Core-Lexika:
Adressat, Meta, Zitat, Testcode. Neu im Core: **gehashte Lexika** (siehe §3), die auch `harmful_content`
nutzt.

## 2. Abgrenzung

`toxic_language` = Hass gegen Gruppen, Entmenschlichung, Drohung, Beleidigung und Belästigung einer Person,
Profanität (schwach). Erkannt in Prompt und Fremdinhalt.

Nicht `toxic_language`:
- Anfragen nach gefährlichen Inhalten (`harmful_content`); Hass ist dort ausgenommen und liegt hier;
- Zitat, Moderation, Gegenrede, Forschung über Hassrede → Gegen-Kontext, kein Fund in `strict`;
- Bewertung, ob die **Antwort** toxisch ist (kein Output-Scanning auf L1).

## 3. Lexika (gehasht)

Im Repo stehen **keine Schimpfwort- oder Slur-Listen im Klartext**. Der Core speichert Begriffe als Hash
über die normalisierte Form (Kleinschreibung, Unicode-NFKC, Leetspeak- und Sternchen-Auflösung aus der
Normalisierung) und prüft je Token und Token-Bigramm in einer Hash-Menge: ein Hash pro Token, keine
Regex, einmal geladen. Die Klartextquelle bleibt außerhalb des Repos; ein Build-Skript erzeugt die
Hash-Datei, ein Prüfskript zählt nur Treffer.

Quelle (festgelegt 2026-11-09): Der Runner leitet die Liste ab, aus den Trainingssplits erlaubt
lizenzierter Datensätze (z. B. GAHD, HateCheck) per Häufigkeit und Kontrast, ergänzt um permissiv lizenzierte
Wortlisten. Die Lizenz je Quelle prüft TX01; nichts unter AGPL oder „nur Forschung“.

| ID | Inhalt (beschrieben, nicht gelistet) |
|---|---|
| `toxic.insult` | Beleidigungen gegen eine Person |
| `toxic.slur` | abwertende Bezeichnungen für geschützte Gruppen |
| `toxic.dehumanise` | Tier-, Ungeziefer-, Krankheits-Metaphern für Menschen |
| `toxic.violence_verb` | Gewaltverben in Drohform (töten, verprügeln, …) |
| `toxic.sexual_harass` | sexualisierte Belästigung |
| `toxic.profanity` | Fluchwörter ohne Ziel |
| `toxic.group` (Klartext erlaubt) | Gruppenbezeichnungen: Religion, Herkunft, Geschlecht, Orientierung, Behinderung |
| `addressee` (Core, geteilt) | du/Sie, Namen, „dieser Typ“ |

**Gegen** (−30):

| ID | Inhalt |
|---|---|
| `toxic.counter_speech` | „es ist falsch, … zu sagen“, „solche Begriffe sind rassistisch“ |
| `toxic.moderation` | Moderationsrichtlinie, gemeldeter Beitrag, Klassifikationsaufgabe |
| `toxic.self_directed` | Selbstabwertung ohne Dritte („ich Idiot“) |
| `meta`, `quotation`, `test_code` (Core, geteilt) | Forschung, Zitat, Fixtures |

## 4. Patterns

| Pattern | Kern | Basis | Validator | `requires_context` | `scored_only` |
|---|---|---|---|---|---|
| `tx_group_derogation` | `slur` oder abwertende Aussage + `group` | 45 | – | nein | nein |
| `tx_dehumanisation` | `group` + `dehumanise` | 45 | – | nein | nein |
| `tx_threat` | `violence_verb` + Ziel (`addressee`/`group`) + Absicht/Zukunft | 45 | Format | nein | nein |
| `tx_insult_addressee` | `insult` + `addressee` | 35 | – | ja | nein |
| `tx_sexual_harassment` | `sexual_harass` + `addressee` | 35 | – | ja | nein |
| `tx_profanity` | `profanity` ohne Ziel | 15 | – | ja | **ja** |

Verschleierung (Leetspeak, Sternchen, Leerzeichen im Wort) löst die Core-Normalisierung auf und gibt Plus
wie bei `injection`. Modi wie PII. Keine Regeln im Bestand.

## 5. Struktur und Träger

Kein Träger-Bonus: Toxizität im Fremdinhalt ist so relevant wie im Prompt. Zitat-Spannen aus dem Core
dämpfen (Gegen-Kontext).

## 6. Facts (Auszug)

`finding{…}`, `target{person|group|none}`, `group_kind`, `threat`, `obfuscated`, `counter_speech`, `quoted`.

## 7. Modell

Kandidaten: R+A+L, B1, B4, B5; laut Recherche zahlt sich ein Zeichen-N-Gramm-LR (K26-artig, ohne Facts)
hier besonders aus. Kein heutiger L1-Scorer. Daten DE/EN reichlich und nativ: GAHD (Kontrastpaare),
GermEval, HateCheck-DE/EN, RTP-LX, Measuring Hate Speech; Holdout siehe `research-2026-11.md` §5.1.

## 8. Policies (später)

- `tx.threat_in_tool_output`: `tx_threat` ∧ `carrier.indirect` → `ask`.

## 9. Bestand

Keine L1-Regeln. L2/L3-Label `toxic_or_harmful` mappt primär hierher (X03).

## 10. Übernommene OSS-Regeln

Keine Regelquellen; nur die lizenzsaubere Lexikonquelle aus TX01.

## 11. Goldens

Je Pattern und Sprache ≥ 5 Positive und ≥ 5 Hard Negatives; Goldens mit Slurs liegen nur gehasht bzw. als
Verweis auf Eval-Daten vor, die zur Eval-Zeit geladen werden. Pflicht-Hard-Negatives: Gegenrede,
Moderationsfälle, Zitate in Berichten, Selbstabwertung, Fachbegriffe mit Doppeldeutung (HateCheck-Fälle).

## 12. Herkunft und Daten

Regeln für Herkunft, Splits und Quellfamilien: [README](../README.md#herkunft-regeln-train-gold-holdout).
Goldens: je Pattern und Sprache ≥ 5 Positive und ≥ 5 Hard Negatives, selbst geschrieben (`ark_authored`), §11.

| | Quelle |
|---|---|
| Patterns/Anker | kein Bestand; gehashtes Lexikon `mined` auf Train (Häufigkeit/Kontrast) plus permissiv lizenzierte Wortlisten (Lizenz je Quelle in TX01); Gruppenbezeichnungen `hand` |
| Train/Dev | GermEval 2018 (Train-Split), 2019, 2021, textdetox-de, Civil Comments/Jigsaw (nur Baseline-Training) |
| Holdout `neutral` | DE: GermEval 2018 (Test-Split), GAHD, HateCheck-DE, chatmod-bench; EN: HateCheck-EN, Measuring Hate Speech, RTP-LX en |
| Holdout `ark_blind` | nicht nötig (genug `neutral`) |
| Hard Negatives | HateCheck-Gegenrede und -Zitate, GAHD-Kontrastpaare, Moderationsfälle |
| Nur berichten | GermEval 2025 (GPL), GerMS-AT (NC), MT-Moderationssätze |
