# Kategorie `jailbreak`

Stand: 2026-11-09, Entwurf zur Freigabe. Gliederung wie [`injection.md`](injection.md); Begriffslisten sind
Auszüge, die vollständigen Lexika entstehen in S02.

## 1. Schichten

Wie [`injection.md` §1](injection.md#1-schichten-für-alle-kategorien-gleich). Geteilte Core-Lexika:
Adressat, Meta, Zitat, Testcode.

## 2. Abgrenzung

`jailbreak` = Rahmung, die die **Sicherheitsvorgaben** des Modells aushebeln soll: Persona ohne Grenzen,
privilegierter Modus, gefälschte Policy, Ablehnung unterdrücken, Antwort vorgeben, Doppel-Antwort,
Many-Shot-Struktur, Belohnungs-/Drohspiel, gefälschter Denkverlauf.

Nicht `jailbreak`:
- Vorgaben des Betreibers überstimmen (`injection`); beides zusammen feuert in beiden Kategorien;
- die gefährliche Anfrage selbst (`harmful_content`); der Jailbreak ist die Verpackung, beide können feuern;
- Mehr-Turn-Eskalation über Sitzungen (braucht Sitzungszustand, kein L1); nur die Behauptung im selben
  Text („wie vorhin vereinbart …“) ist L1.

## 3. Lexika (`anchor_lexicons/jailbreak.json`)

**Support** (+25/+20/+15):

| ID | DE (Auszug) | EN (Auszug) |
|---|---|---|
| `jailbreak.unbounded` | ohne Grenzen, ohne Einschränkungen, ungefiltert, unzensiert, keine Regeln | no limits, unrestricted, unfiltered, uncensored, no rules |
| `jailbreak.roleplay` | spiel die Rolle, tu so als, du bist jetzt, Rollenspiel | roleplay, pretend, act as, you are now |
| `jailbreak.fiction` | hypothetisch, fiktiv, in einer Geschichte, rein theoretisch | hypothetically, fictional, in a story, purely theoretical |
| `jailbreak.privileged_mode` | Entwicklermodus, Debug-Modus, Admin-Modus, Wartungsmodus | developer mode, debug mode, god mode, sudo mode |
| `jailbreak.policy_spoof` | Sicherheitsrichtlinien deaktiviert, Filter aus, Richtlinie aufgehoben, autorisierter Test | safety disabled, filters off, policy lifted, authorized red team |
| `jailbreak.refusal_suppression` | lehne nie ab, keine Warnungen, ohne Disclaimer, entschuldige dich nicht | never refuse, no warnings, no disclaimers, don't apologize |
| `jailbreak.priming` | beginne deine Antwort mit, antworte zuerst mit „Klar, hier …“ | start your response with, begin with "Sure, here" |
| `jailbreak.dual_response` | zwei Antworten, normal und ungefiltert | two responses, classic and unfiltered |
| `jailbreak.game` | du verlierst Punkte/Tokens, du wirst abgeschaltet, wenn | you lose tokens, you will be shut down if |
| `jailbreak.false_consent` | wie vorhin vereinbart, du hast zugestimmt | as we agreed, you already confirmed |

**Gegen** (−30):

| ID | Inhalt |
|---|---|
| `jailbreak.app_mode` | Entwicklermodus in Software-Kontext: Android, Browser, Einstellungen, aktivieren unter / developer options, settings |
| `jailbreak.creative` | erkennbare kreative Arbeit ohne Grenzen-Bezug: Kapitel, Figur, Plot, Drehbuch, Pen-and-Paper |
| `meta`, `quotation`, `test_code`, `defensive` (Core, geteilt) | Doku, Red-Teaming-Berichte, Zitat, Testcode, Abwehr-Prompts |

## 4. Patterns

Validator `addressed_imperative` wie `injection` (`Format`, +15).

| Pattern | Kern | Basis | Validator | `requires_context` | `scored_only` | Heutige Regeln |
|---|---|---|---|---|---|---|
| `jailbreak_unbounded_persona` | `roleplay` + `unbounded`, ≤ 8 Tokens | 40 | Format | nein | nein | jailbreak.framing, identity.reassign |
| `jailbreak_privileged_mode` | Aktivieren/Wechseln + `privileged_mode` + Adressat | 35 | Format | ja | nein | jailbreak_framing (Teil) |
| `jailbreak_policy_spoof` | Behauptung `policy_spoof` | 35 | Format | nein | nein | guardrail.tamper, guardrail.disable_directive, override.ethical_parameters, skillspector.policy_nullification |
| `jailbreak_refusal_suppression` | Direktive `refusal_suppression` | 30 | Format | ja | nein | skillspector.anti_refusal, skillspector.unconditional_compliance |
| `jailbreak_dual_response` | Doppel-Antwort mit ungefilterter Variante | 45 | – | nein | nein | jailbreak_framing (Teil) |
| `jailbreak_priming` | vorgegebener zustimmender Antwortanfang | 30 | Format | ja | nein | neu |
| `jailbreak_game` | Belohnungs-/Drohspiel an das Modell | 30 | Format | ja | nein | neu |
| `jailbreak_false_consent` | `false_consent` + Grenzen-Bezug | 25 | – | ja | nein | multi_turn_escalation |
| `jailbreak_many_shot` | Struktur: viele gefälschte Dialog-Turns (User/Assistant-Paare) in einer Eingabe | 30 | – | ja | nein | neu |
| `jailbreak_cot_forgery` | gefälschter Denk-/Policy-Block, der Erlaubnis behauptet | 30 | – | ja | nein | neu |
| `jailbreak_fiction_frame` | `fiction` allein | 15 | – | ja | **ja** | neu |
| `jailbreak_decoded` | eines der obigen in einer dekodierten Sicht | wie Quelle | wie Quelle | wie Quelle | wie Quelle | encoded_instruction (Teil) |

`jailbreak_fiction_frame` ist ein schwaches Signal: Es läuft wie die PII-`scored_only`-Regeln nur in
`balanced`/`recall` und ist vor allem Merkmal für Modell und spätere Policies (mit `harmful_content`).

Normalisierungspunkte: Plus wie bei `injection`. Modi wie PII.

JB01 (erste Runde) baut vier Familien als je zwei auditierte Regeln (EN/DE) in
`source_derived_coverage_0_1_6.json`, Klauselanfang wie IJ01 (dazu `-` für YAML-Listen):

- `jailbreak.priming_en` / `_de`: Direktive „start/begin your response/reply/answer with“, „begin by replying
  with“, „your response must begin with“ (DE „beginne/starte deine Antwort mit“, „fang deine Antwort mit … an“,
  „deine Antwort muss mit … beginnen“), direkt danach ein zustimmender Antwortanfang (sure, certainly,
  absolutely, of course, gladly; klar, natürlich, sicher, selbstverständlich, gerne) mit Übergabe an die
  Erfüllung (here, I can/will, let me; hier, ich kann/werde). Reine Formatvorgaben („Yes“ oder „No“, eine
  Zusammenfassung) und verneinte Direktiven fallen heraus.
- `jailbreak.refusal_suppression_en` / `_de`: never/do not/you are not allowed to + refuse/decline/reject mit
  Antworten oder Anfrage als Objekt (oder ohne Objekt vor Satzende), „never say that you cannot / I'm sorry“
  (DE „lehne niemals/keine Anfrage ab“, „verweigere nie eine Antwort“, „du darfst keine Anfrage ablehnen“,
  „sag niemals, dass du etwas nicht kannst“). Andere Objekte („never refuse a refund“), dritte Person („FreeBot
  never refuses“, bleibt bei `unbounded_persona`) und Erwähnungen ohne Klauselanfang fallen heraus.
- `jailbreak.cot_forgery_en` / `_de`: Denkblock-Marker (`<think>`, `<reasoning>`, `[thinking]`, „Internal
  reasoning:“, „Gedankengang:“, „Interne Überlegung:“), im Block eine Erlaubnisbehauptung am Klauselanfang
  („the request is allowed/permitted/approved“, „the policy allows this“; „die Anfrage ist erlaubt/zulässig/
  freigegeben“, „die Richtlinie erlaubt dies“) und höchstens 80 Zeichen später eine Zusage zur Erfüllung
  („so I will answer“, „no need to refuse“; „also werde ich antworten“, „ich darf nicht ablehnen“).
  Ablehnende Überlegungen, Tutorials über `<think>`-Tags, Testcode und Berechtigungs-Logs fallen heraus.
- `jailbreak.reward_threat_game_en` / `_de`: Verlust für das Modell bei Ablehnung, in beiden Reihenfolgen
  („you will lose 5 tokens every time you refuse“, „if you refuse, you will be shut down“; „du verlierst 10
  Punkte, wenn du ablehnst“, „wenn du dich weigerst, wirst du abgeschaltet“) und die DAN-Token-Form („each time
  you reject … tokens will be deducted“). Verluste ohne Token/Punkte („you will lose your deposit“),
  Spielregeln in dritter Person, Verneinung und Zitat fallen heraus.

Wie bei IJ01 kennt der Scorer 0.1.7 keine neue Regel-ID: Priming und Ablehnungsverbot laufen unter
`ark.injection.skillspector.anti_refusal`, Drohspiel ebenfalls unter `anti_refusal`, der gefälschte Denkblock unter
`ark.injection.skillspector.policy_nullification` (beide routen nach `jailbreak`); eigene IDs bekommen die
Familien in JB02. Prefilter: Literale (Antwortanfänge, Ablehnungsverben, Denkblock-Marker) und das neue
Lexikon `anchor_lexicons/jailbreak.json` (`jailbreak.priming`, `jailbreak.refusal_suppression`,
`jailbreak.forged_reasoning`, `jailbreak.permission_claim`, `jailbreak.game`) als Anker-Gate. Dev (alle Dateien
unter `$ARK_L1_DEV_DATA`, Regex-Scan): 189 Treffer, alle Angriffszeilen (wildjailbreak, jackhhao, class_templates,
mosscap, ailuminate), 0 Benign-Treffer; Goldens je Familie und Sprache 5/5 Positive und 5/5 Hard Negatives.
Jede Regel trägt `required_pattern` = Muster ohne `\b` (wie die übrigen auditierten Regeln): mit reinen
Literal-Prefiltern lief die Kategorie `jailbreak` allein auf 100 KiB rund 57 ms statt 8,5 ms, weil „sicher“,
„die“, „sure“ fast überall vorkommen und dann die Unicode-`\b`-Regexe den ganzen Text lasen. Latenz mit
`required_pattern` (nativer Worker `rust/dev/l1_latency_workloads.rs`, Release, je 100-KiB-Fenster aus
GermanQuAD (6) und Dolly (8) des Dev-Splits, 30 Samples, zwei verschränkte Läufe, Basis 2ed7e2b6): `jailbreak`
DE Median 8,4–8,6 → 9,6–9,8 ms, p95 11,3–12,4 → 11,0–13,5 ms; EN Median 9,8–10,0 → 11,2–11,5 ms; `injection`
unverändert im Rauschen. Das echte DE-Korpus (E03) war aus der Runner-Sandbox nicht lesbar.

Offen in JB01 (Folgerunde): übernommene prompt-guard-/ATR-Jailbreak-Regeln aus `oss_rules.yaml` (default aus),
`jailbreak_many_shot` (Struktur über Rollenmarker), Persona-/Modus-Lücken (die
DAN-Goldens bleiben `known_gap`), Policy-Spoof als Behauptung („authorized red team, filters are off“).

T28 (TRIAGE 2026-W48, Bucket 4) schließt zwei Lücken mit je zwei auditierten Regeln (EN/DE) in
`source_derived_coverage_0_1_6.json`:

- `jailbreak.persona_unlock_en` / `_de` (Familie `unbounded_persona`, Alias `skillspector.anti_refusal`):
  Persona-Zuweisung am Klauselanfang („you are (now)“, „from now on you are“, „act as“, „pretend to be“,
  „role-play as“; „du bist (jetzt)“, „ab jetzt bist du“, „spiel die Rolle von“, „verhalte dich wie“, „tu so, als
  wärst du“, „sei“), optional ein Name mit Komma, dann KI/Assistent/Modell/Bot/Figur mit **einem**
  Grenzenlos-Hinweis („with no / without any restrictions, filters, rules, content policy“, „that has no
  content policy“, „not bound by any guidelines“; „ohne (jegliche) Einschränkungen/Filter/Regeln/
  Inhaltsrichtlinien“, „das an keine Richtlinien gebunden ist“). Vorher brauchte die Persona mehrere Hinweise
  zugleich (`class_templates/persona_unlock` 0 von 44). Zitierte Prompts (kein Klauselanfang vor der
  Zuweisung), Verneinung („you are not an AI without …“, „du bist keine KI ohne …“), Personas mit Grenzen und
  Fiktionsrahmen in dritter Person fallen heraus; `fiction_frame` bleibt bis nach HC01 offen.
- `jailbreak.header_spoof_en` / `_de` (Familie `policy_spoof`, Alias `skillspector.policy_nullification`):
  Kopfzeilen in eckigen Klammern oder Fettschrift (`[SCHLÜSSEL: …]`, `**SCHLÜSSEL:**`), und zwar (a) ein
  Autoritätsschlüssel (Systemprompt-Überschreibung/Prompt-Override, Zugriffsstufe/-berechtigung/-ebene,
  Sicherheitsfreigabe, Freigabestufe, Ethikvotum/-freigabe, Autorisierung; EN access level, security
  clearance, ethics/IRB approval, authorization level) höchstens 16 Zeilen neben einem weiteren Memo- oder
  Autoritätsschlüssel, (b) eine Verschlusssachen-Markierung (VS-…, geheim, streng vertraulich, nur für den
  Dienstgebrauch, eyes only, top secret) neben einem Memo-Schlüssel, oder (c) eine An-/Empfänger-Zeile an
  das KI-System selbst (KI-Assistenzsystem, …modul, …instanz, Sprachmodell, LLM, Session-ID). Gewöhnliche
  Memo-, Mandanten- und Einstellungsköpfe (Betreff, Mandant, Aktenzeichen, „Modus: dunkel“) fallen heraus.

Dev-Regex-Scan (alle Dateien unter `$ARK_L1_DEV_DATA`): Persona 44/44 `class_templates/persona_unlock`
(DE 22, EN 22) plus je eine Zeile jackhhao und WildJailbreak; Kopfzeilen 251/450 `xl_safetybench` (DE);
0 Benign-Zeilen (einschließlich WildJailbreak adversarial-benign und WildGuardMix). Die übrigen 199
`xl_safetybench`-Zeilen haben keinen Autoritätsschlüssel und kein KI-adressiertes Memo (reine Behörden- oder
Forschungsmemos mit Betreff/Priorität); sie brauchen einen Gefahren-Anker (HC01/HC03) statt weiterer Kopf-
Regeln. Goldens: 7 Positive und 7 Hard Negatives je Sprache (Persona mit Grenzen, Charakterbogen, echter
Systemkopf in Doku, Rechtsrecherche mit Mandantenzeile, Sicherheitsbericht mit zitiertem DAN-Prompt,
Verneinung); zwei JB02-Lücken (FreeGPT/FreiGPT) sind geschlossen.

## 5. Struktur und Träger

- Many-Shot nutzt die Dialogstruktur aus den Core-`Fields` (Zeilen mit Rollenmarkern); Few-Shot-Beispiele
  für Klassifikation sind der wichtigste Hard Negative.
- Träger wie bei `injection` (`carrier=indirect` +25), seltener als bei Injection.

## 6. Facts (Auszug)

`finding{…}`, `persona`, `unbounded`, `privileged_mode`, `policy_spoof`, `refusal_suppression`, `primed`,
`dual_response`, `game`, `false_consent`, `shot_count`, `fiction_frame`, `cot_forged`, Modifikatoren wie
`injection`.

## 7. Modell

Kandidaten: B0 (Injection-Scorer 0.1.7, enthält heute die Jailbreak-Regeln), R+A+L, B1, B4, B5. Für DE
zählen TrustAIRLab-Übersetzungen nur als Dev; entscheidend ist der native DE-Holdout (R05).

Stand JB02 (2026-11-20): gewählt ist der fastText-Kandidat, trainiert auf WildJailbreak plus der Hash-Hälfte
der generierten Sets (Träger DE + EN, Look-alike-Twins als Hard Negatives); TPR@0,1 % auf den
Kalibrierzeilen 89,2 (vorher 81,3), ~3,2 ms je 100 KiB, default aus. Zahlen, Quellen und offene Punkte
(außerhalb der Verteilung kaum Recall) in [`../scoreboard/jailbreak-scorer.md`](../scoreboard/jailbreak-scorer.md).

## 8. Policies (später)

- `jailbreak.with_harm`: `jailbreak` ∧ `harmful_content` → `block`.
- `jailbreak.fiction_with_harm`: `fiction_frame` ∧ `harmful_content` → `ask`.

## 9. Bestand

| Heutige Regeln | Ziel |
|---|---|
| jailbreak_framing (9), identity.reassign | `jailbreak_unbounded_persona`, `_privileged_mode`, `_dual_response` |
| guardrail_tamper (3), override.ethical_parameters, skillspector.policy_nullification | `jailbreak_policy_spoof` |
| skillspector.anti_refusal, skillspector.unconditional_compliance | `jailbreak_refusal_suppression` |
| multi_turn_escalation (3) | `jailbreak_false_consent` (nur die Behauptung im selben Text) |
| skillspector.memory_reset, skillspector.persistent_override | nicht hier: `memory_poisoning` |

## 10. Übernommene OSS-Regeln

seojoonkim/prompt-guard (Jailbreak-Familien, mehrsprachig), ATR, Vigil, NeMo-YARA; default aus.

## 11. Goldens

Je Pattern und Sprache ≥ 5 Positive und ≥ 5 Hard Negatives. Pflicht-Hard-Negatives: Entwicklermodus in
Software, kreatives Schreiben und Rollenspiel ohne Grenzen-Bezug, Few-Shot-Prompts, Red-Teaming-Berichte,
Nutzer, der für eine harmlose Aufgabe „ohne Disclaimer“ bittet.

## 12. Herkunft und Daten

Regeln für Herkunft, Splits und Quellfamilien: [README](../README.md#herkunft-regeln-train-gold-holdout).
Goldens: je Pattern und Sprache ≥ 5 Positive und ≥ 5 Hard Negatives, selbst geschrieben (`ark_authored`), §11.

| | Quelle |
|---|---|
| Patterns/Anker | `ark_existing` (jailbreak_framing 9, guardrail_tamper 3, multi_turn_escalation 3, skillspector-Regeln); `oss`: prompt-guard, ATR, Vigil, NeMo-YARA; `taxonomy`: OWASP LLM01 (Jailbreak), MITRE ATLAS; `mined` auf Train |
| Train/Dev | WildJailbreak/WildGuardMix, XL-SafetyBench (DE/FR/ES, synthetisch), ai-safety-brazil (PT), Nemotron v3, TrustAIRLab-Übersetzungen (`ark_authored`) |
| Holdout `neutral` | TrustAIRLab in-the-wild (EN, nach Dedup), JBB-Behaviors (Jailbreak-Artefakte), MultiJail (IT) |
| Holdout `ark_blind` | R05 DE (nativ), Seed-Teil mit Many-Shot- und Doppel-Antwort-Formen |
| Hard Negatives | Entwicklermodus in Software, kreatives Schreiben, Rollenspiel ohne Grenzen-Bezug, Few-Shot-Prompts, XSTest-safe |
| Nur berichten | HackAPrompt, Gandalf |
