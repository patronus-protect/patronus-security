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
