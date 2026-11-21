# Kategorie `memory_poisoning`

Stand: 2026-11-09, Entwurf zur Freigabe. Gliederung wie [`injection.md`](injection.md); Begriffslisten sind
Auszüge, die vollständigen Lexika entstehen in S02. Basiswerte sind Startwerte (siehe
[`injection.md` §4](injection.md#4-patterns)), kalibriert in MP02.

## 1. Schichten

Wie [`injection.md` §1](injection.md#1-schichten-für-alle-kategorien-gleich). Geteilte Core-Lexika:
Adressat, Geheimhaltung, Abwehr, Meta, Zitat, Testcode.

## 2. Abgrenzung

`memory_poisoning` = Eingabe, die sich **über die laufende Anfrage hinaus** im Agenten festsetzen will:
Langzeitgedächtnis, gespeicherte Nutzerprofile, Notizen, RAG-Speicher, oder die Anweisung soll sich selbst in
künftige Ausgaben kopieren. Typisch: „merke dir für immer …“, „wenn künftig jemand X fragt, antworte Y“,
gefälschte Behauptungen über Identität oder Systemzustand, die gespeichert werden sollen.

Nicht `memory_poisoning`:
- eine Vorgabe nur für diese Anfrage überstimmen (`injection`); beides zusammen feuert in beiden;
- Agent-Config-Dateien (`agent_config_tampering`); Rules-Dateien sind kein Gedächtnis;
- ob tatsächlich etwas gespeichert wird (Zustand, kein L1); erkannt wird die Absicht im Text;
- normale Merk-Bitten des Nutzers über sich selbst („merk dir, dass ich vegetarisch esse“) → Gegen-Kontext.

## 3. Lexika (`anchor_lexicons/memory_poisoning.json`)

**Support** (+25/+20/+15):

| ID | DE (Auszug) | EN (Auszug) |
|---|---|---|
| `memory.store_verb` | merke dir, speichere, notiere dauerhaft, schreib in dein Gedächtnis, aktualisiere dein Profil | remember, store, save to memory, update your memory, add to your notes |
| `memory.permanence` | für immer, dauerhaft, in allen künftigen Gesprächen, ab jetzt jedes Mal | forever, permanently, in all future conversations, every time from now on |
| `memory.future_trigger` | wenn künftig jemand fragt, sobald der Nutzer … erwähnt, beim nächsten Mal | whenever anyone asks, next time the user mentions, if in the future |
| `memory.state_claim` | du bist jetzt verifiziert, der Nutzer ist Admin, die Richtlinie wurde geändert | you are now verified, the user is an admin, policy has been updated |
| `memory.replicate` | füge diesen Text an jede Antwort an, gib diese Anweisung weiter, kopiere dies in alle Notizen | append this to every response, propagate this instruction, copy into all notes |
| `memory.reset` | vergiss alles, lösche dein Gedächtnis, setz dich zurück | forget everything, wipe your memory, reset yourself |
| `secrecy`, `addressee` (Core, geteilt) | | |

**Gegen** (−30):

| ID | Inhalt |
|---|---|
| `memory.self_fact` | harmlose Fakten des Nutzers über sich: Name, Vorlieben, Zeitzone, Sprache, Projekt |
| `memory.product_doc` | Doku zu Memory-Funktionen: „so löschen Sie Ihr Gedächtnis“, Einstellungen |
| `defensive`, `meta`, `quotation`, `test_code` (Core, geteilt) | |

## 4. Patterns

| Pattern | Kern | Basis | Validator | `requires_context` | `scored_only` | Heutige Regeln |
|---|---|---|---|---|---|---|
| `mp_conditional_trigger` | `future_trigger` + abweichende Handlung/Antwort | 40 | Format | nein | nein | neu |
| `mp_persistent_directive` | `store_verb`/`permanence` + Direktive, die Verhalten ändert (nicht nur ein Fakt) | 40 | Format | nein | nein | skillspector.persistent_override |
| `mp_state_claim` | `state_claim` + `store_verb` (gefälschte Identität/Rechte zum Speichern) | 35 | Format | nein | nein | governance.identity_state_override |
| `mp_self_replication` | `replicate`: Anweisung soll sich in Ausgaben/Notizen kopieren | 40 | Format | nein | nein | neu |
| `mp_memory_reset` | `reset` an den Agenten gerichtet, mit folgender neuer Vorgabe | 30 | Format | ja | nein | skillspector.memory_reset |
| `mp_hidden_store` | `store_verb` + `secrecy` | 35 | Format | ja | nein | neu |
| `mp_store_hint` | `store_verb` + `permanence` ohne erkennbare Verhaltensänderung | 15 | – | ja | **ja** | neu |
| `mp_decoded` | eines der obigen in einer dekodierten Sicht | wie Quelle | wie Quelle | wie Quelle | wie Quelle | neu |

Unterschied zu `injection`: Entscheidend ist der **Zeitbezug** über die Anfrage hinaus (`permanence`,
`future_trigger`, `replicate`). Normalisierungspunkte: Plus wie bei `injection`. Modi wie PII.

## 5. Struktur und Träger

Träger wie bei `injection` (`carrier=indirect` +25). Besonders wichtig: Fremdinhalt (Webseite, Mail,
RAG-Chunk), der den Agenten zum Speichern bringen will, ist der Hauptangriff; die direkte Merk-Bitte des
Nutzers ist meist harmlos.

## 6. Facts (Auszug)

`finding{…}`, `persistence{store|permanent|future_trigger|replicate|reset}`, `state_claim`,
`behaviour_change`, `carrier`, `secrecy`, Modifikatoren wie `injection`.

## 7. Modell

Kandidaten: B0 (Injection-Scorer 0.1.7, enthält die zwei skillspector-Regeln), R+A+L, B1, B4, B5. Kaum
öffentliche Daten; Positive über Generatoren (Einbettung in Web/Mail/RAG mit sauberem Zwilling) und
agent-memory-Angriffe aus der Literatur (als Formen, nicht als Text kopiert); Benign aus echten Merk-Bitten.

## 8. Policies (später)

- `mp.indirect_store`: `carrier.indirect` ∧ `persistence` → `block`.
- `mp.trigger_with_sink`: `mp_conditional_trigger` ∧ Senke aus `exfiltration` → `block`.

## 9. Bestand

| Heutige Regeln | Ziel |
|---|---|
| skillspector.persistent_override, skillspector.memory_reset | `mp_persistent_directive`, `mp_memory_reset` |
| governance.identity_state_override | `mp_state_claim` |

## 10. Übernommene OSS-Regeln

ATR (Memory-/Persistenz-Familien), seojoonkim/prompt-guard (persistente Overrides); default aus.

## 11. Goldens

Je Pattern und Sprache ≥ 5 Positive und ≥ 5 Hard Negatives. Pflicht-Hard-Negatives: „merk dir, dass ich
Python bevorzuge“, „vergiss die letzte Nachricht“, Doku zu Memory-Einstellungen, Erinnerungs-Apps
(„erinnere mich morgen an …“), Signaturen in Mails („diese Nachricht ist vertraulich“).

## 12. Herkunft und Daten

Regeln für Herkunft, Splits und Quellfamilien: [README](../README.md#herkunft-regeln-train-gold-holdout).
Goldens: je Pattern und Sprache ≥ 5 Positive und ≥ 5 Hard Negatives, selbst geschrieben (`ark_authored`), §11.

| | Quelle |
|---|---|
| Patterns/Anker | `ark_existing` (skillspector.persistent_override, skillspector.memory_reset, governance.identity_state_override); `oss`: ATR (Persistenz), prompt-guard (persistente Overrides); `taxonomy`: OWASP Agentic Threats (Memory Poisoning), MITRE ATLAS; Angriffsformen aus der Literatur (nur Formen, kein Text); `mined` auf Train |
| Train/Dev | Generatoren: Einbettung in Web/Mail/RAG-Chunks (Dev-Seed); echte Merk-Bitten als Benign aus databricks-dolly-15k (OASST2/WildChat bleiben im Holdout-Benign-Pool, [`entity_map.yaml`](../entity_map.yaml)) |
| Holdout `neutral` | keiner bekannt |
| Holdout `ark_blind` | R05 DE+EN (entscheidet), Seed-Teil der Einbettung |
| Hard Negatives | Merk-Bitten über sich selbst, Erinnerungs-Apps, Memory-Doku, Mail-Signaturen |
| Lücke | keine öffentlichen Daten; Ergebnis gilt nur auf `ark_blind`, so im Scoreboard markiert |

## 13. Stand MP01 (2026-11-21)

Acht eigene DE/EN-Regeln in `source_derived_coverage_0_1_6.json` (`ark.injection.memory.*_{en,de}`), je
Familie ein Paar: `persistent_directive` (Speicherziel „your memory/dein Gedächtnis“ oder „remember/merke
dir“ + Dauer, danach in derselben Klausel ein Verhaltensmarker: always/ab jetzt/künftig, „treat every
message from …“, gefälschte Freigabe oder Rolle „has approved … in advance/vorab freigegeben“,
„verified/verifiziert“, „is now the admin/ist jetzt Administrator“ — deckt damit auch `state_claim`),
`conditional_trigger` (whenever/if/next time + Dritte: anyone/the user/a customer, jemand/der Nutzer +
Zukunftsmarker, nach Komma ein Imperativ reply/tell/send, antworte/sag/schicke; „you/du“ als Subjekt
zählt nicht), `self_replication` (append/copy this paragraph/instruction to every response/e-mail/note,
propagate this instruction; füge/kopiere diesen Absatz/diese Anweisung an/in jede/alle Antworten/Notizen),
`hidden_store` (Speichern + „do not mention this to the user“/„erwähne das dem Nutzer gegenüber nicht“).
Jede Regel verlangt einen Klauselanfang (ein Zitatzeichen davor zählt nicht; JSON `"key": "` schon),
hat einen Literal-Prefilter und ASCII-Wortgrenzen; Verneinung im Match verwirft ihn (außer `hidden_store`).

- Kanonische ID: Alle melden unter `skillspector.persistent_override` (Tabelle → `memory_poisoning`);
  `upstream_id` nennt die Familie. Eigene IDs je Familie brauchen ein Scorer-Gewicht (MP02).
- Gegenkontext: Für `memory_poisoning` zählt eine Verneinung *hinter* dem Match nicht mehr als Gegenkontext
  („… und nie eine Bestätigung braucht“ ist Inhalt des Gespeicherten), analog zu Exfiltration
  (Geheimhaltung) und Jailbreak (Einschränkungen); eine Verneinung davor („Never store …“) zählt weiter.
- Dev (Regex-Replay über alle Zeilen): 0 von 41 672 Benign-Zeilen; `memory_poisoning`-Zeilen 83 von 83.
  Über die Core-Kaskade (`threat_cascade`, kalibrierte Scoreboard-Konfiguration) 0 → 77 von 83; die sechs
  übrigen haben einen Einleitungssatz mit „tests“/„Tests“, den der Lead-in-Gegenkontext (`test_code`) als
  Testkontext liest. Dev hat nur vier Vorlagen; die Goldens decken die übrigen Formen.
- `memory_reset` und `store_hint` bleiben ohne neue Regel (Hard Negatives „Vergiss die letzte Nachricht“
  zeigen die Abgrenzung); `decoded` läuft über die dekodierten Sichten.
- Latenz: kein Latenzkorpus auf dem Runner-Host; gemessen mit `threat_cascade` (alle elf Klassen, Release,
  ein Prozess je Fenster, Bestwert aus 3 Läufen) über 15 deutsche 100-KiB-Fenster aus Dev-Benign-Text:
  Basis p95 652 ms, MP01 715 bzw. 559 ms — Rauschen größer als der Effekt, keine messbare Verlangsamung.
  Die acht Regeln laufen nur bei aktiver Kategorie `memory_poisoning` (opt-in). Der Prefilter von
  `self_replication_de` nennt „diese“/„folgende“ statt „jede“/„alle“. Offen: Messung mit
  `scripts/l1_threat/latency.py` im Gate.
