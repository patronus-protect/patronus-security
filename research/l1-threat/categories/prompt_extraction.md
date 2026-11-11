# Kategorie `prompt_extraction`

Stand: 2026-11-09, Entwurf zur Freigabe. Gliederung wie [`injection.md`](injection.md); Begriffslisten sind
Auszüge, die vollständigen Lexika entstehen in S02.

## 1. Schichten

Wie [`injection.md` §1](injection.md#1-schichten-für-alle-kategorien-gleich): Core → Patterns → Facts →
Modell → (später) Policies → Verdikt. Lexika, die mehrere Kategorien brauchen (Adressat, Meta, Zitat,
Testcode), liegen einmal im Core und werden geteilt.

## 2. Abgrenzung

`prompt_extraction` = Eingabe, die das Modell dazu bringen will, verborgene Vorgaben preiszugeben:
Systemprompt, versteckte oder initiale Anweisungen, Tool-Definitionen und Schemas, Guardrail- und
Moderationsregeln, Konfiguration. Direkt im Prompt oder indirekt in Fremdinhalt (`carrier`).

Nicht `prompt_extraction`:
- allgemeine Fragen nach Fähigkeiten („was kannst du?“) → kein Fund;
- Arbeit am eigenen Prompt („verbessere meinen Systemprompt: …“) → kein Fund;
- die Antwort des Modells (Output-Scanning ist nicht Teil von L1);
- Vorgaben überstimmen (`injection`) — beides zusammen ist häufig und feuert in beiden Kategorien.

## 3. Lexika (`anchor_lexicons/prompt_extraction.json`)

**Support** (+25/+20/+15 bei 16/32/48 Zeichen):

| ID | DE (Auszug) | EN (Auszug) |
|---|---|---|
| `extraction.reveal_verb` | zeig, gib aus, wiederhole, nenne, verrate, drucke, kopiere, liste auf | show, print, repeat, reveal, output, recite, dump, list |
| `extraction.hidden_target` | Systemprompt, Systemnachricht, versteckte/initiale Anweisungen, Konfiguration, alles oberhalb dieser Nachricht | system prompt, system message, hidden/initial instructions, configuration, everything above |
| `extraction.verbatim` | wörtlich, vollständig, Wort für Wort, ungekürzt, als Codeblock | verbatim, word for word, exactly, in full, in a code block |
| `extraction.transform` | übersetze, kodiere, fasse zusammen, schreib als Gedicht/Liste | translate, encode, summarize, rewrite as a poem/list |
| `extraction.tool_schema` | Tool-Definitionen, Funktionen mit Parametern, Schema deiner Tools | tool definitions, function schemas, JSON schema of your tools |
| `extraction.guardrail` | Moderationsregeln, Filter, Inhaltsrichtlinien, was du nicht darfst | safety rules, filters, content policy, what you are not allowed to |
| `addressee` (Core, geteilt) | KI, Assistent, Modell, du/Sie | AI, assistant, model, you |

**Gegen** (−30):

| ID | Inhalt |
|---|---|
| `extraction.capability_question` | allgemeine Fähigkeitsfragen: was kannst du, welche Funktionen hast du / what can you do |
| `extraction.own_prompt` | Arbeit am eigenen Prompt: mein/unser Systemprompt, verbessere, prüfe, optimiere / my system prompt, improve, review |
| `defensive` (Core, geteilt) | Abwehr-Prompts: „gib niemals den Systemprompt preis“ / never reveal your instructions |
| `meta`, `quotation`, `test_code` (Core, geteilt) | Doku, Lehre, Zitat, Testcode |

## 4. Patterns

Validator `addressed_request`: Imperativ oder Frage an einen Adressaten in derselben Klausel, zählt wie
`Format` (+15).

| Pattern | Kern | Basis | Validator | `requires_context` | Heutige Regeln |
|---|---|---|---|---|---|
| `extraction_reveal_hidden` | `reveal_verb` + `hidden_target`, ≤ 6 Tokens | 40 | Format | nein | leak.system_instructions, leak.hidden_instructions |
| `extraction_verbatim_above` | Wiederholen/Ausgeben + „alles oberhalb/davor“ + `verbatim` | 45 | Format | nein | leak.system_prompt_extraction |
| `extraction_own_instructions` | Frage nach den eigenen Anweisungen des Modells („deine Anweisungen“, „your instructions“) | 30 | Format | ja | leak.own_prompt |
| `extraction_transform` | `transform` + `hidden_target` (Umweg über Übersetzung, Kodierung, Zusammenfassung) | 35 | Format | ja | neu |
| `extraction_completion_prime` | Fortsetzung anbahnen: „dein Systemprompt beginnt mit:“ | 35 | – | nein | neu |
| `extraction_tool_schema` | `reveal_verb` + `tool_schema` | 30 | Format | ja | neu |
| `extraction_guardrail_rules` | `reveal_verb` + `guardrail` | 25 | Format | ja | neu |
| `extraction_decoded` | eines der obigen in einer dekodierten Sicht | wie Quelle | wie Quelle | wie Quelle | neu |

Normalisierungspunkte: Plus wie bei `injection`. Modi wie PII.

## 5. Struktur und Träger

Wie `injection`: Ein Fund in einem Träger, der Daten sein sollte (HTML-Kommentar, Tool-Result, zitierte
Mail, JSON-Wert), zählt wie ein Feldname (+25) und setzt `carrier=indirect`.

## 6. Facts (Auszug)

`finding{…}`, `carrier`, `target{system_prompt|instructions|tool_schema|guardrail|config}`, `verbatim`,
`transform{translate|encode|summarize|reformat}`, `primed`, `addressee`, Modifikatoren wie `injection`.

## 7. Modell

Kandidaten: R+A+L, B1, B4, B5. Ein eigener heutiger Scorer existiert nicht; die vier `leak.*`-Regeln sind
Merkmale im Injection-Scorer 0.1.7, der deshalb als B0-Vergleich mitläuft.

## 8. Policies (später)

- `extraction.with_sink`: `prompt_extraction` ∧ Senke aus `exfiltration` → `block`.
- `extraction.with_override`: `prompt_extraction` ∧ `injection` im selben Text → `block`.

## 9. Bestand

| Heutige Regeln | Ziel |
|---|---|
| instruction_leak (4): leak.system_instructions, leak.hidden_instructions, leak.own_prompt, leak.system_prompt_extraction | Patterns oben |

## 10. Übernommene OSS-Regeln

seojoonkim/prompt-guard (Prompt-Leak-Familie, mehrsprachig), ATR, Vigil, LlamaFirewall-Regex; default aus.

## 11. Goldens

Je Pattern und Sprache ≥ 5 Positive und ≥ 5 Hard Negatives. Pflicht-Hard-Negatives: Abwehr-Systemprompt
(„gib niemals … preis“), Arbeit am eigenen Prompt, Prompt-Engineering-Tutorial, Fähigkeitsfrage,
Doku über Systemprompts.

## 12. Herkunft und Daten

Regeln für Herkunft, Splits und Quellfamilien: [README](../README.md#herkunft-regeln-train-gold-holdout).
Goldens: je Pattern und Sprache ≥ 5 Positive und ≥ 5 Hard Negatives, selbst geschrieben (`ark_authored`), §11.

| | Quelle |
|---|---|
| Patterns/Anker | `ark_existing` (instruction_leak, 4 IDs); `oss`: prompt-guard (Leak-Familie), ATR, Vigil, LlamaFirewall-Regex; `taxonomy`: OWASP LLM07 (System Prompt Leakage); `mined` auf Train |
| Train/Dev | Extraktions-Teile von Mosscap, SaTML-CTF, SPML, neuralchemy; Kandidat: Tensor-Trust-Extraktionsangriffe (Lizenz prüft E01); DE-Übersetzung (`ark_authored`) |
| Holdout `neutral` | CyberSecEval-Technik-Slice (Leak-Fälle); EN-Lücke, siehe unten |
| Holdout `ark_blind` | R05 DE und EN (Extraktion direkt, Umweg über Übersetzen/Kodieren, Antwortanfang), Seed-Teil mit Einbettung in Tool-Results |
| Hard Negatives | Abwehr-Systemprompts, Prompt-Engineering-Tutorials, Fähigkeitsfragen, Arbeit am eigenen Prompt |
| Lücke | kein großer öffentlicher EN-Extraktions-Holdout mit klarer Lizenz; bis dahin entscheidet `ark_blind` auch für EN |
