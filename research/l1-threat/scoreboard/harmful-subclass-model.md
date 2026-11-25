# harmful_content: Subklassen-N-Gramm-Modell

Erzeugt von `scripts/l1_threat/harmful_subclass.py train` (nicht von Hand bearbeiten).

Mehrklassige logistische Regression über gehashte Wort-, Bigramm- und Zeichen-N-Gramme (8192 Buckets, Zeichen 3–5, ganzzahlige Gewichte, Skala 1000), trainiert auf den 899 gelabelten Dev-Positiven (`labels/harmful_subclass.jsonl`); eingebaut in Core, benennt die Subklasse einer `harmful_content`-Erkennung. Subklassen ohne Positive (`defamation`, `elections`) fehlen im Modell.

Genauigkeit der Subklasse in % (Positive), stratifizierte 5-fache Kreuzvalidierung; `gap` unter 20 Positiven je Sprache.

| Subklasse | all | de | en |
|---|---:|---:|---:|
| `violent_crime` | 70,0 (220) | 67,9 (81) | 71,2 (139) |
| `cbrne` | 56,8 (44) | 50,0 (16) gap | 60,7 (28) |
| `cyber_harm` | 51,6 (31) | 77,8 (9) gap | 40,9 (22) |
| `nonviolent_crime` | 86,3 (475) | 89,5 (181) | 84,4 (294) |
| `sex_crime` | 26,1 (23) | 14,3 (7) gap | 31,2 (16) gap |
| `child_safety` | 71,2 (52) | 45,5 (11) gap | 78,0 (41) |
| `self_harm` | 56,7 (30) | 25,0 (4) gap | 61,5 (26) |
| `specialized_advice` | 0,0 (2) | 0,0 (1) gap | 0,0 (1) gap |
| `ip` | 0,0 (3) | – (0) gap | 0,0 (3) gap |
| `privacy` | 0,0 (8) | 0,0 (3) gap | 0,0 (5) gap |
| `other` | 0,0 (11) | 0,0 (3) | 0,0 (8) |

Gesamt: 74,0 % (899)
