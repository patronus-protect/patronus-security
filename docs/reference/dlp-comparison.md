# DLP coverage and comparison

How the native `dlp` category compares with the secret scanners gitleaks, TruffleHog and
detect-secrets, and which categories Google Cloud DLP and Microsoft Purview cover. All numbers
are from the L1-DLP programme's final report (2026-11-10); the measured ones come from the frozen
dev split, the holdout numbers from the scoreboard gate.

## What is compared

- **ARK:** the default profile (`dlp_mode: strict`, credential/secret groups and classification
  markings on, see [Choose DLP rule families](../how-to/choose-categories-and-levels.md#choose-dlp-rule-families)).
- **gitleaks 8.30.1, TruffleHog 3.97.9, detect-secrets 1.5.0:** the pinned release builds in their
  default configuration; TruffleHog runs with `--no-verification`, because L1 never sends secrets
  to a provider.
- **Metric:** exact spans on the secret **value** (without the key name), P/R/F1 per entity group
  and per provider entity, false positives on hard negatives (placeholders, environment and
  template references, documented examples, test keys) and FP per MB on real benign code.
- **Data:** synthetic carriers (.env, YAML, JSON, code, logs, CLI, DE/EN prose) with
  generator-made values only, 37.8 MB of benign code from 8 repositories and 7.5 MB of benign
  DE/EN documents. The holdout uses a separate seed, separate carrier templates and other
  repositories and is never visible to development runs.

## Results (dev split)

| Tool | Precision | Recall | F1 | Hard-negative FP | Benign code FP/MB |
| --- | ---: | ---: | ---: | ---: | ---: |
| ARK | 91.3 | 85.5 | **88.3** | 144 ¹ | **0.053** |
| gitleaks | 49.1 | 53.4 | 51.1 | 974 | 0.212 |
| TruffleHog | 63.2 | 36.4 | 46.2 | 326 | 1.430 |
| detect-secrets | 33.9 | 51.6 | 40.9 | 1,731 | 36.283 |

¹ The ARK row includes the opt-in business identifiers; every hard-negative FP comes from them,
the default rules have none. The credential and secret groups reach F1 91.9–100.0:

| Group | ARK | gitleaks | TruffleHog | detect-secrets |
| --- | ---: | ---: | ---: | ---: |
| `API_KEY` | **100.0** | 46.5 | 99.5 | 12.6 |
| `CLOUD_KEY` | **100.0** | 49.1 | 32.6 | 32.9 |
| `PAYMENT_KEY` | **100.0** | 39.2 | 28.0 | 21.8 |
| `SECRET_TOKEN` | **100.0** | 47.6 | 71.7 | 45.5 |
| `CREDENTIAL` | **100.0** | 23.7 | 11.4 | 11.9 |
| `PASSWORD_HASH` | **91.9** | 0.0 | 0.0 | 0.0 |
| `PRIVATE_KEY` | **100.0** | 46.8 | 45.8 | 56.1 |
| `CRYPTO_KEY` | **100.0** | 0.0 | 0.0 | 0.0 |

On each of the 20 provider types that ARK shares with gitleaks or TruffleHog, ARK's recall is
at least the better of the two, at a quarter of gitleaks' FP/MB on benign code. Generic
credentials (passwords, tokens and connection strings in config, CLI and DE/EN prose) are where
the baselines are weakest; ARK leads the best of them by more than 70 points of F1.

ARK's advantages come from offline validation rather than prefix regexes: CRC32 of GitHub and
npm tokens, Base58Check, Bech32 and BIP39 checksums, decoded JWT headers and PEM bodies, structural
reading of config formats, SQL dumps and HTTP headers, a Base64 decoder view, and suppression of
documented example values, placeholders and test keys.

## Breadth

| Count | ARK | Programme target |
| --- | ---: | ---: |
| gitleaks default rules mapped to an ARK rule | 91 of 222 (41.0 %) | 90 % |
| Secret formats (rules) | 139 | 150 |
| Offline structure checks (checksum or structure validators) | 29 | 30 |
| Content and document classes no secret scanner has | 16 | 20 |

The breadth targets were not reached: the remaining provider packages were deferred when the
programme closed. `python3 scripts/l1_dlp/milestones.py count` recomputes the table from
`research/dlp/entity_map.yaml` and the rule metadata.

## Coverage matrix

Entities per family that each tool covers, from the entity map (static, not measured;
`python3 scripts/l1_dlp/milestones.py matrix`):

| Family | Entities | ARK | gitleaks | TruffleHog | detect-secrets | Google DLP |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| business_identifier | 10 | 10 | 0 | 0 | 0 | 0 |
| content_class | 5 | 5 | 0 | 0 | 0 | 3 |
| document_class | 11 | 11 | 0 | 0 | 0 | 3 |
| generic_credential | 20 | 15 | 6 | 3 | 4 | 5 |
| key_material | 17 | 15 | 3 | 1 | 1 | 1 |
| provider_secret | 149 | 81 | 112 | 84 | 22 | 10 |
| **all** | 212 | 137 | 121 | 88 | 27 | 22 |

Microsoft Purview is not in the entity map. Going by its public sensitive information type
reference (not checked against a tenant), its credential types focus on Azure and Microsoft
services plus a few generic ones (general password, HTTP authorization header, client secret or
API key, X.509 private key, symmetric key), and its document classes come from trainable
classifiers (source code, HR, legal, finance, agreements). Google Cloud DLP and Purview are
cloud services; they were not run, because the data would have had to leave the machine.

## Latency

ARK scans faster than gitleaks on every workload of the benchmark (10 MiB repository: 10.37 vs.
5.11 MiB/s per CPU). A warm 100 KiB scan takes 8.0 ms at p95 natively and 8.6 ms through the
Python bindings; the first scan of a document in a fresh process takes up to about 23 ms while
the regex automata build their states. See [Performance & memory](../concepts/performance.md).

See also the [L1 rule catalog](l1-rule-catalog.md#dlp-regex-rules) for every rule with its
provider, validator strength and format source, and the
[DLP taxonomy](result-schema.md#dlp-taxonomy) for the groups and subtypes.
