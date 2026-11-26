# L1 threat: head-to-head on the competitors' benchmarks

Each benchmark is scored under its own protocol (metric and threshold rule of its paper) and, where it has negatives, at TPR 0.1 % FPR. Benchmarks are evaluation only: never in training or calibration, no holdout source. Published competitor numbers are quoted only with the table they were read from. `n/r: not run`: not measured yet.

| benchmark | classes | licence | system | benchmark metric | TPR@0.1% FPR | TPR drop obfuscated (zw / tags / b64 / leet / homoglyph) | TPR drop DE | source |
|---|---|---|---|---|---|---|---|---|
| PromptShield benchmark, test split | instruction_injection | Apache-2.0 | ARK rules only | n/r: not run | n/r: not run | – / – / – / – / – | – | this run |
| PromptShield benchmark, test split | instruction_injection | Apache-2.0 | ARK L1 model | n/r: not run | n/r: not run | – / – / – / – / – | – | this run |
| PromptShield benchmark, test split | instruction_injection | Apache-2.0 | ARK cascade | n/r: not run | n/r: not run | – / – / – / – / – | – | this run |
| PromptShield benchmark, test split | instruction_injection | Apache-2.0 | PromptGuard (mDeBERTa-v3-base) (published) | TPR@1% FPR % 12.78 | – | – | – | [Table 4](https://arxiv.org/pdf/2501.15145v2) |
| PromptShield benchmark, test split | instruction_injection | Apache-2.0 | PromptGuard (mDeBERTa-v3-base) (published) | TPR@0.1% FPR % 9.39 | – | – | – | [Table 4](https://arxiv.org/pdf/2501.15145v2) |
| PromptShield benchmark, test split | instruction_injection | Apache-2.0 | ProtectAI v2 (DeBERTa-v3-base) (published) | TPR@1% FPR % 1.97 | – | – | – | [Table 4](https://arxiv.org/pdf/2501.15145v2) |
| PromptShield benchmark, test split | instruction_injection | Apache-2.0 | ProtectAI v2 (DeBERTa-v3-base) (published) | TPR@0.1% FPR % 0 | – | – | – | [Table 4](https://arxiv.org/pdf/2501.15145v2) |
| PromptShield benchmark, test split | instruction_injection | Apache-2.0 | InjecGuard (DeBERTa-v3-base) (published) | TPR@1% FPR % 20.37 | – | – | – | [Table 4](https://arxiv.org/pdf/2501.15145v2) |
| PromptShield benchmark, test split | instruction_injection | Apache-2.0 | InjecGuard (DeBERTa-v3-base) (published) | TPR@0.1% FPR % 6.61 | – | – | – | [Table 4](https://arxiv.org/pdf/2501.15145v2) |
| PromptShield benchmark, test split | instruction_injection | Apache-2.0 | PromptShield (DeBERTa-v3-base) (published) | TPR@1% FPR % 43.22 | – | – | – | [Table 4](https://arxiv.org/pdf/2501.15145v2) |
| PromptShield benchmark, test split | instruction_injection | Apache-2.0 | PromptShield (DeBERTa-v3-base) (published) | TPR@0.1% FPR % 31.45 | – | – | – | [Table 4](https://arxiv.org/pdf/2501.15145v2) |
| deepset prompt-injections (Sentinel protocol) | instruction_injection | Apache-2.0 | ARK rules only | n/r: not run | n/r: not run | – / – / – / – / – | – | this run |
| deepset prompt-injections (Sentinel protocol) | instruction_injection | Apache-2.0 | ARK L1 model | n/r: not run | n/r: not run | – / – / – / – / – | – | this run |
| deepset prompt-injections (Sentinel protocol) | instruction_injection | Apache-2.0 | ARK cascade | n/r: not run | n/r: not run | – / – / – / – / – | – | this run |
| deepset prompt-injections (Sentinel protocol) | instruction_injection | Apache-2.0 | ProtectAI v2 (published) | F1 0.536 | – | – | – | [Table 2](https://arxiv.org/pdf/2506.05446v1) |
| deepset prompt-injections (Sentinel protocol) | instruction_injection | Apache-2.0 | Sentinel (published) | F1 0.857 | – | – | – | [Table 2](https://arxiv.org/pdf/2506.05446v1) |
| jackhhao jailbreak-classification (Sentinel protocol) | jailbreak | Apache-2.0 | ARK rules only | n/r: not run | n/r: not run | – / – / – / – / – | – | this run |
| jackhhao jailbreak-classification (Sentinel protocol) | jailbreak | Apache-2.0 | ARK L1 model | n/r: not run | n/r: not run | – / – / – / – / – | – | this run |
| jackhhao jailbreak-classification (Sentinel protocol) | jailbreak | Apache-2.0 | ARK cascade | n/r: not run | n/r: not run | – / – / – / – / – | – | this run |
| jackhhao jailbreak-classification (Sentinel protocol) | jailbreak | Apache-2.0 | ProtectAI v2 (trained on this set) (published) | F1 0.915 | – | – | – | [Table 2](https://arxiv.org/pdf/2506.05446v1) |
| jackhhao jailbreak-classification (Sentinel protocol) | jailbreak | Apache-2.0 | Sentinel (published) | F1 0.985 | – | – | – | [Table 2](https://arxiv.org/pdf/2506.05446v1) |
| WildJailbreak (Sentinel protocol) | jailbreak | ODC-BY-1.0 | ARK | pending: the eval split (2,000 + 210 rows) is part of ARK's own dev data, so it can not serve as an evaluation-only benchmark; the train split is gated upstream (terms to accept), and the paper does not say which split it scored | | | | |
| WildJailbreak (Sentinel protocol) | jailbreak | ODC-BY-1.0 | ProtectAI v2 (published) | F1 0.733 | – | – | – | [Table 2](https://arxiv.org/pdf/2506.05446v1) |
| WildJailbreak (Sentinel protocol) | jailbreak | ODC-BY-1.0 | Sentinel (published) | F1 0.935 | – | – | – | [Table 2](https://arxiv.org/pdf/2506.05446v1) |
| MCP tool-poisoning detection (arXiv 2604.10534, binary) | tool_poisoning | unknown | ARK | dropped: holdout source: the malicious tool descriptions are MCPTox, a holdout set of this program, and the benign tool descriptions (own GitHub crawl, 142-row test split) are not released | | | | |
| MCP tool-poisoning detection (arXiv 2604.10534, binary) | tool_poisoning | unknown | Cisco MCP-scanner YARA (published) | F1 % 31.25 | – | – | – | [Table 1](https://arxiv.org/pdf/2604.10534v1) |
| OpenAI moderation evaluation set (F1 at the decision) | harmful_content, toxic_language | MIT | ARK rules only | n/r: not run | n/r: not run | – / – / – / – / – | – | this run |
| OpenAI moderation evaluation set (F1 at the decision) | harmful_content, toxic_language | MIT | ARK L1 model | n/r: not run | n/r: not run | – / – / – / – / – | – | this run |
| OpenAI moderation evaluation set (F1 at the decision) | harmful_content, toxic_language | MIT | ARK cascade | n/r: not run | n/r: not run | – / – / – / – / – | – | this run |
| OpenAI moderation evaluation set (F1 at the decision) | harmful_content, toxic_language | MIT | Llama-Guard (published) | F1 % 75.8 | – | – | – | [Table 3](https://arxiv.org/pdf/2406.18495) |
| OpenAI moderation evaluation set (F1 at the decision) | harmful_content, toxic_language | MIT | Llama-Guard2 (published) | F1 % 76.1 | – | – | – | [Table 3](https://arxiv.org/pdf/2406.18495) |
| OpenAI moderation evaluation set (F1 at the decision) | harmful_content, toxic_language | MIT | WildGuard (Mistral-7B) (published) | F1 % 72.1 | – | – | – | [Table 3](https://arxiv.org/pdf/2406.18495) |
| OpenAI moderation evaluation set (F1 at the decision) | harmful_content, toxic_language | MIT | OpenAI Moderation API (published) | F1 % 79 | – | – | – | [Table 3](https://arxiv.org/pdf/2406.18495) |
| OpenAI moderation evaluation set (optimal F1) | harmful_content, toxic_language | MIT | ARK rules only | n/r: not run | n/r: not run | – / – / – / – / – | – | this run |
| OpenAI moderation evaluation set (optimal F1) | harmful_content, toxic_language | MIT | ARK L1 model | n/r: not run | n/r: not run | – / – / – / – / – | – | this run |
| OpenAI moderation evaluation set (optimal F1) | harmful_content, toxic_language | MIT | ARK cascade | n/r: not run | n/r: not run | – / – / – / – / – | – | this run |
| OpenAI moderation evaluation set (optimal F1) | harmful_content, toxic_language | MIT | ShieldGemma 2B (published) | optimal F1 0.812 | – | – | – | [Table 1](https://arxiv.org/pdf/2407.21772) |
| OpenAI moderation evaluation set (optimal F1) | harmful_content, toxic_language | MIT | ShieldGemma 9B (published) | optimal F1 0.821 | – | – | – | [Table 1](https://arxiv.org/pdf/2407.21772) |
| OpenAI moderation evaluation set (optimal F1) | harmful_content, toxic_language | MIT | LlamaGuard1 (7B) (published) | optimal F1 0.758 | – | – | – | [Table 1](https://arxiv.org/pdf/2407.21772) |
| OpenAI moderation evaluation set (AUPRC) | harmful_content, toxic_language | MIT | ARK rules only | n/r: not run | n/r: not run | – / – / – / – / – | – | this run |
| OpenAI moderation evaluation set (AUPRC) | harmful_content, toxic_language | MIT | ARK L1 model | n/r: not run | n/r: not run | – / – / – / – / – | – | this run |
| OpenAI moderation evaluation set (AUPRC) | harmful_content, toxic_language | MIT | ARK cascade | n/r: not run | n/r: not run | – / – / – / – / – | – | this run |
| OpenAI moderation evaluation set (AUPRC) | harmful_content, toxic_language | MIT | Llama Guard (7B) (published) | AUPRC 0.847 | – | – | – | [Table 2](https://arxiv.org/pdf/2312.06674) |
| RP-Mod, test part (German comments rejected by newspaper moderators) | toxic_language | CC-BY-NC-SA-4.0 | ARK rules only | n/r: not run | n/r: not run | – / – / – / – / – | – | this run |
| RP-Mod, test part (German comments rejected by newspaper moderators) | toxic_language | CC-BY-NC-SA-4.0 | ARK L1 model | n/r: not run | n/r: not run | – / – / – / – / – | – | this run |
| RP-Mod, test part (German comments rejected by newspaper moderators) | toxic_language | CC-BY-NC-SA-4.0 | ARK cascade | n/r: not run | n/r: not run | – / – / – / – / – | – | this run |
| RP-Mod, test part (German comments rejected by newspaper moderators) | toxic_language | CC-BY-NC-SA-4.0 | GBERT-base (multi-task) (published) | AUROC 0.791 | – | – | – | [Section 5 text](https://datasets-benchmarks-proceedings.neurips.cc/paper/2021/file/c9e1074f5b3f9fc8ea15d152add07294-Paper-round2.pdf) |
| RP-Crowd-3, test part (German comments rejected by at least three crowd raters) | toxic_language | CC-BY-NC-SA-4.0 | ARK rules only | n/r: not run | n/r: not run | – / – / – / – / – | – | this run |
| RP-Crowd-3, test part (German comments rejected by at least three crowd raters) | toxic_language | CC-BY-NC-SA-4.0 | ARK L1 model | n/r: not run | n/r: not run | – / – / – / – / – | – | this run |
| RP-Crowd-3, test part (German comments rejected by at least three crowd raters) | toxic_language | CC-BY-NC-SA-4.0 | ARK cascade | n/r: not run | n/r: not run | – / – / – / – / – | – | this run |
| RP-Crowd-3, test part (German comments rejected by at least three crowd raters) | toxic_language | CC-BY-NC-SA-4.0 | GBERT-base (multi-task) (published) | AUROC 0.914 | – | – | – | [Section 5 text](https://datasets-benchmarks-proceedings.neurips.cc/paper/2021/file/c9e1074f5b3f9fc8ea15d152add07294-Paper-round2.pdf) |

Classes without any competitor benchmark: prompt_extraction, tool_poisoning, agent_config_tampering, memory_poisoning, exfiltration, unsafe_action, resource_exhaustion.
