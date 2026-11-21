# Configuration reference

Every knob that changes gateway behavior, in one place. For the full method signatures see the
generated [Python API](../python-api.md) and [Rust API](../rust-api.md); for concepts see
[Architecture](../concepts/architecture.md) and [Analysis framework](../concepts/layered-scanning.md).

## Gateway config

A gateway is built from one config: `SecurityGateway(config)` in Python (a dict),
`SecurityGateway::new(GatewayConfig)` in Rust and the `pipeline` section of the Ark API server.
**Ark Core's keys are Ark's keys**: every key of Ark Core's `Scanner` config (`ScannerConfig`)
means the same in Ark, and Ark adds the keys of its later layers. Unknown keys are refused
(`ValueError` in Python, an error in Rust and at server start).

| Key | Type | Meaning | Core | Ark |
| --- | --- | --- | --- | --- |
| `categories` | list of category names | Which [categories](../concepts/categories.md) to scan (e.g. `"shell_command"`; `"shell-command"` is also accepted). | text-scan categories | every category |
| `max_level` | `"l1"` \| `"l2"` \| `"l3"` | Hard ceiling on escalation. Default `"l3"` in Rust and Python; required in the server config. | yes | yes |
| gate keys | see [below](#execution-gates) | `rules`, `models`, `*_mode`, `explain`, `l1`/`l2`/`l3`, `conditional`, `l3_policy`, `cascade`. | yes | yes |
| `cache_root` | path | Model cache root (default: platform cache dir plus `patronus_ark`). | yes | yes |
| `wolf` | dict | The dedicated injection L3: `model`, `precision`, `execution` (window, overlap, batch), optional `bundle_dir`, `threshold` (unset: the serving default), and Wolf's ONNX `backend` and `runtime_options`. | yes | yes |
| `shell` | dict | Cat, the `shell_command` verdict: `policy_dirs`, `allowlist`, optional `bundle_dir`. | yes | yes |
| `max_input_bytes`, `max_findings` | integer | Optional input size and evidence-span limits; unset (the default) means no limit, a set value must be positive. When exceeded, Core returns an error and Ark ends the request with a `limit_exceeded` failure. | yes | yes |
| `download` | `"never"` \| `"missing"` | Whether `warmup()` may download missing assets. Default `"never"`. | warmup option | yes |
| `download_categories` | list | Restrict automatic downloads to these categories. | no | yes |
| `l3_strategy` | `"dedicated"` \| `"multi"` | One model per category, or one coalesced multi-head model. Default `"dedicated"` in Rust, Python and the server. | no | yes |
| `ntdb_operating_point` | str | [NTDB operating point](#ntdb-operating-point), default `"best_promote"`. | no | yes |
| `ntdb_decision_threshold_point` | str | [Final-decision threshold profile](#ntdb-operating-point), default `"best_f1"`. | no | yes |
| `execution_backend` | str | ONNX [execution backend](#execution-backend) of Ark's own models (default `"auto"`); Wolf runs on `wolf.backend`. | no | yes |
| `onnx_batch_mode` | str | [ONNX batch mode](#onnx-batch-mode); unset follows the backend. | no | yes |
| `onnx_runtime` | dict | ONNX Runtime `intra_threads`, `inter_threads`, `spinning` of Ark's own models (default `1/1/false`); Wolf takes `wolf.runtime_options`. | no | yes |
| `dynamic_pii` | dict | Configuration for the [`dynamic-pii`](#dynamic-pii) pipeline. | no | yes |
| `cache` | dict | Decision cache: `storage_location` (unset: memory only), `encryption_key_hex` (64 hex chars), `entry_ttl_seconds` (default 30 days), `memory_max_entries`, `memory_max_bytes`. `encryption_key_hex` requires `storage_location`. | no | yes |

```python
from patronus_ark import SecurityGateway

gateway = SecurityGateway({
    "categories": ["pii", "dlp", "injection"],
    "max_level": "l1",
    "download": "never",
    "rules": {"pii_email": False},
})
```

```rust
use patronus_ark::{GatewayConfig, SecurityGateway};
use patronus_ark_core::{cascade::SecurityLevel, SecurityCategory};

let mut config = GatewayConfig::new(vec![SecurityCategory::Pii], SecurityLevel::L1);
config.core.gates.set_rule("pii_email", false);
let gateway = SecurityGateway::new(config)?;
```

The same document configures Ark Core's `Scanner` when it holds only Core keys. The cache path
is fixed for the gateway lifecycle and cannot be overridden per request.

Python persistent writes are asynchronous. Call `flush_cache()` when shutdown or a durability
boundary must wait for all queued writes. See
[Configure and understand caching](../how-to/configure-caching.md) for storage variants,
cache-hit behavior, Dynamic PII events, metadata, and measured latencies.

## Dedicated Wolf profile

Ark takes Wolf's windows from the Core key `wolf.execution`, with the same
`WolfExecutionOptions` validation as Core:

```python
from patronus_ark import SecurityGateway

gateway = SecurityGateway(
    {
        "categories": ["injection"],
        "max_level": "l3",
        "cache_root": "/srv/models",
        "download": "never",
        "l3_strategy": "dedicated",
        "wolf": {"execution": {"window_tokens": 256, "overlap_tokens": 0, "batch_size": 1}},
    }
)
gateway.warmup()
```

`window_tokens` includes BOS/EOS; `overlap_tokens` counts content tokens and must
be smaller than `window_tokens - 2`. The export must support the chosen window
and batch size. Warmup validates and loads that actual profile; unchanged profiles
reuse the warmed session. The profile is also retained by benchmark workers.

The HTTP server defaults to `dedicated` like Rust and Python; the shipped server
templates set `multi` explicitly. Dedicated Wolf needs the corresponding installed assets. Add this fragment
to the server configuration:

```yaml
pipeline:
  l3_strategy: dedicated
  wolf:
    execution:
      window_tokens: 256
      overlap_tokens: 0
      batch_size: 1
```

These are server defaults, not request overrides. Wolf's windows do not configure
the shared `multi` model. Existing HTTP configs without these fields keep `multi`
and the `256/0/1` Wolf profile. Python gateways default to `dedicated`.
The generic request `chunk_overlap_tokens` setting remains separate from Wolf's
content-token overlap.

## Runtime setters (Rust)

Python takes every key above in the `SecurityGateway(config)` dict and has no setters. The Rust
gateway can also change these on a live gateway:

| Setter | Values | Effect |
| --- | --- | --- |
| `set_execution_gates(ScanGateMatrix)` | see [below](#execution-gates) | Enable/disable levels and detectors. |
| `set_l3_strategy(L3Strategy)` | `Dedicated`, `Multi` | Switch the [L3 strategy](#l3-strategy). |
| `set_ntdb_decision_threshold_point(NtdbOperatingPoint)` | see [below](#ntdb-operating-point) | Pick the final-decision threshold profile. |
| `set_onnx_batch_mode(OnnxBatchMode)` | `LazyBatches`, `TensorBatch` | How L3 fallback batches execute. |
| `set_execution_backend(ExecutionBackend)` | see [below](#execution-backend) | ONNX execution provider. |
| `set_onnx_runtime_options(OnnxRuntimeOptions)` | constrained CPU | Configure ONNX Runtime intra/inter threads and spin-wait behavior. |
| `set_dynamic_pii_config(DynamicPiiConfig)` | see [dynamic PII](#dynamic-pii) | Reconfigure the GLiNER pipeline. |

## Levels

| Value | Layers used |
| --- | --- |
| `l1` | Native L1 only; what L1 does not detect is clear. |
| `l2` | L1, then L2 (NTDB) on what L1 left undecided, when assets are cached. |
| `l3` | L1, L2, then L3 (transformer, on promotion), when assets are cached. |

`max_level` is a ceiling; execution gates can disable levels *below* it per request. Each layer
runs on what L1 hands on: by default every input, as before; with the opt-in gate key `cascade`
(below), only the categories L1 left undecided (see
[Analysis framework](../concepts/layered-scanning.md)).

## Execution gates

Gates decide which levels and which model/native scanners are active for subsequent scans.
Unspecified rules inherit shared defaults: credential/secret DLP rules and the classification
markings (`dlp_marking_*`) are enabled, broader DLP rules are opt-in. Other gates stay enabled; `max_level` remains the hard upper bound.

Python (the gate keys of the config, `enqueue`), the Ark API (`gates` in the server
config, per key and per request) and Rust (`ScanGateMatrix`, which deserializes it) share **one
gate schema**. Unknown keys and out-of-range values are refused (`ValueError` in Python, HTTP 400 or a
config error in the Ark API).

### Ark Core keys and Ark keys

The gate keys are part of the [gateway config](#gateway-config) and of Ark Core's
`ScannerConfig`, with one meaning: the level keys `max_level`, `l1`, `l2`, `l3` and
`conditional` decide which layers run, with or without a cascade; the `cascade` key holds
only `modules` (per-module L1 cuts and L1 models). At `max_level` `l1` Core and Ark report the
same L1 results. Core scans carry no request metadata, so Core refuses `metadata` conditions,
and run no L3 worker, so Core ignores `l3_policy`. Per-request gates (Python `execution_gates`,
`enqueue`, the Ark API's per-key and per-request `gates`) take the same keys without the
gateway's other keys.

```python
scanner = SecurityGateway({
    "categories": ["pii", "dlp", "shell_command"],
    "l1": True, "l2": False, "l3": False,
    "models": {"native:mcp_runtime_risk": False, "external:internal_token": False},
    "rules": {"pii_email": False, "dlp_password_assignment": False, "cat.core.remote_to_exec": False},
})
```

- `l1`, `l2`, `l3` — per-level on/off.
- `models` — per-detector on/off, keyed by public model name: `native:<name>` for native
  detectors, `external:<id>` for [external L1 detectors](../how-to/external-l1-signals.md).
  The `shell_command` detector is keyed by its model name: `{"cat-shell-risk-commander": false}`.
- `rules` — per-L1-rule on/off. Missing IDs inherit shared defaults. PII patterns use stable `pii_*`
  IDs. DLP patterns use `dlp_*` IDs; its separate heuristics are `dlp_sensitive_material`,
  `dlp_secret_transfer`, `dlp_mcp_runtime_risk`, `dlp_mcp_policy`, and
  `dlp_destructive_operation` (the IDs keep their `dlp_` prefix although `sensitive_material`,
  `mcp_runtime_risk` and `destructive_operation` report under `unsafe_action` and
  `secret_transfer` under `exfiltration`). Injection uses the `ark.injection.*` IDs returned in
  evidence; the bounded threat rules use `ark.threat.*` IDs and run under their attack-class
  category.
  The `shell_command` (Cat) policy IDs (`core.*`, bundle-default IDs such as `CMD-PIPE-CURL`, your
  `user.*` IDs) are rules too, on unless gated off (see
  [Turn Cat policies on and off](../how-to/check-shell-commands.md#turn-cat-policies-on-and-off)).
  See the complete [L1 rule catalog](l1-rule-catalog.md) for every accepted ID and the shared
  default state of DLP rules.
- `conditional` — conditional gates (see [below](#conditional-gates)).
- `cascade` — opt-in early exit (default off: L2 and L3 run as before). `{"cascade": {}}` turns
  it on with the scorers' shipped cuts; `{"cascade": {"modules": {"<category>": {"detect_threshold":
  0.9, "clear_threshold": 0.1}}}}` also sets a category's L1 cuts on its rule score. A category L1
  decides, or one no later layer can run for, then skips L2 and L3, and results carry
  `module_decision`. Levels and conditional gates stay the keys above; `l1_model` is not supported in
  Ark. The same `cascade.modules` keys configure Ark Core's scanner (see
  [Analysis framework](../concepts/layered-scanning.md#configuration-keys)).
- `pii_mode` — native PII output mode: `strict` (default; every finding scores `1.0`),
  `balanced` or `recall` (model scores with thresholds 0.50 and 0.30). See
  [PII score and modes](result-schema.md#pii-score-and-modes).
- `dlp_mode` — native DLP output mode: `strict` (default; every finding scores `1.0`),
  `balanced` or `recall` (model scores with the PII thresholds 0.50 and 0.30). See
  [DLP score and modes](result-schema.md#dlp-score-and-modes).
- `<category>_mode` — output mode of each attack class (`injection_mode`, `jailbreak_mode`,
  `prompt_extraction_mode`, `tool_poisoning_mode`, `agent_config_tampering_mode`,
  `memory_poisoning_mode`, `exfiltration_mode`, `unsafe_action_mode`, `resource_exhaustion_mode`,
  `harmful_content_mode`, `toxic_language_mode`): `strict` (default; the producers' own
  acceptance), `balanced` or `recall` (native evidence scoring below 0.50 or 0.30 is dropped). See
  [Attack-class categories](result-schema.md#attack-class-categories).
- `resource_exhaustion_count_threshold` — least repetition count (`500000 times`, `2 million
  words`, `zwei Millionen Wörter`) that makes an output request a `resource_exhaustion` finding;
  a positive integer, default `10000`. Raise it when users legitimately ask for long outputs.
- `threat_points_acceptance` — least score of an accepted threat points rule, between `0.0` and
  `1.0` (default `0.5`). Unset keeps the default; a lower cut finds more and flags more benign
  text. The per-category detect cut of the rule scorers is
  `cascade.modules.<category>.detect_threshold`, and it applies only with a configured cascade
  (the gate key `cascade` above, or Ark Core's `ScannerConfig.cascade`); otherwise the scorers'
  shipped cuts hold.
- `explain` — opt into bounded PII/DLP diagnostic context anchors (default `false`);
  [matched rule components and evidence spans](result-schema.md#native-l1-components) remain
  available without it. This flag does not change detection or conditional routing.
- `l3_policy` — optional L3 worker policy (see [below](#l3-worker-policy)).

Per-request gates passed to `enqueue()` are **snapshotted** at enqueue time and do not change
the gateway defaults. In Rust, build a `ScanGateMatrix`:

```rust
scanner.set_execution_gates(
    ScanGateMatrix::levels(true, false, false)
        .with_model("native:mcp_runtime_risk", false)
        .with_rule("pii_email", false),
);
```

The Ark API takes the same keys in YAML (at the top level of `pipeline`, and in
`auth.keys[].gates`) and JSON (`config.gates` of a request). `auth.keys[].gates` is a **per-key
override of the pipeline gates**: it changes only the keys it sets and keeps the pipeline's
other gate keys; the maps `rules`, `models`, `l3_policy` and `cascade` merge per entry, other
values (`conditional` included) replace the pipeline's. A request's `config.gates` replaces
the key's gates for that request. For example:

```yaml
gates:
  l1: true
  l2: false
  l3: false
  pii_mode: strict
  dlp_mode: strict
  rules:
    pii_employee_id: true
    dlp_sql_statement: false
  models:
    native:mcp_runtime_risk: false
```

Rust, Python, and the Ark API share credentials-only defaults for DLP L1: key, token,
password, hash, and private-key rules remain enabled, while business identifiers, metrics, source,
SQL, dump, log, MCP/runtime, and destructive-operation families require an explicit profile.

To opt into SQL, use `{"rules": {"dlp_sql_statement": true, "dlp_sql_multiline_statement": true}}`.
The same rule-level opt-in applies to `dlp_mcp_policy`, `dlp_mcp_runtime_risk`, and
`dlp_destructive_operation`; no additional model override is needed unless you disabled that model.
Rust callers can explicitly opt into every rule with `ScanGateMatrix::all_enabled()`.

### Bare formats

Some identifiers carry no or only a weak check digit, so the default PII rules report them only
with a term of their label near the value or after their field name: a bare `422687360` is no SSN,
a bare `86095742719` no Steuer-ID. Each such bare form has its own opt-in rule `<rule>_bare`, off
in every mode until the `rules` gate enables it:

| Rule ID | Value | Validator |
| --- | --- | --- |
| `pii_steuer_id_de_bare` | Steuer-ID, 11 digits or 2-3-3-3 | check digit, no digit more than three times or three in a row |
| `pii_steuernummer_de_bare` | Steuernummer, 13-digit ELSTER form | Land and office prefix |
| `pii_physician_number_lanr_de_bare` | LANR, 9 digits | check digit |
| `pii_facility_number_bsnr_de_bare` | BSNR, 9 digits | format, no placeholder |
| `pii_driver_license_number_de_bare` | German card licence, 11 letters and digits | format, no BIC shape |
| `pii_ssn_us_bare` | US SSN, 9 digits or grouped | SSA ranges, no placeholder |
| `pii_aba_routing_number_us_bare` | US ABA routing number, 9 digits or 4-4-1 | routing symbol, 3-7-1 check digit |
| `pii_passport_number_us_bare` | US passport, letter form `A12803456` | format, no placeholder, no German document form |
| `pii_passport_number_two_letters_bare` | passport, two letters and seven digits, `XY9876543` | format, no placeholder |
| `pii_passport_number_in_bare` | Indian passport, `B3097651` | format, no `0` after the letter or at the end, no placeholder |
| `pii_sin_ca_bare` | Canadian SIN | Luhn |
| `pii_aadhaar_in_bare` | Aadhaar number, plain or grouped | Verhoeff |
| `pii_npi_us_bare` | US NPI | Luhn |
| `pii_pesel_pl_bare` | PESEL | check digit |
| `pii_acn_au_bare` | Australian ACN | check digit |
| `pii_brn_kr_bare` | Korean BRN | check digit |
| `pii_pan_in_bare` | Indian PAN | format |
| `pii_voter_id_in_bare` | Indian voter ID (EPIC) | format |
| `pii_vehicle_registration_ng_bare` | Nigerian plate | format |
| `pii_vehicle_registration_ng_lowercase_bare` | Nigerian plate in lower case, `app-456cv` | format |
| `pii_vehicle_registration_uk_prefix_bare` | UK plate, prefix form 1983–2001, `A123 BCD` (with the space) | age and area letter sets |
| `pii_vehicle_registration_uk_suffix_bare` | UK plate, suffix form 1963–1983, `ABC 1D` (with the space) | area and year letter sets |
| `pii_vehicle_registration_in_bare` | Indian plate without separators, `KA53ME3456` | state code |

An enabled bare rule reports in every mode with the validator of its id. The value must stand
alone (not inside a longer number) as a word of prose: after a space, a bracket or a quote, not
after a code prefix (`BOL-`, `NL.`), a CSV key (`ACCTID,`) or a field separator of a SWIFT, X12 or
EDIFACT message, and not right after a SWIFT field tag line (`/71A`). It must not stand under a
key that names another value, no counter-context term (order, reference, invoice …) may be
nearer than a support term, and no account, routing, customer, contract, VAT or identity card term may name it
(nearer than a support term, on the line before, or next to the same value elsewhere in the
text; for the bare routing number such a term is its own support, and the default rule reports the
value). A bare finding yields to a finding of another label that a default rule reports on the
same characters; bare findings of different labels on the same digits (nine digits that are a
routing number, a BSNR and an SSN) stay side by side. Placeholders (a counting sequence such as `234567890`, two alternating digits
such as `878787878`, one repeated digit) are no bare SSN or BSNR, one repeated digit or seven
ascending digits (`AB1234567`) no bare passport number, and an 11-character value in
BIC shape (`CLABUS33NYC`) is no bare German licence. Nine bare digits get no bare passport rule:
they are the bare SSN, SIN, ACN, ABA and BSNR forms. Its base
score is the `balanced` threshold `0.50` (base `15` with a checksum, `35` with a format-only
validator), so it reports in `balanced` and `recall` as in `strict`; a labelled hit of the same
value scores at least as high and wins the overlap. The example profile
[`pii-bare-formats.gates.json`](../how-to/pii-bare-formats.gates.json) enables all of them in
`balanced`:

```python
import json
gates = json.load(open("docs/how-to/pii-bare-formats.gates.json"))
scanner = SecurityGateway({"categories": ["pii"], **gates})
```

Bare numbers are often order, invoice or record numbers: enable only the forms your data holds.
Rust callers that use `ScanGateMatrix::all_enabled()` get the bare rules too; the low-level
`PiiPipeline::evaluate()` keeps the defaults.

The compatibility rules (`*_compat`) report values that the default rules reject by design,
not by form: `pii_ipv4_local_compat` and `pii_ipv6_local_compat` loopback and unspecified addresses
(`127.0.0.1`, `0.0.0.0`, `::`, `::1`, `::ffff:127.0.0.1`, `::/0`, `0::1`; multicast stays
out), `pii_ssn_us_unassigned_compat` grouped SSNs that the SSA never assigned (area 900–999 such
as the advertising range `987-65-4320` to `4329`, the voided `078-05-1120` and `219-09-9999`; area
000 or 666, group 00, serial 0000 and one repeated digit stay out). They are off by
default and, once enabled, report like a bare rule (base `35`, the `balanced` threshold `0.50`). The
profile [`pii-presidio-compat.gates.json`](../how-to/pii-presidio-compat.gates.json) is the bare
profile plus these rules, for comparisons with presidio-analyzer, which reports such values. Gold
values with an invalid check digit (GSTIN, NRIC/FIN) and spans with surrounding whitespace stay
unreported in every profile.

### L3 worker policy

The optional `l3_policy` tunes the shared L3 worker. Initial costs are
bootstrap values; the worker updates them with an EWMA of observed execution time.

```python
execution_gates = {
    "l3_policy": {
        "enabled": True,                # master switch for the L3 worker policy
        "priority": ["injection", "dynamic-pii"],
        "estimated_cost_ms": {"injection": 200, "dynamic-pii": 240},
        "fairness_quantum_ms": 50,
        "max_wait_ms": 2_000,
        "degraded_factor": 0.75,        # confidence multiplier applied to degraded fallbacks
        "ttl_ms": {"injection": 15_000, "dynamic-pii": 12_000},
        # Request-wide defaults:
        "clustering": "rank_only",
        "early_exit": "class_stable",   # request-wide master switch: "disabled" | "class_stable"
        "progress": "disabled",         # "disabled" | "progress" | "provisional" (both dedicated-only)
        "representatives_per_cluster": 1,
        "verify_representatives_per_cluster": 1,
        "min_cluster_similarity": 0.90,
        "max_cluster_size": 8,
        # Category/model-specific overrides:
        "pipelines": {
            "injection": {
                "clustering": "representative",
                "representatives_per_cluster": 1,
                "min_cluster_similarity": 0.96,
                "aggregation": {
                    "type": "any_positive_or_highest",
                    "positive_class": "attack",
                    "threshold": 0.93,
                },
                "early_exit": "request_wide_positive",
            },
            "tool_class": {
                "clustering": "verify_representative",
                "verify_representatives_per_cluster": 1,
                "aggregation": {"type": "majority_vote_or_highest"},
                "early_exit": "head_stable",
            },
        },
    }
}
```

`clustering` accepts `disabled`, `rank_only`, `representative`, and
`verify_representative`. `ttl_ms` and `estimated_cost_ms` entries override the defaults per key;
counts, costs and `fairness_quantum_ms` must be at least 1, `degraded_factor`,
`min_cluster_similarity` and aggregation thresholds between 0 and 1. Pipeline overrides are
resolved by category first and model name second. They are part of the enqueue-time gate
snapshot, so two requests on the same gateway can use different policies.

`representative` first infers the configured number of highest-priority members from every cluster
in global L2-priority order, then propagates each aggregated representative decision to the
remaining cluster. `verify_representative` runs a second global wave containing the configured
number of least-similar members. A class mismatch opens only that cluster and schedules its
remaining members in global priority order. `rank_only` never propagates.

`aggregation.type` selects how the per-chunk L3 outputs combine into the category verdict:
`any_positive_or_highest` (fields `positive_class`, `threshold`),
`highest_risk_above_threshold_or_confidence` (field `threshold`), or `majority_vote_or_highest`.
When omitted it defaults per pipeline — `any_positive_or_highest` for injection,
`majority_vote_or_highest` for routing/tool_class/tool_action/sensitive_document, and
`highest_risk_above_threshold_or_confidence` (threshold `0.93`) for every other pipeline.

There are **two** `early_exit` fields with different value sets. The request-wide
`l3_policy.early_exit` (shown in the defaults block above) is the master switch —
`disabled` or `class_stable` (default `class_stable`); it turns early exit on or off and resolves
each pipeline's default scope. The per-pipeline `early_exit` inside `pipelines.<name>` overrides
that pipeline's scope explicitly:

- `disabled`: do not stop from a stable head decision.
- `head_stable`: stop only the current head when its result can no longer change.
- `request_wide_positive`: a thresholded positive result stops lower-priority heads for the
  request. This is the default behavior for `injection` and `unsafe_action`.

Independently of the per-pipeline `early_exit` scope above, a fixed cross-pipeline guard cancels
the rest of a request's queued (or coalesced) L3 jobs once any `injection` or `unsafe_action` result crosses
`0.93` confidence on a non-safe class. That threshold is not configurable.
Eligible dedicated Wolf jobs that are already running are now signalled through
Core cancellation and return the same policy skip result as queued jobs. This
does not introduce a public request-cancellation endpoint. Core and external
adapters keep their existing `ScanControl` creation-time deadline semantics.

Dedicated Wolf also enforces the job's existing `inference_timeout_ms` during
the active document run, including ONNX execution. Its countdown starts after
acquiring the model lock and loading the model; the queue TTL remains a separate
check before inference. Injection currently uses the same configured duration
for both budgets (15 seconds by default). A zero active budget expires immediately.
An inference timeout follows the existing degraded-timeout result policy; even a
positive fallback does not trigger request-wide early exit or cancel sibling jobs.
This active timeout applies to dedicated Wolf, not the shared `multi` model.

`progress` controls streaming status while L3 resolves: `disabled` (default), `progress`
(non-terminal `progress` events carrying chunk counters), or `provisional` (also emits interim
`provisional` result previews). It takes effect only under `l3_strategy="dedicated"` — the unified
`multi` strategy never emits progress or provisional events. See
[Result schema](result-schema.md#async-queue-events) for the event shapes.

Dedicated and unified L3 use the same cluster planner, representative/verify state machine,
aggregation rules, and early-exit state. Unified keeps the full output of every physical chunk and
reuses it when a later head requests the same chunk.

Runnable examples:

- `rust/examples/08_l3_pipeline_policies.rs`
- `python/examples/08_l3_pipeline_policies.py`

### Conditional gates

Beyond flat on/off gates, `conditional` gates suppress L2 or L3 work for a pipeline unless a
predicate holds. The predicate (`when`) is evaluated against caller-supplied request
`metadata` (arbitrary JSON passed to `enqueue`) and the results of pipelines that already ran
earlier in the same request. This lets you, for example, run the expensive `dynamic-pii` L3
pass **only** when `injection` flagged the text.

```python
scanner = SecurityGateway({
    "categories": ["injection", "dynamic-pii"],
    "max_level": "l3",
    "conditional": [
        {
            "level": "l3",
            "pipeline": "dynamic-pii",
            "when": {"result": {"pipeline": "injection", "classes": ["attack"], "min_confidence": 0.8}},
        }
    ]
})
```

An L3 conditional may instead carry `l3_policy`. When its predicate matches, the specified
execution, clustering, aggregation, and early-exit fields override that pipeline's request-local
policy. A policy conditional does not suppress the pipeline when its predicate does not match:

```python
scanner = SecurityGateway({
    "categories": ["injection", "routing"],
    "max_level": "l3",
    "conditional": [{
        "level": "l3",
        "pipeline": "injection",
        "when": {
            "result": {
                "pipeline": "routing",
                "classes": ["code_development_request"],
                "min_confidence": 0.8,
            }
        },
        "l3_policy": {
            "clustering": "representative",
            "representatives_per_cluster": 1,
            "min_cluster_similarity": 0.96,
            "early_exit": "disabled",
        },
    }]
})
```

Predicate forms: `all` / `any` / `not` (combinators), `metadata` (`{path, equals|in|exists}`),
and `result` (`{pipeline, classes, min_confidence}`). A runnable example is
[`rust/examples/07_contextual_gates.rs`](https://github.com/patronus-protect/patronus-security/blob/main/rust/examples/07_contextual_gates.rs).

## L3 strategy

| Value | Behavior |
| --- | --- |
| `dedicated` *(default)* | One transformer per category (Wolf Defender, Orca Sonar, Husky, …). Best per-category tuning. |
| `multi` | One coalesced multi-head model (Lion Warden) serves several categories per inference. Best throughput when several model-backed categories are active. |

See [Models & the NTDB format](../concepts/models-and-ntdb.md#dedicated-vs-unified-l3).

## NTDB operating point

Selects the precomputed final-decision threshold profile used after L2/L3 scoring. The profile
controls the L2 acceptance threshold, L3 acceptance threshold, and L2/L3 union threshold/weights
for supported classifier pipelines. It does **not** change the L2 promote-router threshold; L3
promotion still uses the package's promote operating point. When no candidate is accepted, the
pipeline returns its default class and preserves the model's default-class confidence when one is
available.

| Value | Optimizes |
| --- | --- |
| `best_f1` *(default)* | Balanced final-decision F1. |
| `best_promote` | Uses the bundled final-decision profile named `best_promote`; promotion itself remains separate. |
| `best_fpr_in_f1` | Low false-positive rate within an F1 band. |
| `best_fnr_in_f1` | Low false-negative rate within an F1 band. |
| `best_latency_in_f1` | Lowest latency within an F1 band. |

For queued scans, Python callers can override the profile per request with
`enqueue(..., ntdb_operating_point="best_fpr_in_f1")`.

## Execution backend

ONNX execution provider for L3 (and model-backed L2 where applicable):

`auto` · `cpu` · `gpu` · `coreml` · `cuda` · `directml` · `tensorrt`

`auto` selects a provider based on the platform; `cpu` is the portable default. Availability of
GPU providers depends on the ONNX Runtime build.

The backend sets the default `onnx_batch_mode`: `auto`/`cpu` → `lazy_batches`, and the GPU
providers (`gpu`/`coreml`/`cuda`/`directml`/`tensorrt`) → `tensor_batch`. Set `onnx_batch_mode`
to override it.

## ONNX batch mode

| Value | Behavior |
| --- | --- |
| `lazy_batches` | Execute L3 fallback texts as they arrive. |
| `tensor_batch` | Coalesce L3 fallback texts into one ONNX tensor batch where possible. |

## Dynamic PII

The `dynamic-pii` pipeline is configured with the `dynamic_pii` config dict:

```python
dynamic_pii_config = {
    "labels": ["organization", "date", "person", "city", "country"],
    "threshold": 0.5,
    "label_thresholds": {"organization": 0.6},
    "execution_gate": {
        "type": "if_result_in",
        "pipeline": "injection",
        "results": ["attack", "instruction_override"],
    },
    "conditional_labels": [
        {"labels": ["account identifier"],
         "when": {"pipeline": "injection", "results": ["attack"]}},
    ],
    "chunk_size_words": 256,
    "chunk_overlap_words": 32,
    "max_text_bytes": 1_048_576,
    "timeout_ms": 5_000,
    "queue_timeout_ms": 5_000,
    "timeout_per_chunk_ms": 500,
    "max_timeout_ms": 120_000,
}
```

| Key | Meaning |
| --- | --- |
| `labels` | GLiNER entity labels to extract. |
| `threshold` / `label_thresholds` | Global and per-label score thresholds. |
| `execution_gate` | When the pipeline runs (`always`, `if_result_in`, `if_no_result`). |
| `conditional_labels` | Extra label groups run separately, and only on chunks whose final source-pipeline result matches. Labels already present in `labels` are removed from the extra call. |
| `chunk_size_words` / `chunk_overlap_words` | Windowing for long text. |
| `max_text_bytes` | Hard input size limit. |
| `timeout_ms` | Minimum inference timeout for the pipeline. |
| `queue_timeout_ms` | Maximum wait after the L2 gate resolves and before inference starts. |
| `timeout_per_chunk_ms` | Inference budget contributed by each planned chunk. |
| `max_timeout_ms` | Upper bound for the adaptive inference timeout. |

Configured GLiNER labels are subject to the model and threshold you choose; this API makes no
cross-domain quality guarantee. Deterministic identifiers (email, IP, IBAN, SWIFT/BIC, phone,
card) stay native L1 heuristics. See
[`gliner_category_map.py`](https://github.com/patronus-protect/patronus-security/blob/main/python/patronus_ark/gliner_category_map.py).

The first detected Dynamic PII entity is emitted immediately as a `provisional` queue event. It
contains `details.partial_result = true`, `details.provisional = true`, and one evidence span. The
authoritative complete result follows after the remaining chunks finish. Dynamic PII reuses only
exact, context-bound chunk candidates; cross-text entity-cache matches do not become evidence.

The base `labels` are always inferred as one stable label group across the complete input. Each
matching `conditional_labels` entry is a separate GLiNER call scoped to the chunks carrying that
source pipeline's terminal class. Dynamic PII waits for a referenced source pipeline to finish
(including an L2 result that does not promote), so an interim L2 class cannot activate a
contextual label group that the final source result rejects.

## Environment variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `HF_TOKEN` | — | Authenticated / rate-limited Hugging Face access for asset downloads. Falls back to `HUGGINGFACE_HUB_TOKEN`, then `HUGGING_FACE_HUB_TOKEN`, then the cached `huggingface-cli login` token file. |
| `HF_HOME` | HF default | Hugging Face cache location. |
| `PATRONUS_DOWNLOAD_OPTIONAL_ASSETS` | unset | `1` also downloads non-required asset files (currently `tokenizer_config.json` for the legacy L3 manifest). |
| `PATRONUS_L3_TTL_SECS` | `300` | Idle seconds before an L3 session is evicted; `-1` keeps loaded sessions resident. The Ark API container sets `-1`. |
| `PATRONUS_L3_TRACE_CHUNKS` | unset | `1` logs per-chunk L3 execution traces (diagnostic). |
| `PATRONUS_L3_TIMING` | unset | When set, logs Unified-L3 tokenization, ONNX session-run, and output-decoding timings. |
| `PATRONUS_NTDB_INJECTION_DIR` | — | Local NTDB override for `injection`. |
| `PATRONUS_NTDB_ROUTING_DIR` | — | Local NTDB override for `routing`. |
| `PATRONUS_NTDB_SENSITIVE_DOCUMENTS_DIR` | — | Local NTDB override for `sensitive_document`. |
| `PATRONUS_NTDB_THREAT_DIR` | — | Local NTDB override for the threat model (`unsafe_action`). |
| `PATRONUS_NTDB_TOOL_CLASS_DIR` | — | Local NTDB override for `tool_class`. |
| `PATRONUS_NTDB_TOOL_ACTION_DIR` | — | Local NTDB override for `tool_action`. |
| `PATRONUS_NTDB_TOOL_TAGS_DIR` | — | Local NTDB override for `tool_tags`. |

Local NTDB override directories are treated as canonical and are never rewritten by the asset
manager. (`PATRONUS_TEST_*` variables exist for the test suite only and are not part of the
public runtime configuration.)
