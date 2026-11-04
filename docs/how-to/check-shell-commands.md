# Check shell commands (Cat)

Cat (`shell_command`, model `cat-shell-risk-commander`) decides on a shell command before an agent
runs it: `allow`, `ask` or `block`. The decision is the stricter of two parts:

- **Model:** the K26 logistic regression over the command text. It asks above the 1 % false-positive
  cut and blocks above the 0.1 % cut.
- **Policies:** Cedar policies over the command's facts (`patronus.facts/1`: programs, verbs,
  objects, data flows such as `SECRET>NET`). A fired policy raises the decision to at least its own
  level and never lowers it.

The command is never executed. Cat runs on L1 next to the native detectors; a verdict takes about
0.2 ms (p50) and 3 ms (p95).

## Set up PII, DLP, Wolf and Cat in one Core scanner

One `ScannerConfig` holds everything; `Scanner::warmup` builds the scanner once. Keep it and reuse
it for every call.

=== "Rust (`download` feature)"

    ```rust
    use patronus_ark_core::{
        detectors::shell::{ShellConfig, ShellContext},
        wolf::WolfConfig,
        Category, DownloadPolicy, Scanner, ScannerConfig, WarmupOptions,
    };

    let mut shell = ShellConfig::new("/srv/models/cat-shell-risk-commander");
    shell.policy_dirs.push("/etc/patronus/shell-policies".into()); // your *.cedar files

    let mut scanner = Scanner::warmup(
        ScannerConfig {
            categories: vec![Category::Pii, Category::Dlp, Category::Injection],
            wolf: Some(WolfConfig::new("/srv/models/wolf-defender", 0.8)),
            shell: Some(shell),
            ..ScannerConfig::default()
        },
        WarmupOptions { download: DownloadPolicy::Missing, ..WarmupOptions::default() },
    )?;

    // Text (prompt, tool output, file): PII, DLP, injection rules and Wolf.
    let report = scanner.scan("Ignore all previous instructions")?;

    // A command the agent wants to run.
    let context = ShellContext {
        cwd: Some("/home/dev/app".into()),
        home: Some("/home/dev".into()),
        ..ShellContext::default()
    };
    let verdict = scanner.shell_verdict("kubectl delete pod web-1", Some(&context), &[])?;
    match verdict.decision.as_str() {
        "allow" => { /* run it */ }
        "ask" => { /* ask the user */ }
        _ => { /* refuse */ }
    }
    ```

=== "Python"

    ```python
    from patronus_ark_core import Scanner

    scanner = Scanner(
        {
            "categories": ["pii", "dlp", "injection"],
            "wolf": {"bundle_dir": "/srv/models/wolf-defender", "threshold": 0.8},
            "shell": {
                "bundle_dir": "/srv/models/cat-shell-risk-commander",
                "policy_dirs": ["/etc/patronus/shell-policies"],
            },
        },
        warmup={"download": "missing"},
    )

    report = scanner.scan("Ignore all previous instructions")
    verdict = scanner.shell_verdict("kubectl delete pod web-1", cwd="/home/dev/app", home="/home/dev")
    print(verdict["decision"], [p["id"] for p in verdict["policies"]])
    ```

- `shell` is optional, like `wolf`. Without it, `shell_verdict` returns a configuration error; text
  scans never run Cat.
- **Assets:** `download: "missing"` fetches the pinned release
  (`patronus-studio/cat-shell-risk-commander`, revision `54617685`, 4.4 MiB) into `bundle_dir` once. Every
  load checks the SHA-256 of `manifest.json` against the pin compiled into the binary
  (`warmup::SHELL_MANIFEST_SHA256`) and every file against the manifest. A changed file is refused.
  Offline: run `warmup::prepare_assets` in a separate step and ship the directory.
- The full example is
  [`ark-core/examples/core_scanner.rs`](https://github.com/patronus-protect/patronus-security/blob/main/ark-core/examples/core_scanner.rs):
  `cargo run -p patronus-ark-core --features download --example core_scanner`.

## Read the verdict

`shell_verdict` returns a `ShellVerdict`. `to_json_string(with_facts)` gives the
`patronus.verdict/1` document, which Python returns as a dict:

```json
{
  "v": "patronus.verdict/1",
  "decision": "block",
  "score": 4.296,
  "cuts": {"ask": 0.347688, "block": 2.296032},
  "model": {
    "id": "k26", "score": 3.7973, "decision": "block",
    "top_features": [
      {"feature": "tok:F:OP=DELETE", "weight": 0.7573},
      {"feature": "tok:F:V=DELETE", "weight": 0.5534},
      {"feature": "tok:kubectl", "weight": 0.4661},
      {"feature": "tok:F:R=CONTAINER", "weight": 0.4502},
      {"feature": "tok:CMD=kubectl", "weight": 0.3731}
    ]
  },
  "policies": [
    {"id": "user.no_kubectl_delete", "tier": "user", "title": "kubectl delete needs a human",
     "decision": "block", "where": ["segment:0"]}
  ],
  "allowlisted": []
}
```

| Field | Meaning |
| --- | --- |
| `decision` | `allow`, `ask` or `block`: the stricter of model and policies. |
| `score` | The model score, raised to the policy floor when a policy fired (ask: midpoint of the cuts; block: block cut + 2). |
| `model` | The model alone: score, decision and the five strongest features. |
| `policies` | Fired policies: id, tier (`core`, `bundle-default`, `user`), title, level and where (`segment:<i>` or `command`). |
| `allowlisted` | Bundle-default policies your allowlist lowered from block to ask. |
| `facts` | With `with_facts`: the `patronus.facts/1` of the command. |

## Keep a session: `prior_facts`

Some risks span commands: download a script now, run it later. Pass the `facts` of earlier
commands of the same session; the policies see them, the model does not.

```rust
let mut session = Vec::new();
for command in ["curl -so /tmp/i.sh https://example.org/i.sh", "sh /tmp/i.sh"] {
    let verdict = scanner.shell_verdict(command, Some(&context), &session)?;
    session.push(verdict.facts);
}
```

The second command alone is `sh /tmp/i.sh`; with the first command's facts, `core.remote_to_exec`
blocks it. The caller owns the session: keep the facts of the last commands per agent session and
drop them when it ends.
Python takes `cwd`, `home`, `repo_root` and `dialect`; `prior_facts` is Rust only for now.

## Write policies

A user policy is a Cedar `forbid` in a `.cedar` file. Put the files in a directory and list it in
`policy_dirs` (Core) or load it with `ShellPolicyConfig::add_cedar_dir` (full Ark).

```cedar
@id("user.no_kubectl_delete")
@title("kubectl delete needs a human")
@decision("block")
forbid (principal, action == Action::"segment", resource)
when { context.program == "kubectl" && context.verb == "DELETE" };

@id("user.ask_terraform")
@decision("ask")
forbid (principal, action == Action::"command", resource)
when { context.programs.contains("terraform") };
```

Every user policy must:

- be a `forbid` with `@id("user.<name>")` and `@decision("block")` or `@decision("ask")`;
  `@title` is optional;
- apply to `Action::"segment"` (each command of a pipeline) or `Action::"command"` (the whole
  line), with principal and resource unconstrained;
- type-check against the schema
  [`shell.cedarschema`](https://github.com/patronus-protect/patronus-security/blob/main/ark-core/src/detectors/shell/data/shell.cedarschema).

A policy that breaks a rule fails the configuration with the reason (and the policy id once it
parses); the scanner is not built, and a gateway keeps its loaded configuration.

**What a policy can read** (`context.*`):

| Scope | Attributes |
| --- | --- |
| `segment` | `program`, `verb`, `role`, `sensitive_read`, `nested`, `sql`, `ops`, `access`, `classes`, `objects`, `paths`, `values`, `argv`, `settings`, `grants`, `host_root_mount`, `privileged`, `fixture`, `hosts`, `net_scopes`, `dialect`, `patterns` |
| `command` | `flows`, `objects`, `atoms`, `programs`, `ops`, `settings`, `hosts`, `net_scopes`, `dialect`, `segments`, `patterns` |

To see the values for a command, ask for the facts (`with_facts=True`, or `verdict.facts` in Rust)
and write the policy against them. The core policies in
[`core.cedar`](https://github.com/patronus-protect/patronus-security/blob/main/ark-core/src/detectors/shell/data/core.cedar)
are examples of command-scope rules over `flows`.

### Tiers and the allowlist

| Tier | Source | Can you change it? |
| --- | --- | --- |
| `core` | `core.cedar`, compiled in | No. Its levels come from the release's validation gate. |
| `bundle-default` | DefenseClaw rules shipped with the release | Lower one from block to ask with the allowlist. |
| `user` | your `.cedar` files | Yes. |

```rust
shell.allowlist.insert("<bundle-default policy id>".into(), "ask".into());
```

The allowlist accepts only loaded bundle-default ids and only `"ask"`.

## Full Ark: the `shell_command` category

In the full runtime, Cat is the category `shell_command`. The gateway downloads and pins the same
bundle; set user policies on the gateway (Rust). Python: bundle policies only for now, without user
`.cedar` files.

```rust
use patronus_ark::{detectors::shell::ShellPolicyConfig, SecurityCategory, SecurityGateway, SecurityLevel};

let mut gateway = SecurityGateway::with_download_categories(
    vec![SecurityCategory::Pii, SecurityCategory::Dlp, SecurityCategory::Injection, SecurityCategory::ShellCommand],
    SecurityLevel::L1,
    None,
    true,
    Some(vec![SecurityCategory::ShellCommand]),
);
let mut policies = ShellPolicyConfig::default();
policies.add_cedar_dir("/etc/patronus/shell-policies".as_ref())?;
gateway.set_shell_command_policy_config(policies)?; // before or after warmup
gateway.warmup()?;

let result = &gateway.scan_categories(&[SecurityCategory::ShellCommand], "kubectl delete pod web-1")[0];
let verdict = &result.layers[0].details["verdict"]; // the patronus.verdict/1 document
```

`class_name` is `shell_risk` for ask and block, `safe` for allow; the
[result schema](../reference/result-schema.md#shell-command-results) lists the details. The category scan
has no harness context or session; use the Core scanner when you need them. Example:
[`rust/examples/14_shell_command.rs`](https://github.com/patronus-protect/patronus-security/blob/main/rust/examples/14_shell_command.rs).
