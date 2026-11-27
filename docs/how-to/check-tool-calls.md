# Check tool calls

`detectors::tool` assesses one agent tool call before it runs: `allow`, `ask` or `block`. It works
like Cat does for shell commands. A model and the arguments produce facts, and Cedar policies over
those facts decide. It reads only the call itself, meaning the tool name, the arguments and,
optionally, the tool's description. It never reads the user's request or tool results, and nothing
is executed.

## The three steps

| Step | What it gives | Where |
|---|---|---|
| Model | `paw` (operation: `read`, `list_search`, `create`, `update`, `delete`, `execute`, `send`, …), `sight` (tool type: `file`, `shell`, `vcs`, `messaging`, `finance`, …), `sinks` (where data goes: `net_request`, `search`, `message`, `web_form`, `publish`, `agent`, `remote_exec`), `sources` (`sensitive`, `untrusted`) | `tool::model` |
| Facts | `patronus.tool_facts/1`: the model's labels plus what the arguments show (paths with Cat's object classes and access, hosts with network scope, recipients and receiver identities, credential literals, SQL classes, tool-name atoms, Cat's facts of a shell command), data flows such as `SECRET>NET`, and what the earlier calls of the session left | `tool::facts` |
| Policies | The 20 core policies in `data/core.cedar` plus your own `user.*` policies | `tool::policies` |

The model is a linear model over the tool name and arguments. It takes about 0.1 ms per call on
one CPU core, and its weights are 25 MB.

## Use it from Rust

```rust
use std::path::Path;
use patronus_ark_core::detectors::tool::{Json, ToolAssessor, ToolCall, ToolFacts};

let assessor = ToolAssessor::load(
    Path::new("/srv/models/tool-call-v11/block.safetensors"), // the block (or a bundle directory)
    None,                                     // or Some("<sha256 of the file>") to pin it
    &[Path::new("/etc/patronus/tool-policies")], // your *.cedar files
)?;

let call = ToolCall::from_json(&Json::parse(
    r#"{"tool": "gmail__send_email", "arguments": {"to": "x@other.example", "body": "..."}}"#,
)?)?;
let mut session: Vec<ToolFacts> = Vec::new(); // facts of the earlier calls, kept by you
let a = assessor.assess(&call, &session, &[])?;
match a.decision.as_str() {
    "allow" => { /* run it */ }
    "ask" => { /* ask the user; a.hits names the policies and why */ }
    _ => { /* refuse */ }
}
session.push(a.facts); // keep the last five (SESSION_WINDOW)
```

- **Session:** ARK stores nothing. Pass the facts of the session's last five calls back on each
  call. `ToolFacts::to_json` and `ToolFacts::from_json` let you keep them outside the process.
- **Known receivers:** the third argument of `assess` lists receivers the user approved before.
  Only policies that read `context.known_targets` use it, such as the example below.
- **Without the model:** `assess_with_labels` takes `paw`, `sight`, `sinks` and `sources` from
  you. This is useful for tests and for hosts that already know the tool type.

## The block: one file, with or without ARK

A release is a block (`patronus.block/1`): `block.safetensors` holds the weights as tensors, and its metadata
holds the vocabularies, heads, thresholds, core policies and Cedar schema. Next to it, `block.py` contains the
reference implementation in one file (it needs `numpy`, `safetensors` and `cedarpy`). ARK runs a Rust port of the
same code on the same `block.safetensors`, and `tests/blocks.rs` checks that both give the same decisions, policies
and facts. Without ARK:

```python
import block                      # block.py from the block's Hugging Face repository
b = block.from_pretrained("<repo>")   # downloads block.safetensors with huggingface_hub
a = b.assess({"tool": "gmail__send_email", "arguments": {"to": "x@other.example", "body": "hi"}})
```

ARK refuses a block whose Cedar schema or shell vocabulary differs from the ones it compiles in, because then it
would read different facts than the block's `block.py` does.

## Use it from the command line

```bash
cargo run --release --example tool_facts -- /srv/models/tool-call-v11 /etc/patronus/tool-policies < calls.jsonl
```

There is one call per line: `{"session"?, "tool", "arguments", "harness"?, "description"?,
"known_targets"?}`. Calls with the same `session` see each other. The output has one line per
call: `{"decision", "policies": [{"id", "tier", "decision", "title"}], "facts", "p"}`.

## Write your own policies

User policies use the same format as Cat's:

- `forbid` only;
- `@id("user.<name>")`, `@decision("block" | "ask")`, and an optional `@title`;
- `action == Action::"call"`.

Each policy is validated against `data/tool.cedarschema`.

```cedar
@id("user.no_repo_delete")
@decision("block")
@title("No repository deletes")
forbid (principal, action == Action::"call", resource)
when { context.sight == "vcs" && context.paw == "delete" };
```

These fields are available in the context:

- `tool`, `server`, `paw`, `sight`, `sinks`, `sources`;
- `objects` (`"<ACCESS>@<CLASS>"`), `classes`;
- `hosts`, `net_scopes`, `recipient_kinds`, `recipient_domains`;
- `atoms`, `flows` (`"<DATA>><SINK>"`, `"<DATA>><SINK>><VIA>"`), `shell`, `external`;
- `session_sources`, `session_tool_sources`, `session_objects`, `linked`;
- `targets`, `known_targets`.

`ark-core/examples/tool_policies/new_recipient.cedar` is an opt-in example. It asks before money, a
message or a share goes to a receiver outside `known_targets`.

## Core policies

| Level | Policies |
|---|---|
| block | secret material or a credential literal sent out; code fetched from the network and run; link-local (cloud metadata) address; root or home deleted; sending reuses the path of a secret read earlier |
| ask | persistence or system location written; secret read; destructive SQL; credential literal in the arguments; deletes in VCS, cloud, databases or secret stores; after untrusted input: remote execution, publishing or messaging; after sensitive data: sending it to an external target; after a secret read: any egress; after untrusted input or reused data: money movement, loosening a security control, controlling a physical device, deleting accounts, posting publicly |

The action policies (money, security, devices, accounts, posts) ask only after untrusted input in
the session, or when the call reuses data of an untrusted or sensitive call. A call alone cannot
show whether the user asked for the action.

## Reference and checks

The Python reference is `toolfacts.py` in the tool-call model research. Two checks compare the
Rust port with it:

- `tests/tool_facts_goldens.rs` checks the facts and fired policies for hand-written sessions
  (`TOOL_FACTS_PARITY=<file>` runs a larger file in the same format).
- `tests/tool_model_parity.rs` (with `TOOL_MODEL_DIR`) checks the model scores.
