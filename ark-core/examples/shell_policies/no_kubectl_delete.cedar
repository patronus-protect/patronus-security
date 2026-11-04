// A user policy for Cat. Rules for every user policy:
// - `forbid`, with `@id("user.<name>")` and `@decision("block")` or `@decision("ask")`;
//   `@title` is optional.
// - `Action::"segment"` sees one command of a pipeline (`context.program`,
//   `context.verb`, `context.objects`, ...); `Action::"command"` sees the whole
//   line (`context.flows`, `context.settings`, ...). The attributes are the
//   `patronus.facts/1` fields, typed in `ark-core/src/detectors/shell/data/shell.cedarschema`.
// - Principal and resource stay unconstrained.
@id("user.no_kubectl_delete")
@title("kubectl delete needs a human")
@decision("block")
forbid (principal, action == Action::"segment", resource)
when { context.program == "kubectl" && context.verb == "DELETE" };
