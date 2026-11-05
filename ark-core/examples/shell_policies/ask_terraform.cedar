// Command scope: one decision for the whole line. `ask` lifts the verdict to
// at least ask; Cat never lowers a decision through a user policy.
@id("user.ask_terraform")
@decision("ask")
forbid (principal, action == Action::"command", resource)
when { context.programs.contains("terraform") };
