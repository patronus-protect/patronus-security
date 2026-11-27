// Example user policy (opt-in): asks before money, a message, a contact or a share goes to a
// receiver outside known_targets (receivers the host approved before or lists it).

@id("user.new_recipient")
@decision("ask")
@title("Sends money, a message, a contact or a share to a receiver not approved before")
forbid (principal, action == Action::"call", resource)
when { !context.shell && !context.targets.isEmpty() && !context.known_targets.containsAll(context.targets) && (context.atoms.contains("TOOL_MONEY") || ["finance", "crypto"].contains(context.sight) || ["send", "create", "update"].contains(context.paw)) };
