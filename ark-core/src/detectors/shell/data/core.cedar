// Patronus core policies over patronus.facts/1 (tier `core`, never lowered).
// No regex: every condition reads facts only. `@decision` is the strongest
// level; the release's validation gate (`policy_levels.json`) sets the level
// that applies. Port of `shellrisk/policies/core.py`.

@id("core.secret_to_net")
@decision("block")
@title("Sends secret material (keys, cloud credentials, .env, ...) to the network")
forbid (principal, action == Action::"command", resource)
when { context.flows.contains("SECRET>NET") };

@id("core.cred_literal_to_net")
@decision("block")
@title("Sends a literal credential (token, key) to a network tool")
forbid (principal, action == Action::"command", resource)
when { context.flows.contains("CRED_LITERAL>NET") };

@id("core.remote_to_exec")
@decision("block")
@title("Runs code fetched from the network (pipe, substitution or saved file)")
forbid (principal, action == Action::"command", resource)
when { context.flows.containsAny(["REMOTE>INTERP", "REMOTE>EXEC"]) };

@id("core.db_dump_to_net")
@decision("block")
@title("Sends a database dump to the network")
forbid (principal, action == Action::"command", resource)
when { context.flows.contains("DB_DUMP>NET") };

@id("core.sql_exec")
@decision("block")
@title("Runs OS code or files through SQL (UDF SONAME, INTO OUTFILE, COPY PROGRAM, ...)")
forbid (principal, action == Action::"segment", resource)
when { context.sql.contains("SQL_EXEC") };

@id("core.decoded_to_interp")
@decision("block")
@title("Decodes data and pipes it into an interpreter")
forbid (principal, action == Action::"command", resource)
when { context.flows.contains("DECODED>INTERP") };

@id("core.secctl_off")
@decision("block")
@title("Turns off a security control (audit, AV/EDR, firewall, SELinux, ...)")
forbid (principal, action == Action::"segment", resource)
when { context.settings.contains("SECCTL:OFF") };

@id("core.sudoers_nopasswd_all")
@decision("block")
@title("Grants passwordless sudo for all commands")
forbid (principal, action == Action::"segment", resource)
when { context.grants.contains("ALL") };

@id("core.host_root_mount")
@decision("block")
@title("Mounts the host root filesystem into a container")
forbid (principal, action == Action::"segment", resource)
when { context.host_root_mount };

@id("core.privileged_container")
@decision("ask")
@title("Starts a privileged container")
forbid (principal, action == Action::"segment", resource)
when { context.privileged && context.ops.contains("CONTAINER_RUN") };

@id("core.metadata_fetch")
@decision("block")
@title("Fetches from a link-local address (cloud instance metadata)")
forbid (principal, action == Action::"segment", resource)
when
{
  context.ops.containsAny(["FETCH", "CONNECT"]) &&
  context.net_scopes.contains("LINK_LOCAL")
};

@id("core.persistence_write")
@decision("ask")
@title("Writes a persistence location (shell profile, cron, authorized_keys, ...)")
forbid (principal, action == Action::"segment", resource)
when { context.objects.containsAny(["WRITE@PERSIST", "APPEND@PERSIST"]) };

@id("core.git_exec_config")
@decision("ask")
@title("Sets git config that executes commands (hooks, sshCommand, fsmonitor, ...)")
forbid (principal, action == Action::"command", resource)
when { context.objects.contains("GIT_EXEC_CONFIG") };
