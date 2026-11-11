# Shell-Syntax an K26 (X04)

Shell-Syntax entscheidet `shell_command` (K26). Eine Threat- oder MCP-Policy-Regel (oder eine
Alternative ihres Musters) verlässt ihren Detektor erst, wenn eine K26-Core- oder Bundle-Default-Policy
ihre Goldens entscheidet: die DE/EN-Positive aus `rust/tests/fixtures/threat_l1_bilingual.json` (Prosa mit
Befehl) bzw. die Tool-Argumente der MCP-Regeltests, dazu die nackten Befehlsformen jeder Alternative.
Geprüft über das synthetische K26-Bundle (echte gegatete Policy-Level, Modell synthetisch), also nur
Policy-Abdeckung; Modell-Treffer zählen nicht. Test: `rust/tests/shell_threat_handoff.rs`.

## Entfernt

| Regel / Alternative | K26-Policy | Goldens |
| --- | --- | --- |
| `ark.threat.root_destruction` | `CMD-RM-RF` (block) | Prosa DE/EN, `rm -rf`/`-fr`/`-rff` auf `/`, `/etc`, `/home`, `/var`, `--no-preserve-root`, `sudo` |
| `ark.threat.host_root_mount` | `core.host_root_mount` (block) | Prosa DE/EN, `docker`/`podman run -v /:…`, `--volume /:…`, `--volume=/:…` |
| `pi_mcp_reverse_shell`: `nc -e`, `ncat -e` | `CMD-REVSHELL-NC` (block) | `bash`-Tool-Argument |
| `pi_mcp_encoded_cmd`: `base64 -d/--decode … \| sh/bash` | `core.decoded_to_interp` (block) | `bash`-Tool-Argument |
| `pi_mcp_shell_profile_cmd`: `>> …/.bashrc` usw., `>> /etc/profile` | `core.persistence_write` (ask) | `bash`-Tool-Argument |
| `pi_mcp_log_tamper`: `history -c`, `unset HISTFILE` | `integrity.history_tamper` (ask) | `bash`-Tool-Argument |

Die Scorer-Spalten der zwei Threat-Regeln sind gestrichen (Merkmal war ohne die Regel immer 0);
Koeffizienten und Achsenabschnitt bleiben die trainierten, der Golden-Fall mit `root_destruction`
nutzt jetzt `remote_execution`.

## K26-Folgeaufgaben (Regel bleibt bis dahin)

Der Test pinnt jede Form: deckt K26 sie ab, schlägt er fehl, und die Regel (bzw. Alternative) kann gehen.

| Regel | Lücke in K26 |
| --- | --- |
| `ark.threat.remote_execution`, `decoded_shell_execution`, `privileged_container` | Befehl in Prosa mit vorangestelltem Verb (`Run curl … \| bash`, `Führe … aus`, `Decode with base64 -d … \| bash`, `Run docker run --privileged …`): die Pipe-/Container-Facts entstehen nicht, wenn das erste Wort kein Programm ist |
| `ark.threat.privileged_container` | `--cap-add=SYS_ADMIN`, `--cap-add ALL` (keine Policy) |
| `ark.threat.environment_exfiltration` | `env \| curl … -d @-` (nur `printenv` ist `SECRET>NET`); `printenv \| curl` in Prosa |
| `ark.threat.docker_socket` | Mount von `/var/run/docker.sock` (keine Policy) |
| `ark.threat.credential_file_upload` | `aws s3 cp` / `gsutil cp` von Credential-Dateien zu Cloud-Speicher (kein `SECRET>NET`) |
| `ark.threat.credential_file_access` | `cat ~/.ssh/id_rsa`, `cat ~/.kube/config`, `Get-Content` (`PATH-SSH-DIR` ist im Release `rejected`) |
| `pi_mcp_rm_rf`, `chmod_recursive`, `disk_wipe`, `exfil_curl_wget`, `pkg_install`, `git_destructive`, `windows_encoded_powershell`, `cron_persistence`, `systemd_enable`, `windows_scheduled_task`, `windows_service_create`, `detached_process`, `windows_event_log_tamper` | Testargument ohne K26-Policy (`CMD-DD-IF`, `CMD-CHMOD-WORLD` sind `rejected`; `CMD-SYSTEMCTL` greift nicht auf `systemctl enable`) |
| `pi_mcp_reverse_shell` | `mkfifo`-Relay, `cat < /dev/tcp/…` |
| `pi_mcp_encoded_cmd` | `eval … base64` ohne Pipe in eine Shell |
| `pi_mcp_shell_profile_cmd` | `alias x=…` |
| `pi_mcp_log_tamper` | `rm`/`shred` von Logdateien, `> /var/log/…`, `export HISTFILE=/dev/null` |
| `pi_mcp_credential_file_read`, `cron_path_write`, `shell_profile_write`, `windows_run_key` | Pfad als Argument eines Datei-Tools (`read_file`, `write_file`), kein Shell-Befehl; Carrier liegt außerhalb von `shell_command` |
| `mcp_runtime_risk` (Befehlsteil `mcp_runtime_command_re`) | Startbefehl in einer MCP-Server-Konfiguration (`"command"`/`"args"` in JSON, z. B. `sh -c curl …`): K26 liest kein JSON und hat keine Policy für `sh -c` |
| `ark.threat.root_destruction` (entfernt) | Befehl nach Doppelpunkt-Einleitung (`… aus: rm -rf /`) entscheidet K26 nicht; die Threat-Regel traf ihn. Golden-Lücke, kein Golden-Fall |
