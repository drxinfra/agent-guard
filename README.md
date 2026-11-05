# agent-guard

[Русская версия](README.ru.md)

Guardrails for AI agents on real servers. A Claude Code plugin by [drxinfra](https://drxinfra.ru/agent-guard.html) that works with any stack:

- **Asks before state changes.** Before a command that changes a system, Claude Code shows it with the reason and runs it only after you agree, even in auto mode. Disk wipes and `rm -rf /` are blocked.
- **Masks secrets.** Passwords, tokens, keys, connection strings and credentials in URLs are replaced with `‹hidden›` in Bash, Read and Grep output before the model sees them.
- **Keeps a journal.** Every Bash command the agent runs goes to a JSON Lines journal (command with secrets masked, never its output).
- **Skill.** Tells the agent how to behave under the guard: explain the target, the effect and the rollback; never work around masks or prompts.

## Install

```
/plugin marketplace add drxinfra/agent-guard
/plugin install agent-guard@agent-guard
```

Needs `python3` (3.6+) in `PATH`. No dependencies.

## What is asked

| Area | `prod` asks | `test` asks (destructive only) |
|---|---|---|
| Services | `systemctl start/stop/restart/enable...`, `service`, `reboot`, `launchctl` | — |
| Containers | `docker/podman run, stop, restart, push`, `compose up/down` | `rm`, `rmi`, `prune`, `system prune`, `compose down -v` |
| Kubernetes | `kubectl apply/patch/scale/rollout restart/drain...`, `helm install/upgrade/rollback`, `flux reconcile` | `kubectl delete`, `helm uninstall`, `flux delete` |
| IaC | `terraform/tofu/terragrunt apply/import/taint/state mv`, `pulumi up/refresh/import`, `ansible-playbook` without `--check`, `ansible -m shell/service/copy...` | `terraform destroy`, `apply -destroy`, `state rm`, `pulumi destroy` |
| Cloud CLIs | `aws ... create-/update-/put-/stop-/modify-...`, `aws s3 cp/mv/sync`, `yc/gcloud/az ... create/update/stop/start/deploy/set...` | `aws ... delete-/terminate-/remove-...`, `aws s3 rm/rb`, `yc/gcloud/az ... delete` |
| Databases | SQL writes and DDL via `psql`, `mysql`, `sqlcmd`, `sqlite3`, `clickhouse-client`...; `pg_ctl`, `pg_restore`, `mysqladmin`; MongoDB writes; Redis `SET`, `CONFIG SET`, `SHUTDOWN` | `DROP`, `TRUNCATE`, `DELETE FROM`, `dropdb`; Mongo `drop`/`delete*`; Redis `FLUSHALL`, `FLUSHDB`, `DEL` |
| Brokers | `rabbitmqctl set_policy/add_user/stop_app...` | `purge_queue`, `delete_queue`, `reset` |
| HTTP | `curl/wget/httpie` with `POST/PUT/PATCH` or a body (Elasticsearch `_search` and the like are read-only) | `DELETE` |
| Git | — | `git push --force`, `git push -f` |
| Host | packages, users, firewall, `kill`, mounts, `crontab`, `rm`/`sed -i`/`>` in `/etc`, `/opt`, `/var`, `~`...; Write/Edit into system paths outside the project | removing packages and users, firewall flush, `lvremove`, `rm -r` and `find -delete` in system or home paths, `crontab -r` |
| agent-guard itself | changing `.agent-guard` (any profile) | same |

Always blocked (`deny`, both profiles): `mkfs`, `wipefs`, `dd of=/dev/sdX`, `rm -rf /`, fork bomb.

The full rule set with test cases is in [hooks/guard.py](hooks/guard.py) and [tests/test_guard.py](tests/test_guard.py).

## Settings

| Variable | Values |
|---|---|
| `AGENT_GUARD_PROFILE` | `prod` (default): ask on any state change; `test`: ask only on destructive commands; `off` |
| `AGENT_GUARD_MASK` | `off` disables masking |
| `AGENT_GUARD_JOURNAL` | `off` disables the journal |

Set them in the shell or in the `env` block of Claude Code settings. Per project, put `.agent-guard` in the project root (looked up from the working directory upwards); it wins over the environment:

```
profile=test
mask=on
journal=off
```

## Journal

`${CLAUDE_PLUGIN_DATA}/journal.jsonl` (fallback `~/.local/state/agent-guard/journal.jsonl`), one line per command: UTC time, session id, working directory, host, profile, masked command, exit code and interrupted flag when Claude Code reports them, failed, and whether the guard asked. Rotated at 10 MB (one old file kept), file mode 0600.

```
python3 hooks/journal.py --since 1h
python3 hooks/journal.py --grep kubectl --asked
python3 hooks/journal.py --failed --last 20 --json
```

Without `--file` the reader looks in `CLAUDE_PLUGIN_DATA`, the fallback path and `~/.claude/plugins/data/agent-guard*/`.

## Limits

- Claude Code only: the hooks use its PreToolUse/PostToolUse protocol. Other agents get nothing from this plugin.
- `python3` must be in `PATH`. Without it the hooks do not run and nothing is guarded.
- Regex heuristics, not a sandbox. An unusually written command (a script file, `eval`, base64, an alias) can slip through; run agents with least privilege and keep backups.
- With `--dangerously-skip-permissions` (bypassPermissions mode) do not rely on the confirmation prompt.
- Masking covers what goes to the model. Anything else that sees raw tool output (for example telemetry export, if your organization has enabled it) is out of scope.
- The journal sees commands that finished. A command blocked or declined at the prompt is not journaled.

## Development

```
python3 -m unittest discover -s tests
claude plugin validate . --strict
sh tools/leakcheck.sh
python3 tools/package.py
```

Licensed under Apache-2.0. See [NOTICE](NOTICE) about the names "agent-guard" and "drxinfra".
