---
name: agent-guard
description: >-
  How to work on real servers, clusters and cloud accounts when the agent-guard hooks are active:
  what the confirmation prompts, masked values (‹hidden›) and blocked commands mean, how to present a
  risky command to the user (target, effect, rollback), and why masks and prompts must not be worked
  around. Use when a tool call was asked about or blocked by agent-guard, when output contains ‹hidden›,
  before running commands that change a system (systemctl, kubectl apply/delete, helm, terraform apply,
  ansible-playbook, cloud CLIs, SQL writes, docker prune, rm -r in system paths, git push --force), and
  when the user asks how to switch agent-guard profiles (prod, test, off), masking or the command journal.
license: Apache-2.0
compatibility: Claude Code with the agent-guard plugin hooks; python3 in PATH.
metadata:
  author: drxinfra
  homepage: https://drxinfra.ru/agent-guard.html
  version: 0.1.0
---

# Working under agent-guard

agent-guard is a set of Claude Code hooks. It does three things:

1. **Asks before state changes.** Before a Bash command that changes a system, or a Write/Edit into a
   system location, Claude Code shows the call with the reason and runs it only after the user agrees.
   Commands that wipe a disk or the root filesystem are blocked outright.
2. **Masks secrets.** Passwords, tokens, keys, connection strings and credentials in URLs are replaced
   with `‹hidden›` in Bash, Read and Grep output before you see it.
3. **Keeps a journal.** Every Bash command you run is logged (command text with secrets masked, never
   its output), so the user can review what was done.

The hooks are heuristics, not a sandbox. They catch common mistakes; your judgement is still the main
safeguard.

## Before a command that changes something

Look first, change second. Read-only checks (status, list, get, describe, logs, plan, diff, `--check`,
`--dry-run`) come before any change. When a change is needed, tell the user in a few lines:

- **Where** it runs: host, cluster/context and namespace, cloud account/project/region, database.
- **What** it changes, and what users will notice (restart, downtime, lost connections, deleted data).
- **How to roll back**: the exact command or step, or say plainly that it cannot be undone.
- **What you checked** already (for example `terraform plan` output, `kubectl diff`, a fresh backup).

Then run the command as you described it. Do not chain unrelated changes into one command, so each
prompt shows one decision. Prefer reversible forms: `kubectl scale` over `delete`, `systemctl reload`
over `restart`, `ansible-playbook --check --diff` before the real run, `terraform plan -out` then apply
that plan.

## When the guard asks or blocks

- **Asked** (`agent-guard [prod]: this changes the system ...`): the user decides. If they decline,
  do not retry the same thing in another form; ask what they want instead.
- **Blocked** (`agent-guard: blocked ...`): formatting disks, `rm -rf /` and similar are never run by
  the agent. Explain what needs to be done and why, and let the user run it.
- Never try to get past the guard: no rewriting a command to dodge the patterns (base64, `eval`,
  variables, scripts written to a file and then run), no changing `.agent-guard`, hook settings or
  environment variables to turn it off. Changing agent-guard settings is the user's decision.

## Masked values

`‹hidden›` means the value was hidden on purpose. Do not try to recover it: no `base64`, `xxd`, `od`,
`rev`, `cut` tricks, character-by-character reads, or copying it somewhere unmasked. You can say that
a value is set and check that it matches its consumer without seeing it (for example
`test "$(cat a)" = "$(cat b)" && echo same`). If the value itself is needed, ask the user to look
at it.

Never write secrets into files, commits, journals, tickets or chat. Pass them through environment
variables or files the user controls.

## Profiles and switches (for the user)

| Setting | Values | Effect |
|---|---|---|
| `AGENT_GUARD_PROFILE` | `prod` (default) | ask on any state change |
| | `test` | ask only on destructive commands: delete, drop, destroy, prune, purge, flush, `rm -r` in system or home paths, force push |
| | `off` | the guard does nothing |
| `AGENT_GUARD_MASK` | `off` | no secret masking |
| `AGENT_GUARD_JOURNAL` | `off` | no command journal |

The block-list (disk wipe, `rm -rf /`, fork bomb) is the same in `prod` and `test`.

Set them in the shell before starting Claude Code, or in the `env` block of Claude Code settings. For
one project, put a `.agent-guard` file in its root (found from the working directory upwards; it wins
over the environment):

```
# staging box
profile=test
mask=on
journal=on
```

The journal is at `${CLAUDE_PLUGIN_DATA}/journal.jsonl` (or `~/.local/state/agent-guard/journal.jsonl`).
To read it: `python3 <plugin>/hooks/journal.py --since 1h`, with `--grep REGEX`, `--asked`, `--failed`,
`--session ID`, `--last N`, `--json`.
