#!/usr/bin/env python3
"""agent-guard PreToolUse hook: asks a human before commands that change a system.

Claude Code passes the tool call as JSON on stdin. For Bash the command text is
matched against rules; for Write/Edit the target path is checked. The answer is
permissionDecision "ask" (Claude Code shows the command and the reason and runs it
only after confirmation) or "deny" (commands that wipe a disk or the root
filesystem: a human runs those outside the agent).

Profiles (env AGENT_GUARD_PROFILE or profile= in .agent-guard, see config.py):
  prod  ask on any state change (default)
  test  ask only on destructive commands (delete, drop, destroy, prune, rm -r,
        force push, purge, flush); the deny list is the same
  off   the hook does nothing

These are regex heuristics, not a sandbox. Standard library only, Python 3.6+.
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import config  # noqa: E402

I = re.I
# End of a shell word: whitespace, end, quote or a shell separator.
END = r"(?=$|[\s'\";&|)`])"
# Rest of one simple command (stops at separators and newlines).
REST = r"[^\n;&|]*?"

# Commands that are never run through the agent.
DENY = [
    ("formatting or wiping a disk",
     re.compile(r"\b(?:mkfs(?:\.\w+)?|wipefs|sgdisk\s+--zap(?:-all)?|blkdiscard)\b"
                r"|\bdd\b[^\n;|&]*\bof=/dev/(?!null\b|zero\b|stdout\b|stderr\b)", I)),
    ("deleting the root filesystem",
     re.compile(r"\brm\s+(?:-[a-zA-Z]*\s+)*-[a-zA-Z]*[rR][a-zA-Z]*\s+(?:-[a-zA-Z-]+\s+)*(?:--no-preserve-root\s+)?/(?:\*)?(?=\s|$|;|&|\|)")),
    ("fork bomb", re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:")),
]

# System locations: deleting or overwriting files there is a state change.
SYS = r"(?:/(?:etc|opt|var|srv|usr|boot|home|root|data|mnt|lib|lib64|bin|sbin)(?:/|\b)|~(?:/|\s|$)|\$HOME\b|\$\{HOME\})"

# Destructive: data or resources are deleted. Asked in prod and test.
DESTRUCTIVE = [
    ("recursive delete in a system or home location",
     re.compile(r"(?:^|[\s;&|(])(?:sudo\s+)?rm\s+(?:-\S+\s+)*-[a-zA-Z]*[rR][a-zA-Z]*\s+(?:-\S+\s+)*(?:[^\s;&|]+\s+)*?[\"']?" + SYS, I)),
    ("mass delete with find in a system or home location",
     re.compile(r"\bfind\s+(?:-[HLP]\s+)*[\"']?" + SYS + r"[^\n;|&]*\s(?:-delete\b|-exec(?:dir)?\s+(?:rm|shred|truncate)\b)", I)),
    ("shredding files", re.compile(r"(?:^|[\s;&|(])(?:sudo\s+)?shred\s", I)),
    ("Kubernetes or Helm: deleting resources",
     re.compile(r"\bkubectl\s+(?:-\S+\s+(?:\S+\s+)?)*?delete\b"
                r"|\bhelm\s+(?:-\S+\s+)*(?:uninstall|delete|del)\b"
                r"|\bflux\s+delete\b", I)),
    ("containers: removing containers, images, volumes or pruning",
     re.compile(r"\b(?:docker|podman|nerdctl)\s+(?:container\s+|image\s+|volume\s+|network\s+|system\s+|builder\s+|buildx\s+)?(?:rm|rmi|prune)\b"
                r"|\b(?:docker|podman)[\s-]compose\b" + REST + r"\bdown\b" + REST + r"\s(?:-v|--volumes|--rmi)\b", I)),
    ("Terraform/OpenTofu/Pulumi: destroying infrastructure or state",
     re.compile(r"\b(?:terraform|tofu|terragrunt)\s+(?:-\S+\s+)*(?:run-all\s+)?(?:destroy\b|apply\b" + REST + r"\s-destroy\b"
                r"|state\s+rm\b|workspace\s+delete\b)"
                r"|\bpulumi\s+(?:-\S+\s+)*(?:destroy\b|stack\s+rm\b|state\s+delete\b)", I)),
    ("cloud CLI: deleting or terminating resources",
     re.compile(r"\baws\b" + REST + r"\s(?:delete|terminate|remove|deregister|purge)-[\w-]+" + END +
                r"|\baws\b" + REST + r"\bs3\s+(?:rm|rb)\b|\baws\b" + REST + r"\bs3\s+sync\b" + REST + r"\s--delete\b"
                r"|\b(?:yc|gcloud|az)\s+(?:[a-z][\w-]*\s+){1,5}?(?:delete|remove|purge|rm|terminate)" + END, I)),
    ("git: force push", re.compile(r"\bgit\b" + REST + r"\bpush\b" + REST + r"\s(?:--force|-[a-zA-Z]*f[a-zA-Z]*)" + END)),
    ("PostgreSQL: dropping databases, roles, clusters or backups",
     re.compile(r"\b(?:dropdb|dropuser|pg_dropcluster|pg_resetwal|pg_resetxlog|pg_archivecleanup)\b"
                r"|\bpg_probackup(?:-\d+)?\s+(?:delete|del-instance)\b", I)),
    ("MySQL: dropping a database", re.compile(r"\bmysqladmin\b" + REST + r"\sdrop\b", I)),
    ("RabbitMQ: deleting or purging",
     re.compile(r"\brabbitmqctl\s+(?:-\S+\s+(?:\S+\s+)?)*(?:delete_queue|purge_queue|reset|force_reset|delete_user|delete_vhost|forget_cluster_node)\b"
                r"|\brabbitmq-queues\s+(?:\S+\s+)*?delete_member\b"
                r"|\brabbitmqadmin\s+(?:\S+\s+)*?(?:delete|purge)\b", I)),
    ("removing packages",
     re.compile(r"\b(?:apt|apt-get|aptitude)\s+(?:-\S+\s+)*(?:remove|purge|autoremove)\b"
                r"|\b(?:dnf|yum|zypper)\s+(?:-\S+\s+)*(?:remove|erase|autoremove)\b"
                r"|\brpm\s+-\S*e\S*|\bdpkg\s+(?:-r|-P|--remove|--purge)\b"
                r"|\b(?:snap|flatpak|brew)\s+(?:remove|uninstall)\b|\bpip3?\s+uninstall\b", I)),
    ("deleting users or groups", re.compile(r"\b(?:userdel|groupdel|deluser|delgroup)\b", I)),
    ("flushing firewall rules",
     re.compile(r"\b(?:iptables|ip6tables)\s+(?:-t\s+\S+\s+)?(?:-F|-X|--flush|--delete-chain)\b"
                r"|\bnft\s+(?:flush|delete)\b|\bufw\s+(?:reset|delete)\b", I)),
    ("removing volumes or partitions",
     re.compile(r"\b(?:lvremove|vgremove|pvremove|lvreduce|vgreduce)\b|\bparted\b" + REST + r"\srm\b", I)),
    ("deleting the crontab", re.compile(r"\bcrontab\s+(?:-u\s+\S+\s+)?-r\b", I)),
]

# State changes. Asked only in prod.
CHANGE = [
    ("service management or reboot",
     re.compile(r"\bsystemctl\s+(?:--\S+\s+)*(?:start|stop|restart|reload|try-restart|reload-or-restart|enable|disable|mask|unmask|kill|isolate|daemon-reload|set-property|edit|revert|link|preset)\b"
                r"|\bservice\s+\S+\s+(?:start|stop|restart|reload|force-reload)\b"
                r"|\b(?:reboot|poweroff|halt)\b|\bshutdown\s+(?:-[rhP]|now|\+)|\binit\s+[06]\b"
                r"|\blaunchctl\s+(?:load|unload|bootstrap|bootout|kickstart|enable|disable|stop|start)\b", I)),
    ("containers: run, stop, restart, push",
     re.compile(r"\b(?:docker|podman|nerdctl)\s+(?:container\s+|image\s+|volume\s+|network\s+|system\s+)?"
                r"(?:stop|kill|restart|pause|unpause|update|start|run|create|load|import|tag|push|commit|rename)\b"
                r"|\b(?:docker|podman)[\s-]compose\s+(?:-f\s+\S+\s+|-p\s+\S+\s+|--\S+\s+)*(?:down|up|restart|stop|start|rm|kill|pull|create|run)\b"
                r"|\bdocker\s+(?:swarm|service|stack|node)\s+(?:\S+\s+)*?(?:init|join|leave|create|update|rm|scale|rollback|deploy|promote|demote)\b", I)),
    ("Kubernetes and Helm: changing the cluster",
     re.compile(r"\bkubectl\s+(?:-\S+\s+(?:\S+\s+)?)*?(?:apply|create|replace|patch|edit|scale|autoscale|drain|cordon|uncordon|taint|label|annotate|set|expose|run)\b"
                r"|\bkubectl\s+(?:-\S+\s+(?:\S+\s+)?)*?rollout\s+(?:restart|undo|pause|resume)\b"
                r"|\bhelm\s+(?:-\S+\s+)*(?:install|upgrade|rollback)\b"
                r"|\bflux\s+(?:reconcile|suspend|resume|create)\b|\bkustomize\s+build\b[^\n]*\|\s*kubectl\s+apply", I)),
    ("Terraform/OpenTofu/Pulumi: changing infrastructure or state",
     re.compile(r"\b(?:terraform|tofu|terragrunt)\s+(?:-\S+\s+)*(?:run-all\s+)?(?:apply|import|taint|untaint|force-unlock|refresh"
                r"|state\s+(?:mv|push|replace-provider))\b"
                r"|\bpulumi\s+(?:-\S+\s+)*(?:up|update|refresh|import|cancel|state\s+\w+)\b", I)),
    ("Ansible: applying changes",
     re.compile(r"\bansible-playbook\b(?![^\n;|&]*--(?:check|syntax-check|list-tasks|list-hosts|list-tags)\b)"
                r"|\bansible\s+\S+\s+[^\n;|&]*-m\s+(?:\S*\.)?(?:shell|command|raw|script|service|systemd|systemd_service|file|copy|template|lineinfile|blockinfile|replace|apt|dnf|yum|package|pip|user|group|reboot|cron|mount|git|unarchive|get_url)\b", I)),
    ("cloud CLI: changing resources",
     re.compile(r"\baws\b" + REST + r"\s(?:create|update|put|stop|start|modify|run|reboot|attach|detach|associate|disassociate|authorize|revoke|add|set|import|restore|release|register|disable|enable|reset|replace|tag|untag|cancel|invoke|publish|send|copy|upload|rotate|allocate|assign|unassign|apply|change|restart|resize|promote|failover)-[\w-]+" + END +
                r"|\baws\b" + REST + r"\bs3\s+(?:mv|cp|sync|mb)\b"
                r"|\byc\s+(?!config\b|init\b)(?:[a-z][\w-]*\s+){1,5}?(?:create|update|stop|start|restart|move|relocate|attach-[\w-]+|detach-[\w-]+|add-[\w-]+|set-[\w-]+|bind|unbind|deploy|rollback|import|restore|resize|upload|cp|mv|sync)" + END +
                r"|\bgcloud\s+(?!config\b|auth\b|components\b|init\b)(?:[a-z][\w-]*\s+){1,5}?(?:create|update|stop|start|reset|resize|deploy|patch|import|restore|suspend|resume|move|cp|mv|rsync|add-[\w-]+|set-[\w-]+|attach-[\w-]+|detach-[\w-]+|enable|disable|apply)" + END +
                r"|\baz\s+(?!account\b|config\b|login\b|logout\b|extension\b|cloud\b|upgrade\b|bicep\b)(?:[a-z][\w-]*\s+){1,5}?(?:create|update|stop|start|restart|deallocate|set|add|deploy|import|restore|resize|redeploy|reimage|upload|swap|enable|disable|invoke|run-command|assign|apply|scale)" + END, I)),
    ("PostgreSQL: server management, restore or DDL tools",
     re.compile(r"\b(?:pg_ctl|pg_ctlcluster\s+\S+\s+\S+)\s+(?:-\S+\s+(?:\S+\s+)?)*(?:stop|restart|promote|reload|kill)\b"
                r"|\b(?:pg_rewind|pg_restore|createdb|createuser|pg_upgrade|pg_createcluster)\b"
                r"|\bpg_probackup(?:-\d+)?\s+(?:restore|merge|add-instance|set-config|set-backup|init)\b", I)),
    ("MySQL: server management",
     re.compile(r"\bmysqladmin\b" + REST + r"\s(?:create|shutdown|flush-\w+|kill|password|reload|refresh|start-replica|stop-replica|start-slave|stop-slave)\b", I)),
    ("RabbitMQ: policies, users, cluster",
     re.compile(r"\brabbitmqctl\s+(?:-\S+\s+(?:\S+\s+)?)*(?:stop_app|start_app|stop|set_policy|clear_policy|set_operator_policy|clear_operator_policy|set_permissions|clear_permissions|add_user|change_password|clear_password|set_user_tags|close_connection|close_all_connections|set_vm_memory_high_watermark|set_disk_free_limit|eval|add_vhost|join_cluster|update_cluster_nodes|rename_cluster_node|enable_feature_flag|set_parameter|clear_parameter|set_global_parameter|import_definitions)\b"
                r"|\brabbitmq-queues\s+(?:\S+\s+)*?(?:add_member|grow|shrink|rebalance)\b"
                r"|\brabbitmq-plugins\s+(?:enable|disable)\b"
                r"|\brabbitmqadmin\s+(?:\S+\s+)*?(?:declare|close|publish|import)\b", I)),
    ("installing or upgrading packages",
     re.compile(r"\b(?:apt|apt-get|aptitude)\s+(?:-\S+\s+)*(?:install|upgrade|dist-upgrade|full-upgrade|reinstall)\b"
                r"|\b(?:dnf|yum|zypper)\s+(?:-\S+\s+)*(?:install|update|upgrade|downgrade|reinstall)\b"
                r"|\brpm\s+(?:-\S*[iUF]\S*)\b|\bdpkg\s+(?:-i|--install)\b"
                r"|\bsudo\s+(?:-\S+\s+)*pip3?\s+install\b|\b(?:snap|flatpak)\s+install\b", I)),
    ("users, passwords and firewall",
     re.compile(r"\b(?:useradd|usermod|groupadd|groupmod|gpasswd|chpasswd|passwd|chage|visudo|adduser|addgroup)\b"
                r"|\b(?:iptables|ip6tables)\s+(?!-[LS]\b|--list\b)-\S"
                r"|\bnft\s+(?!list\b)(?:add|insert|replace|create|-f)\b"
                r"|\bfirewall-cmd\s+(?:\S+\s+)*?--(?:add|remove|reload|permanent|set|zone=\S+\s+--(?:add|remove))"
                r"|\bufw\s+(?:allow|deny|reject|limit|enable|disable|insert)\b", I)),
    ("mass delete with find",
     re.compile(r"\bfind\b[^\n;|&]*\s(?:-delete\b|-exec(?:dir)?\s+(?:rm|shred|truncate)\b)", I)),
    ("killing processes", re.compile(r"(?:^|[\s;&|(])(?:kill|pkill|killall)\s+(?!-l\b|-0\b)", I)),
    ("disks and mounts",
     re.compile(r"\b(?:fdisk|parted|gdisk|sfdisk|lvextend|lvresize|lvcreate|vgextend|resize2fs|xfs_growfs|tune2fs|swapoff|swapon|umount)\b"
                r"|\bmount\s+(?:-[a-zA-Z]+\s+)*(?:/|UUID=|LABEL=|-a\b|-o\b|--bind\b|-t\s)", I)),
    ("cron", re.compile(r"\bcrontab\s+(?:-u\s+\S+\s+)?(?:-e|-i|[^\s-]\S*)", I)),
    ("deleting files in system locations",
     re.compile(r"(?:^|[\s;&|(])(?:sudo\s+)?(?:rm|unlink|rmdir)\s+(?:-\S+\s+)*(?:[^\s;&|]+\s+)*?[\"']?" + SYS, I)),
    ("overwriting a file in a system location",
     re.compile(r"(?:\btruncate\s+-s\s*\S+\s+[\"']?" + SYS +
                r"|\bsed\s+(?:-\S+\s+)*-i\S*\s+[^\n;|&]*?" + SYS +
                r"|\btee\s+(?:-a\s+)?[\"']?" + SYS +
                r"|(?:^|[^<>&0-9])>{1,2}\s*[\"']?" + SYS +
                r"|\b(?:mv|cp|install|ln)\s+(?:-\S+\s+)*\S+\s+[\"']?/etc/"
                r"|\bchmod\s+(?:-R\s+)?\S+\s+[\"']?" + SYS + r"|\bchown\s+(?:-R\s+)?\S+\s+[\"']?" + SYS + r")", I)),
]

# Database clients: the query text is checked only if a client is in the command.
SQL_CLIENT = re.compile(r"\b(?:psql|pgcli|sqlcmd|mysql|mariadb|clickhouse-client|sqlite3|sqlplus|cqlsh|isql|duckdb)\b", I)
SQL_DESTROY = re.compile(
    r"\b(?:delete\s+from|truncate|drop\s+(?:table|database|schema|index|view|role|user|extension|function|procedure|trigger|owned|materialized|sequence|type|keyspace|tablespace|publication|subscription))\b", I)
SQL_WRITE = re.compile(
    r"\b(?:insert\s+into|update\s+\S+\s+set|replace\s+into|merge\s+into"
    r"|alter\s+(?:table|database|system|role|user|index|sequence|schema|extension|default|keyspace)|create\s+(?:table|database|schema|index|role|user|extension|function|procedure|trigger|view|materialized|keyspace)"
    r"|grant\s|revoke\s|vacuum\b|reindex\b|cluster\b|copy\s+\S+\s+from|refresh\s+materialized|reassign\s+owned|load\s+data"
    r"|pg_terminate_backend|pg_cancel_backend|pg_reload_conf|pg_drop_replication_slot|pg_create_\w+_replication_slot|pg_switch_wal|pg_promote|set_config\s*\(|lo_unlink"
    r"|kill\s+(?:query\s+)?\d|shutdown\b|set\s+global\b|flush\s+(?:privileges|tables|logs))", I)

MONGO_CLIENT = re.compile(r"\b(?:mongosh|mongo)\b", I)
MONGO_DESTROY = re.compile(r"\.(?:drop\w*|delete(?:One|Many)|remove|findOneAndDelete)\s*\(", I)
MONGO_WRITE = re.compile(r"\.(?:insert\w*|update\w*|replaceOne|findOneAnd(?:Update|Replace)|createIndex(?:es)?|renameCollection|createCollection"
                         r"|createUser|updateUser|grantRolesToUser|bulkWrite|shutdownServer|adminCommand)\s*\(", I)

# redis-cli and valkey-cli: commands go as arguments.
REDIS = r"\b(?:redis-cli|valkey-cli|keydb-cli)\b" + REST + r"\s"
REDIS_DESTROY = re.compile(REDIS + r"[\"']?(?:flushall|flushdb|del|unlink|hdel|srem|zrem|lrem|ltrim|xdel|xtrim)" + END, I)
REDIS_WRITE = re.compile(REDIS + r"[\"']?(?:set|setex|mset|hset|hmset|lpush|rpush|sadd|zadd|incr\w*|decr\w*|expire|persist|rename|restore|config\s+set|shutdown|bgrewriteaof|bgsave|save|failover|replicaof|slaveof|cluster\s+(?:reset|failover|forget|meet)|acl\s+(?:setuser|deluser)|client\s+kill|script\s+flush|function\s+(?:load|delete|flush)|eval\w*|publish|xadd|swapdb|move|migrate)" + END, I)

# HTTP requests that change data. Read-only Elasticsearch/OpenSearch POSTs (_search, _count...) are not writes.
HTTP_CLIENT = re.compile(r"\b(?:curl|wget|http|https|xh|httpie)\b", I)
HTTP_DELETE = re.compile(r"(?:-X\s*|--request[=\s]+|--method[=\s]+)['\"]?DELETE\b|\bDELETE\s+\S*://", I)
HTTP_WRITE = re.compile(
    r"(?:-X\s*|--request[=\s]+|--method[=\s]+)['\"]?(?:POST|PUT|PATCH)\b"
    r"|\s(?:-d|--data(?:-raw|-binary|-urlencode)?|-F|--form|-T|--upload-file|--post-data|--post-file|--body-data|--json)[\s=]"
    r"|\b(?:POST|PUT|PATCH)\s+\S*://", I)
HTTP_READ_ONLY = re.compile(
    r"/_(?:search|msearch|count|sql|validate/query|analyze|explain|field_caps|termvectors|mtermvectors|render/template)\b"
    r"|/_cluster/allocation/explain\b|/_nodes/[^\s'\"]*hot_threads\b|/graphql\b", I)

# Changing agent-guard's own settings is always the user's decision.
SELF_FILE = re.compile(r"\.agent-guard(?![\w.-])")
SELF_WRITE = re.compile(r">|\b(?:tee|rm|mv|cp|ln|truncate|install|dd|ed|perl|python\d*(?:\.\d+)?|ruby|node|awk|vi|vim|nano|touch|chmod)\b|\bsed\b[^\n;|&]*\s-i", I)
SELF_REASON = "changing agent-guard settings (.agent-guard): the user decides that"

# Redirects to /dev/null and the like are not writes.
SAFE_REDIRECT = re.compile(r"[0-9&]?>{1,2}\s*/dev/(?:null|stdout|stderr|tty)\b|[0-9]?>&[0-9-]")

# Write/Edit outside the project into these locations is a state change (prod).
SYS_EDIT = re.compile(r"^/(?:etc|usr|boot|var|opt|srv|lib|lib64|bin|sbin|root)/")
EDIT_TOOLS = ("Write", "Edit", "MultiEdit", "NotebookEdit")


def _http(part):
    """("destroy"|"change"|None) for one simple command."""
    if not HTTP_CLIENT.search(part) or HTTP_READ_ONLY.search(part):
        return None
    if HTTP_DELETE.search(part):
        return "destroy"
    if HTTP_WRITE.search(part):
        return "change"
    return None


def scan(cmd):
    """All matches of a command: (deny, destructive, change) lists of reasons."""
    text = SAFE_REDIRECT.sub(" ", cmd)
    deny = [why for why, rx in DENY if rx.search(text)]
    destroy = [why for why, rx in DESTRUCTIVE if rx.search(text)]
    change = [why for why, rx in CHANGE if rx.search(text)]
    http = set(_http(p) for p in re.split(r"[;&|\n]+", text))
    if "destroy" in http:
        destroy.append("HTTP DELETE request")
    if "change" in http:
        change.append("HTTP request that changes data (POST, PUT, PATCH)")
    if SQL_CLIENT.search(text):
        if SQL_DESTROY.search(text):
            destroy.append("SQL that deletes data or drops objects")
        if SQL_WRITE.search(text):
            change.append("SQL that changes data, schema or the server")
    if MONGO_CLIENT.search(text):
        if MONGO_DESTROY.search(text):
            destroy.append("MongoDB: deleting documents or dropping collections")
        if MONGO_WRITE.search(text):
            change.append("MongoDB: writing data")
    if REDIS_DESTROY.search(text):
        destroy.append("Redis: deleting keys or flushing")
    if REDIS_WRITE.search(text):
        change.append("Redis: writing data or changing the server")
    if SELF_FILE.search(text) and SELF_WRITE.search(text):
        destroy.append(SELF_REASON)
    return deny, destroy, change


def classify(cmd, profile="prod"):
    """("deny"|"ask"|None, [reasons]) for a Bash command under a profile."""
    if profile == "off":
        return None, []
    deny, destroy, change = scan(cmd)
    if deny:
        return "deny", deny
    reasons = destroy + (change if profile == "prod" else [])
    seen = []
    for r in reasons:
        if r not in seen:
            seen.append(r)
    return ("ask", seen) if seen else (None, [])


def classify_edit(path, cwd, profile="prod"):
    """Decision for Write/Edit of a file path."""
    if profile == "off" or not path:
        return None, []
    if os.path.basename(path) == config.CONFIG_FILE:
        return "ask", [SELF_REASON]
    if profile != "prod":
        return None, []
    p = os.path.normpath(path)
    if cwd:
        root = os.path.normpath(cwd)
        if p == root or p.startswith(root.rstrip("/") + "/"):
            return None, []
    if SYS_EDIT.match(p):
        return "ask", ["editing a file in a system location outside the project"]
    return None, []


def decide(data, environ=None):
    """Hook output dict or None for a parsed hook input."""
    cwd = data.get("cwd") or ""
    conf = config.load(cwd, environ)
    profile = conf["profile"]
    tool = data.get("tool_name")
    tin = data.get("tool_input") or {}
    if tool == "Bash":
        decision, reasons = classify(tin.get("command") or "", profile)
    elif tool in EDIT_TOOLS:
        decision, reasons = classify_edit(tin.get("file_path") or tin.get("notebook_path") or "", cwd, profile)
    else:
        return None
    if not decision:
        return None
    if decision == "deny":
        reason = ("agent-guard: blocked (%s). A human runs such commands outside the agent. "
                  "Explain to the user what needs to be done and why." % "; ".join(reasons))
    else:
        reason = ("agent-guard [%s]: this changes the system (%s). Before approving, check which host it runs on, "
                  "what it changes and how to roll it back." % (profile, "; ".join(reasons)))
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                   "permissionDecision": decision,
                                   "permissionDecisionReason": reason}}


def main():
    data = config.read_input()
    out = decide(data) if data else None
    if out:
        config.write_output(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
