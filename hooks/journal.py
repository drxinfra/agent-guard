#!/usr/bin/env python3
"""agent-guard audit journal: one JSON line per Bash command the agent ran.

Hook mode (PostToolUse and PostToolUseFailure for Bash, see hooks.json):
  python3 journal.py --hook        reads the hook input on stdin, appends a line

Each line: ts (UTC), session_id, cwd, host, profile, command (secrets masked),
exit code and interrupted flag when Claude Code reports them, failed, and whether
the guard asked for confirmation (asked, reasons). Command output is never stored.

File: ${CLAUDE_PLUGIN_DATA}/journal.jsonl, or ~/.local/state/agent-guard/journal.jsonl
when CLAUDE_PLUGIN_DATA is not set. At ~10 MB the file is rotated to journal.jsonl.1
(one old file is kept). Switch off: AGENT_GUARD_JOURNAL=off, or journal=off in .agent-guard.

Reading:
  python3 journal.py [--since 1h] [--grep REGEX] [--session ID] [--asked] [--failed]
                     [--last N] [--json] [--file PATH]
  --since takes 30m, 2h, 1d, 1w or a date (2026-11-05, 2026-11-05T14:00), UTC.

Standard library only, Python 3.6+.
"""
import argparse
import datetime
import glob
import io
import json
import os
import re
import socket
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import config  # noqa: E402
import guard  # noqa: E402
import mask_secrets  # noqa: E402

NAME = "journal.jsonl"
MAX_BYTES = 10 * 1024 * 1024
TS_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def _utcnow():
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


def journal_path(environ=None):
    env = os.environ if environ is None else environ
    base = env.get("CLAUDE_PLUGIN_DATA")
    if not base:
        base = os.path.join(os.path.expanduser("~"), ".local", "state", "agent-guard")
    return os.path.join(base, NAME)


def _exit_code(data):
    resp = data.get("tool_response")
    if isinstance(resp, dict):
        for k in ("exitCode", "exit_code", "returnCode", "returncode", "code"):
            if isinstance(resp.get(k), int) and not isinstance(resp.get(k), bool):
                return resp[k]
    for text in (data.get("error"), resp if isinstance(resp, str) else None):
        if isinstance(text, str):
            m = re.match(r"\s*(?:Error:\s*)?Exit code (\d+)", text)
            if m:
                return int(m.group(1))
    return None


def entry(data, environ=None):
    """The journal record for a hook input, or None if it is not a Bash call."""
    if data.get("tool_name") != "Bash":
        return None
    cwd = data.get("cwd") or ""
    conf = config.load(cwd, environ)
    if not conf["journal"]:
        return None
    command = (data.get("tool_input") or {}).get("command") or ""
    decision, reasons = guard.classify(command, conf["profile"])
    resp = data.get("tool_response")
    rec = {
        "ts": _utcnow().strftime(TS_FORMAT),
        "session_id": data.get("session_id"),
        "cwd": cwd,
        "host": socket.gethostname(),
        "profile": conf["profile"],
        "command": mask_secrets.mask(command)[0],
        "failed": data.get("hook_event_name") == "PostToolUseFailure",
        "asked": decision == "ask",
    }
    if reasons:
        rec["reasons"] = reasons
    code = _exit_code(data)
    if code is not None:
        rec["exit"] = code
    if isinstance(resp, dict) and isinstance(resp.get("interrupted"), bool):
        rec["interrupted"] = resp["interrupted"]
    elif data.get("is_interrupt") is True:
        rec["interrupted"] = True
    return rec


def append(rec, path):
    d = os.path.dirname(path)
    if not os.path.isdir(d):
        os.makedirs(d, 0o700)
    try:
        if os.path.getsize(path) >= MAX_BYTES:
            os.replace(path, path + ".1")
    except OSError:
        pass
    line = (json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        os.write(fd, line)
    finally:
        os.close(fd)


def hook():
    data = config.read_input()
    try:
        rec = entry(data) if data else None
        if rec:
            append(rec, journal_path())
    except Exception as e:  # the journal must never break the agent's work
        sys.stderr.buffer.write(("agent-guard journal: %s\n" % e).encode("utf-8"))
    return 0


# ---------- reading ----------

def parse_since(value, now=None):
    now = now or _utcnow()
    m = re.match(r"^(\d+)\s*([smhdw])$", value.strip())
    if m:
        n, unit = int(m.group(1)), m.group(2)
        secs = n * {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}[unit]
        return now - datetime.timedelta(seconds=secs)
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return datetime.datetime.strptime(value.strip().rstrip("Z"), fmt)
        except ValueError:
            pass
    raise argparse.ArgumentTypeError("--since: use 30m, 2h, 1d, 1w or a date like 2026-11-05T14:00")


def candidate_files(explicit=None, environ=None):
    if explicit:
        return [explicit]
    env = os.environ if environ is None else environ
    paths = [journal_path(env), journal_path({})]
    pattern = os.path.join(os.path.expanduser("~"), ".claude", "plugins", "data", "agent-guard*", NAME)
    paths += sorted(glob.glob(pattern))
    out = []
    for p in paths:
        for f in (p + ".1", p):
            if os.path.isfile(f) and f not in out:
                out.append(f)
    return out


def read_records(files):
    recs = []
    for f in files:
        with io.open(f, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if isinstance(rec, dict):
                    recs.append(rec)
    recs.sort(key=lambda r: r.get("ts") or "")
    return recs


def select(recs, since=None, grep=None, session=None, asked=False, failed=False):
    rx = re.compile(grep, re.I) if grep else None
    floor = since.strftime(TS_FORMAT) if since else None
    for r in recs:
        if floor and (r.get("ts") or "") < floor:
            continue
        if rx and not rx.search(r.get("command") or ""):
            continue
        if session and not (r.get("session_id") or "").startswith(session):
            continue
        if asked and not r.get("asked"):
            continue
        if failed and not (r.get("failed") or r.get("exit") not in (None, 0)):
            continue
        yield r


def fmt(r):
    flags = []
    if r.get("asked"):
        flags.append("ASKED")
    if r.get("exit") not in (None, 0):
        flags.append("exit=%s" % r["exit"])
    elif r.get("failed"):
        flags.append("failed")
    if r.get("interrupted"):
        flags.append("interrupted")
    cmd = (r.get("command") or "").replace("\n", " \\n ")
    return "%s  %s  %s  %s%s" % (r.get("ts", "?"), r.get("host", "?"), (r.get("session_id") or "-")[:8],
                                 ("[%s] " % " ".join(flags)) if flags else "", cmd)


def _write(text):
    sys.stdout.buffer.write(text.encode("utf-8"))


def cli(argv):
    ap = argparse.ArgumentParser(prog="journal.py", description="Read the agent-guard command journal.")
    ap.add_argument("--hook", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--since", type=parse_since, help="30m, 2h, 1d, 1w or a UTC date/time")
    ap.add_argument("--grep", help="regex over the command (case-insensitive)")
    ap.add_argument("--session", help="session id or its prefix")
    ap.add_argument("--asked", action="store_true", help="only commands the guard asked about")
    ap.add_argument("--failed", action="store_true", help="only failed commands")
    ap.add_argument("--last", type=int, metavar="N", help="only the last N matches")
    ap.add_argument("--json", action="store_true", help="print raw JSON lines")
    ap.add_argument("--file", help="journal file to read")
    args = ap.parse_args(argv)
    if args.hook:
        return hook()
    files = candidate_files(args.file)
    if not files:
        sys.stderr.buffer.write(("journal: no journal found (looked at %s)\n" % journal_path()).encode("utf-8"))
        return 1
    out = list(select(read_records(files), args.since, args.grep, args.session, args.asked, args.failed))
    if args.last:
        out = out[-args.last:]
    for r in out:
        _write((json.dumps(r, ensure_ascii=False, sort_keys=True) if args.json else fmt(r)) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(cli(sys.argv[1:]))
