"""agent-guard settings: profile, masking and journal switches.

Sources, later ones win:
  1. defaults: profile=prod, mask=on, journal=on
  2. environment: AGENT_GUARD_PROFILE, AGENT_GUARD_MASK, AGENT_GUARD_JOURNAL
  3. file .agent-guard in the project root, found from the hook's cwd upwards:
       # comments are allowed
       profile=test
       mask=on
       journal=off

Standard library only, Python 3.6+.
"""
import io
import json
import os
import sys

PROFILES = ("prod", "test", "off")
CONFIG_FILE = ".agent-guard"
OFF = ("off", "0", "no", "false", "disable", "disabled")
ON = ("on", "1", "yes", "true", "enable", "enabled")


def read_input():
    """Hook input from stdin as a dict ({} if it is not JSON)."""
    try:
        data = json.loads(sys.stdin.buffer.read().decode("utf-8", "replace"))
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def write_output(obj):
    """JSON to stdout as UTF-8 bytes: with Python 3.6 and LANG=C the text stream is ASCII."""
    sys.stdout.buffer.write(json.dumps(obj, ensure_ascii=False).encode("utf-8"))
    sys.stdout.buffer.flush()


def find_config(cwd):
    """Path of the nearest .agent-guard from cwd upwards, or None."""
    d = os.path.abspath(cwd or os.getcwd())
    while True:
        p = os.path.join(d, CONFIG_FILE)
        if os.path.isfile(p):
            return p
        parent = os.path.dirname(d)
        if parent == d:
            return None
        d = parent


def parse_config(path):
    out = {}
    try:
        with io.open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.split("#", 1)[0].strip()
                if "=" not in line:
                    continue
                k, v = line.split("=", 1)
                out[k.strip().lower()] = v.strip().strip("'\"").lower()
    except (IOError, OSError):
        pass
    return out


def _switch(value, default):
    if value in OFF:
        return False
    if value in ON:
        return True
    return default


def load(cwd=None, environ=None):
    """Effective settings: {"profile", "mask", "journal", "source"}."""
    env = os.environ if environ is None else environ
    profile = env.get("AGENT_GUARD_PROFILE", "").strip().lower()
    mask = env.get("AGENT_GUARD_MASK", "").strip().lower()
    journal = env.get("AGENT_GUARD_JOURNAL", "").strip().lower()
    source = "env" if profile else "default"
    path = find_config(cwd)
    if path:
        conf = parse_config(path)
        if conf.get("profile"):
            profile, source = conf["profile"], path
        mask = conf.get("mask", mask)
        journal = conf.get("journal", journal)
    if profile in OFF:
        profile = "off"
    if profile not in PROFILES:
        # Unknown value: fail safe to the strictest profile.
        profile = "prod"
    return {"profile": profile, "mask": _switch(mask, True), "journal": _switch(journal, True), "source": source}
