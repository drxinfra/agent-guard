#!/usr/bin/env python3
"""agent-guard PostToolUse hook for Bash, Read and Grep: hides secrets before the model sees them.

Claude Code passes the tool result as JSON on stdin (tool_response). Every string in it
goes through mask_secrets.py; if anything was hidden, the hook returns updatedToolOutput
of the same shape, so the model gets ‹hidden› instead of the value, and additionalContext
tells it the values were hidden on purpose.

Known shapes: Bash {stdout, stderr, interrupted, isImage, noOutputExpected};
Read {type, file: {filePath, content, numLines, startLine, totalLines}};
Grep {mode, numFiles, filenames, content, numLines, totalLines}.

Switch off: AGENT_GUARD_MASK=off, or mask=off in .agent-guard. Standard library only.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import config  # noqa: E402
import mask_secrets  # noqa: E402

# Paths and service fields are left as they are: the response shape must not change.
SKIP_KEYS = {"filePath", "file_path", "path", "type", "mode", "filenames"}


def walk(value, key=None):
    """Copy of the structure with masked strings, and the number of hidden values."""
    if isinstance(value, str):
        if key in SKIP_KEYS:
            return value, 0
        return mask_secrets.mask(value)
    if isinstance(value, list):
        out, total = [], 0
        for v in value:
            m, n = walk(v, key if key in SKIP_KEYS else None)
            out.append(m)
            total += n
        return out, total
    if isinstance(value, dict):
        out, total = {}, 0
        for k, v in value.items():
            m, n = walk(v, k)
            out[k] = m
            total += n
        return out, total
    return value, 0


def decide(data, environ=None):
    if not config.load(data.get("cwd"), environ)["mask"]:
        return None
    resp = data.get("tool_response")
    if resp is None:
        return None
    masked, n = walk(resp)
    if not n:
        return None
    note = ("agent-guard: %d secret value(s) in the %s output were replaced with %s (passwords, tokens, keys). "
            "They are hidden on purpose: do not try to get them another way. If a value is really needed, "
            "ask the user to look at it themselves." % (n, data.get("tool_name", "tool"), mask_secrets.MASK))
    return {"hookSpecificOutput": {"hookEventName": "PostToolUse",
                                   "updatedToolOutput": masked,
                                   "additionalContext": note}}


def main():
    data = config.read_input()
    out = decide(data) if data else None
    if out:
        config.write_output(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
