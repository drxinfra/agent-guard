#!/usr/bin/env python3
"""Builds release archives in dist/.

  dist/agent-guard-<version>.zip   the whole plugin: for `claude --plugin-dir` and installs without GitHub
  dist/SHA256SUMS                  checksums

The version is taken from .claude-plugin/plugin.json. Standard library only.
"""
import hashlib
import json
import os
import shutil
import sys
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NAME = "agent-guard"
PLUGIN_FILES = [".claude-plugin", "skills", "hooks", "README.md", "README.ru.md", "LICENSE", "NOTICE"]
SKIP_DIRS = {"__pycache__", ".git"}
SKIP_FILES = {".DS_Store"}
# The same timestamp for every file: the same sources give the same checksum.
STAMP = (2026, 1, 1, 0, 0, 0)


def files_under(path):
    if os.path.isfile(path):
        yield path
        return
    for root, dirs, files in os.walk(path):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for f in sorted(files):
            if f not in SKIP_FILES and not f.endswith(".pyc"):
                yield os.path.join(root, f)


def write_zip(target, entries):
    """entries: [(path on disk, path in archive)]."""
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as z:
        for src, arc in entries:
            info = zipfile.ZipInfo(arc, STAMP)
            mode = 0o755 if os.access(src, os.X_OK) else 0o644
            info.external_attr = (mode | 0o100000) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            with open(src, "rb") as f:
                z.writestr(info, f.read())


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    with open(os.path.join(ROOT, ".claude-plugin", "plugin.json"), encoding="utf-8") as f:
        version = json.load(f)["version"]
    dist = os.path.join(ROOT, "dist")
    shutil.rmtree(dist, ignore_errors=True)
    entries = []
    for item in PLUGIN_FILES:
        for src in files_under(os.path.join(ROOT, item)):
            entries.append((src, NAME + "/" + os.path.relpath(src, ROOT).replace(os.sep, "/")))
    target = os.path.join(dist, "%s-%s.zip" % (NAME, version))
    write_zip(target, entries)
    with open(os.path.join(dist, "SHA256SUMS"), "w") as f:
        f.write("%s  %s\n" % (sha256(target), os.path.basename(target)))
    print("%8.1f KB  %s" % (os.path.getsize(target) / 1024.0, os.path.relpath(target, ROOT)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
