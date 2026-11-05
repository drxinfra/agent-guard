#!/usr/bin/env sh
# Leak check: the public repo must not contain private names, internal hosts or credentials.
# The pattern list is not in the repo: it comes from LEAKCHECK_PATTERN (a CI secret)
# or from a local .leakcheck file (one regex per line, the file is git-ignored).
set -eu
cd "$(dirname "$0")/.."
pat="${LEAKCHECK_PATTERN:-}"
if [ -z "$pat" ] && [ -f .leakcheck ]; then
  pat=$(grep -v '^[[:space:]]*\(#\|$\)' .leakcheck | paste -sd'|' -)
fi
if [ -z "$pat" ]; then
  echo "leakcheck: no patterns (LEAKCHECK_PATTERN or .leakcheck), skipped"
  exit 0
fi
# Tracked and new files, except ignored ones.
if git ls-files --cached --others --exclude-standard | tr '\n' '\0' | xargs -0 grep -EnI -i "$pat" --; then
  echo "leakcheck: suspicious lines found, see above" >&2
  exit 1
fi
echo "leakcheck: clean"
