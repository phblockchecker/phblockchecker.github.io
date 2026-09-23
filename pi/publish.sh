#!/usr/bin/env bash
# Run the checker, then force-push out/ as a single parentless commit to the `data` branch.
# Setup once: see README (the push goes through Tor via out/'s core.sshCommand).
set -euo pipefail
export TZ=UTC  # commit timestamps carry no local timezone
cd "$(dirname "$0")"

python3 checker.py

cd out
[ -d .git ] || { echo "out/ is not a git repo yet; see README setup" >&2; exit 1; }
git add -A
commit=$(git commit-tree "$(git write-tree)" -m "update")
git push -qf origin "$commit:refs/heads/data"
git gc --auto -q
