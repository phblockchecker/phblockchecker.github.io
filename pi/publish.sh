#!/usr/bin/env bash
# Run the checker, then force-push out/ as a single parentless commit to the `data` branch.
# Setup once: see README. Set GIT_PROXY=socks5h://127.0.0.1:9050 to push through Tor.
set -euo pipefail
cd "$(dirname "$0")"

python3 checker.py

cd out
[ -d .git ] || { echo "out/ is not a git repo yet; see README setup" >&2; exit 1; }
git add -A
commit=$(git commit-tree "$(git write-tree)" -m "update")
git -c http.proxy="${GIT_PROXY:-}" push -qf origin "$commit:refs/heads/data"
git gc --auto -q
