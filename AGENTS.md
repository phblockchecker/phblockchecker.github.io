# AGENTS.md

## TL;DR

cicc discord/reddit ban check is a static site showing whether Discord and Reddit are blocked on a PH ISP (Globe), how it's being done, and how to get around it.

- **Probe** (`pi/checker.py`): runs hourly on a Raspberry Pi on a home Globe line. It tests plain DNS, DoT and DoH against every resolver in `pi/config.json`, checks for DNS hijacking, and checks for SNI/IP filtering. Writes `pi/out/latest.json` and `pi/out/history.json`. Needs only python3 and curl.
- **Publish** (`pi/publish.sh`): force-pushes `pi/out/` to the `data` branch as a single parentless commit, optionally through Tor (`GIT_PROXY`).
- **Site** (`index.html`, `style.css`, `app.js`): plain HTML/CSS/JS with no build step, served by GitHub Pages from `main`. It reads data from `raw.githubusercontent.com/.../data/`, or from `pi/out/` on localhost.
- **Local preview:** `python3 pi/checker.py && python3 -m http.server`

## Anonymity rules (strict)

This project must never be linkable to the maintainer's real identity. Treat every rule below as a hard requirement.

1. **Check the account before any GitHub action.** Before `git push` or any `gh` command, run `gh api user --jq .login`. It must print `phblockchecker`. If it doesn't, stop and tell the user. Never switch accounts yourself.
2. **Git identity is per-repo only.** It must be `phblockchecker <332948810+phblockchecker@users.noreply.github.com>`. Check with `git config user.name` / `git config user.email` before committing. The global git config holds the real identity, so never rely on it and never change it.
3. **No personal info in any file, commit, or branch.** That means no real names, emails, usernames of other accounts, home paths (`/Users/...`, `/home/<name>`), hostnames, IPs of the home network, or location more specific than "a home Globe connection". Grep before committing.
4. **Nothing on the site that phones home.** No analytics, trackers, external fonts, CDNs, or third-party scripts. Everything is self-hosted except the data fetch from GitHub.
5. **Never commit `pi/out/`.** It is gitignored. It holds a separate git repo whose remote URL contains a token.
6. **No secrets in the repo.** GitHub tokens live only in `pi/out/.git/config` on the Pi.
7. **The Pi pushes through Tor.** Only the push goes through Tor; the probes must use the ISP directly, or the measurement is meaningless.
8. **When unsure, ask.** If a change might expose identity (new service, new dependency, new external request), ask the user first.
