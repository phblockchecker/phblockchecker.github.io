# cicc discord/reddit ban check

A static site showing whether Discord/Reddit are blocked on a PH ISP, and how. A Raspberry Pi probes every 10 minutes and force-pushes the results to a `data` branch. GitHub Pages serves the site from `main`.

```
index.html, style.css, app.js   site (GitHub Pages, main branch)
pi/checker.py                   probe: DNS (plain/DoT/DoH), DNS hijack, SNI/IP filtering
pi/config.json                  sites, resolvers, timeouts
pi/publish.sh                   run probe + push pi/out/ to the `data` branch
```

## Opsec first

- Set a pseudonymous git identity **in this repo** before your first commit, so your real name/email doesn't end up in public commits:
  `git config user.name "phblock" && git config user.email "<id>+phblock@users.noreply.github.com"`
- Do the same in `pi/out/` on the Pi (below).
- Push with an SSH deploy key scoped to this repo only (write access), routed through Tor.

## 1. GitHub

1. Create a public repo, push `main`, then turn on Settings → Pages → Deploy from branch → `main` / root.
2. In `app.js`, set `DATA_URL` to `https://raw.githubusercontent.com/<user>/<repo>/data/`.

## 2. Pi

Needs `python3`, `curl`, and `git` (all preinstalled on Raspberry Pi OS). The ISP's DNS is tested through the home router (the default gateway), so a Pi-hole or custom DNS on the Pi doesn't matter. Just don't set custom DNS on the router itself. To test a specific resolver instead, set `isp_resolver` in `config.json` to its IP.

```sh
sudo apt install tor
git -c http.proxy=socks5h://127.0.0.1:9050 clone https://github.com/<user>/<repo>.git ~/ph-dns-checker
ssh-keygen -t ed25519 -N "" -f ~/.ssh/phblock   # add ~/.ssh/phblock.pub as a deploy key with write access

cd ~/ph-dns-checker/pi
python3 checker.py                     # test run; writes out/latest.json

cd out
git init -q
git config user.name "phblock"
git config user.email "<id>+phblock@users.noreply.github.com"
git config core.sshCommand "ssh -i ~/.ssh/phblock -o IdentitiesOnly=yes -o ProxyCommand='nc -X 5 -x 127.0.0.1:9050 %h %p'"
git remote add origin git@github.com:<user>/<repo>.git
cd .. && ./publish.sh
```

Each run is pushed as a single commit with no history, so the repo stays tiny. `history.json` (last 24 hours) lives on the Pi.

The push is what connects your home IP to the repo, so `core.sshCommand` sends it through Tor. The probes themselves have to go out over the ISP.

### Cron (every 10 minutes)

`crontab -e`:

```
*/10 * * * * flock -n /tmp/phblock.lock /home/pi/ph-dns-checker/pi/publish.sh >> /home/pi/phblock.log 2>&1
```

## Local preview

```sh
python3 pi/checker.py && python3 -m http.server   # open http://localhost:8000
```

## Tuning

- Block pages are flagged automatically as "likely block page" (with the page title when it loads). Once confirmed, add the IP or CNAME host under `blockpages.<network>` in `config.json` to mark it certain. Networks with no entry rely on auto-detection only.
- Add sites or resolvers in `config.json`. The site picks them up automatically.
