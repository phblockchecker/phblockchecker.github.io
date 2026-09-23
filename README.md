# cicc discord/reddit ban check

A static site showing whether Discord/Reddit are blocked on a PH ISP, and how. A Raspberry Pi probes every hour and force-pushes the results to a `data` branch. GitHub Pages serves the site from `main`.

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
- Use a fine-grained GitHub token scoped to this repo only, with **Contents: read/write**.

## 1. GitHub

1. Create a public repo, push `main`, then turn on Settings → Pages → Deploy from branch → `main` / root.
2. In `app.js`, set `DATA_URL` to `https://raw.githubusercontent.com/<user>/<repo>/data/`.

## 2. Pi

Needs `python3`, `curl`, and `git` (all preinstalled on Raspberry Pi OS). The ISP's DNS is tested through the home router (the default gateway), so a Pi-hole or custom DNS on the Pi doesn't matter. Just don't set custom DNS on the router itself. To test a specific resolver instead, set `isp_resolver` in `config.json` to its IP.

```sh
git clone https://github.com/<user>/<repo>.git ~/ph-dns-checker
cd ~/ph-dns-checker/pi
python3 checker.py                     # test run; writes out/latest.json

cd out
git init -q
git config user.name "phblock"
git config user.email "<id>+phblock@users.noreply.github.com"
git remote add origin https://<token>@github.com/<user>/<repo>.git
cd .. && ./publish.sh
```

Each run is pushed as a single commit with no history, so the repo stays tiny. `history.json` (last 7 days) lives on the Pi.

### Push through Tor (optional, recommended)

The push is what connects your home IP to the repo. The probes themselves have to go out over the ISP, so only the push goes through Tor.

```sh
sudo apt install tor
GIT_PROXY=socks5h://127.0.0.1:9050 ./publish.sh
```

### Cron (hourly)

`crontab -e`:

```
0 * * * * GIT_PROXY=socks5h://127.0.0.1:9050 /home/pi/ph-dns-checker/pi/publish.sh >> /home/pi/phblock.log 2>&1
```

## Local preview

```sh
python3 pi/checker.py && python3 -m http.server   # open http://localhost:8000
```

## Tuning

- Found the ISP's block-page IP? Add it to `blockpage_ips` in `config.json`. The probe also flags block pages automatically when the ISP's answer serves the wrong TLS certificate.
- Add sites or resolvers in `config.json`. The site picks them up automatically.
