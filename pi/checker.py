#!/usr/bin/env python3
"""Measure DNS/TLS blocking from this network and write JSON for the site. Needs only python3 + curl."""
import ipaddress
import json
import random
import re
import socket
import ssl
import struct
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
CONFIG = json.loads((HERE / "config.json").read_text())
OUT = HERE / "out"
TIMEOUT = CONFIG["timeout"]
KNOWN_PAGES = CONFIG["blockpages"].get(CONFIG["network"], {})  # confirmed; other ISPs rely on auto-detection
BLOCKPAGE_IPS = set(KNOWN_PAGES.get("ips", []))
BLOCKPAGE_HOSTS = set(KNOWN_PAGES.get("hosts", []))
RCODES = {1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED"}


# --- DNS wire format (A queries; A + CNAME answers) ---

def build_query(name, qid):
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
    return header + qname + struct.pack(">HH", 1, 1)


def skip_name(buf, i):
    while buf[i]:
        if buf[i] & 0xC0 == 0xC0:
            return i + 2
        i += buf[i] + 1
    return i + 1


def read_name(buf, i):
    labels = []
    for _ in range(128):  # bounds compression-pointer loops
        if not buf[i]:
            break
        if buf[i] & 0xC0 == 0xC0:
            i = struct.unpack(">H", buf[i:i + 2])[0] & 0x3FFF
            continue
        labels.append(buf[i + 1:i + 1 + buf[i]].decode(errors="replace"))
        i += buf[i] + 1
    return ".".join(labels).lower()


def parse_response(buf, qid):
    rid, flags, qdcount, ancount, _, _ = struct.unpack(">HHHHHH", buf[:12])
    if rid != qid:
        raise ValueError("id mismatch")
    i = 12
    for _ in range(qdcount):
        i = skip_name(buf, i) + 4
    ips, cnames = [], []
    for _ in range(ancount):
        i = skip_name(buf, i)
        rtype, _, _, rdlen = struct.unpack(">HHIH", buf[i:i + 10])
        i += 10
        if rtype == 1 and rdlen == 4:
            ips.append(socket.inet_ntoa(buf[i:i + 4]))
        elif rtype == 5:
            cnames.append(read_name(buf, i))
        i += rdlen
    return flags & 0xF, ips, cnames


# --- Transports ---

def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("closed")
        buf += chunk
    return buf


def udp(ip, q):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(TIMEOUT)
        s.sendto(q, (ip, 53))
        return s.recv(4096)


def dot(ip, host, q):
    ctx = ssl.create_default_context()
    with socket.create_connection((ip, 853), TIMEOUT) as raw, ctx.wrap_socket(raw, server_hostname=host) as s:
        s.sendall(struct.pack(">H", len(q)) + q)
        return recv_exact(s, struct.unpack(">H", recv_exact(s, 2))[0])


CURL_ERRORS = {6: "can't resolve host", 7: "connect failed", 22: "HTTP error", 35: "TLS error", 56: "reset"}


def curl(*args, input=None, timeout=TIMEOUT):
    p = subprocess.run(["curl", "-s", "--max-time", str(timeout), *args], input=input, capture_output=True)
    if p.returncode == 28:
        raise TimeoutError
    if p.returncode:
        raise ConnectionError(CURL_ERRORS.get(p.returncode, f"curl {p.returncode}"))
    return p.stdout


def doh(url, q, tor=False):
    # curl, not urllib: some DoH servers are HTTP/2-only (curl uses it when built with it)
    proxy = ["--proxy", CONFIG["tor_proxy"]] if tor else []
    return curl("-f", *proxy, "--data-binary", "@-", "-H", "content-type: application/dns-message",
                "-H", "accept: application/dns-message", url, input=q, timeout=TIMEOUT * 3 if tor else TIMEOUT)


def page_title(ip, domain):
    try:
        html = curl("-L", "--max-redirs", "3", "-H", f"Host: {domain}", f"http://{ip}/").decode(errors="replace")
    except (TimeoutError, ConnectionError):
        return None
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    return m and " ".join(m.group(1).split())[:100]


def senders(r):
    out = {}
    if r.get("ip") and r.get("plain", True):
        out["udp"] = lambda q: udp(r["ip"], q)
    if r.get("tls_host"):
        out["dot"] = lambda q: dot(r.get("ip") or r["tls_host"], r["tls_host"], q)
    if r.get("doh"):
        out["doh"] = lambda q: doh(r["doh"], q)
    return out


# --- Checks ---

def is_bogus(ip):
    return not ipaddress.ip_address(ip).is_global


def query(send, domain, qid, retries=1):
    """Return (ip, err, status): status is ok | blocked (bad answer) | error (no usable reply).
    Retries to skip transient failures."""
    ip, err, status = query_once(send, domain, qid)
    return query(send, domain, qid, retries - 1) if err and retries else (ip, err, status)


def query_once(send, domain, qid):
    try:
        rcode, ips, cnames = parse_response(send(build_query(domain, qid)), qid)
    except TimeoutError:
        return None, "timeout", "error"
    except Exception as e:
        return None, str(e) or type(e).__name__, "error"
    if rcode:
        return None, RCODES.get(rcode, f"rcode {rcode}"), "blocked"
    if page := next((c for c in cnames if c in BLOCKPAGE_HOSTS), None) or \
            next((ip for ip in ips if ip in BLOCKPAGE_IPS), None):
        return None, f"block page {page}", "blocked"
    if not ips:
        return None, "no answer", "blocked"
    bad = next((ip for ip in ips if is_bogus(ip)), None)
    return (None, f"bogus IP {bad}", "blocked") if bad else (ips[0], None, "ok")


def test_transport(send, qid, domains):
    _, err, _ = query(send, CONFIG["control"], qid)
    if err:
        return {"status": "down", "detail": err}
    results = {}
    for d in domains:
        ip, err, status = query(send, d, qid, retries=2)
        results[d] = {"status": "ok", "ip": ip} if ip else {"status": status, "detail": err}
    return {"status": "up", "domains": results}


def tls_handshake(ip, sni, verify):
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((ip, 443), TIMEOUT) as raw, ctx.wrap_socket(raw, server_hostname=sni):
            return "ok"
    except ssl.SSLCertVerificationError:
        return "bad_cert"
    except ssl.SSLError:
        return "alert"  # server (or middlebox) answered
    except OSError:
        return "interfered"  # timeout / reset / refused


def test_tls(domain, ip):
    """ok | tampered (wrong cert) | sni (name filtered) | ip (address blocked) | unknown."""
    if not ip:
        return {"status": "unknown"}
    real = tls_handshake(ip, domain, True)
    if real != "ok":
        real = tls_handshake(ip, domain, True)
    if real == "ok":
        return {"status": "ok", "ip": ip}
    if real == "bad_cert":
        return {"status": "tampered", "ip": ip}
    decoy = tls_handshake(ip, CONFIG["decoy_sni"], False)
    return {"status": "sni" if decoy != "interfered" else "ip", "ip": ip}


def probe_answered():
    """A reply from an address that runs no DNS server means port 53 is being hijacked."""
    qid = random.getrandbits(16)
    return query(lambda q: udp(CONFIG["hijack_probe_ip"], q), CONFIG["control"], qid, retries=0)[1] != "timeout"


def blockpage_ips(r):
    return {res["detail"].partition("block page ")[2].split()[0]
            for res in r["results"].get("udp", {}).get("domains", {}).values() if "block page " in res.get("detail", "")}


def hijacked_resolvers(resolvers):
    """Non-ISP resolvers whose plain DNS returned the ISP's own block page (the ISP rewrote the reply)."""
    isp_pages = BLOCKPAGE_IPS.union(*(blockpage_ips(r) for r in resolvers if r.get("isp")))
    return [r["name"] for r in resolvers if not r.get("isp") and blockpage_ips(r) & isp_pages]


def default_gateway():
    linux = Path("/proc/net/route")
    if linux.exists():
        f = next(f for f in map(str.split, linux.read_text().splitlines()[1:]) if f[1] == "00000000")
        return socket.inet_ntoa(struct.pack("<L", int(f[2], 16)))
    if sys.platform == "win32":
        out = subprocess.run(["route", "print", "-4", "0.0.0.0"], capture_output=True, text=True).stdout
        # skip "On-link" (VPN) routes
        return next(f[2] for f in map(str.split, out.splitlines()) if f[:2] == ["0.0.0.0"] * 2 and f[2][0].isdigit())
    out = subprocess.run(["route", "-n", "get", "default"], capture_output=True, text=True).stdout  # macOS
    return next(l.split()[1] for l in out.splitlines() if "gateway:" in l)


def isp_resolver():
    """The home router forwards DNS to the ISP, unlike resolv.conf (which may point at a Pi-hole)."""
    ip = CONFIG["isp_resolver"]
    return {"name": f"{CONFIG['network']} default", "ip": default_gateway() if ip == "gateway" else ip, "isp": True}


def ok_answers(resolvers, transports):
    return [(res, d) for r in resolvers for t in transports
            for d, res in r["results"].get(t, {}).get("domains", {}).items() if res["status"] == "ok"]


def trusted_ips(resolvers, domains, pool):
    """Encrypted answers the ISP can't rewrite. Falls back to DoH over Tor (if running) when all are blocked."""
    trusted = {d: set() for d in domains}
    for res, d in ok_answers(resolvers, ("doh", "dot")):
        trusted[d].add(res["ip"])
    missing = [d for d, ips in trusted.items() if not ips]
    for d, (ip, _, _) in zip(missing, pool.map(lambda d: query(lambda q: doh(CONFIG["tor_doh"], q, True), d, 0), missing)):
        trusted[d].update([ip] if ip else [])
    return trusted


def flag_blockpages(resolvers, pool, trusted):
    """A plain DNS answer the encrypted ones never gave is a likely block page if it doesn't serve the site:
    wrong cert, or no working HTTPS while a trusted IP has it."""
    answers = ok_answers(resolvers, ("udp",))
    keys = list({(res["ip"], d) for res, d in answers if res["ip"] not in trusted[d]}
                | {(ip, d) for d, ips in trusted.items() for ip in ips})
    hs = dict(zip(keys, pool.map(lambda k: tls_handshake(*k, True), keys)))

    def reason(ip, d):
        if ip in trusted[d]:
            return None
        if hs[ip, d] == "bad_cert":
            return "wrong cert"
        if hs[ip, d] != "ok" and any(hs[t, d] == "ok" for t in trusted[d]):
            return "no HTTPS"

    flagged = {k: why for k in keys if (why := reason(*k))}
    titles = dict(zip(flagged, pool.map(lambda k: page_title(*k), flagged)))
    for res, d in answers:
        if why := flagged.get((res["ip"], d)):
            ip = res.pop("ip")
            res.update(status="blocked", detail=f"likely block page {ip} ({why})")
            if titles[ip, d]:
                res["title"] = titles[ip, d]


def clean_ip(resolvers, domain, trusted):
    return next(iter(trusted[domain]), None) or next(
        (res["ip"] for res, d in ok_answers(resolvers, ("udp",)) if d == domain), None)


def summarize(site, resolvers, tls):
    doms = site["domains"]

    def works(r, t):
        """True = all clean, False = something blocked, None = can't tell (down or errors)."""
        res = r["results"].get(t, {})
        if res.get("status") != "up":
            return None
        statuses = {res["domains"][d]["status"] for d in doms}
        return False if "blocked" in statuses else None if "error" in statuses else True

    isp = next(r for r in resolvers if r.get("isp"))
    isp_dns = works(isp, "udp")
    tls_statuses = [tls[d]["status"] for d in doms]
    if "unknown" in tls_statuses:
        level = "unknown"
    elif any(s != "ok" for s in tls_statuses):
        level = "hard"
    else:
        level = {True: "open", False: "dns", None: "unknown"}[isp_dns]
    return {
        "level": level,
        "isp_dns": isp_dns,
        "alt_dns": any(works(r, "udp") is True for r in resolvers if not r.get("isp")),
        "encrypted_dns": any(works(r, t) is True for r in resolvers for t in ("dot", "doh")),
        "tls": dict(zip(doms, tls_statuses)),
    }


def main():
    domains = [d for s in CONFIG["sites"] for d in s["domains"]]
    resolvers = [isp_resolver()] + CONFIG["resolvers"]
    jobs = [(r, t, send) for r in resolvers for t, send in senders(r).items()]

    with ThreadPoolExecutor(32) as pool:
        probe = pool.submit(probe_answered)
        futures = [pool.submit(test_transport, send, 0 if t == "doh" else random.getrandbits(16), domains)
                   for _, t, send in jobs]
        for (r, t, _), f in zip(jobs, futures):
            r.setdefault("results", {})[t] = f.result()
        trusted = trusted_ips(resolvers, domains, pool)
        flag_blockpages(resolvers, pool, trusted)
        tls = dict(zip(domains, pool.map(lambda d: test_tls(d, clean_ip(resolvers, d, trusted)), domains)))
        hijacked = hijacked_resolvers(resolvers)
        hijack = probe.result() or bool(hijacked)

    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    summary = {s["name"]: summarize(s, resolvers, tls) for s in CONFIG["sites"]}
    report = {
        "updated": now,
        "network": CONFIG["network"],
        "sites": CONFIG["sites"],
        "dns_intercepted": hijack,
        "hijacked": hijacked,
        "summary": summary,
        "tls": tls,
        # ISP resolver IP is the home router's, so it's not published
        "resolvers": [{k: r[k] for k in ("name", "ip", "tls_host", "results") if k in r and not (k == "ip" and r.get("isp"))}
                      | {"isp": r.get("isp", False)} for r in resolvers],
    }

    OUT.mkdir(exist_ok=True)
    history_file = OUT / "history.json"
    history = json.loads(history_file.read_text()) if history_file.exists() else []
    history = (history + [{"t": now, "levels": {k: v["level"] for k, v in summary.items()}}])[-CONFIG["history_limit"]:]
    history_file.write_text(json.dumps(history, separators=(",", ":")))
    (OUT / "latest.json").write_text(json.dumps(report, indent=1))
    print(now, {k: v["level"] for k, v in summary.items()}, "intercepted" if hijack else "")


if __name__ == "__main__":
    main()
