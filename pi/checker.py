#!/usr/bin/env python3
"""Measure DNS/TLS blocking from this network and write JSON for the site. Needs only python3 + curl."""
import ipaddress
import json
import random
import socket
import ssl
import struct
import subprocess
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
CONFIG = json.loads((HERE / "config.json").read_text())
OUT = HERE / "out"
TIMEOUT = CONFIG["timeout"]
BLOCKPAGE_IPS = set(CONFIG["blockpage_ips"])
RCODES = {1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED"}


# --- DNS wire format (A records only) ---

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


def parse_response(buf, qid):
    rid, flags, qdcount, ancount, _, _ = struct.unpack(">HHHHHH", buf[:12])
    if rid != qid:
        raise ValueError("id mismatch")
    i = 12
    for _ in range(qdcount):
        i = skip_name(buf, i) + 4
    ips = []
    for _ in range(ancount):
        i = skip_name(buf, i)
        rtype, _, _, rdlen = struct.unpack(">HHIH", buf[i:i + 10])
        i += 10
        if rtype == 1 and rdlen == 4:
            ips.append(socket.inet_ntoa(buf[i:i + 4]))
        i += rdlen
    return flags & 0xF, ips


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


def doh(url, q):
    # curl, not urllib: some DoH servers are HTTP/2-only
    p = subprocess.run(["curl", "-sf", "--http2", "--max-time", str(TIMEOUT), "--data-binary", "@-",
                        "-H", "content-type: application/dns-message", "-H", "accept: application/dns-message", url],
                       input=q, capture_output=True)
    if p.returncode == 28:
        raise TimeoutError
    if p.returncode:
        raise ConnectionError(CURL_ERRORS.get(p.returncode, f"curl {p.returncode}"))
    return p.stdout


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
    return ip in BLOCKPAGE_IPS or not ipaddress.ip_address(ip).is_global


def query(send, domain, qid, retries=1):
    """Return (ip, None) on a clean answer, else (None, reason). Retries to skip transient failures."""
    ip, err = query_once(send, domain, qid)
    return query(send, domain, qid, retries - 1) if err and retries else (ip, err)


def query_once(send, domain, qid):
    try:
        rcode, ips = parse_response(send(build_query(domain, qid)), qid)
    except TimeoutError:
        return None, "timeout"
    except Exception as e:
        return None, str(e) or type(e).__name__
    if rcode:
        return None, RCODES.get(rcode, f"rcode {rcode}")
    if not ips:
        return None, "no answer"
    bad = next((ip for ip in ips if is_bogus(ip)), None)
    return (None, f"bogus IP {bad}") if bad else (ips[0], None)


def test_transport(send, qid, domains):
    _, err = query(send, CONFIG["control"], qid)
    if err:
        return {"status": "down", "detail": err}
    results = {}
    for d in domains:
        ip, err = query(send, d, qid)
        results[d] = {"status": "ok", "ip": ip} if ip else {"status": "blocked", "detail": err}
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


def dns_intercepted():
    """A reply from an address that runs no DNS server means port 53 is being hijacked."""
    qid = random.getrandbits(16)
    return query(lambda q: udp(CONFIG["hijack_probe_ip"], q), CONFIG["control"], qid, retries=0)[1] != "timeout"


def isp_resolver():
    ip = CONFIG["isp_resolver"]
    if ip == "auto":
        lines = Path("/etc/resolv.conf").read_text().splitlines()
        ip = next(l.split()[1] for l in lines if l.startswith("nameserver"))
    return {"name": f"{CONFIG['network']} default", "ip": ip, "isp": True}


def flag_blockpages(isp):
    """ISP answers that look valid but serve the wrong cert are block pages."""
    for d, res in isp["results"].get("udp", {}).get("domains", {}).items():
        if res["status"] == "ok" and tls_handshake(res["ip"], d, True) == "bad_cert":
            isp["results"]["udp"]["domains"][d] = {"status": "blocked", "detail": f"block page {res['ip']}"}


def clean_ip(resolvers, domain):
    for t in ("doh", "dot", "udp"):
        for r in resolvers:
            res = r["results"].get(t, {}).get("domains", {}).get(domain, {})
            if res.get("status") == "ok":
                return res["ip"]


def summarize(site, resolvers, tls):
    doms = site["domains"]

    def works(r, t):
        res = r["results"].get(t, {})
        return res.get("status") == "up" and all(res["domains"][d]["status"] == "ok" for d in doms)

    isp = next(r for r in resolvers if r.get("isp"))
    tls_statuses = [tls[d]["status"] for d in doms]
    if "unknown" in tls_statuses:
        level = "unknown"
    elif any(s != "ok" for s in tls_statuses):
        level = "hard"
    else:
        level = "open" if works(isp, "udp") else "dns"
    return {
        "level": level,
        "isp_dns": works(isp, "udp"),
        "alt_dns": any(works(r, "udp") for r in resolvers if not r.get("isp")),
        "encrypted_dns": any(works(r, t) for r in resolvers for t in ("dot", "doh")),
        "tls": dict(zip(doms, tls_statuses)),
    }


def main():
    domains = [d for s in CONFIG["sites"] for d in s["domains"]]
    resolvers = [isp_resolver()] + CONFIG["resolvers"]
    jobs = [(r, t, send) for r in resolvers for t, send in senders(r).items()]

    with ThreadPoolExecutor(32) as pool:
        hijack = pool.submit(dns_intercepted)
        futures = [pool.submit(test_transport, send, 0 if t == "doh" else random.getrandbits(16), domains)
                   for _, t, send in jobs]
        for (r, t, _), f in zip(jobs, futures):
            r.setdefault("results", {})[t] = f.result()
        flag_blockpages(resolvers[0])
        tls = dict(zip(domains, pool.map(lambda d: test_tls(d, clean_ip(resolvers, d)), domains)))
        hijack = hijack.result()

    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    summary = {s["name"]: summarize(s, resolvers, tls) for s in CONFIG["sites"]}
    report = {
        "updated": now,
        "network": CONFIG["network"],
        "sites": CONFIG["sites"],
        "dns_intercepted": hijack,
        "summary": summary,
        "tls": tls,
        "resolvers": [{k: r[k] for k in ("name", "ip", "results") if k in r} | {"isp": r.get("isp", False)}
                      for r in resolvers],
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
