#!/usr/bin/env python3
"""Post VT comments for new MISP 1932 IOCs. Quota-capped.

Free VT tier is about 500 requests/day and 4/minute.
This job does writes only (no lookups). Default 25 per run.
Cron runs twice a day, daily cap 50 — still under the free 500/day quota.
"""
from __future__ import annotations

import argparse
import json
import re
import ssl
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone, timedelta
from pathlib import Path

sys.path.insert(0, str(Path.home() / ".config/agents/skills/soc-connector/scripts"))
from misp_client import MISPClient  # noqa: E402
import yaml  # noqa: E402

BASE = Path.home() / ".config/soc-orchestrator"
LEDGER = BASE / "vt-commented.txt"
DAILY = BASE / "vt-comment-daily.json"
CONFIG = BASE / "config.yaml"
DELAY = 16  # 4/min
DAILY_CAP = 50

SENSOR = {
    # public sensor IPs are read from config.yaml at runtime; do not hardcode here
}


def sensor_map(cfg):
    return cfg.get("sensor_public_ips") or {}


def mask2(ip: str) -> str:
    p = (ip or "").split(".")
    return f"{p[0]}.{p[1]}.*.*" if len(p) == 4 else "?.?.*.*"


def cloud(ip: str) -> bool:
    try:
        a, b = [int(x) for x in ip.split(".")[:2]]
    except Exception:
        return False
    return (
        a in (13, 20, 34, 35, 40, 52)
        or (a == 104 and 16 <= b <= 31)
        or (a == 172 and 64 <= b <= 71)
        or (a, b) in ((162, 158), (141, 101), (108, 162))
    )


def load_cfg():
    text = CONFIG.read_text()
    cfg = yaml.safe_load(text)
    vt = re.search(r'api_key:\s*"([^"]+)"', text.split("virustotal")[1]).group(1)
    return cfg, vt


def ledger() -> set[str]:
    if not LEDGER.exists():
        return set()
    return {ln.strip() for ln in LEDGER.read_text().splitlines() if ln.strip()}


def remember(ip: str) -> None:
    with LEDGER.open("a") as fh:
        fh.write(ip + "\n")


def daily_used() -> int:
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    if not DAILY.exists():
        return 0
    data = json.loads(DAILY.read_text())
    if data.get("date") != today:
        return 0
    return int(data.get("used") or 0)


def daily_add(n: int) -> None:
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    used = daily_used() + n
    DAILY.write_text(json.dumps({"date": today, "used": used}))


def parse(cmt: str) -> dict:
    def grab(pat, default="0"):
        m = re.search(pat, cmt or "")
        return m.group(1) if m else default
    return {
        "count": grab(r"Wazuh:\s*(\d+)x"),
        "lvl": grab(r"lvl=(\d+)"),
        "otx": grab(r"pulses=(\d+)"),
        "aip": grab(r"AIPDB:\s*score=(\d+)"),
        "isp": grab(r"isp=([^|]+)", "").strip(),
    }


def worth(ip: str, meta: dict) -> bool:
    if "/" in ip:
        return False
    lvl = int(meta["lvl"] or 0)
    otx = int(meta["otx"] or 0)
    aip = int(meta["aip"] or 0)
    isp = (meta["isp"] or "").lower()
    googleish = any(x in isp for x in ("google", "microsoft", "azure", "amazon"))
    if cloud(ip) and lvl < 10 and googleish and not (otx >= 5 or aip >= 80 and "google" not in isp):
        return False
    if cloud(ip) and lvl < 10 and "google" in isp:
        return False
    return lvl >= 10 or otx >= 5 or (aip >= 80 and "google" not in isp)


def defang(ip: str) -> str:
    head, _, last = (ip or "").rpartition(".")
    return f"{head}[.]{last}" if last else (ip or "")


def comment_text(ip, meta, date, agent="sensor-syd"):
    lvl = int(meta["lvl"] or 0)
    count = int(meta["count"] or 0)
    if lvl >= 10 and count < 30:
        cat, ttp = "Reconnaissance", "T1046 Network Service Discovery"
        ports, what = "any (recon)", "inbound connections or packets from this IP to exposed services"
    elif int(meta["aip"] or 0) >= 80 and lvl >= 10:
        cat, ttp = "Brute Force", "T1110 Brute Force"
        ports, what = "22/tcp (SSH)", "SSH/auth failures (failed password, invalid user) with this IP as source"
    else:
        cat, ttp = "Web Attack", "T1190 Exploit Public-Facing Application"
        ports, what = "80/tcp, 443/tcp (HTTP/S)", "HTTP(S) requests from this IP (error floods, scanners, exploit probes)"
    conf = "High" if lvl >= 10 or int(meta["otx"] or 0) >= 5 or int(meta["aip"] or 0) >= 80 else "Medium"
    fang = defang(ip)
    target = f"{agent} ({mask2(SENSOR[agent])})" if agent in SENSOR else agent
    return (
        f"Date: {date}\n"
        f"IOC: {fang}\n"
        f"Type: IPv4 attacker (ip-src)\n"
        f"Category: {cat}\n"
        f"Confidence: {conf}\n"
        f"Ports: {ports}\n"
        f"Observed Behavior: Wazuh {meta['count']} alerts, level {meta['lvl']}. "
        f"OTX pulses={meta['otx']}. AbuseIPDB={meta['aip']}. {meta['isp']}\n"
        f"Target: {target}  [host prefix only; not a victim PII]\n"
        f"Source: Wazuh Indexer (SOC Orchestrator)\n"
        f"TTPs: {ttp}\n"
        f"Hunt: source IP = {fang}\n"
        f"Fields: src_ip | source.ip | client.ip | c-ip\n"
        f"What: {what}\n"
        f"Also: firewall drops / IDS / auth fail from same IP\n"
        f"Refs:\n"
        f"  VT https://www.virustotal.com/gui/ip-address/{ip}\n"
        f"  AbuseIPDB https://www.abuseipdb.com/check/{ip}\n"
        f"  GreyNoise https://viz.greynoise.io/ip/{ip}\n"
        f"Via: kit-cloud SoC (Kowalski, analysis)\n"
        f"Contact: admin@kit-cloud.com for more context on this IOC."
    )


def post(vt, ip, text):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    body = json.dumps({"data": {"type": "comment", "attributes": {"text": text}}}).encode()
    req = urllib.request.Request(
        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}/comments",
        data=body,
        headers={"x-apikey": vt, "User-Agent": "soc-orchestrator/1.0", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=30) as r:
            return r.status, "ok"
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:160]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--max", type=int, default=25, help="max comments this run")
    ap.add_argument("--days", type=int, default=7)
    args = ap.parse_args()
    cfg, vt = load_cfg()
    global SENSOR
    SENSOR = sensor_map(cfg)
    used = daily_used()
    room = max(0, DAILY_CAP - used)
    limit = min(args.max, room)
    print(f"daily_used={used} cap={DAILY_CAP} this_run={limit}")
    if limit <= 0:
        print("daily VT comment cap reached")
        return
    m = MISPClient(cfg["misp"]["url"], cfg["misp"]["api_key"], verify_tls=False)
    attrs = (m.get_event(1932).get("Event") or {}).get("Attribute") or []
    cut = datetime.now(timezone.utc) - timedelta(days=args.days)
    done = ledger()
    todo = []
    for a in attrs:
        ts = int(a.get("timestamp") or 0)
        if not ts:
            continue
        dt = datetime.fromtimestamp(ts, timezone.utc)
        if dt < cut:
            continue
        ip = a.get("value") or ""
        if ip in done or "/" in ip:
            continue
        meta = parse_safe(a.get("comment") or "")
        if not worth(ip, meta):
            continue
        todo.append((dt, ip, meta))
    todo.sort()
    print(f"candidates={len(todo)} posting={min(limit, len(todo))}")
    posted = 0
    for dt, ip, meta in todo[:limit]:
        text = comment_text(ip, meta, dt.strftime("%Y-%m-%d"))
        status, msg = post(vt, ip, text)
        if status == 429:
            print("429 quota/rate — stop")
            time.sleep(5)
            break
        if status in (200, 201) or (status in (400, 409) and "already" in msg.lower()):
            remember(ip)
            posted += 1
            print(f"OK {ip}")
        else:
            print(f"ERR {ip} {status} {msg[:100]}")
        time.sleep(DELAY)
    if posted:
        daily_add(posted)
    print(f"posted={posted}")


def parse_safe(cmt):
    def grab(pat, default="0"):
        m = re.search(pat, cmt or "")
        return m.group(1) if m else default
    return {
        "count": grab(r"Wazuh:\s*(\d+)x"),
        "lvl": grab(r"lvl=(\d+)"),
        "otx": grab(r"pulses=(\d+)"),
        "aip": grab(r"AIPDB:\s*score=(\d+)"),
        "isp": grab(r"isp=([^|]+)", "").strip(),
    }


if __name__ == "__main__":
    main()
