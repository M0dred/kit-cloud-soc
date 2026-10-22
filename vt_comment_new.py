#!/usr/bin/env python3
"""Publish a few vetted SSH-source observations from MISP 1932 to VT.

Uses the SAME renderer as MISP; never votes or auto-blocks. The local daily
cap is a safety limit, NOT a statement about the VT account's actual quota.
"""
from __future__ import annotations

import argparse
import fcntl
import ipaddress
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone, timedelta
from pathlib import Path

import yaml
from ioc_comment import render_comment

sys.path.insert(0, str(Path.home() / ".config/agents/skills/soc-connector/scripts"))
from misp_client import MISPClient  # noqa: E402

BASE = Path.home() / ".config/soc-orchestrator"
LEDGER = BASE / "vt-commented.txt"
DAILY = BASE / "vt-comment-daily.json"
CONFIG = BASE / "config.yaml"
CACHE = BASE / "enrich-cache.json"
DAILY_CAP = 6
DELAY = 20  # less than four VT writes per minute


def parse_comment(text: str) -> dict:
    """Read both the former one-line MISP notes and our structured comments."""
    def grab(pattern, default=""):
        hit = re.search(pattern, text or "", flags=re.I)
        return hit.group(1).strip() if hit else default

    return {
        "count": int(grab(r"Wazuh:\s*(\d+)x") or grab(r"Wazuh\s+(\d+)\s+alerts") or 0),
        "level": int(grab(r"lvl=(\d+)") or grab(r"alerts,\s*level\s+(\d+)") or 0),
        "rule": grab(r"\bRule:\s*([^\n]+)", ""),
        "agent": grab(r"\bTarget:\s*([\w-]+)", ""),
        "otx": int(grab(r"(?:OTX:\s*)?pulses=(\d+)") or 0),
        "aip": int(grab(r"(?:AIPDB:\s*score|AbuseIPDB)=(\d+)") or 0),
        "gn": grab(r"GreyNoise=([\w-]+)", ""),
        "isp": grab(r"isp=([^|\n]+)", ""),
    }


def cloud_range(ip: str) -> bool:
    """Conservative skip for broadly cloud-associated IPv4 ranges."""
    a, b = [int(x) for x in ip.split(".")[:2]]
    return (a in (13, 20, 34, 35, 40, 52) or
            a == 104 and 16 <= b <= 31 or
            a == 172 and 64 <= b <= 71 or
            (a, b) in ((162, 158), (141, 101), (108, 162)))


def public_ip(value: str) -> bool:
    try:
        addr = ipaddress.ip_address(value)
        return addr.version == 4 and addr.is_global
    except ValueError:
        return False


def eligible(ip: str, meta: dict, intel: dict) -> bool:
    """Only SSH auth-failure evidence corroborated independently; no cloud/web 400."""
    if not public_ip(ip) or cloud_range(ip):
        return False
    rule = meta["rule"].lower()
    if not ("sshd" in rule or ("ssh" in rule and any(word in rule for word in ("failed", "invalid", "brute", "auth")))):
        return False
    if meta["count"] < 20 or meta["level"] < 10:
        return False
    ab = intel.get("aipdb") or {}
    gn = intel.get("gn") or {}
    otx = intel.get("otx") or {}
    isp = str(ab.get("isp") or meta.get("isp") or "").lower()
    if any(word in isp for word in ("google", "microsoft", "azure", "amazon", "cloudflare", "oracle")):
        return False
    if gn.get("riot") is True or gn.get("classification") == "benign":
        return False
    return (str(gn.get("classification") or meta["gn"]).lower() == "malicious"
            or int(ab.get("score") or meta["aip"] or 0) >= 80
            or int(otx.get("pulses") or meta["otx"] or 0) >= 5)


def daily_used() -> int:
    if not DAILY.exists():
        return 0
    d = json.loads(DAILY.read_text())
    if d.get("date") != datetime.now(timezone.utc).strftime("%Y-%m-%d"):
        return 0
    return int(d.get("used") or 0)


def mark_sent(ip: str) -> None:
    with LEDGER.open("a") as fh:
        fh.write(ip + "\n")
        fh.flush()
        os.fsync(fh.fileno())
    tmp = DAILY.with_suffix(".tmp")
    tmp.write_text(json.dumps({"date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                               "used": daily_used() + 1}))
    tmp.replace(DAILY)


def post(vt_key: str, ip: str, text: str) -> tuple[int, str]:
    body = json.dumps({"data": {"type": "comment", "attributes": {"text": text}}}).encode()
    req = urllib.request.Request(
        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}/comments",
        data=body, headers={"x-apikey": vt_key, "Content-Type": "application/json",
                            "User-Agent": "kit-cloud-soc/2.0"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as response:  # verify public TLS certificate
            return response.status, "ok"
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode(errors="replace")[:160]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--max", type=int, default=3, help="maximum comments in this invocation")
    ap.add_argument("--days", type=int, default=7)
    ap.add_argument("--dry-run", action="store_true", help="preview candidates, no posts or ledger changes")
    args = ap.parse_args()
    if args.max < 0 or args.days < 0:
        ap.error("--max and --days must be non-negative")
    cfg = yaml.safe_load(CONFIG.read_text())
    lock = BASE / "vt-comment.lock"
    with lock.open("a+") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        done = set(LEDGER.read_text().splitlines()) if LEDGER.exists() else set()
        used = daily_used()
        limit = min(args.max, max(0, DAILY_CAP - used))
        print(f"daily_used={used} local_cap={DAILY_CAP} this_run={limit}")
        if limit == 0:
            return 0
        misp = MISPClient(cfg["misp"]["url"], cfg["misp"]["api_key"],
                          verify_tls=cfg["misp"].get("verify_tls", True))
        event = misp.get_event(cfg["misp"].get("event_id", 1932))
        if event.get("_error") or not isinstance(event.get("Event"), dict):
            raise RuntimeError("MISP event fetch failed; not treating errors as zero candidates")
        cache = json.loads(CACHE.read_text()) if CACHE.exists() else {}
        cutoff = datetime.now(timezone.utc) - timedelta(days=args.days)
        todo = []
        for attr in event["Event"].get("Attribute", []):
            if attr.get("type") not in ("ip-src", "ip-dst"):
                continue  # old Event 1932 records used ip-dst for inbound sources
            ip = attr.get("value") or ""
            if ip in done or not public_ip(ip):
                continue
            ts = int(attr.get("timestamp") or 0)
            if not ts or datetime.fromtimestamp(ts, timezone.utc) < cutoff:
                continue
            meta = parse_comment(attr.get("comment") or "")
            intel = cache.get(ip) or {}
            if not eligible(ip, meta, intel):
                continue
            todo.append((ts, ip, meta, intel))
        todo.sort(reverse=True)
        print(f"candidates={len(todo)} posting={min(limit, len(todo))}")
        for _, ip, meta, _ in todo[:min(limit, len(todo))]:
            print(f"candidate {ip} count={meta['count']} level={meta['level']} rule={meta['rule'][:75]}")
        if args.dry_run or not todo:
            return 0
        key = cfg["virustotal"]["api_key"]
        failed = 0
        posted = 0
        for _, ip, meta, intel in todo[:limit]:
            text = render_comment(ip, meta["count"], meta["agent"], meta["rule"],
                                  intel=intel, level=meta["level"],
                                  sensor_public_ips=cfg.get("sensor_public_ips"))
            code, message = post(key, ip, text)
            if code in (200, 201):
                mark_sent(ip)
                posted += 1
                print(f"OK {ip}")
            elif code in (400, 409) and "already" in message.lower():
                mark_sent(ip)
                print(f"already posted {ip}")
            elif code == 429:
                print("429 quota/rate — stopped", file=sys.stderr)
                failed = 1
                break
            else:
                print(f"ERR {ip} HTTP {code}", file=sys.stderr)
                failed = 1
            if posted < limit:
                time.sleep(DELAY)
        print(f"posted={posted}")
        return failed


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print(f"VT comment job failed: {type(exc).__name__}: {str(exc)[:120]}", file=sys.stderr)
        sys.exit(1)
