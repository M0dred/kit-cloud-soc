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
from source_policy import protected_ips, shareable, ssh_failure_sample, fresh_intel, authenticated_failures

_skill = Path.home() / ".config/agents/skills/soc-connector/scripts"
if not (_skill / "misp_client.py").exists():
    _skill = Path(__file__).resolve().parent / "src/soc-connector"  # offline repository tests
sys.path.insert(0, str(_skill))
from misp_client import MISPClient  # noqa: E402
from soc_contracts import published_event

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


def shortlisted(ip, meta, intel, excluded, now=None):
    """Pre-filter only, never sufficient to share. Old scores are not evidence."""
    if not shareable(ip, excluded) or cloud_range(ip):
        return False
    if not ssh_failure_sample(meta['rule']):
        return False
    if meta["count"] < 20 or meta["level"] < 10:
        return False
    ab = intel.get("aipdb") or {}
    gn = intel.get("gn") or {}
    isp = str(ab.get("isp") or meta.get("isp") or "").lower()
    if any(word in isp for word in ("google", "microsoft", "azure", "amazon", "cloudflare", "oracle")):
        return False
    if gn.get("riot") is True or gn.get("classification") == "benign":
        return False
    fresh = fresh_intel(intel, now)
    score = fresh.get('aipdb', {}).get('score'); pulses = fresh.get('otx', {}).get('pulses')
    return (fresh.get('gn', {}).get('classification') == 'malicious' or
            type(score) is int and 80 <= score <= 100 or type(pulses) is int and pulses >= 5)


def eligible(ip, meta, intel, proof=None, *, excluded=None, now=None):
    if excluded is None or not shortlisted(ip, meta, intel, excluded, now) or not isinstance(proof, dict):
        return False
    try:
        last = datetime.fromisoformat(proof['last_seen'].replace('Z','+00:00'))
        age = (now or datetime.now(timezone.utc)) - last
        return (timedelta(0) <= age <= timedelta(hours=24) and type(proof['count']) is int and proof['count'] >= 20 and
                type(proof['level']) is int and 10 <= proof['level'] <= 16)
    except (AttributeError, KeyError, TypeError, ValueError):
        return False


def daily_used() -> int:
    d = json.loads(DAILY.read_text())  # a missing ledger is unknown, not a fresh quota
    day = datetime.strptime(d['date'], '%Y-%m-%d').date()
    today = datetime.now(timezone.utc).date()
    used = d.get('used')
    if day > today or type(used) is not int or not 0 <= used <= DAILY_CAP:
        raise ValueError('invalid VT budget ledger; refusing to post')
    return used if day == today else 0


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
    excluded = protected_ips(cfg.get('sensor_public_ips'))
    lock = BASE / "vt-comment.lock"
    with lock.open("a+") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        done = set(LEDGER.read_text().splitlines())  # missing dedup history must fail closed
        used = daily_used()
        limit = min(3, args.max, max(0, DAILY_CAP - used))
        print(f"daily_used={used} local_cap={DAILY_CAP} this_run={limit}")
        if limit == 0:
            return 0
        misp = MISPClient(cfg["misp"]["url"], cfg["misp"]["api_key"],
                          verify_tls=cfg["misp"].get("verify_tls", True))
        eid = cfg['misp'].get('event_id', 1932)
        event = published_event(misp.get_event(eid), eid)
        cache = json.loads(CACHE.read_text()) if CACHE.exists() else {}
        cutoff = datetime.now(timezone.utc) - timedelta(days=args.days)
        todo = []
        for attr in event['Attribute']:
            if attr.get("type") not in ("ip-src", "ip-dst"):
                continue  # old Event 1932 records used ip-dst for inbound sources
            ip = attr.get("value") or ""
            if ip in done or not shareable(ip, excluded):
                continue
            ts = int(attr.get("timestamp") or 0)
            if not ts or not cutoff <= datetime.fromtimestamp(ts, timezone.utc) <= datetime.now(timezone.utc):
                continue
            meta = parse_comment(attr.get("comment") or "")
            intel = cache.get(ip) or {}
            if not shortlisted(ip, meta, intel, excluded):
                continue
            todo.append((ts, ip, meta, intel))
        proofs = authenticated_failures(cfg, [ip for _, ip, _, _ in todo])
        todo.sort(key=lambda row: row[0], reverse=True)
        # Legacy ip-dst and ip-src may describe the same source. At most one post per IP.
        unique = set()
        selected = []
        for row in todo:
            _, ip, meta, intel = row
            if ip not in unique and eligible(ip, meta, intel, proofs.get(ip), excluded=excluded):
                selected.append(row); unique.add(ip)
        todo = selected
        print(f"candidates={len(todo)} posting={min(limit, len(todo))}")
        for _, ip, _, _ in todo[:limit]:
            print(f"candidate {ip} verified SSH failure alerts={proofs[ip]['count']} max_level={proofs[ip]['level']}")
        if args.dry_run or not todo:
            return 0
        key = cfg["virustotal"]["api_key"]
        failed = 0
        posted = 0
        for _, ip, meta, intel in todo[:limit]:
            if not eligible(ip, meta, intel, proofs.get(ip), excluded=excluded):
                continue  # age may cross the boundary while waiting to post
            proof = proofs[ip]
            text = render_comment(ip, proof['count'], None, 'SSH authentication failure',
                                  intel=fresh_intel(intel), level=proof['level'], observed_at=proof['last_seen'],
                                  sensor_public_ips=cfg.get("sensor_public_ips"),
                                  format_vt=True)
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
