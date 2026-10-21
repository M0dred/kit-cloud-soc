#!/usr/bin/env python3
"""Resume VT comments for MISP Event 1930 IPs using the SOC comment template.

Idempotent: skips IPs that already have an SOC Orchestrator / box-iocs comment.
Progress is persisted so the job can be restarted after quota or reboot.
"""
from __future__ import annotations

import json
import os
import ssl
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

BASE = Path.home() / ".config/soc-orchestrator"
IP_FILE = BASE / "misp1930-ips.txt"
PROGRESS_FILE = BASE / "vt-comments-progress.json"
LOG_FILE = BASE / "vt-comments.log"
DELAY_GET = 0.4
DELAY_POST = 20
COMMENT_TEMPLATE = (
    "Date: {date}\n"
    "Category: Reconnaissance\n"
    "Confidence: Medium\n"
    "Observed Behavior: Detected in curated IOC list (box-iocs.txt)\n"
    "Target: sensor-syd / internal mesh networks\n"
    "Source: /tmp/box-iocs.txt (SOC Orchestrator enrichment)\n"
    "TTPs: T1046 Network Service Discovery\n"
    "Auto-reported via SOC Orchestrator."
)


def log(msg: str) -> None:
    line = f"{datetime.now(timezone.utc).isoformat()} {msg}"
    print(line, flush=True)
    with LOG_FILE.open("a") as fh:
        fh.write(line + "\n")


def load_vt_key() -> str:
    import re

    cfg = (BASE / "config.yaml").read_text()
    m = re.search(r'api_key:\s*"([^"]+)"', cfg.split("virustotal")[1])
    if not m:
        raise SystemExit("VT api_key not found in config.yaml")
    return m.group(1)


def load_progress() -> dict:
    if PROGRESS_FILE.exists():
        return json.loads(PROGRESS_FILE.read_text())
    return {
        "done_have": [],
        "done_posted": [],
        "errors": {},
        "started": datetime.now(timezone.utc).isoformat(),
    }


def save_progress(p: dict) -> None:
    p["updated"] = datetime.now(timezone.utc).isoformat()
    PROGRESS_FILE.write_text(json.dumps(p, indent=2))


def vt_request(url: str, key: str, data: bytes | None = None, method: str | None = None) -> dict:
    headers = {
        "x-apikey": key,
        "User-Agent": "soc-connector/1.0",
        "Accept": "application/json",
    }
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return {"ok": True, "status": r.status, "body": json.loads(r.read().decode())}
    except urllib.error.HTTPError as e:
        body = e.read().decode()[:400]
        return {"ok": False, "status": e.code, "body": body}
    except Exception as e:
        return {"ok": False, "status": 0, "body": str(e)[:200]}


def has_our_comment(body: dict) -> bool:
    for c in body.get("data") or []:
        text = ((c.get("attributes") or {}).get("text") or "")
        if "SOC Orchestrator" in text or "box-iocs" in text:
            return True
    return False


def post_comment(ip: str, key: str) -> dict:
    text = COMMENT_TEMPLATE.format(date=datetime.now(timezone.utc).strftime("%Y-%m-%d"))
    payload = json.dumps(
        {"data": {"type": "comment", "attributes": {"text": text}}}
    ).encode()
    return vt_request(
        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}/comments",
        key,
        data=payload,
        method="POST",
    )


def main() -> None:
    BASE.mkdir(parents=True, exist_ok=True)
    if not IP_FILE.exists():
        raise SystemExit(f"missing {IP_FILE}")
    ips = [ln.strip() for ln in IP_FILE.read_text().splitlines() if ln.strip()]
    key = load_vt_key()
    progress = load_progress()
    skip = set(progress.get("done_have") or []) | set(progress.get("done_posted") or [])
    remaining = [ip for ip in ips if ip not in skip]
    log(f"[START] total={len(ips)} skip={len(skip)} remaining={len(remaining)}")

    posted = 0
    already = 0
    errors = 0
    for i, ip in enumerate(remaining, 1):
        got = vt_request(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}/comments?limit=10",
            key,
        )
        if not got["ok"]:
            if got["status"] == 429:
                log(f"[QUOTA] GET {ip} rate/quota limited — stopping. posted={posted} already={already} errors={errors}")
                save_progress(progress)
                return
            errors += 1
            progress["errors"][ip] = f"GET {got['status']} {got['body'][:80]}"
            log(f"[{i}/{len(remaining)}] {ip} GET error {got['status']}")
            time.sleep(2)
            continue

        if has_our_comment(got["body"]):
            already += 1
            progress["done_have"].append(ip)
            if i % 10 == 0:
                log(f"[PROGRESS] {i}/{len(remaining)} posted={posted} already={already} errors={errors}")
                save_progress(progress)
            time.sleep(DELAY_GET)
            continue

        res = post_comment(ip, key)
        if res["ok"]:
            posted += 1
            progress["done_posted"].append(ip)
            log(f"[{i}/{len(remaining)}] {ip} POSTED")
        elif res["status"] == 429:
            log(f"[QUOTA] POST {ip} — stopping. posted={posted} already={already} errors={errors}")
            save_progress(progress)
            return
        else:
            errors += 1
            progress["errors"][ip] = f"POST {res['status']} {res['body'][:80]}"
            log(f"[{i}/{len(remaining)}] {ip} POST error {res['status']} {res['body'][:120]}")
        save_progress(progress)
        time.sleep(DELAY_POST)

    save_progress(progress)
    log(f"[DONE] posted={posted} already={already} errors={errors}")


if __name__ == "__main__":
    main()
