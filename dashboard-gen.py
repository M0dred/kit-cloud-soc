#!/usr/bin/env python3
"""Generate a static SOC dashboard (docs/index.html + data.json) for GitHub Pages.

No server, no JS deps beyond vanilla — reads local SoC state and writes JSON + HTML.
Secrets are never included: only counts, IPs (public attackers), and run history.
"""
import json
import re
import ssl
import sys
import urllib.request
import base64
from collections import Counter
from datetime import datetime, timezone, timedelta
from pathlib import Path

sys.path.insert(0, str(Path.home() / ".config/agents/skills/soc-connector/scripts"))
from misp_client import MISPClient  # noqa: E402
import yaml  # noqa: E402

BASE = Path.home() / ".config/soc-orchestrator"
OUT = BASE / "dashboard"
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE



def _is_private(ip):
    import ipaddress
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local
    except ValueError:
        return True


def _pub(b):
    return (b["key"], b["doc_count"])


def wazuh_7d():
    cfg = BASE.joinpath("config.yaml").read_text()
    u = re.search(r'indexer_user:\s*"([^"]+)"', cfg).group(1)
    p = re.search(r'indexer_pass:\s*"([^"]+)"', cfg).group(1)
    auth = "Basic " + base64.b64encode(f"{u}:{p}".encode()).decode()
    body = json.dumps({
        "size": 0,
        "query": {"range": {"timestamp": {"gte": "now-7d"}}},
        "aggs": {
            "agents": {"terms": {"field": "agent.name", "size": 10}},
            "src": {"terms": {"field": "data.srcip", "size": 20}},
            "days": {"date_histogram": {"field": "timestamp", "calendar_interval": "day"}},
        },
    }).encode()
    req = urllib.request.Request(
        "https://10.0.1.1:9200/wazuh-alerts-4.x-*/_search",
        data=body, headers={"Authorization": auth, "Content-Type": "application/json"}, method="POST")
    d = json.loads(urllib.request.urlopen(req, context=CTX, timeout=40).read())
    ag = d["aggregations"]
    return {
        "total_7d": sum(b["doc_count"] for b in ag["agents"]["buckets"]),
        "by_agent": [(b["key"], b["doc_count"]) for b in ag["agents"]["buckets"]],
        "top_src": [(b["key"], b["doc_count"]) for b in ag["src"]["buckets"] if not _is_private(b["key"])],
        "by_day": [(b["key_as_string"][:10], b["doc_count"]) for b in ag["days"]["buckets"]],
    }


def misp_1932():
    cfg = yaml.safe_load(BASE.joinpath("config.yaml").read_text())
    m = MISPClient(cfg["misp"]["url"], cfg["misp"]["api_key"], verify_tls=False)
    attrs = (m.get_event(1932).get("Event") or {}).get("Attribute") or []
    ips = [a for a in attrs if a.get("type") == "ip-dst"]
    cidrs = [a["value"] for a in ips if "/" in a.get("value", "")]
    recent = []
    now = datetime.now(timezone.utc)
    for a in attrs:
        ts = int(a.get("timestamp") or 0)
        if ts and (now - datetime.fromtimestamp(ts, timezone.utc)).days <= 14:
            recent.append({"ip": a["value"], "date": datetime.fromtimestamp(ts, timezone.utc).strftime("%m-%d"),
                           "comment": (a.get("comment") or "")[:200]})
    recent.sort(key=lambda x: x["date"], reverse=True)
    return {"total": len(ips), "cidrs": cidrs, "recent_14d": recent[:30]}


def runs():
    lines = (BASE / "cron.log").read_text().splitlines()
    out = []
    for l in lines:
        m = re.match(r"(\S+) END (ok|FAIL: .*)", l)
        if m:
            out.append({"ts": m.group(1), "status": "ok" if m.group(2) == "ok" else "fail", "why": m.group(2)[5:] if m.group(2) != "ok" else ""})
    return out[-40:]


def vt_ledger():
    f = BASE / "vt-commented.txt"
    if not f.exists():
        return {"posted_total": 0}
    ips = [l.strip() for l in f.read_text().splitlines() if l.strip()]
    return {"posted_total": len(ips)}


def health():
    import subprocess
    r = subprocess.run(["python3", str(BASE / "health-check.py")], capture_output=True, text=True, timeout=60)
    agents = ""
    for l in r.stdout.splitlines():
        if l.startswith("agents_down="):
            agents = l.split("=", 1)[1]
    return {"agents_down": agents or "none", "checked": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}



def enrich_meta_for(ips):
    """ASN/geo/GN/AIPDB/OTX per IP from local threat DB (offline, no API calls)."""
    import sqlite3, json as _json
    db = Path.home() / ".config/linux-log-threat-hunt/threat-intel.db"
    if not db.exists():
        return {}
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    out = {}
    for ip in ips:
        out[ip] = {}
    con.close()
    # primary source: orchestrator enrich cache (GN/OTX/AIPDB live results)
    cache_path = Path.home() / ".config/soc-orchestrator/enrich-cache.json"
    if cache_path.exists():
        cache = _json.loads(cache_path.read_text() or "{}")
        for ip in ips:
            c = cache.get(ip) or {}
            meta = {}
            gn = c.get("gn") or {}
            if isinstance(gn, dict) and gn.get("classification"):
                meta["gn"] = str(gn["classification"])[:12]
                if gn.get("name"):
                    meta["org"] = str(gn["name"])[:28]
            otx = c.get("otx") or {}
            if isinstance(otx, dict) and otx.get("pulses") is not None:
                meta["otx"] = otx.get("pulses")
                if otx.get("cc"):
                    meta["country"] = str(otx["cc"])[:2].upper()
            ab = c.get("aipdb") or {}
            if isinstance(ab, dict) and ab.get("score") is not None:
                meta["aip"] = ab.get("score")
                if ab.get("isp"):
                    meta["asn"] = str(ab["isp"])[:30]
                if ab.get("cc"):
                    meta.setdefault("country", str(ab["cc"])[:2].upper())
            if meta:
                out.setdefault(ip, {}).update(meta)
    # fallback: VT AS/country from threat DB evidence
    db = Path.home() / ".config/linux-log-threat-hunt/threat-intel.db"
    if db.exists():
        con = sqlite3.connect(db)
        con.row_factory = sqlite3.Row
        for ip in ips:
            if out.get(ip, {}).get("asn"):
                continue
            row = con.execute("select evidence from iocs where ip=?", (ip,)).fetchone()
            if row:
                ev = _json.loads(row["evidence"] or "{}")
                if ev.get("as_owner"):
                    out.setdefault(ip, {})["asn"] = str(ev["as_owner"])[:30]
                if ev.get("country"):
                    out.setdefault(ip, {}).setdefault("country", ev["country"][:2].upper())
        con.close()
    return out


def main():
    data = {"generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}
    for key, fn in [("wazuh", wazuh_7d), ("misp", misp_1932), ("vt", vt_ledger), ("health", health)]:
        try:
            data[key] = fn()
        except Exception as e:
            data[key] = {"error": str(e)[:120]}
    data["runs"] = runs()
    try:
        top = [x[0] for x in (data.get("wazuh") or {}).get("top_src") or []][:20]
        data["enrich_meta"] = enrich_meta_for(top)
    except Exception as e:
        data["enrich_meta"] = {"error": str(e)[:100]}
    bl = BASE / "soc_blocklist.txt"
    data["blocklist_n"] = len([l for l in bl.read_text().splitlines() if l.strip() and not l.startswith("#")]) if bl.exists() else 0

    OUT.mkdir(exist_ok=True)
    (OUT / "data.json").write_text(json.dumps(data, indent=1))
    print("data.json written", len(json.dumps(data)), "bytes")
    print(json.dumps({k: (v if not isinstance(v, dict) else list(v.keys())) for k, v in data.items()}, indent=1)[:400])


if __name__ == "__main__":
    main()
