#!/usr/bin/env python3
"""Generate a static SOC dashboard (docs/index.html + data.json) for GitHub Pages.

No server, no JS deps beyond vanilla — reads local SoC state and writes JSON + HTML.
Secrets are never included: only counts, IPs (public attackers), and run history.
"""
import ipaddress
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
OUT = BASE / "dashboard"  # local detailed dashboard
PUBLIC = BASE / "docs"  # restricted, review-only public GitHub Pages data
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE



def _is_private(ip):
    import ipaddress
    try:
        a = ipaddress.ip_address(ip)
        return a.version != 4 or not a.is_global
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
    m = MISPClient(cfg["misp"]["url"], cfg["misp"]["api_key"],
                   verify_tls=cfg["misp"].get("verify_tls", True))
    event = m.get_event(cfg["misp"].get("event_id", 1932))
    if event.get("_error") or not isinstance(event.get("Event"), dict):
        raise RuntimeError("MISP event fetch failed")
    attrs = event["Event"].get("Attribute") or []
    ips = [a for a in attrs if a.get("type") in ("ip-src", "ip-dst")]
    cidrs = [a["value"] for a in ips if "/" in a.get("value", "")]
    recent = []
    now = datetime.now(timezone.utc)
    for a in ips:
        ts = int(a.get("timestamp") or 0)
        if ts and (now - datetime.fromtimestamp(ts, timezone.utc)).days <= 14 and not _is_private(a.get("value") or ""):
            recent.append({"ip": a["value"], "date": datetime.fromtimestamp(ts, timezone.utc).strftime("%m-%d"),
                           "comment": (a.get("comment") or "")[:200]})
    recent.sort(key=lambda x: x["date"], reverse=True)
    # Public watchlist is smaller than the internal blocklist: require corroborated SSH evidence.
    from vt_comment_new import eligible, parse_comment
    cache_file = BASE / "enrich-cache.json"
    cache = json.loads(cache_file.read_text()) if cache_file.exists() else {}
    sensor_ips = set((cfg.get("sensor_public_ips") or {}).values())
    watchlist = sorted({a["value"] for a in ips if a.get("to_ids") in (True, 1, "1") and
                        a.get("value") not in sensor_ips and
                        eligible(a["value"], parse_comment(a.get("comment") or ""),
                                 cache.get(a["value"]) or {})})
    return {"total": len(ips), "cidrs": cidrs, "recent_14d": recent[:30],
            "watchlist": watchlist}


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

    # Nothing sensitive or unreviewed from local health, notes or alert comments
    # should be mirrored to the public GitHub Pages folder.
    if not isinstance(data.get("wazuh", {}).get("top_src"), list) or not isinstance(data.get("misp", {}).get("watchlist"), list):
        raise RuntimeError("dashboard inputs incomplete; refusing to publish stale/unsafe data")
    waz = data["wazuh"]
    misp = data["misp"]
    sensor_ips = set((yaml.safe_load((BASE / "config.yaml").read_text()).get("sensor_public_ips") or {}).values())
    public_src = [(ip, n) for ip, n in waz["top_src"] if ip not in sensor_ips and not _is_private(ip)]
    top = {ip for ip, _ in public_src}
    public = {
        "generated": data["generated"],
        "wazuh": {
            "total_7d": waz.get("total_7d", 0),
            "by_agent": [[f"Sensor {i+1}", n] for i, (_, n) in enumerate(waz.get("by_agent", []))],
            "top_src": public_src, "by_day": waz.get("by_day", []),
        },
        "misp": {
            "total": misp["total"], "cidrs": [],
            "recent_14d": [{"ip": x["ip"], "date": x["date"], "comment": "Observed source; review locally"}
                           for x in misp["recent_14d"] if x["ip"] not in sensor_ips],
        },
        "vt": data.get("vt", {}),
        "health": {"agents_down": "withheld"},
        "runs": [{"ts": x["ts"], "status": x["status"], "why": ""} for x in data["runs"]],
        "blocklist_n": len(misp["watchlist"]),
        "enrich_meta": {
            ip: {k: (re.sub(r"[^\w .,/()\-]", "", str(v))[:35] if isinstance(v, str) else v)
                 for k, v in (meta or {}).items() if k in ("gn", "otx", "aip", "asn", "country", "org")}
            for ip, meta in (data.get("enrich_meta") or {}).items() if ip in top
        },
    }
    PUBLIC.mkdir(exist_ok=True)
    (PUBLIC / "data.json").write_text(json.dumps(public, indent=1) + "\n")
    edl = [
        "# kit-cloud SoC public watchlist — REVIEW BEFORE BLOCKING; not proof of compromise",
        "# Observed IPv4 sources with SSH authentication-failure evidence and independent reports",
        "# Derived from curated MISP Event 1932; excludes unreviewed internal blocklist entries",
        "# contact: admin@kit-cloud.com",
        "",
    ] + misp["watchlist"]
    (PUBLIC / "blocklist.txt").write_text("\n".join(edl) + "\n")
    print(f"public watchlist written {len(misp['watchlist'])} IPs")
    print("public data.json written", len(json.dumps(public)), "bytes")
    print(json.dumps({k: (v if not isinstance(v, dict) else list(v.keys())) for k, v in data.items()}, indent=1)[:400])


if __name__ == "__main__":
    main()
