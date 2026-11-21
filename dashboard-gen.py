#!/usr/bin/env python3
"""Generate a private SOC snapshot and an allowlisted public GitHub Pages view.

Never publish asset-level evidence, raw events, victim addresses or secrets.
Source IPs are observations for investigation, not verified attackers.
"""
import ipaddress
import json
import re
import ssl
import sys
import urllib.request
import base64
from datetime import datetime, timezone, timedelta
from pathlib import Path

_skill = Path.home() / ".config/agents/skills/soc-connector/scripts"
if not (_skill / "misp_client.py").exists():
    _skill = Path(__file__).resolve().parent / "src/soc-connector"  # offline repository tests
sys.path.insert(0, str(_skill))
from misp_client import MISPClient  # noqa: E402
from soc_contracts import complete_search, published_event
from wazuh_indexer import WazuhIndexerClient
from source_policy import protected_ips, public_unicast, authenticated_failures, iso_country
import yaml  # noqa: E402

BASE = Path.home() / ".config/soc-orchestrator"
THREAT_DB = Path.home() / ".config/linux-log-threat-hunt/threat-intel.db"
OUT = BASE / "dashboard"  # local detailed dashboard
PUBLIC = BASE / "docs"  # restricted, review-only public GitHub Pages data
# Connection details and TLS policy come only from private configuration.



def _is_private(ip):
    return not public_unicast(ip)


def utc_timestamp(raw):
    if not isinstance(raw, str):
        return None
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        return parsed.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC") if parsed.tzinfo else None
    except ValueError:
        return None


def parse_wazuh_rollup(d):
    """Use OpenSearch's exact hit total, never a sum of truncated top-N buckets."""
    complete_search(d)
    total = d["hits"]["total"]
    if isinstance(total, dict):
        if total.get("relation") != "eq":
            raise ValueError("Wazuh hit count is a lower bound, not an exact total")
        total = total["value"]
    ag = d["aggregations"]
    source_samples = {}
    for bucket in ag["src"]["buckets"]:
        ip = bucket["key"]
        if _is_private(ip):
            continue
        samples = []
        for hit in ((bucket.get("sample") or {}).get("hits") or {}).get("hits", []):
            doc = hit.get("_source") or {}
            data = doc.get("data") or {}
            if data.get("srcip") != ip:
                continue
            rule = doc.get("rule") or {}
            agent = doc.get("agent") or {}
            samples.append({"time_utc": utc_timestamp(doc.get("timestamp")),
                            "event_id": str(hit.get("_id") or "")[:128],
                            "source_ip": ip, "destination_ip": data.get("dstip"),
                            "destination_port": data.get("dstport"), "agent_id": agent.get("id"),
                            "agent_name": agent.get("name"), "rule_id": rule.get("id"),
                            "rule_level": rule.get("level"), "rule": str(rule.get("description") or "")[:180]})
        source_samples[ip] = samples
    return {
        "total_7d": int(total),
        "by_agent": [(b["key"], b["doc_count"]) for b in ag["agents"]["buckets"]],
        "top_src": [(b["key"], b["doc_count"]) for b in ag["src"]["buckets"] if not _is_private(b["key"])],
        "by_day": [(b["key_as_string"][:10], b["doc_count"]) for b in ag["days"]["buckets"]],
        "samples_by_source": source_samples,  # private only; never copy into docs/
    }


def public_sample_context(samples):
    """Public, fixed-vocabulary description of a *sample*, never its raw rule/asset.

    Top-three samples are not a complete timeline or a dominant-behavior count.
    """
    latest = None
    for item in samples[:3]:
        stamp = str(item.get("time_utc") or "")
        try:
            datetime.strptime(stamp, "%Y-%m-%d %H:%M:%S UTC")
            if latest is None or stamp > latest:
                latest = stamp
        except ValueError:
            pass
    if not samples:
        return {"last_sample_utc": None, "sample_behavior": "No alert sample available"}
    sample = samples[0]
    desc = str(sample.get("rule") or "").lower()
    if "ssh" in desc or "sshd" in desc:
        behavior = "SSH authentication alert"
    elif any(word in desc for word in ("http", "web server", "nginx", "apache")):
        behavior = "Web request alert (outcome unverified)"
    else:
        behavior = "Other detection (sample only)"
    return {"last_sample_utc": latest, "sample_behavior": behavior}


def wazuh_7d():
    w = yaml.safe_load((BASE/'config.yaml').read_text())['wazuh']
    client = WazuhIndexerClient(w['indexer_host'], w['indexer_user'], w['indexer_pass'], verify_tls=w.get('verify_tls',True))
    body = {
        "size": 0,
        "track_total_hits": True,
        "query": {"range": {"timestamp": {"gte": "now-7d"}}},
        "aggs": {
            "agents": {"terms": {"field": "agent.name", "size": 10}},
            "src": {"terms": {"field": "data.srcip", "size": 20},
                    "aggs": {"sample": {"top_hits": {"size": 3,
                        "sort": [{"timestamp": {"order": "desc"}}],
                        "_source": ["timestamp", "data.srcip", "data.dstip", "data.dstport",
                                    "agent.id", "agent.name", "rule.id", "rule.level", "rule.description"]}}}},
            "days": {"date_histogram": {"field": "timestamp", "calendar_interval": "day"}},
        },
    }
    return parse_wazuh_rollup(client.query_alerts(body, index='wazuh-alerts-4.x-*'))


def misp_1932():
    cfg = yaml.safe_load(BASE.joinpath("config.yaml").read_text())
    m = MISPClient(cfg["misp"]["url"], cfg["misp"]["api_key"],
                   verify_tls=cfg["misp"].get("verify_tls", True))
    eid = cfg['misp'].get('event_id', 1932)
    attrs = published_event(m.get_event(eid), eid)['Attribute']
    ips = [a for a in attrs if a.get("type") in ("ip-src", "ip-dst")]
    cidrs = [a["value"] for a in ips if "/" in a.get("value", "")]
    # Full event membership is known; recent_14d below is only a 30-row preview.
    members = {a["value"] for a in ips if not _is_private(a.get("value") or "")}
    recent = []
    now = datetime.now(timezone.utc)
    for a in ips:
        ts = int(a.get("timestamp") or 0)
        if ts and (now - datetime.fromtimestamp(ts, timezone.utc)) <= timedelta(days=14) and not _is_private(a.get("value") or ""):
            recent.append({"ip": a["value"], "date": datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d"),
                           "updated_at": ts, "comment": (a.get("comment") or "")[:200]})
    recent.sort(key=lambda x: x["updated_at"], reverse=True)
    # Public watchlist is smaller than the internal blocklist: require corroborated SSH evidence.
    from vt_comment_new import eligible, parse_comment, shortlisted
    cache_file = BASE / "enrich-cache.json"
    cache = json.loads(cache_file.read_text()) if cache_file.exists() else {}
    excluded = protected_ips(cfg.get('sensor_public_ips'))
    candidates = []
    for a in ips:
        ip = a['value']; intel = cache.get(ip) or {}; meta = parse_comment(a.get('comment') or '')
        if a.get('to_ids') in (True, 1, '1') and shortlisted(ip, meta, intel, excluded):
            candidates.append((ip, meta, intel))
    proofs = authenticated_failures(cfg, [r[0] for r in candidates])
    watchlist = sorted({ip for ip,meta,intel in candidates if eligible(ip, meta, intel, proofs.get(ip), excluded=excluded)})
    return {"total": len(ips), "cidrs": cidrs, "recent_14d": recent[:30],
            "watchlist": watchlist, "member_ips": sorted(members)}


def pipeline_coverage(now=None):
    """Bounded, aggregate 24h Wazuh input coverage from the most recent run.

    Not a source list or a claim about the separate seven-day dashboard query.
    """
    empty = {"bucket_limit": 500, "outside_top_alerts": None,
             "approx_source_values": None, "measured_at_utc": None}
    path = BASE / "summaries/summary.json"
    if not path.exists():
        return empty
    try:
        summary = json.loads(path.read_text())
        finished = datetime.fromisoformat(summary["finished"].replace("Z", "+00:00"))
        age = ((now or datetime.now(timezone.utc)) - finished.astimezone(timezone.utc)).total_seconds()
        info = (summary.get("stage_results") or {}).get("wazuh_source_coverage") or {}
        if not 0 <= age <= 24 * 3600 or info.get("source_bucket_limit") != 500:
            return empty
        outside = int(info["outside_top_alerts"])
        approx = int(info["approx_unique_sources"])
        if not (0 <= outside < 100000000 and 0 <= approx < 100000000):
            return empty
        return {"bucket_limit": 500, "outside_top_alerts": outside,
                "approx_source_values": approx,
                "measured_at_utc": finished.strftime("%Y-%m-%d %H:%M UTC")}
    except (OSError, KeyError, TypeError, ValueError):
        return empty


def runs():
    lines = (BASE / "cron.log").read_text().splitlines()
    out = []
    by_timestamp = {}
    for line in lines:
        match = re.match(r"(\S+) END (ok|FAIL: .*)", line)
        if match:
            record = {"ts": match.group(1), "status": "ok" if match.group(2) == "ok" else "fail",
                      "why": match.group(2)[5:] if match.group(2) != "ok" else ""}
            out.append(record)
            by_timestamp[record["ts"]] = record
            continue
        # An appended operator correction can demote a known completed run,
        # never promote an error or expose the private correction rationale.
        correction = re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z RUN_STATUS_CORRECTION "
            r"target_end=(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z) status=fail", line)
        record = by_timestamp.get(correction.group(1)) if correction else None
        if record is not None:
            record["status"] = "fail"
            record["why"] = "operator status correction"
    return out[-40:]


def vt_ledger():
    f = BASE / "vt-commented.txt"
    if not f.exists():
        return {'posted_total': None}
    ips = [l.strip() for l in f.read_text().splitlines() if l.strip()]
    return {"posted_total": len(ips)}


def health():
    path = BASE / 'agent-status.json'  # do not run a second state-mutating health check
    states = json.loads(path.read_text())
    checked = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)
    if not states or not timedelta(0) <= datetime.now(timezone.utc)-checked <= timedelta(hours=1):
        return {'agents_down':'unknown'}
    return {'agents_down': ','.join(n for n,s in states.items() if s != 'active') or 'none',
            'checked': checked.strftime('%Y-%m-%d %H:%M UTC')}



def lookup_freshness(entry, name, now=None, ttl_hours=48):
    """Differentiate fresh, stale and never-timestamped reputation results."""
    now = now or datetime.now(timezone.utc)
    history = (entry.get("_lookups") or {}).get(name) or {}
    checked = history.get("checked_at")
    attempt = history.get("status")
    state = "unknown_age" if entry.get(name) else "not_queried"
    if not checked and not entry.get(name) and attempt in ('error','rate_limited'):
        state = 'rate_limited' if attempt == 'rate_limited' else 'lookup_failed'
    if checked:
        try:
            age = (now - datetime.fromisoformat(checked.replace("Z", "+00:00"))).total_seconds()
            if 0 <= age <= ttl_hours * 3600:
                state = ("fresh" if attempt == "ok" else
                         "not_observed" if attempt == "not_found" else "cached")
            else:
                state = "stale"
        except (ValueError, TypeError):
            state = "unknown_age"
    if checked and state != "unknown_age":
        checked = datetime.fromisoformat(checked.replace("Z", "+00:00")).astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    else:
        checked = None
    return {"state": state, "checked_at": checked, "last_attempt": attempt or "unknown"}


def public_enrichment(meta):
    """Allow only non-sensitive reputation fields and canonical freshness labels."""
    out = {}
    for key in ("gn", "country", "org", "provider"):
        value = (meta or {}).get(key)
        if value is not None:
            out[key] = re.sub(r"[^\w .,/()\-]", "", str(value))[:35]
    for key in ("otx", "aip"):
        value = (meta or {}).get(key)
        if isinstance(value, (int, float)) and 0 <= value <= 100000:
            out[key] = value
    out["sources"] = {}
    for name in ("gn", "otx", "aipdb"):
        source = ((meta or {}).get("sources") or {}).get(name) or {}
        state = source.get("state")
        if state not in ('fresh','cached','stale','not_observed','unknown_age','not_queried','rate_limited','lookup_failed'):
            state = "unknown_age"
        checked = source.get("checked_at")
        out["sources"][name] = {
            "state": state,
            "checked_at": checked if isinstance(checked, str) and re.fullmatch(r"\d{4}-\d\d-\d\d \d\d:\d\d UTC", checked) else None,
            "last_attempt": source.get("last_attempt") if source.get("last_attempt") in ("ok", "not_found", "error", "rate_limited") else "unknown",
        }
    return out


def read_ndr_evidence(ips, now=None):
    """Read locally retained matched alerts; never expose them to GitHub Pages."""
    now = now or datetime.now(timezone.utc)
    path = BASE / "ndr-evidence.json"
    if not path.exists():
        return {"status": "not_collected", "checked_at": None, "window_hours": 24, "matches": []}
    try:
        d = json.loads(path.read_text())
        checked = datetime.fromisoformat(d["checked_at"].replace("Z", "+00:00"))
        if checked.tzinfo is None or d.get("status") != "ok" or d.get("schema_version") != 1:
            raise ValueError("invalid NDR evidence schema")
        age = (now - checked).total_seconds()
        status = "ok" if 0 <= age <= 30 * 3600 else "stale"
        matches = [m for m in d.get("matches", []) if m.get("ip") in set(ips)]
        return {"status": status, "checked_at": checked.astimezone(timezone.utc).isoformat(),
                "window_hours": 24, "matches": matches}
    except (OSError, ValueError, TypeError, KeyError):
        return {"status": "invalid", "checked_at": None, "window_hours": 24, "matches": []}


def enrich_meta_for(ips):
    """GN/OTX/AbuseIPDB with provenance; no lookups or secrets are exported."""
    import sqlite3
    cache_path = BASE / "enrich-cache.json"
    cache = json.loads(cache_path.read_text() or "{}") if cache_path.exists() else {}
    out = {}
    for ip in ips:
        c = cache.get(ip) or {}
        meta = {"sources": {name: lookup_freshness(c, name) for name in ("gn", "otx", "aipdb")}}
        gn = c.get("gn") or {}
        if isinstance(gn, dict) and not gn.get("_error") and str(gn.get("classification") or "").lower() in ('malicious', 'suspicious', 'benign', 'unknown'):
            meta["gn"] = str(gn["classification"]).lower()
            if gn.get("name"):
                meta["org"] = str(gn["name"])[:28]
        otx = c.get("otx") or {}
        if isinstance(otx, dict) and not otx.get("_error") and otx.get("pulses") is not None:
            meta["otx"] = otx.get("pulses")
            if iso_country(otx.get('cc')):
                meta['country'] = iso_country(otx['cc'])
        ab = c.get("aipdb") or {}
        if isinstance(ab, dict) and not ab.get("_error") and ab.get("score") is not None:
            meta["aip"] = ab.get("score")
            if ab.get("isp"):
                meta["provider"] = str(ab["isp"])[:30]
            if iso_country(ab.get('cc')):
                meta.setdefault('country', iso_country(ab['cc']))
        out[ip] = meta
    # Legacy DB evidence has unknown freshness and may contain asset context.
    # Keep its AS/country fallback private; never populate public provider fields.
    if THREAT_DB.exists():
        con = sqlite3.connect(THREAT_DB.resolve().as_uri() + "?mode=ro", uri=True)
        try:
            con.row_factory = sqlite3.Row
            for ip in ips:
                if out.get(ip, {}).get("provider"):
                    continue
                row = con.execute("select evidence from iocs where ip=?", (ip,)).fetchone()
                if row:
                    ev = json.loads(row["evidence"] or "{}")
                    if not isinstance(ev, dict):
                        continue
                    if ev.get("as_owner"):
                        out[ip]["db_provider_private"] = str(ev["as_owner"])[:30]
                    if ev.get("country"):
                        out[ip]["db_country_private"] = str(ev["country"])[:2].upper()
        finally:
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
        # A broken enrichment fallback must not publish a silently empty snapshot.
        raise RuntimeError("dashboard enrichment generation failed") from e
    bl = BASE / "soc_blocklist.txt"
    data["blocklist_n"] = len([l for l in bl.read_text().splitlines() if l.strip() and not l.startswith("#")]) if bl.exists() else 0
    private_ips = [x[0] for x in (data.get("wazuh") or {}).get("top_src", [])]
    data["evidence"] = {"wazuh_top_samples": (data.get("wazuh") or {}).get("samples_by_source", {}),
                        "ndr": read_ndr_evidence(private_ips),
                        "limitations": "Top three Wazuh alerts per source (7d); NDR 24h MISP-only; no confirmed outcome."}

    OUT.mkdir(exist_ok=True)
    (OUT / "data.json").write_text(json.dumps(data, indent=1))

    # Nothing sensitive or unreviewed from local health, notes or alert comments
    # should be mirrored to the public GitHub Pages folder.
    if not isinstance(data.get("wazuh", {}).get("top_src"), list) or not isinstance(data.get("misp", {}).get("watchlist"), list):
        raise RuntimeError("dashboard inputs incomplete; refusing to publish stale/unsafe data")
    waz = data["wazuh"]
    misp = data["misp"]
    sensor_ips = protected_ips(yaml.safe_load((BASE / 'config.yaml').read_text()).get('sensor_public_ips'))
    public_src = [(ip, n) for ip, n in waz["top_src"] if ip not in sensor_ips and not _is_private(ip)]
    top = {ip for ip, _ in public_src}
    public = {
        "generated": data["generated"],
        "wazuh": {
            "total_7d": waz.get("total_7d", 0),
            "by_agent": [],  # private agent distribution; rank-based labels were misleading
            "top_src": public_src, "by_day": waz.get("by_day", []),
            "source_context": {ip: public_sample_context((waz.get("samples_by_source") or {}).get(ip) or [])
                               for ip, _ in public_src},
            "pipeline_24h_coverage": pipeline_coverage(),
        },
        "misp": {
            "total": misp["total"], "cidrs": [],
            "recent_14d": [{"ip": x["ip"], "date": x["date"], "comment": "Observed source; review locally"}
                           for x in misp["recent_14d"] if x["ip"] not in sensor_ips],
            "membership_scope": "full Event 1932; legacy ip-dst and new ip-src",
            "top_source_membership": {ip: ip in set(misp["member_ips"]) for ip in top},
        },
        'vt': {'posted_total': data['vt']['posted_total'] if type(data['vt'].get('posted_total')) is int and data['vt']['posted_total'] >= 0 else None},
        "health": {"agents_down": "withheld"},
        "runs": [{"ts": x["ts"], "status": x["status"], "why": ""} for x in data["runs"]],
        "blocklist_n": len(misp["watchlist"]),
        "enrich_meta": {
            ip: public_enrichment(meta)
            for ip, meta in (data.get("enrich_meta") or {}).items() if ip in top
        },
    }
    PUBLIC.mkdir(exist_ok=True)
    (PUBLIC / "data.json").write_text(json.dumps(public, indent=1) + "\n")
    edl = [
        "# kit-cloud SoC public watchlist — REVIEW BEFORE BLOCKING; not proof of compromise",
        f"# Batch: {data['generated']}; check status.json; do not use a stale (>24h) list",
        '# Scope: at least 20 level 10+ SSH authentication-failure alerts within 24h and independent lookup within 48h',
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
