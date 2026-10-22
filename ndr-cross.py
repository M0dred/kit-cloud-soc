#!/usr/bin/env python3
"""Cross MISP 1932 IOCs against Clear NDR (24h); save PRIVATE evidence.

Only an IOC-side IP is called a match. Individual alert samples are retained
locally for investigation, never exposed through GitHub Pages or VT.
"""
import argparse
import ipaddress
import json
import re
import ssl
import sys
import urllib.parse
import urllib.request
import http.cookiejar
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path.home() / ".config/agents/skills/soc-connector/scripts"))
from misp_client import MISPClient  # noqa: E402
import yaml  # noqa: E402

BASE = Path.home() / ".config/soc-orchestrator"
BASE_CFG = BASE / "config.yaml"
EVIDENCE_FILE = BASE / "ndr-evidence.json"


def ndr_es(opener, csrf, index, body):
    path = f"/kibana/api/console/proxy?path={urllib.parse.quote(index + '/_search')}&method=POST"
    req = urllib.request.Request(
        "https://10.0.1.50:8443" + path,
        data=json.dumps(body).encode(),
        headers={"Referer": "https://10.0.1.50:8443/", "X-CSRFToken": csrf,
                 "kbn-xsrf": "true", "osd-xsrf": "true", "Content-Type": "application/json"},
        method="POST",
    )
    resp = opener.open(req, timeout=60)
    return json.loads(resp.read().decode())


def ioc_hits(aggregations, chunk):
    """Return only the IOC-side buckets; never label the other endpoint an IOC."""
    matches = set(chunk)
    hits = []
    for field, side in (("src", "src"), ("dst", "dst")):
        for bucket in (aggregations.get(field) or {}).get("buckets", []):
            if bucket["key"] in matches:
                hits.append((bucket["key"], side, bucket["doc_count"]))
    return hits


def utc_timestamp(raw):
    if not isinstance(raw, str):
        return None
    try:
        value = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC") if value.tzinfo else None
    except ValueError:
        return None


def evidence_matches(aggregations, chunk):
    """Include matched indicator buckets only; their opposite endpoint is private."""
    allowed = set(chunk)
    records = []
    for field, side in (("src", "src"), ("dst", "dst")):
        buckets = (aggregations.get(field) or {}).get("buckets") or []
        for bucket in buckets:
            if bucket.get("key") not in allowed:
                continue
            ip = bucket["key"]
            samples = []
            for hit in ((bucket.get("sample") or {}).get("hits") or {}).get("hits", []):
                doc = hit.get("_source") or {}
                if doc.get("src_ip" if side == "src" else "dest_ip") != ip:
                    continue
                alert = doc.get("alert") or {}
                samples.append({
                    "time_utc": utc_timestamp(doc.get("@timestamp") or doc.get("timestamp")),
                    "source_ip": doc.get("src_ip"), "destination_ip": doc.get("dest_ip"),
                    "sid": alert.get("signature_id") or doc.get("alert.signature_id"),
                    "signature": str(alert.get("signature") or doc.get("alert.signature") or "")[:180],
                })
            records.append({"ip": ip, "side": side, "count": int(bucket.get("doc_count") or 0),
                            "samples": samples})
    return records


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-notify", action="store_true", help="read-only validation; do not notify Telegram")
    args = ap.parse_args()
    cfg = yaml.safe_load(BASE_CFG.read_text())
    ndr = cfg["ndr"]
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ctx),
        urllib.request.HTTPCookieProcessor(cj),
    )
    opener.addheaders = [("User-Agent", "soc-ndr-cross/1.0")]
    html = opener.open(ndr["url"] + "/accounts/login/", timeout=20).read().decode("utf-8", "replace")
    token = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', html).group(1)
    login = urllib.request.Request(
        ndr["url"] + "/accounts/login/",
        data=urllib.parse.urlencode({
            "csrfmiddlewaretoken": token,
            "username": ndr["username"],
            "password": ndr["password"],
            "next": "/",
        }).encode(),
        method="POST",
    )
    login.add_header("Referer", ndr["url"] + "/accounts/login/")
    login.add_header("Content-Type", "application/x-www-form-urlencoded")
    opener.open(login, timeout=20)
    csrf = [c.value for c in cj if c.name == "csrftoken"][0]

    misp = MISPClient(cfg["misp"]["url"], cfg["misp"]["api_key"],
                      verify_tls=cfg["misp"].get("verify_tls", True))
    event = misp.get_event(cfg["misp"].get("event_id", 1932))
    if event.get("_error") or not isinstance(event.get("Event"), dict):
        raise RuntimeError("MISP fetch failed; NDR cross-check not performed")
    attrs = event["Event"].get("Attribute") or []
    def valid_source(a):
        if a.get("type") not in ("ip-src", "ip-dst"):
            return False  # ip-dst entries were historically mis-typed inbound sources
        try:
            addr = ipaddress.ip_address(a.get("value") or "")
            return addr.version == 4 and addr.is_global
        except ValueError:
            return False

    ips = sorted({a["value"] for a in attrs if valid_source(a)})
    print(f"iocs={len(ips)}")

    matches = []
    for i in range(0, len(ips), 50):
        chunk = ips[i:i + 50]
        body = {
            "size": 0,
            "query": {"bool": {
                "must": [{"range": {"@timestamp": {"gte": "now-24h"}}}],
                "should": [{"terms": {"src_ip.keyword": chunk}},
                            {"terms": {"dest_ip.keyword": chunk}}],
                "minimum_should_match": 1,
            }},
            "aggs": {
                "src": {"terms": {"field": "src_ip.keyword", "size": len(chunk), "include": chunk},
                        "aggs": {"sample": {"top_hits": {"size": 3,
                            "_source": ["@timestamp", "timestamp", "src_ip", "dest_ip",
                                        "alert.signature_id", "alert.signature"]}}}},
                "dst": {"terms": {"field": "dest_ip.keyword", "size": len(chunk), "include": chunk},
                        "aggs": {"sample": {"top_hits": {"size": 3,
                            "_source": ["@timestamp", "timestamp", "src_ip", "dest_ip",
                                        "alert.signature_id", "alert.signature"]}}}},
            },
        }
        d = ndr_es(opener, csrf, "logstash-alert-*", body)
        if d.get("error") or not all(isinstance((d.get("aggregations") or {}).get(k), dict) for k in ("src", "dst")):
            raise RuntimeError("NDR query returned an error or no aggregations")
        matches.extend(evidence_matches(d["aggregations"], chunk))

    # Do not keep a previous successful snapshot when the current query fails.
    evidence = {"schema_version": 1, "status": "ok", "checked_at": datetime.now(timezone.utc).isoformat(),
                "window_hours": 24, "matches": matches}
    tmp = EVIDENCE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(evidence, indent=1))
    tmp.chmod(0o600)
    tmp.replace(EVIDENCE_FILE)
    hits = [(r["ip"], r["side"], r["count"]) for r in matches]
    if hits:
        for ip, side, n in sorted(hits):
            print(f"HIT {ip} {side} {n}")
        # single Telegram ping for LAN-visible IOCs
        if args.no_notify:
            return
        try:
            text = "SOC: NDR cross — " + "; ".join(f"{ip}({side},{n})" for ip, side, n in sorted(hits)[:10])
            t = BASE_CFG.read_text()
            bot = re.search(r'bot_token:\s*"([^"]+)"', t).group(1)
            chat = re.search(r'chat_id:\s*(\d+)', t).group(1)
            req = urllib.request.Request(
                f"https://api.telegram.org/bot{bot}/sendMessage",
                data=urllib.parse.urlencode({"chat_id": chat, "text": text[:3500]}).encode(),
            )
            urllib.request.urlopen(req, timeout=20).read()
        except Exception as e:
            print(f"telegram failed: {e}", file=sys.stderr)
    else:
        print("HIT none")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"NDR cross error: {e}", file=sys.stderr)
        sys.exit(1)
