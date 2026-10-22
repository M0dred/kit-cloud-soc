#!/usr/bin/env python3
"""Cross MISP 1932 IOCs against Clear NDR alert history (last 24h).

Prints HIT lines when an IOC appears in NDR logstash-alert-* src/dst.
Exit 0 always unless the NDR API itself fails (rc=1).
"""
import ipaddress
import json
import re
import ssl
import sys
import urllib.parse
import urllib.request
import http.cookiejar
from pathlib import Path

sys.path.insert(0, str(Path.home() / ".config/agents/skills/soc-connector/scripts"))
from misp_client import MISPClient  # noqa: E402
import yaml  # noqa: E402

BASE_CFG = Path.home() / ".config/soc-orchestrator/config.yaml"


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


def main():
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

    hits = []
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
                "src": {"terms": {"field": "src_ip.keyword", "size": 20}},
                "dst": {"terms": {"field": "dest_ip.keyword", "size": 20}},
            },
        }
        d = ndr_es(opener, csrf, "logstash-alert-*", body)
        hits.extend(ioc_hits(d.get("aggregations") or {}, chunk))

    if hits:
        for ip, side, n in sorted(hits):
            print(f"HIT {ip} {side} {n}")
        # single Telegram ping for LAN-visible IOCs
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
