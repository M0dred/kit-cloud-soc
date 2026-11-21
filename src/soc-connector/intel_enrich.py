#!/usr/bin/env python3
"""GreyNoise / OTX / AbuseIPDB lookups. Stdlib only."""
from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request


def _get(url: str, headers: dict, timeout: int = 20):
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode()), r.status
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read().decode()), e.code
        except Exception:
            return {"_error": True}, e.code
    except Exception as e:
        return {"_error": True, "_message": str(e)[:80]}, 0


def greynoise(ip: str, api_key: str) -> dict:
    data, code = _get(
        f"https://api.greynoise.io/v3/community/{ip}",
        {"key": api_key, "Accept": "application/json", "User-Agent": "soc-connector/1.0"},
    )
    if code == 429:
        return {"_rate_limited": True, "http": code}
    if code not in (200, 404):
        return {"_error": True, "http": code}
    if code == 200 and (not isinstance(data,dict) or not isinstance(data.get('classification'), str)):
        return {'_error': True, 'http': code}
    return {
        # A 404's API message is not a classification and must not imply benign.
        "classification": data.get("classification") if code == 200 else None,
        "_not_found": code == 404,
        "noise": data.get("noise"),
        "riot": data.get("riot"),
        "name": data.get("name") or "",
        "last_seen": data.get("last_seen") or "",
        "http": code,
    }


def otx(ip: str, api_key: str) -> dict:
    data, code = _get(
        f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
        {"X-OTX-API-KEY": api_key, "User-Agent": "soc-connector/1.0"},
        timeout=35,
    )
    if code == 429:
        return {"_error": True, "_rate_limited": True, "http": code}
    if code != 200 or not isinstance(data,dict) or not isinstance(data.get('pulse_info'),dict):
        return {'_error': True, 'http': code}
    n = data['pulse_info'].get('count')
    if type(n) is not int or n < 0:
        return {'_error': True, 'http': code}
    cc = data.get('country_iso_code')
    return {'pulses': n, 'cc': cc.upper() if isinstance(cc,str) and len(cc)==2 and cc.isascii() and cc.isalpha() else '', 'http': code}


def abuseipdb(ip: str, api_key: str) -> dict:
    q = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": 90})
    data, code = _get(
        f"https://api.abuseipdb.com/api/v2/check?{q}",
        {"Key": api_key, "Accept": "application/json", "User-Agent": "soc-connector/1.0"},
    )
    if code == 429:
        return {"_rate_limited": True, "http": code}
    d = data.get('data') if isinstance(data,dict) else None
    if code != 200 or not isinstance(d, dict) or type(d.get('abuseConfidenceScore')) is not int or not 0 <= d['abuseConfidenceScore'] <= 100:
        return {'_error': True, 'http': code}
    return {
        "score": d.get("abuseConfidenceScore"),
        "reports": d.get("totalReports"),
        "cc": d.get("countryCode"),
        "isp": (d.get("isp") or "")[:40],
        "http": code,
    }


def format_comment(intel: dict) -> str:
    parts = []
    gn = intel.get("gn") or {}
    if gn and not gn.get("_rate_limited") and not gn.get("_error") and not gn.get("_not_found"):
        parts.append(
            f"GN: class={gn.get('classification')} noise={gn.get('noise')} "
            f"riot={gn.get('riot')} last={gn.get('last_seen')}"
        )
    o = intel.get("otx") or {}
    if o and not o.get("_error"):
        parts.append(f"OTX: pulses={o.get('pulses')} cc={o.get('cc')}")
    a = intel.get("aipdb") or {}
    if a and not a.get("_rate_limited") and not a.get("_error"):
        parts.append(
            f"AIPDB: score={a.get('score')} reports={a.get('reports')} "
            f"cc={a.get('cc')} isp={a.get('isp')}"
        )
    return " | ".join(parts)
