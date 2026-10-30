"""One cautious, stack-neutral template for MISP and VT IPv4 source comments.

Rendering is pure: it never looks up an IOC, votes, or posts a comment.
"""
from __future__ import annotations

import ipaddress
from datetime import datetime, timezone


def defang(ip: str) -> str:
    head, _, last = ip.rpartition(".")
    return f"{head}[.]{last}" if head else ip


def _number(value, default=0):
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


def render_comment(ip, count, agent, rule, vt=None, intel=None, level=None,
                   sensor_public_ips=None, when=None, format_vt=False):
    address = ipaddress.ip_address(ip)
    if address.version != 4 or not address.is_global:
        raise ValueError("Only public IPv4 source indicators may be shared")
    ip = str(address)
    intel = intel or {}
    # Rule descriptions can contain usernames, URLs, query tokens and hostnames.
    # Classify locally but share only fixed vocabulary, never the raw text.
    low = str(rule or "").lower()[:200]
    count, lvl = _number(count), _number(level)
    if "sshd" in low or ("ssh" in low and any(x in low for x in ("failed", "invalid", "brute", "auth"))):
        category = "SSH authentication failures"
        ttp = "T1110 Brute Force (suspected; attempts do not establish compromise)"
        ports = "SSH (typically 22/tcp; destination port not verified)"
        look_for = "SSH login failures associated with this source IP"
        safe_rule = "sshd authentication failures (raw rule withheld)"
    elif any(x in low for x in ("http", "web", "400", "url")):
        category = "Web requests / errors (unconfirmed probing)"
        ttp = "Not established; HTTP errors alone do not prove exploitation"
        ports = "HTTP(S) (typically 80/443; destination port not verified)"
        look_for = "HTTP(S) requests, repeated errors or unusual paths from this source IP"
        safe_rule = "Web request alert (raw rule withheld)"
    elif "scan" in low or "recon" in low:
        category = "Network reconnaissance (suspected)"
        ttp = "T1046 Network Service Discovery (suspected, not confirmed)"
        ports = "Unknown; check locally"
        look_for = "inbound connection attempts across services from this source IP"
        safe_rule = "Network scan alert (raw rule withheld)"
    else:
        category = "Inbound activity (unclassified)"
        ttp = "Not established from available telemetry"
        ports = "Unknown; check locally"
        look_for = "events containing this IP as the connecting source"
        safe_rule = "Unclassified alert (raw rule withheld)"
    gn_value = intel.get("greynoise_classification") or intel.get("gn_class") or (intel.get("gn") or {}).get("classification")
    gn = str(gn_value).lower() if str(gn_value).lower() in ("malicious", "benign") else None
    otx = intel.get("otx_pulses")
    if otx is None and not (intel.get("otx") or {}).get("_error"):
        otx = (intel.get("otx") or {}).get("pulses")
    aip = intel.get("abuseipdb_score")
    if aip is None and not (intel.get("aipdb") or {}).get("_error"):
        aip = (intel.get("aipdb") or {}).get("score")
    extra = []
    if gn:
        extra.append(f"GreyNoise={gn}")
    if otx is not None:
        extra.append(f"OTX pulses={_number(otx)}")
    if aip is not None:
        extra.append(f"AbuseIPDB={_number(aip)}")
    corroborated = (str(gn).lower() == "malicious" or _number(otx) >= 5 or _number(aip) >= 80)
    confidence = ("Moderate (external reports; lookup age unverified; not attribution)"
                  if corroborated else "Low (unconfirmed)")
    # Asset identities and target network prefixes belong in the private case.
    target = "withheld"
    stamp = when or datetime.now(timezone.utc)
    if stamp.tzinfo is None:
        raise ValueError("comment time must be timezone aware")
    stamp = stamp.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    fang = defang(ip)
    # Never interpolate third-party free-text AS/owner fields into shared text.
    detail = "; ".join(extra)
    if detail:
        detail = " " + detail + "."
    body = (
        f"Date: {stamp} (comment generated; observation time not verified)\n"
        f"IOC: {fang}\n"
        f"Type: IPv4 observed source (ip-src)\n"
        f"Category: {category}\n"
        f"Confidence: {confidence}\n"
        f"Ports: {ports}\n"
        f"Observed Behavior: Wazuh {count} alerts, level {lvl}.{detail} "
        f"Rule: {safe_rule}\n"
        f"Target: {target}\n"
        f"Source: Wazuh alerts (kit-cloud SoC)\n"
        f"TTPs: {ttp}\n"
        f"Hunt: source IP = {fang}\n"
        f"Fields: src_ip | source.ip | client.ip | c-ip\n"
        f"What: {look_for}\n"
        f"Dst: {ports}\n"
        f"Also: correlate with firewall, IDS and auth logs; repeated alerts alone are not proof.\n"
        f"Action: investigate locally before considering a block. Not a victim ID.\n"
    )
    # Only VT receives a fenced summary; reference URLs stay outside the fence.
    # If VT displays Markdown literally, the labels are still readable plain text.
    if format_vt:
        body = "```text\n" + body + "```\n"
    return body + (
        f"Refs:\n"
        f"  VT https://www.virustotal.com/gui/ip-address/{ip}\n"
        f"  AbuseIPDB https://www.abuseipdb.com/check/{ip}\n"
        f"  GreyNoise https://viz.greynoise.io/ip/{ip}\n"
        f"  OTX https://otx.alienvault.com/indicator/ip/{ip}\n"
        f"  Shodan https://www.shodan.io/host/{ip}\n"
        f"  BGP https://bgp.he.net/ip/{ip}\n"
        f"Via: kit-cloud SoC (Kowalski, analysis)\n"
        f"Contact: admin@kit-cloud.com for more context on this IOC."
    )
