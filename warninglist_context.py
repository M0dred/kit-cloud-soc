#!/usr/bin/env python3
"""Private, read-only context for observed IPv4 sources from MISP warninglists.

The upstream CIDRs describe provider address space, *not* benign activity.
This module cannot change IOC selection, MISP IDS flags, enforcement or docs/.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parent
REPORT = BASE / "warninglist-context.json"  # root-only; never add to docs/
UPSTREAM = "https://raw.githubusercontent.com/MISP/misp-warninglists/main/lists/"
# Small, fixed, IPv4 CIDR-only subset; do not ingest full warninglists as an EDL.
SOURCES = {
    "amazon-aws": ("AWS address range", 100, "List of known Amazon AWS IP address ranges"),
    "microsoft-azure": ("Azure address range", 100, "List of known Microsoft Azure Datacenter IP Ranges"),
    "google-gcp": ("GCP address range", 50, "List of known GCP (Google Cloud Platform) IP address ranges"),
    "cloudflare": ("Cloudflare address range", 10, "List of known Cloudflare IP ranges"),
}
MAX_BYTES = 1_000_000
MAX_VERSION_AGE_DAYS = 60


def fetch_list(slug: str) -> dict:
    """Fetch public definitions only; source IPs are never sent upstream."""
    if slug not in SOURCES:
        raise ValueError("unapproved warninglist")
    url = f"{UPSTREAM}{slug}/list.json"
    req = urllib.request.Request(url, headers={"User-Agent": "soc-warninglist-context/1.0"})
    with urllib.request.urlopen(req, timeout=18) as response:
        if response.status != 200 or response.geturl() != url:
            raise ValueError("unexpected warninglist response")
        raw = response.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("oversized warninglist")
    return json.loads(raw)


def parse_list(data: dict, slug: str, *, now: datetime, sources: dict = SOURCES):
    """Validate type, provenance age and bounded CIDRs before trusting a list."""
    if (not isinstance(data, dict) or data.get("type") != "cidr"
            or data.get("name") != sources[slug][2]):
        raise ValueError("unexpected warninglist type or name")
    version = str(data.get("version") or "")
    if not re.fullmatch(r"\d{8}", version):
        raise ValueError("invalid warninglist version")
    try:
        day = datetime.strptime(version, "%Y%m%d").date()
    except ValueError as e:
        raise ValueError("invalid warninglist version") from e
    age = (now.astimezone(timezone.utc).date() - day).days
    if age < 0 or age > MAX_VERSION_AGE_DAYS:
        raise ValueError("warninglist version stale or in the future")
    entries = data.get("list")
    if not isinstance(entries, list) or not sources[slug][1] <= len(entries) <= 12000:
        raise ValueError("unexpected warninglist size")
    ranges = []
    for entry in entries:
        if not isinstance(entry, str):
            raise ValueError("invalid CIDR")
        net = ipaddress.ip_network(entry, strict=True)
        if net.prefixlen < 8:
            raise ValueError("overly broad CIDR")
        if net.version == 4 and net.is_global:
            ranges.append(net)
    if len(ranges) < sources[slug][1] // 2:
        raise ValueError("insufficient IPv4 ranges")
    return version, ranges


def build_report(observations, *, fetch=fetch_list, now=None, sources=SOURCES,
                 coverage=None):
    """Only private source-IP labels. A missing source makes the *whole* result unknown."""
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    ips = set()
    for item in observations[:500]:
        try:
            addr = ipaddress.ip_address(item.get("ip"))
            if addr.version == 4 and addr.is_global:
                ips.add(str(addr))
        except (TypeError, ValueError, AttributeError):
            continue
    report = {
        "schema_version": 1,
        "generated_utc": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "scope": "24h top-500 Wazuh source buckets; provider range is not a verdict",
        "origin": "MISP/misp-warninglists upstream (read-only; not enabled in local MISP)",
        "status": "unavailable",
        "observed_sources": len(ips),
        "outside_top_alerts": None,
        "list_versions": {},
        "matches": [],
    }
    if isinstance(coverage, dict) and type(coverage.get("outside_top_alerts")) is int:
        outside = coverage["outside_top_alerts"]
        if 0 <= outside < 100_000_000:
            report["outside_top_alerts"] = outside
    if not ips:
        report["status"] = "no_observations"
        return report
    try:
        loaded = {}
        for slug in sources:
            version, ranges = parse_list(fetch(slug), slug, now=now, sources=sources)
            loaded[slug] = (version, ranges)
    except Exception:
        # No partial positive/negative claims if any list failed or was stale.
        return report
    report["status"] = "fresh"
    report["list_versions"] = {slug: loaded[slug][0] for slug in sources}
    for ip in sorted(ips, key=lambda value: int(ipaddress.IPv4Address(value))):
        addr = ipaddress.IPv4Address(ip)
        labels = [sources[slug][0] for slug in sources
                  if any(addr in net for net in loaded[slug][1])]
        if labels:
            report["matches"].append({"source_ip": ip, "provider_ranges": labels})
    return report


def write_report(report: dict, path: Path = REPORT) -> None:
    """Fail if the private report cannot be atomically replaced; never expose stale data."""
    temp = path.with_suffix(".tmp")
    try:
        with temp.open("w") as fh:
            os.fchmod(fh.fileno(), 0o600)
            json.dump(report, fh, sort_keys=True)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        temp.replace(path)
    finally:
        temp.unlink(missing_ok=True)
