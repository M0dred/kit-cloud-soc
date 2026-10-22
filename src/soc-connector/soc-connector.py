#!/usr/bin/env python3
"""
soc-connector — MISP + Wazuh integration skill for linux-log-threat-hunt.

Bidirectional sync between:
- Local threat intel DB (linux-log-threat-hunt)
- MISP (push/pull IOCs, create events)
- Wazuh (query alerts, block IPs, agent management)

Environment variables:
  MISP_URL              MISP base URL (e.g., https://misp.example.com)
  MISP_API_KEY          MISP API key
  WAZUH_URL             Wazuh API URL (e.g., https://wazuh.example.com:55000)
  WAZUH_USER            Wazuh API username
  WAZUH_PASS            Wazuh API password
  WAZUH_INDEXER_HOST    Wazuh Indexer host (e.g., 10.0.0.1 — port 9200 assumed)
  WAZUH_INDEXER_USER    Indexer username (default: admin)
  WAZUH_INDEXER_PASS    Indexer password
  VT_API_KEY            Optional: for VT enrichment before pushing

Usage:
  # MISP: push local IOCs as an event
  python3 soc-connector.py misp push --name "sensor-02 SSH brute force" \
    --ips-file /tmp/sensor02_ips.txt --tag brute_force --tag ssh

  # MISP: pull IOCs down for blocklist generation
  python3 soc-connector.py misp pull --days 7 --output /tmp/misp_iocs.json

  # MISP: query reputation
  python3 soc-connector.py misp query --ip 1.2.3.4

  # Wazuh: list agents
  python3 soc-connector.py wazuh agents

  # Wazuh: get high-severity alerts
  python3 soc-connector.py wazuh alerts --severity 10 --last-hours 24

  # Wazuh: block IP on all agents
  python3 soc-connector.py wazuh block --ip 1.2.3.4 --all-agents

  # Sync: local DB → MISP (one-way push)
  python3 soc-connector.py sync --to misp --days 3 --min-confidence high

  # Sync: MISP → local DB (pull + ingest)
  python3 soc-connector.py sync --from misp --days 7

  # Full round-trip: enrich local DB with Wazuh alerts + push new IOCs to MISP
  python3 soc-connector.py sync --both --days 3
"""
import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone, timedelta

from misp_client import MISPClient
from wazuh_client import WazuhClient
from wazuh_indexer import WazuhIndexerClient

# Optional local DB integration
try:
    sys.path.insert(0, os.path.expanduser(
        "~/.config/agents/skills/linux-log-threat-hunt/scripts"
    ))
    from threat_db import ThreatDB
except ImportError:
    ThreatDB = None


def get_misp_client(verify_tls=True):
    url = os.environ.get("MISP_URL")
    key = os.environ.get("MISP_API_KEY")
    if not url or not key:
        print("[ERROR] Set MISP_URL and MISP_API_KEY env vars.", file=sys.stderr)
        sys.exit(1)
    return MISPClient(url, key, verify_tls=verify_tls)


def get_wazuh_client(verify_tls=True):
    url = os.environ.get("WAZUH_URL")
    user = os.environ.get("WAZUH_USER")
    pw = os.environ.get("WAZUH_PASS")
    if not url or not user or not pw:
        print("[ERROR] Set WAZUH_URL, WAZUH_USER, and WAZUH_PASS env vars.", file=sys.stderr)
        sys.exit(1)
    return WazuhClient(url, user, pw, verify_tls=verify_tls)


def get_indexer_client(verify_tls=True):
    host = os.environ.get("WAZUH_INDEXER_HOST")
    user = os.environ.get("WAZUH_INDEXER_USER", "admin")
    pw = os.environ.get("WAZUH_INDEXER_PASS")
    if not host or not pw:
        print("[ERROR] Set WAZUH_INDEXER_HOST and WAZUH_INDEXER_PASS env vars.", file=sys.stderr)
        sys.exit(1)
    return WazuhIndexerClient(host, user, pw, verify_tls=verify_tls)


# ---------------------------------------------------------------------------
# MISP commands
# ---------------------------------------------------------------------------

def cmd_misp_push(args):
    misp = get_misp_client(verify_tls=not args.no_verify_tls)

    iocs = []
    # Read IPs from file or stdin
    fh = open(args.ips_file) if args.ips_file else sys.stdin
    for line in fh:
        val = line.strip()
        if not val or val.startswith("#"):
            continue
        ioc = {"value": val, "type": args.type, "category": args.category,
               "confidence": args.confidence or "medium", "source": args.source or "soc-connector"}
        if args.comment:
            ioc["comment"] = args.comment
        iocs.append(ioc)
    if args.ips_file:
        fh.close()

    if not iocs:
        print("No IOCs to push.")
        return

    print(f"Pushing {len(iocs)} IOCs to MISP...")
    res = misp.push_ioc_event(
        name=args.name,
        iocs=iocs,
        tags=args.tag,
        threat_level=args.threat_level,
        comment_prefix=f"[{args.source}] " if args.source else "",
    )
    if res.get("_error"):
        print(f"FAIL: {res.get('_message', res.get('_body', 'unknown'))}")
        sys.exit(1)
    print(f"OK: Event {res['event_id']} created")
    print(f"URL: {res['event_url']}")
    print(f"Attributes: {res['attributes_added']}")


def cmd_misp_pull(args):
    misp = get_misp_client(verify_tls=not args.no_verify_tls)
    print(f"Pulling IOCs from MISP (last {args.days} days)...")
    iocs = misp.pull_iocs(
        types=args.type.split(",") if args.type else None,
        tags=args.tag if args.tag else None,
        days=args.days,
        limit=args.limit,
        to_ids_only=not args.include_non_ids,
    )
    if isinstance(iocs, dict) and iocs.get("_error"):
        print(f"FAIL: {iocs.get('_message', iocs.get('_body', 'unknown'))}")
        sys.exit(1)

    print(f"Pulled {len(iocs)} IOCs")

    # Ingest into local DB
    if args.use_local_db and ThreatDB:
        db = ThreatDB()
        for ioc in iocs:
            db.upsert_ioc(
                ioc["value"],
                categories=[ioc.get("category", "misp_pull")],
                sources=["misp"],
                confidence="medium",
                evidence={"misp_event": ioc.get("event_id"), "misp_info": ioc.get("event_info")},
            )
        print(f"Ingested {len(iocs)} into local DB")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(iocs, f, indent=2, default=str)
        print(f"Saved to {args.output}")
    else:
        print(json.dumps(iocs[:20], indent=2, default=str))
        if len(iocs) > 20:
            print(f"... ({len(iocs) - 20} more)")


def cmd_misp_query(args):
    misp = get_misp_client(verify_tls=not args.no_verify_tls)
    if args.ip:
        res = misp.query_ip(args.ip)
    elif args.domain:
        res = misp.query_domain(args.domain)
    else:
        print("Provide --ip or --domain", file=sys.stderr)
        sys.exit(1)

    if res.get("_error"):
        print(f"FAIL: {res.get('_message', res.get('_body', 'unknown'))}")
        sys.exit(1)

    events = res.get("response", [])
    print(f"Found in {len(events)} MISP event(s)")
    for ev in events[:10]:
        info = ev.get("Event", {}).get("info", "N/A")
        eid = ev.get("Event", {}).get("id", "N/A")
        tags = [t.get("name", "") for t in ev.get("Event", {}).get("Tag", [])]
        print(f"  Event {eid}: {info}  [tags: {', '.join(tags)}]")


# ---------------------------------------------------------------------------
# Wazuh commands
# ---------------------------------------------------------------------------

def cmd_wazuh_agents(args):
    wazuh = get_wazuh_client(verify_tls=not args.no_verify_tls)
    res = wazuh.list_agents(status=args.status, limit=args.limit)
    if res.get("_error"):
        print(f"FAIL: {res.get('_message', res.get('_body', 'unknown'))}")
        sys.exit(1)

    items = res.get("data", {}).get("affected_items", [])
    print(f"Agents: {len(items)}")
    for a in items:
        print(f"  ID={a.get('id'):>3}  {a.get('name', '?'):<20}  IP={a.get('ip', '?'):<15}  "
              f"Status={a.get('status', '?'):<12}  OS={a.get('os', {}).get('name', '?')}")


def cmd_wazuh_alerts(args):
    wazuh = get_wazuh_client(verify_tls=not args.no_verify_tls)

    # NOTE: Wazuh Manager API does not expose security alerts directly.
    # Security alerts live in the Wazuh Indexer (OpenSearch).
    # We query manager internal logs here as a proxy, or agent logs if available.
    res = wazuh.get_manager_logs(
        limit=args.limit,
        search=args.search,
    )
    if res.get("_error"):
        print(f"FAIL: {res.get('_message', res.get('_body', 'unknown'))}")
        sys.exit(1)

    items = res.get("data", {}).get("affected_items", [])
    print(f"Manager logs: {len(items)}")
    for item in items[:args.limit]:
        print(f"  [{item.get('tag', '?'):<20}] {item.get('timestamp', '?')}  {item.get('description', '')[:100]}")
        if args.verbose:
            print(f"       {item.get('full_log', '')[:200]}")


def cmd_wazuh_block(args):
    wazuh = get_wazuh_client(verify_tls=not args.no_verify_tls)
    agent = "!0" if args.all_agents else args.agent
    if not agent:
        print("Provide --agent ID or --all-agents", file=sys.stderr)
        sys.exit(1)

    print(f"Blocking {args.ip} on agent(s) {agent}...")
    res = wazuh.block_ip(agent, args.ip, command=args.command)
    if res.get("_error"):
        print(f"FAIL: {res.get('_message', res.get('_body', 'unknown'))}")
        sys.exit(1)
    print("OK")


def cmd_wazuh_mitre(args):
    wazuh = get_wazuh_client(verify_tls=not args.no_verify_tls)
    if args.tactics:
        res = wazuh.get_mitre_tactics(search=args.search, limit=args.limit)
    else:
        res = wazuh.get_mitre_techniques(search=args.search, limit=args.limit)
    if res.get("_error"):
        print(f"FAIL: {res.get('_message', res.get('_body', 'unknown'))}")
        sys.exit(1)
    print(json.dumps(res.get("data", {}).get("affected_items", [])[:20], indent=2, default=str))


# ---------------------------------------------------------------------------
# Wazuh Indexer — Alert fetch commands
# ---------------------------------------------------------------------------

def cmd_fetch_alerts(args):
    indexer = get_indexer_client(verify_tls=not args.no_verify_tls)

    if args.sample:
        print("[*] Fetching sample alert document...")
        res = indexer.get_alert_sample(size=args.sample)
        if res.get("_error"):
            print(f"FAIL: {res.get('_message', res.get('_body', 'unknown'))}")
            sys.exit(1)
        print(json.dumps(res.get("hits", {}).get("hits", []), indent=2, default=str)[:2000])
        return

    if args.group:
        print(f"[*] Fetching IPs by rule group: {args.group} (last {args.days} days)...")
        results = indexer.fetch_ips_by_rule_group(args.group, days=args.days, max_results=args.limit)
    else:
        print(f"[*] Fetching suspicious external IPs (last {args.days} days, min_level={args.min_level or 'any'})...")
        results = indexer.fetch_suspicious_ips(
            days=args.days,
            min_level=args.min_level,
            max_results=args.limit,
            exclude_private=not args.include_private,
            agent_id=args.agent,
        )

    if isinstance(results, dict) and results.get("_error"):
        print(f"FAIL: {results.get('_message', results.get('_body', 'unknown'))}")
        sys.exit(1)

    print(f"[+] {len(results)} IPs found\n")
    print(f"{'IP':<18} {'Count':>8} {'Lvl':>4} {'Agent':<18} {'Rule Description':<45}")
    print("-" * 100)
    for r in results:
        print(f"{r['ip']:<18} {r['count']:>8} {r.get('rule_level') or '?' :>4} "
              f"{r.get('agent_name') or r.get('agent') or '?':<18} {r.get('rule_desc','?')[:45]}")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\n[+] Saved to {args.output}")


# ---------------------------------------------------------------------------
# Sync commands
# ---------------------------------------------------------------------------

def cmd_sync(args):
    if not ThreatDB:
        print("[ERROR] threat_db.py not found. Install linux-log-threat-hunt skill.", file=sys.stderr)
        sys.exit(1)

    db = ThreatDB()
    pushed = 0
    pulled = 0

    # Push local DB → MISP
    if args.to_misp or args.both:
        misp = get_misp_client(verify_tls=not args.no_verify_tls)
        iocs = db.list_iocs(min_confidence=args.min_confidence, days=args.days, limit=5000)
        # Filter: only those not reported to MISP in last N days
        fresh = []
        for ioc in iocs:
            # Simple heuristic: if never reported to VT, probably not reported to MISP either
            # A proper implementation would track last_reported_misp in the DB schema
            last_vt = ioc.get("last_reported_vt")
            if not last_vt or _older_than(last_vt, args.days):
                fresh.append({
                    "value": ioc["ip"],
                    "type": "ip-dst",
                    "category": "Network activity",
                    "confidence": ioc.get("confidence", "medium"),
                    "source": ",".join(json.loads(ioc.get("sources", "[]"))),
                    "comment": str(json.loads(ioc.get("evidence", "{}"))),
                })
        if fresh:
            print(f"Pushing {len(fresh)} IOCs to MISP...")
            res = misp.push_ioc_event(
                name=f"Auto-sync from {os.uname().nodename} — {len(fresh)} IOCs",
                iocs=fresh,
                tags=["auto-sync", "soc-connector"],
                threat_level=3,
            )
            if not res.get("_error"):
                pushed = len(fresh)
                print(f"OK: Event {res.get('event_id')}")
            else:
                print(f"FAIL: {res.get('_message', 'unknown')}")
        else:
            print("No new IOCs to push to MISP.")

    # Pull MISP → local DB
    if args.from_misp or args.both:
        misp = get_misp_client(verify_tls=not args.no_verify_tls)
        print(f"Pulling IOCs from MISP...")
        iocs = misp.pull_iocs(days=args.days, limit=5000)
        if isinstance(iocs, list):
            for ioc in iocs:
                db.upsert_ioc(
                    ioc["value"],
                    categories=[ioc.get("category", "misp_pull")],
                    sources=["misp"],
                    confidence="medium",
                    evidence={"misp_event": ioc.get("event_id"), "misp_info": ioc.get("event_info")},
                )
            pulled = len(iocs)
            print(f"Ingested {pulled} IOCs from MISP")
        else:
            print(f"FAIL: {iocs.get('_message', 'unknown')}")

    print(f"\nSync complete. Pushed {pushed}, pulled {pulled}.")


def _older_than(iso_timestamp, days):
    try:
        dt = datetime.fromisoformat(iso_timestamp)
        return datetime.now(timezone.utc) - dt > timedelta(days=days)
    except Exception:
        return True


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="SOC Connector — MISP + Wazuh integration")
    sub = parser.add_subparsers(dest="cmd")
    parser.add_argument("--no-verify-tls", action="store_true", help="Skip TLS verification")

    # MISP push
    p_misp_push = sub.add_parser("misp-push", help="Push IOCs to MISP as an event")
    p_misp_push.add_argument("--name", required=True, help="Event name")
    p_misp_push.add_argument("--ips-file", help="File with one IP/value per line (default: stdin)")
    p_misp_push.add_argument("--type", default="ip-dst", help="MISP attribute type")
    p_misp_push.add_argument("--category", default="Network activity")
    p_misp_push.add_argument("--tag", action="append", default=[], help="MISP tag(s)")
    p_misp_push.add_argument("--threat-level", type=int, default=3, choices=[1, 2, 3, 4])
    p_misp_push.add_argument("--confidence", default="medium")
    p_misp_push.add_argument("--source", default="soc-connector")
    p_misp_push.add_argument("--comment", help="Prefix comment for all attributes")
    p_misp_push.add_argument("--use-local-db", action="store_true", help="Pull IOCs from local DB instead of file")
    p_misp_push.add_argument("--min-confidence", default="medium")
    p_misp_push.add_argument("--days", type=int, default=7)

    # MISP pull
    p_misp_pull = sub.add_parser("misp-pull", help="Pull IOCs from MISP")
    p_misp_pull.add_argument("--days", type=int, default=7)
    p_misp_pull.add_argument("--type", help="Comma-separated attribute types")
    p_misp_pull.add_argument("--tag", action="append", default=[])
    p_misp_pull.add_argument("--limit", type=int, default=1000)
    p_misp_pull.add_argument("--output", help="Output JSON file")
    p_misp_pull.add_argument("--include-non-ids", action="store_true", help="Include non-to_ids attributes")
    p_misp_pull.add_argument("--use-local-db", action="store_true", help="Ingest into local DB")

    # MISP query
    p_misp_q = sub.add_parser("misp-query", help="Query MISP for IP/domain")
    p_misp_q.add_argument("--ip")
    p_misp_q.add_argument("--domain")

    # Wazuh agents
    p_waz_agents = sub.add_parser("wazuh-agents", help="List Wazuh agents")
    p_waz_agents.add_argument("--status", choices=["active", "disconnected", "never_connected", "pending"])
    p_waz_agents.add_argument("--limit", type=int, default=500)

    # Wazuh alerts (manager logs)
    p_waz_alerts = sub.add_parser("wazuh-alerts", help="Query Wazuh manager logs (not security alerts)")
    p_waz_alerts.add_argument("--search", help="Search term in log messages")
    p_waz_alerts.add_argument("--limit", type=int, default=50)
    p_waz_alerts.add_argument("--verbose", action="store_true")

    # Wazuh block
    p_waz_block = sub.add_parser("wazuh-block", help="Block IP via active response")
    p_waz_block.add_argument("--ip", required=True)
    p_waz_block.add_argument("--agent", help="Agent ID")
    p_waz_block.add_argument("--all-agents", action="store_true")
    p_waz_block.add_argument("--command", default="firewalld-drop",
                             help="Active response command (firewalld-drop, host-deny, etc.)")

    # Wazuh MITRE
    p_waz_mitre = sub.add_parser("wazuh-mitre", help="Query MITRE ATT&CK mappings")
    p_waz_mitre.add_argument("--tactics", action="store_true", help="List tactics instead of techniques")
    p_waz_mitre.add_argument("--search", help="Search term")
    p_waz_mitre.add_argument("--limit", type=int, default=100)

    # Wazuh Indexer — fetch alerts
    p_fetch = sub.add_parser("fetch-alerts", help="Query Wazuh security alerts via Indexer (OpenSearch)")
    p_fetch.add_argument("--days", type=int, default=3, help="Lookback days")
    p_fetch.add_argument("--min-level", type=int, help="Minimum rule severity level")
    p_fetch.add_argument("--agent", help="Filter by agent ID")
    p_fetch.add_argument("--group", help="Filter by rule group (e.g., sshd, attack, recon)")
    p_fetch.add_argument("--limit", type=int, default=200, help="Max unique IPs to return")
    p_fetch.add_argument("--include-private", action="store_true", help="Include RFC1918/private IPs")
    p_fetch.add_argument("--output", help="Save results to JSON file")
    p_fetch.add_argument("--sample", type=int, metavar="N", help="Show N sample alert docs (for schema inspection)")

    # Sync
    p_sync = sub.add_parser("sync", help="Bidirectional sync between local DB and MISP")
    p_sync.add_argument("--to-misp", action="store_true", help="Push local IOCs to MISP")
    p_sync.add_argument("--from-misp", action="store_true", help="Pull MISP IOCs to local DB")
    p_sync.add_argument("--both", action="store_true", help="Push then pull")
    p_sync.add_argument("--days", type=int, default=7)
    p_sync.add_argument("--min-confidence", default="medium")

    args = parser.parse_args()

    if args.cmd == "misp-push":
        cmd_misp_push(args)
    elif args.cmd == "misp-pull":
        cmd_misp_pull(args)
    elif args.cmd == "misp-query":
        cmd_misp_query(args)
    elif args.cmd == "wazuh-agents":
        cmd_wazuh_agents(args)
    elif args.cmd == "wazuh-alerts":
        cmd_wazuh_alerts(args)
    elif args.cmd == "wazuh-block":
        cmd_wazuh_block(args)
    elif args.cmd == "wazuh-mitre":
        cmd_wazuh_mitre(args)
    elif args.cmd == "fetch-alerts":
        cmd_fetch_alerts(args)
    elif args.cmd == "sync":
        cmd_sync(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
