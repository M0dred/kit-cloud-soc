#!/usr/bin/env python3
"""
Local threat intelligence database for linux-log-threat-hunt.

Features:
- Deduplicate IOCs across analysis runs
- Skip VT/AbuseIPDB reporting if already reported within cooldown window
- Self-hosted blocklist export (iptables, nftables, pf, plain text)
- Temporal tracking: first_seen, last_seen, hit_count
- Cross-host correlation: track which sensors observed each IP

Usage:
    from threat_db import ThreatDB
    db = ThreatDB()
    db.upsert_ioc("1.2.3.4", categories=["brute_force"], sources=["sensor-02"],
                  evidence={"ssh_failed": 42}, confidence="high")
    if db.should_report_vt("1.2.3.4", cooldown_hours=24):
        vt_client.report_ip(...)
        db.mark_reported_vt("1.2.3.4")
"""
import json
import os
import sqlite3
from datetime import datetime, timezone, timedelta

DEFAULT_DB_PATH = os.path.expanduser("~/.config/linux-log-threat-hunt/threat-intel.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS iocs (
    ip TEXT PRIMARY KEY,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    hit_count INTEGER DEFAULT 1,
    report_count INTEGER DEFAULT 0,
    last_reported_vt TEXT,
    last_reported_abuseipdb TEXT,
    vt_malicious INTEGER,
    vt_suspicious INTEGER,
    vt_harmless INTEGER,
    categories TEXT,      -- JSON list
    sources TEXT,         -- JSON list of hostnames
    evidence TEXT,        -- JSON dict
    confidence TEXT       -- low | medium | high | critical
);

CREATE TABLE IF NOT EXISTS observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    source TEXT NOT NULL,      -- hostname/sensor name
    log_type TEXT,             -- auth, web, system, etc.
    behavior TEXT,             -- ssh_brute, webshell_scan, etc.
    raw_evidence TEXT,
    FOREIGN KEY (ip) REFERENCES iocs(ip)
);

CREATE INDEX IF NOT EXISTS idx_iocs_last_seen ON iocs(last_seen);
CREATE INDEX IF NOT EXISTS idx_iocs_categories ON iocs(categories);
CREATE INDEX IF NOT EXISTS idx_iocs_confidence ON iocs(confidence);
CREATE INDEX IF NOT EXISTS idx_observations_ip ON observations(ip);
CREATE INDEX IF NOT EXISTS idx_observations_time ON observations(observed_at);
"""


class ThreatDB:
    def __init__(self, path=None):
        self.path = path or DEFAULT_DB_PATH
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        self._init_db()

    def _conn(self):
        return sqlite3.connect(self.path)

    def _init_db(self):
        with self._conn() as conn:
            conn.executescript(SCHEMA)

    # ------------------------------------------------------------------
    # Core CRUD
    # ------------------------------------------------------------------

    def upsert_ioc(self, ip, categories=None, sources=None, evidence=None,
                   confidence="medium", vt_malicious=None, vt_suspicious=None,
                   vt_harmless=None):
        """Insert or update an IOC, incrementing hit_count."""
        now = self._now()
        categories_json = json.dumps(sorted(set(categories or [])), default=str)
        sources_json = json.dumps(sorted(set(sources or [])), default=str)
        evidence_json = json.dumps(evidence or {}, default=str)

        with self._conn() as conn:
            cur = conn.execute(
                "SELECT hit_count, categories, sources, evidence FROM iocs WHERE ip = ?",
                (ip,),
            )
            row = cur.fetchone()
            if row:
                hit_count, old_cats, old_srcs, old_ev = row
                # Merge categories and sources
                merged_cats = sorted(set(json.loads(old_cats or "[]")) | set(categories or []))
                merged_srcs = sorted(set(json.loads(old_srcs or "[]")) | set(sources or []))
                merged_ev = {**json.loads(old_ev or "{}"), **(evidence or {})}
                conn.execute(
                    """UPDATE iocs SET
                        last_seen = ?,
                        hit_count = hit_count + 1,
                        categories = ?,
                        sources = ?,
                        evidence = ?,
                        confidence = ?,
                        vt_malicious = COALESCE(?, vt_malicious),
                        vt_suspicious = COALESCE(?, vt_suspicious),
                        vt_harmless = COALESCE(?, vt_harmless)
                    WHERE ip = ?""",
                    (now, json.dumps(merged_cats), json.dumps(merged_srcs),
                     json.dumps(merged_ev), confidence,
                     vt_malicious, vt_suspicious, vt_harmless, ip),
                )
            else:
                conn.execute(
                    """INSERT INTO iocs
                    (ip, first_seen, last_seen, categories, sources, evidence,
                     confidence, vt_malicious, vt_suspicious, vt_harmless)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (ip, now, now, categories_json, sources_json, evidence_json,
                     confidence, vt_malicious, vt_suspicious, vt_harmless),
                )

    def add_observation(self, ip, source, log_type=None, behavior=None, raw_evidence=None):
        """Log a single observation event for temporal analysis."""
        now = self._now()
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO observations (ip, observed_at, source, log_type, behavior, raw_evidence)
                VALUES (?, ?, ?, ?, ?, ?)""",
                (ip, now, source, log_type, behavior,
                 json.dumps(raw_evidence, default=str) if raw_evidence else None),
            )

    def get_ioc(self, ip):
        """Return dict for an IP or None."""
        with self._conn() as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT * FROM iocs WHERE ip = ?", (ip,)).fetchone()
            return dict(row) if row else None

    def list_iocs(self, min_confidence=None, category=None, source=None,
                  days=7, limit=1000):
        """Query IOCs with optional filters."""
        sql = "SELECT * FROM iocs WHERE 1=1"
        params = []
        if min_confidence:
            order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
            min_val = order.get(min_confidence, 1)
            # SQLite doesn't have enum ordering; use CASE
            sql += " AND (CASE confidence WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 ELSE 1 END) >= ?"
            params.append(min_val)
        if category:
            sql += " AND categories LIKE ?"
            params.append(f'%"{category}"%')
        if source:
            sql += " AND sources LIKE ?"
            params.append(f'%"{source}"%')
        if days:
            cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
            sql += " AND last_seen >= ?"
            params.append(cutoff)
        sql += " ORDER BY last_seen DESC LIMIT ?"
        params.append(limit)

        with self._conn() as conn:
            conn.row_factory = sqlite3.Row
            return [dict(r) for r in conn.execute(sql, params).fetchall()]

    # ------------------------------------------------------------------
    # Reporting deduplication
    # ------------------------------------------------------------------

    def should_report_vt(self, ip, cooldown_hours=24):
        """Return True if we haven't reported this IP to VT within the cooldown window."""
        row = self.get_ioc(ip)
        if not row:
            return True
        last = row.get("last_reported_vt")
        if not last:
            return True
        try:
            last_dt = datetime.fromisoformat(last)
            return datetime.now(timezone.utc) - last_dt > timedelta(hours=cooldown_hours)
        except Exception:
            return True

    # Backward-compatible alias
    should_report_to_vt = should_report_vt

    def should_report_abuseipdb(self, ip, cooldown_hours=24):
        """Same for AbuseIPDB."""
        row = self.get_ioc(ip)
        if not row:
            return True
        last = row.get("last_reported_abuseipdb")
        if not last:
            return True
        try:
            last_dt = datetime.fromisoformat(last)
            return datetime.now(timezone.utc) - last_dt > timedelta(hours=cooldown_hours)
        except Exception:
            return True

    # Backward-compatible alias
    should_report_to_abuseipdb = should_report_abuseipdb

    def mark_reported_vt(self, ip):
        self._mark_reported(ip, "last_reported_vt")

    def mark_reported_abuseipdb(self, ip):
        self._mark_reported(ip, "last_reported_abuseipdb")

    def _mark_reported(self, ip, column):
        now = self._now()
        with self._conn() as conn:
            conn.execute(
                f"UPDATE iocs SET {column} = ?, report_count = report_count + 1 WHERE ip = ?",
                (now, ip),
            )

    # ------------------------------------------------------------------
    # Blocklist export
    # ------------------------------------------------------------------

    def export_blocklist(self, fmt="txt", min_confidence="medium", days=7,
                         output_path=None):
        """Export blocklist in various firewall formats.

        fmts: txt, iptables, nftables, pf, json, csv
        """
        iocs = self.list_iocs(min_confidence=min_confidence, days=days, limit=10000)
        ips = [r["ip"] for r in iocs]

        if not output_path:
            ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            output_path = f"/tmp/blocklist_{ts}.{fmt}"

        if fmt == "txt":
            with open(output_path, "w") as f:
                f.write("# linux-log-threat-hunt blocklist\n")
                f.write(f"# Generated: {self._now()}\n")
                f.write(f"# Count: {len(ips)}\n")
                for ip in ips:
                    f.write(f"{ip}\n")

        elif fmt == "iptables":
            with open(output_path, "w") as f:
                f.write("#!/bin/sh\n# linux-log-threat-hunt iptables blocklist\n")
                f.write(f"# Generated: {self._now()}\n")
                for ip in ips:
                    f.write(f"iptables -A INPUT -s {ip} -j DROP\n")

        elif fmt == "nftables":
            with open(output_path, "w") as f:
                f.write("# linux-log-threat-hunt nftables blocklist\n")
                f.write(f"# Generated: {self._now()}\n")
                f.write("table inet threat_blocklist {\n  set bad_ips {\n    type ipv4_addr\n    flags interval\n    elements = { ")
                f.write(", ".join(ips))
                f.write(" }\n  }\n}\n")

        elif fmt == "pf":
            with open(output_path, "w") as f:
                f.write("# linux-log-threat-hunt pf blocklist\n")
                f.write(f"# Generated: {self._now()}\n")
                f.write("table <threat_intel> persist {\n")
                for ip in ips:
                    f.write(f"  {ip}\n")
                f.write("}\n")
                f.write("block drop quick from <threat_intel>\n")

        elif fmt == "json":
            with open(output_path, "w") as f:
                json.dump({
                    "generated": self._now(),
                    "count": len(ips),
                    "iocs": iocs,
                }, f, indent=2, default=str)

        elif fmt == "csv":
            import csv
            with open(output_path, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=[
                    "ip", "first_seen", "last_seen", "hit_count", "report_count",
                    "confidence", "categories", "sources",
                ])
                writer.writeheader()
                for r in iocs:
                    writer.writerow({k: r.get(k, "") for k in writer.fieldnames})

        return output_path

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def stats(self):
        with self._conn() as conn:
            total = conn.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
            reported = conn.execute(
                "SELECT COUNT(*) FROM iocs WHERE last_reported_vt IS NOT NULL"
            ).fetchone()[0]
            by_conf = conn.execute(
                "SELECT confidence, COUNT(*) FROM iocs GROUP BY confidence"
            ).fetchall()
            recent = conn.execute(
                "SELECT COUNT(*) FROM iocs WHERE last_seen >= datetime('now', '-24 hours')"
            ).fetchone()[0]
        return {
            "total_iocs": total,
            "reported_to_vt": reported,
            "by_confidence": dict(by_conf),
            "last_24h": recent,
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _now():
        return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Local threat intel database")
    sub = p.add_subparsers(dest="cmd")

    # query
    q = sub.add_parser("query", help="Query IOCs")
    q.add_argument("--ip", help="Lookup specific IP")
    q.add_argument("--min-confidence", choices=["low", "medium", "high", "critical"],
                   default="medium")
    q.add_argument("--category", help="Filter by category")
    q.add_argument("--source", help="Filter by sensor source")
    q.add_argument("--days", type=int, default=7)
    q.add_argument("--limit", type=int, default=100)

    # export
    e = sub.add_parser("export", help="Export blocklist")
    e.add_argument("--format", choices=["txt", "iptables", "nftables", "pf", "json", "csv"],
                   default="txt")
    e.add_argument("--output", help="Output file path")
    e.add_argument("--min-confidence", default="medium")
    e.add_argument("--days", type=int, default=7)

    # stats
    sub.add_parser("stats", help="Show database stats")

    # import
    imp = sub.add_parser("import", help="Import IPs from file or stdin")
    imp.add_argument("--file", help="File with one IP per line (default: stdin)")
    imp.add_argument("--category", default="unknown")
    imp.add_argument("--source", default="manual")
    imp.add_argument("--confidence", default="medium")

    args = p.parse_args()
    db = ThreatDB()

    if args.cmd == "query":
        if args.ip:
            result = db.get_ioc(args.ip)
            print(json.dumps(result, indent=2, default=str) if result else "Not found")
        else:
            results = db.list_iocs(min_confidence=args.min_confidence,
                                   category=args.category, source=args.source,
                                   days=args.days, limit=args.limit)
            print(json.dumps(results, indent=2, default=str))

    elif args.cmd == "export":
        path = db.export_blocklist(fmt=args.format, min_confidence=args.min_confidence,
                                   days=args.days, output_path=args.output)
        print(f"Exported to {path}")

    elif args.cmd == "stats":
        print(json.dumps(db.stats(), indent=2))

    elif args.cmd == "import":
        fh = open(args.file) if args.file else sys.stdin
        count = 0
        for line in fh:
            ip = line.strip()
            if ip and not ip.startswith("#"):
                db.upsert_ioc(ip, categories=[args.category], sources=[args.source],
                              confidence=args.confidence)
                count += 1
        print(f"Imported {count} IOCs")
