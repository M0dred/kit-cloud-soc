#!/usr/bin/env python3
"""Local, append-only IOC review decisions. Never changes MISP or public Pages.

This is an analyst review ledger, NOT an incident/case system or proof of
compromise. The reviewer identity is self-declared; filesystem access is root-only.
"""
from __future__ import annotations

import argparse
import ipaddress
import os
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

DB = Path('/root/.config/soc-orchestrator/reviews.sqlite3')
VERDICTS = ('approve_ids', 'reject', 'revoke')
SCHEMA = '''
CREATE TABLE IF NOT EXISTS reviews (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip TEXT NOT NULL,
  verdict TEXT NOT NULL CHECK(verdict IN ('approve_ids','reject','revoke')),
  reviewer TEXT NOT NULL,
  rationale TEXT NOT NULL,
  evidence_ref TEXT,
  reviewed_at_utc TEXT NOT NULL,
  expires_at_utc TEXT
);
CREATE INDEX IF NOT EXISTS reviews_by_ip ON reviews(ip, id);
CREATE TRIGGER IF NOT EXISTS reviews_no_update BEFORE UPDATE ON reviews
BEGIN SELECT RAISE(ABORT, 'review decisions are append-only'); END;
CREATE TRIGGER IF NOT EXISTS reviews_no_delete BEFORE DELETE ON reviews
BEGIN SELECT RAISE(ABORT, 'review decisions are append-only'); END;
'''


def open_db(path: Path = DB) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        os.close(fd)
    except FileExistsError:
        pass
    os.chmod(path, 0o600)
    con = sqlite3.connect(path)
    con.executescript(SCHEMA)
    return con


def valid_ip(ip: str) -> str:
    address = ipaddress.ip_address(ip)
    if address.version != 4 or not address.is_global:
        raise ValueError('source must be a global IPv4 address')
    return str(address)


def record(path: Path, ip: str, verdict: str, reviewer: str, rationale: str,
           evidence_ref: str | None = None, expires: str | None = None,
           now: datetime | None = None) -> int:
    ip = valid_ip(ip)
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if verdict not in VERDICTS:
        raise ValueError('invalid verdict')
    if not re.fullmatch(r'[A-Za-z0-9_.@-]{3,64}', reviewer):
        raise ValueError('reviewer identifier required (3–64 safe characters)')
    if not 20 <= len(rationale.strip()) <= 1000:
        raise ValueError('rationale must contain 20–1000 characters')
    if evidence_ref and not re.fullmatch(r'[A-Za-z0-9._:/-]{4,128}', evidence_ref):
        raise ValueError('private evidence reference must be a short opaque ID')
    expiry = None
    if expires:
        parsed = datetime.fromisoformat(expires.replace('Z', '+00:00'))
        if parsed.tzinfo is None or parsed.astimezone(timezone.utc) <= now:
            raise ValueError('expiry must be a future UTC time with timezone')
        expiry = parsed.astimezone(timezone.utc).isoformat()
    if verdict == 'approve_ids' and (not evidence_ref or not expiry):
        raise ValueError('IDS approval requires an evidence reference and future expiry')
    with open_db(path) as con:
        if verdict == 'revoke' and not con.execute(
                "SELECT 1 FROM reviews WHERE ip=? AND verdict='approve_ids' LIMIT 1", (ip,)).fetchone():
            raise ValueError('cannot revoke an IP without a prior recorded approval')
        cur = con.execute('''INSERT INTO reviews
            (ip, verdict, reviewer, rationale, evidence_ref, reviewed_at_utc, expires_at_utc)
            VALUES (?, ?, ?, ?, ?, ?, ?)''',
            (ip, verdict, reviewer, rationale.strip(), evidence_ref,
             now.isoformat(), expiry))
        return cur.lastrowid


def history(path: Path, ip: str) -> list[dict]:
    ip = valid_ip(ip)
    if not path.exists():
        return []
    with sqlite3.connect(path) as con:
        con.row_factory = sqlite3.Row
        rows = con.execute('SELECT * FROM reviews WHERE ip=? ORDER BY id', (ip,)).fetchall()
        return [dict(row) for row in rows]


def current_decision(path: Path, ip: str, now: datetime | None = None) -> str:
    events = history(path, ip)
    if not events:
        return 'unreviewed'
    last = events[-1]
    if last['verdict'] == 'approve_ids' and last['expires_at_utc']:
        if datetime.fromisoformat(last['expires_at_utc']) <= (now or datetime.now(timezone.utc)).astimezone(timezone.utc):
            return 'expired'
    return last['verdict']


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    read = sub.add_parser('status', help='local review decision only, not MISP state')
    read.add_argument('ip')
    put = sub.add_parser('record', help='append a manual decision; does NOT write to MISP')
    put.add_argument('ip')
    put.add_argument('--verdict', choices=VERDICTS, required=True)
    put.add_argument('--reviewer', required=True)
    put.add_argument('--rationale', required=True)
    put.add_argument('--evidence-ref', help='private alert/case reference; required for approval')
    put.add_argument('--expires', help='ISO UTC time with timezone; required for approval')
    args = parser.parse_args()
    try:
        if args.command == 'status':
            print('Local review:', current_decision(DB, args.ip), '(MISP state not checked)')
        else:
            row_id = record(DB, args.ip, args.verdict, args.reviewer, args.rationale,
                            args.evidence_ref, args.expires)
            print(f'Local decision #{row_id} recorded: {args.verdict}; no MISP or GitHub write')
    except (ValueError, sqlite3.Error) as exc:
        parser.error(str(exc))


if __name__ == '__main__':
    main()
