#!/usr/bin/env python3
"""Private first-level geography analysis; never linked from or written to Pages."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
import unicodedata
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from source_policy import iso_country, public_unicast

BASE = Path(__file__).resolve().parent
GEO = Path('/mnt/storage0/soc-geoatlas')  # Optional administrator-provisioned root-only dataset.
MIN_ROWS = 3
UTC = '%Y-%m-%d %H:%M UTC'


def stamp(value):
    d = datetime.strptime(value, UTC).replace(tzinfo=timezone.utc)
    if d.strftime(UTC) != value:
        raise ValueError('noncanonical UTC')
    return d


def count(value):
    return type(value) is int and 0 <= value <= 2**53-1


def label(value):
    if not isinstance(value, str) or len(value) > 72:
        return None
    value = ' '.join(unicodedata.normalize('NFC', value).strip().split())
    if not value or not value[0].isalpha() or not all(c.isalpha() or unicodedata.category(c).startswith('M') or c in " .,'’()-&" for c in value):
        return None
    return value


def cohort(raw):
    doc = json.loads(raw)
    stamp(doc['generated'])
    rows, meta = doc['wazuh']['top_src'], doc['enrich_meta']
    if not isinstance(rows, list) or len(rows)>20 or not isinstance(meta, dict):
        raise ValueError('invalid public cohort')
    seen, output = set(), []
    for row in rows:
        if not isinstance(row, list) or len(row)!=2 or not public_unicast(row[0]) or row[0] in seen or not count(row[1]):
            raise ValueError('invalid public source row')
        ip, alerts = row
        seen.add(ip)
        cc = iso_country((meta.get(ip) or {}).get('country')) or 'unknown'
        output.append((ip, alerts, cc))
    if not count(sum(n for _, n, _ in output)):
        raise ValueError('unsafe total')
    return doc['generated'], output


def envelope(raw, batch):
    return {'schema_version': 1, 'batch_utc': batch, 'snapshot_sha256': hashlib.sha256(raw).hexdigest(),
            'minimum_rows': MIN_ROWS, 'database_build_utc': None, 'countries': None}


def state_for(record, country):
    if country == 'unknown' or not isinstance(record, dict) or (record.get('country') or {}).get('iso_code') != country:
        return None  # Keep the earlier classification; never silently move a row across countries.
    candidates = record.get('subdivisions')
    if not isinstance(candidates, list) or not candidates or not isinstance(candidates[0], dict):
        return None
    names = candidates[0].get('names')
    return label(names.get('en')) if isinstance(names, dict) else None  # First-level only; no city or coordinates.


def profile(raw, lookup=None, build=None):
    batch, rows = cohort(raw)
    result = envelope(raw, batch)
    if lookup is None:
        return result
    stamp(build)
    partitions = defaultdict(lambda: defaultdict(lambda: [0, 0]))
    for ip, alerts, country in rows:
        key = state_for(lookup(ip), country) if country != 'unknown' else None
        pair = partitions[country][key]
        pair[0] += 1; pair[1] += alerts
    countries = {}
    for cc, bins in sorted(partitions.items()):
        visible, withheld = [], [0, 0]
        for name, (num, alerts) in bins.items():
            if name is not None and num >= MIN_ROWS:
                visible.append({'name': name, 'rows': num, 'alerts': alerts})
            else:
                withheld[0] += num; withheld[1] += alerts
        visible.sort(key=lambda x: (-x['alerts'], x['name']))
        countries[cc] = {'subdivisions': visible, 'withheld_rows': withheld[0], 'withheld_alerts': withheld[1]}
    result.update(database_build_utc=build, countries=countries)
    return result


def verify(raw, result):
    batch, rows = cohort(raw)
    required = envelope(raw, batch)
    if not isinstance(result, dict) or set(result) != set(required) or any(result[k] != v for k, v in required.items() if k not in ('database_build_utc', 'countries')):
        raise ValueError('sidecar does not match batch')
    if result['countries'] is None and result['database_build_utc'] is None:
        return
    stamp(result['database_build_utc'])
    totals = defaultdict(lambda: [0, 0])
    for _, alerts, cc in rows:
        totals[cc][0] += 1; totals[cc][1] += alerts
    countries = result['countries']
    if not isinstance(countries, dict) or countries.keys() != totals.keys():
        raise ValueError('country scope differs')
    for cc, a in countries.items():
        if set(a) != {'subdivisions', 'withheld_rows', 'withheld_alerts'} or not all(count(a[k]) for k in ('withheld_rows','withheld_alerts')):
            raise ValueError('invalid aggregate field')
        r, s, seen = a['withheld_rows'], a['withheld_alerts'], set()
        visible = a['subdivisions']
        if not isinstance(visible, list) or len(visible)>20//MIN_ROWS or (cc=='unknown' and visible):
            raise ValueError('invalid subdivision list')
        for cell in visible:
            if set(cell)!={'name','rows','alerts'} or not label(cell['name']) or label(cell['name'])!=cell['name'] or cell['name'] in seen or not count(cell['rows']) or cell['rows']<MIN_ROWS or not count(cell['alerts']):
                raise ValueError('invalid subdivision cell')
            seen.add(cell['name']);r+=cell['rows'];s+=cell['alerts']
        if [r,s]!=totals[cc]:
            raise ValueError('subdivisions do not reconcile')


def local_profile(raw, root=GEO, now=None):
    batch, _ = cohort(raw)  # A malformed public snapshot itself remains a publication failure.
    unavailable = envelope(raw, batch)
    try:
        if not root.is_dir() or root.is_symlink() or root.stat().st_mode & 0o077 or root.stat().st_uid!=os.getuid():
            return unavailable
        f = root/'city.mmdb'
        if not f.is_file() or f.is_symlink() or f.stat().st_mode & 0o077 or f.stat().st_uid!=os.getuid():
            return unavailable
        reader = root/'reader'
        if reader.is_dir() and not reader.is_symlink() and reader.stat().st_uid==os.getuid() and not reader.stat().st_mode & 0o077:
            sys.path.insert(0, str(reader))
        import maxminddb  # Optional apt package; not required for status-only or tests.
        with maxminddb.open_database(str(f)) as db:
            m = db.metadata()
            built = datetime.fromtimestamp(m.build_epoch, timezone.utc)
            if m.database_type!='DBIP-City-Lite' or not timedelta(0) <= (now or datetime.now(timezone.utc))-built <= timedelta(days=45):
                return unavailable
            return profile(raw, db.get, built.strftime(UTC))
    except (OSError, ImportError, ValueError, RuntimeError, TypeError, AttributeError, OverflowError):
        return unavailable  # Geography fails closed without blocking other public data.


def private_output(value):
    root = Path.home()/'.local/state/soc-audits'
    if root.is_symlink() or not root.is_dir() or root.stat().st_uid != os.getuid() or root.stat().st_mode & 0o077:
        raise ValueError('private audit directory unavailable')
    target = Path(value).resolve()
    if target.parent != root.resolve() or target.suffix != '.json':
        raise ValueError('output must be a JSON file directly in the private audit directory')
    return target


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--private-output', required=True, help='Output within the private audit directory, never Pages')
    a = p.parse_args()
    try:
        target = private_output(a.private_output)
    except (OSError, ValueError):
        p.error('output must be a JSON file in the restricted audit directory')
    raw = (BASE/'docs/data.json').read_bytes()
    out = local_profile(raw)
    verify(raw, out)
    with tempfile.NamedTemporaryFile(dir=target.parent, delete=False) as tmp:
        path = Path(tmp.name)
        try:
            tmp.write((json.dumps(out,ensure_ascii=False,indent=2)+'\n').encode());tmp.flush()
            path.chmod(0o600);path.replace(target)
        finally:
            path.unlink(missing_ok=True)


if __name__ == '__main__':
    main()
