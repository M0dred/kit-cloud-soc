#!/usr/bin/env python3
"""Build a bounded replay from explicitly selected, published snapshot commits."""
import argparse
from collections import defaultdict
from datetime import datetime
import ipaddress
import json
from pathlib import Path
import re
import subprocess


def stamp(value):
    d = datetime.strptime(value, '%Y-%m-%d %H:%M UTC')
    if d.strftime('%Y-%m-%d %H:%M UTC') != value:
        raise ValueError('invalid UTC minute')
    return d


def project(data, status):
    at = stamp(data['generated'])
    beat = stamp(status['last_attempt_utc'])
    if status.get('schema_version') != 1 or status.get('state') != 'ok' or abs((at-beat).total_seconds()) > 900 or 'public_revision' in data:
        raise ValueError('not a confirmed published batch')
    sources = data['wazuh']['top_src']
    if not isinstance(sources, list) or len(sources) > 20:
        raise ValueError('invalid public source selection')
    groups, seen = defaultdict(lambda: [0, 0]), set()
    for ip, count in sources:
        parsed = ipaddress.IPv4Address(ip)
        if ip in seen or not parsed.is_global or parsed.is_multicast or type(count) is not int or not 0 <= count < 10**9:
            raise ValueError('invalid source row')
        seen.add(ip)
        country = data['enrich_meta'].get(ip, {}).get('country')
        key = country if isinstance(country, str) and re.fullmatch(r'[A-Z]{2}', country) else 'unknown'
        groups[key][0] += 1
        groups[key][1] += count
    return {'batch_utc': data['generated'], 'countries': [[k, *v] for k, v in sorted(groups.items())]}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--repo', type=Path, required=True)
    p.add_argument('commits', nargs='+', help='reviewed commit IDs reachable on main')
    a = p.parse_args()
    if not 2 <= len(a.commits) <= 12 or not all(re.fullmatch(r'[0-9a-f]{7,40}', s) for s in a.commits):
        p.error('provide 2–12 reviewed commit IDs')
    git = ['git', '-C', str(a.repo)]
    frames = []
    for rev in a.commits:
        subprocess.run([*git, 'merge-base', '--is-ancestor', rev, 'refs/heads/main'], check=True, timeout=8)
        def load(path):
            return json.loads(subprocess.check_output([*git, 'show', f'{rev}:docs/{path}'], timeout=8))
        frames.append(project(load('data.json'), load('status.json')))
    frames.sort(key=lambda f: f['batch_utc'])
    if len({f['batch_utc'] for f in frames}) != len(frames):
        p.error('duplicate publication time')
    print(json.dumps({'schema_version': 1, 'frames': frames}, separators=(',', ':')))


if __name__ == '__main__':
    main()
