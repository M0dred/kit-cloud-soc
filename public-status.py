#!/usr/bin/env python3
"""Write a tiny public run heartbeat; never publish errors, agents or evidence."""
from __future__ import annotations

import argparse
import html
import json
import os
from datetime import datetime, timezone
from pathlib import Path

OUT = Path('/root/.config/soc-orchestrator/docs/status.json')
STATES = ('ok', 'degraded', 'unknown')


def status_record(state: str, now: datetime | None = None) -> dict:
    if state not in STATES:
        raise ValueError('invalid public run state')
    timestamp = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    return {'schema_version': 1, 'state': state,
            'last_attempt_utc': timestamp.strftime('%Y-%m-%d %H:%M UTC')}


def status_svg(data: dict) -> str:
    """Render only the already public heartbeat; no exception or evidence details."""
    state = data['state']
    if state not in STATES:
        raise ValueError('invalid public run state')
    timestamp = datetime.strptime(data['last_attempt_utc'], '%Y-%m-%d %H:%M UTC')
    label, color = {
        'ok': ('Operational', '#4ade80'),
        'degraded': ('Degraded', '#fb7185'),
        'unknown': ('Unknown', '#a8b3cf'),
    }[state]
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="620" height="106" viewBox="0 0 620 106" role="img" aria-label="Pipeline status: {html.escape(label)}">
  <rect width="620" height="106" rx="12" fill="#191b36"/>
  <circle cx="28" cy="32" r="7" fill="{color}"/>
  <text x="47" y="38" fill="#ffffff" font-family="system-ui,sans-serif" font-size="17" font-weight="700">Pipeline status: {html.escape(label)}</text>
  <text x="20" y="67" fill="#d8d9ec" font-family="system-ui,sans-serif" font-size="13">Last attempt: {html.escape(timestamp.strftime('%Y-%m-%d %H:%M UTC'))}</text>
  <text x="20" y="89" fill="#a8b3cf" font-family="system-ui,sans-serif" font-size="11">Sanitized heartbeat · not an incident verdict or proof of freshness</text>
</svg>
'''


def _atomic_text(path: Path, content: str) -> None:
    temp = path.with_suffix('.tmp')
    try:
        with temp.open('w', encoding='utf-8') as fh:
            os.fchmod(fh.fileno(), 0o600)
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        temp.replace(path)
    finally:
        temp.unlink(missing_ok=True)


def write_status(state: str, path: Path = OUT, now: datetime | None = None) -> None:
    data = status_record(state, now)
    _atomic_text(path, json.dumps(data, sort_keys=True) + '\n')
    _atomic_text(path.with_suffix('.svg'), status_svg(data))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--state', choices=STATES, required=True)
    args = parser.parse_args()
    write_status(args.state)
    print('public pipeline heartbeat written:', args.state)
