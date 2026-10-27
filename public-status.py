#!/usr/bin/env python3
"""Write a tiny public run heartbeat; never publish errors, agents or evidence."""
from __future__ import annotations

import argparse
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


def write_status(state: str, path: Path = OUT, now: datetime | None = None) -> None:
    data = status_record(state, now)
    temp = path.with_suffix('.tmp')
    try:
        with temp.open('w') as fh:
            os.fchmod(fh.fileno(), 0o600)
            json.dump(data, fh, sort_keys=True)
            fh.write('\n')
            fh.flush()
            os.fsync(fh.fileno())
        temp.replace(path)
    finally:
        temp.unlink(missing_ok=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--state', choices=STATES, required=True)
    args = parser.parse_args()
    write_status(args.state)
    print('public pipeline heartbeat written:', args.state)
