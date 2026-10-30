#!/usr/bin/env python3
"""Read-only daily backup check for the twice-daily SOC cron.

The 02:30 UTC backup job redirects failures to a log. This check turns a
missing/corrupt archive into an existing SOC failure notification at 06/22 UTC.
No archive contents or credentials are printed.
"""
from __future__ import annotations

import sys
import tarfile
from datetime import datetime, timezone
from pathlib import Path

DEST = Path('/mnt/storage0/soc-backups')
REQUIRED = {'soc-orchestrator/config.yaml', 'soc-orchestrator/cron-run.sh',
            'soc-orchestrator/warninglist_context.py',
            'agents/skills/soc-connector/scripts/soc-orchestrator.py'}


def verified_today(dest: Path = DEST, now: datetime | None = None) -> bool:
    day = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).strftime('%Y%m%d')
    try:
        if dest.stat().st_mode & 0o077:
            return False
        for archive in sorted(dest.glob(f'soc-{day}-*.tar.gz'), reverse=True):
            if archive.stat().st_mode & 0o077 or archive.stat().st_size == 0:
                continue
            try:
                with tarfile.open(archive, 'r:gz') as tar:
                    if REQUIRED.issubset(set(tar.getnames())):
                        return True
            except (OSError, tarfile.TarError):
                continue
    except OSError:
        return False
    return False


if __name__ == '__main__':
    if verified_today():
        print('daily root-only backup: present and readable')
    else:
        print('FAIL daily backup missing, unreadable or unsafe')
        sys.exit(1)
