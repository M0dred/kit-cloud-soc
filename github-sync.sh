#!/bin/bash
# Only publish generated, privacy-checked docs; code changes require review.
set -euo pipefail
umask 077
export GIT_TERMINAL_PROMPT=0
REPO=/root/.config/soc-orchestrator
exec 8>/run/soc-github-sync.lock
flock -n 8 || { echo 'GitHub sync skipped: already running'; exit 0; }
cd "$REPO"
python3 - <<'PY'
import ipaddress
import json
from pathlib import Path
import yaml
b=Path('/root/.config/soc-orchestrator')
files=[b/'docs/data.json',b/'docs/blocklist.txt']
d=json.loads(files[0].read_text())
c=yaml.safe_load((b/'config.yaml').read_text())
assert d['health']=={'agents_down':'withheld'}
assert all(n.startswith('Sensor ') for n,_ in d['wazuh']['by_agent'])
assert all(x['comment']=='Observed source; review locally' for x in d['misp']['recent_14d'])
assert all(not x['why'] for x in d['runs'])
ips=[line for line in files[1].read_text().splitlines() if line and not line.startswith('#')]
assert all(ipaddress.ip_address(ip).version==4 and ipaddress.ip_address(ip).is_global for ip in ips)
assert set(ips).isdisjoint(set((c.get('sensor_public_ips') or {}).values()))
assert all(not any(ip in path.read_text() for path in files) for ip in (c.get('sensor_public_ips') or {}).values())
for group in (c.get('wazuh') or {},c.get('misp') or {},c.get('virustotal') or {},
              c.get('telegram') or {},c.get('ndr') or {},c.get('otx') or {},
              c.get('abuseipdb') or {},c.get('greynoise') or {}):
 for key,value in group.items():
  if any(word in key.lower() for word in ('pass','api_key','token')) and isinstance(value,str) and len(value)>12:
   assert not any(value in path.read_text() for path in files), 'credential in public docs'
print('GitHub public docs privacy gate passed')
PY
# Never update a branch someone else advanced; do not auto-publish unreviewed code.
if ! git fetch --quiet origin main >/dev/null 2>&1; then
  echo 'GitHub sync failed: fetch origin/main' >&2; exit 1
fi
if [ "$(git rev-parse HEAD)" != "$(git rev-parse origin/main)" ]; then
  echo 'GitHub sync failed: local and origin/main differ; review manually' >&2; exit 1
fi
git add -- docs/data.json docs/blocklist.txt
if git diff --cached --quiet -- docs/data.json docs/blocklist.txt; then
  echo 'GitHub docs already current'
  exit 0
fi
if ! git -c user.name='kit-cloud SoC' -c user.email='admin@kit-cloud.com' \
    commit -q -m "Update reviewed public SOC dashboard $(date -u +%Y-%m-%dT%H:%MZ)" \
    -- docs/data.json docs/blocklist.txt; then
  echo 'GitHub sync failed: commit' >&2; exit 1
fi
if ! git push -q origin HEAD:main >/dev/null 2>&1; then
  echo 'GitHub sync failed: push (local commit retained for review)' >&2; exit 1
fi
echo "$(date -u +%FT%TZ) GitHub docs synced"
