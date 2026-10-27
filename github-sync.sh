#!/bin/bash
# Only publish generated, privacy-checked docs; code changes require review.
set -euo pipefail
umask 077
export GIT_TERMINAL_PROMPT=0
REPO=/root/.config/soc-orchestrator
exec 8>/run/soc-github-sync.lock
flock -n 8 || { echo 'GitHub sync failed: another sync holds the lock'; exit 1; }
cd "$REPO"
mode="${1:-}"
if [ "$#" -gt 1 ] || { [ -n "$mode" ] && [ "$mode" != "--check-only" ] && [ "$mode" != "--status-only" ]; }; then
  echo 'usage: github-sync.sh [--check-only|--status-only]' >&2; exit 2
fi
python3 - "$mode" <<'PY'
import ipaddress
import json
import sys
from datetime import datetime
from pathlib import Path
import yaml
b=Path('/root/.config/soc-orchestrator')
status=json.loads((b/'docs/status.json').read_text())
assert set(status)=={'schema_version','state','last_attempt_utc'}
assert status['schema_version']==1 and status['state'] in ('ok','degraded','unknown')
assert datetime.strptime(status['last_attempt_utc'], '%Y-%m-%d %H:%M UTC')
if sys.argv[1]=='--status-only':
    print('GitHub public status privacy gate passed')
    sys.exit(0)
files=[b/'docs/data.json',b/'docs/blocklist.txt']
d=json.loads(files[0].read_text())
c=yaml.safe_load((b/'config.yaml').read_text())
assert set(d)=={'generated','wazuh','misp','vt','health','runs','blocklist_n','enrich_meta'}
assert set(d['wazuh'])=={'total_7d','top_src','by_day','by_agent','source_context','pipeline_24h_coverage'}
assert d['wazuh']['by_agent']==[]
context=d['wazuh']['source_context']
assert set(context)=={ip for ip,_ in d['wazuh']['top_src']}
assert all(set(v)=={'last_sample_utc','sample_behavior'} for v in context.values())
assert all(v['sample_behavior'] in {'SSH authentication alert',
  'Web request alert (outcome unverified)', 'Other detection (sample only)',
  'No alert sample available'} for v in context.values())
assert all(v['last_sample_utc'] is None or
  datetime.strptime(v['last_sample_utc'], '%Y-%m-%d %H:%M:%S UTC') for v in context.values())
coverage=d['wazuh']['pipeline_24h_coverage']
assert set(coverage)=={'bucket_limit','outside_top_alerts','approx_source_values','measured_at_utc'}
assert coverage['bucket_limit']==500
assert coverage['outside_top_alerts'] is None or (type(coverage['outside_top_alerts']) is int and
  0<=coverage['outside_top_alerts']<100000000)
assert coverage['approx_source_values'] is None or (type(coverage['approx_source_values']) is int and
  0<=coverage['approx_source_values']<100000000)
assert coverage['measured_at_utc'] is None or datetime.strptime(coverage['measured_at_utc'], '%Y-%m-%d %H:%M UTC')
assert set(d['misp'])=={'total','cidrs','recent_14d','membership_scope','top_source_membership'}
assert d['misp']['cidrs']==[]
assert d['health']=={'agents_down':'withheld'}
assert all(set(x)=={'ip','date','comment'} and x['comment']=='Observed source; review locally' for x in d['misp']['recent_14d'])
assert set(d['misp']['top_source_membership'])=={ip for ip,_ in d['wazuh']['top_src']}
assert all(type(value) is bool for value in d['misp']['top_source_membership'].values())
assert all(set(meta)<= {'gn','otx','aip','country','org','provider','sources'} for meta in d['enrich_meta'].values())
assert all(set(meta.get('sources',{}))== {'gn','otx','aipdb'} for meta in d['enrich_meta'].values())
assert all(not x['why'] for x in d['runs'])
ips=[line for line in files[1].read_text().splitlines() if line and not line.startswith('#')]
assert all(ipaddress.ip_address(ip).version==4 and ipaddress.ip_address(ip).is_global for ip in ips)
assert set(ips).isdisjoint(set((c.get('sensor_public_ips') or {}).values()))
assert all(not any(ip in path.read_text() for path in files) for ip in (c.get('sensor_public_ips') or {}).values())
def scan_credentials(obj):
 if isinstance(obj,dict):
  for key,value in obj.items():
   if any(word in str(key).lower() for word in ('pass','api_key','token')) and isinstance(value,str) and len(value)>12:
    assert not any(value in path.read_text() for path in files), 'credential in public docs'
   else: scan_credentials(value)
 elif isinstance(obj,list):
  for value in obj: scan_credentials(value)
scan_credentials(c)
print('GitHub public docs privacy gate passed')
PY
if [ "${1:-}" = "--check-only" ]; then
  echo 'GitHub sync check-only: no commit or push'
  exit 0
fi
# Never update a branch someone else advanced; do not auto-publish unreviewed code.
if ! git fetch --quiet origin main >/dev/null 2>&1; then
  echo 'GitHub sync failed: fetch origin/main' >&2; exit 1
fi
if [ "$(git rev-parse HEAD)" != "$(git rev-parse origin/main)" ]; then
  echo 'GitHub sync failed: local and origin/main differ; review manually' >&2; exit 1
fi
files=(docs/status.json)
if [ "$mode" != "--status-only" ]; then
  files+=(docs/data.json docs/blocklist.txt)
fi
git add -- "${files[@]}"
if git diff --cached --quiet -- "${files[@]}"; then
  echo 'GitHub docs already current'
  exit 0
fi
if ! git -c user.name='kit-cloud SoC' -c user.email='admin@kit-cloud.com' \
    commit -q -m "Update reviewed public SOC dashboard $(date -u +%Y-%m-%dT%H:%MZ)" \
    -- "${files[@]}"; then
  echo 'GitHub sync failed: commit' >&2; exit 1
fi
if ! git push -q origin HEAD:main >/dev/null 2>&1; then
  echo 'GitHub sync failed: push (local commit retained for review)' >&2; exit 1
fi
echo "$(date -u +%FT%TZ) GitHub docs synced"
