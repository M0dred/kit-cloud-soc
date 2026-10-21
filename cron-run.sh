#!/bin/bash
# Melbourne 08:00 / 16:00 via crontab. Debian cron ignores CRON_TZ; schedule is UTC 06:00 and 22:00.
# 1) Wazuh indexer → threat DB → GN/OTX/AIPDB → MISP 1932 (--skip-vt)
# 2) Local /var/log hunt
# 3) Clear NDR status
# 4) VT comments, capped
# Failures are sent to Telegram. Normal new-IOC notices stay in the orchestrator (notify_on=new_misp).
set -uo pipefail
export PATH=/usr/bin:/bin
LOCK=/run/soc-orchestrator.lock
LOG=/root/.config/soc-orchestrator/cron.log
ORCH=/root/.config/agents/skills/soc-connector/scripts/soc-orchestrator.py
HUNT=/root/.config/agents/skills/linux-log-threat-hunt/scripts/analyze-logs.py
NDR=/root/.config/agents/skills/soc-connector/scripts/ndr-cli.py
OUTDIR=/root/.config/soc-orchestrator
FAILS=()

notify_fail() {
  [ ${#FAILS[@]} -eq 0 ] && return 0
  local text
  text=$(printf '%s\n' "SOC cron FAILED $(date -u +%FT%TZ)" "${FAILS[@]}" "log: $LOG")
  /usr/bin/python3 - "$text" << 'PY'
import sys, json, urllib.request, urllib.parse, re
from pathlib import Path
text = sys.argv[1]
cfg = Path.home().joinpath(".config/soc-orchestrator/config.yaml").read_text()
token = re.search(r'bot_token:\s*"([^"]+)"', cfg).group(1)
chat = re.search(r'chat_id:\s*(\d+)', cfg).group(1)
body = urllib.parse.urlencode({"chat_id": chat, "text": text[:3500]}).encode()
req = urllib.request.Request(f"https://api.telegram.org/bot{token}/sendMessage", data=body)
try:
    urllib.request.urlopen(req, timeout=20).read()
except Exception as e:
    print(f"telegram notify failed: {e}", file=sys.stderr)
PY
}

exec 9>"$LOCK"
if ! flock -n 9; then
  echo "$(date -u +%FT%TZ) skip: previous run still holding lock" >>"$LOG"
  FAILS+=("previous run still holding lock")
  notify_fail
  exit 0
fi

MARK=$(date -u +%FT%TZ)
echo "$MARK START (Melbourne cron)" >>"$LOG"

echo "$(date -u +%FT%TZ) --- orchestrator (Wazuh+MISP) ---" >>"$LOG"
if ! /usr/bin/python3 "$ORCH" run --skip-vt >>"$LOG" 2>&1; then
  echo "$(date -u +%FT%TZ) orchestrator FAIL" >>"$LOG"
  FAILS+=("orchestrator exited non-zero")
fi

# rotate summary snapshot (keep 30)
S=/root/.config/soc-orchestrator/summaries
mkdir -p "$S"
if [ -f "$S/summary.json" ]; then
  cp "$S/summary.json" "$S/$(date -u +%Y%m%d-%H%M).json"
  ls -1t "$S"/20*.json 2>/dev/null | tail -n +31 | xargs -r rm --
fi
if ! timeout 5 bash -c 'echo >/dev/tcp/10.0.1.1/9200'; then
  FAILS+=("Wazuh indexer 10.0.1.1:9200 unreachable")
else
  echo "$(date -u +%FT%TZ) --- health ---" >>"$LOG"
  HEALTH=$(/usr/bin/python3 /root/.config/soc-orchestrator/health-check.py 2>>"$LOG") || FAILS+=("health check failed")
  printf '%s\n' "$HEALTH" >>"$LOG"
  while IFS= read -r line; do
    case "$line" in
      FAIL*) FAILS+=("${line#FAIL }") ;;
    esac
  done <<< "$HEALTH"
fi
IPS=$(awk -v m="$MARK" '$0 ~ m {p=1} p && /wazuh_ips:/ {print $2; exit}' "$LOG" || true)
if [ "${IPS:-x}" = "0" ]; then
  echo "$(date -u +%FT%TZ) note: 0 external IPs this window; not a failure if ingest is fresh" >>"$LOG"
fi

# IntelMQ removed from stack (2026-10-21): step disabled.

echo "$(date -u +%FT%TZ) --- NDR cross vs 1932 ---" >>"$LOG"
if ! /usr/bin/python3 /root/.config/soc-orchestrator/ndr-cross.py >>"$LOG" 2>&1; then
  echo "$(date -u +%FT%TZ) ndr-cross FAIL (non-fatal)" >>"$LOG"
fi

echo "$(date -u +%FT%TZ) --- local /var/log hunt ---" >>"$LOG"
if [ -f "$HUNT" ]; then
  if ! /usr/bin/python3 "$HUNT" /var/log >"$OUTDIR/logs-sensor-syd-cron.json" 2>>"$LOG"; then
    echo "$(date -u +%FT%TZ) log-hunt FAIL" >>"$LOG"
    FAILS+=("local log hunt failed")
  fi
else
  echo "analyze-logs.py missing" >>"$LOG"
  FAILS+=("analyze-logs.py missing")
fi

echo "$(date -u +%FT%TZ) --- NDR status ---" >>"$LOG"
if [ -f "$NDR" ]; then
  if ! /usr/bin/python3 "$NDR" status >>"$LOG" 2>&1; then
    echo "$(date -u +%FT%TZ) ndr FAIL" >>"$LOG"
    FAILS+=("NDR status failed")
  fi
else
  echo "ndr-cli.py missing" >>"$LOG"
  FAILS+=("ndr-cli.py missing")
fi

echo "$(date -u +%FT%TZ) --- VT comments (capped) ---" >>"$LOG"
if ! /usr/bin/python3 /root/.config/soc-orchestrator/vt_comment_new.py --max 25 --days 7 >>"$LOG" 2>&1; then
  echo "$(date -u +%FT%TZ) vt-comment FAIL" >>"$LOG"
  FAILS+=("VT comment job failed")
fi
if awk -v m="$MARK" '$0 ~ m {p=1} p && /429 quota/ {found=1} END {exit !found}' "$LOG"; then
  FAILS+=("VT comment hit 429 quota")
fi

if [ ${#FAILS[@]} -eq 0 ]; then
  echo "$(date -u +%FT%TZ) END ok" >>"$LOG"
else
  echo "$(date -u +%FT%TZ) END FAIL: ${FAILS[*]}" >>"$LOG"
  notify_fail
fi
