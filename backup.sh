#!/bin/bash
# Daily local recovery archive. Contains API credentials: never publish it.
set -euo pipefail
umask 077
DEST=/mnt/storage0/soc-backups
mkdir -p "$DEST"
chmod 700 "$DEST"
# Secure older archives too (including ones created before this fix).
find "$DEST" -maxdepth 1 -type f -name 'soc-*.tar.gz' -exec chmod 600 {} +
STAMP=$(date -u +%Y%m%d-%H%M)
TMP=$(mktemp "$DEST/.soc-XXXXXXXX.tar.gz")
trap 'rm -f "$TMP"' EXIT
# Do not conceal tar failures; don't back up Git objects, caches or generated logs.
EXTRA=()
if [ -f /root/.config/soc-orchestrator/reviews.sqlite3 ]; then
  EXTRA+=(soc-orchestrator/reviews.sqlite3)
fi
tar -czf "$TMP" --exclude='.git' --exclude='__pycache__' \
  -C /root/.config \
  soc-orchestrator/config.yaml soc-orchestrator/cron-run.sh \
  soc-orchestrator/ioc_comment.py soc-orchestrator/vt_comment_new.py \
  soc-orchestrator/github-sync.sh soc-orchestrator/dashboard-gen.py \
  soc-orchestrator/backup-health.py soc-orchestrator/public-status.py \
  soc-orchestrator/review-store.py \
  soc-orchestrator/health-check.py soc-orchestrator/ndr-cross.py \
  soc-orchestrator/memory.md soc-orchestrator/README.md \
  soc-orchestrator/vt-commented.txt soc-orchestrator/vt-comment-daily.json \
  soc-orchestrator/state.json soc-orchestrator/enrich-cache.json \
  linux-log-threat-hunt/threat-intel.db \
  agents/skills/soc-connector "${EXTRA[@]}"
# A successful tar exit and archive readback are both required.
tar -tzf "$TMP" > /dev/null
mv "$TMP" "$DEST/soc-$STAMP.tar.gz"
chmod 600 "$DEST/soc-$STAMP.tar.gz"
trap - EXIT
ls -1t "$DEST"/soc-*.tar.gz | tail -n +15 | xargs -r rm --
echo "$(date -u +%FT%TZ) backup verified: $DEST/soc-$STAMP.tar.gz"
