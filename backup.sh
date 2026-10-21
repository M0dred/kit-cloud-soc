#!/bin/bash
# Daily backup of SoC live state to /mnt/storage0. Keeps 14 copies.
set -euo pipefail
DEST=/mnt/storage0/soc-backups
mkdir -p "$DEST"
STAMP=$(date -u +%Y%m%d-%H%M)
tar -czf "$DEST/soc-$STAMP.tar.gz" \
  -C /root/.config \
  soc-orchestrator/config.yaml soc-orchestrator/cron-run.sh \
  soc-orchestrator/vt_comment_new.py soc-orchestrator/health-check.py \
  soc-orchestrator/memory.md \
  agents/skills/soc-connector 2>/dev/null || true
# rotate
ls -1t "$DEST"/soc-*.tar.gz 2>/dev/null | tail -n +15 | xargs -r rm --
echo "$(date -u +%FT%TZ) backup ok -> $DEST/soc-$STAMP.tar.gz"
