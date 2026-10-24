#!/usr/bin/env bash
# No credentials or live SOC services are required.
set -euo pipefail
cd "$(dirname "$0")/.."
export SOC_TEST_USE_SNAPSHOT=1
python3 -m unittest discover -s tests -q
python3 -m unittest discover -s src/soc-connector/tests -q
node --check docs/app.js
node tests/test_public_ui.js
bash -n cron-run.sh backup.sh github-sync.sh
printf 'Offline SOC checks passed\n'
