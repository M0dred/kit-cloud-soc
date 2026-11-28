#!/usr/bin/env bash
# No credentials or live SOC services are required.
set -euo pipefail
cd "$(dirname "$0")/.."
export SOC_TEST_USE_SNAPSHOT=1
python3 -m unittest discover -s tests -q
python3 -m unittest discover -s src/soc-connector/tests -q
node --check docs/public-view.js
node --check docs/published-refresh.js
node --check docs/app.js
node --check docs/tree.js
node --check docs/flow.js
node --check docs/country-map.js
node --check docs/activity.js
node tests/test_public_ui.js
node tests/test_public_ui_ux.js
node tests/test_published_refresh.js
node tests/test_snapshot_tree.js
node tests/test_country_flow.js
node tests/test_country_map.js
node tests/test_real_activity.js
for script in cron-run.sh backup.sh github-sync.sh; do bash -n "$script"; done
printf 'Offline SOC checks passed\n'
