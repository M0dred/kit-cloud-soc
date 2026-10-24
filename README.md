# kit-cloud SoC

Homelab SOC pipeline: **Wazuh Indexer → local threat DB → GreyNoise/OTX/AbuseIPDB → MISP Event 1932 → cautiously filtered VirusTotal community comments**. No automatic blocking or VT voting. New automated MISP attributes are **not** IDS-enabled (`to_ids=false`) until an analyst reviews them; older attributes are not changed automatically.

## Schedule and publication

- UTC `06:00` and `22:00`: `cron-run.sh` uses Wazuh → MISP and local NDR/log hunts; it runs the independently capped VT comment job (`vt_comment_new.py`, *at most 3 per run / 6 per UTC day*) and generates a dashboard.
- GitHub sync is **restricted to `docs/data.json` and `docs/blocklist.txt`** after a successful pipeline and privacy gate, via `github-sync.sh`. GitHub Pages uses `docs/`. Code/config changes are **not** auto-published: review, test, then commit/push manually.
- The local detailed dashboard lives in `dashboard/` (ignored by Git); private `ndr-evidence.json` retains bounded NDR alert samples and is not committed. Public `docs/` suppresses agent/victim data, raw events and failure details; it shows exact Wazuh totals, **whitelisted labels and UTC time of bounded alert samples**, full 1932 membership **only for displayed source IPs**, enrichment lookup age/status, and the 24h pipeline's top-500 coverage limit. Samples are not complete behavior histories. The public watchlist is **review-only**, never a command to block an IP.
- `02:30 UTC`: `backup.sh` writes a verified, root-only recovery archive to `/mnt/storage0/soc-backups` (contains secrets; do not upload). `backup-health.py` checks the current UTC day's archive after each SOC run; if absent/corrupt/unsafe it triggers the existing failure notification **without preventing an otherwise safe public sync**.
- These UTC times move by one hour in Melbourne during daylight saving. No SSH keys are installed.

## Code

| Path | Purpose |
|---|---|
| `cron-run.sh`, `backup.sh`, `backup-health.py`, `github-sync.sh` | active jobs and daily backup monitoring |
| `src/soc-connector/` | reviewed snapshot of live skill code; active file is under `~/.config/agents/skills/soc-connector/scripts/` |
| `src/linux-log-threat-hunt/threat_db.py` | snapshot of DB dependency; active copy lives under the skill |
| `ioc_comment.py` | one source comment template, shared by MISP and VT |
| `vt_comment_new.py` | strict, capped VT posting and offline `--dry-run` preview |
| `ndr-cross.py`, `health-check.py`, `dashboard-gen.py` | bounded private Wazuh/NDR evidence, health and split local/public dashboard |
| `docs/app.js`, `themes/issues-to-incidents.html` | safe public DOM rendering; private read-only evidence workflow (not a case system) |
| `tests/test_pipeline.py`, `tests/test_dashboard.py`, `tests/test_backup_health.py`, `tests/test_public_ui.js` | offline regression/privacy and stale-page tests |
| `config.example.yaml` | placeholder config, **never** the real `config.yaml` |

For a manual dry run of the VT selection (no posts):

```bash
python3 vt_comment_new.py --dry-run --max 3 --days 7
python3 -m unittest discover -s tests -v
```

`bash tests/run-offline.sh` runs the Python, JavaScript and shell checks without live SOC credentials, using the reviewed `src/` snapshot and pinned PyYAML (`requirements-test.txt`). GitHub Actions CI is not yet enabled: the current push credential lacks permission to add workflow files. Live code updates to the skill must be **reviewed and copied into `src/`** before a separate code commit. The local backup contains live code as well. GitHub Pages is *not* a backup of credentials or state. Event 1932 includes legacy `ip-dst` entries that were actually observed as inbound sources; newly added attributes use `ip-src`, and consumers support both during migration.

Contact: admin@kit-cloud.com
