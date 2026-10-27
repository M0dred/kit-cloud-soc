# kit-cloud SoC

Homelab SOC pipeline: **Wazuh Indexer → local threat DB → GreyNoise/OTX/AbuseIPDB → MISP Event 1932 → cautiously filtered VirusTotal community comments**. No automatic blocking or VT voting. New automated MISP attributes are **not** IDS-enabled (`to_ids=false`) until an analyst reviews them; older attributes are not changed automatically.

## Schedule and publication

- UTC `06:00` and `22:00`: `cron-run.sh` uses Wazuh → MISP and local NDR/log hunts; it runs the independently capped VT comment job (`vt_comment_new.py`, *at most 3 per run / 6 per UTC day*) and generates a dashboard.
- GitHub sync publishes privacy-checked `docs/data.json`, `docs/blocklist.txt` and `docs/status.json` after a complete run. If any pipeline stage fails, `github-sync.sh --status-only` publishes **only** a sanitized degraded heartbeat; it does not replace the last safe dashboard snapshot or disclose failure details. GitHub Pages uses `docs/`. Code/config changes are **not** auto-published: review, test, then commit/push manually.
- The local detailed dashboard lives in `dashboard/` (ignored by Git); private `ndr-evidence.json` retains bounded NDR alert samples and is not committed. Root-only `reviews.sqlite3` records **manual IOC review decisions** with evidence references and expiry; it never writes to MISP or GitHub and is **not** an incident/case store. Approvals/revocations still require a separate, verified human action in MISP. Public `docs/` suppresses agent/victim data, raw events and failure details; it shows exact Wazuh totals, **whitelisted labels and UTC time of bounded alert samples**, full 1932 membership **only for displayed source IPs**, enrichment lookup age/status, and the 24h pipeline's top-500 coverage limit. Samples are not complete behavior histories. The public watchlist requires MISP `to_ids=true`, corroborated SSH-source evidence and a non-cloud public IP. Older `to_ids=true` entries are **not** necessarily analyst-reviewed; one public IP does not mean MISP contains one indicator. The feed is **review-only**, never a command to block an IP.
- `02:30 UTC`: `backup.sh` writes a verified, root-only recovery archive to `/mnt/storage0/soc-backups` (contains secrets; do not upload). `backup-health.py` checks the current UTC day's archive after each SOC run; if absent/corrupt/unsafe it triggers the existing failure notification **without preventing an otherwise safe public sync**.
- These UTC times move by one hour in Melbourne during daylight saving. No SSH keys are installed.

## Code

| Path | Purpose |
|---|---|
| `cron-run.sh`, `backup.sh`, `backup-health.py`, `public-status.py`, `github-sync.sh` | active jobs, public run heartbeat and daily backup monitoring |
| `src/soc-connector/` | reviewed snapshot of live skill code; active file is under `~/.config/agents/skills/soc-connector/scripts/` |
| `src/linux-log-threat-hunt/threat_db.py` | snapshot of DB dependency; active copy lives under the skill |
| `ioc_comment.py` | one source comment template, shared by MISP and VT |
| `vt_comment_new.py` | strict, capped VT posting and offline `--dry-run` preview |
| `ndr-cross.py`, `health-check.py`, `dashboard-gen.py` | bounded private Wazuh/NDR evidence, health and split local/public dashboard |
| `docs/app.js`, `themes/issues-to-incidents.html`, `review-store.py` | safe public DOM rendering; private read-only evidence and local manual IOC reviews (not a case system) |
| `tests/` | offline regression/privacy, reviewed-IOC and healthy/degraded/stale-page tests |
| `config.example.yaml` | placeholder config, **never** the real `config.yaml` |

For a manual dry run of the VT selection (no posts):

```bash
python3 vt_comment_new.py --dry-run --max 3 --days 7
python3 -m unittest discover -s tests -v
```

`bash tests/run-offline.sh` runs the Python, JavaScript and shell checks without live SOC credentials, using the reviewed `src/` snapshot and pinned PyYAML (`requirements-test.txt`). GitHub Actions CI is not yet enabled: the current push credential lacks permission to add workflow files. To record a private manual decision: `python3 review-store.py record <PUBLIC_SOURCE_IP> --verdict approve_ids --reviewer <ID> --rationale '<20+ character evidence-based reason>' --evidence-ref <PRIVATE_ALERT_REF> --expires <UTC_ISO_TIME>`. This **does not** enable IDS flags in MISP; verify the evidence and make that separate decision in an authenticated MISP session. Expiry and revocation in this ledger do **not** automatically clear an existing MISP flag; the reviewer must reconcile that state manually. The reviewer identifier is self-declared and this local ledger is not a tamper-proof audited case system.

Live code updates to the skill must be **reviewed and copied into `src/`** before a separate code commit. The local backup contains live code as well. GitHub Pages is *not* a backup of credentials or state. Event 1932 includes legacy `ip-dst` entries that were actually observed as inbound sources; newly added attributes use `ip-src`, and consumers support both during migration.

Contact: admin@kit-cloud.com
