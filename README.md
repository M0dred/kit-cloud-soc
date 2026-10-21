# kit-cloud SoC

Homelab SOC pipeline: **Wazuh → enrichment (GreyNoise/OTX/AbuseIPDB) → MISP 1932 → VirusTotal community comments → Telegram**.

## Live dashboard

`docs/index.html` renders `docs/data.json` — open locally or serve via **GitHub Pages** (Settings → Pages → branch `main`, folder `/docs`).

Regenerated every pipeline run (UTC 06:00 / 22:00) by `dashboard-gen.py`. Contains **attacker IPs only** (defanged in UI), counts, and run history — no internal identifiers, no secrets.

## What's in this repo

| Path | Purpose |
|---|---|
| `cron-run.sh` | main pipeline, cron UTC 06:00/22:00 |
| `soc-orchestrator.py` (skills repo) | 6-stage: fetch → ingest → enrich → MISP → blocklist → vote |
| `vt_comment_new.py` | VT community comments, daily-capped, cloud-noise filtered |
| `health-check.py` | indexer + agent health, soft/hard severity |
| `ndr-cross.py` | MISP 1932 ∩ Clear NDR (LAN sightings → Telegram) |
| `dashboard-gen.py` | builds this dashboard |
| `config.example.yaml` | sanitized config — copy to `config.yaml` and fill keys |
| `memory.md` | operator handover notes |

## Setup on a new host

```bash
cp config.example.yaml config.yaml   # fill Wazuh/MISP/VT/GN/OTX/AIPDB/Telegram keys
crontab -e                           # 0 6,22 * * * /root/.config/soc-orchestrator/cron-run.sh
```

Requirements: Python 3.10+, `pyyaml`. Everything else is stdlib.

## Data sources

- Wazuh Indexer (alerts) · MISP 2.5 (Event 1932) · Clear NDR (LAN) · GreyNoise/OTX/AbuseIPDB (enrichment) · VirusTotal (community comments)

Contact: admin@kit-cloud.com
