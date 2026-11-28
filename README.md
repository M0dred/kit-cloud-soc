# kit-cloud SoC

**Evidence before escalation.** A homelab SOC pipeline connecting **Wazuh → local threat DB → GreyNoise/OTX/AbuseIPDB → MISP Event 1932 → cautiously filtered VirusTotal community comments**.

[**Open the Evidence Brief**](https://m0dred.github.io/kit-cloud-soc/) · [Classic Dashboard](https://m0dred.github.io/kit-cloud-soc/classic.html) · [Real Activity Heatmap](https://m0dred.github.io/kit-cloud-soc/activity.html) · [Country Pulse Map](https://m0dred.github.io/kit-cloud-soc/flow.html#pulse-map) · [Public snapshot](docs/data.json) · [Offline tests](tests/run-offline.sh)

![Pipeline state from the existing public status.json](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fraw.githubusercontent.com%2FM0dred%2Fkit-cloud-soc%2Fmain%2Fdocs%2Fstatus.json&query=%24.state&label=pipeline)
![Last pipeline attempt from the existing public status.json](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fraw.githubusercontent.com%2FM0dred%2Fkit-cloud-soc%2Fmain%2Fdocs%2Fstatus.json&query=%24.last_attempt_utc&label=last%20attempt%20UTC)

> The heartbeat and batch dashboard can be stale. Neither proves event freshness, compromise, or incident status. There is **no automatic blocking or VT voting**. New automated MISP attributes start with **IDS use disabled (`to_ids=false`)** until an analyst reviews them; older attributes are not changed automatically.


The Evidence Brief leads with batch time, the last known pipeline attempt, the exact seven-day total, and the bounded public cohort. A missed scheduled slot is overdue after a 30-minute grace period, even when the last published result was OK. Select a source to open an adjacent desktop inspector or an inline mobile detail. The map and other visualizations are secondary views. The classic layout restores the original hero and four KPI tiles on the same protected evidence pipeline and detail controls. These pages check the published heartbeat and batch once per minute while visible (or via **Check now**). Unchanged files keep chart and selection state; the last published batch is not live telemetry and the server-side schedule is unchanged.

**Real Activity Heatmap** shows the published Wazuh daily UTC counts, with optional rotatable and tiltable 3D columns. The first and last dates of the rolling window may be partial, and missing daily values stay distinct from zero. No hourly, geographical or sensor-to-target conclusions are drawn.

**Source Evidence Atlas** uses country-only totals from the real, published top-source subset. The default is a quiet choropleth with a numerical legend. Switch between alert volume, source count, and fresh lookup coverage (`rows with at least one fresh successful provider result / displayed rows in the group`). A visible zero is not an unplotted group, and coverage is not a risk score. The UTC sparkline shows all Wazuh alerts, not a country timeline, and retains gaps. The map starts paused; **Play highlights** steps by rank, not UTC event order. Moving dots and lines connect country label points to an off-map Wazuh summary, never to a real sensor or target. Toggle links for a shaded map, change the metric (alerts or source rows), or use the share strip, 2D/3D rankings and evidence breakdown. By default, the report groups `CN`, `TW`, and `HK` under China. Selecting that group highlights Taiwan on the main map and opens a regional inset with Taiwan and Hong Kong labels and counts by original code. The Hong Kong label point is from the same Natural Earth release’s 1:10m admin-0 geometry; no sensor positions appear. **Map options → Original labels** splits the rollup without changing data or boundaries. Rankings, 3D controls and evidence remain in expandable panels. Unknown labels and groups without an outline point remain in the table. Existing IP country labels are not attribution, and no new lookups are made.

[**SOC data flow**](https://m0dred.github.io/kit-cloud-soc/data-flow.html) traces the logical Collection → Enrichment → Action relationships. Selection highlights upstream and downstream dependencies and shows what may cross each trust boundary. Published heartbeat is context, not per-node health or a map of assets.

On the country map, **Live follow** highlights a newly verified published batch as it arrives. **Replay batches** steps through a small archive of reviewed publication times, plus eligible batches seen in the current tab. Replay reuses country aggregates from the published 7-day source subsets. Windows overlap, gaps are possible, and neither mode plays back individual alerts, inferred routes or sensor data.

Design references: [Shodan country filters](https://help.shodan.io/the-basics/search-query-fundamentals), [Censys aggregation and drill-down](https://docs.censys.com/docs/ls-api), and [GreyNoise Visualizer](https://docs.greynoise.io/docs/using-the-greynoise-visualizer). These are interaction references only; the atlas neither queries those products nor imports their data, map styles, or libraries.

The bundled outline is [Natural Earth public-domain data](https://www.naturalearthdata.com/about/terms-of-use/), 1:110m admin-0 countries, tag `v5.1.2`. It is served locally as `docs/world-map.json`, with approximate boundaries and country label points. To regenerate, supply the pinned upstream `ne_110m_admin_0_countries.geojson` to `python3 tools/build_world_map.py <geojson> docs/world-map.json`; the tool verifies its SHA-256 before conversion.

**States / provinces are private.** The public state/province aggregate was withdrawn after cross-artifact privacy review. `docs/subdivisions.json` now contains a fixed privacy notice, not counts or locations. Historical copies may still exist. The optional DB-IP City Lite analysis tool can write output only in the restricted local audit directory; it is not called by the publisher.

**Batch changes** compares the displayed snapshot with the preceding published data batch. Expand the tree for alert, coverage, catalog, watchlist and top-source-set changes. The rolling windows overlap; a source leaving the displayed set is not cleared or presumed absent. Heartbeat-only updates do not change the comparison. The diff contains counts, not historical source addresses.

Select a source to open an optional external lookup (GreyNoise, AlienVault OTX, AbuseIPDB, VirusTotal, Shodan or BGP/ASN). It opens only when clicked and sends the selected source IP to that provider; links do not imply that the scheduled pipeline queried that provider.

```mermaid
flowchart LR
  W[Wazuh alerts] --> P[Bounded enrichment]
  H[Private coverage preflight] --> P
  N[Local NDR / log hunts] --> Vgate{Required stages complete?}
  P --> M[MISP Event 1932]
  M --> R{Human review}
  R -->|approved separately| I[IDS-enabled indicator]
  R -->|public-safe subset only| D[Privacy-checked snapshot]
  D --> G[GitHub Pages]
  P --> Vgate
  Vgate --> V[Capped VT comments after source-specific evidence check]
  R -. never automatic .-> X[No blocking / no VT voting]
```

## What is dynamic—and what is deliberately not

| Area | Automated behavior | Human boundary |
|---|---|---|
| Pipeline heartbeat | Existing `public-status.py` writes only `status.json`; Shields reads its public `state` and UTC attempt time for the README badges | Only `ok` / `degraded` / `unknown` and UTC last-attempt time; never error details |
| Public dashboard | Complete runs can update `docs/data.json` and `docs/blocklist.txt` after privacy checks | Last safe snapshot is retained on failure; public data is not a live detection feed |
| Failed runs | `--status-only` publishes only the sanitized heartbeat | No failure details, evidence, agent/victim data, or empty replacement snapshot |
| Code and workflow | Manual review, test, commit and push | Code/config is never auto-published |
| MISP and response | Enrichment and previews guide review | IDS flags, blocking and incident decisions require a separate verified human action |

## Review model

- **Observation is not compromise.** Wazuh totals, NDR samples and catalog membership are leads, not verdicts.
- **MISP knowledge is not local proof.** Event 1932 includes legacy `ip-dst` entries actually observed as inbound sources; new attributes use `ip-src`, and consumers support both during migration.
- **IDS use stays off by default for new automated attributes.** The MISP new-event helper also defaults to `to_ids=false`, reports add/publish failures and requires manual review of partial events.
- **Public watchlist is not a block command.** It requires MISP `to_ids=true`, a shareable source, the existing conservative SSH/volume/provider filters, an independent successful positive lookup within 48h, and at least 20 actual Wazuh SSH authentication-failure alerts (each level ≥10) in the last 24h. Only the internal Indexer receives the batched evidence query. Mixed source counts, generic `sshd` messages, old MISP scores, a fresh zero or GreyNoise `suspicious` do not establish this evidence. Older `to_ids=true` entries are not necessarily analyst-reviewed, and one public IP does not imply one MISP indicator.
- **Manual review records are not a Case system.** `reviews.sqlite3` keeps bounded private decisions with evidence references and expiry, but it never writes to MISP or GitHub. Approval, revocation and expiry reconciliation still need separate authenticated action.
- **Public output is bounded.** Per-agent data, raw events, detailed failures and private AS context remain private. The 24-hour top-500 coverage limit and enrichment age/status are explicit.

<details>
<summary><strong>Private MISP Warninglists context</strong></summary>

After the Wazuh 24-hour top-500 source fetch, `warninglist_context.py` reads four **public upstream** MISP CIDR warninglists (AWS, Azure, GCP, Cloudflare) over verified HTTPS and writes only source IP/provider-range matches to root-only `warninglist-context.json`.

The local MISP's built-in lists are disabled and some are older; this job **does not enable them or write to MISP**. A range match is *not* a benign verdict, an allowlist, independent evidence, or an auto-exclusion. No MISP/VT selection threshold, IDS flag, blocklist, public Pages data, or automated response reads these labels.

The report shows top-500 coverage and upstream list versions. If any list is unavailable, malformed or older than 60 days, it becomes `unavailable` with **no matches**, not a false no-match finding. Optional lookup is skipped on dry runs. The private report is ignored by Git and backed up with root-only archives.

</details>

<details>
<summary><strong>Schedule, publication and recovery</strong></summary>

- **UTC `06:00`, `12:00`, `18:00` and `22:00`:** `cron-run.sh` attempts Wazuh → MISP and local NDR/log hunts four times daily, including the independently capped VT comment job (`vt_comment_new.py`, **at most 3 per run / 6 per UTC day**). Dashboard generation requires successful stages. These are scheduled attempts, not a freshness guarantee; additional attempts can increase API load and failure notifications while sources are down.
- **Enrichment limits:** reuse successful/explicit not-observed lookups for 24h without refreshing their timestamps. A 429 stops only that provider and persists a local pause (GN 24h, OTX/AbuseIPDB 6h); this is not the remote quota reset time. Per-provider attempt, success, error, not-found, cache, limit and skip counts are kept privately. Unknown data is not a benign verdict.
- **Sharing preflight:** hard coverage failures select private intake only (no MISP/VT or external enrichment); a later failed required NDR/log stage withholds VT and the full public snapshot. An internal MISP observation written earlier on otherwise valid inputs is not an incident or an IDS approval. `health-policy.json` is a root-only private object with a `sleep_eligible` array; absent policy means no soft exceptions. Configure the private `sensor_public_ips` inventory before enabling sharing. Public examples contain placeholders.
- The legacy direct IP batch-push and bulk DB export paths in `soc-connector.py` are retired: they did not apply the 1932 sharing checks. Private DB evidence is not a public comment source. The standalone VT job refuses to assume an empty deduplication or daily ledger if one is missing.
- **MISP publication:** the flat managed event must have the expected ID, a complete attribute inventory and confirmed published state. An ambiguous/failed add or publish leaves a private intent record (`misp-publish-pending.json`); unpublished or conflicting changes require authenticated human reconciliation. A later read may clear the intent only when the server already confirms the expected IDS-disabled attributes were published. Do not delete a pending record or publish someone else's edits simply to turn a run green. The read-before-publish comparison is not a server-side transaction.
- **Historical display corrections:** a separately reviewed public projection can be labeled with `public_revision`. The snapshot time and actual run heartbeat are not advanced. A new scheduled data snapshot supersedes the correction.
- **GitHub sync:** publishes privacy-checked `docs/data.json`, `docs/blocklist.txt`, `docs/snapshot-diff.json` and `docs/status.json` after a full data publication. `--status-only` publishes only the sanitized heartbeat. If sync fails after the first heartbeat write, the local heartbeat is corrected to `degraded`; the remote can still retain an old heartbeat while publishing is unavailable, so its age and independent notifications matter. A hard non-active Agent is a health failure on every run, including baseline; sleep-prone Agents remain warnings. Manager inventory is paginated and validated; a missing tracked Agent stays unknown until it reappears or an approved decommission is reconciled. Failed dashboard enrichment fallback fails the snapshot rather than silently publishing empty enrichment; DB-only AS context remains private.
- **Run history:** operator-verified status corrections are appended privately to the cron log, can only mark a completed run as failed, and appear in public run history on the next safe snapshot without exposing their reasons.
- **Local detailed dashboard:** lives in `dashboard/` and is ignored by Git. Private `ndr-evidence.json` retains bounded NDR alert samples and is not committed.
- **UTC `02:30`:** `backup.sh` writes a verified, root-only recovery archive to `/mnt/storage0/soc-backups`. It contains secrets and must never be uploaded. `backup-health.py` checks the current UTC day's archive after each SOC run and reports absent, corrupt or unsafe backups without forcing an otherwise safe public sync.
- UTC schedules move by one hour in Melbourne during daylight saving. No SSH keys are installed.
- The latest private local hunt output is `local-hunt-latest.json` (ignored by Git). The public text watchlist includes a UTC batch timestamp and a stale-use warning.
- Recovery archives now also include the private health baseline/policy, the local hunt executable and DB implementation, and any existing NDR evidence or pending MISP intent. Restore sensitive files only under restricted access. GitHub Pages is **not** a backup of credentials or state.

</details>

<details>
<summary><strong>Code map</strong></summary>

| Path | Purpose |
|---|---|
| `cron-run.sh`, `backup.sh`, `backup-health.py`, `public-status.py`, `github-sync.sh` | Active jobs, public heartbeat/SVG and daily backup monitoring |
| `src/soc-connector/` | Reviewed snapshot of live skill code; active file is under `~/.config/agents/skills/soc-connector/scripts/` |
| `src/linux-log-threat-hunt/threat_db.py` | Snapshot of DB dependency; active copy lives under the skill |
| `ioc_comment.py` | One source comment template: fixed public behavior labels, raw rule/target withheld; VT-only fenced summary with references outside the fence |
| `warninglist_context.py` | Root-only, read-only provider-range context; no actions or sharing |
| `vt_comment_new.py` | Strict, capped VT posting and offline `--dry-run` preview |
| `ndr-cross.py`, `health-check.py`, `dashboard-gen.py` | Bounded private Wazuh/NDR evidence, health and split local/public dashboard |
| `docs/app.js`, `themes/issues-to-incidents.html`, `review-store.py` | Safe public DOM rendering; private read-only evidence and local manual IOC reviews |
| `tests/` | Offline regression/privacy, reviewed-IOC and healthy/degraded/stale-page tests |
| `config.example.yaml` | Placeholder config, **never** the real `config.yaml` |

Live code updates to the skill must be reviewed and copied into `src/` before a separate code commit. The local backup contains live code as well.

</details>

## Local verification

To preview only the static dashboard on your own machine, from the repository root run `python3 -m http.server --bind 127.0.0.1 --directory docs 8000`, then open `http://127.0.0.1:8000/`. Do not serve the repository root. No SOC credentials are needed for this preview or `bash tests/run-offline.sh`.

For an operator dry run of VT selection (no posts; requires the private configuration and reads MISP):

```bash
python3 vt_comment_new.py --dry-run --max 3 --days 7
python3 -m unittest discover -s tests -v
bash tests/run-offline.sh
```

The offline suite uses the reviewed `src/` snapshot and pinned PyYAML (`requirements-test.txt`). **GitHub Actions CI is not yet enabled**: the current push credential lacks permission to add workflow files.

To record a private manual decision:

```bash
python3 review-store.py record <PUBLIC_SOURCE_IP> \
  --verdict approve_ids --reviewer <ID> \
  --rationale '<20+ character evidence-based reason>' \
  --evidence-ref <PRIVATE_ALERT_REF> --expires <UTC_ISO_TIME>
```

This does **not** enable IDS flags in MISP. Verify the evidence and make that separate decision in an authenticated MISP session. Expiry and revocation in this ledger do **not** automatically clear an existing MISP flag. The reviewer identifier is self-declared and the local ledger is not a tamper-proof audited Case system.

Contact: admin@kit-cloud.com
