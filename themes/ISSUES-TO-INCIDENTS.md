# Issue → Incident: alternative kit-cloud SoC workspace

**Status:** private, read-only evidence workspace. Wiz-inspired investigation flow, not a copy of Wiz branding/components and **not** an incident-detection system. Public GitHub Pages gets only allowlisted source summary; no private evidence or incidents are published.

## What our current data actually supports

| Integration | Available now | Do not infer |
|---|---|---|
| Wazuh Indexer | Exact 7-day alert total, top source-IP counts; private snapshot includes at most three alerts per displayed source with UTC timestamp, rule and agent/destination; 24h pipeline records top-500 truncation | A complete timeline, full source coverage when the 500-bucket limit is hit, an exploit outcome or a proven asset relation from only three samples |
| Local threat DB | Source IP observations, evidence and VT result cache | The identity of an affected application or a verified attack path |
| GN / OTX / AbuseIPDB | Cached context with lookup time/status for new results; legacy cache entries have unknown age; existing request caps remain | Independent confirmation of an incident, benign verdict from a missing GN record, or attribution |
| MISP Event 1932 | Full membership for displayed source IPs (legacy `ip-dst`, new `ip-src`); separate recent preview; **new** automated attributes have `to_ids=false` pending review, old attributes unchanged | Catalog membership or a volume threshold proves compromise; older `to_ids=true` entries have all been reviewed |
| VT | Total comments posted; separate, strictly capped IOC publishing | A per-source VT verdict from `dashboard/data.json` or confirmation of exploitation |
| Clear NDR | A 24-hour MISP-IOC cross-check retains up to three matching alert samples per IOC side in root-only `ndr-evidence.json` | A verified join to Wazuh's affected asset/time, complete NDR coverage, or compromise from matching an IP |
| Case management | Local append-only `reviews.sqlite3` captures manually entered **IOC** review decisions; there is still no analyst case/incident state store or automatic MISP approval | A zero count of actual incidents: **not tracked** is the honest label |

## Design

```text
Overview                    Issues to review                       Evidence panel
 ├─ top source snapshot      ├─ source IP, 7d count, enrichment    ├─ observed Wazuh count
 ├─ MISP catalog size        └─ review order (not severity)       ├─ MISP: full catalog membership
 ├─ case count: N/A                                                ├─ GN/OTX/Abuse: context only
 └─ latest cron status                                             ├─ sampled Wazuh/NDR alerts; join/outcome missing
                                                                    └─ promotion checklist

Observed signal → issue to review → corroborated, asset/time-linked evidence
                                    → analyst decision → incident → manual containment
```

Design language: light canvas, ink/purple accents, compact left navigation, dense source table, persistent evidence drawer, and explicit missing-evidence steps. No fake attack-path lines or "confirmed attacker" score badges. Top counts are **triage volume**, not confidence. Panel reads existing local `dashboard/data.json` only, makes no API calls and has no mutating controls.

## A defensible promotion policy (future implementation)

1. **Observation:** raw Wazuh alert with UTC timestamp, `data.srcip`, rule ID/level, agent ID, original alert/document reference. Keep the rule as evidence, not as a verdict.
2. **Issue:** dedupe observations for one *known* asset/behavior/time window; record hypothesis and owner. Large alert count or MISP/VT listing alone never creates a confirmed incident.
3. **Incident candidate:** independent telemetry (e.g. Clear NDR, firewall or auth) correlated to the same source, asset and bounded UTC window. NAT, proxies and shared-cloud IPs require manual disambiguation. NDR "HIT" without that join is not a confirmed incident.
4. **Confirmed incident:** analyst documents credible malicious outcome or verified compromise (e.g. successful unauthorized auth + host evidence), timeline, affected asset, confidence and rationale. "HTTP 400", reputation score and scanner volume alone cannot promote.
5. **Response:** approval/owner, containment options, rollback and post-incident review. Auto-block stays disabled.

Minimal future private model: `observations(id, source_ip, agent_id, timestamp_utc, rule_id, raw_ref)`; `issues(id, dedupe_key, asset_ref, first_seen, last_seen, hypothesis, priority, owner, status)`; `evidence(issue_id, source, event_ref, timestamp_utc, relationship, caveat)`; `incidents(id, issue_ids, analyst, decision, confirmed_outcome, severity, state, opened_at, closed_at)`. Require provenance and UTC timestamps for every edge. Use SQLite or an existing case system, **not** MISP Event 1932 as a case table.

## Trust boundary

- Private case graph may contain agent names, victim/asset links and raw event references; keep it under a protected local service with authentication. Do **not** add it to public `docs/`, `dashboard-gen.py`'s public JSON, or automatic GitHub sync.
- Public GitHub Pages remains aggregate, sanitized and review-only; it must never report incident counts from nonexistent case data. A separate `docs/status.json` can report only the run state and UTC attempt time after a failure; last safe source data remains unchanged.
- The prototype is at `themes/issues-to-incidents.html`; it reads `../dashboard/data.json` when served from the repo root. **Never** expose the repository root using a generic HTTP server: it contains `config.yaml` and other secrets.

### Safe visual preview using already-public sanitized data

The following sandbox copies **only** the theme and the sanitized public JSON. It does not serve `config.yaml` or private dashboard data:

```bash
preview=$(mktemp -d)
mkdir -p "$preview/themes" "$preview/dashboard"
cp /root/.config/soc-orchestrator/themes/issues-to-incidents.html "$preview/themes/"
cp /root/.config/soc-orchestrator/docs/data.json "$preview/dashboard/data.json"
python3 -m http.server --bind 127.0.0.1 --directory "$preview" 8765
# open http://127.0.0.1:8765/themes/issues-to-incidents.html locally
# Ctrl-C then rm -rf -- "$preview"
```

The page labels cases **N/A** because no analyst case store is integrated. Private samples are bounded (Wazuh top three over 7d; NDR matches from Event 1932 over 24h), not a full search or verified outcome. Before enabling incident creation: define/test source+asset+UTC correlation, attach successful-auth/host outcome evidence, add a reviewed case state store, and protect a private service with authentication/audit logging. No new platform is required for this prototype.
