# Issue → Incident: alternative kit-cloud SoC workspace

**Status:** private, read-only design prototype. Wiz-inspired investigation flow, not a copy of Wiz branding/components and **not** an incident-detection system. The existing dashboard, cron, GitHub Pages and alerting are unchanged.

## What our current data actually supports

| Integration | Available now | Do not infer |
|---|---|---|
| Wazuh Indexer | 7-day top source-IP alert counts, per-agent aggregate totals and run health; pipeline has rule description/agent sample in its own fetch | A per-source asset link, exploit success, compromise or complete timeline from dashboard aggregates |
| Local threat DB | Source IP observations, evidence and VT result cache | The identity of an affected application or a verified attack path |
| GN / OTX / AbuseIPDB | Cached reputation context on a subset of IPs; coverage has rate limits | Independent confirmation of an incident or attribution |
| MISP Event 1932 | Catalog of indicators (legacy `ip-dst`, new `ip-src`); dashboard contains only 30 recent attribute previews | Every cataloged IP was recently seen or is malicious; absence from the preview means absence from MISP |
| VT | Total comments posted; separate, strictly capped IOC publishing | A per-source VT verdict from `dashboard/data.json` or confirmation of exploitation |
| Clear NDR | A 24-hour IOC cross-check runs in the pipeline | A durable, per-asset/per-time evidence link in the existing dashboard JSON |
| Case management | No case/incident state store | A zero count of actual incidents: **not tracked** is the honest label |

## Design

```text
Overview                    Issues to review                       Evidence panel
 ├─ top source snapshot      ├─ source IP, 7d count, enrichment    ├─ observed Wazuh count
 ├─ MISP catalog size        └─ review order (not severity)       ├─ MISP: recent catalog presence only
 ├─ case count: N/A                                                ├─ GN/OTX/Abuse: context only
 └─ latest cron status                                             ├─ NDR/asset/outcome: missing link
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
- Public GitHub Pages remains aggregate, sanitized and review-only; it must never report incident counts from nonexistent case data.
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

The page labels cases **N/A** because no analyst case store is integrated. Before enabling private live incident views: collect per-alert Wazuh asset/time references; persist structured NDR matches (source/destination, timestamp, signature, asset mapping); add a reviewed case state store; test joins and false-positive handling; then add authentication/audit logging. No new platform is required for the prototype.
