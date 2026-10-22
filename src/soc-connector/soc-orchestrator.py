#!/usr/bin/env python3
"""
soc-orchestrator — Unified SOC pipeline.

Stages:
  1. Fetch suspicious IPs from Wazuh Indexer
  2. Ingest into local threat DB (deduplication)
  3. VT-check new/unseen IPs (rate-limited)
  4. Update MISP event (add new attributes, no duplicates)
  5. Generate blocklist
  6. Auto-block high-confidence IPs via Wazuh active response (optional)

Usage:
    # Run full pipeline
    python3 soc-orchestrator.py run --config ~/.config/soc-orchestrator/config.yaml

    # Dry-run (no MISP push, no blocks)
    python3 soc-orchestrator.py run --dry-run

    # Show current state
    python3 soc-orchestrator.py status
"""
import argparse
import ipaddress
import json
import os
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

# Add skill paths
_SKILL_ROOT = Path(__file__).parent.resolve()
sys.path.insert(0, str(_SKILL_ROOT))
sys.path.insert(0, os.path.expanduser("~/.config/agents/skills/linux-log-threat-hunt/scripts"))
sys.path.insert(0, os.path.expanduser("~/.config/soc-orchestrator"))

from wazuh_indexer import WazuhIndexerClient
from wazuh_client import WazuhClient
from misp_client import MISPClient
from threat_db import ThreatDB
import intel_enrich
from ioc_comment import render_comment


# ---------------------------------------------------------------------------
# Config / State
# ---------------------------------------------------------------------------

DEFAULT_CONFIG = Path.home() / ".config/soc-orchestrator/config.yaml"
STATE_FILE = Path.home() / ".config/soc-orchestrator/state.json"


def load_config(path):
    import yaml
    with open(path) as f:
        return yaml.safe_load(f)


def load_state():
    if STATE_FILE.exists():
        with open(STATE_FILE) as f:
            return json.load(f)
    return {}


def save_state(state):
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2, default=str)


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

class Orchestrator:
    def __init__(self, cfg, dry_run=False, skip_vt=False):
        self.cfg = cfg
        self.dry_run = dry_run
        self.skip_vt = skip_vt
        self.state = load_state()
        self.summary = {
            "started": datetime.now(timezone.utc).isoformat(),
            "stage_results": {},
        }

        # Clients
        w = cfg["wazuh"]
        self.indexer = WazuhIndexerClient(
            w["indexer_host"], w["indexer_user"], w["indexer_pass"],
            verify_tls=w.get("verify_tls", True),
        )
        self.wazuh_mgr = WazuhClient(
            w["manager_url"], w["manager_user"], w["manager_pass"],
            verify_tls=w.get("verify_tls", True),
        )

        m = cfg["misp"]
        self.misp = MISPClient(
            m["url"], m["api_key"], verify_tls=m.get("verify_tls", True),
        )

        self.db = ThreatDB(cfg.get("database", {}).get("path"))

    def log(self, msg):
        print(msg)

    @staticmethod
    def _public_ipv4(value):
        try:
            address = ipaddress.ip_address(value)
            return address.version == 4 and address.is_global
        except (ValueError, TypeError):
            return False

    # ------------------------------------------------------------------
    # Stage 1: Fetch from Wazuh
    # ------------------------------------------------------------------

    def stage_fetch_wazuh(self):
        self.log("\n[STAGE 1] Fetching suspicious IPs from Wazuh Indexer...")
        hours = self.cfg["pipeline"]["lookback_hours"]
        min_level = self.cfg["pipeline"]["min_wazuh_level"]

        results = self.indexer.fetch_suspicious_ips(
            days=max(1, hours // 24),
            min_level=min_level,
            max_results=500,
            exclude_private=True,
        )

        if isinstance(results, dict) and results.get("_error"):
            raise RuntimeError(f"Wazuh Indexer fetch failed: {results.get('_status', results.get('_message', 'unknown'))}")

        results = [item for item in results if self._public_ipv4(item.get("ip"))]
        self.log(f"    [+] {len(results)} suspicious external IPs found")
        self.summary["stage_results"]["wazuh_ips"] = len(results)
        self._wazuh_ips = results
        return results

    # ------------------------------------------------------------------
    # Stage 2: Ingest to local DB
    # ------------------------------------------------------------------

    def stage_ingest_db(self, wazuh_ips):
        self.log("\n[STAGE 2] Ingesting into local threat DB...")
        ingested = 0
        new_ips = []

        for item in wazuh_ips:
            ip = item["ip"]
            count = item.get("count", 0)
            lvl = item.get("rule_level", 0) or 0
            agent = item.get("agent_name", "unknown")
            desc = item.get("rule_desc", "")

            try:
                lvl_num = int(lvl)
            except (ValueError, TypeError):
                lvl_num = 0

            confidence = (
                "critical" if lvl_num >= 13 else
                "high" if lvl_num >= 10 else
                "medium" if count > 100 else "low"
            )

            row = self.db.get_ioc(ip)
            is_new = row is None

            self.db.upsert_ioc(
                ip,
                categories=item.get("rule_groups", ["wazuh"]),
                sources=["wazuh", agent],
                evidence={
                    "wazuh_count": count,
                    "wazuh_level": lvl_num,
                    "wazuh_rule": desc,
                    "wazuh_agent": agent,
                },
                confidence=confidence,
            )
            ingested += 1
            if is_new:
                new_ips.append(ip)

        self.log(f"    [+] {ingested} IPs ingested ({len(new_ips)} new)")
        self.summary["stage_results"]["db_ingested"] = ingested
        self.summary["stage_results"]["db_new"] = len(new_ips)
        return new_ips

    # ------------------------------------------------------------------
    # Stage 3: VT Check
    # ------------------------------------------------------------------

    def stage_vt_check(self, candidate_ips):
        self.log("\n[STAGE 3] Checking VirusTotal (rate-limited)...")
        vt_cfg = self.cfg.get("virustotal", {})
        api_key = vt_cfg.get("api_key")
        max_checks = vt_cfg.get("max_checks_per_run", 20)
        delay = vt_cfg.get("delay_seconds", 30)
        cooldown = vt_cfg.get("cooldown_hours", 24)

        if not api_key:
            self.log("    [!] No VT_API_KEY configured — skipping")
            return {}

        import ssl
        import urllib.request

        ctx = ssl.create_default_context()

        # Prioritize: never-checked first, then by Wazuh count
        prioritized = []
        for ip in candidate_ips:
            if self.db.should_report_vt(ip, cooldown_hours=cooldown):
                row = self.db.get_ioc(ip)
                count = json.loads(row.get("evidence", "{}")).get("wazuh_count", 0) if row else 0
                prioritized.append((ip, count))

        prioritized.sort(key=lambda x: -x[1])
        to_check = prioritized[:max_checks]

        checked = 0
        malicious_found = 0
        vt_results = {}

        for ip, _ in to_check:
            req = urllib.request.Request(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={"x-apikey": api_key, "User-Agent": "soc-orchestrator/1.0"},
            )
            try:
                with urllib.request.urlopen(req, context=ctx, timeout=30) as r:
                    data = json.loads(r.read().decode())
                    attrs = data.get("data", {}).get("attributes", {})
                    stats = attrs.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    harmless = stats.get("harmless", 0)

                    vt_results[ip] = {
                        "malicious": malicious,
                        "suspicious": suspicious,
                        "harmless": harmless,
                        "as_owner": attrs.get("as_owner", "?"),
                        "country": attrs.get("country", "?"),
                    }

                    self.db.upsert_ioc(
                        ip,
                        vt_malicious=malicious,
                        vt_suspicious=suspicious,
                        vt_harmless=harmless,
                    )
                    self.db.mark_reported_vt(ip)
                    checked += 1

                    if malicious > 0 or suspicious > 0:
                        malicious_found += 1

                    if checked < len(to_check):
                        time.sleep(delay)
            except urllib.error.HTTPError as e:
                if e.code == 429:
                    self.log(f"    ⚠️  Rate limited — waiting 60s...")
                    time.sleep(60)
                else:
                    self.log(f"    ⚠️  {ip}: HTTP {e.code}")
            except Exception as e:
                self.log(f"    ⚠️  {ip}: {str(e)[:60]}")

        self.log(f"    [+] VT checked {checked} IPs, {malicious_found} malicious/suspicious")
        self.summary["stage_results"]["vt_checked"] = checked
        self.summary["stage_results"]["vt_malicious"] = malicious_found
        return vt_results

    # ------------------------------------------------------------------
    # Stage 3b: VT Vote + Comment
    # ------------------------------------------------------------------

    def stage_vt_vote(self, vt_results, wazuh_ips):
        vt_cfg = self.cfg.get("virustotal", {})
        vote_cfg = vt_cfg.get("auto_vote", {})
        if not vote_cfg.get("enabled", False):
            self.log("\n[STAGE 3b] VT auto-vote: disabled")
            return

        self.log("\n[STAGE 3b] Voting + commenting on VirusTotal...")

        import ssl
        import urllib.request

        ctx = ssl.create_default_context()

        api_key = vt_cfg.get("api_key")
        min_score = vote_cfg.get("min_vt_score", 2)
        min_count = vote_cfg.get("min_wazuh_count", 100)
        verdict = vote_cfg.get("verdict", "malicious")
        add_comment = vote_cfg.get("add_comment", True)
        delay = max(16, int(vt_cfg.get("delay_seconds", 30)))

        # Build wazuh count lookup
        count_map = {item["ip"]: item.get("count", 0) for item in wazuh_ips}
        agent_map = {item["ip"]: item.get("agent_name") or item.get("agent") or "unknown" for item in wazuh_ips}
        rule_map = {item["ip"]: item.get("rule_desc") or "" for item in wazuh_ips}
        level_map = {item["ip"]: item.get("rule_level", 0) for item in wazuh_ips}

        voted = 0
        commented = 0

        for ip, data in vt_results.items():
            vt_score = data.get("malicious", 0) + data.get("suspicious", 0)
            wazuh_count = count_map.get(ip, 0)

            if vt_score < min_score or wazuh_count < min_count:
                continue

            if self.dry_run:
                self.log(f"    [DRY-RUN] Would vote {verdict} on {ip}")
                voted += 1
                continue

            # Vote
            vote_body = json.dumps({
                "data": {"type": "vote", "attributes": {"verdict": verdict}}
            }).encode()

            req = urllib.request.Request(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}/votes",
                data=vote_body,
                headers={
                    "x-apikey": api_key,
                    "User-Agent": "soc-orchestrator/1.0",
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, context=ctx, timeout=30) as r:
                    self.log(f"    ✅ {ip}: voted {verdict}")
                    voted += 1
            except urllib.error.HTTPError as e:
                body = e.read().decode()[:100]
                if e.code == 429:
                    self.log(f"    ⚠️  Rate limited — waiting 60s")
                    time.sleep(60)
                elif "already voted" in body.lower():
                    self.log(f"    [-] {ip}: already voted")
                else:
                    self.log(f"    ⚠️  {ip}: vote failed HTTP {e.code}")
            except Exception as e:
                self.log(f"    ⚠️  {ip}: vote error {str(e)[:60]}")

            # Comment
            if add_comment:
                comment_text = self._vt_comment(
                    ip, wazuh_count, agent_map.get(ip), rule_map.get(ip), data,
                    intel=(getattr(self, "intel", {}) or {}).get(ip) or {},
                    level=level_map.get(ip),
                    sensor_public_ips=self.cfg.get("sensor_public_ips"),
                )
                comment_body = json.dumps({
                    "data": {"type": "comment", "attributes": {"text": comment_text}}
                }).encode()

                req = urllib.request.Request(
                    f"https://www.virustotal.com/api/v3/ip_addresses/{ip}/comments",
                    data=comment_body,
                    headers={
                        "x-apikey": api_key,
                        "User-Agent": "soc-orchestrator/1.0",
                        "Content-Type": "application/json",
                    },
                    method="POST",
                )
                try:
                    with urllib.request.urlopen(req, timeout=30) as r:
                        self.log(f"       ✅ comment added")
                        commented += 1
                except urllib.error.HTTPError as e:
                    body = e.read().decode()[:100]
                    if e.code == 429:
                        time.sleep(60)
                    elif "duplicate" in body.lower() or "already" in body.lower():
                        pass
                except Exception:
                    pass

            time.sleep(delay)

        self.log(f"    [+] Voted {voted} IPs, commented {commented}")
        self.summary["stage_results"]["vt_voted"] = voted
        self.summary["stage_results"]["vt_commented"] = commented

    @staticmethod
    def _merge_enrichment_cache(cache, updates):
        """Preserve the last success; record failed/limited attempts separately."""
        for ip, rec in updates.items():
            if not any(name in rec for name in ("gn", "otx", "aipdb")):
                continue
            prev = cache.setdefault(ip, {})
            lookups = prev.setdefault("_lookups", {})
            for name in ("gn", "otx", "aipdb"):
                if name not in rec:
                    continue
                value = rec[name] or {}
                when = rec.get(f"{name}_checked_at")
                history = lookups.setdefault(name, {})
                history["last_attempt_at"] = when
                history["http"] = value.get("http")
                if value.get("_rate_limited"):
                    history["status"] = "rate_limited"
                elif value.get("_error"):
                    history["status"] = "error"
                elif value.get("_not_found"):
                    history["status"] = "not_found"
                    history["checked_at"] = when
                    prev[name] = value  # clear any stale malicious classification
                else:
                    history["status"] = "ok"
                    history["checked_at"] = when
                    prev[name] = value
        return cache

    def stage_enrich_intel(self, wazuh_ips):
        """GreyNoise / OTX / AbuseIPDB. Caps per source; stop a source on 429."""
        self.log("\n[STAGE 3c] Enrichment (GreyNoise / OTX / AbuseIPDB)...")
        out = {}
        ips = [i.get("ip") for i in wazuh_ips if i.get("ip")]
        gn_cfg = self.cfg.get("greynoise") or {}
        otx_cfg = self.cfg.get("otx") or {}
        ab_cfg = self.cfg.get("abuseipdb") or {}
        gn_n = otx_n = ab_n = 0
        gn_stop = not gn_cfg.get("enabled") or not gn_cfg.get("api_key")
        otx_stop = not otx_cfg.get("enabled") or not otx_cfg.get("api_key")
        ab_stop = not ab_cfg.get("enabled") or not ab_cfg.get("api_key")
        gn_max = int(gn_cfg.get("max_per_run", 15))
        otx_max = int(otx_cfg.get("max_per_run", 40))
        ab_max = int(ab_cfg.get("max_per_run", 40))
        for ip in ips:
            rec = out.setdefault(ip, {})
            if not gn_stop and gn_n < gn_max:
                rec["gn"] = intel_enrich.greynoise(ip, gn_cfg["api_key"])
                rec["gn_checked_at"] = datetime.now(timezone.utc).isoformat()
                if rec["gn"].get("_rate_limited"):
                    gn_stop = True
                    self.log("    GreyNoise rate-limited, skipping rest")
                else:
                    gn_n += 1
                    time.sleep(0.25)
            if not otx_stop and otx_n < otx_max:
                rec["otx"] = intel_enrich.otx(ip, otx_cfg["api_key"])
                rec["otx_checked_at"] = datetime.now(timezone.utc).isoformat()
                otx_n += 1
                time.sleep(0.15)
            if not ab_stop and ab_n < ab_max:
                rec["aipdb"] = intel_enrich.abuseipdb(ip, ab_cfg["api_key"])
                rec["aipdb_checked_at"] = datetime.now(timezone.utc).isoformat()
                if rec["aipdb"].get("_rate_limited"):
                    ab_stop = True
                    self.log("    AbuseIPDB rate-limited, skipping rest")
                else:
                    ab_n += 1
                    time.sleep(0.15)
        self.log(f"    [+] GN={gn_n} OTX={otx_n} AIPDB={ab_n}")
        # persist enrichment cache for dashboard/other consumers
        try:
            cache_path = Path.home() / ".config/soc-orchestrator/enrich-cache.json"
            cache = {}
            if cache_path.exists():
                import json as _j
                cache = _j.loads(cache_path.read_text() or "{}")
            self._merge_enrichment_cache(cache, out)
            tmp = cache_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(cache, indent=1))
            tmp.chmod(0o600)
            tmp.replace(cache_path)
        except Exception as e:
            raise RuntimeError("enrichment cache update failed") from e
        self.summary["stage_results"]["enrich_gn"] = gn_n
        self.summary["stage_results"]["enrich_otx"] = otx_n
        self.summary["stage_results"]["enrich_aipdb"] = ab_n
        return out

    # ------------------------------------------------------------------
    # Stage 4: Update MISP
    # ------------------------------------------------------------------

    @staticmethod
    def _vt_comment(ip, count, agent, rule, vt, intel=None, level=None,
                    sensor_public_ips=None):
        """The same reviewed template used for both MISP and VT comments."""
        return render_comment(ip, count, agent, rule, vt, intel, level,
                              sensor_public_ips)


    @staticmethod
    def _cloud_web_noise(ip, rule_desc, intel):
        """Skip Azure/GCP/Cloudflare web-400 noise unless OTX/AIPDB is hot."""
        desc = (rule_desc or "").lower()
        if "web server 400" not in desc:
            return False
        try:
            a, b = [int(x) for x in ip.split(".")[:2]]
        except Exception:
            return False
        cloud = (
            a in (13, 20, 34, 35, 40, 52)
            or (a == 104 and 16 <= b <= 31)
            or (a == 172 and 64 <= b <= 71)
            or (a, b) in ((162, 158), (141, 101), (108, 162))
        )
        if not cloud:
            return False
        intel = intel or {}
        otx = (intel.get("otx") or {}).get("pulses") or 0
        aip = (intel.get("aipdb") or {}).get("score") or 0
        try:
            otx = int(otx)
            aip = int(aip)
        except Exception:
            otx, aip = 0, 0
        if otx >= 5 or aip >= 80:
            return False
        return True

    def stage_update_misp(self, wazuh_ips, vt_results):
        self.log("\n[STAGE 4] Updating MISP event...")

        # Determine which IPs qualify for MISP
        threshold_vt = self.cfg["pipeline"]["vt_push_threshold"]
        threshold_count = self.cfg["pipeline"]["wazuh_count_threshold"]
        intel_map = getattr(self, "intel", {}) or {}

        push_ips = []
        skipped_cloud = 0
        for item in wazuh_ips:
            ip = item["ip"]
            count = item.get("count", 0)
            lvl = item.get("rule_level", 0) or 0
            try:
                lvl_num = int(lvl)
            except:
                lvl_num = 0

            vt = vt_results.get(ip, {})
            vt_score = vt.get("malicious", 0) + vt.get("suspicious", 0)

            if not (vt_score >= threshold_vt or lvl_num >= 10 or count >= threshold_count):
                continue
            if lvl_num < 12 and self._cloud_web_noise(ip, item.get("rule_desc") or item.get("rule_description") or "", intel_map.get(ip)):
                skipped_cloud += 1
                continue
            push_ips.append(ip)

        if skipped_cloud:
            self.log(f"    [-] skipped {skipped_cloud} Azure/GCP/Cloudflare web-400 IPs")
        if not push_ips:
            self.log("    [!] No IPs qualify for MISP push")
            return

        self.log(f"    [*] {len(push_ips)} IPs qualify")

        if self.dry_run:
            self.log("    [DRY-RUN] Would push to MISP")
            return

        # Build IOC list — same comment template as VirusTotal
        by_ip = {item["ip"]: item for item in wazuh_ips}
        intel_all = getattr(self, "intel", {}) or {}
        iocs = []
        for ip in push_ips:
            row = self.db.get_ioc(ip)
            evidence = json.loads(row.get("evidence", "{}")) if row else {}
            item = by_ip.get(ip) or {}
            vt = dict(vt_results.get(ip) or {})
            if not vt and row:
                vt = {
                    "malicious": row.get("vt_malicious") or 0,
                    "suspicious": row.get("vt_suspicious") or 0,
                }
            comment = self._vt_comment(
                ip,
                evidence.get("wazuh_count") or item.get("count") or 0,
                item.get("agent_name") or item.get("agent") or evidence.get("wazuh_agent"),
                item.get("rule_desc") or evidence.get("wazuh_rule") or "",
                vt,
                intel=intel_all.get(ip) or {},
                level=evidence.get("wazuh_level") or item.get("rule_level"),
                sensor_public_ips=self.cfg.get("sensor_public_ips"),
            )
            iocs.append({
                "value": ip,
                "type": "ip-src",
                "category": "Network activity",
                "comment": comment,
                "to_ids": True,
            })

        # Use configured event_id or create new
        event_id = self.cfg["misp"].get("event_id")

        if event_id:
            # Existing values (including legacy ip-dst) must not be re-added as ip-src.
            event = self.misp.get_event(event_id)
            if event.get("_error") or not isinstance(event.get("Event"), dict):
                raise RuntimeError(f"MISP Event {event_id} lookup failed")
            existing = {a.get("value") for a in event["Event"].get("Attribute", [])
                        if a.get("type") in ("ip-src", "ip-dst")}
            added = 0
            for ioc in iocs:
                if ioc["value"] in existing:
                    continue
                res = self.misp.add_attribute(
                    event_id=event_id,
                    type_=ioc["type"],
                    value=ioc["value"],
                    category=ioc["category"],
                    comment=ioc["comment"],
                    to_ids=ioc["to_ids"],
                )
                if res.get("_error"):
                    raise RuntimeError(f"MISP add attribute failed: HTTP {res.get('_status', 'unknown')}")
                existing.add(ioc["value"])
                added += 1

            if added:
                res = self.misp.publish_event(event_id)
                if res.get("_error"):
                    raise RuntimeError(f"MISP Event {event_id} publish failed: HTTP {res.get('_status', 'unknown')}")
            self.log(f"    [+] Updated MISP Event {event_id} (+{added} attributes)")
            self.log(f"    [+] URL: {self.cfg['misp']['url']}/events/view/{event_id}")
            self.summary["stage_results"]["misp_event_id"] = event_id
            self.summary["stage_results"]["misp_attributes_added"] = added
        else:
            # Create new event
            tags = self.cfg["misp"].get("tags", ["auto-sync", "soc-orchestrator"])
            res = self.misp.push_ioc_event(
                name=f"SOC Orchestrator — {len(iocs)} IOCs ({datetime.now(timezone.utc).strftime('%Y-%m-%d')})",
                iocs=iocs,
                tags=tags,
                threat_level=2,
            )
            if res.get("_error"):
                self.log(f"    FAIL: {res.get('_body', res.get('_message', 'unknown'))[:200]}")
                return

            event_id = res["event_id"]
            self.log(f"    [+] Created MISP Event {event_id}")
            self.log(f"    [+] URL: {res['event_url']}")
            self.log(f"    [+] Attributes: {res['attributes_added']}")
            self.summary["stage_results"]["misp_event_id"] = event_id
            self.summary["stage_results"]["misp_attributes_added"] = res["attributes_added"]

            # Save event_id to config state for next run
            self.state["last_misp_event_id"] = event_id
            save_state(self.state)

    # ------------------------------------------------------------------
    # Stage 5: Blocklist
    # ------------------------------------------------------------------

    def stage_blocklist(self, wazuh_ips):
        self.log("\n[STAGE 5] Generating blocklist...")

        # Include all IPs with level >= 7 or count >= 50
        block_ips = []
        for item in wazuh_ips:
            ip = item["ip"]
            count = item.get("count", 0)
            lvl = item.get("rule_level", 0) or 0
            try:
                lvl_num = int(lvl)
            except:
                lvl_num = 0
            if lvl_num >= 7 or count >= 50:
                block_ips.append(ip)

        path = str(Path.home() / ".config/soc-orchestrator/soc_blocklist.txt")
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            f.write(f"# SOC Orchestrator blocklist\n")
            f.write(f"# Generated: {datetime.now(timezone.utc).isoformat()}\n")
            f.write(f"# IPs: {len(block_ips)}\n\n")
            for ip in sorted(block_ips):
                f.write(f"{ip}\n")

        self.log(f"    [+] Blocklist: {path} ({len(block_ips)} IPs)")
        self.summary["stage_results"]["blocklist_ips"] = len(block_ips)
        self.summary["stage_results"]["blocklist_path"] = path

    # ------------------------------------------------------------------
    # Stage 6: Auto-block (optional)
    # ------------------------------------------------------------------

    def stage_auto_block(self, wazuh_ips, vt_results):
        auto = self.cfg["pipeline"].get("auto_block", {})
        if not auto.get("enabled", False):
            self.log("\n[STAGE 6] Auto-block: disabled")
            return

        self.log("\n[STAGE 6] Auto-blocking high-confidence IPs...")
        min_vt = auto.get("min_vt_malicious", 3)
        min_count = auto.get("min_wazuh_count", 500)
        command = auto.get("command", "firewalld-drop")
        target = auto.get("target_agents", "!0")

        blocked = 0
        for item in wazuh_ips:
            ip = item["ip"]
            count = item.get("count", 0)
            vt = vt_results.get(ip, {})
            vt_m = vt.get("malicious", 0)

            if vt_m >= min_vt and count >= min_count:
                if self.dry_run:
                    self.log(f"    [DRY-RUN] Would block {ip}")
                    blocked += 1
                    continue

                res = self.wazuh_mgr.block_ip(target, ip, command=command)
                if res.get("_error"):
                    self.log(f"    ⚠️  {ip}: block failed — {res.get('_body', '')[:80]}")
                else:
                    self.log(f"    🔒 {ip}: blocked on agents {target}")
                    blocked += 1

        self.log(f"    [+] Blocked {blocked} IPs")
        self.summary["stage_results"]["blocked"] = blocked

    # ------------------------------------------------------------------
    # Telegram notifications
    # ------------------------------------------------------------------
    def send_telegram(self, message):
        tg = self.cfg.get("telegram", {})
        if not tg.get("enabled", False):
            return
        token = tg.get("bot_token")
        chat_id = tg.get("chat_id")
        if not token or not chat_id:
            return
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        payload = json.dumps({
            "chat_id": chat_id,
            "text": message,
            "parse_mode": "Markdown",
            "disable_web_page_preview": True,
        }).encode()
        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                pass
        except Exception as e:
            self.log(f"    [!] Telegram send failed: {str(e)[:80]}")

    def build_telegram_summary(self):
        s = self.summary["stage_results"]
        mode = "🧪 *DRY-RUN*" if self.dry_run else "🔴 *LIVE*"
        started = (self.summary.get("started") or "")[:19].replace("T", " ")
        finished = (self.summary.get("finished") or "")[:19].replace("T", " ")
        items = getattr(self, "_wazuh_ips", None) or []
        top = sorted(items, key=lambda x: -(x.get("count") or 0))[:3]

        def _clean(t):
            return (t or "").replace("*", "").replace("_", " ").replace("`", "'")[:40]

        lines = [
            "📡 *SOC Orchestrator Report*",
            "",
            f"{mode} | `{started}` UTC",
            "",
            "📊 *Wazuh*",
            f"• IPs fetched: `{s.get('wazuh_ips', 0)}`",
            f"• DB ingested: `{s.get('db_ingested', 0)}` (new: `{s.get('db_new', 0)}`)",
            "• Top:",
        ]
        if top:
            for t in top:
                lines.append(
                    f"  • `{t.get('ip')}` x{t.get('count')} {_clean(t.get('rule_desc'))}"
                )
        else:
            lines.append("  • n/a")
        lines.extend([
            "",
            "🛡️ *Enrichment*",
            f"• GreyNoise: `{s.get('enrich_gn', 0)}` | OTX: `{s.get('enrich_otx', 0)}` | AbuseIPDB: `{s.get('enrich_aipdb', 0)}`",
            f"• VirusTotal: checked `{s.get('vt_checked', 0)}` | malicious `{s.get('vt_malicious', 0)}`",
            "",
            "🎯 *MISP*",
        ])
        ev = s.get("misp_event_id") or self.cfg.get("misp", {}).get("event_id")
        if ev:
            misp_url = f"{self.cfg.get('misp', {}).get('url', '')}/events/view/{ev}"
            lines.append(f"• Event: [{ev}]({misp_url})")
            lines.append(f"• Attributes added: `{s.get('misp_attributes_added', 0)}`")
        else:
            lines.append("• No MISP update")
        lines.extend([
            "",
            "🚫 *Blocklist*",
            f"• IPs: `{s.get('blocklist_ips', 0)}` (auto-block off)",
            "",
            f"⏱️ Finished: `{finished}` UTC",
        ])
        return "\n".join(lines)

    def maybe_notify_telegram(self):
        tg = self.cfg.get("telegram", {})
        if not tg.get("enabled", False):
            return
        if self.dry_run:
            self.log("[telegram] skipped (dry-run)")
            return
        notify_on = tg.get("notify_on", "always")
        s = self.summary["stage_results"]
        should_notify = False
        if notify_on == "always":
            should_notify = True
        elif notify_on == "new_iocs":
            should_notify = s.get("db_new", 0) > 0
        elif notify_on == "new_misp":
            should_notify = s.get("misp_attributes_added", 0) > 0
        if should_notify:
            self.send_telegram(self.build_telegram_summary())

    # ------------------------------------------------------------------
    # Run full pipeline
    # ------------------------------------------------------------------

    def run(self):
        self.log("=" * 80)
        self.log("SOC ORCHESTRATOR")
        self.log(f"Started: {self.summary['started']}")
        self.log(f"Mode: {'DRY-RUN' if self.dry_run else 'LIVE'}")
        self.log("=" * 80)

        # Stage 1
        wazuh_ips = self.stage_fetch_wazuh()
        if not wazuh_ips:
            self.log("\n[!] No Wazuh IPs found — aborting")
            return self.finish()

        # Stage 2
        new_ips = self.stage_ingest_db(wazuh_ips)

        # Stage 3
        if self.skip_vt:
            self.log("\n[STAGE 3] VT checks: skipped (--skip-vt)")
            vt_results = {}
        else:
            vt_results = self.stage_vt_check(new_ips)

        # Stage 3b
        if not self.skip_vt:
            self.stage_vt_vote(vt_results, wazuh_ips)

        # Stage 3c: GreyNoise / OTX / AbuseIPDB
        self.intel = self.stage_enrich_intel(wazuh_ips)

        # Stage 4
        self.stage_update_misp(wazuh_ips, vt_results)

        # Stage 5
        self.stage_blocklist(wazuh_ips)

        # Stage 6
        self.stage_auto_block(wazuh_ips, vt_results)

        return self.finish()

    def finish(self):
        self.summary["finished"] = datetime.now(timezone.utc).isoformat()

        notif = self.cfg.get("notifications", {})
        if notif.get("summary_json"):
            with open(notif["summary_json"], "w") as f:
                json.dump(self.summary, f, indent=2, default=str)
            self.log(f"\n[+] Summary saved: {notif['summary_json']}")

        self.log("\n" + "=" * 80)
        self.log("SUMMARY")
        self.log("=" * 80)
        for k, v in self.summary["stage_results"].items():
            self.log(f"  {k}: {v}")
        self.log("=" * 80)

        self.maybe_notify_telegram()
        return self.summary


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="SOC Orchestrator")
    sub = parser.add_subparsers(dest="cmd")

    # run
    p_run = sub.add_parser("run", help="Run full pipeline")
    p_run.add_argument("--config", "-c", default=str(DEFAULT_CONFIG), help="Config file path")
    p_run.add_argument("--dry-run", action="store_true", help="Don't modify MISP or block IPs")
    p_run.add_argument("--skip-vt", action="store_true", help="Skip VirusTotal checks and votes")

    # status
    p_status = sub.add_parser("status", help="Show orchestrator state")

    args = parser.parse_args()

    if args.cmd == "run":
        cfg = load_config(args.config)
        orch = Orchestrator(cfg, dry_run=args.dry_run, skip_vt=args.skip_vt)
        orch.run()
    elif args.cmd == "status":
        state = load_state()
        print(json.dumps(state, indent=2, default=str))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
