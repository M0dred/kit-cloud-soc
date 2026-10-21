# SOC Environment Memory & Handover Document

**Last Updated:** 2026-09-02 00:06 UTC
**Agent:** pi (grok-4.6) continuing Kimi session `ses_334e00cb-340e-49dc-bf88-eca4412e9c4b`
**Session ID:** ses_334e00cb-340e-49dc-bf88-eca4412e9c4b

---

## 0. Resume Notes (2026-09-02)

Kimi CLI session was interrupted (OAuth token rejected / turns cancelled on "which kimi session you are?").
Work resumed from this handover file + wire.jsonl.

**Live status at resume / corrected 2026-09-02 01:36 UTC:**
- Wazuh Manager is **NOT** `10.0.0.1` from sensor-syd. Agent points at **`10.147.20.1`**. Hostname `wazuh-ubuntu-2C4G`. SSH root works. API `:55000` works. Dashboard `:443` works.
- Indexer still bound to wazuh vpncloud `10.0.0.1` (Wazuh files **untouched**). Netbird access via standalone proxy `indexer-netbird-proxy.service`: `10.0.1.1:9200` → `10.0.0.1:9200`. Orchestrator `indexer_host` now `10.0.1.1`. Dashboard/Filebeat still use `10.0.0.1`.
- MISP up (v2.5.22), Event 1930 = 603 ip-dst.
- VT comments: posted +42 then **quota stop** at `45.79.211.97`. Progress file on disk. Resume after quota reset.
- SSH key auth from syd: **none** (no outbound keys). Password still works on a subset.

**SSH OK (8) as of 2026-09-02:**
- sensor-syd (self)
- root@10.147.20.1 wazuh-ubuntu-2C4G
- kowalski@10.0.0.50 debian
- root@10.0.0.86 Aliyun
- kowalski@10.147.20.88 boxhezi
- kowalski@10.0.0.105 kowalski-pc
- kowalski@10.0.0.11 raspberrypi (pass 221221)
- kowalski@10.0.0.150 sonar-mini (pass 221221)

**Still no shell:**
- my-test-0 — still no shell (root/kowalski, previous + new passwords all denied on ZT/vpncloud)
- sensor-melb — **OK** `root@10.0.1.87` (Netbird) with second new password. Public `67.219.110.185:22` refused (use Netbird only). No SSH keys (password preferred).
- win-lab-pve 192.168.1.104 — from Wazuh LAN: RDP 3389 open, SSH closed, SMB 445. No shell from here.
- kowalski-mac — Wazuh disconnected; Netbird 10.0.1.131 and LAN 192.168.1.224 not reachable now (laptop likely sleep)

**Ignore / owner-confirmed legit:** 10.147.20.106, 192.168.1.112; sensor-02 retired.
**Legit SSH to syd/melb (2026-09-02 owner):** `101.115.147.167` (ZeroTier), `101.119.182.190`, `128.250.3.24` / `128.250.0.103` (UniMelb). Do not treat as compromise.

**ClickHouse** on same `10.0.1.106` (native **:19000**, HTTP 8123 not exposed). User `kowalski`. DBs `netdb` (~16GB: 28M hosts, ports, AU/Go8 subsets, EPSS, ExploitDB) + `bounty_intel` (schema-heavy, most tables empty; 12 DoD VDP candidate_findings). Not on 192.168.1.103 from syd. Same box as Splunk.

**Splunk** `10.0.1.106` (Netbird, hostname `kit-lab`): Web `:8000`, mgmt REST **`:8090`** (not 8089). Splunk **10.4.2 Free**. Default `admin` works. Indexes: `main` ~22M events / 1.7GB — **this host /var/log + journald + docker**, not Wazuh fleet. 8191 closed. HTTP 80/443 = 404.
**VT:** wait for daily quota then resume comments.
**Policy (cron / auto-block / new MISP event):** deferred.

**2026-09-02 review:** orchestrator `--dry-run --skip-vt` via Netbird indexer. 183 IPs / 168 new in local DB. Did **not** push MISP 1930. Curated 22 high-signal IPs in `high-signal-2026-09-02.txt`.

**Clear NDR** `https://10.0.1.50:8443` (Netbird). Login `clearndr` Superuser.
- 2026-09-02: ETOpen updated **11159 → 11271**; lateral source refreshed; Default ruleset rebuilt (`update_ruleset`), still 48108 enabled, validity true.
- API: `POST /rest/rules/source/{pk}/update_source/` and `POST /rest/rules/ruleset/{pk}/update_ruleset/` (session+CSRF).
- Client: `soc-connector/scripts/ndr_client.py` + `ndr-cli.py`; skill `clear-ndr`; config `ndr:` in soc-orchestrator yaml.
- 2026-09-05: OTX + AbuseIPDB keys in soc-orchestrator config. AbuseIPDB check OK on 185.177.72.22 (score 100, 2664 reports).
- 2026-09-07: cron fixed — Debian cron ignored CRON_TZ so 16:00 UTC fired at 02:00 AEST. Now `0 6,22 * * *` UTC = Melbourne 16:00 / 08:00 AEST.
- 2026-09-05: root crontab 08:00 and 16:00 **UTC** → `cron-run.sh` (`soc-orchestrator.py run --skip-vt`, flock, log `cron.log`). Telegram only if new MISP attrs.
- 2026-09-05: logrotate: `/etc/logrotate.d/tor` → `tor.disabled`, service SUCCESS. ntp user recreated, `ntp.service` active (clock still slewing ~63s). MISP 1932 **published=true**.
- 2026-09-05: orchestrator `event_id=1932`; Telegram skip on dry-run + `notify_on=new_misp`. GreyNoise community key in config. Enriched 49/85 attrs on 1932 (42 malicious noise, 7 not observed) then **429 quota**. Resume remaining tomorrow.
- 2026-09-02 go-ahead: **MISP Event 1932** (22 high-signal IPs, published, not 1930). NDR disabled STUN SIDs **2033078** (high port) and **2033077** (low port) on Default ruleset + rebuild. SSH outbound SID 2003068 left enabled (signal).

**Resume artifacts:**
- IP list: `~/.config/soc-orchestrator/misp1930-ips.txt` (603)
- Progress: `~/.config/soc-orchestrator/vt-comments-progress.json`
- Log: `~/.config/soc-orchestrator/vt-comments.log`

---

## 1. Environment Overview

### Machines
| Host | IP | Role | OS | Access |
|------|-----|------|-----|--------|
| **sensor-syd** | `149.28.165.53` / `10.0.0.4` / `10.147.20.4` | Wazuh Manager + Central node | Debian 12 (Trixie) | root via SSH |
| **10.0.0.86** | `10.147.20.86` (ZeroTier only) | Aliyun Cloud VPS | Ubuntu 22.04 | root@10.147.20.86 |
| **10.0.0.88** | `10.0.0.88` / `10.147.20.88` | Proxmox VE Hypervisor | Debian 13 (Trixie) | kowalski@10.0.0.88 |
| **10.0.0.50** | `10.0.0.50` / `10.147.20.50` | kowalski Workstation | Debian 12 (Bookworm) | kowalski@10.0.0.50 |

### Networks
- **vpncloud mesh:** `10.0.0.0/24`
- **ZeroTier:** `10.147.20.0/24`
- **Netbird:** `100.113.0.0/16`
- **Proxmox LAN:** `192.168.31.0/24`
- **kowalski LAN:** `192.168.1.0/24`

---

## 2. Credentials (SENSITIVE — Mask in Public Sharing)

| Service | Key/Pass | Note |
|---------|----------|------|
| SSH (.86/.88/.50) | `Pwdn0s@fe;` | User: root or kowalski |
| Wazuh Indexer | `admin` / `L4B4qGU2JyBQ.` | `10.0.0.1:9200` |
| Wazuh Manager API | `wazuh-wui` / `+FMBD0AOTReg+ivkhp5Z8uSORtsZp*L8` | `10.0.0.1:55000` |
| MISP | `k0AkWOjFybei1uHbMjlliDTElYF58FXLCkdTt0LV` | `https://misp.kit-ai.net` |
| VirusTotal | `775b92d0d7b3bee7c1eec32df37798b2b1548fec874080a561850237cd15c597` | Free tier (daily quota) |
| Telegram Bot | `8146281560:AAH2bTjr7fphVdZyNH5D_2AanHOPxUYwiy0` | Bot: @hey_max_intel_bot |
| Telegram Chat ID | `8780233201` | User: Max |

---

## 3. Skills Installed

### sensor-syd (this machine)
| Skill | Version | Path |
|-------|---------|------|
| linux-forensics-assessment | 1.0 | `~/.config/agents/skills/linux-forensics-assessment/` |
| linux-log-threat-hunt | 1.0 | `~/.config/agents/skills/linux-log-threat-hunt/` |
| recon-passive | 1.0 | `~/.config/agents/skills/recon-passive/` |
| soc-connector | 1.1 | `~/.config/agents/skills/soc-connector/` |
| web-app-security-assessment | 1.0 | `~/.config/agents/skills/web-app-security-assessment/` (copied from .50) |

### 10.0.0.50 (kowalski)
- linux-forensics-assessment
- linux-log-threat-hunt
- recon-passive
- web-app-security-assessment

### 10.0.0.86 & 10.0.0.88
- **No skills installed** (deployment gap)

---

## 4. SOC Orchestrator Configuration

**File:** `~/.config/soc-orchestrator/config.yaml`

```yaml
telegram:
  enabled: true
  bot_token: "8146281560:AAH2bTjr7fphVdZyNH5D_2AanHOPxUYwiy0"
  chat_id: 8780233201
  notify_on: "always"  # always | new_iocs | new_misp | never

virustotal:
  max_checks_per_run: 10
  delay_seconds: 30
  cooldown_hours: 24
  auto_vote:
    enabled: true
    min_vt_score: 2
    min_wazuh_count: 100
    verdict: "malicious"
    add_comment: true

pipeline:
  lookback_hours: 24
  min_wazuh_level: 5
  vt_push_threshold: 2
  wazuh_count_threshold: 200
  auto_block:
    enabled: false
```

**Key Flags Added:**
- `--dry-run` — no MISP changes
- `--skip-vt` — bypass VT checks (fast mode)

---

## 5. Work Completed This Session

### Phase 1: SOC Pipeline Operations
- ✅ Ran SOC orchestrator dry-run (500 IPs, 4 MISP-qualified, 40 blocklisted)
- ✅ Ran SOC orchestrator live run (+4 attributes to MISP Event 1930)
- ✅ Updated VT comments for `172.235.255.170` and `172.212.217.152` with masked target + TTPs
- ✅ Tuned VT settings: `max_checks: 10`, `delay: 30s` (was 20/16s)

### Phase 2: Forensics & Log Analysis
- ✅ Forensic analysis on 10.0.0.86, 10.0.0.88, 10.0.0.50 — all clean
- ✅ LAN scans: 192.168.31.0/24 (8 devices), 192.168.1.0/24 (~24 devices) — all legitimate
- ✅ Cron audits on all nodes; removed orphaned `john` cron/configs on sensor-syd
- ✅ Full log analysis via `linux-log-threat-hunt` on all 3 remote machines
- ✅ Identified suspicious IPs: `10.147.20.106` (default cred scanner), `192.168.1.112` (botnet-like)

### Phase 3: Integrations
- ✅ Added Telegram notifications to SOC orchestrator
- ✅ Added `--skip-vt` flag for fast pipeline mode
- ✅ Configurable VT delay (no longer hardcoded 16s)

### Phase 4: Bulk IOC Enrichment
- ✅ Enriched 585 IPs from `/tmp/box-iocs.txt`
- ✅ All 585 IPs synced to MISP Event 1930
- ❌ VT comments blocked by daily quota (QuotaExceededError)

### Phase 5: Skill Management
- ✅ Copied `web-app-security-assessment` from .50 to sensor-syd
- ✅ Total skills on sensor-syd: 5

---

## 6. Current State & Findings

### MISP Event 1930
- **Total attributes:** 87 + 585 box-iocs = ~672 (may need cleanup of old attributes)
- **box-iocs attributes:** 585
- **URL:** https://misp.kit-ai.net/events/view/1930

### Threat DB
- **Path:** `~/.config/linux-log-threat-hunt/threat-intel.db`
- **IPs ingested:** 500+ from Wazuh, 585 from box-iocs
- **Tables:** `iocs`, `observations`

### Suspicious IPs Identified
| IP | Context | Action Needed |
|----|---------|---------------|
| `10.147.20.106` | 557 SSH failed attempts with default credential scanner usernames | Identify device |
| `192.168.1.112` | 75 SSH failed attempts with random usernames | Identify device |
| `111.12.63.137` | 48 SSH brute force attempts on .86 | Monitor |
| `139.19.117.130` | 15 SSH brute force attempts on .86 | Monitor |

### Blocklist
- **Path:** `/tmp/soc_blocklist.txt`
- **Count:** 40 IPs (last generated)
- **Auto-block:** DISABLED

---

## 7. Ongoing Background Processes

| Task | PID | Status | Log |
|------|-----|--------|-----|
| VT comment script (quota-blocked) | — | KILLED | `/tmp/vt_comment_after_enrich.log` |
| Enrichment + MISP sync | — | COMPLETE | `/tmp/enrich_and_sync.log` |

**VT comment script was killed** because VT daily quota was exhausted after 585 lookups. Comments will need to run once quota resets (24h).

---

## 8. Known Issues & Limitations

| Issue | Impact | Priority |
|-------|--------|----------|
| VT free tier quota (500/day) | Enrichment blocked after 585 lookups | High |
| Azure cloud noise in MISP | 40+ IPs on blocklist are likely benign cloud scanners | High |
| No skills on .86/.88 | Remote log analysis requires manual script copy | Medium |
| No Active Response | Detected threats not automatically blocked | High |
| No container security skill | .50 Docker/K3s blindspot | High |
| VT comment script stuck on quota | Process killed, needs restart after quota reset | Medium |

---

## 9. Recommended Next Steps

### Immediate (Today/Tomorrow)
1. **Identify `10.147.20.106` and `192.168.1.112`** — are these your devices?
2. **Wait for VT quota reset**, then re-run VT comments for box-iocs
3. **Review MISP Event 1930** — prune old/stale attributes

### Short-term (This Week)
1. **Build Active Response skill** — read blocklist, generate iptables/nftables, push via Wazuh
2. **Add AS-owner filtering** to reduce Azure cloud noise in MISP/blocklist
3. **Deploy skills to .86 and .88** via rsync/ssh
4. **Set daily cron for SOC orchestrator** at 03:00 UTC

### Medium-term
1. **Container security skill** for .50 Docker/K3s
2. **Cross-skill correlation** — forensics findings trigger prioritized log analysis
3. **VT paid plan** or add GreyNoise/AbuseIPDB as secondary enrichers

---

## 10. File Locations

| Item | Path |
|------|------|
| SOC config | `~/.config/soc-orchestrator/config.yaml` |
| Threat DB | `~/.config/linux-log-threat-hunt/threat-intel.db` |
| Blocklist | `/tmp/soc_blocklist.txt` |
| Summary JSON | `/tmp/soc-orchestrator-summary.json` |
| Enrichment results | `/tmp/box-iocs-enriched.json` |
| Log analysis (sensor-syd) | `/tmp/logs_sensor-syd.json` |
| Log analysis (.86) | `/tmp/logs_10.0.0.86.json` |
| Log analysis (.88) | `/tmp/logs_10.0.0.88.json` |
| Log analysis (.50) | `/tmp/logs_10.0.0.50.json` |
| box-iocs input | `/tmp/box-iocs.txt` |

---

## 11. Handover Notes for Next Agent

- **Start here:** Read sections 1-4 for environment context, section 5 for what was done, section 6 for current state.
- **VT quota is exhausted** — do not attempt VT lookups/comments until tomorrow.
- **MISP Event 1930** is the central IOC repository. It has grown large; consider creating a new event or pruning.
- **The `john` cron was removed** from `/etc/cron.d/john`. Do not reinstall unless specifically needed.
- **Remote SSH access** uses password `Pwdn0s@fe;` with `sshpass`. No key-based auth is set up.
- **Telegram notifications** are active on `notify_on: always`. Change to `new_misp` to reduce noise.
- **web-app-security-assessment** was copied from .50 to sensor-syd but not yet tested locally.

---

*Generated by Kimi CLI for SOC environment handover. Review and redact credentials before sharing externally.*

---

## 12. 2026-09-29 Session (indexer fix, IntelMQ, health check)

### Wazuh indexer shard outage — FIXED
- Symptom: `wazuh_ips: 0` every cron from 09-23. Filebeat `Cannot index event`; cluster shards hit 1000/1000 (3 pri + auto replicas per daily index, single node).
- Fix: closed 251 alert/monitoring indices older than 2026-08-01 (data kept, re-openable). Legacy template `_template/wazuh` now 1 shard / 0 replicas / auto_expand false (applies to NEW daily indices). `cluster.max_shards_per_node` raised to 1500 (persistent).
- Alerts resumed 2026-09-29 ~11:12 UTC. 09-23..09-28 gap is permanent — not in the index.
- Watch: shards >= 1200 → cron Telegram (health-check.py).

### cron-run.sh v2
- Failure paths now Telegram: stale ingest (latest alert age >= 3h), shards >= 1200, indexer unreachable, orchestrator/log-hunt/NDR/VT step failures, lock skip, VT 429.
- `wazuh_ips: 0` is NO LONGER a failure — quiet windows are normal; staleness is what matters.
- Health logic in `~/.config/soc-orchestrator/health-check.py`; agent baseline `agent-status.json` (created 09-29, win-lite already down = no alert).
- VT comments: DAILY_CAP 50/day, --max 25/run (was 20/10).

### IntelMQ (kit-ai) — inspected + partially fixed
- Manager UI https://intelmq.kit-ai.net/ (basic auth), API https://intelmq.kit-ai.net/intelmq/v1/api/* (POST login form → token in plain `Authorization:` header, NOT Bearer). OpenAPI at /intelmq/openapi.json.
- Host: `debian` = kowalski@10.0.1.50 (Netbird) = 10.147.20.50 (ZT) = LAN 192.168.1.111. venv /home/kowalski/intelmq-run, user systemd units (intelmq.service, intelmq-api.service, intelmq-manager.service). API uvicorn :8000, manager :1337. ~104 bots, ~48 public feeds.
- FIXED 09-29: installed beautifulsoup4 + python-gnupg in venv; restarted cybercrime-tracker-latest-parser, precisionsec-agent-tesla-parser, turris-greylist-pgp collector → all running. misp-collector reset was transient Cloudflare; search works, tag `to_process` empty.
- NOT fixed (by design): Cymru Whois queue ~1.29M growing ~+30/s until DNS queues (~210k each, drain ~3h) empty; total drain est. 3–4 days at ~6.5 ev/s. Outputs only get events AFTER whois. Pipeline change (dedupe→sql direct) offered, user declined for now.
- DO NOT: feed IntelMQ sources into 1932; tag anything `to_process`; clear queues.
- intelmq-events PostgreSQL at 192.168.1.108:55432 — unreachable from sensor-syd.

### sensor-syd disk
- 09-29: 96% → 90% (npm/apt cache, journal vacuum 100M, old /tmp venvs). .pdtm/.nvm/.grok/.codex left untouched (user tools).
- postgresql@14-main: unit not-found (already gone). Nothing to disable.

### JEV / Splunk / ClickHouse / NDR
- Unchanged: not wired into cron. NDR status-only. ClickHouse reachable via /tmp/chvenv (clickhouse_driver). win-lite agent still disconnected since 09-20 (RDP-only host).

### IntelMQ DB cross-check (2026-10-05)
- intelmq-events PostgreSQL IS reachable: from .50 via LAN (192.168.1.108:55432, pg 16.15). Direct 10.0.1.149:55432 opens but pg_hba rejects NAT source 172.18.0.1; port 5543 refused (55432 is correct).
- `events` ~8.3M rows, 282k distinct IPs, covers 2026-09-28→now, near-real-time (~2h lag). Whois backlog drained.
- Feed names (for filters): DGA Domains, Full Bogons v4/v6, Telnet/SSH/SIP/VNC Login (Dataplane), CINS Army List, Greylist (Turris), Drop/Dropv6 (Spamhaus), C2 Tracker (Viriback), Feodo Tracker, URLs (VxVault), Public feed (OpenPhish), Bots/Apache/Mail/IMAP/FTP/Strong IPs (Blocklist.de), Bruteforce Blocker, Reputation List (AlienVault). NOTE: many feeds have NULL time.source — filter on time.observation.
- `~/.config/soc-orchestrator/intelmq-cross.py`: reads IPs from threat DB (last --hours), batch-queries via SSH inline python on .50 (no files left there), writes intelmq-hits.json. ~2s for 725 IPs. HIGH={Feodo,C2,CINS,Drop,Dropv6}, MEDIUM={URLs,Public feed,Latest,Bots,Strong IPs}.
- Baseline 2026-10-05: 24h → 725 checked, 668 matched, 83 high (CINS; mostly MSFT/GCP/HWcloud scanner IPs), 57 medium; malware feeds 0 hits.
- Wired into cron-run.sh after orchestrator as REPORT-ONLY; failure → Telegram. No MISP/VT/blocking changes from this step.
