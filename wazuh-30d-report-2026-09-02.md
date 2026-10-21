# Wazuh 30-day comprehensive analysis
**Window:** ~2026-08-03 → 2026-09-02 UTC  
**Generated:** 2026-09-02  
**Source:** Indexer `wazuh-alerts-4.x-*` via Netbird `10.0.1.1:9200`

## 1. Executive summary

No evidence of a successful compromise. The fleet spent 30 days absorbing internet noise on **public sensors** (syd, retired sensor-02, later melb). Host agents (PC, Pi, Windows, Wazuh manager) are quiet aside from FIM/rootcheck false positives.

**Highest-signal items already in MISP Event 1932:** IMDS/SSRF (`85.239.151.74`, `162.243.83.227`), LFI/SQLi probes, `185.177.72.0/24` scanner family, SSH brute clusters.

**Operational issues, not IOCs:** Indexer **gap 2026-08-23–08-28 (six days, 0 alerts)**; sensor-02 retired but still ~30k historical; kowalski-mac disconnected after 09-02 03:43.

## 2. Volume and coverage

| Agent | Alerts | Role |
|---|---|---|
| sensor-syd | 329,458 | Public honeypot/sensor (majority) |
| sensor-melb | 51,705 | Public sensor (joined later) |
| sensor-02 | 30,400 | **Retired** — historical only |
| my-test-0 | 11,685 | Cloud box |
| win-lab-pve | 3,202 | Windows lab |
| wazuh-ubuntu-2C4G | 2,767 | Manager (LXC FP) |
| raspberrypi | 2,744 | LAN |
| kowalski-pc | 2,501 | Workstation |
| kowalski-mac | 98 | Laptop, now disconnected |
| sonar-mini | 48 | Lab |

**~434k alerts.** Levels: 5 (~379k), 10 (~25k), 7 (~11k), 13 (118, mostly CVEs).

Daily: 5k–20k until **Aug 23–28 silence**, then spike **51k on Aug 29** (catch-up or syd flood). Sep 1–2 back to 15–24k.

## 3. What the noise is

| Pattern | Count | Verdict |
|---|---|---|
| Web 400 | 263,032 | Internet scanners vs syd/02 |
| SSH invalid user / fail / PAM | ~110k | Same, no success from those IPs |
| Multi-400 / recon | 18,107 | Scanner clustering (level 10) |
| Docker fifo errors | 3,204 | syd/melb container churn |
| Promiscuous veth | 662 | **melb only** — docker |
| ClamAV / dpkg / ports | thousands | Patching and docker |

## 4. Authentication (the important slice)

**316 `sshd: authentication success` in 30d**, almost all **root** (305) or kowalski (11).

Public/mesh sources (owner-confirmed **clean** where noted):

| Source | Count | Note |
|---|---|---|
| 67.219.110.185 | 127 | **sensor-melb public → syd** |
| 10.0.1.21 | 85 | Netbird (internal) |
| 128.250.3.24 / .0.103 | 21 | UniMelb — **owner clean** |
| 101.115.147.167 | 13 | ZeroTier — **owner clean** |
| 101.119.182.190 | 2 | **owner clean** |
| 101.165.207.145, 101.115.138.205, 117.102.x, 175.36.147.31, 49.184.231.52, 120.21.9.88 | few | AU residential/mobile — likely you |

**No successful SSH from the brute IPs** (45.148, 62.60, 91.92, 77.239, 185.177).

Wazuh CDB “malicious IP” **failures** (not success): `195.178.110.232` (146), `193.32.162.84` (62).

## 5. Web application

| Rule | 30d | Outcome |
|---|---|---|
| Suspicious URL (.env, .git, .ssh, wp-config) | 2,564 | Essentially **404** |
| Common web attack (traversal, pearcmd, luci wget\|sh) | 402 | 404 except SPA 200s |
| SQL injection | 153 | Probes (`run_sql`, UNION); 404 or SPA |
| Web attack HTTP 200 | 9 | Same body size as homepage (**SPA FP**) except `85.215.205.230` (113kB) and sensor-02 UNION |
| URL too long / SSRF | 6 | `162.243.83.227` (repeat), `85.239.151.74` (IMDS) |

**No webshell, no 200 on real secret files that we can prove.**

## 6. Host integrity

**Rootcheck 2,708:** 2,409 on **Wazuh manager** `/dev/.lxc/proc/*` (LXC false positive). 294 syd. Mac: hidden TCP **55555** (common macOS FP).

**FIM 5,369:** Windows registry ~2.6k on win-lab (normal churn). Pi / my-test-0 / kowalski-pc package and config edits. Not malware paths.

**Vuln-detector:** kernel CVE flood on syd (level 13) — inventory, not exploitation.

## 7. Notable IPs / campaigns (already or should be in 1932)

- **185.177.72.0/24** — persistent web scanner (400 + traversal + .env)
- **45.148.10.x / 62.60.130.x / 91.92.x / 77.239.124.x / 45.153.34.x** — SSH/PAM brute
- **162.243.83.227** — weekly long-URL
- **85.239.151.74** — AWS IMDS SSRF
- **103.168.66.158** — mass “HTTP 200” (verify SPA)
- **103.215.74.185** — SQL probe volume

MISP **Event 1932** holds the curated set (85 attrs as of last push). **1930** remains the bloated drawer — do not dump 30d scanners there.

## 8. Blind spots

1. **Aug 23–28 Indexer gap** — unknown what happened (indexer down, filebeat, disk).  
2. **NDR ≠ Wazuh** — NDR is LAN SPAN; these 30d attackers hit **cloud WAN**.  
3. **my-test-0** no SSH from syd; **kowalski-mac** offline.  
4. Success logins from extra AU IPs (`101.165…`, `117.102…`, `49.184…`) not explicitly owner-acked (low volume, likely you).

## 9. Verdict

**Internet-facing sensors are doing their job. No confirmed breach.**  
Priorities: (1) explain/fix the 6-day alert black hole, (2) keep 1932 as the clean IOC event, (3) treat `.162` NDR “malware” as CTF/research unless that VPS is unknown.
