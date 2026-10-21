# Hunt cross — Wazuh high-signal vs Clear NDR (2026-09-02)

## Result
**0/22 overlap.** NDR `logstash-alert-2026.09.01/02` has no `src_ip`/`dest_ip` for the Wazuh curated list.

## Why
- Wazuh 24h hot IPs = **internet scanners → sensor-syd / sensor-melb public** (web 400, SSH/PAM).
- Clear NDR tap = **192.168.1.0/24 LAN** (top alert src `192.168.1.169` = Wazuh manager).
- Different wires. Cloud sensors are not on this SPAN.

## NDR today (own view)
~59k alerts 2026-09-02, mostly:
- ET STUN on high ports (~51k) — mesh/VPN
- Telegram API DNS/SNI
- ZeroTier UDP
- 95× `ET SCAN Potential SSH Scan OUTBOUND`
Top dest: `149.28.139.190` (my-test-0 public), `67.219.110.185` (sensor-melb public), STUN/Telegram infra.

## Query path used
Kibana console proxy → NDR OpenSearch `logstash-alert-*` (not Wazuh Indexer).
