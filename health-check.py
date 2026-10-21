#!/usr/bin/env python3
"""Facts for cron. Prints FAIL lines; does not send Telegram."""
import json
import re
import ssl
import urllib.request
import base64
from datetime import datetime, timezone
from pathlib import Path

CFG = Path("/root/.config/soc-orchestrator/config.yaml")
STATE = Path("/root/.config/soc-orchestrator/agent-status.json")
STALE_HOURS = 3


def _cfg():
    return CFG.read_text()


def _grab(text, key):
    return re.search(rf'{key}:\s*"([^"]+)"', text).group(1)


def indexer_facts(user, password):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    auth = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()

    def call(path, data=None):
        req = urllib.request.Request(
            "https://10.0.1.1:9200" + path,
            data=data,
            headers={"Authorization": auth, "Content-Type": "application/json"},
            method="POST" if data is not None else "GET",
        )
        with urllib.request.urlopen(req, context=ctx, timeout=20) as resp:
            return json.loads(resp.read().decode())

    health = call("/_cluster/health")
    body = json.dumps({
        "size": 1,
        "sort": [{"timestamp": {"order": "desc"}}],
        "_source": ["timestamp"],
    }).encode()
    hits = call("/wazuh-alerts-4.x-*/_search", body)
    ts = ((hits.get("hits") or {}).get("hits") or [{}])[0].get("_source", {}).get("timestamp") or ""
    age = None
    if ts:
        seen = datetime.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
        age = (datetime.now(timezone.utc) - seen).total_seconds() / 3600
    return health.get("active_shards") or 0, ts, age


def agent_states(user, password):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(
        "https://10.147.20.1:55000/security/user/authenticate",
        headers={"Authorization": "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()},
    )
    token = json.loads(urllib.request.urlopen(req, context=ctx, timeout=12).read())["data"]["token"]
    req = urllib.request.Request(
        "https://10.147.20.1:55000/agents?limit=100&select=name,status",
        headers={"Authorization": "Bearer " + token},
    )
    items = json.loads(urllib.request.urlopen(req, context=ctx, timeout=12).read())["data"]["affected_items"]
    return {item["name"]: item["status"] for item in items}


def main():
    # Laptop/desktop agents that routinely sleep: report as WARN, never FAIL.
    SOFT = {"win-lite", "kowalski-mac", "kowalski-pc", "raspberrypi", "sonar-mini"}
    text = _cfg()
    shards, ts, age = indexer_facts(_grab(text, "indexer_user"), _grab(text, "indexer_pass"))
    print(f"shards={shards}")
    print(f"latest={ts}")
    if age is None:
        print("latest_age_hours=")
        print("FAIL no latest Wazuh alert")
    else:
        print(f"latest_age_hours={age:.2f}")
        if age >= STALE_HOURS:
            print(f"FAIL ingest stale {age:.1f}h, last alert {ts}")
    if shards >= 1200:
        print(f"FAIL shards {shards}/1500")

    current = agent_states(_grab(text, "manager_user"), _grab(text, "manager_pass"))
    previous = json.loads(STATE.read_text()) if STATE.exists() else {}
    first = not STATE.exists()
    newly_down = []
    recovered = []
    for name, status in sorted(current.items()):
        old = previous.get(name)
        if status != "active" and old == "active":
            newly_down.append(f"{name}={status}")
        elif name not in previous and status != "active" and not first:
            newly_down.append(f"{name}={status}")
        elif status == "active" and old not in (None, "active"):
            recovered.append(name)
    STATE.write_text(json.dumps(current, indent=2, sort_keys=True) + "\n")
    if first:
        print("agent_baseline=created")
    if newly_down:
        hard = [x for x in newly_down if x.split("=")[0] not in SOFT]
        soft = [x for x in newly_down if x.split("=")[0] in SOFT]
        if hard:
            print("FAIL agent down: " + ", ".join(hard))
        if soft:
            print("WARN agent down (soft target): " + ", ".join(soft))
    if recovered:
        print("NOTE agent recovered: " + ", ".join(recovered))
    down = [f"{n}={s}" for n, s in sorted(current.items()) if s != "active"]
    print("agents_down=" + (",".join(down) if down else "none"))


if __name__ == "__main__":
    main()
