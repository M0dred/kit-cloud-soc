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
# These endpoints may legitimately sleep. They still appear as WARN, not FAIL.
SOFT_AGENTS = {"win-lite", "kowalski-mac", "kowalski-pc", "raspberrypi", "sonar-mini"}


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
    hard_down = []
    soft_down = []
    recovered = []
    for name, status in sorted(current.items()):
        old = previous.get(name)
        if status != "active":
            (soft_down if name in SOFT_AGENTS else hard_down).append(f"{name}={status}")
        elif old not in (None, "active"):
            recovered.append(name)
    STATE.write_text(json.dumps(current, indent=2, sort_keys=True) + "\n")
    if first:
        print("agent_baseline=created")
    # Failure is a current condition, not just a transition. Otherwise an
    # unchanged outage is reported healthy from the second run onward.
    if hard_down:
        print("FAIL agent down: " + ", ".join(hard_down))
    if soft_down:
        print("WARN agent down (soft target): " + ", ".join(soft_down))
    if recovered:
        print("NOTE agent recovered: " + ", ".join(recovered))
    down = [f"{n}={s}" for n, s in sorted(current.items()) if s != "active"]
    print("agents_down=" + (",".join(down) if down else "none"))


if __name__ == "__main__":
    main()
