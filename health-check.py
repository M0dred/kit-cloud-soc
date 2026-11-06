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
AGENT_PAGE_SIZE = 100
MAX_AGENT_RECORDS = 10000  # fail closed instead of silently truncating larger inventories
MISSING_STATUS = "not_returned_by_manager"
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
    with urllib.request.urlopen(req, context=ctx, timeout=12) as resp:
        token = json.loads(resp.read())["data"]["token"]
    agents = {}
    offset = 0
    expected_total = None
    while True:
        req = urllib.request.Request(
            f"https://10.147.20.1:55000/agents?limit={AGENT_PAGE_SIZE}&offset={offset}&select=name,status",
            headers={"Authorization": "Bearer " + token},
        )
        with urllib.request.urlopen(req, context=ctx, timeout=12) as resp:
            result = json.loads(resp.read())
        data = result.get("data") if isinstance(result, dict) else None
        if (not isinstance(data, dict) or type(result.get("error")) is not int or
                result["error"] != 0):
            raise RuntimeError("Wazuh Manager agent inventory failed")
        items = data.get("affected_items")
        total = data.get("total_affected_items")
        failed = data.get("total_failed_items")
        if (type(total) is not int or not 1 <= total <= MAX_AGENT_RECORDS or
                not isinstance(items, list) or len(items) != min(AGENT_PAGE_SIZE, total - offset) or
                type(failed) is not int or failed != 0 or data.get("failed_items") != []):
            raise RuntimeError("Wazuh Manager agent inventory incomplete or invalid")
        if expected_total is None:
            expected_total = total
        elif total != expected_total:
            raise RuntimeError("Wazuh Manager agent inventory changed during pagination")
        for item in items:
            if (not isinstance(item, dict) or not isinstance(item.get("name"), str) or
                    not item["name"].strip() or not isinstance(item.get("status"), str) or
                    not item["status"].strip() or item["name"] in agents):
                raise RuntimeError("Wazuh Manager agent record invalid or duplicated")
            agents[item["name"]] = item["status"]
        offset += len(items)
        if offset == total:
            return agents


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
    # Missing from a complete manager response is unknown, not a recovery.
    # Preserve it in the private baseline until the agent reappears or a
    # decommission is explicitly reviewed by an operator.
    missing = set(previous) - set(current)
    for name in missing:
        current[name] = MISSING_STATUS
    hard_down = []
    soft_down = []
    hard_missing = []
    soft_missing = []
    recovered = []
    for name, status in sorted(current.items()):
        old = previous.get(name)
        if name in missing:
            (soft_missing if name in SOFT_AGENTS else hard_missing).append(name)
        elif status != "active":
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
    if hard_missing:
        print("FAIL agent status unavailable: " + ", ".join(hard_missing))
    if soft_missing:
        print("WARN agent status unavailable (soft target): " + ", ".join(soft_missing))
    if recovered:
        print("NOTE agent recovered: " + ", ".join(recovered))
    down = [f"{n}={s}" for n, s in sorted(current.items()) if s != "active"]
    print("agents_down=" + (",".join(down) if down else "none"))


if __name__ == "__main__":
    main()
