#!/usr/bin/env python3
"""Wazuh Indexer (OpenSearch) client for querying security alerts.

The Wazuh Manager API does NOT expose security alerts in v4.x.
Alerts are stored in the Indexer under `.wazuh-alerts-*` indices.
This client queries those indices directly.

Uses Python stdlib only.
"""
import json
import ssl
import urllib.request
import base64
from datetime import datetime, timezone, timedelta


class WazuhIndexerClient:
    def __init__(self, host, username, password, verify_tls=True):
        self.base_url = f"https://{host}:9200" if ":" not in host else f"https://{host}"
        self.username = username
        self.password = password
        self.verify_tls = verify_tls
        self._ctx = ssl.create_default_context()
        if not verify_tls:
            self._ctx.check_hostname = False
            self._ctx.verify_mode = ssl.CERT_NONE
        self._auth = base64.b64encode(f"{username}:{password}".encode()).decode()
        self.last_coverage = None  # set by fetch_suspicious_ips; pre-public-IP filtering

    def _req(self, path, data=None, method="GET"):
        url = f"{self.base_url}{path}"
        headers = {"Authorization": f"Basic {self._auth}", "Content-Type": "application/json"}
        payload = json.dumps(data).encode() if data else None
        req = urllib.request.Request(url, headers=headers, data=payload, method=method)
        try:
            with urllib.request.urlopen(req, context=self._ctx, timeout=30) as r:
                return json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            body = e.read().decode()[:500]
            return {"_error": True, "_status": e.code, "_body": body}
        except Exception as e:
            return {"_error": True, "_message": str(e)}

    # ------------------------------------------------------------------
    # Cluster / Index info
    # ------------------------------------------------------------------

    def health(self):
        return self._req("/_cluster/health")

    def list_indices(self, pattern=".wazuh-alerts-*"):
        res = self._req(f"/_cat/indices/{pattern}?v&s=index")
        if isinstance(res, dict) and res.get("_error"):
            return res
        # _cat returns plain text; parse it
        lines = res.strip().split("\n") if isinstance(res, str) else []
        return lines

    # ------------------------------------------------------------------
    # Alert queries
    # ------------------------------------------------------------------

    def query_alerts(self, query_body, index="wazuh-alerts-*"):
        """Run an arbitrary search against alert indices."""
        return self._req(f"/{index}/_search", data=query_body, method="POST")

    def get_alert_sample(self, index="wazuh-alerts-*", size=1):
        """Fetch sample alert documents to inspect schema."""
        return self.query_alerts({"size": size, "sort": [{"timestamp": {"order": "desc"}}]})

    def count_alerts(self, days=1, agent_id=None, min_level=None):
        """Count alerts matching filters."""
        must = [{"range": {"timestamp": {"gte": f"now-{days}d"}}}]
        if agent_id:
            must.append({"term": {"agent.id": agent_id}})
        if min_level:
            must.append({"range": {"rule.level": {"gte": min_level}}})
        body = {
            "size": 0,
            "query": {"bool": {"must": must}},
        }
        return self.query_alerts(body)

    def fetch_suspicious_ips(self, days=3, min_level=None, max_results=200,
                             exclude_private=True, agent_id=None):
        """Aggregate top source IPs from alerts.

        Returns list of dicts:
          [{"ip": "1.2.3.4", "count": 42, "agent": "sensor-02",
            "rule_level": 10, "rule_desc": "...", "rule_groups": [...]}, ...]
        """
        must = [
            {"range": {"timestamp": {"gte": f"now-{days}d"}}},
            {"exists": {"field": "data.srcip"}},
        ]
        if min_level:
            must.append({"range": {"rule.level": {"gte": min_level}}})
        if agent_id:
            must.append({"term": {"agent.id": agent_id}})

        must_not = [{"terms": {"data.srcip": ["127.0.0.1", "0.0.0.0", "::1"]}}]

        body = {
            "size": 0,
            "query": {"bool": {"must": must, "must_not": must_not}},
            "aggs": {
                "approx_unique_sources": {"cardinality": {"field": "data.srcip", "precision_threshold": 40000}},
                "ips": {
                    "terms": {"field": "data.srcip", "size": max_results, "order": {"_count": "desc"}},
                    "aggs": {
                        "agents": {"terms": {"field": "agent.name.keyword", "size": 5}},
                        "top_hit": {
                            "top_hits": {
                                "size": 1,
                                "_source": [
                                    "rule.description", "rule.level", "rule.groups",
                                    "agent.name", "agent.id", "timestamp", "data.srcip", "data.dstip",
                                ]
                            }
                        },
                    }
                }
            }
        }

        self.last_coverage = None
        res = self.query_alerts(body)
        if res.get("_error"):
            return res
        if res.get("timed_out") or (res.get("_shards") or {}).get("failed", 0):
            return {"_error": True, "_message": "Indexer source aggregation incomplete"}

        aggs = res.get("aggregations") or {}
        terms = aggs.get("ips") or {}
        buckets = terms.get("buckets", [])
        # Terms aggregation has a top-N limit. An estimate, never a claim that
        # all source IPs were captured; private/reserved sources are counted too.
        self.last_coverage = {
            "source_bucket_limit": max_results,
            "returned_buckets": len(buckets),
            "outside_top_alerts": int(terms.get("sum_other_doc_count") or 0),
            "approx_unique_sources": int((aggs.get("approx_unique_sources") or {}).get("value") or 0),
        }
        results = []
        for b in buckets:
            ip = b["key"]
            if exclude_private and self._is_private(ip):
                continue
            hit = b["top_hit"]["hits"]["hits"][0]["_source"]
            results.append({
                "ip": ip,
                "count": b["doc_count"],
                "agents": [a["key"] for a in b["agents"]["buckets"]],
                "rule_level": hit.get("rule", {}).get("level"),
                "rule_desc": hit.get("rule", {}).get("description"),
                "rule_groups": hit.get("rule", {}).get("groups"),
                "agent_name": hit.get("agent", {}).get("name"),
                "agent_id": hit.get("agent", {}).get("id"),
                "timestamp": hit.get("timestamp"),
                "dstip": hit.get("data", {}).get("dstip"),
            })
        return results

    def fetch_ips_by_rule_group(self, group, days=3, max_results=100):
        """Fetch IPs triggering a specific rule group (e.g., 'sshd', 'attack', 'recon')."""
        body = {
            "size": 0,
            "query": {"bool": {"must": [
                {"range": {"timestamp": {"gte": f"now-{days}d"}}},
                {"term": {"rule.groups": group}},
                {"exists": {"field": "data.srcip"}}
            ], "must_not": [
                {"terms": {"data.srcip": ["127.0.0.1", "0.0.0.0", "::1"]}}
            ]}},
            "aggs": {
                "ips": {
                    "terms": {"field": "data.srcip", "size": max_results, "order": {"_count": "desc"}},
                    "aggs": {
                        "top_hit": {
                            "top_hits": {
                                "size": 1,
                                "_source": ["rule.description", "rule.level", "agent.name"]
                            }
                        }
                    }
                }
            }
        }
        res = self.query_alerts(body)
        if res.get("_error"):
            return res

        buckets = res.get("aggregations", {}).get("ips", {}).get("buckets", [])
        results = []
        for b in buckets:
            ip = b["key"]
            if self._is_private(ip):
                continue
            hit = b["top_hit"]["hits"]["hits"][0]["_source"]
            results.append({
                "ip": ip,
                "count": b["doc_count"],
                "rule_level": hit.get("rule", {}).get("level"),
                "rule_desc": hit.get("rule", {}).get("description"),
                "agent": hit.get("agent", {}).get("name"),
            })
        return results

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _is_private(ip):
        if ip.startswith(("127.", "10.", "192.168.")):
            return True
        if ip.startswith("172."):
            try:
                return 16 <= int(ip.split(".")[1]) <= 31
            except Exception:
                pass
        return False
