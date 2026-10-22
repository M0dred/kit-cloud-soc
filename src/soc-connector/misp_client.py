#!/usr/bin/env python3
"""MISP API client.

Supports: JWT auth (API key), event/attribute search, IOC event creation,
publishing, and pull of network indicators.

Uses Python stdlib only.
"""
import json
import ssl
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime, timezone, timedelta


class MISPClient:
    def __init__(self, base_url, api_key, verify_tls=True):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.verify_tls = verify_tls
        self._ctx = ssl.create_default_context()
        if not verify_tls:
            self._ctx.check_hostname = False
            self._ctx.verify_mode = ssl.CERT_NONE

    def _req(self, path, data=None, method="GET", headers=None):
        url = f"{self.base_url}{path}"
        h = {
            "Authorization": self.api_key,
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        }
        if headers:
            h.update(headers)
        payload = json.dumps(data).encode() if data else None
        req = urllib.request.Request(url, headers=h, data=payload, method=method)
        try:
            with urllib.request.urlopen(req, context=self._ctx, timeout=30) as r:
                return json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            body = e.read().decode()[:500]
            return {"_error": True, "_status": e.code, "_body": body}
        except Exception as e:
            return {"_error": True, "_message": str(e)}

    # ------------------------------------------------------------------
    # Core REST search
    # ------------------------------------------------------------------

    def search_events(self, value=None, type_attribute=None, tags=None,
                      from_date=None, to_date=None, limit=100):
        body = {
            "returnFormat": "json",
            "limit": limit,
        }
        if value:
            body["value"] = value
        if type_attribute:
            body["type"] = type_attribute
        if tags:
            body["tags"] = tags if isinstance(tags, list) else [tags]
        if from_date:
            body["from"] = from_date
        if to_date:
            body["to"] = to_date
        return self._req("/events/restSearch", data=body, method="POST")

    def search_attributes(self, value=None, type_attribute=None, tags=None,
                          from_date=None, to_date=None, limit=1000,
                          to_ids=None):
        body = {
            "returnFormat": "json",
            "limit": limit,
        }
        if value:
            body["value"] = value
        if type_attribute:
            body["type"] = type_attribute
        if tags:
            body["tags"] = tags if isinstance(tags, list) else [tags]
        if from_date:
            body["from"] = from_date
        if to_date:
            body["to"] = to_date
        if to_ids is not None:
            body["to_ids"] = to_ids
        return self._req("/attributes/restSearch", data=body, method="POST")

    # ------------------------------------------------------------------
    # Events
    # ------------------------------------------------------------------

    def create_event(self, info, threat_level=3, analysis=0, distribution=0,
                     tags=None):
        event = {
            "info": info,
            "threat_level_id": threat_level,
            "analysis": analysis,
            "distribution": distribution,
        }
        if tags:
            event["Tag"] = [{"name": t} for t in (tags if isinstance(tags, list) else [tags])]
        return self._req("/events/add", data=event, method="POST")

    def publish_event(self, event_id):
        return self._req(f"/events/publish/{event_id}", method="POST")

    def get_event(self, event_id):
        return self._req(f"/events/{event_id}")

    # ------------------------------------------------------------------
    # Attributes
    # ------------------------------------------------------------------

    def add_attribute(self, event_id, type_, value, category="Network activity",
                      comment="", to_ids=True):
        attr = {
            "type": type_,
            "value": value,
            "category": category,
            "comment": comment,
            "to_ids": to_ids,
        }
        return self._req(f"/attributes/add/{event_id}", data=attr, method="POST")

    # ------------------------------------------------------------------
    # High-level convenience
    # ------------------------------------------------------------------

    def query_ip(self, ip):
        """Search MISP for a specific IP value."""
        return self.search_events(value=ip, type_attribute="ip-dst|ip-src", limit=20)

    def query_domain(self, domain):
        """Search MISP for a specific domain."""
        return self.search_events(value=domain, type_attribute="domain", limit=20)

    def pull_iocs(self, types=None, tags=None, days=7, limit=5000,
                  to_ids_only=True):
        """Pull IOCs from MISP into a flat list for blocklist / ingestion.

        Returns list of dicts:
          [{"value": "1.2.3.4", "type": "ip-dst", "category": "...",
            "event_id": "123", "event_info": "...", "timestamp": "..."}, ...]
        """
        from_date = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d")
        net_types = types or ["ip-dst", "ip-src", "domain", "hostname",
                               "url", "md5", "sha1", "sha256"]
        results = []
        for t in (net_types if isinstance(net_types, list) else [net_types]):
            res = self.search_attributes(
                type_attribute=t,
                tags=tags,
                from_date=from_date,
                limit=limit,
                to_ids=to_ids_only,
            )
            if res.get("_error"):
                return res
            for attr in res.get("response", {}).get("Attribute", []):
                ev = attr.get("Event", {})
                results.append({
                    "value": attr.get("value"),
                    "type": attr.get("type"),
                    "category": attr.get("category"),
                    "to_ids": attr.get("to_ids"),
                    "timestamp": attr.get("timestamp"),
                    "comment": attr.get("comment"),
                    "event_id": ev.get("id"),
                    "event_info": ev.get("info"),
                    "event_date": ev.get("date"),
                })
        return results

    def push_ioc_event(self, name, iocs, tags=None, threat_level=3,
                       comment_prefix=""):
        """Create a MISP event and populate it with IOCs.

        iocs: list of dicts with keys: value, type, category, comment, confidence, source
        Returns: {"event_id": ..., "event_url": ..., "attributes_added": N}
        """
        ev = self.create_event(
            info=name,
            threat_level=threat_level,
            tags=tags,
        )
        if ev.get("_error"):
            return ev
        event_id = ev.get("id") or ev.get("Event", {}).get("id")
        if not event_id:
            return {"_error": True, "_message": "Event created but no ID returned", "raw": ev}

        added = 0
        for ioc in iocs:
            comment = ioc.get("comment", "")
            if comment_prefix and not comment.startswith(comment_prefix):
                comment = comment_prefix + comment
            attr_res = self.add_attribute(
                event_id=event_id,
                type_=ioc.get("type", "ip-dst"),
                value=ioc["value"],
                category=ioc.get("category", "Network activity"),
                comment=comment,
                to_ids=True,
            )
            if attr_res.get("_error"):
                print(f"WARN: failed to add attribute {ioc['value']}: "
                      f"{attr_res.get('_body', attr_res.get('_message', ''))}")
            else:
                added += 1

        self.publish_event(event_id)
        return {
            "event_id": event_id,
            "event_url": f"{self.base_url}/events/view/{event_id}",
            "attributes_added": added,
        }
