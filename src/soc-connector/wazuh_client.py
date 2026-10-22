#!/usr/bin/env python3
"""Wazuh API client.

Supports: JWT auth, alerts query, agent management, active response,
custom rules deployment, MITRE mapping query.

Uses Python stdlib only.
"""
import json
import ssl
import urllib.request
import urllib.error
from datetime import datetime, timezone, timedelta


class WazuhClient:
    def __init__(self, base_url, username, password, verify_tls=True):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.verify_tls = verify_tls
        self._token = None
        self._ctx = ssl.create_default_context()
        if not verify_tls:
            self._ctx.check_hostname = False
            self._ctx.verify_mode = ssl.CERT_NONE

    # ------------------------------------------------------------------
    # Auth
    # ------------------------------------------------------------------

    def _get_token(self):
        if self._token:
            return self._token
        payload = json.dumps({}).encode()
        req = urllib.request.Request(
            f"{self.base_url}/security/user/authenticate",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        # Wazuh uses basic auth for the initial token request
        import base64
        creds = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
        req.add_header("Authorization", f"Basic {creds}")
        try:
            with urllib.request.urlopen(req, context=self._ctx, timeout=30) as r:
                data = json.loads(r.read().decode())
                self._token = data.get("data", {}).get("token")
                return self._token
        except urllib.error.HTTPError as e:
            body = e.read().decode()[:500]
            return {"_error": True, "_status": e.code, "_body": body}
        except Exception as e:
            return {"_error": True, "_message": str(e)}

    def _req(self, path, data=None, method="GET", headers=None):
        token = self._get_token()
        if isinstance(token, dict) and token.get("_error"):
            return token

        url = f"{self.base_url}{path}"
        h = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
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
            # Handle 401 by retrying token refresh once
            if e.code == 401:
                self._token = None
                token = self._get_token()
                if isinstance(token, dict) and token.get("_error"):
                    return token
                h["Authorization"] = f"Bearer {token}"
                req = urllib.request.Request(url, headers=h, data=payload, method=method)
                with urllib.request.urlopen(req, context=self._ctx, timeout=30) as r:
                    return json.loads(r.read().decode())
            return {"_error": True, "_status": e.code, "_body": body}
        except Exception as e:
            return {"_error": True, "_message": str(e)}

    # ------------------------------------------------------------------
    # Agents
    # ------------------------------------------------------------------

    def list_agents(self, status=None, limit=500):
        """List all agents. status: active, disconnected, never_connected, pending."""
        qs = f"?limit={limit}"
        if status:
            qs += f"&status={status}"
        return self._req(f"/agents{qs}")

    def get_agent(self, agent_id):
        return self._req(f"/agents?agents_list={agent_id}")

    def get_agent_key(self, agent_id):
        return self._req(f"/agents/{agent_id}/key")

    def get_agent_config(self, agent_id, component="syscheck"):
        return self._req(f"/agents/{agent_id}/config/{component}/configuration")

    def restart_agent(self, agent_id):
        return self._req(f"/agents/{agent_id}/restart", method="PUT")

    # ------------------------------------------------------------------
    # Logs (manager internal logs — not security alerts)
    #
    # NOTE: Security alerts are stored in the Wazuh Indexer (OpenSearch).
    # Query them via the Wazuh Dashboard API or Indexer API, not here.
    # ------------------------------------------------------------------

    def get_manager_logs(self, limit=100, offset=0, sort_by="timestamp",
                         sort_order="desc", search=None):
        """Query Wazuh manager internal logs (analysisd, authd, etc.)."""
        # Wazuh sort: prefix with '-' for descending; '+' must be URL-encoded
        sort_prefix = "-" if sort_order == "desc" else "%2B"
        qs = f"?limit={limit}&offset={offset}&sort={sort_prefix}{sort_by}"
        if search:
            qs += f"&search={urllib.parse.quote(search)}"
        return self._req(f"/manager/logs{qs}")

    def get_agent_logs(self, agent_id, limit=100, offset=0):
        """Query agent internal logs (ossec.log).

        NOTE: This endpoint may not exist on all Wazuh versions.
        Falls back to manager logs for agent 000.
        """
        qs = f"?limit={limit}&offset={offset}"
        res = self._req(f"/agents/{agent_id}/logs{qs}")
        if res.get("_status") == 404 and agent_id == "000":
            return self.get_manager_logs(limit=limit, offset=offset)
        return res

    def get_decoders(self, limit=500):
        return self._req(f"/decoders?limit={limit}")

    def get_rules(self, limit=500, status=None, group=None):
        qs = f"?limit={limit}"
        if group:
            qs += f"&group={group}"
        if status:
            qs += f"&status={status}"
        return self._req(f"/rules{qs}")

    def get_mitre_techniques(self, limit=500, search=None):
        """Query MITRE ATT&CK techniques from Wazuh."""
        qs = f"?limit={limit}"
        if search:
            qs += f"&search={urllib.parse.quote(search)}"
        return self._req(f"/mitre/techniques{qs}")

    def get_mitre_tactics(self, limit=500, search=None):
        """Query MITRE ATT&CK tactics from Wazuh."""
        qs = f"?limit={limit}"
        if search:
            qs += f"&search={urllib.parse.quote(search)}"
        return self._req(f"/mitre/tactics{qs}")

    # ------------------------------------------------------------------
    # Vulnerability / Syscheck / SCA
    # ------------------------------------------------------------------

    def get_vulnerabilities(self, agent_id, severity=None, limit=100):
        """Query vulnerability inventory for an agent.

        NOTE: Requires Wazuh Vulnerability Detector module enabled.
        Returns 404 if the module is disabled or no scan exists.
        """
        qs = f"?limit={limit}"
        if severity:
            qs += f"&severity={severity}"
        return self._req(f"/vulnerability/{agent_id}{qs}")

    def get_syscheck_files(self, agent_id, limit=100, file=None):
        qs = f"?limit={limit}"
        if file:
            qs += f"&file={urllib.parse.quote(file)}"
        return self._req(f"/syscheck/{agent_id}{qs}")

    def get_sca(self, agent_id, limit=100):
        return self._req(f"/sca/{agent_id}?limit={limit}")

    # ------------------------------------------------------------------
    # Active Response
    # ------------------------------------------------------------------

    def active_response(self, agent_id, command, custom_args=None, alert=None):
        """Send active response command to agent(s).

        Common commands: restart-wazuh, firewalld-drop, host-deny,
        ip-customblock, netsh, route-null

        agent_id: specific ID or "!0" for all agents
        """
        payload = {
            "command": command,
            "arguments": custom_args or [],
            "alert": alert or {},
        }
        return self._req(f"/active-response?agents_list={agent_id}",
                         data=payload, method="PUT")

    def block_ip(self, agent_id, ip, command="firewalld-drop"):
        """Convenience wrapper to block an IP via active response."""
        return self.active_response(
            agent_id=agent_id,
            command=command,
            custom_args=[ip],
            alert={"data": {"srcip": ip}},
        )

    # ------------------------------------------------------------------
    # Manager / Cluster
    # ------------------------------------------------------------------

    def get_manager_status(self):
        return self._req("/manager/status")

    def get_manager_info(self):
        return self._req("/manager/info")

    def get_cluster_status(self):
        return self._req("/cluster/status")

    def get_cluster_nodes(self):
        return self._req("/cluster/nodes")

    # ------------------------------------------------------------------
    # Custom Rules (requires manager filesystem access or API)
    # ------------------------------------------------------------------

    def upload_rule(self, rule_name, rule_xml):
        """Upload custom rules to Wazuh manager.

        Note: Wazuh API doesn't directly expose rule file uploads in all versions.
        This may require manager filesystem access or configuration API.
        """
        # Wazuh API for manager config updates
        payload = {"path": f"etc/rules/{rule_name}", "content": rule_xml}
        return self._req("/manager/files", data=payload, method="POST")

    def reload_rules(self):
        """Trigger ruleset reload."""
        return self._req("/manager/restart", method="PUT")

    # ------------------------------------------------------------------
    # Bulk operations
    # ------------------------------------------------------------------

    def get_agents_by_ip(self, ip):
        """Find which agent(s) are associated with an IP."""
        agents = self.list_agents(limit=1000)
        if agents.get("_error"):
            return agents
        matches = []
        for a in agents.get("data", {}).get("affected_items", []):
            if a.get("ip") == ip or a.get("manager") == ip:
                matches.append(a)
        return matches

    def push_blocklist_to_agents(self, ips, command="firewalld-drop"):
        """Block a list of IPs on all agents."""
        results = []
        for ip in ips:
            res = self.block_ip("!0", ip, command)
            results.append({"ip": ip, "result": res})
        return results
