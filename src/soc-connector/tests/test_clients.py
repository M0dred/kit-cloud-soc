#!/usr/bin/env python3
"""Unit tests for MISP and Wazuh clients.

Tests do NOT require a live server; they exercise import, instantiation,
schema generation, and request URL formation.

Run:
    python3 -m pytest scripts/tests/test_clients.py -v
    # or without pytest:
    python3 scripts/tests/test_clients.py
"""
import json
import os
import sys
import unittest
from unittest.mock import patch, MagicMock

# Ensure imports work when running from repo root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from misp_client import MISPClient
from wazuh_client import WazuhClient


class TestMISPClient(unittest.TestCase):

    def test_init(self):
        c = MISPClient("https://misp.example.com", "secret123", verify_tls=False)
        self.assertEqual(c.base_url, "https://misp.example.com")
        self.assertEqual(c.api_key, "secret123")
        self.assertFalse(c.verify_tls)

    def test_query_ip_url_formation(self):
        """Ensure search_events is called with correct params."""
        c = MISPClient("https://misp.example.com", "k")
        with patch.object(c, "_req") as mock_req:
            c.query_ip("1.2.3.4")
            call_args = mock_req.call_args
            self.assertIn("/events/restSearch", call_args[0][0])

    def test_push_ioc_event_creates_then_adds(self):
        """Simulate event creation + attribute addition."""
        c = MISPClient("https://misp.example.com", "k")
        with patch.object(c, "_req") as mock_req:
            # First call: create_event returns event dict with id
            mock_req.return_value = {"id": "42"}
            res = c.push_ioc_event(
                name="Test Event",
                iocs=[{"value": "1.2.3.4", "type": "ip-dst"}],
            )
            # create_event + add_attribute + publish_event = 3 calls
            self.assertEqual(mock_req.call_count, 3)
            self.assertEqual(res.get("event_id"), "42")
            self.assertEqual(res.get("attributes_added"), 1)

    def test_pull_iocs_parses_attributes(self):
        c = MISPClient("https://misp.example.com", "k")
        fake_response = {
            "response": {
                "Attribute": [
                    {
                        "value": "1.2.3.4",
                        "type": "ip-dst",
                        "category": "Network activity",
                        "to_ids": True,
                        "timestamp": "1234567890",
                        "comment": "",
                        "Event": {"id": "7", "info": "Test", "date": "2024-01-01"},
                    }
                ]
            }
        }
        # Patch search_attributes directly to avoid iterating over default types
        with patch.object(c, "search_attributes", return_value=fake_response):
            iocs = c.pull_iocs(types=["ip-dst"], days=7)
            self.assertEqual(len(iocs), 1)
            self.assertEqual(iocs[0]["value"], "1.2.3.4")
            self.assertEqual(iocs[0]["event_id"], "7")


class TestWazuhClient(unittest.TestCase):

    def test_init(self):
        c = WazuhClient("https://wazuh.example.com:55000", "u", "p", verify_tls=False)
        self.assertEqual(c.base_url, "https://wazuh.example.com:55000")
        self.assertEqual(c.username, "u")

    @patch("urllib.request.urlopen")
    def test_auth_and_get_token(self, mock_urlopen):
        """Simulate JWT token acquisition."""
        resp = MagicMock()
        resp.read.return_value = json.dumps({"data": {"token": "fakejwt"}}).encode()
        mock_urlopen.return_value.__enter__.return_value = resp

        c = WazuhClient("https://wazuh.example.com:55000", "u", "p", verify_tls=False)
        token = c._get_token()
        self.assertEqual(token, "fakejwt")

    @patch("urllib.request.urlopen")
    def test_list_agents(self, mock_urlopen):
        """Simulate listing agents."""
        resp = MagicMock()
        resp.read.return_value = json.dumps({
            "data": {
                "affected_items": [
                    {"id": "001", "name": "agent1", "status": "active"}
                ]
            }
        }).encode()
        mock_urlopen.return_value.__enter__.return_value = resp

        c = WazuhClient("https://wazuh.example.com:55000", "u", "p", verify_tls=False)
        result = c.list_agents()
        self.assertIn("affected_items", result.get("data", {}))
        self.assertEqual(result["data"]["affected_items"][0]["name"], "agent1")

    @patch("urllib.request.urlopen")
    def test_block_ip(self, mock_urlopen):
        """Simulate active response block."""
        resp = MagicMock()
        resp.read.return_value = json.dumps({"message": "Success"}).encode()
        mock_urlopen.return_value.__enter__.return_value = resp

        c = WazuhClient("https://wazuh.example.com:55000", "u", "p", verify_tls=False)
        result = c.block_ip("001", "10.0.0.99")
        self.assertFalse(result.get("_error", False))


class TestStdlibOnly(unittest.TestCase):
    """Ensure no third-party dependencies leaked in."""

    def test_no_requests_import(self):
        with open(os.path.join(os.path.dirname(__file__), "..", "misp_client.py")) as f:
            self.assertNotIn("import requests", f.read())
        with open(os.path.join(os.path.dirname(__file__), "..", "wazuh_client.py")) as f:
            self.assertNotIn("import requests", f.read())


if __name__ == "__main__":
    unittest.main(verbosity=2)
