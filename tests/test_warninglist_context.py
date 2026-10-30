"""Offline tests: private warninglist labels never become verdicts or public data."""
import importlib.util
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("warninglist_context", BASE / "warninglist_context.py")
context = importlib.util.module_from_spec(spec)
spec.loader.exec_module(context)
NOW = datetime(2026, 10, 30, tzinfo=timezone.utc)
SOURCES = {"fixture-provider": ("Fixture provider range", 1, "Fixture CIDR list")}


def fixture(**updates):
    record = {"name": "Fixture CIDR list", "type": "cidr", "version": 20261020,
              "list": ["8.8.8.0/24", "2001:4860:4860::/48"]}
    record.update(updates)
    return record


class WarninglistContextTests(unittest.TestCase):
    def test_only_global_source_ipv4_and_provider_label(self):
        rows = [{"ip": "8.8.8.8", "agent_name": "private-agent",
                 "destination_ip": "192.0.2.33", "token": "FAKE_PRIVATE_TEST_TOKEN"},
                {"ip": "10.0.0.1"}, {"ip": "203.0.113.11"},
                {"ip": "1.1.1.1"}, {"ip": "not-an-ip"}]
        report = context.build_report(rows, fetch=lambda _: fixture(), now=NOW,
                                      sources=SOURCES, coverage={"outside_top_alerts": 7})
        self.assertEqual(report["status"], "fresh")
        self.assertEqual(report["observed_sources"], 2)
        self.assertEqual(report["outside_top_alerts"], 7)
        self.assertEqual(report["matches"], [{"source_ip": "8.8.8.8",
                                               "provider_ranges": ["Fixture provider range"]}])
        self.assertEqual(report["list_versions"], {"fixture-provider": "20261020"})
        encoded = json.dumps(report)
        for secret in ("private-agent", "192.0.2.33", "FAKE_PRIVATE_TEST_TOKEN"):
            self.assertNotIn(secret, encoded)
        self.assertNotIn("verdict", report)

    def test_missing_source_fails_closed_and_clears_matches(self):
        sources = {**SOURCES, "missing-source": ("Missing", 1, "Missing")}
        def fetch(slug):
            if slug == "missing-source":
                raise OSError("do not expose private failure details")
            return fixture()
        result = context.build_report([{"ip": "8.8.8.8"}], fetch=fetch, now=NOW, sources=sources)
        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(result["matches"], [])
        self.assertEqual(result["list_versions"], {})
        self.assertNotIn("private failure", json.dumps(result))

    def test_invalid_stale_and_future_lists_fail_closed(self):
        for updates in ({"type": "string"}, {"name": "Wrong source"},
                        {"version": 20260701}, {"version": 20261101},
                        {"list": []}, {"list": ["0.0.0.0/0"]},
                        {"list": ["8.8.8.7/24"]}, {"list": ["not a CIDR"]}):
            with self.subTest(updates=updates):
                result = context.build_report([{"ip": "8.8.8.8"}],
                    fetch=lambda _: fixture(**updates), now=NOW, sources=SOURCES)
                self.assertEqual(result["status"], "unavailable")
                self.assertEqual(result["matches"], [])

    def test_no_sources_does_not_contact_upstream(self):
        def unexpected(_):
            raise AssertionError("no fetch for an empty window")
        report = context.build_report([], fetch=unexpected, now=NOW, sources=SOURCES)
        self.assertEqual(report["status"], "no_observations")
        self.assertEqual(report["matches"], [])

    def test_file_is_atomic_private_and_old_matches_are_removed(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "warninglist-context.json"
            context.write_report({"matches": [{"source_ip": "8.8.8.8"}]}, path)
            context.write_report({"matches": [], "status": "unavailable"}, path)
            self.assertEqual(json.loads(path.read_text()), {"matches": [], "status": "unavailable"})
            self.assertEqual(path.stat().st_mode & 0o077, 0)
            self.assertFalse(path.with_suffix(".tmp").exists())

    def test_fetch_accepts_only_four_upstream_paths(self):
        with self.assertRaises(ValueError):
            context.fetch_list("../../not-approved")


if __name__ == "__main__":
    unittest.main()
