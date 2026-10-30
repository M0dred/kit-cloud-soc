"""Offline checks for exact rollups, full MISP membership and public privacy."""
import importlib.util
import contextlib
import io
import json
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("soc_dashboard", ROOT / "dashboard-gen.py")
dash = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dash)


class DashboardTests(unittest.TestCase):
    def test_total_is_not_sum_of_top_agents(self):
        d = {"hits": {"total": {"value": 100, "relation": "eq"}},
             "aggregations": {
                 "agents": {"buckets": [{"key": "host-a", "doc_count": 60}]},
                 "src": {"buckets": [{"key": "45.148.10.141", "doc_count": 14}]},
                 "days": {"buckets": [{"key_as_string": "2026-10-22T00:00:00Z", "doc_count": 100}]}}}
        result = dash.parse_wazuh_rollup(d)
        self.assertEqual(result["total_7d"], 100)
        self.assertEqual(sum(n for _, n in result["by_agent"]), 60)
        self.assertEqual(sum(n for _, n in result["by_day"]), 100)
        d["aggregations"]["src"]["buckets"][0]["sample"] = {"hits": {"hits": [{
            "_id": "private-ref", "_source": {"timestamp": "2026-10-22T06:00:00Z",
                "data": {"srcip": "45.148.10.141", "dstip": "203.0.113.10"},
                "agent": {"id": "001", "name": "private-agent"}, "rule": {"id": "5710"}}}]}}
        sampled = dash.parse_wazuh_rollup(d)
        self.assertEqual(sampled["samples_by_source"]["45.148.10.141"][0]["time_utc"], "2026-10-22 06:00:00 UTC")
        self.assertEqual(sampled["samples_by_source"]["45.148.10.141"][0]["destination_ip"], "203.0.113.10")
        d["hits"]["total"]["relation"] = "gte"
        with self.assertRaises(ValueError):
            dash.parse_wazuh_rollup(d)

    def test_enrichment_age_and_public_fields(self):
        now = datetime(2026, 10, 22, 12, tzinfo=timezone.utc)
        fresh = (now - timedelta(hours=2)).isoformat()
        old = (now - timedelta(days=3)).isoformat()
        entry = {"gn": {"classification": "malicious"}, "otx": {"pulses": 2},
                 "_lookups": {"gn": {"status": "ok", "checked_at": fresh},
                              "otx": {"status": "ok", "checked_at": old}}}
        self.assertEqual(dash.lookup_freshness(entry, "gn", now)["state"], "fresh")
        self.assertEqual(dash.lookup_freshness(entry, "otx", now)["state"], "stale")
        self.assertEqual(dash.lookup_freshness({"gn": {"classification": "malicious"}}, "gn", now)["state"], "unknown_age")
        p = dash.public_enrichment({"gn": '<script>alert(1)</script>', "aip": 90,
                                    "sources": {"gn": dash.lookup_freshness(entry, "gn", now)}})
        self.assertNotIn('<', p["gn"])
        self.assertEqual(p["sources"]["gn"]["state"], "fresh")
        self.assertNotIn("classification", p["sources"]["gn"])

    def test_db_provider_fallback_reads_only_private_evidence(self):
        with tempfile.TemporaryDirectory() as folder:
            temp = Path(folder)
            db = temp / "fixture-threat.db"
            con = sqlite3.connect(db)
            con.execute("CREATE TABLE iocs (ip TEXT PRIMARY KEY, evidence TEXT)")
            con.execute("INSERT INTO iocs VALUES (?, ?)", ("8.8.8.8",
                        json.dumps({"as_owner": "private.internal.example", "country": "US"})))
            con.commit()
            con.close()
            with patch.object(dash, "BASE", temp), patch.object(dash, "THREAT_DB", db, create=True):
                meta = dash.enrich_meta_for(["8.8.8.8"])["8.8.8.8"]
            self.assertEqual(meta["db_provider_private"], "private.internal.example")
            self.assertEqual(meta["db_country_private"], "US")
            public = dash.public_enrichment(meta)
            self.assertNotIn("db_provider_private", public)
            self.assertNotIn("provider", public)
            self.assertNotIn("private.internal.example", json.dumps(public))

    def test_enrichment_failure_preserves_last_safe_public_snapshot(self):
        with tempfile.TemporaryDirectory() as folder:
            temp = Path(folder)
            (temp / "docs").mkdir()
            (temp / "docs/data.json").write_text("LAST_SAFE_PUBLIC_SNAPSHOT")
            waz = {"top_src": [["8.8.8.8", 1]], "by_day": [], "total_7d": 1}
            misp = {"total": 0, "watchlist": [], "member_ips": [], "recent_14d": []}
            with patch.object(dash, "BASE", temp), patch.object(dash, "OUT", temp / "dashboard"), \
                 patch.object(dash, "PUBLIC", temp / "docs"), \
                 patch.object(dash, "wazuh_7d", return_value=waz), \
                 patch.object(dash, "misp_1932", return_value=misp), \
                 patch.object(dash, "vt_ledger", return_value={"posted_total": 0}), \
                 patch.object(dash, "health", return_value={}), \
                 patch.object(dash, "runs", return_value=[]), \
                 patch.object(dash, "enrich_meta_for", side_effect=ValueError("private fixture evidence")):
                with self.assertRaisesRegex(RuntimeError, "enrichment generation failed"):
                    dash.main()
            self.assertEqual((temp / "docs/data.json").read_text(), "LAST_SAFE_PUBLIC_SNAPSHOT")
            self.assertFalse((temp / "dashboard/data.json").exists())

    def test_ndr_snapshot_age_and_private_matches(self):
        now = datetime(2026, 10, 22, 12, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as folder:
            temp = Path(folder)
            (temp / "ndr-evidence.json").write_text(json.dumps({"schema_version": 1,
                "status": "ok", "checked_at": (now - timedelta(hours=3)).isoformat(),
                "matches": [{"ip": "45.148.10.141", "samples": [{"destination_ip": "203.0.113.10"}]},
                            {"ip": "45.148.10.142", "samples": []}]}))
            with patch.object(dash, "BASE", temp):
                record = dash.read_ndr_evidence(["45.148.10.141"], now)
                self.assertEqual(record["status"], "ok")
                self.assertEqual(len(record["matches"]), 1)
                record = dash.read_ndr_evidence(["45.148.10.141"], now + timedelta(days=2))
                self.assertEqual(record["status"], "stale")

    def test_pipeline_coverage_reports_truncation_only_while_fresh(self):
        now = datetime(2026, 10, 24, 6, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as folder:
            temp = Path(folder)
            (temp / 'summaries').mkdir()
            (temp / 'summaries/summary.json').write_text(json.dumps({
                'finished': now.isoformat(), 'stage_results': {'wazuh_source_coverage': {
                    'source_bucket_limit': 500, 'outside_top_alerts': 41,
                    'approx_unique_sources': 541, 'private_asset': 'do not publish'}}}))
            with patch.object(dash, 'BASE', temp):
                info = dash.pipeline_coverage(now)
                self.assertEqual(info['outside_top_alerts'], 41)
                self.assertEqual(info['approx_source_values'], 541)
                self.assertNotIn('private_asset', info)
                self.assertIsNone(dash.pipeline_coverage(now + timedelta(days=2))['outside_top_alerts'])

    def test_public_sample_context_only_emits_whitelisted_categories(self):
        ip = "45.148.10.141"
        private = {"time_utc": "2026-10-22 06:00:00 UTC", "rule": "sshd failed 203.0.113.10",
                   "destination_ip": "203.0.113.10", "agent_name": "private-agent"}
        ctx = dash.public_sample_context([private])
        self.assertEqual(ctx, {"last_sample_utc": "2026-10-22 06:00:00 UTC",
                               "sample_behavior": "SSH authentication alert"})
        self.assertNotIn("203.0.113.10", json.dumps(ctx))
        self.assertEqual(dash.public_sample_context([{"rule": "unrecognized 203.0.113.10"}]),
                         {"last_sample_utc": None, "sample_behavior": "Other detection (sample only)"})

    def test_private_evidence_never_reaches_public_json(self):
        victim = '203.0.113.10'
        ip = '45.148.10.141'
        waz = {"total_7d": 1, "top_src": [(ip, 1)], "by_agent": [('private-agent', 1)],
               "by_day": [('2026-10-22', 1)],
               "samples_by_source": {ip: [{"agent_name": "private-agent", "destination_ip": victim,
                                          "time_utc": "2026-10-22 06:00:00 UTC", "rule": "sshd failed "+victim}]}}
        misp = {"total": 1, "recent_14d": [{"ip": ip, "date": "2026-10-22",
                "comment": 'victim '+victim}], "member_ips": [ip], "watchlist": [ip], "cidrs": []}
        ndr = {"status": "ok", "checked_at": "2026-10-22T11:00:00+00:00", "matches": [
            {"ip": ip, "samples": [{"destination_ip": victim}]}]}
        with tempfile.TemporaryDirectory() as folder:
            temp = Path(folder)
            (temp / 'config.yaml').write_text('sensor_public_ips:\n  sensor: "'+victim+'"\n')
            with patch.object(dash, 'BASE', temp), patch.object(dash, 'OUT', temp/'dashboard'), \
                 patch.object(dash, 'PUBLIC', temp/'docs'), patch.object(dash, 'wazuh_7d', return_value=waz), \
                 patch.object(dash, 'misp_1932', return_value=misp), patch.object(dash, 'vt_ledger', return_value={'posted_total': 0}), \
                 patch.object(dash, 'health', return_value={}), patch.object(dash, 'runs', return_value=[]), \
                 patch.object(dash, 'enrich_meta_for', return_value={ip: {'sources': {}}}), \
                 patch.object(dash, 'read_ndr_evidence', return_value=ndr), contextlib.redirect_stdout(io.StringIO()):
                dash.main()
            private = (temp/'dashboard/data.json').read_text()
            public = (temp/'docs/data.json').read_text()
            pub_data = json.loads(public)
            self.assertIn(victim, private)
            self.assertNotIn(victim, public)
            self.assertNotIn('private-agent', public)
            self.assertNotIn('samples_by_source', public)
            self.assertNotIn('member_ips', public)
            self.assertNotIn('ndr', public)
            self.assertTrue(pub_data['misp']['top_source_membership'][ip])
            self.assertEqual(pub_data['wazuh']['by_agent'], [])
            self.assertEqual(pub_data['wazuh']['source_context'][ip]['sample_behavior'],
                             'SSH authentication alert')
            self.assertEqual(pub_data['wazuh']['source_context'][ip]['last_sample_utc'],
                             '2026-10-22 06:00:00 UTC')

    def test_full_membership_not_recent_slice(self):
        old = int((datetime.now(timezone.utc) - timedelta(days=90)).timestamp())
        fresh = int(datetime.now(timezone.utc).timestamp())
        attrs = [{"type": "ip-dst", "value": "45.148.10.141", "timestamp": old},
                 {"type": "ip-src", "value": "45.148.10.142", "timestamp": fresh},
                 {"type": "ip-src", "value": "10.0.0.3", "timestamp": fresh}]
        class FakeMisp:
            def __init__(self, *args, **kwargs): pass
            def get_event(self, event): return {"Event": {"Attribute": attrs}}
        with tempfile.TemporaryDirectory() as folder:
            temp = Path(folder)
            (temp / "config.yaml").write_text('misp:\n  url: https://test.invalid\n  api_key: fixture\n  event_id: 1932\n')
            with patch.object(dash, "BASE", temp), patch.object(dash, "MISPClient", FakeMisp):
                result = dash.misp_1932()
        self.assertEqual(result["total"], 3)
        self.assertIn("45.148.10.141", result["member_ips"])
        self.assertNotIn("45.148.10.141", [r["ip"] for r in result["recent_14d"]])
        self.assertNotIn("10.0.0.3", result["member_ips"])


if __name__ == "__main__": unittest.main()
