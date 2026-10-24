"""Offline regression tests for SOC comments, IOC selection and MISP writes."""
import importlib.util
import json
import os
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock, patch

BASE = Path(__file__).resolve().parents[1]
SKILL = Path.home() / ".config/agents/skills/soc-connector/scripts"
SNAPSHOT = os.environ.get('SOC_TEST_USE_SNAPSHOT') == '1' or not (SKILL / 'soc-orchestrator.py').exists()
if SNAPSHOT:
    SKILL = BASE / 'src/soc-connector'
sys.path.insert(0, str(BASE))
sys.path.insert(0, str(SKILL))
sys.path.insert(0, str(BASE / 'src/linux-log-threat-hunt' if SNAPSHOT else
                       Path.home() / '.config/agents/skills/linux-log-threat-hunt/scripts'))
from ioc_comment import render_comment  # noqa: E402
from vt_comment_new import eligible, parse_comment  # noqa: E402
import intel_enrich  # noqa: E402


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


orch = load("orch", SKILL / "soc-orchestrator.py")
ndr = load("ndr", BASE / "ndr-cross.py")
NOW = datetime(2026, 10, 22, 6, 0, tzinfo=timezone.utc)
SENSORS = {"sensor-test": "203.0.113.10"}


class CommentTests(unittest.TestCase):
    def render(self, rule, intel=None, agent="sensor-test", count=60, level=10):
        return render_comment("45.148.10.141", count, agent, rule, intel=intel,
                              level=level, when=NOW, sensor_public_ips=SENSORS)

    def test_ssh_source_corroboration_and_masking(self):
        text = self.render("sshd failed password for 203.0.113.10", {
            "gn": {"classification": "malicious"}, "otx": {"pulses": 2},
            "aipdb": {"score": 87},
        })
        self.assertIn("Date: 2026-10-22 06:00 UTC", text)
        self.assertIn("IOC: 45.148.10[.]141", text)
        self.assertIn("ip-src", text)
        self.assertIn("OTX pulses=2", text)
        self.assertIn("AbuseIPDB=87", text)
        self.assertIn("Target: sensor-test (203.0.*.*)", text)
        self.assertNotIn("203.0.113.10", text)
        self.assertIn("Rule: sshd failed password for [address withheld]", text)
        self.assertIn("https://www.virustotal.com/gui/ip-address/45.148.10.141", text)
        self.assertIn("Via: kit-cloud SoC (Kowalski, analysis)", text)

    def test_web400_not_exploitation_or_high_confidence(self):
        text = self.render("Web server 400 error code", count=356, level=5)
        self.assertIn("HTTP errors alone do not prove exploitation", text)
        self.assertIn("Low (unconfirmed)", text)
        self.assertNotIn("T1190", text)
        self.assertNotIn("IPv4 attacker", text)

    def test_unclassified_unknown_target(self):
        text = self.render("Unrecognized event", agent="private-internal-host")
        self.assertIn("Target: withheld", text)
        self.assertNotIn("private-internal-host", text)
        self.assertIn("Not established from available telemetry", text)

    def test_reject_nonpublic_ioc(self):
        with self.assertRaises(ValueError):
            render_comment("10.0.1.1", 200, "sensor-test", "sshd", level=10)

    def test_new_format_is_parseable(self):
        text = self.render("sshd: authentication failed", {"aipdb": {"score": 90}})
        meta = parse_comment(text)
        self.assertEqual((meta["count"], meta["level"]), (60, 10))
        self.assertEqual(meta["aip"], 90)
        self.assertEqual(meta["agent"], "sensor-test")
        self.assertTrue(eligible("45.148.10.141", meta, {}))

    def test_legacy_comment_parse_and_cloud_web_skip(self):
        self.assertEqual(parse_comment("Wazuh: 400x, lvl=10 | OTX: pulses=5 | AIPDB: score=80")['count'], 400)
        web = parse_comment(self.render("Web server 400 error code", {"aipdb": {"score": 100}}))
        self.assertFalse(eligible("45.148.10.141", web, {}))
        ssh = parse_comment(self.render("sshd authentication failed", {"aipdb": {"score": 100}}))
        self.assertFalse(eligible("20.249.5.100", ssh, {}))
        self.assertFalse(eligible("10.0.0.1", ssh, {}))
        self.assertFalse(eligible("45.148.10.141", ssh, {"gn": {"riot": True}}))


class PipelineTests(unittest.TestCase):
    def fake_orch(self, existing=()):
        obj = orch.Orchestrator.__new__(orch.Orchestrator)
        obj.cfg = {"pipeline": {"vt_push_threshold": 2, "wazuh_count_threshold": 200},
                   "misp": {"event_id": 1932, "url": "https://misp.example"},
                   "sensor_public_ips": SENSORS}
        obj.intel = {}
        obj.dry_run = False
        obj.db = Mock()
        obj.db.get_ioc.return_value = {"evidence": json.dumps({"wazuh_count": 60,
                               "wazuh_level": 10}), "vt_malicious": 0, "vt_suspicious": 0}
        obj.misp = Mock()
        obj.misp.get_event.return_value = {"Event": {"Attribute": [
            {"type": "ip-dst", "value": ip} for ip in existing]}}
        obj.misp.add_attribute.return_value = {"Attribute": {"id": "1"}}
        obj.misp.publish_event.return_value = {"message": "Published"}
        obj.summary = {"stage_results": {}}
        obj.log = lambda message: None
        return obj

    def test_misp_new_source_not_duplicate_old_type(self):
        obj = self.fake_orch(existing=["45.148.10.141"])
        attrs = [{"ip": "45.148.10.141", "count": 60, "rule_level": 10,
                  "rule_desc": "sshd: failed password", "agent_name": "sensor-test"},
                 {"ip": "45.148.10.142", "count": 60, "rule_level": 10,
                  "rule_desc": "sshd: failed password", "agent_name": "sensor-test"}]
        obj.stage_update_misp(attrs, {})
        self.assertEqual(obj.summary["stage_results"]["misp_attributes_added"], 1)
        self.assertEqual(obj.misp.add_attribute.call_args.kwargs["type_"], "ip-src")
        self.assertIs(obj.misp.add_attribute.call_args.kwargs["to_ids"], False)
        obj.misp.publish_event.assert_called_once()

    def test_count_only_misp_candidate_is_never_auto_ids(self):
        obj = self.fake_orch()
        obj.stage_update_misp([{"ip": "45.148.10.141", "count": 220,
                                "rule_level": 5, "rule_desc": "HTTP 400"}], {})
        self.assertIs(obj.misp.add_attribute.call_args.kwargs["to_ids"], False)

    def test_misp_errors_are_not_silent(self):
        obj = self.fake_orch()
        obj.misp.get_event.return_value = {"_error": True, "_status": 503}
        with self.assertRaises(RuntimeError):
            obj.stage_update_misp([{"ip": "45.148.10.141", "count": 60,
                                     "rule_level": 10, "rule_desc": "sshd"}], {})

    def test_enrichment_cache_keeps_last_success_after_quota_error(self):
        previous = {"45.148.10.141": {"gn": {"classification": "malicious", "http": 200},
                                       "_lookups": {"gn": {"status": "ok", "checked_at": "2026-10-22T06:00:00+00:00"}}}}
        updates = {"45.148.10.141": {"gn": {"_rate_limited": True, "http": 429},
                                      "gn_checked_at": "2026-10-22T08:00:00+00:00"}}
        result = orch.Orchestrator._merge_enrichment_cache(previous, updates)["45.148.10.141"]
        self.assertEqual(result["gn"]["classification"], "malicious")
        self.assertEqual(result["_lookups"]["gn"]["checked_at"], "2026-10-22T06:00:00+00:00")
        self.assertEqual(result["_lookups"]["gn"]["status"], "rate_limited")
        result = orch.Orchestrator._merge_enrichment_cache(previous, {"45.148.10.141": {
            "gn": {"_not_found": True, "classification": None, "http": 404},
            "gn_checked_at": "2026-10-22T09:00:00+00:00"}})["45.148.10.141"]
        self.assertIsNone(result["gn"]["classification"])

    def test_greynoise_404_message_not_a_classification(self):
        with patch.object(intel_enrich, "_get", return_value=({"message": "IP not observed"}, 404)):
            result = intel_enrich.greynoise("45.148.10.141", "fixture")
        self.assertIsNone(result["classification"])
        self.assertTrue(result["_not_found"])

    def test_ndr_only_reports_matched_indicator(self):
        ag = {"src": {"buckets": [{"key": "45.148.10.141", "doc_count": 1,
              "sample": {"hits": {"hits": [{"_source": {"@timestamp": "2026-10-22T06:00:00Z",
                       "src_ip": "45.148.10.141", "dest_ip": "203.0.113.10",
                       "alert": {"signature_id": 20210}}}]}}}]},
              "dst": {"buckets": [{"key": "203.0.113.10", "doc_count": 1}]}}
        hits = ndr.ioc_hits(ag, ["45.148.10.141"])
        self.assertEqual(hits, [("45.148.10.141", "src", 1)])
        records = ndr.evidence_matches(ag, ["45.148.10.141"])
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["samples"][0]["time_utc"], "2026-10-22 06:00:00 UTC")
        self.assertEqual(records[0]["samples"][0]["destination_ip"], "203.0.113.10")


if __name__ == "__main__":
    unittest.main()
