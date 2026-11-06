"""Offline health-state regressions; never connect to Wazuh or use real agents."""
import contextlib
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('soc_health_check', ROOT / 'health-check.py')
health = importlib.util.module_from_spec(spec)
spec.loader.exec_module(health)


class HealthAgentStateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name) / 'agent-status.json'
        self.patches = [
            patch.object(health, 'STATE', self.state),
            patch.object(health, 'SOFT_AGENTS', {'fixture-laptop'}, create=True),
            patch.object(health, '_cfg', return_value='fixture config, no credentials'),
            patch.object(health, '_grab', return_value='fixture'),
            patch.object(health, 'indexer_facts', return_value=(20, '2026-11-06T06:00:00Z', 0.1)),
        ]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)

    def call(self, agents):
        out = io.StringIO()
        with patch.object(health, 'agent_states', return_value=agents), contextlib.redirect_stdout(out):
            health.main()
        return out.getvalue()

    def test_hard_agent_stays_failed_until_observed_active(self):
        self.state.write_text(json.dumps({'fixture-server': 'active'}))
        first = self.call({'fixture-server': 'disconnected'})
        second = self.call({'fixture-server': 'disconnected'})
        self.assertIn('FAIL agent down:', first)
        self.assertIn('FAIL agent down:', second, 'Persistent outage must not silently become healthy')
        recovered = self.call({'fixture-server': 'active'})
        self.assertNotIn('FAIL agent down:', recovered)
        self.assertIn('NOTE agent recovered:', recovered)
        self.assertEqual(json.loads(self.state.read_text()), {'fixture-server': 'active'})

    def test_initial_baseline_does_not_hide_hard_agent_outage(self):
        output = self.call({'fixture-server': 'disconnected'})
        self.assertIn('agent_baseline=created', output)
        self.assertIn('FAIL agent down:', output)

    def test_soft_agent_outage_is_warn_only_across_runs(self):
        first = self.call({'fixture-laptop': 'disconnected'})
        second = self.call({'fixture-laptop': 'disconnected'})
        for output in (first, second):
            self.assertIn('WARN agent down (soft target):', output)
            self.assertNotIn('FAIL agent down:', output)

    def test_unrecognized_nonactive_state_fails_closed(self):
        output = self.call({'fixture-server': 'unexpected-status'})
        self.assertIn('FAIL agent down:', output)


if __name__ == '__main__':
    unittest.main()
