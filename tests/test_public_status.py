"""Offline checks for privacy-limited public run status and atomic write."""
import importlib.util
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

spec = importlib.util.spec_from_file_location('soc_public_status', Path(__file__).resolve().parents[1] / 'public-status.py')
status = importlib.util.module_from_spec(spec)
spec.loader.exec_module(status)


class PublicStatusTests(unittest.TestCase):
    def test_status_contains_no_sensor_or_error_detail(self):
        now = datetime(2026, 10, 27, 22, 1, tzinfo=timezone.utc)
        d = status.status_record('degraded', now)
        self.assertEqual(d, {'schema_version': 1, 'state': 'degraded',
                             'last_attempt_utc': '2026-10-27 22:01 UTC'})
        with self.assertRaises(ValueError):
            status.status_record('compromised', now)

    def test_atomic_root_only_write(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / 'status.json'
            status.write_status('unknown', target)
            self.assertEqual(json.loads(target.read_text())['state'], 'unknown')
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            self.assertFalse(target.with_suffix('.tmp').exists())


if __name__ == '__main__':
    unittest.main()
