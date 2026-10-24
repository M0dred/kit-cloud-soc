"""Offline checks for backup freshness and root-only recovery permissions."""
import importlib.util
import io
import tarfile
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / 'backup-health.py'
spec = importlib.util.spec_from_file_location('soc_backup_health', SCRIPT)
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


class BackupHealthTests(unittest.TestCase):
    def test_valid_daily_archive_and_missing_next_day(self):
        today = datetime(2026, 10, 24, 6, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as folder:
            dest = Path(folder)
            dest.chmod(0o700)
            archive = dest / 'soc-20261024-0230.tar.gz'
            with tarfile.open(archive, 'w:gz') as tar:
                for name in check.REQUIRED:
                    blob = b'fixture'
                    entry = tarfile.TarInfo(name)
                    entry.size = len(blob)
                    tar.addfile(entry, io.BytesIO(blob))
            archive.chmod(0o600)
            self.assertTrue(check.verified_today(dest, today))
            self.assertFalse(check.verified_today(dest, today + timedelta(days=1)))
            archive.chmod(0o644)
            self.assertFalse(check.verified_today(dest, today))

    def test_corrupt_archive_does_not_count(self):
        with tempfile.TemporaryDirectory() as folder:
            dest = Path(folder)
            dest.chmod(0o700)
            archive = dest / 'soc-20261024-0230.tar.gz'
            archive.write_bytes(b'not a tarball')
            archive.chmod(0o600)
            self.assertFalse(check.verified_today(dest, datetime(2026, 10, 24, tzinfo=timezone.utc)))


if __name__ == '__main__':
    unittest.main()
