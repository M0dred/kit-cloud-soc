"""Local manual IOC review history; no network, MISP writes or case claims."""
import importlib.util
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

spec = importlib.util.spec_from_file_location('soc_review_store', Path(__file__).resolve().parents[1] / 'review-store.py')
review = importlib.util.module_from_spec(spec)
spec.loader.exec_module(review)


class ReviewStoreTests(unittest.TestCase):
    def test_approval_requires_evidence_expiry_and_appends_revocation(self):
        now = datetime(2026, 10, 27, 22, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as folder:
            db = Path(folder) / 'reviews.sqlite3'
            ip = '45.148.10.141'
            reason = 'Verified auth outcome and source correlation in private logs.'
            with self.assertRaisesRegex(ValueError, 'requires'):
                review.record(db, ip, 'approve_ids', 'analyst-01', reason, now=now)
            with self.assertRaisesRegex(ValueError, 'prior recorded approval'):
                review.record(db, ip, 'revoke', 'analyst-01', reason, now=now)
            self.assertEqual(review.current_decision(db, ip, now), 'unreviewed')
            expiry = (now + timedelta(days=3)).isoformat()
            self.assertEqual(review.record(db, ip, 'approve_ids', 'analyst-01', reason,
                                           'alert:opaque-123', expiry, now), 1)
            self.assertEqual(review.current_decision(db, ip, now), 'approve_ids')
            self.assertEqual(review.current_decision(db, ip, now + timedelta(days=4)), 'expired')
            review.record(db, ip, 'revoke', 'analyst-02', 'Approval withdrawn after evidence review.', now=now)
            self.assertEqual(review.current_decision(db, ip, now), 'revoke')
            self.assertEqual(len(review.history(db, ip)), 2)
            self.assertEqual(db.stat().st_mode & 0o777, 0o600)
            with sqlite3.connect(db) as con:
                with self.assertRaises(sqlite3.DatabaseError):
                    con.execute('DELETE FROM reviews')

    def test_reject_nonpublic_and_short_rationale(self):
        with tempfile.TemporaryDirectory() as folder:
            db = Path(folder) / 'reviews.sqlite3'
            with self.assertRaises(ValueError):
                review.record(db, '10.0.0.1', 'approve_ids', 'analyst-01', 'Verified auth outcome and evidence.',
                              'alert:opaque-123', '2026-11-01T00:00:00Z')
            with self.assertRaises(ValueError):
                review.record(db, '45.148.10.141', 'reject', 'analyst-01', 'Too short')
            self.assertFalse(db.exists())


if __name__ == '__main__':
    unittest.main()
