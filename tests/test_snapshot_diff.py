"""Offline aggregate diff and publication tests; only synthetic public data and local Git."""
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from snapshot_diff import PUBLIC_DATA, PUBLIC_DIFF, build, compare

ROOT = Path(__file__).resolve().parents[1]
OLDER = '2026-11-26 06:06 UTC'
NEWER = '2026-11-26 12:01 UTC'
SOURCES = ('192.0.2.1', '192.0.2.2', '192.0.2.3')  # Local synthetic IDs only; no lookups.


def sample(stamp, rows=(), alerts=0, outside=None):
    return {'generated': stamp, 'wazuh': {'total_7d': alerts, 'top_src': [list(x) for x in rows],
            'pipeline_24h_coverage': {'outside_top_alerts': outside}},
            'misp': {'total': 3}, 'blocklist_n': 0}


def git(repo, *args):
    return subprocess.check_output(['git', '-C', str(repo), *args], stderr=subprocess.DEVNULL)


class SnapshotDiffTests(unittest.TestCase):
    def test_diffs_are_aggregate_and_keep_nulls(self):
        a, b, c = SOURCES
        old = sample(OLDER, [(a, 3), (b, 1)], alerts=5)
        old['private'] = 'must not propagate'
        new = sample(NEWER, [(b, 2), (c, 1)], alerts=4, outside=2)
        diff = compare(old, new)
        self.assertEqual(diff['metrics']['alerts_7d'], [5, 4])
        self.assertEqual(diff['metrics']['outside_top_500_alerts'], [None, 2])
        self.assertEqual(diff['sources'], {'entered': 1, 'left': 1, 'retained': 1, 'changed_alert_counts': 1})
        for token in (*SOURCES, 'must not propagate'):
            self.assertNotIn(token, json.dumps(diff))

    def test_no_baseline_or_display_correction_are_not_a_zero_diff(self):
        curr = sample(NEWER)
        for result in [compare(None, curr), compare(sample(OLDER), {**curr, 'public_revision': {}})]:
            self.assertIsNone(result['previous_utc'])
            self.assertIsNone(result['metrics'])
            self.assertIsNone(result['sources'])
        with self.assertRaises(ValueError):
            compare(curr, curr)
        with self.assertRaises(ValueError):
            compare(None, sample(NEWER, [(SOURCES[0], 1), (SOURCES[0], 2)]))

    def test_git_history_skips_unchanged_batch_and_heartbeat(self):
        with tempfile.TemporaryDirectory() as folder:
            repo = Path(folder)
            (repo / 'docs').mkdir()
            git(repo, 'init', '-b', 'main')
            git(repo, 'config', 'user.name', 'Offline fixture')
            git(repo, 'config', 'user.email', 'offline@example.invalid')
            shutil.copy(ROOT / 'snapshot_diff.py', repo)
            def commit(file, data):
                (repo / file).write_text(json.dumps(data) + '\n')
                git(repo, 'add', file)
                git(repo, 'commit', '-m', 'offline fixture')
            commit(PUBLIC_DATA, sample(OLDER, alerts=8))
            self.assertIsNone(json.loads(build(repo))['previous_utc'])
            commit(PUBLIC_DATA, sample(NEWER, alerts=12))
            initial = build(repo)
            self.assertEqual(json.loads(initial)['metrics']['alerts_7d'], [8, 12])
            commit('docs/status.json', {'state': 'degraded'})
            self.assertEqual(build(repo), initial)
            diff = repo / PUBLIC_DIFF
            diff.write_text('unreviewed bytes')
            command = [sys.executable, str(repo / 'snapshot_diff.py')]
            self.assertEqual(subprocess.run([*command, '--check'], capture_output=True).returncode, 1)
            self.assertEqual(diff.read_text(), 'unreviewed bytes')
            subprocess.run(command, check=True, capture_output=True)
            self.assertEqual(diff.read_bytes(), initial)
            subprocess.run([*command, '--check'], check=True, capture_output=True)
            commit(PUBLIC_DATA, {**sample(NEWER, alerts=99), 'public_revision': {'kind': 'projection_correction'}})
            self.assertIsNone(json.loads(build(repo))['previous_utc'])
            commit(PUBLIC_DATA, sample('2026-11-26 18:01 UTC', alerts=100))
            self.assertEqual(json.loads(build(repo))['metrics']['alerts_7d'], [99, 100])
