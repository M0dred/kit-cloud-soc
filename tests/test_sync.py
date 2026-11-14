"""Offline status-only Git sync against a local bare remote; no SOC credentials."""
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def git(repo, *args):
    return subprocess.check_output(['git', '-C', str(repo), *args], text=True).strip()


class StatusOnlySyncTests(unittest.TestCase):
    def test_failed_run_syncs_only_sanitized_status(self):
        with tempfile.TemporaryDirectory() as folder:
            tmp = Path(folder)
            repo, remote = tmp / 'repo', tmp / 'remote.git'
            repo.mkdir()
            (repo / 'docs').mkdir()
            subprocess.run(['git', 'init', '--bare', str(remote)], check=True, capture_output=True)
            subprocess.run(['git', 'init', '-b', 'main', str(repo)], check=True, capture_output=True)
            git(repo, 'config', 'user.name', 'Offline test')
            git(repo, 'config', 'user.email', 'offline@example.invalid')
            status = repo / 'docs/status.json'
            status.write_text(json.dumps({'schema_version': 1, 'state': 'ok',
                                          'last_attempt_utc': '2026-10-27 06:03 UTC'}))
            data = repo / 'docs/data.json'
            data.write_text('old safe snapshot')
            git(repo, 'add', 'docs/status.json', 'docs/data.json')
            git(repo, 'commit', '-m', 'initial')
            git(repo, 'remote', 'add', 'origin', str(remote))
            git(repo, 'push', '-u', 'origin', 'main')
            data.write_text('unreviewed private contents - must never sync')
            status.write_text(json.dumps({'schema_version': 1, 'state': 'degraded',
                                          'last_attempt_utc': '2026-10-27 22:01 UTC'}))
            script = (ROOT / 'github-sync.sh').read_text().replace(
                'REPO=/root/.config/soc-orchestrator', f'REPO={repo}').replace(
                'exec 8>/run/soc-github-sync.lock', f'exec 8>{tmp / "lock"}').replace(
                "b=Path('/root/.config/soc-orchestrator')", f"b=Path('{repo}')")
            local_script = tmp / 'sync.sh'
            local_script.write_text(script)
            result = subprocess.run(['bash', str(local_script), '--status-only'],
                                    capture_output=True, text=True, timeout=20,
                                    env={**os.environ, 'GIT_TERMINAL_PROMPT': '0'})
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('degraded', git(repo, 'show', 'HEAD:docs/status.json'))
            self.assertEqual(git(repo, 'show', 'HEAD:docs/data.json'), 'old safe snapshot')
            self.assertEqual(git(remote, 'show', 'main:docs/data.json'), 'old safe snapshot')
            self.assertIn('docs/data.json', git(repo, 'status', '--short'))

    def test_remote_advance_refuses_publish_without_discarding_local_snapshot(self):
        with tempfile.TemporaryDirectory() as folder:
            tmp = Path(folder)
            repo, remote, upstream = tmp / 'repo', tmp / 'remote.git', tmp / 'upstream'
            repo.mkdir()
            (repo / 'docs').mkdir()
            subprocess.run(['git', 'init', '--bare', '--initial-branch=main', str(remote)], check=True, capture_output=True)
            subprocess.run(['git', 'init', '-b', 'main', str(repo)], check=True, capture_output=True)
            git(repo, 'config', 'user.name', 'Offline test')
            git(repo, 'config', 'user.email', 'offline@example.invalid')
            fixture = {
                'generated': '2026-11-13 22:01 UTC',
                'wazuh': {'total_7d': 0, 'top_src': [], 'by_day': [], 'by_agent': [], 'source_context': {},
                          'pipeline_24h_coverage': {'bucket_limit': 500, 'outside_top_alerts': None,
                            'approx_source_values': None, 'measured_at_utc': None}},
                'misp': {'total': 0, 'cidrs': [], 'recent_14d': [], 'membership_scope': 'fixture',
                         'top_source_membership': {}},
                'vt': {'posted_total': 0}, 'health': {'agents_down': 'withheld'}, 'runs': [],
                'blocklist_n': 0, 'enrich_meta': {},
            }
            data, status = repo / 'docs/data.json', repo / 'docs/status.json'
            data.write_text(json.dumps(fixture) + '\n')
            status.write_text(json.dumps({'schema_version': 1, 'state': 'ok',
                                          'last_attempt_utc': '2026-11-13 22:01 UTC'}))
            (repo / 'docs/blocklist.txt').write_text('# fixture, review only\n')
            (repo / 'config.yaml').write_text('sensor_public_ips: {}\n')
            (repo / 'README.md').write_text('initial\n')
            git(repo, 'add', 'README.md', 'docs')
            git(repo, 'commit', '-m', 'initial')
            git(repo, 'remote', 'add', 'origin', str(remote))
            git(repo, 'push', '-u', 'origin', 'main')
            original_head = git(repo, 'rev-parse', 'HEAD')
            subprocess.run(['git', 'clone', '--quiet', str(remote), str(upstream)], check=True)
            git(upstream, 'config', 'user.name', 'Offline upstream')
            git(upstream, 'config', 'user.email', 'upstream@example.invalid')
            (upstream / 'README.md').write_text('reviewed upstream change\n')
            git(upstream, 'add', 'README.md')
            git(upstream, 'commit', '-m', 'advance upstream')
            git(upstream, 'push', 'origin', 'main')
            remote_head = git(remote, 'rev-parse', 'main')
            data.write_text(json.dumps(fixture, indent=2) + '\n')
            local_data = data.read_text()
            status.write_text(json.dumps({'schema_version': 1, 'state': 'degraded',
                                          'last_attempt_utc': '2026-11-13 22:01 UTC'}))
            local_status = status.read_text()
            script = (ROOT / 'github-sync.sh').read_text().replace(
                'REPO=/root/.config/soc-orchestrator', f'REPO={repo}').replace(
                'exec 8>/run/soc-github-sync.lock', f'exec 8>{tmp / "lock"}').replace(
                "b=Path('/root/.config/soc-orchestrator')", f"b=Path('{repo}')")
            local_script = tmp / 'sync.sh'
            local_script.write_text(script)
            result = subprocess.run(['bash', str(local_script)], capture_output=True, text=True, timeout=20,
                                    env={**os.environ, 'GIT_TERMINAL_PROMPT': '0'})
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('public docs privacy gate passed', result.stdout)
            self.assertIn('local and origin/main differ', result.stderr)
            self.assertEqual(git(repo, 'rev-parse', 'HEAD'), original_head)
            self.assertEqual(git(remote, 'rev-parse', 'main'), remote_head)
            self.assertEqual(data.read_text(), local_data)
            self.assertEqual(status.read_text(), local_status)
            self.assertEqual(git(repo, 'diff', '--cached', '--name-only'), '')


if __name__ == '__main__':
    unittest.main()
