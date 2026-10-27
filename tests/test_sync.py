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


if __name__ == '__main__':
    unittest.main()
