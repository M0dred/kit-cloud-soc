"""Run a fixture-only cron wrapper: no network, MISP, VT, Git or Telegram calls."""
import json
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class CronHealthIntegrationTests(unittest.TestCase):
    def test_persistent_hard_outage_never_turns_green_before_recovery(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            (base / 'docs').mkdir()
            data = base / 'docs/data.json'
            data.write_text('LAST_SAFE_SNAPSHOT')
            (base / 'agent-status.json').write_text(json.dumps({'fixture-server': 'active'}))
            current = base / 'fixture-agent-states.json'
            current.write_text(json.dumps({'fixture-server': 'disconnected'}))

            for name in ('orchestrator.py', 'hunt.py', 'ndr-cli.py', 'ndr-cross.py',
                         'vt_comment_new.py', 'backup-health.py'):
                (base / name).write_text('print("offline fixture OK")\n')
            (base / 'dashboard-gen.py').write_text(
                f'from pathlib import Path\nPath({str(data)!r}).write_text("FRESH_FIXTURE_SNAPSHOT")\n')
            status = base / 'docs/status.json'
            (base / 'public-status.py').write_text(
                f'import json,sys\nfrom pathlib import Path\nPath({str(status)!r}).write_text(json.dumps({{"state":sys.argv[2]}}))\n')
            (base / 'health-check.py').write_text(f'''\
import importlib.util,json
from pathlib import Path
spec=importlib.util.spec_from_file_location("health_fixture", {str(ROOT / 'health-check.py')!r})
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
m.STATE=Path({str(base / 'agent-status.json')!r})
m.SOFT_AGENTS={{"fixture-laptop"}}
m._cfg=lambda: "synthetic"
m._grab=lambda text,key: "synthetic"
m.indexer_facts=lambda user,password: (20,"2026-11-06T06:00:00Z",0.1)
m.agent_states=lambda user,password: json.loads(Path({str(current)!r}).read_text())
m.main()
''')
            mode_log = base / 'sync-modes.txt'
            (base / 'github-sync.sh').write_text(
                f'#!/bin/bash\nprintf "%s\\n" "${{1:-full}}" >> {shlex.quote(str(mode_log))}\n')

            script = (ROOT / 'cron-run.sh').read_text()
            replacements = {
                '/run/soc-orchestrator.lock': str(base / 'cron.lock'),
                '/root/.config/agents/skills/soc-connector/scripts/soc-orchestrator.py': str(base / 'orchestrator.py'),
                '/root/.config/agents/skills/linux-log-threat-hunt/scripts/analyze-logs.py': str(base / 'hunt.py'),
                '/root/.config/agents/skills/soc-connector/scripts/ndr-cli.py': str(base / 'ndr-cli.py'),
                '/root/.config/soc-orchestrator': str(base),
                "if ! timeout 5 bash -c 'echo >/dev/tcp/10.0.1.1/9200'; then": 'if ! true; then',
                'notify_fail() {\n': 'notify_fail() {\n  return 0 # offline fixture; never send Telegram\n',
            }
            for original, replacement in replacements.items():
                self.assertIn(original, script, f'cron fixture replacement no longer valid: {original}')
                script = script.replace(original, replacement)
            local_script = base / 'cron-run.sh'
            local_script.write_text(script)

            def run():
                return subprocess.run(['bash', str(local_script)], capture_output=True, text=True, timeout=20)

            for _ in range(2):
                result = run()
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(json.loads(status.read_text())['state'], 'degraded')
                self.assertEqual(data.read_text(), 'LAST_SAFE_SNAPSHOT')
            self.assertEqual(mode_log.read_text().splitlines(), ['--status-only', '--status-only'])
            current.write_text(json.dumps({}))  # prior hard agent not returned by fixture API
            for _ in range(2):
                result = run()
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(json.loads(status.read_text())['state'], 'degraded')
                self.assertEqual(data.read_text(), 'LAST_SAFE_SNAPSHOT')
            current.write_text(json.dumps({'fixture-server': 'active'}))
            result = run()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(status.read_text())['state'], 'ok')
            self.assertEqual(data.read_text(), 'FRESH_FIXTURE_SNAPSHOT')
            self.assertEqual(mode_log.read_text().splitlines(), ['--status-only'] * 4 + ['full'])


if __name__ == '__main__':
    unittest.main()
