"""End-to-end CLI checks using isolated files and actual subprocesses."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent
class CLITests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.data = json.loads((ROOT/'samples/snapshot.json').read_text())
        self.input = self.root/'snapshot.json'

    def run_cli(self, extra=(), expected=0):
        self.input.write_text(json.dumps(self.data), encoding='utf-8')
        result = subprocess.run([sys.executable, str(ROOT/'access_guard.py'), str(self.input),
            '--as-of', '2026-11-04T00:00:00Z', '--output', str(self.root/'report'), *extra], capture_output=True, text=True)
        self.assertEqual(result.returncode, expected, result.stderr)
        self.assertNotIn('Traceback', result.stderr)
        return result

    def test_demo_and_repeat(self):
        self.assertEqual(json.loads(self.run_cli().stdout), {'critical':1,'high':5,'medium':2})
        before = (self.root/'report/audit.json').read_bytes()
        self.run_cli()
        self.assertEqual(before, (self.root/'report/audit.json').read_bytes())

    def test_empty_snapshot(self):
        self.data = dict(users=[],roles=[],resources=[])
        self.assertEqual(json.loads(self.run_cli().stdout), {'critical':0,'high':0,'medium':0})

    def test_null_date(self):
        self.data['users'][0]['last_login'] = None
        self.run_cli(expected=2)

    def test_missing_date(self):
        del self.data['users'][0]['last_login']
        self.run_cli(expected=2)

    def test_bad_baselines(self):
        baseline = self.root/'baseline.json'
        for value in (None, [], {}, {'findings':[None]}, {'findings':[{'id':[]}]}):
            with self.subTest(value=value):
                baseline.write_text(json.dumps(value))
                self.run_cli(('--baseline', str(baseline)), expected=2)

    def test_remediation_comparison(self):
        self.run_cli()
        baseline = self.root/'baseline.json'
        baseline.write_bytes((self.root/'report/audit.json').read_bytes())
        self.data['users'][0]['mfa'] = True
        self.run_cli(('--baseline',str(baseline)))
        result=json.loads((self.root/'report/audit.json').read_text())
        self.assertEqual(len(result['comparison']['no_longer_observed']),1)
        self.assertEqual(len(result['comparison']['persistent']),7)

    def test_bad_threshold(self): self.run_cli(('--stale-days','0'),expected=2)

    def test_output_is_file(self):
        (self.root/'report').write_text('occupied')
        self.run_cli(expected=2)

if __name__ == '__main__': unittest.main()
