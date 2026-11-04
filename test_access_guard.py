import copy
import tempfile
from pathlib import Path
import unittest
from access_guard import audit, compare, write_report

NOW = '2026-11-04T00:00:00Z'
def clean():
    return dict(users=[dict(id='alice', status='active', mfa=True, roles=['reader'], last_login=NOW)],
                roles=[dict(id='reader', permissions=['document:read'])],
                resources=[dict(id='store', public=False, encrypted=True, logging=True)])

class AuditTests(unittest.TestCase):
    def test_clean(self): self.assertEqual(audit(clean(), NOW)['findings'], [])

    def test_all_controls(self):
        data = clean()
        data['roles'][0]['permissions'] = ['*']
        data['users'][0].update(mfa=False, last_login='2026-01-01T00:00:00Z')
        data['users'].append(dict(id='former', status='terminated', mfa=True, roles=['reader'], last_login=NOW))
        data['resources'][0].update(public=True, encrypted=False, logging=False)
        self.assertEqual({f['rule'] for f in audit(data, NOW)['findings']},
                         {'IAM-01','IAM-02','IAM-03','IAM-04','IAM-05','CLOUD-01','CLOUD-02','CLOUD-03'})

    def test_separation_across_roles(self):
        data = clean()
        data['roles'] = [dict(id='maker', permissions=['payment:create']), dict(id='checker', permissions=['payment:approve'])]
        data['users'][0]['roles'] = ['maker', 'checker']
        self.assertEqual(audit(data, NOW)['findings'][0]['rule'], 'IAM-05')

    def test_invalid_role(self):
        data = clean(); data['users'][0]['roles'] = ['missing']
        with self.assertRaises(ValueError): audit(data, NOW)

    def test_duplicate_id(self):
        data = clean(); data['users'].append(copy.deepcopy(data['users'][0]))
        with self.assertRaises(ValueError): audit(data, NOW)

    def test_reject_string_boolean(self):
        data = clean(); data['users'][0]['mfa'] = 'false'
        with self.assertRaises(ValueError): audit(data, NOW)

    def test_future_login(self):
        data = clean(); data['users'][0]['last_login'] = '2027-01-01T00:00:00Z'
        with self.assertRaises(ValueError): audit(data, NOW)

    def test_timezone_required(self):
        with self.assertRaises(ValueError): audit(clean(), '2026-11-04')

    def test_stale_boundary(self):
        data = clean(); data['users'][0]['last_login'] = '2026-11-03T00:00:00Z'
        self.assertEqual(audit(data, NOW, stale_days=1)['findings'][0]['rule'], 'IAM-03')

    def test_baseline_comparison(self):
        data = clean(); data['users'][0]['mfa'] = False
        old = audit(data, NOW)
        delta = compare(audit(clean(), NOW), old)
        self.assertEqual(len(delta['no_longer_observed']), 1)
        self.assertFalse(delta['new'])

    def test_deterministic_evidence(self):
        self.assertEqual(audit(clean(), NOW), audit(clean(), NOW))

    def test_html_escaping(self):
        data = clean(); data['resources'][0].update(id='<script>bad</script>', public=True)
        with tempfile.TemporaryDirectory() as tmp:
            write_report(audit(data, NOW), tmp)
            self.assertNotIn('<script>', (Path(tmp) / 'report.html').read_text())

if __name__ == '__main__': unittest.main()
