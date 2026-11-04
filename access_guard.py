"""Offline identity-access and cloud configuration review using explicit snapshot evidence."""
import argparse
from datetime import datetime, timezone
import hashlib
import html
import json
from pathlib import Path

def date(value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError('dates must be nonempty ISO timestamp strings with a timezone')
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.tzinfo is None: raise ValueError('dates require a timezone')
    return parsed.astimezone(timezone.utc)

def validate(data):
    if not isinstance(data, dict): raise ValueError('snapshot must be an object')
    for key in ('users', 'roles', 'resources'):
        if not isinstance(data.get(key), list): raise ValueError(f'{key} must be an array')
        seen = set()
        for item in data[key]:
            if not isinstance(item, dict) or not isinstance(item.get('id'), str) or not item['id'].strip():
                raise ValueError(f'{key}: every entry requires a text ID')
            if item['id'] in seen: raise ValueError(f'{key}: duplicate ID')
            seen.add(item['id'])
    roles = {r['id'] for r in data['roles']}
    for role in data['roles']:
        permissions = role.get('permissions')
        if not isinstance(permissions, list) or not all(isinstance(p, str) and p for p in permissions):
            raise ValueError('permissions must be a list of strings')
    for user in data['users']:
        if user.get('status') not in ('active', 'disabled', 'terminated'): raise ValueError('invalid user status')
        if type(user.get('mfa')) is not bool: raise ValueError('mfa must be boolean')
        if not isinstance(user.get('roles'), list) or not all(isinstance(r, str) and r in roles for r in user['roles']):
            raise ValueError('unknown role reference')
        date(user['last_login'])
    for resource in data['resources']:
        for key in ('public', 'encrypted', 'logging'):
            if type(resource.get(key)) is not bool: raise ValueError(f'{key} must be boolean')
    return data

def audit(data, as_of, stale_days=90):
    validate(data)
    now = date(as_of)
    if stale_days < 1: raise ValueError('stale-days must be positive')
    findings = []
    def add(rule, entity, severity, evidence, action):
        findings.append(dict(id=hashlib.sha256(f'{rule}:{entity}'.encode()).hexdigest()[:20],
            rule=rule, entity=entity, severity=severity, evidence=evidence, remediation=action))
    roles = {r['id']: r for r in data['roles']}
    for role in roles.values():
        broad = [p for p in role['permissions'] if '*' in p]
        if broad: add('IAM-01', role['id'], 'high', {'wildcard_permissions': broad}, 'Replace wildcard grants with required actions and scope.')
    for user in data['users']:
        permissions = {p for r in user['roles'] for p in roles[r]['permissions']}
        age = (now - date(user['last_login'])).total_seconds() / 86400
        if age < 0: raise ValueError(f'{user["id"]}: last_login is after the audit date')
        if user['status'] == 'active' and not user['mfa']:
            add('IAM-02', user['id'], 'high', {'mfa': False}, 'Require MFA after validating account type and recovery procedure.')
        if user['status'] == 'active' and age >= stale_days:
            add('IAM-03', user['id'], 'medium', {'inactive_days': int(age)}, 'Ask the owner to recertify access or disable the unused account.')
        if user['status'] != 'active' and user['roles']:
            add('IAM-04', user['id'], 'high', {'status': user['status'], 'assigned_roles': user['roles']}, 'Review and remove residual entitlements through the approved workflow.')
        # Exact grants or global wildcard satisfy both sides; partial wildcards are separately flagged.
        if {'payment:create', 'payment:approve'} <= permissions or '*' in permissions:
            add('IAM-05', user['id'], 'critical', {'permissions': sorted(permissions)}, 'Separate payment creation and approval responsibilities.')
    for resource in data['resources']:
        for field, rule, severity, action in (
            ('public', 'CLOUD-01', 'high', 'Validate public exposure; restrict access if not required.'),
            ('encrypted', 'CLOUD-02', 'high', 'Enable approved encryption and review key access.'),
            ('logging', 'CLOUD-03', 'medium', 'Enable audit logging and define retention and review ownership.')):
            if resource[field] == (field == 'public'):
                add(rule, resource['id'], severity, {field: resource[field]}, action)
    findings.sort(key=lambda f: ({'critical': 0, 'high': 1, 'medium': 2}[f['severity']], f['rule'], f['entity']))
    canonical = json.dumps(data, sort_keys=True, separators=(',', ':')).encode()
    return dict(as_of=now.isoformat(), stale_days=stale_days, source_sha256=hashlib.sha256(canonical).hexdigest(),
                counts={s: sum(f['severity'] == s for f in findings) for s in ('critical', 'high', 'medium')},
                findings=findings, summary={'users': len(data['users']), 'roles': len(roles), 'resources': len(data['resources'])})

def compare(current, baseline):
    old = {f['id']: f for f in baseline['findings']}
    new = {f['id']: f for f in current['findings']}
    # Absence is not proof of remediation if an entity vanished from the input scope.
    return {'new': sorted(new.keys() - old.keys()), 'no_longer_observed': sorted(old.keys() - new.keys()),
            'persistent': sorted(old.keys() & new.keys()),
            'changed_evidence': sorted(k for k in old.keys() & new.keys() if old[k]['evidence'] != new[k]['evidence'])}

def write_report(result, folder):
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    (folder / 'audit.json').write_text(json.dumps(result, indent=2, sort_keys=True), encoding='utf-8')
    rows = ''.join('<tr>' + ''.join(f'<td>{html.escape(str(value))}</td>' for value in
        (f['rule'], f['severity'], f['entity'], json.dumps(f['evidence']), f['remediation'])) + '</tr>' for f in result['findings'])
    document = '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>AccessGuard audit</title><style>body{font:15px system-ui;color:#142b40;background:#f4f7fa;margin:40px}h1{font-size:40px}table{border-collapse:collapse;width:100%;background:white}td,th{text-align:left;padding:14px;border-bottom:1px solid #d9e1e9;overflow-wrap:anywhere}th{background:#163f50;color:white}.wrap{overflow-x:auto}code{overflow-wrap:anywhere}</style><h1>AccessGuard</h1><p>Identity access and cloud configuration review | '+html.escape(result['as_of'])+'</p><p>'+str(len(result['findings']))+' findings. Snapshot-based evidence; manual validation required.</p><div class="wrap"><table><thead><tr><th>Control</th><th>Severity</th><th>Entity</th><th>Evidence</th><th>Remediation</th></tr></thead><tbody>'+rows+'</tbody></table></div><p>Canonical source SHA-256: <code>'+result['source_sha256']+'</code></p><p>These are project-defined controls, not a regulatory compliance certification.</p></html>'
    (folder / 'report.html').write_text(document, encoding='utf-8')

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('snapshot')
    parser.add_argument('--as-of', required=True, help='ISO timestamp with timezone; explicit for reproducibility')
    parser.add_argument('--stale-days', type=int, default=90)
    parser.add_argument('--baseline')
    parser.add_argument('--output', default='report')
    args = parser.parse_args()
    try:
        data = json.loads(Path(args.snapshot).read_text(encoding='utf-8'))
        result = audit(data, args.as_of, args.stale_days)
        if args.baseline:
            result['comparison'] = compare(result, json.loads(Path(args.baseline).read_text(encoding='utf-8')))
        write_report(result, args.output)
        print(json.dumps(result['counts']))
    except (ValueError, KeyError, TypeError, OSError) as exc:
        parser.exit(2, f'Error: {exc}\n')

if __name__ == '__main__': main()
