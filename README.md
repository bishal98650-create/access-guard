# AccessGuard — Identity Access & Cloud Controls Review

A Python portfolio project for evidence-based access reviews. It evaluates an offline snapshot of identities, role permissions and cloud resource settings, generates prioritized remediation findings, and compares audits over time. Built in November 2026; Python standard library only.

## Run the complete demo

Requires Python 3.10 or later. From this repository directory:

```sh
python -m unittest discover -v
python access_guard.py samples/snapshot.json --as-of 2026-11-04T00:00:00Z --output report
```

Open `report/report.html`. The deliberately insecure synthetic snapshot produces eight findings: one critical, five high, two medium. Save the generated `audit.json` elsewhere as a baseline, correct sample settings in a copy, then run:

```sh
python access_guard.py corrected-snapshot.json --as-of 2026-11-04T00:00:00Z --baseline baseline.json --output comparison
```

`comparison/audit.json` lists new, persistent, changed-evidence and no-longer-observed findings. Disappearance is not labelled “resolved”: an entity might simply have been removed from the export. Confirm equivalent scope before claiming remediation.

## Architecture and data contract

```text
JSON snapshot -> schema and reference validation -> eight deterministic controls
                                                   |
                                      prioritized findings + source digest
                                                   |
                                       baseline comparison + HTML/JSON
```

The top-level object requires `users`, `roles`, `resources` arrays. IDs must be unique within each collection. Users require status (`active`, `disabled`, `terminated`), boolean MFA, role IDs and timezone-aware last_login. Roles contain permission strings. Resources contain boolean public/encrypted/logging flags. Missing fields, strings used as booleans, duplicate IDs and unknown role references reject the audit. Future last-login timestamps are rejected. An explicit audit time makes inactivity calculations reproducible.

## Control catalogue

| Control | Finding | Severity |
|---|---|---|
| IAM-01 | Role contains wildcard permission | High |
| IAM-02 | Active user lacks MFA | High |
| IAM-03 | Active account unused for at least 90 days (configurable) | Medium |
| IAM-04 | Disabled/terminated identity retains role assignments | High |
| IAM-05 | Same identity can create and approve payments | Critical |
| CLOUD-01 | Resource marked publicly accessible | High |
| CLOUD-02 | Resource encryption disabled | High |
| CLOUD-03 | Resource audit logging disabled | Medium |

The segregation-of-duties check combines permissions across roles. Exact payment grants and a global `*` are evaluated; provider-specific conditional permissions, partial wildcard expansion, deny precedence and nested groups are not modelled. All wildcard grants are separately flagged. Public resources may be intentional and non-human accounts may need alternative authentication controls. Human reviewers must evaluate these cases.

## Evidence and prioritization

Every finding has a deterministic control/entity ID, severity, observed evidence and recommended action. Critical findings appear first; severity is a project-defined prioritization scheme, not CVSS. The source SHA-256 is calculated over canonical JSON, so whitespace changes do not change it. Array ordering does affect the digest. Keep original exports separately when byte-level preservation matters.

These are custom technical controls, not certified mappings to an external regulatory framework. The tool supports compliance preparation by organizing evidence; it does not certify compliance. It does not connect to AWS/Azure, retrieve real identities, change permissions, detect software CVEs, run penetration tests or predict fraud.

## Testing and operational limits

Tests cover all eight controls, clean data, combined-role conflicts, duplicate IDs, unknown references, strict booleans, date errors, threshold boundaries, baseline changes, reproducibility and HTML escaping. CI is configured for Windows/Linux and Python 3.10/3.12; verify hosted runs after publication. No production performance or security certification is claimed. Review [SECURITY.md](SECURITY.md) before using real data.

## Interview walkthrough

1. Show why disabling an account and removing its access are separate checks.
2. Explain why two individually acceptable roles can create a payment conflict.
3. Trace a finding to the exact snapshot evidence and proposed remediation.
4. Correct MFA and encryption in a copied fixture and compare findings.
5. Explain why missing findings do not automatically prove remediation.
6. Discuss future provider adapters, permission evaluation, exception expiry and reviewer sign-off.

Development assistance: created with AI-assisted implementation. Run and understand the scenarios, validate the assumptions and extend the code before representing it as independent experience.
