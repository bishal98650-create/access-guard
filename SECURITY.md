# Security model

This is an offline portfolio lab. Use synthetic fixtures first. No network scanning, credential collection, cloud modification, or automatic remediation occurs. Source snapshots can contain sensitive identifiers: store real inputs, SQLite databases and generated reports outside public repositories. The included samples contain invented users and documentation-only IP addresses.

The local operating-system account is the trust boundary. There is no authentication or multi-user authorization layer. Anyone with write access to the database or input files can alter evidence. SHA-256 detects accidental changes only when compared with a separately trusted digest; it is not a digital signature or tamper-proof chain of custody. HTML reports escape untrusted fields, and reports load no remote resources.

Limits: inputs are processed in memory, so use bounded trusted exports; maliciously large files can exhaust memory. Do not host these tools as a public service without upload limits, authentication, authorization, encryption, retention rules and independent review. Findings require human validation and do not establish a breach or legal compliance.
