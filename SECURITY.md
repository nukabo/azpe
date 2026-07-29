# Security policy

AZPE takes the security of its diagnostic utility and release distribution pipelines seriously.

---

## Supported versions

| Version | Supported |
| ------- | --------- |
| `v0.1.x` | :white_check_mark: |
| `< 0.1.0` | :x: |

---

## Reporting a vulnerability

> [!IMPORTANT]
> If you discover a potential security vulnerability in AZPE, **please do not report it publicly** via GitHub Issues or public discussions.

Instead, please send an email describing the vulnerability to the project maintainers. Include step-by-step details on how to reproduce the issue and any potential impact.

Maintainers will review the report and respond within 48 hours.

---

## Security design principles

- **Zero credentials**: AZPE never asks for, stores, or handles Azure credentials, tokens, or login keys.
- **System trust store enforcement**: Certificate validation is strictly enforced against system CAs (`InsecureSkipVerify: false`).
- **Query parameter value redaction**: Terminal and JSON outputs automatically redact query parameter values (e.g. `/path?sig=REDACTED`).
- **Zero security policy bypass**: The PowerShell client operates strictly within enterprise application controls without execution policy or AMSI bypasses.
