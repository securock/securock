# Security Policy

## Reporting a vulnerability

Please report security issues privately through GitHub Security Advisories
on [securock/securock](https://github.com/securock/securock/security/advisories/new).

Do not open a public issue for an unreleased vulnerability.

We aim to acknowledge reports within 5 business days.

## Supported versions

Only the latest tagged release is supported until v1.0.

## What Securock verifies about itself

Release artifacts are published with:

- `checksums.txt`
- SPDX SBOMs
- GitHub artifact attestations

Consumers can verify a binary with:

```bash
gh attestation verify ./securock --repo securock/securock
```

`scripts/install.sh` checks the published SHA-256 before install. If `gh`
is available, it also verifies the GitHub attestation.
