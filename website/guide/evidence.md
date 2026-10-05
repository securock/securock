# Evidence

| State | Meaning |
| --- | --- |
| `unknown` | Lookup skipped or failed. |
| `missing` | Lookup succeeded and found nothing. |
| `present` | Registry returned provenance, signatures, or a trust chain. Not cryptographically verified. |
| `verified` | Cryptographic verification succeeded (registry ECDSA signature or Sigstore provenance) and the subject digest matches the lockfile. |

Provenance, signature, and chain use these states. npm evidence can
reach `verified` when registry keys / Sigstore roots are available and
the locked digest binds to the signed artifact.

Vulnerability and malicious-package lookups have their own state:

| State | Meaning |
| --- | --- |
| `unknown` | OSV was not queried (offline, private registry, or error). |
| `checked` | OSV was queried. Vulns use `items`; malware uses `reports` (`MAL-*`). |

Capability, behavior, and ownership evidence use the same `unknown` /
`checked` states. For npm, Securock records:

- install scripts and native-code hints from the registry
- publisher and maintainers
- network, filesystem, environment, and shell indicators from published
  package sources
- finer-grained hosts, paths, commands, and env vars as `behavior`
- source → build → artifact fields from provenance attestations as `chain`

Malicious package reports are not vulnerabilities. A package with no
CVEs can still be malware. The default policy denies both.

Default policy treats `unknown` as unknown trust, not trusted.

See [Privacy](https://github.com/securock/securock/blob/main/docs/privacy.md) for what is sent off-machine.
See [Trust model](https://github.com/securock/securock/blob/main/docs/trust-model.md) for the full evidence matrix.
