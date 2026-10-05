# Evidence

| State | Meaning |
| --- | --- |
| `unknown` | Lookup skipped or failed. |
| `missing` | Lookup succeeded and found nothing. |
| `present` | Registry returned provenance or signatures. Not cryptographically verified. |
| `verified` | Reserved for future Sigstore / registry-key verification. |

v0.1 records presence only. It will not emit `verified`.

Vulnerability lookups have their own state:

| State | Meaning |
| --- | --- |
| `unknown` | OSV was not queried (offline, private registry, or error). |
| `checked` | OSV was queried; `items` is the ID list. |

Capability evidence uses the same `unknown` / `checked` states. For npm,
Securock records install scripts and native code hints from the registry,
then scans published package sources for network, filesystem, environment,
and shell indicators.

Default policy treats `unknown` as unknown trust, not trusted.

See [Privacy](https://github.com/securock/securock/blob/main/docs/privacy.md) for what is sent off-machine.
