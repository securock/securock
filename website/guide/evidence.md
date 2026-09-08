# Evidence

| State | Meaning |
| --- | --- |
| `unknown` | Lookup skipped or failed. |
| `missing` | Lookup succeeded and found nothing. |
| `present` | Registry returned provenance or signatures. Not cryptographically verified. |
| `verified` | Reserved for future Sigstore / registry-key verification. |

v0.1 records presence only. It will not emit `verified`.
