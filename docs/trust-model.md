# Trust model

## What "trusted" means

`trusted` means Securock's active policy did not fail the artifact.

The default policy requires that OSV was queried and returned no
known vulnerabilities. Unchecked vulnerabilities (`state: unknown`)
are `unknown`, not `trusted`. Digest, provenance, and signature checks
are optional policy rules and are off by default.

`trusted` is not a guarantee that a package is safe, authentic, or
free of malicious behavior.

Policy files are fail-closed: unknown fields, versions, and network
modes are errors. Typos such as `require_provenace` do not silently
disable a rule.

## What "untrusted" means

The artifact failed at least one enabled policy rule. Typical reasons:

- known vulnerabilities
- missing digest, when required
- provenance not verified, when required
- signature not verified, when required

## What "unknown" means

Securock could not complete an evidence lookup, or the ecosystem does
not yet expose that evidence. Unknown is not the same as verified.

## Evidence states

| State | Meaning |
| --- | --- |
| `unknown` | lookup skipped or failed |
| `missing` | lookup succeeded and found no evidence |
| `present` | registry returned provenance or signatures; not cryptographically verified |
| `verified` | cryptographic verification succeeded |

v0.1 npm collection can emit `present`, never `verified`. `verified`
is reserved for Sigstore and registry-key verification.

Offline scans leave provenance, signature, and vulnerability state
as `unknown`. That is not a clean bill of health.

Private registries are not queried in the default `public-only`
network mode. See [Privacy](privacy.md).

## Evidence Securock records

| Evidence | npm / pnpm | cargo / go / pypi |
| --- | --- | --- |
| digest | from the language lockfile | from the language lockfile |
| vulnerabilities | OSV ids | OSV ids |
| provenance | npm provenance attestation present | `unknown` |
| signature | npm `dist.signatures` present | `unknown` |

v0.1 records presence only. It does not perform full Sigstore or
registry-key cryptographic verification, so it will not emit
`verified`.

## What Securock does not guarantee

- that a trusted package is benign
- that a version bump is a security fix
- that transitive behavior is reachable or exploitable
- that GitHub, npm, or OSV are uncompromised
- that experimental ecosystems have the same evidence quality as npm
