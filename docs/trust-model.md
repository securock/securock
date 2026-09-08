# Trust model

## What "trusted" means

`trusted` means Securock's active policy did not fail the artifact.

The default policy requires that OSV returned no known vulnerabilities.
Digest, provenance, and signature checks are optional policy rules and
are off by default.

`trusted` is not a guarantee that a package is safe, authentic, or
free of malicious behavior.

## What "untrusted" means

The artifact failed at least one enabled policy rule. Typical reasons:

- known vulnerabilities
- missing digest, when required
- provenance not verified, when required
- signature not verified, when required

## What "unknown" means

Securock could not complete an evidence lookup, or the ecosystem does
not yet expose that evidence. Unknown is not the same as verified.

Offline scans leave provenance and signature as `unknown`.

## Evidence Securock records

| Evidence | npm / pnpm | cargo / go / pypi |
| --- | --- | --- |
| digest | from the language lockfile | from the language lockfile |
| vulnerabilities | OSV ids | OSV ids |
| provenance | presence of an npm provenance attestation | `unknown` |
| signature | presence of npm `dist.signatures` | `unknown` |

For npm provenance and signatures, v0.1 records that the registry
returned the evidence. It does not yet perform full Sigstore or
registry-key cryptographic verification.

## What Securock does not guarantee

- that a trusted package is benign
- that a version bump is a security fix
- that transitive behavior is reachable or exploitable
- that GitHub, npm, or OSV are uncompromised
- that experimental ecosystems have the same evidence quality as npm
