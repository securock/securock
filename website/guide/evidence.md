---
title: Evidence
description: How Securock records provenance, signature, vulnerability, malicious-package, capability, behavior, ownership, and trust-chain evidence states.
---

# Evidence

Securock stores evidence on each artifact in `securock.lock`. Reading
those states correctly is how you decide whether a package is trusted
under policy, merely unchecked, or actively failing a rule.

`trusted` still means “passed the active policy,” not “proven safe.”
See the [Trust model](/reference/trust-model) for the full matrix.

## Provenance, signature, and chain states

| State      | Meaning                                                                                     |
| ---------- | ------------------------------------------------------------------------------------------- |
| `unknown`  | Lookup skipped or failed.                                                                   |
| `missing`  | Lookup succeeded and found nothing.                                                         |
| `present`  | Registry returned provenance, signatures, or a trust chain. Not cryptographically verified. |
| `verified` | Cryptographic verification succeeded and the subject digest matches the lockfile.           |

Provenance, signature, and chain use these states. npm evidence can
reach `verified` when registry keys / Sigstore roots are available and
the locked digest binds to the signed artifact.

How to read them:

- **`unknown`** — do not treat as clean. Offline mode and private
  registries leave many axes here.
- **`missing`** — Securock looked and found no attestation or signature.
- **`present`** — material exists but was not cryptographically verified
  (or verification did not bind the digest).
- **`verified`** — crypto check succeeded and matches the lockfile digest.

`require_provenance: true` accepts `present` or `verified`. To require
cryptographic verification, set `minimum: verified` under policy (or use
`--profile strict`). See [Policy](/guide/policy).

## Vulnerability and malicious states

| State     | Meaning                                                               |
| --------- | --------------------------------------------------------------------- |
| `unknown` | OSV was not queried (offline, private registry, or error).            |
| `checked` | OSV was queried. Vulns use `items`; malware uses `reports` (`MAL-*`). |

Malicious package reports are **not** vulnerabilities. A package with
no CVEs can still be malware. The default policy denies both.

Default policy treats `unknown` as unknown trust, **not** trusted.

## Capability, behavior, and ownership

Capability, behavior, and ownership use the same `unknown` / `checked`
states. Depth depends on the [ecosystem](/guide/ecosystems).

### npm family (npm / pnpm / Yarn / Bun / Deno npm)

Securock records:

- install scripts and native-code hints from the registry
- publisher and maintainers
- network, filesystem, environment, and shell indicators from published
  package sources
- finer-grained hosts, paths, commands, and env vars as `behavior`
- source → build → artifact fields from provenance attestations as
  `chain` (source, commit, ref, builder, workflow, predicate type)

Capability detection uses install-script and native-build metadata, then
a deterministic scan of published JS/TS sources. It is not a full
behavioral sandbox and may under-report obfuscated code.

Provenance verification for npm only accepts SLSA predicate types
(`https://slsa.dev/provenance/v0.1`, `v0.2`, and `v1`). Policy can
further limit accepted sources, builders, workflows, refs, and
predicate types via `allow_*` lists under `rules.provenance`; those
lists require a verified trust chain.

### PyPI (uv / Poetry / PDM)

Securock queries the Integrity API, reconstructs each PEP 740
attestation into a Sigstore bundle, and re-verifies it against the
public-good trust root (signer identity, artifact filename and digest,
DSSE signature, transparency log). A successful check records
provenance/signature `verified` with Trusted Publisher and certificate
identity on the chain; otherwise attestations remain `present`.

### Other ecosystems

Digest comes from the language lockfile. OSV runs when
`public-only` can prove a public origin. Provenance, signature,
capability, behavior, ownership, and chain usually stay `unknown`.

## Offline and private registries

`--offline` leaves remote evidence `unknown`. Private registries are
not queried in the default `public-only` network mode. Details:
[Privacy](/reference/privacy).

## Next steps

- [Policy](/guide/policy) — require floors and allowlists
- [Ecosystems](/guide/ecosystems) — where each evidence axis is collected
- [Trust model](/reference/trust-model) — trusted / untrusted / unknown
