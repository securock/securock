---
title: Trust model
description: What Securock means by trusted, untrusted, and unknown, and which evidence each ecosystem can collect under policy.
---

# Trust model

This page defines trust status and the evidence Securock records. For
configuration examples, see [Policy](/guide/policy). For per-ecosystem
depth, see [Ecosystems](/guide/ecosystems).

> Canonical source:
> [`docs/trust-model.md`](https://github.com/securock/securock/blob/main/docs/trust-model.md).

## What "trusted" means

`trusted` means the artifact passed the active policy. It is not a
guarantee that a package is safe, authentic, or free of malicious
behavior. The CLI prints this as `trusted (under active policy)`.

The default policy requires that OSV was queried and returned no known
vulnerabilities, and that malicious reports are clear. Unchecked
vulnerabilities (`state: unknown`) are `unknown`, not `trusted`.
Digest, provenance, signature, capability, and ownership checks are
optional policy rules and are off by default.

Policy files are fail-closed: unknown fields, versions, and network
modes are errors.

## What "untrusted" means

The artifact failed at least one enabled policy rule. Typical reasons:

- known vulnerabilities
- malicious package reports (`MAL-*`)
- missing digest, when required
- invalid or weak digest (sha1 / malformed), when `require_digest` is set
- provenance not verified, when required
- signature not verified, when required
- denied capability (shell, install scripts, …)
- filesystem access above the configured maximum

## What "unknown" means

Securock could not complete an evidence lookup, or the ecosystem does
not yet expose that evidence. Unknown is not the same as verified.

## Evidence states

| State      | Meaning                                                                    |
| ---------- | -------------------------------------------------------------------------- |
| `unknown`  | Lookup skipped or failed                                                   |
| `missing`  | Lookup succeeded and found no evidence                                     |
| `present`  | Registry returned provenance or signatures; not cryptographically verified |
| `verified` | Cryptographic verification succeeded                                       |

`require_provenance: true` accepts `present` or `verified`. To require
cryptographic verification:

```yaml
rules:
  provenance:
    minimum: verified
  signature:
    minimum: verified
```

Or use the built-in strict profile:

```bash
securock verify --profile strict
```

`strict` requires digests plus `provenance` / `signature` minimum
`verified`. Prefer `strict` on npm-heavy trees today.

## Evidence Securock records

| Evidence        | npm / pnpm / yarn / bun / deno npm                                          | PyPI (uv / Poetry / PDM)                                                             | All other ecosystems                     |
| --------------- | --------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ | ---------------------------------------- |
| digest          | from the language lockfile                                                  | from the language lockfile                                                           | from the language lockfile               |
| vulnerabilities | OSV ids (non-`MAL-`)                                                        | OSV ids when the source is proven public                                             | OSV ids when the source is proven public |
| malicious       | OpenSSF Malicious Packages via OSV `MAL-*`                                  | same, when OSV is queried                                                            | same, when OSV is queried                |
| provenance      | npm provenance; `verified` after Sigstore check + digest bind               | PEP 740 Integrity API; `verified` after Sigstore re-verify + filename/digest bind    | `unknown`                                |
| signature       | npm `dist.signatures`; `verified` after ECDSA check + digest bind           | same PEP 740 path as provenance                                                      | `unknown`                                |
| capabilities    | registry metadata + package source heuristics                               | `unknown`                                                                            | `unknown`                                |
| behavior        | hosts, file paths, commands, env vars from source heuristics                | `unknown`                                                                            | `unknown`                                |
| ownership       | npm publisher (`_npmUser`) and maintainers                                  | `unknown`                                                                            | `unknown`                                |
| chain           | source repo, commit, ref, builder, workflow, predicate type from provenance | Trusted Publisher + verified Sigstore identity (SAN) and predicate type from PEP 740 | `unknown`                                |

Malicious package reports are not vulnerabilities. A package with no
CVEs can still be malware. The default policy denies both.

Capability detection for npm uses install-script and native-build
metadata, then a deterministic scan of published JS/TS sources for
network, filesystem, environment, and shell indicators. It is not a
full behavioral sandbox and may under-report obfuscated code.

Trust chain evidence is extracted from npm provenance attestations
(SLSA predicates). Securock only accepts SLSA provenance predicate
types (`https://slsa.dev/provenance/v0.1`, `v0.2`, and `v1`) for
provenance evidence. Policy origin allowlists can further restrict
which source, builder, workflow, ref, and predicate type count as
trusted. Securock does not rebuild the artifact from source.

Deno JSR and HTTPS URL artifacts record integrity from `deno.lock`.
OSV does not cover those ecosystems yet, so vulnerability state stays
`unknown`.

Offline scans leave provenance, signature, capability, ownership,
behavior, chain, vulnerability, and malicious-report state as
`unknown`. That is not a clean bill of health.

Private registries are not queried in the default `public-only`
network mode. See [Privacy](/reference/privacy).

## What Securock does not guarantee

- that a trusted package is benign
- that a version bump is a security fix
- that transitive behavior is reachable or exploitable
- that GitHub, npm, or OSV are uncompromised
- that non-npm ecosystems collect provenance or signature evidence
- that capability heuristics catch every malicious behavior
- that a present trust chain proves the artifact was built from that source

## Next steps

- [Policy](/guide/policy) — encode these floors in YAML
- [Evidence](/guide/evidence) — operator-facing state guide
- [Threat model](/reference/threat-model) — what drift does and does not catch
