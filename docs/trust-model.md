# Trust model

## What "trusted" means

`trusted` means the artifact passed the active policy. It is not a
guarantee that a package is safe, authentic, or free of malicious
behavior. The CLI prints this as `trusted (under active policy)`.

The default policy requires that OSV was queried and returned no
known vulnerabilities. Unchecked vulnerabilities (`state: unknown`)
are `unknown`, not `trusted`. Digest, provenance, signature,
capability, and ownership checks are optional policy rules and are off
by default.

Policy files are fail-closed: unknown fields, versions, and network
modes are errors. Typos such as `require_provenace` do not silently
disable a rule.

Example capability and ownership gates:

```yaml
version: 1
rules:
  require_no_vulnerabilities: true
  capabilities:
    deny:
      - shell
      - native_code
      - install_scripts
    filesystem:
      maximum: read
  ownership:
    publisher_change: deny
    maintainer_added: warn
    maintainer_removed: review
```

`deny` and `review` fail `verify`. `warn` is reported but does not fail.
When ownership rules are omitted, any ownership change remains trust
drift. When any ownership action is set, unset actions default to
`deny` (fail-closed).

## What "untrusted" means

The artifact failed at least one enabled policy rule. Typical reasons:

- known vulnerabilities
- malicious package reports (`MAL-*`)
- missing digest, when required
- provenance not verified, when required
- signature not verified, when required
- denied capability (shell, install scripts, …)
- filesystem access above the configured maximum

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

`require_provenance: true` accepts `present` or `verified`. To require
cryptographic verification:

```yaml
rules:
  provenance:
    minimum: verified
  signature:
    minimum: verified
```

To also require that verified provenance came from an expected origin:

```yaml
rules:
  provenance:
    minimum: verified
    allow_sources:
      - github.com/acme/pkg
    allow_builders:
      - https://github.com/actions/runner
    allow_workflows:
      - release.yml
    allow_refs:
      - refs/heads/main
    allow_predicate_types:
      - https://slsa.dev/provenance/v1
```

Empty allowlists are ignored. When any origin allowlist is set, Securock
requires a cryptographically verified trust chain and fails artifacts
whose chain fields do not match. Offline scans leave chain evidence
`unknown`, so origin allowlists surface as `unknown` rather than
trusted.

Or use the built-in strict profile:

```bash
securock verify --profile strict
```

`strict` requires digests plus `provenance` / `signature` minimum
`verified`. It is mutually exclusive with `--policy`.

npm collection verifies registry ECDSA signatures against
`/-/npm/v1/keys` and Sigstore provenance bundles against the public-good
trusted root. Both require the lockfile digest to match the signed
artifact before emitting `verified`.

Offline scans leave provenance, signature, capability, ownership,
behavior, chain, vulnerability, and malicious-report state as
`unknown`. That is not a clean bill of health.

Private registries are not queried in the default `public-only`
network mode. See [Privacy](privacy.md).

## Evidence Securock records

| Evidence | npm / pnpm / yarn / bun / deno npm | all other ecosystems |
| --- | --- | --- |
| digest | from the language lockfile | from the language lockfile |
| vulnerabilities | OSV ids (non-`MAL-`) | OSV ids when the source is proven public |
| malicious | OpenSSF Malicious Packages via OSV `MAL-*` | same, when OSV is queried |
| provenance | npm provenance attestation present; `verified` after Sigstore check + digest bind | `unknown` |
| signature | npm `dist.signatures` present; `verified` after ECDSA check + digest bind | `unknown` |
| capabilities | registry metadata + package source heuristics | `unknown` |
| behavior | hosts, file paths, commands, env vars from source heuristics | `unknown` |
| ownership | npm publisher (`_npmUser`) and maintainers | `unknown` |
| chain | source repo, commit, ref, builder, workflow, predicate type from provenance attestations | `unknown` |

Malicious package reports are not vulnerabilities. A package with no
CVEs can still be malware. The default policy denies both.

Capability detection for npm uses install-script and native-build
metadata, then a deterministic scan of published JS/TS sources for
network, filesystem, environment, and shell indicators. It is not a
full behavioral sandbox and may under-report obfuscated code.

Trust chain evidence is extracted from npm provenance attestations
(SLSA predicates). It records the claimed source repository, commit,
ref, builder identity, workflow path, and predicate type when present.
When the Sigstore bundle verifies and the subject digest matches the
lockfile digest, provenance and chain are recorded as `verified`.
Securock only accepts SLSA provenance predicate types
(`https://slsa.dev/provenance/v0.1`, `v0.2`, and `v1`) for provenance
evidence. Policy origin allowlists can further restrict which source,
builder, workflow, ref, and predicate type count as trusted. Securock
does not rebuild the artifact from source.

Deno JSR and HTTPS URL artifacts record integrity from `deno.lock`.
OSV does not cover those ecosystems yet, so vulnerability state stays
`unknown`.

## What Securock does not guarantee

- that a trusted package is benign
- that a version bump is a security fix
- that transitive behavior is reachable or exploitable
- that GitHub, npm, or OSV are uncompromised
- that non-npm ecosystems collect provenance or signature evidence
- that capability heuristics catch every malicious behavior
- that a present trust chain proves the artifact was built from that source
