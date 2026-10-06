# Threat model

## Protects against

Securock is designed to make these changes visible and, under policy,
fail CI:

- **Dependency substitution** — a subject appears whose identity was not
  in `securock.lock`
- **Artifact modification** — the digest for a subject changes
- **Trust-state changes** — provenance, signature, vulnerability IDs,
  capabilities, behavior, ownership (publisher/maintainers), trust
  chain (source/commit/builder/workflow), trust status, or trust
  reasons drift between lock and the current tree
- **Known vulnerable dependency changes** — OSV reports an advisory for
  a locked or updated artifact when the default policy is enabled
- **Package-manager disguise** — switching npm ↔ pnpm does not rewrite
  subject identity, because resolver is separate from ecosystem

`securock diff` is the operator-facing view of those changes.
`securock verify` fails CI on trust-relevant drift against
`securock.lock`. `securock scan` fails CI on current policy violations
even when the lockfile already records them. The GitHub Action default
(`command: all`) runs `scan`, `diff`, and `verify`. `securock explain
<package>` shows why a subject is trusted under the active scan.

## Does not protect against

- zero-day or undisclosed malicious code in a package that OSV does not
  list
- compromised maintainer accounts that publish a new "trusted" version
  without a detectable ownership change in registry metadata
- typosquatting unless the new subject is caught as an addition against
  an existing lockfile
- runtime integrity after install (memory, disk, or container attacks)
- malicious build systems that produce a matching digest for bad code
- supply-chain attacks in ecosystems whose provenance and signature
  evidence Securock does not collect
- installer compromise if `checksums.txt` and GitHub attestations are
  both attacker-controlled
- obfuscated capability use that the package source heuristics miss
- provenance signed by an OIDC issuer outside the trusted GitHub Actions
  / GitLab patterns Securock accepts for `verified`, or provenance whose
  source/builder/workflow/ref/predicate type is outside an active policy
  origin allowlist

## Trust boundary

Securock trusts, as inputs:

- the project's language lockfiles on disk
- OSV, for vulnerability ids
- the npm registry, for attestation and signature material (verified
  cryptographically when keys / Sigstore roots are available)
- GitHub, for Securock's own release attestations

A compromise of those services can produce a `trusted` result that is
still wrong. The lockfile exists so that drift against a previously
accepted state is still observable.

OpenSSF Malicious Packages (`MAL-*` via OSV) are recorded separately
from CVEs. Capability and behavior fields are heuristic for npm package
sources; they detect drift and policy violations, not every possible
malicious payload.
