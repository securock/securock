# Threat model

## Protects against

Securock is designed to make these changes visible and, under policy,
fail CI:

- **Dependency substitution** — a subject appears whose identity was not
  in `securock.lock`
- **Artifact modification** — the digest for a subject changes
- **Trust-state changes** — provenance, signature, vulnerability IDs,
  trust status, or trust reasons drift between lock and the current tree
- **Known vulnerable dependency changes** — OSV reports an advisory for
  a locked or updated artifact when the default policy is enabled
- **Package-manager disguise** — switching npm ↔ pnpm does not rewrite
  subject identity, because resolver is separate from ecosystem

`securock diff` is the operator-facing view of those changes.
`securock verify` is the CI gate.

## Does not protect against

- zero-day or undisclosed malicious code in a package that OSV does not
  list
- compromised maintainer accounts that publish a new "trusted" version
- typosquatting unless the new subject is caught as an addition against
  an existing lockfile
- runtime integrity after install (memory, disk, or container attacks)
- malicious build systems that produce a matching digest for bad code
- full cryptographic verification of npm provenance/signatures in v0.1
- supply-chain attacks in Cargo, Go, or PyPI provenance, which remain
  experimental
- installer compromise if `checksums.txt` and GitHub attestations are
  both attacker-controlled

## Trust boundary

Securock trusts, as inputs:

- the project's language lockfiles on disk
- OSV, for vulnerability ids
- the npm registry, for attestation and signature presence
- GitHub, for Securock's own release attestations

A compromise of those services can produce a `trusted` result that is
still wrong. The lockfile exists so that drift against a previously
accepted state is still observable.
