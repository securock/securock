# securock.lock specification

`securock.lock` is a language-agnostic snapshot of dependency trust.
Go is the implementation language of Securock, not a constraint on
what the lockfile can describe.

## Goals

The same project inputs must produce the same lockfile bytes.

```
sha256(securock.lock)
```

must be stable across machines, clocks, and working directories.

## Forbidden fields

The v1 lockfile must not contain:

- timestamps such as `generated_at`
- absolute filesystem paths
- other host-specific metadata
- advisory `modified` timestamps from vulnerability databases

Those values change without a trust-relevant change in the project.

## Document

```yaml
version: 1
source:
  ecosystems:
    - npm
  resolvers:
    - pnpm
artifacts:
  - subject:
      ecosystem: npm
      name: react
    version: 19.2.0
    digest: sha256:...
    source:
      resolver: pnpm
      registry: https://registry.npmjs.org
    evidence:
      provenance: unknown
      signature: unknown
    trust:
      status: trusted
```

Subject identity is `ecosystem:name` and does not include a version.
`npm:react@19.1.0` and `npm:react@19.2.0` are two artifacts of the
same subject `npm:react`.

`ecosystem` is the package registry ecosystem. `resolver` is the
package manager that produced the input lockfile. Switching from
pnpm to npm must not rewrite every subject identity.

`source.ecosystems` and `source.resolvers` are optional sorted lists.
They must not include a path.

## Canonical encoding

- YAML 1.2, 2-space indentation
- artifacts sorted by subject `ecosystem`, then `name`, then `version`, then resolver
- vulnerability ids sorted lexicographically
- trust reasons sorted lexicographically
- empty optional collections omitted

Evidence states are `unknown`, `missing`, `present`, and `verified`.
`present` means the evidence was observed. `verified` is reserved for
cryptographic verification.
