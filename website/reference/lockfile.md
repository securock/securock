---
title: Lockfile
description: securock.lock v2 format — subject identity, determinism rules, evidence axes, policy digest, and v1 migration.
---

# Lockfile

`securock.lock` is a language-agnostic snapshot of dependency trust.
Go is the implementation language of Securock, not a constraint on what
the lockfile can describe.

> Canonical specification source:
> [`docs/specification.md`](https://github.com/securock/securock/blob/main/docs/specification.md)
> in the repository.

## Goals

The same project inputs must produce the same lockfile bytes.

```
sha256(securock.lock)
```

must be stable across machines, clocks, and working directories.

## Forbidden fields

The lockfile must not contain:

- timestamps such as `generated_at`
- absolute filesystem paths
- other host-specific metadata
- advisory `modified` timestamps from vulnerability databases

Those values change without a trust-relevant change in the project.

## Document shape (v2)

```yaml
version: 2
source:
  ecosystems:
    - npm
  resolvers:
    - pnpm
policy:
  digest: sha256:...
artifacts:
  - subject:
      ecosystem: npm
      name: react
    version: 19.2.0
    digest: sha512:...
    source:
      resolver: pnpm
      registry: https://registry.npmjs.org
    evidence:
      provenance: unknown
      signature: unknown
      vulnerabilities:
        state: unknown
      malicious:
        state: unknown
      capabilities:
        state: unknown
      behavior:
        state: unknown
      ownership:
        state: unknown
      chain:
        state: unknown
    trust:
      status: unknown
      reasons:
        - malicious reports not checked
        - vulnerabilities not checked
```

## Identity

Subject identity is `ecosystem:name` and does **not** include a version.
`npm:react@19.1.0` and `npm:react@19.2.0` are two artifacts of the same
subject `npm:react`. A bump is a change to one subject, not a delete
plus an add.

`ecosystem` is the package registry family. `resolver` is the package
manager that produced the input lockfile. Switching from pnpm to npm
must not rewrite every subject identity.

`source.ecosystems` and `source.resolvers` are optional sorted lists.
They must not include a path. Artifact `source.registry` is the package
metadata origin. `source.artifact` is the download URL when it differs,
or a Git repository URL. `source.kind` is `registry`, `workspace`,
`git`, `file`, or `url`. `source.requested` and `source.resolved`
record a specifier that redirected (for example a Deno HTTPS import).

A change to `source.kind`, `source.registry`, `source.artifact`,
`source.requested`, or `source.resolved` is **trust drift** even when
the name, version, and digest stay the same.

## Evidence axes

`capabilities`, `ownership`, `behavior`, and `chain` use
`state: checked` / evidence states when collected and `unknown` when
skipped (offline or unsupported ecosystem). A change to any of them is
trust drift.

Vulnerability evidence is not a bare list. `state: checked` means OSV
was queried. `unknown` means it was not. An empty `items` list with
`state: unknown` is not the same as zero vulnerabilities.

URL artifacts may omit `version`. Their identity is `subject.name`
(the requested URL). Do not encode a URL into `version`.

```yaml
- subject:
    ecosystem: url
    name: https://esm.sh/preact
  source:
    resolver: deno
    requested: https://esm.sh/preact
    resolved: https://esm.sh/preact@10.26.8
```

When a remote hash is present, `version` is that hash (not a URL).

## Digests

| Prefix                            | Meaning                                                                   |
| --------------------------------- | ------------------------------------------------------------------------- |
| `sha256:` / `sha384:` / `sha512:` | Content hash of the package artifact (npm SRI, Cargo checksum, PyPI file) |
| `goh1:`                           | Go module directory hash from `go.sum` (`h1:`)                            |

`require_digest: true` (including the `strict` profile) requires a
non-empty digest that uses a strong algorithm with a well-formed
payload: `sha256`, `sha384`, `sha512`, or `goh1`. `sha1` and opaque
strings fail the policy.

PyPI may emit one artifact per wheel or sdist, distinguished by
`filename`. The same `ecosystem:name@version` with two different
digests is an artifact conflict and must fail the scan, except when
`filename` distinguishes PyPI files.

## Policy digest

`policy.digest` is a SHA-256 of a canonical JSON encoding of the active
policy (version, resolved network mode, registry allowlists, and
non-default rules including capability deny lists, ownership change
actions, and provenance origin allowlists). It must not include a file
path.

## v1 migration

`version: 1` lockfiles from Securock v0.1.x are migrated to `version: 2`
in memory on read. Kept fields are digest, source, provenance,
signature, and vulnerabilities. New evidence axes (`malicious`,
`capabilities`, `behavior`, `ownership`, `chain`) and trust are set to
`unknown` — a v1 `trusted` status is not carried forward. Read-only
commands do not rewrite the file; run `securock lock` to persist a
refreshed v2 snapshot.

## Canonical encoding

- YAML 1.2, 2-space indentation
- artifacts sorted by subject `ecosystem`, then `name`, then `version`, then resolver
- vulnerability ids, malicious report ids, ownership maintainers, and trust reasons sorted lexicographically
- empty optional collections omitted

Evidence states for provenance / signature / chain:
`unknown`, `missing`, `present`, `verified`.

Vulnerability, malicious, capability, behavior, and ownership states:
`unknown` and `checked`.

Unknown lockfile fields, schema versions, ecosystems, evidence states,
and trust statuses are errors.

## Commands that use the lockfile

| Command           | Role                                                                                  |
| ----------------- | ------------------------------------------------------------------------------------- |
| `lock`            | Write the file                                                                        |
| `diff` / `verify` | Compare the tree to the file                                                          |
| `scan`            | Inspect the tree (default); fails on current policy violations even if already locked |

JSON Schemas: [`schemas/`](https://github.com/securock/securock/tree/main/schemas).

## Next steps

- [Usage](/guide/usage) — CLI workflow around the lockfile
- [Evidence](/guide/evidence) — reading evidence states
- [Threat model](/reference/threat-model) — what drift protects against
