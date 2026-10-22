---
title: Policy
description: Configure Securock default and strict profiles, custom YAML policy rules, capability and ownership gates, and provenance origin allowlists.
---

# Policy

Policy decides when an artifact is `trusted`, `untrusted`, or `unknown`.
`trusted` means the artifact passed the active policy. It is **not** a
guarantee that a package is safe, authentic, or free of malicious
behavior.

## Built-in profiles

```sh
securock verify --profile default
securock verify --profile strict
```

| Profile   | Requirements                                                                      |
| --------- | --------------------------------------------------------------------------------- |
| `default` | OSV queried with no known vulnerabilities; no malicious (`MAL-*`) reports         |
| `strict`  | Default rules, plus a strong digest and provenance / signature minimum `verified` |

Unchecked vulnerabilities (`state: unknown`) are `unknown`, not
`trusted`. Digest, provenance, signature, capability, and ownership
checks beyond the profile defaults are optional.

`--profile` and `--policy` are mutually exclusive.

Prefer `strict` on npm-heavy trees today: other ecosystems often leave
provenance and signature as `unknown`. See
[Ecosystems](/guide/ecosystems).

## Custom policy files

```sh
securock verify --policy .securock/policy.yaml
```

Policy files are **fail-closed**: unknown fields, versions, and network
modes are errors. Typos such as `require_provenace` do not silently
disable a rule.

Minimal example:

```yaml
version: 1
rules:
  require_no_vulnerabilities: true
  require_no_malicious: true
```

### Evidence floors

```yaml
version: 1
rules:
  require_digest: true
  require_provenance: true # accepts present or verified
  require_signature: true
  provenance:
    minimum: verified
  signature:
    minimum: verified
```

`require_provenance: true` accepts `present` or `verified`. Setting
`minimum: verified` requires cryptographic verification bound to the
lockfile digest.

### Capability and ownership gates

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

| Ownership action  | Effect                  |
| ----------------- | ----------------------- |
| `deny` / `review` | Fail `verify`           |
| `warn`            | Reported, does not fail |

When ownership rules are omitted, any ownership change remains trust
drift. When any ownership action is set, unset actions default to
`deny` (fail-closed).

### Health and typosquat gates

```yaml
version: 1
rules:
  require_no_vulnerabilities: true
  health:
    deprecated: deny
    typosquat: deny
```

| Rule         | Effect when `deny`                                                           |
| ------------ | ---------------------------------------------------------------------------- |
| `deprecated` | Deprecated or yanked releases are `untrusted`; unchecked health is `unknown` |
| `typosquat`  | Names within one edit of a popular npm or PyPI package are `untrusted`       |

Both default to allow and are not part of the `default` or `strict`
profiles. Only the age of a release is left out on purpose: trust
status must not change just because time passed, so `securock audit`
reports `stale-release` instead. See
[Release health](/guide/evidence#release-health).

### License gates

```yaml
version: 1
rules:
  require_no_vulnerabilities: true
  licenses:
    deny:
      - AGPL-*
      - GPL-*
    allow:
      - MIT
      - Apache-2.0
      - BSD-3-Clause
```

| Rule    | Effect                                                              |
| ------- | ------------------------------------------------------------------- |
| `deny`  | A package whose license is on the list is `untrusted`               |
| `allow` | When set, a package whose license is not on the list is `untrusted` |

Entries are SPDX identifiers, compared without regard to case. A trailing `*` matches a
prefix, so `GPL-*` covers every GPL version. A dual-licensed package passes if any alternative
does: `MIT OR GPL-3.0-only` passes a rule denying `GPL-*`, while `MIT AND GPL-3.0-only` does
not. `deny` wins over `allow`.

Licenses are read from the registry (see [Release health](/guide/evidence#release-health)), so
the rule applies to npm and PyPI. Other ecosystems have no license evidence, which makes them
`unknown` under any license rule. A package that declares no license fails an `allow` list but
is not rejected by a `deny` list alone. Deprecated spellings are normalized (`GPL-3.0` is
`GPL-3.0-only`), as are common PyPI classifier names such as `MIT License`.

### Provenance origin allowlists

To require verified provenance from an expected origin:

```yaml
version: 1
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

Empty allowlists are ignored. When any origin allowlist is set,
Securock requires a cryptographically verified trust chain and fails
artifacts whose chain fields do not match. Offline scans leave chain
evidence `unknown`, so origin allowlists surface as `unknown` rather
than trusted.

### Network mode in policy

```yaml
version: 1
network:
  mode: public-only
  registries:
    npm:
      - https://registry.npmjs.org
rules:
  require_no_vulnerabilities: true
```

Modes match the CLI: `public-only`, `offline`, `allow-all`. See
[Privacy](/reference/privacy).

## What "untrusted" and "unknown" mean

**Untrusted** — at least one enabled rule failed. Typical reasons:
known vulnerabilities, malicious reports, missing or weak digest when
required, provenance / signature below the floor, denied capabilities,
filesystem access above the configured maximum.

**Unknown** — Securock could not complete an evidence lookup, or the
ecosystem does not yet expose that evidence. Unknown is not verified.

## Policy digest in the lockfile

`policy.digest` in `securock.lock` is a SHA-256 of a canonical encoding
of the active policy (version, resolved network mode, registry
allowlists, and non-default rules). Changing the policy changes the
fingerprint even when package digests stay the same. Details:
[Lockfile](/reference/lockfile).

## Next steps

- [Evidence](/guide/evidence) — how states map to policy floors
- [Trust model](/reference/trust-model) — full evidence matrix and limits
- [GitHub Action](/guide/action) — pass `policy` or `profile` in CI
