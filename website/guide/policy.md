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
