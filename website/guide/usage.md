---
title: Usage
description: Securock CLI commands, flags, exit codes, and how scan differs from verify when enforcing trust policy and lockfile drift.
---

# Usage

Securock reads language lockfiles, applies a policy, and either writes
or compares against `securock.lock`.

```sh
securock scan [path]
securock lock [path]
securock diff [path]
securock verify [path]
securock explain PACKAGE [path]
securock version
```

`scan` is the default when no command is given. `trusted` means the
artifact passed the active policy, not that it is cryptographically
verified. The CLI prints this as `trusted (under active policy)`.

## Commands

| Command   | What it does                                               |
| --------- | ---------------------------------------------------------- |
| `scan`    | Inspect the current tree under the active policy (default) |
| `lock`    | Write a deterministic `securock.lock`                      |
| `diff`    | Show trust drift versus the lockfile                       |
| `verify`  | Fail on trust-relevant drift versus the lockfile           |
| `explain` | Print a trust checklist for one package                    |
| `version` | Print the build version                                    |

### `scan` vs `verify`

These answer different questions:

- **`scan`** fails on **current** policy violations even when
  `securock.lock` already records them. Use it to keep the tree honest
  under today's policy.
- **`verify`** fails when the tree **drifts** from the accepted lockfile
  (digest, evidence, ownership, capabilities, trust reasons, and so on).
- **`diff`** is the operator view of the same comparison `verify` uses.

The GitHub Action default (`command: all`) runs `scan`, then `diff`,
then `verify`.

`explain PACKAGE` prints digest, source, provenance, signature, trust
chain, ownership, capabilities, vulnerabilities, and malicious-package
checks for one subject under the active policy.

## Shared flags

| Flag        | Meaning                                                      |
| ----------- | ------------------------------------------------------------ |
| `--network` | `public-only` (default), `offline`, or `allow-all`           |
| `--offline` | Skip remote lookups; remote evidence stays `unknown`         |
| `--policy`  | Path to a policy file                                        |
| `--profile` | Built-in policy: `default` or `strict` (not with `--policy`) |
| `--lock`    | Path to `securock.lock` (for `lock` / `diff` / `verify`)     |
| `--format`  | `text` (default) or `json`                                   |
| `--no-fail` | Always exit `0`                                              |

`--offline` records vulnerability, malicious, capability, behavior,
ownership, provenance, signature, and chain evidence as `unknown`.

`--policy` and `--profile` are mutually exclusive. See
[Policy](/guide/policy) for profiles and YAML rules.

## Exit codes

| Code | Meaning                                 |
| ---- | --------------------------------------- |
| `0`  | Success / no trust drift (for `verify`) |
| `1`  | Trust violation                         |
| `2`  | Configuration or operational error      |

## JSON output

```sh
securock scan --format json
securock diff --format json
securock verify --format json
securock explain react --format json
```

- `scan --format json` emits the lock document shape.
- `diff` and `verify` print a `schema_version: 1` report.
- `explain --format json` emits the matched artifacts.

Machine-readable schemas live in the repository under
[`schemas/`](https://github.com/securock/securock/tree/main/schemas)
(`securock-lock`, `scan-report`, `diff-report`, `verify-report`).

## Typical workflow

1. Install Securock ([Install](/guide/install)).
2. From a project with a language lockfile, create a baseline:

   ```sh
   securock lock
   ```

   Offline first-time snapshots may need `--offline --no-fail` because
   unchecked vulns are `unknown`, not trusted. See
   [Quick start](/guide/quickstart).

3. Change dependencies the usual way (`npm install`, `cargo update`, …).
4. Inspect and gate the change:

   ```sh
   securock diff
   securock verify
   ```

5. When you accept the new trust state, rewrite the lockfile:

   ```sh
   securock lock
   ```

## Next steps

- [Policy](/guide/policy) — default vs `strict`, custom YAML
- [Ecosystems](/guide/ecosystems) — which lockfiles and evidence depth
- [Evidence](/guide/evidence) — how to read evidence states
- [GitHub Action](/guide/action) — CI wiring
