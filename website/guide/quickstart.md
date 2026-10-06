---
title: Quick start
description: Walk the Securock lock → update → diff → verify loop on the npm example, including offline first-time snapshots.
---

# Quick start

This walkthrough uses the committed
[npm example](https://github.com/securock/securock/tree/main/examples/npm)
to show the core loop: lock a trust snapshot, change a dependency,
inspect drift, then accept or reject it.

## Prerequisites

1. [Install](/guide/install) the Securock CLI.
2. Clone the repository (or copy `examples/npm`):

```sh
git clone https://github.com/securock/securock.git
cd securock/examples/npm
```

## 1. Create a baseline lockfile

```sh
securock lock --offline --no-fail
securock verify --offline
```

`--offline` skips OSV and registry lookups. The default policy treats
unchecked vulnerabilities and malicious reports as `unknown`, so the
first `lock` exits `1` unless `--no-fail` is set. The committed
`securock.lock` in that directory is that unknown snapshot (for
`ms@2.1.3`).

Online runs can omit `--offline` and `--no-fail` once public evidence
lookups succeed under the default policy.

## 2. Simulate a dependency change

The example ships an updated language lockfile under `after/`:

```sh
cp after/package-lock.json package-lock.json
securock diff --offline
securock verify --offline
```

`diff` reports the version and digest change. `verify` fails until you
accept the new tree.

## 3. Accept the new trust state

```sh
securock lock --offline
securock verify --offline
```

Restore the original language lockfile when you are done:

```sh
git checkout -- package-lock.json
```

## What you just practiced

```text
language lockfile  →  securock.lock  →  bump deps  →  diff / verify
```

- Language lockfiles pin versions.
- `securock.lock` pins the trust decision you accepted for those versions.
- Drift in digest, evidence, ownership, capabilities, or trust reasons
  is visible to operators (`diff`) and enforceable in CI (`verify`).

## Next steps

- [Usage](/guide/usage) — full command and flag reference
- [Policy](/guide/policy) — tighten or customize what counts as trusted
- [GitHub Action](/guide/action) — run the same loop in CI
- [Ecosystems](/guide/ecosystems) — apply the loop to other package managers
