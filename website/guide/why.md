---
title: Why Securock
description: Language lockfiles pin versions. Securock locks the trust decision behind each version and fails CI when digest, evidence, ownership, or provenance drifts.
---

# Why Securock

A dependency bump can change more than a version string. Between two
`npm install` runs, the same package can ship with a different tarball
digest, lose its provenance attestation, gain a new maintainer, or start
running an install script. None of that is visible in the language
lockfile, because a language lockfile only pins **versions**.

Securock adds a second file, `securock.lock`, that pins the **trust
decision** you accepted for those versions — and fails CI when that
state drifts.

## The loop

```text
language lockfile  →  securock.lock  →  bump deps  →  diff / verify
```

1. **`securock lock`** scans the current tree, collects evidence, and
   writes a deterministic snapshot of every artifact and its trust
   status.
2. You bump dependencies the way you already do (`npm install`,
   `cargo update`, …).
3. **`securock diff`** shows the operator view: which artifacts changed
   version, digest, evidence, ownership, capabilities, or trust
   reasons.
4. **`securock verify`** runs the same comparison and exits `1`, so CI
   fails until the new trust state is consciously accepted with
   **`securock update --write`** (or a fresh `lock`).

Security review happens at the bump, not after the fact.

## What gets recorded

For each artifact, Securock records:

| Axis            | Example                                                        |
| --------------- | -------------------------------------------------------------- |
| Identity        | subject (`npm:react`), version, content digest                 |
| Provenance      | SLSA attestation, builder, workflow, source repo and commit    |
| Signature       | registry signature state, verified against the locked digest   |
| Vulnerabilities | OSV advisories with severity and the version that fixes them   |
| Malware         | OpenSSF Malicious Packages reports (`MAL-*`)                   |
| Capabilities    | network, filesystem, shell, native code, install scripts       |
| Ownership       | publisher and maintainer list                                  |
| Behavior        | concrete hosts, paths, commands, and env vars the package uses |
| Health          | release day, deprecation, license                              |

What each ecosystem can actually collect varies; see
[Ecosystems](/guide/ecosystems) and the full [Trust model](/reference/trust-model).

## Trust, not a safety guarantee

`trusted` means the artifact passed the **active policy**. It is not a
claim that a package is safe. Evidence that was not collected is
`unknown` — never interpreted as clean. That fail-closed rule is what
makes offline runs and private registries honest: the lockfile says
what was checked and what was not, and `unknown` states are visible
instead of silently rendered green.

Compare the three status levels on the
[Trust model](/reference/trust-model) page.

## How it compares

| Capability                                                                  | Language lockfile | Vulnerability scanners (`npm audit`, `cargo audit`, …) | Securock |
| --------------------------------------------------------------------------- | ----------------- | ------------------------------------------------------ | -------- |
| Pins versions                                                               | yes               | no                                                     | yes      |
| Flags known vulnerabilities                                                 | no                | yes                                                    | yes      |
| Fails when a digest changes at the same version                             | no                | no                                                     | yes      |
| Fails when provenance, signature, ownership, capabilities, or health change | no                | no                                                     | yes      |
| Records the decision so CI gates drift, not facts                           | no                | no                                                     | yes      |
| Deterministic, offline-friendly lockfile                                    | partial           | no                                                     | yes      |

Vulnerability scanners ask "what does the ecosystem report today?".
Securock also asks "what did we accept, and has anything changed since
we accepted it?" — including changes an advisory database never emits,
such as a new install script or a changed maintainer list.

## Where it runs

- A single static Go binary for macOS and Linux (amd64 / arm64):
  [Install](/guide/install).
- A [GitHub Action](/guide/action) that runs `scan`, `diff`, and
  `verify` on every pull request and comments a trust report.
- Default network mode is `public-only`: private registries and
  `GOPRIVATE` modules stay on machine ([privacy](/reference/privacy)).

## Next steps

- [Quick start](/guide/quickstart) — walk the loop on the committed npm
  example
- [Usage](/guide/usage) — every command and flag
- [Policy](/guide/policy) — decide what `trusted` means for your team
