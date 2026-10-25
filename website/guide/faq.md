---
title: FAQ
description: Answers to common Securock questions — what trusted means, offline first lock, private registries, lockfile compatibility, and how it compares to scanner tools.
head:
  - - script
    - type: application/ld+json
    - '{"@context":"https://schema.org","@type":"FAQPage","mainEntity":[{"@type":"Question","name":"Does securock.lock replace my language lockfile?","acceptedAnswer":{"@type":"Answer","text":"No. The language lockfile still pins versions and is what your package manager reads. securock.lock records the trust decision you accepted for those versions and is read by securock only."}},{"@type":"Question","name":"What does the trusted status mean?","acceptedAnswer":{"@type":"Answer","text":"Trusted means the artifact passed the active policy. It is not a claim that a package is safe. Evidence that was not collected is recorded as unknown, never as trusted."}},{"@type":"Question","name":"Why does my first securock lock exit 1?","acceptedAnswer":{"@type":"Answer","text":"When remote evidence has not been collected, for example with --offline, unchecked vulnerabilities and malicious reports are unknown. The default policy treats unknown as not trusted, so the first lock of an offline tree exits 1 unless you pass --no-fail."}},{"@type":"Question","name":"Does Securock send my private dependencies anywhere?","acceptedAnswer":{"@type":"Answer","text":"No. The default public-only network mode queries OSV and known public registries for artifacts whose origin can be proven public. Private registries, GOPRIVATE modules, and ambiguous sources stay on machine with evidence left unknown."}},{"@type":"Question","name":"Which package managers are supported?","acceptedAnswer":{"@type":"Answer","text":"npm, pnpm, Yarn, Bun and Deno lockfiles, Cargo, Go modules, uv, Poetry and PDM, Composer, Bundler, NuGet, SwiftPM, Pub, Mix, and Gradle lockfiles. Evidence depth varies per ecosystem."}},{"@type":"Question","name":"How is Securock different from npm audit or Dependabot?","acceptedAnswer":{"@type":"Answer","text":"Scanners report what the advisory databases say today. Securock also records the trust decision you accepted — digests, provenance, signatures, ownership, capabilities — and fails CI when any of it drifts, even changes no advisory emits."}},{"@type":"Question","name":"Can I silence a finding without weakening policy?","acceptedAnswer":{"@type":"Answer","text":"Yes. securock accept records a reviewed finding with a reason, approver and expiry in .securock/exceptions.yaml. audit suppresses it until the date it lapses, then the finding returns. The lockfile and trust statuses are never changed."}},{"@type":"Question","name":"Can older Securock releases read a version 3 lockfile?","acceptedAnswer":{"@type":"Answer","text":"No. Decoding is strict: older releases refuse a version 3 file, and newer releases migrate version 1 and 2 files in memory. Update every machine and CI job that runs securock before committing a v3 file."}},{"@type":"Question","name":"Is Windows supported?","acceptedAnswer":{"@type":"Answer","text":"Released binaries currently target macOS and Linux (amd64 and arm64). The Windows build is smoke-tested in CI, but it is not shipped by the installer yet."}}]}'
---

# FAQ

## Does `securock.lock` replace my language lockfile?

No. The language lockfile (`package-lock.json`, `Cargo.lock`, `uv.lock`,
`Gemfile.lock`, …) still pins versions and is what your package manager
reads. `securock.lock` records the trust decision you accepted for those
versions and is read by Securock only. See
[Why Securock](/guide/why).

## What does the `trusted` status mean?

Trusted means the artifact **passed the active policy** — not that the
package is safe. Evidence that was not collected is recorded as
`unknown`, never as trusted. Details:
[Trust model](/reference/trust-model).

## Why does my first `securock lock` exit 1?

With `--offline` (or before any remote lookup succeeds), unchecked
vulnerabilities and malicious reports are `unknown`. The default policy
treats `unknown` as not trusted, so snapshotting an offline tree exits
`1` unless you pass `--no-fail`:

```sh
securock lock --offline --no-fail
```

Later, online runs can omit both once evidence is collected.

## Does Securock send my private dependencies anywhere?

No. The default network mode is `public-only`: OSV and known public
registries, and only for artifacts whose origin can be proven public.
Private registries, `GOPRIVATE` / `GONOPROXY` modules, and ambiguous
sources stay on machine with evidence left `unknown`. Details:
[Privacy](/reference/privacy).

## Which package managers are supported?

npm, pnpm, Yarn, Bun and Deno, Cargo, Go modules, uv, Poetry and PDM,
Composer, Bundler, NuGet, SwiftPM, Pub, Mix, and Gradle. Evidence depth
varies by ecosystem — npm and PyPI collect the most. Full table:
[Ecosystems](/guide/ecosystems).

## How is Securock different from `npm audit` or Dependabot?

Scanners report what advisory databases say **today**. Securock also
records the trust decision you **accepted** — digests, provenance,
signatures, ownership, capabilities — and fails CI when any of it
drifts, including changes no advisory ever emits, such as a new install
script or a changed maintainer list. Overview:
[Why Securock](/guide/why#how-it-compares).

## Can I silence a finding without weakening policy?

Yes. [`securock accept`](/guide/reports#accept-findings) records a
reviewed finding with a reason, approver, and expiry in
`.securock/exceptions.yaml`. `audit` suppresses it until the date it
lapses, when the finding returns. The lockfile and trust statuses are
never changed by an exception.

## Can older Securock releases read a version 3 lockfile?

No. Decoding is strict: older releases refuse a version 3 file with a
message to upgrade, and newer releases migrate version 1 and 2 files
in memory. Update every machine and CI job that runs securock before
committing a v3 file. Details:
[Lockfile](/reference/lockfile#version-history).

## Is Windows supported?

Released binaries currently target macOS and Linux (amd64 and arm64).
The Windows build is smoke-tested in CI, but the installer does not ship
it yet.

## Why did `diff` report drift when I only changed the policy?

The lockfile records a `policy.digest` fingerprint of the active
policy. Changing the policy changes that fingerprint, and that is trust
drift on purpose: the recorded state was accepted under different
rules. Re-record the accepted state (`securock lock` or
`update --write`) after you review the new rules. Details:
[Lockfile](/reference/lockfile#policy-digest).

## Next steps

- [Quick start](/guide/quickstart) — walk the loop end to end
- [Usage](/guide/usage) — commands and flags
- [Policy](/guide/policy) — what `trusted` means under your rules
