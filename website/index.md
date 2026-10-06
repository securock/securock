---
layout: home
title: Securock
description: A lockfile for trust, not just versions. Snapshot dependency digests, provenance, signatures, and policy decisions, then fail CI when that trust state drifts.
hero:
  name: Securock
  text: A lockfile for trust, not just versions.
  tagline: Reads npm, pnpm, Yarn, Bun, Deno, Cargo, Go, uv, Poetry, PDM, Composer, Bundler, NuGet, SwiftPM, Pub, Mix, and Gradle lockfiles. Records digest, provenance, signature, vulnerability, malicious-package, capability, behavior, ownership, and trust-chain evidence, then fails when that trust state drifts.
  actions:
    - theme: brand
      text: Quick start
      link: /guide/quickstart
    - theme: alt
      text: Try the example
      link: https://github.com/securock/securock/tree/main/examples/npm
features:
  - title: lock
    details: Write a deterministic securock.lock from the current tree.
  - title: update
    details: Bump a dependency the way you already do, in the language lockfile.
  - title: diff
    details: See version, digest, evidence, ownership, capabilities, and trust reasons.
  - title: verify
    details: Fail CI on the same trust-relevant drift that diff reports.
  - title: explain
    details: Print a trust checklist for one package under the active policy.
---
