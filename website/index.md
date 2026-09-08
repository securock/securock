---
layout: home
hero:
  name: Securock
  text: A lockfile for trust, not just versions.
  tagline: Reads npm, pnpm, Cargo, Go, and uv lockfiles, records digest / provenance / signature / vulnerability evidence, and fails when that trust state drifts.
  actions:
    - theme: brand
      text: Read the docs
      link: /guide/install
    - theme: alt
      text: Try the example
      link: https://github.com/securock/securock/tree/main/examples/npm
features:
  - title: lock
    details: Write a deterministic securock.lock from the current tree.
  - title: update
    details: Bump a dependency the way you already do, in the language lockfile.
  - title: diff
    details: See version, digest, evidence, vulnerability IDs, and trust reasons.
  - title: verify
    details: Fail CI unless the current tree matches the locked trust state.
---

<Ledger />
