---
layout: home
title: Securock — a lockfile for trust, not just versions
description: Securock records dependency digests, provenance, signatures, vulnerability and malware evidence, and policy decisions in securock.lock, then fails CI when that trust state drifts. Single static binary, 19 resolvers, public-only network mode.
hero:
  name: Securock
  text: A lockfile for trust, not just versions.
  tagline: Snapshot digest, provenance, signature, vulnerability, malware, capability, and ownership evidence for every dependency. Fail CI when that trust state drifts — not just when a version does.
  actions:
    - theme: brand
      text: Quick start
      link: /guide/quickstart
    - theme: alt
      text: Why Securock
      link: /guide/why
    - theme: alt
      text: Install
      link: /guide/install
features:
  - icon: '<svg class="lucide lucide-file-lock-2" xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" > <path d="M4 9.8V4a2 2 0 0 1 2-2h8a2.4 2.4 0 0 1 1.706.706l3.588 3.588A2.4 2.4 0 0 1 20 8v12a2 2 0 0 1-2 2h-3" /> <path d="M14 2v5a1 1 0 0 0 1 1h5" /> <path d="M9 17v-2a2 2 0 0 0-4 0v2" /> <rect width="8" height="5" x="3" y="17" rx="1" /> </svg>'
    title: Trust snapshots
    details: "`securock lock` writes a deterministic securock.lock that records what you accepted for each artifact — digests, provenance, signatures, ownership, capabilities, and health. No timestamps, no absolute paths, byte-identical on re-run."
    link: /reference/lockfile
    linkText: Lockfile format
  - icon: '<svg class="lucide lucide-git-compare" xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" > <circle cx="18" cy="18" r="3" /> <circle cx="6" cy="6" r="3" /> <path d="M13 6h3a2 2 0 0 1 2 2v7" /> <path d="M11 18H8a2 2 0 0 1-2-2V9" /> </svg>'
    title: Drift you can see
    details: "`diff` shows the operator view of every change at the same version — a different digest, a lost attestation, a new maintainer, a new install script — before anything ships."
    link: /guide/usage#scan-vs-verify
    linkText: diff and verify
  - icon: '<svg class="lucide lucide-circle-check-big" xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" > <path d="M21.801 10A10 10 0 1 1 17 3.335" /> <path d="m9 11 3 3L22 4" /> </svg>'
    title: A CI gate, not a report
    details: "`verify` exits 1 on the same drift, so pull requests cannot silently change trust state. Accept changes with `update --write` after review, or wire the whole loop into GitHub Actions."
    link: /guide/action
    linkText: GitHub Action
  - icon: '<svg class="lucide lucide-file-signature" xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" > <path d="M14.364 13.634a2 2 0 0 0-.506.854l-.837 2.87a.5.5 0 0 0 .62.62l2.87-.837a2 2 0 0 0 .854-.506l4.013-4.009a1 1 0 0 0-3.004-3.004z" /> <path d="M14.487 7.858A1 1 0 0 1 14 7V2" /> <path d="M20 19.645V20a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h8a2.4 2.4 0 0 1 1.704.706l2.516 2.516" /> <path d="M8 18h1" /> </svg>'
    title: Provenance verification
    details: "npm attestation signatures and PyPI PEP 740 attestations are re-verified against Sigstore roots and bound to the locked digest — alone, or as a minimum floor with the strict profile."
    link: /guide/evidence
    linkText: Evidence states
  - icon: '<svg class="lucide lucide-search-code" xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" > <path d="m13 13.5 2-2.5-2-2.5" /> <path d="m21 21-4.3-4.3" /> <path d="M9 8.5 7 11l2 2.5" /> <circle cx="11" cy="11" r="8" /> </svg>'
    title: Source code analysis
    details: "`sast` tracks untrusted data through your own source to dangerous calls across 9 languages, fully offline — plus Dockerfile, Kubernetes, Terraform, and Actions checks and a committed-secrets scan."
    link: /guide/sast
    linkText: SAST reference
  - icon: '<svg class="lucide lucide-receipt-text" xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" > <path d="M13 16H8" /> <path d="M14 8H8" /> <path d="M16 12H8" /> <path d="M4 3a1 1 0 0 1 1-1 1.3 1.3 0 0 1 .7.2l.933.6a1.3 1.3 0 0 0 1.4 0l.934-.6a1.3 1.3 0 0 1 1.4 0l.933.6a1.3 1.3 0 0 0 1.4 0l.933-.6a1.3 1.3 0 0 1 1.4 0l.934.6a1.3 1.3 0 0 0 1.4 0l.933-.6A1.3 1.3 0 0 1 19 2a1 1 0 0 1 1 1v18a1 1 0 0 1-1 1 1.3 1.3 0 0 1-.7-.2l-.933-.6a1.3 1.3 0 0 0-1.4 0l-.934.6a1.3 1.3 0 0 1-1.4 0l-.933-.6a1.3 1.3 0 0 0-1.4 0l-.933.6a1.3 1.3 0 0 1-1.4 0l-.934-.6a1.3 1.3 0 0 0-1.4 0l-.933.6a1.3 1.3 0 0 1-.7.2 1 1 0 0 1-1-1z" /> </svg>'
    title: Triage with receipts
    details: "`accept` records reviewed findings with reason, approver, and expiry; `vex export` and `sbom export` carry your decisions downstream in OpenVEX, CycloneDX, and SPDX."
    link: /guide/reports
    linkText: Triage and exports
---
