---
title: Triage and exports
description: Accept reviewed findings with a reason and expiry in .securock/exceptions.yaml, then export SBOMs (CycloneDX, SPDX) and VEX documents (OpenVEX, CycloneDX) from securock.lock.
---

# Triage and exports

Not every finding deserves a code change today. The commands on this
page record what you decided and carry that decision with your build
artifacts:

- **`accept`** records a reviewed finding with a reason, an approver,
  and an expiry in `.securock/exceptions.yaml`, so `audit` stops
  failing on it until the date passes.
- **`vex export`** writes those decisions as a VEX document, so what
  you decided about an advisory can travel with the SBOM.
- **`sbom export`** turns `securock.lock` into a CycloneDX or SPDX bill
  of materials; **`sbom verify`** checks an SBOM against the lockfile.

## Accept findings

Use the finding id that `audit` prints:

```sh
securock accept known-vulnerability:GHSA-xxxx-xxxx-xxxx \
  --subject npm:lodash \
  --reason "only used in a build script, tracked in ENG-142" \
  --approver alice --expires 90d

securock accept list          # active and expired exceptions
securock accept remove known-vulnerability:GHSA-xxxx-xxxx-xxxx --subject npm:lodash
```

- `--reason` and `--expires` are required. `--expires` is a date
  (`2026-12-31`, the last day it applies, in UTC) or a number of days such
  as `90d`.
- `--subject` limits the exception to one package. `npm:lodash@4.17.20`
  matches that artifact; `npm:lodash` matches any version. Without it, the
  exception covers every package with that finding.
- For a vulnerability, `--justification` says it does not affect you rather than that you accept
  the risk: `component_not_present`, `vulnerable_code_not_present`,
  `vulnerable_code_not_in_execute_path`, `vulnerable_code_cannot_be_controlled_by_adversary`, or
  `inline_mitigations_already_exist`. It only changes what
  [`vex export`](#vex-export) writes.
- Accepting the same finding and package again renews it.
- Exceptions live in `.securock/exceptions.yaml` (override with
  `--exceptions`). Commit the file and review it like code. It never
  changes `securock.lock` or any trust status; see
  [Trust model](/reference/trust-model#accepted-findings).
- `audit` keeps accepted findings in its output, marked suppressed
  (`suppressed` in JSON, `suppressions` in SARIF), and they do not count
  toward `--fail-on`. Once an exception expires the finding returns, with
  an `exception-expired` finding alongside it.

## VEX export

`vex export` writes the vulnerabilities you recorded with
[`accept`](#accept-findings) as a VEX document:

```sh
securock vex export --author "Security Team" > product.openvex.json            # OpenVEX 0.2.0
securock vex export --author "Security Team" --spec cyclonedx > product.vex.json  # CycloneDX 1.6
```

- An exception with `--justification` becomes `not_affected`, with your reason as the impact
  statement. Any other becomes `affected` with an action statement, `Risk accepted by alice
until 2026-12-31: <reason>`: you are affected and have chosen to wait.
- Packages are named by purl. An exception that names no package covers every package in
  `securock.lock` that has the advisory; one with `--subject` covers only those.
- Expired exceptions, exceptions for advisories not in `securock.lock`, and exceptions that are
  not for a known vulnerability are left out. Packages with no purl (URL imports) are skipped. If
  nothing is left, the command fails instead of writing an empty document, since an OpenVEX
  document needs at least one statement.
- In the CycloneDX form, each affected package is declared as a component with its purl as
  `bom-ref`, so every reference resolves within the document.
- `--author` is required: a VEX document says who vouches for it. The timestamp is the current
  time, or `SOURCE_DATE_EPOCH` when set, which also makes the output reproducible.

## SBOM export and verify

`sbom export` turns `securock.lock` into a software bill of materials on
stdout. It reads the lockfile, so run `securock lock` first and the SBOM
describes exactly what you locked.

```sh
securock sbom export > bom.cdx.json                  # CycloneDX 1.6 (default)
securock sbom export --spec spdx > bom.spdx.json     # SPDX 2.3
securock sbom verify bom.cdx.json                    # compare against securock.lock
```

- Each package carries a Package URL (`purl`) and, when the lockfile
  digest is a standard SHA-1/256/384/512, a `hashes` / `checksums` entry.
  Other digests, such as Go's `h1`, are kept as `securock:digest`.
- Trust evidence (status and reasons, provenance, signature, capabilities,
  ownership, source-to-build chain) is written as `securock:*` component
  properties in CycloneDX and as `securock:key=value` annotations in SPDX.
- Licenses recorded as release health are exported: a license expression made of known SPDX
  identifiers becomes a CycloneDX `expression` / SPDX `licenseDeclared`; any other text is a
  CycloneDX license name and stays out of `licenseDeclared`. The raw text is always kept as
  `securock:license`.
- Known vulnerabilities and malicious-package reports from the lockfile
  appear in the CycloneDX `vulnerabilities` list.
- CycloneDX output is deterministic: it has no timestamp. SPDX requires a creation time and
  uses the current time. Set `SOURCE_DATE_EPOCH` to stamp either format with a fixed time and
  make both reproducible.
- `sbom verify` reports a finding for each package that is missing,
  unexpected, or differs in version, purl, digest, or trust status (and
  for a policy digest mismatch in CycloneDX). It exits `1` on any
  finding and supports `--format json` (`sbom-verify-report` schema).
  It accepts SBOMs from other tools too, matching packages by purl. In SARIF output, results
  point at the SBOM file.

## Next steps

- [Usage](/guide/usage) — the lock / diff / verify loop and shared flags
- [Trust model](/reference/trust-model#accepted-findings) — what an exception does not change
- [Source code analysis](/guide/sast) — findings for `sast` use the same acceptance flow
