---
title: Ecosystems
description: Supported package managers and lockfiles for Securock, evidence depth by ecosystem, and public-only caveats for Go, Gradle, Deno, and more.
---

# Ecosystems

Securock reads language lockfiles and records trust evidence per
artifact. Subject identity uses the **ecosystem** (registry family),
not the package manager. Switching npm ↔ pnpm does not rewrite every
subject identity because **resolver** is stored separately.

When multiple resolvers for the same family are present, prefer one
resolver per family (for example pnpm over npm).

## Supported lockfiles

| Ecosystem | Resolver | Lockfile             |
| --------- | -------- | -------------------- |
| npm       | npm      | `package-lock.json`  |
| npm       | pnpm     | `pnpm-lock.yaml`     |
| npm       | yarn     | `yarn.lock`          |
| npm       | bun      | `bun.lock`           |
| npm       | deno     | `deno.lock`          |
| jsr       | deno     | `deno.lock`          |
| url       | deno     | `deno.lock`          |
| cargo     | cargo    | `Cargo.lock`         |
| go        | go       | `go.mod` + `go.sum`  |
| pypi      | uv       | `uv.lock`            |
| pypi      | poetry   | `poetry.lock`        |
| pypi      | pdm      | `pdm.lock`           |
| packagist | composer | `composer.lock`      |
| rubygems  | bundler  | `Gemfile.lock`       |
| nuget     | nuget    | `packages.lock.json` |
| swift     | swiftpm  | `Package.resolved`   |
| pub       | pub      | `pubspec.lock`       |
| hex       | mix      | `mix.lock`           |
| maven     | gradle   | `gradle.lockfile`    |

All resolvers above are stable. Deno `deno.lock` v5 is the preferred
target; v3/v4 remain supported for compatibility.

## Evidence depth

| Evidence        | npm family (npm / pnpm / yarn / bun / deno npm)             | PyPI (uv / Poetry / PDM)                                   | Other ecosystems                     |
| --------------- | ----------------------------------------------------------- | ---------------------------------------------------------- | ------------------------------------ |
| digest          | from the language lockfile                                  | from the language lockfile                                 | from the language lockfile           |
| vulnerabilities | OSV (non-`MAL-*`)                                           | OSV when the source is proven public                       | OSV when the source is proven public |
| malicious       | OSV `MAL-*`                                                 | same, when OSV is queried                                  | same, when OSV is queried            |
| provenance      | npm attestation; `verified` after Sigstore + digest bind    | PEP 740 Integrity API; `verified` after Sigstore re-verify | `unknown`                            |
| signature       | npm `dist.signatures`; `verified` after ECDSA + digest bind | same PEP 740 path as provenance                            | `unknown`                            |
| capabilities    | registry metadata + source heuristics                       | `unknown`                                                  | `unknown`                            |
| behavior        | hosts, paths, commands, env from heuristics                 | `unknown`                                                  | `unknown`                            |
| ownership       | publisher and maintainers                                   | `unknown`                                                  | `unknown`                            |
| chain           | SLSA fields from provenance                                 | Trusted Publisher + Sigstore identity                      | `unknown`                            |

npm collection verifies registry ECDSA signatures against
`/-/npm/v1/keys` and Sigstore provenance bundles against the public-good
trusted root. Both require the lockfile digest to match the signed
artifact before emitting `verified`.

## Caveats by ecosystem

### Deno

- Deno npm packages use OSV and npm evidence collectors.
- JSR and HTTPS URL artifacts parse stably; OSV does not cover them yet,
  so vulnerability state stays `unknown`.
- URL subjects use the requested URL as `subject.name`; do not put URLs
  in `version`.

### Go

- OSV runs in `public-only` only when the effective `GOPROXY` is the
  single public proxy and the module is not private.
- `GOPRIVATE` / ambiguous multi-proxy lists keep names off OSV; state is
  `unknown`, not trusted.
- Digests use the `goh1:` prefix from `go.sum`.

### Gradle (Maven coordinates)

- `gradle.lockfile` records coordinates but does not prove a registry URL.
- OSV is **not** queried in `public-only`.

### Swift

- Package URLs are recorded, but `public-only` does not treat Git hosts
  as a public registry for OSV.

### pnpm / NuGet / PDM / Mix

Fail-closed public origin rules apply: Securock does not assume a public
registry when the lockfile omits a resolvable public tarball or index.
See [Privacy](/reference/privacy).

## Choosing a profile

| Tree                        | Suggested starting point                            |
| --------------------------- | --------------------------------------------------- |
| npm-heavy with attestations | `--profile strict`                                  |
| Mixed / non-npm             | `default`, then add digest / origin rules carefully |
| Offline fixtures            | `--offline` and expect many `unknown` axes          |

## Next steps

- [Evidence](/guide/evidence) — how to read each state
- [Policy](/guide/policy) — floors that match your evidence depth
- [Privacy](/reference/privacy) — what leaves the machine in `public-only`
