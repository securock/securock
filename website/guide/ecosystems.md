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

## Reachability

`--reachability` ([Usage](/guide/usage#reachability)) needs two things from the lockfile: how each
package enters the project (its scope) and what each package depends on. What each resolver can read:

| Resolver | Scope comes from                                                 | Dependency edges                              |
| -------- | ---------------------------------------------------------------- | --------------------------------------------- |
| npm      | `dev`, `optional` and `devOptional` flags                        | `dependencies` of each package                |
| pnpm     | `importers` (direct dependencies), spread along the graph        | `snapshots`, or `packages` in older lockfiles |
| yarn     | `package.json` of the project and workspaces, spread along edges | `dependencies` of each entry                  |
| bun      | `workspaces` (direct dependencies), spread along the graph       | dependency map of each package                |
| deno     | `workspace` imports, spread along the graph (all runtime)        | `dependencies` of each package                |
| uv       | project and workspace member: dependencies, extras, dev groups   | `dependencies` of each package                |
| poetry   | `groups`, or `category`, or `pyproject.toml` for older lockfiles | `[package.dependencies]`                      |
| pdm      | `groups`, with `pyproject.toml` saying which are extras or dev   | `dependencies` requirement strings            |
| cargo    | `Cargo.toml` of the project and workspace members                | `dependencies` of each package                |
| composer | `packages` is runtime, `packages-dev` is dev                     | `require` of each package                     |
| bundler  | `DEPENDENCIES`, with the `Gemfile` marking dev and test groups   | gems listed under each spec                   |
| nuget    | `Direct` packages are runtime                                    | `dependencies` within each target framework   |
| pub      | `direct main`, `direct dev`, `direct overridden`                 | not recorded                                  |
| mix      | `mix.exs`, where `only: :dev` or `:test` marks dev               | dependency list of each hex entry             |
| gradle   | the configurations a dependency is locked for                    | not recorded                                  |
| go       | not recorded                                                     | not recorded                                  |
| swiftpm  | not recorded                                                     | not recorded                                  |

Where a lockfile records neither, vulnerabilities stay `unknown`. Where the scope comes from a
manifest (`package.json`, `Cargo.toml`, `pyproject.toml`, `Gemfile`, `mix.exs`) and the manifest is
missing, scopes stay `unknown` as well. Go modules are the notable gap: `go.mod` does not say which
modules a package actually imports, so reachability for Go needs call-graph analysis such as
`govulncheck`, which Securock does not do.

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

## Examples

Offline walkthroughs for several resolvers live under
[`examples/`](https://github.com/securock/securock/tree/main/examples):

| Resolver | Directory                                                                           |
| -------- | ----------------------------------------------------------------------------------- |
| npm      | [`examples/npm`](https://github.com/securock/securock/tree/main/examples/npm)       |
| pnpm     | [`examples/pnpm`](https://github.com/securock/securock/tree/main/examples/pnpm)     |
| Yarn     | [`examples/yarn`](https://github.com/securock/securock/tree/main/examples/yarn)     |
| Bun      | [`examples/bun`](https://github.com/securock/securock/tree/main/examples/bun)       |
| uv       | [`examples/uv`](https://github.com/securock/securock/tree/main/examples/uv)         |
| Poetry   | [`examples/poetry`](https://github.com/securock/securock/tree/main/examples/poetry) |
| Go       | [`examples/go`](https://github.com/securock/securock/tree/main/examples/go)         |
| Cargo    | [`examples/cargo`](https://github.com/securock/securock/tree/main/examples/cargo)   |

## Next steps

- [Evidence](/guide/evidence) — how to read each state
- [Policy](/guide/policy) — floors that match your evidence depth
- [Privacy](/reference/privacy) — what leaves the machine in `public-only`
