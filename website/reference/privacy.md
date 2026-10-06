---
title: Privacy
description: What Securock sends off-machine in public-only, offline, and allow-all network modes, and which registries count as public.
---

# Privacy

Securock may send public dependency names and versions to third parties
when it looks up vulnerabilities and package evidence. For npm
capability and behavior scanning it may also download public package
tarballs from the registry. For PyPI it may query the Integrity API for
public file provenance.

> Canonical source:
> [`docs/privacy.md`](https://github.com/securock/securock/blob/main/docs/privacy.md).

## Default: public-only

The default network mode is `public-only`. Securock only queries:

- OSV (`https://api.osv.dev`)
- the npm registry (`https://registry.npmjs.org`) and Yarn's default
  (`https://registry.yarnpkg.com`)
- the PyPI Integrity API (`https://pypi.org/integrity/...`) for public
  PyPI artifacts with a filename in the language lockfile

and only for artifacts whose lockfile registry is a known public
registry:

| Ecosystem | Allowed registries                                                                                                                                                     |
| --------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| npm       | `https://registry.npmjs.org`, `https://registry.yarnpkg.com`                                                                                                           |
| cargo     | crates.io index URLs                                                                                                                                                   |
| go        | `https://proxy.golang.org` when the effective `GOPROXY` is that single public proxy (OS, then `go env -w` / `GOENV`, then Go's default). Multiple proxy URLs (`,` or ` | `) are unknown. `GONOPROXY`overrides`GOPRIVATE`for proxy use;`GOPRIVATE` still keeps names off OSV. |
| pypi      | `https://pypi.org`                                                                                                                                                     |
| packagist | `https://repo.packagist.org`                                                                                                                                           |
| rubygems  | `https://rubygems.org`                                                                                                                                                 |
| nuget     | `https://api.nuget.org`                                                                                                                                                |
| pub       | `https://pub.dev`                                                                                                                                                      |
| hex       | `https://repo.hex.pm`                                                                                                                                                  |
| jsr       | `https://jsr.io` (names are not sent to OSV yet)                                                                                                                       |

Private registries, missing `resolved` URLs, custom or ambiguous
`GOPROXY` lists, and `GOPRIVATE` / `GONOPROXY` modules are recorded in
`securock.lock` but are **not** sent off-machine. Their vulnerability
state is `unknown`, not `trusted`.

Effective Go values include `go env -w` (the user `GOENV` file), not
only OS environment variables. `GONOPROXY=none` can send `GOPRIVATE`
modules through a proxy, but those names are still not sent to OSV. For
Go `replace`, privacy and OSV use the replacement module path, not the
original require path. Swift package URLs are recorded the same way:
`public-only` does not treat Git hosts as a public registry.

## Fail-closed public origin

pnpm often omits tarball URLs. Securock does **not** assume
`registry.npmjs.org` in that case. It only treats a package as public
when a tarball origin or an explicit registry setting (environment,
project `.npmrc` / `.yarnrc.yml`, parent `.yarnrc.yml`, or user
`~/.npmrc` / `~/.yarnrc.yml`) proves a public origin. Yarn Berry
projects without a registry setting use Yarn's documented default,
`https://registry.yarnpkg.com`, which is treated as public npm.

The same fail-closed rule applies to:

- **NuGet** — `NuGet.Config` package sources, merged like NuGet from
  machine and user configs through every parent directory down to the
  project
- **PDM** — lockfile file URLs, plus `[[tool.pdm.source]]` and PDM
  config indexes; the default PyPI index is treated as public
- **Mix** — `mix.lock` repository identity
- **Gradle** — `gradle.lockfile` has no repository URL

Mixed public and private sources are treated as unknown.

## Modes

```sh
securock scan --offline
securock scan --network public-only
securock scan --network allow-all
```

| Mode                    | Behavior                                                                                                 |
| ----------------------- | -------------------------------------------------------------------------------------------------------- |
| `offline` / `--offline` | Skip all remote lookups                                                                                  |
| `public-only` (default) | Public registries and OSV only, as above                                                                 |
| `allow-all`             | Send every dependency name and version to OSV and, for supported collectors, registry evidence endpoints |

Use `allow-all` only when that disclosure is acceptable.

Policy files can set the same mode:

```yaml
version: 1
network:
  mode: public-only
  registries:
    npm:
      - https://registry.npmjs.org
rules:
  require_no_vulnerabilities: true
```

Unknown policy fields are rejected.

## Next steps

- [Ecosystems](/guide/ecosystems) — which collectors hit the network
- [Policy](/guide/policy) — embedding network mode in YAML
- [Trust model](/reference/trust-model) — how `unknown` interacts with trust
