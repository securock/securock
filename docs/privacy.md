# Privacy

Securock may send dependency names and versions to third parties when it
looks up vulnerabilities and npm evidence.

## Default: public-only

The default network mode is `public-only`. Securock only queries:

- OSV (`https://api.osv.dev`)
- the npm registry (`https://registry.npmjs.org`)

and only for artifacts whose lockfile registry is a known public registry:

| Ecosystem | Allowed registries |
| --- | --- |
| npm | `https://registry.npmjs.org` |
| cargo | crates.io index URLs |
| go | `https://proxy.golang.org` (skips `GOPRIVATE`, same prefix globs as `go`) |
| pypi | `https://pypi.org` |
| packagist | `https://repo.packagist.org` |
| rubygems | `https://rubygems.org` |
| nuget | `https://api.nuget.org` |
| pub | `https://pub.dev` |
| hex | `https://repo.hex.pm` |
| jsr | `https://jsr.io` (names are not sent to OSV yet) |

Private registries, missing `resolved` URLs, and `GOPRIVATE` modules are
recorded in `securock.lock` but are **not** sent off-machine. Their
vulnerability state is `unknown`, not `trusted`. Swift package URLs
are recorded the same way: `public-only` does not treat Git hosts as a
public registry.

pnpm often omits tarball URLs. Securock does **not** assume
`registry.npmjs.org` in that case. It only treats a package as public when
a tarball origin or an explicit registry setting (environment, project
`.npmrc`, or user `~/.npmrc`) proves a public origin. The same fail-closed
rule applies to NuGet (`NuGet.Config` package sources), PDM (lockfile file
URLs), Mix (`mix.lock` repository identity), and Gradle (`gradle.lockfile`
has no repository URL). Mixed public and private sources are treated as
unknown.

## Modes

```sh
securock scan --offline
securock scan --network public-only
securock scan --network allow-all
```

`--offline` skips all remote lookups. `allow-all` sends every dependency
name and version to OSV and, for npm, the registry. Use it only when that
disclosure is acceptable.

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
