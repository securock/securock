# Securock

A lockfile for trust, not just versions.

Language lockfiles pin versions. `securock.lock` pins the _trust
decision_ you accepted for those versions.

Securock records digest, provenance, signature, and vulnerability
evidence for each artifact, then fails CI when that trust state
drifts.

**Docs:** [securock.dev](https://securock.dev)

**Status:** pre-1.0. npm, pnpm, Yarn, Bun, and Deno are stable. Other
resolvers parse today; their provenance and signature evidence is still
experimental.

## Why

A dependency bump can change more than a version string: the artifact
digest, known vulnerabilities, or whether provenance is even present.
Those changes are easy to miss in a language lockfile diff.

```text
securock lock     # snapshot the current tree
# …bump a dependency the way you already do…
securock diff     # see version, digest, evidence, and trust reasons
securock verify   # fail CI on the same drift
```

`trusted` means the artifact passed the **active policy**. It is not a
claim that a package is safe. Unchecked vulnerabilities are `unknown`,
not trusted.

## Features

- Deterministic `securock.lock` (no timestamps, no absolute paths)
- `diff` / `verify` on artifact identity, not just package name
- Default network mode is `public-only`: private registries and
  `GOPRIVATE` modules stay on-machine ([privacy](docs/privacy.md))
- GitHub Action that can run an attested release binary
- JSON reports (`--format json`) with exit `0` / `1` / `2`

## Install

### Script

```bash
curl -fsSL https://securock.sh/install | sh
```

The installer checks SHA-256. Unless `SKIP_ATTESTATION=1` is set, it
also requires `gh` and verifies GitHub attestations.

```bash
gh attestation verify securock_darwin_arm64.tar.gz --repo securock/securock
gh attestation verify ./securock --repo securock/securock
```

### Homebrew

HEAD, builds from this repo:

```bash
brew tap securock/securock https://github.com/securock/securock
brew install --HEAD securock
```

### From source

```bash
go install github.com/securock/securock/cmd/securock@latest
```

## Quick start

```bash
git clone https://github.com/securock/securock.git
cd securock/examples/npm

securock lock --offline --no-fail
securock verify --offline

cp after/package-lock.json package-lock.json
securock diff --offline
securock verify --offline   # fails until you accept the new tree
```

`--offline` skips OSV. The default policy treats unchecked
vulnerabilities as `unknown`, so the first `lock` needs `--no-fail`.
The committed `securock.lock` in that directory is that snapshot.

## Usage

| Command            | What it does                                      |
| ------------------ | ------------------------------------------------- |
| `securock scan`    | Inspect the tree (default if you pass no command) |
| `securock lock`    | Write `securock.lock`                             |
| `securock diff`    | Show trust drift vs the lockfile                  |
| `securock verify`  | Fail on trust-relevant drift                      |
| `securock version` | Print the build version                           |

| Flag / exit | Meaning |
| ----------- | ------- |
| `--network public-only` | Default. Public registries only |
| `--offline` | Skip remote lookups; vulnerabilities stay `unknown` |
| `--format json` | Stable API on `scan`, `diff`, and `verify` |
| Exit `0` | Success / no trust drift |
| `1` | Trust violation |
| `2` | Configuration or operational error |

```yaml
# securock.lock (abridged)
version: 1
artifacts:
  - subject:
      ecosystem: npm
      name: react
    version: 19.2.0
    digest: sha256:...
    source:
      resolver: npm
      registry: https://registry.npmjs.org
    evidence:
      provenance: unknown
      signature: unknown
      vulnerabilities:
        state: unknown
    trust:
      status: unknown
```

## GitHub Action

Pin the action to a commit SHA.

```yaml
permissions:
  contents: read
  attestations: read
  pull-requests: write

jobs:
  securock:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0
      - uses: securock/securock@<commit-sha>
        with:
          command: both
```

The action writes a trust report to `$GITHUB_STEP_SUMMARY` even when
it cannot comment on a fork PR.

## Supported ecosystems

### Stable

| Ecosystem | Resolver | Lockfile            |
| --------- | -------- | ------------------- |
| npm       | npm      | `package-lock.json` |
| npm       | pnpm     | `pnpm-lock.yaml`    |
| npm       | yarn     | `yarn.lock`         |
| npm       | bun      | `bun.lock`          |
| npm       | deno     | `deno.lock`         |
| jsr       | deno     | `deno.lock`         |
| url       | deno     | `deno.lock`         |

Deno `deno.lock` v5 is the stable target. v3/v4 are supported for
compatibility. Deno npm packages use OSV and npm evidence. JSR and
HTTPS URL artifacts are stable to parse; OSV does not cover them yet,
so vulnerability state stays `unknown`.

### Experimental

| Ecosystem | Resolver | Lockfile             |
| --------- | -------- | -------------------- |
| cargo     | cargo    | `Cargo.lock`         |
| go        | go       | `go.sum`             |
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

## Documentation

- [Lockfile specification](docs/specification.md)
- [Trust model](docs/trust-model.md)
- [Privacy](docs/privacy.md)
- [Threat model](docs/threat-model.md)
- [GitHub rulesets](docs/github-rulesets.md)

## Contributing

Issues and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md)
and the [Code of Conduct](CODE_OF_CONDUCT.md).

```bash
go test ./...
go test -race ./...
go vet ./...
```

Commits follow [Conventional Commits](https://www.conventionalcommits.org/),
lowercase subject only.

## Security

Report vulnerabilities privately via
[GitHub Security Advisories](https://github.com/securock/securock/security/advisories/new).
Do not open a public issue for an unreleased vulnerability.
See [SECURITY.md](SECURITY.md).

## License

This project is licensed under the Apache License, Version 2.0.
See the [LICENSE](LICENSE) file for details.
