# Securock

**A lockfile for trust, not just versions.**

| [Docs](https://securock.dev) | [Install](#install) | [Quick start](#quick-start) | [Usage](#usage) | [Ecosystems](#supported-ecosystems) | [Privacy](docs/privacy.md) |
| ---------------------------- | ------------------- | --------------------------- | --------------- | ----------------------------------- | -------------------------- |

Language lockfiles pin versions. `securock.lock` pins the _trust
decision_ you accepted for those versions.

Securock records digest, provenance, signature, vulnerability,
malicious-package, capability, behavior, ownership, and trust-chain
evidence for each artifact, then fails CI when that trust state drifts.

```text
securock lock     # snapshot the current tree
# …bump a dependency the way you already do…
securock diff     # see version, digest, evidence, and trust reasons
securock verify   # fail CI on the same drift
```

> `trusted` means the artifact passed the **active policy**. It is not a
> claim that a package is safe. Unchecked vulnerabilities are `unknown`,
> not trusted.

## Why

A dependency bump can change more than a version string: the artifact
digest, known vulnerabilities, or whether provenance is even present.
Those changes are easy to miss in a language lockfile diff.

## Features

**Lockfile and CI**

- Deterministic `securock.lock` (no timestamps, no absolute paths)
- `diff` / `verify` on artifact identity, not just package name
- GitHub Action that can run an attested release binary
- JSON reports (`--format json`) with exit `0` / `1` / `2`

**Evidence**

- npm evidence for provenance, signatures, capabilities, granular
  behavior, ownership, and source→build→artifact trust chain
- PyPI Integrity API attestations (PEP 740) with local Sigstore
  re-verification to provenance/signature `verified`
- OpenSSF Malicious Packages (`MAL-*`) recorded separately from CVEs
- Vulnerabilities carry CVSS-derived severity and the version that fixes them
- Release health (deprecated, release day, license) for npm and PyPI,
  typosquat-suspect names, and optional `health` and `licenses` policy gates
- `explain` prints a trust checklist for one package

**Triage and policy**

- `accept` records reviewed findings with a reason and expiry in
  `.securock/exceptions.yaml`; `audit` suppresses them until they lapse
- `audit --min-release-age` holds back releases that are too new
- `--reachability` marks each vulnerability reachable, unreachable
  (development-only), or unknown from the dependency graph, so `audit`
  stops failing on test tooling

**Source code analysis**

- `sast` follows untrusted data (HTTP input, command-line arguments) through
  assignments, fields, closures, and calls across functions and files to SQL,
  command, code, path, request, response, and deserialization sinks, and prints
  the path it took. Go, JavaScript/TypeScript, Python, Java, PHP, and Ruby,
  fully offline. It also checks Dockerfiles, Kubernetes and Compose manifests,
  Terraform, and GitHub Actions workflows for unsafe settings, and scans every
  text file for committed credentials. A file it cannot parse is reported
  rather than skipped

**Exports**

- CycloneDX 1.6 / SPDX 2.3 SBOM export with trust evidence, and
  `sbom verify` against the lockfile
- `vex export` turns accepted vulnerabilities into OpenVEX or CycloneDX VEX

**Privacy**

- Default network mode is `public-only`: private registries,
  `GOPRIVATE` / `GONOPROXY` modules (including `go env -w`), and custom
  or ambiguous `GOPROXY` lists stay on-machine ([privacy](docs/privacy.md))

## Status

Pre-1.0. All resolvers are stable.

- **npm, pnpm, Yarn, Bun, Deno** collect provenance, signature, capability,
  behavior, ownership, and trust-chain evidence from the npm registry.
- **PyPI (uv / Poetry / PDM)** collects Integrity API attestations and
  locally re-verifies PEP 740 Sigstore envelopes to provenance/signature
  `verified` when the signer identity, filename, digest, signature, and
  transparency log check out.
- **Other resolvers** query OSV when their package source can be proven
  public. Otherwise vulnerability and malicious-package evidence remain
  `unknown`, and unsupported evidence axes stay `unknown`.

### Compatibility

`version: 1` and `version: 2` lockfiles are migrated to `version: 3` in
memory on `diff` / `verify`. Run `securock lock` to write a refreshed v3
file.

A v3 file is refused by older releases (they decode strictly), so update
every machine and CI job that runs securock before committing one.

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

`--offline` skips OSV and registry lookups. The default policy treats
unchecked vulnerabilities and malicious reports as `unknown`, so the
first `lock` needs `--no-fail`. The committed `securock.lock` in that
directory is that snapshot.

The same loop is available for pnpm, Yarn, Bun, uv, Poetry, Go, and
Cargo under [`examples/`](examples/).

## Usage

| Command            | What it does                                                |
| ------------------ | ----------------------------------------------------------- |
| `securock scan`    | Inspect the tree (default if you pass no command)           |
| `securock lock`    | Write `securock.lock`                                       |
| `securock diff`    | Show trust drift vs the lockfile                            |
| `securock update`  | Review trust changes, then refresh the lockfile             |
| `securock verify`  | Fail on trust-relevant drift                                |
| `securock explain` | Explain why a package is trusted                            |
| `securock audit`   | Report dependency findings by severity                      |
| `securock sast`    | Find vulnerabilities in your own source code                |
| `securock doctor`  | Check the project setup for security problems               |
| `securock sbom`    | Export `securock.lock` as CycloneDX or SPDX, or verify one  |
| `securock accept`  | Accept a finding until a date, with a reason                |
| `securock vex`     | Export accepted vulnerabilities as OpenVEX or CycloneDX VEX |
| `securock version` | Print the build version                                     |

| Flag / exit             | Meaning                                                                                        |
| ----------------------- | ---------------------------------------------------------------------------------------------- |
| `--network public-only` | Default. Public registries only (`offline`, `allow-all` also valid)                            |
| `--offline`             | Skip remote lookups; remote evidence stays `unknown`                                           |
| `--policy`              | Path to a policy file                                                                          |
| `--profile`             | Built-in policy profile: `default` or `strict` (not with `--policy`)                           |
| `--lock`                | Path to `securock.lock` (for `lock` / `diff` / `update` / `verify`)                            |
| `--format json`         | Stable JSON on `scan`, `diff`, `verify`, and `explain`                                         |
| `--format sarif`        | SARIF 2.1.0 on every report command, for GitHub code scanning                                  |
| `--output`              | Write the report to a file instead of stdout (also on exit `1`)                                |
| `--min-release-age`     | `audit`. Report npm and PyPI releases newer than this, such as `7d`                            |
| `--fail-on`             | `audit`, `sast` and `doctor`. Exit `1` at or above this severity (default `high`)                      |
| `--exceptions`          | Accepted-findings file (default `.securock/exceptions.yaml`)                                   |
| `--reachability`        | Record package scope and dependencies; mark vulnerabilities reachable, unreachable, or unknown |
| `--no-fail`             | Always exit `0`                                                                                |
| Exit `0`                | Success / no trust drift                                                                       |
| `1`                     | Trust violation                                                                                |
| `2`                     | Configuration or operational error                                                             |

```yaml
# securock.lock (abridged)
version: 3
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
      malicious:
        state: unknown
      capabilities:
        state: checked
        network: false
        filesystem: none
        environment: false
        shell: false
        native_code: false
        install_scripts: false
      behavior:
        state: checked
      ownership:
        state: checked
        publisher: alice <alice@example.com>
        maintainers:
          - alice
      chain:
        state: present
        source: github.com/facebook/react
        commit: abc123
        workflow: release.yml
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
          command: all # scan+diff+verify (default); also scan, diff, verify, both
          # profile: strict
          # policy: .securock/policy.yaml
```

Default `command: all` runs `scan` (current policy violations), then
`diff` and `verify` (trust drift). Use `both` for drift-only checks.
`policy` and `profile` are mutually exclusive.

The action writes a trust report to `$GITHUB_STEP_SUMMARY` even when
it cannot comment on a fork PR.

## Supported ecosystems

### Stable

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

Deno `deno.lock` v5 is the stable target. v3/v4 are supported for
compatibility. Deno npm packages use OSV and npm evidence. JSR and
HTTPS URL artifacts are stable to parse; OSV does not cover them yet,
so vulnerability state stays `unknown`. Gradle records Maven
coordinates from `gradle.lockfile` but does not prove a registry, so
OSV is not queried in `public-only`.

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
