<p align="center">
  <img src="docs/assets/logo.svg" alt="Securock" height="64">
</p>

**Security for dependencies, source code, secrets, and infrastructure.**

[Documentation](https://securock.dev) · [Install](#install) ·
[Quick start](#quick-start) · [GitHub Action](#github-action) ·
[Enterprise operations](docs/enterprise.md)

Securock brings security findings into one report and helps teams track them
through review, remediation, and verification. Use it locally, in CI, or with
an authenticated team control plane.

Language lockfiles pin versions. `securock.lock` pins the **trust decision**
you accepted for those versions, so changes in artifact identity, evidence,
and policy decisions become visible in code review and enforceable in CI.

## Features

- **Scan applications.** Analyze source code, secrets, and infrastructure as
  code offline; combine dependency findings and imported SARIF reports with
  `security`. See [source analysis](website/guide/sast.md) and
  [unified reports](website/guide/usage.md#security).
- **Inspect running environments.** Check HTTP security settings, test explicit
  API authorization contracts and explicit authenticated HTTP scenarios
  (`dast-scenario`), inspect cloud configuration, and discover
  Kubernetes workload image identities. See the
  [scanner reference](website/guide/usage.md).
- **Track dependency trust.** Record deterministic snapshots, review drift,
  inspect provenance and signatures, and export CycloneDX/SPDX SBOMs and VEX.
  Use `reachability SYMBOLS.json --project . --entry example.org/app.main`
  for offline Go call paths to explicitly identified advisory APIs.
  See the [trust model](docs/trust-model.md).
- **Manage remediation.** Compare baselines, assign owners and deadlines,
  prioritize findings, and test supported Go, Python and JavaScript TLS fixes
  before optional PR creation.
  See [remediation workflows](website/guide/usage.md#finding-lifecycle-and-responsibility).
- **Work as a team.** Use OIDC SSO, role-based access, SCIM user provisioning,
  private runners, expiring approvals, signed audit records, encryption-key rotation with `control-rekey`, and SCM/ticket
  connectors. See [enterprise operations](docs/enterprise.md).
- **Verify delivered software.** Bind releases to signed artifact and SBOM
  identities, track customer impact, and detect deployment drift. See
  [release assurance](website/guide/usage.md#delivered-release-assurance).

## Install

### Installer

```sh
curl -fsSL https://securock.sh/install | sh
```

The installer checks SHA-256 and requires `gh` to verify GitHub attestations
unless `SKIP_ATTESTATION=1` is set.

### Homebrew

Build the repository's HEAD:

```sh
brew tap securock/securock https://github.com/securock/securock
brew install --HEAD securock
```

### From source

From a checkout of this repository, using the Go version in `go.mod`:

```sh
go install ./cmd/securock
```

See the [installation guide](website/guide/install.md) for release verification
and other installation options.

## Quick start

### Inspect a project

Run in a directory containing your source and package-manager lockfile:

```sh
securock security .
securock security . --offline
securock security . --format sarif --output security.sarif
```

`security` does not require or write `securock.lock`. If there is no supported
package-manager lockfile, source analysis still runs and dependency coverage is
marked unchecked. The default failure threshold is `high`.

Reports support text, JSON, SARIF, JUnit, and Markdown. Use `--help` on any
command for its options, or read the [usage guide](website/guide/usage.md).

### Track dependency trust

```sh
securock lock
# Update dependencies with your package manager, then review the changes.
securock diff
securock verify
```

Review policy violations before accepting a snapshot. Commit `securock.lock`
to enforce the reviewed trust state in CI. For a reproducible offline
walkthrough, see the [quick-start guide](website/guide/quickstart.md) and
[example projects](examples/).

> `trusted` means an artifact passed the active policy, not that it is safe.
> Evidence that was not collected remains `unknown`.

## GitHub Action

Use the action to check dependency policy and trust drift. Replace
`<commit-sha>` with a reviewed Securock commit.

```yaml
permissions:
  contents: read
  attestations: read
  pull-requests: write

jobs:
  securock:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262
      - uses: securock/securock@<commit-sha>
        with:
          command: all
```

`all` runs `scan`, `diff`, and `verify`. Set `command: security` for the unified
report of dependencies, source, secrets, and infrastructure. The action also
supports SARIF uploads, SBOM exports, and PR reports through separate options.
See the [action guide](website/guide/action.md) for configuration and permissions.

## Supported ecosystems

These package managers have stable lockfile parsers. Evidence availability
varies by registry and resolver; parsing support does not imply that every
trust check is available.

| Ecosystem               | Package managers           |
| ----------------------- | -------------------------- |
| JavaScript / TypeScript | npm, pnpm, Yarn, Bun, Deno |
| Python                  | uv, Poetry, PDM, Pipenv    |
| Go / Rust               | Go modules, Cargo          |
| Java / Kotlin           | Gradle dependency locks    |
| PHP / Ruby              | Composer, Bundler          |
| .NET                    | NuGet                      |
| Swift / Apple           | SwiftPM, CocoaPods         |
| C / C++                 | Conan 2                    |
| R / Julia               | renv, Julia                |
| Haskell / Dart / Elixir | Cabal, Pub, Mix            |

npm-family resolvers collect npm trust evidence. PyPI resolvers can verify
PEP 740 attestations. Public Go, Cargo and NuGet releases also collect available
release-date, license and deprecation metadata. Other evidence may remain `unknown`, including when a
package's public source cannot be established. See the
[ecosystem guide](website/guide/ecosystems.md) for lockfile formats, supported
versions, and resolver-specific limits.

Use `--package-attestations MANIFEST --package-signer-key PUBLIC_KEY_FILE`
with dependency commands to verify local signed SLSA claims for any ecosystem,
including offline scans. Signer changes produce policy drift.

## Status and privacy

Securock is pre-1.0. Use `quality --per-rule --max-fpr 0.02` to gate labeled fixtures by rule.
Source-analysis coverage and accuracy depend on the
language, framework, and rule; see the
[analysis guide](website/guide/sast.md#how-accurate-is-sast) and
[benchmark methodology](docs/sast-benchmarks.md).

The team control plane is a single-instance backend. Legacy snapshots have a
64 MiB state limit; opt-in encrypted bbolt storage commits individual tenants
with a 64 MiB limit per tenant. Read the [deployment and assurance guide](docs/enterprise.md) before
operating it for a team.

The default network mode is `public-only`. `--offline` skips remote lookups;
live application and cloud collection require explicit `--network allow-all`.
See [Privacy](docs/privacy.md) for destinations, credentials, and data handling.

### Exit codes

| Code | Meaning                                                   |
| ---- | --------------------------------------------------------- |
| `0`  | Successful operation; no blocking findings or trust drift |
| `1`  | Blocking findings, trust drift, or a failed policy gate   |
| `2`  | Configuration, operational, or incomplete-analysis error  |

Operational errors still fail with `--no-fail`. Lockfile v1/v2 documents are
migrated to v3 in memory; older releases cannot read v3 files. See the
[lockfile reference](docs/lockfile.md) before upgrading shared CI workflows.

## Documentation

| Task                                | Guide                                                                                 |
| ----------------------------------- | ------------------------------------------------------------------------------------- |
| Explore commands and options        | [Usage](website/guide/usage.md)                                                       |
| Configure gates and exceptions      | [Policy](website/guide/policy.md)                                                     |
| Integrate reports with CI           | [Report formats](website/guide/reports.md) · [GitHub Action](website/guide/action.md) |
| Deploy and operate team services    | [Enterprise operations](docs/enterprise.md)                                           |
| Understand evidence and limitations | [Trust model](docs/trust-model.md) · [Threat model](docs/threat-model.md)             |
| Work with structured output         | [Lockfile specification](docs/specification.md) · [JSON schemas](schemas/)            |

The hosted documentation is available at [securock.dev](https://securock.dev).
Repository links describe the version in this checkout.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development and review requirements,
and the [Code of Conduct](CODE_OF_CONDUCT.md) for community guidelines.

## Security

Report vulnerabilities privately through
[GitHub Security Advisories](https://github.com/securock/securock/security/advisories/new).
See [SECURITY.md](SECURITY.md) for the reporting policy.

## License

[Apache License 2.0](LICENSE).
