# Securock

Supply-chain trust layer for software dependencies.

Securock reads language lockfiles, evaluates each artifact, and writes a
language-agnostic `securock.lock`. Go is the implementation language; it is not
the only ecosystem Securock understands.

```
package-lock.json
pnpm-lock.yaml
Cargo.lock
go.sum
uv.lock
        ↓
   Dependency
        ↓
    Artifact
        ↓
    Evidence
        ↓
 Trust evaluation
        ↓
   securock.lock
```

## Install

```bash
curl -fsSL https://securock.sh/install | sh
curl -fsSL https://securock.sh/install | sh -s -- --version v0.1.0-alpha.1
```

Verify a downloaded archive or the extracted binary against GitHub
artifact attestations:

```bash
gh attestation verify securock_darwin_arm64.tar.gz --repo securock/securock
gh attestation verify ./securock --repo securock/securock
```

Homebrew, from this repository (HEAD):

```bash
brew tap securock/securock https://github.com/securock/securock
brew install --HEAD securock
```

Or build from source:

```bash
go install github.com/securock/securock/cmd/securock@latest
```

## Usage

```bash
securock scan
securock lock
securock diff
securock verify
securock version
```

`diff` and `verify` are the core loop. `scan` inspects a tree, `lock`
writes `securock.lock`, `diff` shows trust drift after a dependency
change, and `verify` fails when the current tree does not match the
locked trust state.

`scan` is the default command. `--offline` skips OSV and registry
lookups and records vulnerability state as `unknown`, which is not
trusted under the default policy. `--network public-only` (default)
does not send private-registry package names off-machine. See
[Privacy](docs/privacy.md).

`--format json` is a stable API on `scan`, `diff`, and `verify`.
Exit `1` is a trust violation. Exit `2` is a configuration or
operational error.

Walk through `lock → update → diff → verify` in
[`examples/npm`](examples/npm).

## GitHub Action

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
          version: v0.1.0-alpha.1
```

Pin the action to a full commit SHA. After a tagged release exists, set
`version` so the action runs that attested binary. The action writes a
trust report to `$GITHUB_STEP_SUMMARY` even when it cannot comment on a
fork PR.

## Lockfile

```yaml
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

## Supported ecosystems

| Ecosystem | Resolver | Lockfile | Status |
| --- | --- | --- | --- |
| npm | npm | `package-lock.json` | stable target |
| npm | pnpm | `pnpm-lock.yaml` | stable target |
| cargo | cargo | `Cargo.lock` | experimental |
| go | go | `go.sum` | experimental |
| pypi | uv | `uv.lock` | experimental |

## License

Apache-2.0

## Docs

- [securock.dev](https://securock.dev)
- [Lockfile specification](docs/specification.md)
- [Trust model](docs/trust-model.md)
- [Privacy](docs/privacy.md)
- [Threat model](docs/threat-model.md)
- [GitHub rulesets](docs/github-rulesets.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)

