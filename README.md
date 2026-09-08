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
```

Or build from source:

```bash
go install github.com/securock/securock/cmd/securock@latest
```

## Usage

```bash
securock scan
securock lock
securock verify
securock version
```

`scan` is the default command. Use `--offline` to skip OSV lookups.

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
    trust:
      status: trusted
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
