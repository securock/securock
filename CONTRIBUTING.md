# Contributing

Thanks for helping improve Securock.

## Development

```bash
go test ./...
go test -race ./...
go vet ./...
```

Parser packages include Go fuzz tests. Seed corpus runs with `go test`.
Longer campaigns:

```bash
go test -fuzz=Fuzz -fuzztime=30s ./internal/ecosystem/npm
```

The CLI entrypoint is `cmd/securock`. Public lockfile types live in
`pkg/lockfile`.

The docs site is VitePress in `website/`:

```bash
cd website
npm install
npm run docs:dev
```

## Pull requests

- Keep changes small and focused.
- Use Conventional Commits, lowercase subject only.
- Include tests for parser, lockfile, or trust-behavior changes.
- Do not add host-specific fields to `securock.lock`.

## Scope

v0.1 treats npm, pnpm, Yarn, and Bun as the stable evidence path. Other
lockfile parsers exist, but provenance and signature evidence for those
ecosystems is experimental.
