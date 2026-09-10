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

All lockfile resolvers are stable. Provenance and signature evidence is
collected from the npm registry for npm, pnpm, Yarn, Bun, and Deno; other
ecosystems record `unknown` for provenance and signature.
