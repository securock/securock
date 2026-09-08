# Contributing

Thanks for helping improve Securock.

## Development

```bash
go test ./...
go vet ./...
```

The CLI entrypoint is `cmd/securock`. Public lockfile types live in
`pkg/lockfile`.

## Pull requests

- Keep changes small and focused.
- Use Conventional Commits, lowercase subject only.
- Include tests for parser, lockfile, or trust-behavior changes.
- Do not add host-specific fields to `securock.lock`.

## Scope

v0.1 treats npm/pnpm as the stable evidence path. Cargo, Go, and PyPI
parsers exist, but provenance and signature evidence for those
ecosystems is experimental.
