# Contributing

Thanks for helping improve Securock.

## Development

Run these before every commit. CI runs the same checks (plus `govulncheck`
and a release snapshot), so anything that fails here fails there:

```bash
gofmt -l cmd internal pkg schemas   # must print nothing
go vet ./...
go test ./...
go test -race ./...
go mod tidy && git diff --exit-code
bash action/run_test.sh             # if action/ or action.yml changed
GOOS=windows go vet ./...           # CI also tests Windows
for d in examples/*/; do go run ./cmd/securock verify --offline "$d"; done
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
npm ci
npm run docs:dev      # or: npm run docs:build
npx prettier --write <the website pages you changed>
```

## Commits and pull requests

- Keep changes small and focused: one logical change per commit.
- Use Conventional Commits (`feat`, `fix`, `docs`, `test`, `chore`, `ci`,
  `refactor`, `perf`), no scope.
- Write a subject line only, with no commit body. Keep it short and all
  lowercase, in the imperative, with no trailing period: `feat: add vex export`.
  Explain the reasoning in the pull request description instead.
- Include tests for parser, lockfile, or trust-behavior changes.
- Do not add host-specific fields to `securock.lock`.
- Fill in the pull request template: a summary, and the checks you ran.

## AI-assisted contributions

Using AI tools to write code, tests, or docs is fine. Using them does not
change who is responsible for the result: you are. A pull request that uses AI
help must meet all of the following.

**You can explain it.** You understand every line you submit: what it does, why
it is written that way, and what else you considered. During review you answer
questions yourself. Pasting a reply from an assistant is not an answer. If you
cannot explain a change, do not submit it.

**You take responsibility for it.** You have read the whole diff, and you stand
behind its correctness, its security, and its licensing. Do not submit code you
suspect was copied from a project whose license is incompatible with this one.
Do not put secrets, tokens, or private data into AI tools.

**You ran the checks locally first.** Formatting, `go vet`, tests, and the rest
of the list under [Development](#development) must pass on your machine
_before_ you commit, not after CI reports a failure. This applies to AI agents
acting on your behalf: they must run the checks, fix what they report, and only
then commit. An agent that cannot run a check must say so, and you must run it.
CI is a safety net, not a linter to iterate against.

**You wrote tests that mean something.** Generated tests must exercise real
behavior and fail without the change they cover. Do not delete or weaken an
existing test to make a change pass.

**You keep it reviewable.** Submit small, focused changes. A large, generated,
or unexplained diff will be asked to be split, and maintainers may close a pull
request that looks like unreviewed AI output.

AI agents working in this repository should read [AGENTS.md](AGENTS.md), which
lists the commands and conventions above in one place. Agents follow the same
commit message rules as everyone else.

## Scope

All lockfile resolvers are stable. Provenance, signature, capability,
behavior, ownership, and trust-chain evidence is collected from the npm
registry for npm, pnpm, Yarn, Bun, and Deno; other ecosystems record
`unknown` for those fields. Vulnerability and malicious-package evidence
comes from OSV when the package source is proven public.
