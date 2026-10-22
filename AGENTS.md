# AGENTS.md

Instructions for AI coding agents working in this repository. Humans: read
[CONTRIBUTING.md](CONTRIBUTING.md), which this file builds on. If the two
disagree, CONTRIBUTING.md wins; if a user's request disagrees with this file,
the user wins.

## Project

Securock is a Go CLI that records the _trust decision_ for each dependency in
`securock.lock` and fails CI when that state drifts. Pre-1.0, Go version in
`go.mod`, no CGO. Docs: https://securock.dev

## Layout

- `cmd/securock`: entrypoint. `internal/cli`: one cobra command per file,
  registered in `root.go`.
- `internal/ecosystem/<resolver>`: one lockfile parser per package manager.
  `internal/evidence`, `internal/osv`: registry and OSV lookups.
- `internal/{scanner,trust,audit,doctor,finding,exceptions,sbom,vex,license,typosquat,reachability}`:
  the logic behind the commands.
- `pkg/lockfile`, `pkg/policy`, `pkg/exceptions`: public types and validation.
- `schemas/`: JSON schemas, embedded and used to validate command output.
- `docs/`, `website/` (VitePress), `examples/`, `action/` + `action.yml`.

## Commands

Run these from the repository root. CI runs the same checks, so a failure here
is a failure there.

```bash
gofmt -l cmd internal pkg schemas        # must print nothing
go vet ./...
go test ./...
go test -race ./...
go mod tidy && git diff --exit-code      # no dependency drift
bash action/run_test.sh                  # when action/ or action.yml changed
GOOS=windows go vet ./...                # CI smoke-tests Windows
for d in examples/*/; do go run ./cmd/securock verify --offline "$d"; done
```

Docs, when `website/` or any `*.md` it renders changed:

```bash
cd website && npm ci && npm run docs:build
npx prettier --write <changed website/**/*.md>   # website pages are prettier-formatted
```

Fuzz a parser you touched: `go test -fuzz=Fuzz -fuzztime=30s ./internal/ecosystem/npm`

## Before you commit

Do not hand a failure to CI. Run the checks above that apply to your change,
fix everything they report, and only then commit. Format and `go vet` are
always required. If a check cannot run (no network, missing tool), say so in
your final message instead of committing as if it passed.

## Code style

- Match the surrounding code: naming, comment density, idiom. Comments explain
  _why_, not what.
- No pictographic emoji (✅ ❌ ⚠️ 🚀 and the like) in code, CLI output, docs,
  comments, or commit messages. Plain symbols such as box-drawing lines
  (`─ │ ├ └`) and arrows (`→`) are fine.
- Output must be deterministic: sort, no timestamps, no absolute paths. A
  lockfile written twice from the same input is byte-identical.
- Fail closed: evidence that was not collected is `unknown`, never `checked` or
  `verified`. Do not infer safety from absence of data.
- New `securock.lock` fields are optional. Changing the lockfile means updating
  `pkg/lockfile` (`document.go`, `validate.go`, `canonicalize.go`),
  `schemas/securock-lock.schema.json`, the docs, and bumping the lockfile
  version if older releases cannot read it. No host-specific fields.
- Prefer the standard library. A new dependency needs a reason in the PR.

## Testing

- Add tests for any parser, lockfile, policy, or trust change. Table tests,
  external `_test` packages (`package foo_test`).
- No real network in tests: use `httptest` and the fake clients already in
  `internal/scanner` and `internal/evidence`.
- CLI tests use `runCLI` and `isolateHome` (`internal/cli/schema_test.go`) and
  run `--offline`. JSON output is validated with `schemas.Validate`.
- A test must fail without the change it covers. Do not weaken or delete an
  existing assertion to make a test pass.

## Network and privacy

Default mode is `public-only`: only known public registries are queried. A new
external host needs an entry in `docs/privacy.md` **and**
`website/reference/privacy.md`, and must respect `--offline` and the registry
allowlist.

## Docs

A new command, flag, or policy rule updates `README.md` and
`website/guide/usage.md` (or `policy.md`), plus `schemas/` for new JSON output.
`docs/` and `website/reference/` mirror each other; change both.

## Git

- Conventional Commits: `feat`, `fix`, `docs`, `test`, `chore`, `ci`,
  `refactor`, `perf`. No scope.
- **Write a subject line only: no commit body.** It is short, all lowercase,
  imperative, with no trailing period: `feat: add vex export`,
  `fix: reduce typosquat noise`. Put the reasoning in the pull request, not in
  the commit.
- One logical change per commit. Keep PRs small and focused.
- Do not push, force-push, or open a PR unless asked. Never rewrite history
  that has been pushed. Do not skip hooks or checks.
- Squash merges append `(#123)` to the subject; do not add it yourself.

## Boundaries

- Never commit secrets, tokens, or private data. Never paste them into prompts.
- Do not edit `.github/rulesets/`, `LICENSE`, or release config without being
  asked.
- Do not hand-edit a `securock.lock` fixture: regenerate it with
  `securock lock --offline --no-fail <dir>`.
- Do not commit build output (`dist/`, `website/.vitepress/dist`, binaries).
- You are not the author of record: a human must be able to explain and own
  every change you make. Read the AI rules in CONTRIBUTING.md.
