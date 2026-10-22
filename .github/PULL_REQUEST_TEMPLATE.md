## Summary

<!-- What changes, and why. One short paragraph or a few bullets. The commit message is a single line, so the reasoning belongs here. -->

-

## Test plan

<!-- How you checked it: the commands you ran and what you saw. Paste output only when it helps. -->

-

## Impact

<!-- Tick what applies. Delete the rest. -->

- [ ] Changes the `securock.lock` format (schema, version, migration)
- [ ] Changes CLI flags, commands, or JSON output (`schemas/` updated)
- [ ] Changes policy rules or trust evaluation
- [ ] Contacts a new external host (`docs/privacy.md` and `website/reference/privacy.md` updated)
- [ ] Docs only

## Checklist

- [ ] Small and focused; commit messages are a lowercase subject line only
- [ ] Ran locally before committing: `gofmt -l cmd internal pkg schemas` (no output), `go vet ./...`, `go test ./...`, `go test -race ./...`, `go mod tidy` (no diff)
- [ ] Added or updated tests for parser, lockfile, or trust behavior
- [ ] Updated docs and the README for user-visible changes
- [ ] I can explain every change in this pull request and take responsibility for it

## Notes for reviewers

<!-- Optional: risks, trade-offs, or where to look first. -->
