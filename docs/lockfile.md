# Lockfile

`securock.lock` is the canonical trust snapshot for a project.

See [specification.md](specification.md) for the v2 format. Older
`version: 1` files are migrated in memory on read; run `securock lock`
to persist a refreshed v2 snapshot.

## Commands

```bash
securock scan
securock lock
securock diff
securock verify
securock explain <package>
securock version
```

`scan` inspects the tree (and is the default command). `lock` writes
the file. `diff` shows what changed. `verify` uses the same comparison
and fails when there is trust-relevant drift. `explain` prints a trust
checklist for one package: digest, source, provenance, signature, trust
chain, ownership, capabilities, vulnerabilities, and malicious-package
reports.

Shared flags: `--offline`, `--network`, `--policy`, `--profile`, `--lock`,
`--format`, `--no-fail`.

Exit codes:

- `0` success / no trust drift
- `1` trust violation
- `2` configuration or operational error

`scan --format json` emits the lock document. `diff` and `verify`
print a `schema_version: 1` report. `explain --format json` emits the
matched artifacts. JSON Schemas live in `schemas/`.

## Identity

Subject identity is `ecosystem:name`. Version is recorded on the
artifact, not in the identity. A bump from `react@19.1.0` to
`react@19.2.0` is a change to one subject, not a delete plus an add.

## Determinism

The same inputs must produce the same bytes. The lockfile does not
store timestamps, absolute paths, or advisory `modified` times.
