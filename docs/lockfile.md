# Lockfile

`securock.lock` is the canonical trust snapshot for a project.

See [specification.md](specification.md) for the v1 format.

## Commands

```bash
securock lock
securock diff
securock verify
```

`lock` writes the file. `diff` compares the current tree to the locked
subjects and prints trust drift. `verify` fails when subjects are added,
removed, digest-changed, or untrusted.

## Identity

Subject identity is `ecosystem:name`. Version is recorded on the
artifact, not in the identity. A bump from `react@19.1.0` to
`react@19.2.0` is a change to one subject, not a delete plus an add.

## Determinism

The same inputs must produce the same bytes. The lockfile does not
store timestamps, absolute paths, or advisory `modified` times.
