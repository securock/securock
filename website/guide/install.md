---
title: Install
description: Install Securock on macOS or Linux with the attested installer, Homebrew, or Go, and verify release archives with GitHub attestations.
---

# Install

Install the Securock CLI on macOS or Linux (amd64 / arm64), then confirm
the binary is on your `PATH`.

## Installer script

```sh
curl -fsSL https://securock.sh/install | sh
```

Pin a release tag:

```sh
curl -fsSL https://securock.sh/install | sh -s -- --version v0.2.1
```

The script downloads `securock_OS_ARCH.tar.gz` from GitHub Releases
(for example `securock_darwin_arm64.tar.gz`), checks `checksums.txt`
(SHA-256), and verifies GitHub attestations with `gh` unless
attestation is skipped.

| Option / env                | Meaning                                                                  |
| --------------------------- | ------------------------------------------------------------------------ |
| `--version TAG`             | Install that release instead of latest                                   |
| `--skip-attestation`        | Skip `gh attestation verify`                                             |
| `SKIP_ATTESTATION=1`        | Same as `--skip-attestation`                                             |
| `INSTALL_DIR`               | Install path (default `/usr/local/bin` if writable, else `~/.local/bin`) |
| `GH_TOKEN` / `GITHUB_TOKEN` | Optional auth for GitHub downloads                                       |

Supported platforms: `darwin` / `linux` × `amd64` / `arm64`.

### PATH

If the installer chose `~/.local/bin`, ensure that directory is on your
`PATH`:

```sh
export PATH="$HOME/.local/bin:$PATH"
```

### Attestation

`gh` is required for attestation checks unless you skip them:

```sh
SKIP_ATTESTATION=1 curl -fsSL https://securock.sh/install | sh
# or
curl -fsSL https://securock.sh/install | sh -s -- --skip-attestation
```

Skip attestation only when you cannot run `gh` and accept verifying the
checksum yourself.

## Homebrew

```sh
brew tap securock/securock https://github.com/securock/securock
brew install --HEAD securock
```

## Go

```sh
go install github.com/securock/securock/cmd/securock@latest
```

Requires a working Go toolchain. The resulting binary is not attested by
the installer path; prefer the release installer in production CI.

## Manual verification

Release archives use lowercase GOOS names, for example
`securock_darwin_arm64.tar.gz`. Verify the archive or the extracted
binary:

```sh
gh attestation verify securock_darwin_arm64.tar.gz --repo securock/securock
gh attestation verify ./securock --repo securock/securock
```

## Troubleshooting

| Symptom                                  | What to check                                                                        |
| ---------------------------------------- | ------------------------------------------------------------------------------------ |
| `unsupported OS` / architecture          | Installer supports darwin/linux amd64/arm64 only                                     |
| `install gh or set SKIP_ATTESTATION=1`   | Install [GitHub CLI](https://cli.github.com/) or skip attestation                    |
| `command not found: securock`            | Add `INSTALL_DIR` (often `~/.local/bin`) to `PATH`                                   |
| Permission denied under `/usr/local/bin` | Re-run without write access so it falls back to `~/.local/bin`, or set `INSTALL_DIR` |

## Next steps

- [Quick start](/guide/quickstart) — walk the lock → diff → verify loop
- [Usage](/guide/usage) — CLI commands and flags
