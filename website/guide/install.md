# Install

```sh
curl -fsSL https://securock.sh/install | sh
curl -fsSL https://securock.sh/install | sh -s -- --version v0.1.0-alpha.1

brew tap securock/securock https://github.com/securock/securock
brew install --HEAD securock

go install github.com/securock/securock/cmd/securock@latest
```

The installer verifies SHA-256 and GitHub attestations. `gh` is required
unless `SKIP_ATTESTATION=1` is set.

Release archives are named `securock_darwin_arm64.tar.gz` (lowercase GOOS). Verify the archive or the extracted binary:

```sh
gh attestation verify securock_darwin_arm64.tar.gz --repo securock/securock
gh attestation verify ./securock --repo securock/securock
```
