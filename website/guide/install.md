# Install

```sh
curl -fsSL https://securock.sh/install | sh

brew tap securock/securock https://github.com/securock/securock
brew install --HEAD securock

go install github.com/securock/securock/cmd/securock@latest
```

Release archives are named `securock_darwin_arm64.tar.gz` (lowercase GOOS). Verify the archive or the extracted binary:

```sh
gh attestation verify securock_darwin_arm64.tar.gz --repo securock/securock
gh attestation verify ./securock --repo securock/securock
```
