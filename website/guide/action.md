# GitHub Action

```yaml
permissions:
  contents: read
  pull-requests: write

jobs:
  securock:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: securock/securock@main
        with:
          command: both
```

The action installs the CLI from the same git ref, runs `diff` and/or `verify`, and updates a pull request comment titled `Securock Trust Report`.
