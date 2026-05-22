# GitHub Action: oteldoctor

Run oteldoctor in your CI pipeline to catch OpenTelemetry Collector configuration issues before production.

## Usage

```yaml
name: oteldoctor scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: "1.23"
      - uses: firfircelik/oteldoctor@main
        with:
          path: ./deploy
          profile: production
          fail-on: high
          format: sarif
```

## Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `path` | Yes | — | File or directory path to analyze |
| `profile` | No | `development` | Analysis profile: `development`, `staging`, `production` |
| `fail-on` | No | `low` | Fail threshold: `critical`, `high`, `medium`, `low` |
| `format` | No | `text` | Output format: `text`, `json`, `sarif` |
| `policy` | No | `""` | Path to `.oteldoctor.yaml` policy file |
| `version` | No | `latest` | oteldoctor version to install |

## Examples

### Basic scan

```yaml
- uses: firfircelik/oteldoctor@main
  with:
    path: ./config/collector.yaml
```

### Production scan with SARIF output

```yaml
- uses: firfircelik/oteldoctor@main
  with:
    path: ./deploy
    profile: production
    format: sarif
    fail-on: medium
```

### With policy file

```yaml
- uses: firfircelik/oteldoctor@main
  with:
    path: ./deploy
    policy: .oteldoctor.yaml
    profile: production
```

### Upload SARIF to GitHub Code Scanning

```yaml
- uses: firfircelik/oteldoctor@main
  with:
    path: ./deploy
    format: sarif
    profile: production
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: oteldoctor.sarif
```

## Notes

- The action installs oteldoctor via `go install` and runs it.
- Use `version` to pin a specific release (e.g., `v0.1.0`).
- The `policy` input lets you suppress or reconfigure rules per environment.
- Exit code 1 means issues were found at or above the `fail-on` threshold.
- Exit code 2 means a parse or runtime error occurred.
