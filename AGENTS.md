# AGENTS.md — oteldoctor

## Quick commands

```bash
make build                        # go build -o bin/oteldoctor ./cmd/oteldoctor
make test                         # go test -race -count=1 ./...  (always use -count=1)
make lint                         # placeholder, not implemented
make clean                        # rm -rf bin/

# Run single package tests:
go test -run TestName ./internal/rules/...
go test -run TestName ./internal/cli/...

# Run the binary:
go run ./cmd/oteldoctor analyze examples/good/collector-dev.yaml
go run ./cmd/oteldoctor analyze --profile production examples/bad/structural.yaml
go run ./cmd/oteldoctor analyze --format sarif examples/bad/security.yaml
go run ./cmd/oteldoctor fix examples/bad/reliability.yaml --dry-run
go run ./cmd/oteldoctor graph examples/good/collector-dev.yaml --format mermaid
go run ./cmd/oteldoctor explain OTEL-REL-102
```

## Architecture

**Entrypoint:** `cmd/oteldoctor/main.go` — calls `cli.Execute()`.

**Package boundaries (top-down):**
- `internal/cli/` — Cobra commands (`analyze`, `fix`, `graph`, `explain`, `version`). The `analyze` command orchestrates the full pipeline: parse → graph → rules → output.
- `internal/parser/` — YAML parser using `gopkg.in/yaml.v3` (yaml.Node for line/column). `ParseFile(realPath, displayPath)` reads from real path, sets source locations from display path.
- `internal/graph/` — Pipeline graph from `model.CollectorConfig`. 6 query helpers. Facts only, no diagnostics.
- `internal/rules/` — Rule engine + 38 rules (8 structural, 8 reliability, 7 security, 5 cost, 5 semantic, 5 k8s). `AllRules()` in `defaults.go`. Rule documentation in `docs.go`.
- `internal/output/` — `TextFormatter`, `JSONFormatter`, `SARIFFormatter` (SARIF 2.1.0). All implement `Formatter` interface.
- `internal/model/` — Type definitions. `Component`, `Pipeline`, `Diagnostic`, `SourceLocation`, etc.
- `internal/policy/` — `.oteldoctor.yaml` loading and discovery. Rule disable/severity/suppression.
- `internal/autofix/` — One safe fix (OTEL-REL-102: reorder memory_limiter). Dry-run shows unified diff.
- `internal/scanner/` — Directory scan for .yaml/.yml, collector config detection (2+ top-level keys), glob filters.
- `internal/extractor/` — K8s ConfigMap detection and embedded collector config extraction.
- `internal/k8s/` — K8s workload parser (Deployment/DaemonSet/StatefulSet + Service).

**Empty/deprecated packages (do not use):** `internal/app/`, `internal/diagnostics/`, `internal/explain/`, `internal/source/`

## Rules architecture

All rules implement the `Rule` interface and use `RuleContext`:
```go
type RuleContext struct {
    Config     *model.CollectorConfig
    Graph      *graph.Graph
    Profile    string           // "development"|"staging"|"production"
    Policy     *policy.Policy
    Workload   *k8s.Workload     // set when linked K8s workload found
    K8sService *k8s.ServiceInfo  // set when linked K8s service found
}
```

Rules register in `AllRules()` (`internal/rules/defaults.go`). New rules must be added there.

## Profile gating conventions

- **Structural rules** (STRUCT-xxx): always fire.
- **Security rules** (SEC-201/203/205/206): production/staging only.
- **Reliability rules** (REL-105/106): production/staging only. Skip debug exporter.
- **Cost rules** (COST-304/305): production only.
- **Semantic rules** (SEM-401/403/404): production/staging only.
- **K8s rules** (K8S-505): production only. Others fire with linked workload.

Use `pickSeverity(ctx.Profile, prod, staging, dev)` for profile-dependent severity.

## "Good" examples must produce 0 issues

`examples/good/` files must produce 0 diagnostics for their intended profile. When adding rules that would flag a "good" config, either:
- Gate the rule behind a production/staging profile check, OR
- Update the example config to satisfy the rule

`examples/good/collector-dev.yaml` → 0 issues with default (development) profile.
`examples/good/collector-production.yaml` → 0 issues with `--profile production`.

## Golden tests

`internal/cli/golden_test.go` contains end-to-end integration tests:
- `TestGolden_CollectorDev_ZeroDiagnostics` — dev config has 0 issues
- `TestGolden_CollectorProduction_ZeroDiagnostics` — production config has 0 issues
- `TestGolden_DebugExporter_NoRetryQueueRules` — debug exporter skipped by REL-105/106
- `TestGolden_SecretRedacted_NoRawValue` — secrets never in text or JSON output
- `TestGolden_Bad*_ContainsRules` — bad configs trigger specific rule IDs

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | No issues or all below `--fail-on` threshold |
| 1 | Issues at/above threshold (returns `cli.ExitError{Code: 1}`) |
| 2 | Parse/config/runtime error |

`main.go` handles the `ExitError` type to produce correct exit codes.

## Common pitfalls

- **Severity rank duplicated in 3 places**: `output/output.go:severityRank`, `rules/registry.go:severityRank`, `cli/analyze.go:failRank+severityInt`. If adding a severity level, update all three.
- **`RunAll()` signature**: `RunAll(ctx RuleContext, showSuppressed bool)`. Tests must pass `false` as second arg.
- **When a rule fires, golden tests may break**: Always run `go test ./...` after adding/modifying ANY rule. If `TestGolden_CollectorDev_ZeroDiagnostics` or `TestGolden_CollectorProduction_ZeroDiagnostics` fail, the new rule is firing on a "good" config and needs profile gating.
- **Component ID format**: `"type"` or `"type/name"`. Use `model.ParseComponentID()`.
- **Secret values must never appear in output**: Check `[REDACTED]` in diagnostic messages. See `OTEL-SEC-202`.
- **K8s workload linking is conservative**: Only links when exactly 1 workload exists in scanned dir. K8s rules return nil when `ctx.Workload == nil`.
- **ConfigMap extraction keys**: `collector.yaml`, `collector.yml`, `relay`, `otel-collector-config`, `config.yaml`.
- **Single file vs directory**: Single files bypass collector-config detection and parse directly. Directory mode filters by collector config before analysis.
