package autofix

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/firfircelik/oteldoctor/internal/model"
	"gopkg.in/yaml.v3"
)

func TestFixMemLimiterOrder_DryRun(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "cfg.yaml")
	orig := []byte(`receivers:
  otlp:
    protocols:
      grpc: {}
processors:
  memory_limiter:
    limit_mib: 512
  batch:
    timeout: 200ms
exporters:
  debug: {}
service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [batch, memory_limiter]
      exporters: [debug]
`)
	os.WriteFile(f, orig, 0644)

	fixer := New(true)
	diags := []model.Diagnostic{
		{RuleID: "OTEL-REL-102", Message: "memory_limiter not first"},
	}

	plans, err := fixer.Fix(f, diags)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(plans) != 1 {
		t.Fatalf("expected 1 plan, got %d", len(plans))
	}

	plan := plans[0]
	if plan.Applied {
		t.Error("dry-run should not apply changes")
	}
	if plan.Diff == "" {
		t.Error("expected non-empty diff in dry-run")
	}
	if !strings.Contains(plan.Diff, "---") {
		t.Error("diff should contain --- header")
	}
	if strings.Contains(string(plan.Modified), "processors: [batch, memory_limiter]") {
		t.Error("modified output should have memory_limiter first")
	}
	if !strings.Contains(string(plan.Modified), "processors: [memory_limiter, batch]") {
		t.Error("modified output should have memory_limiter first, got: " + string(plan.Modified))
	}

	// Original file should be unchanged in dry-run
	current, _ := os.ReadFile(f)
	if string(current) != string(orig) {
		t.Error("dry-run should not modify original file")
	}
}

func TestFixMemLimiterOrder_Write(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "cfg.yaml")
	orig := []byte(`receivers:
  otlp:
    protocols:
      grpc: {}
processors:
  memory_limiter:
    limit_mib: 512
  batch:
    timeout: 200ms
exporters:
  debug: {}
service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [batch, memory_limiter]
      exporters: [debug]
`)
	os.WriteFile(f, orig, 0644)

	fixer := New(false)
	diags := []model.Diagnostic{
		{RuleID: "OTEL-REL-102", Message: "memory_limiter not first"},
	}

	plans, err := fixer.Fix(f, diags)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(plans) != 1 {
		t.Fatalf("expected 1 plan, got %d", len(plans))
	}
	if !plans[0].Applied {
		t.Error("write mode should apply changes")
	}

	// Original file should be modified
	current, _ := os.ReadFile(f)
	if strings.Contains(string(current), "processors: [batch, memory_limiter]") {
		t.Error("file should have memory_limiter first after write")
	}
	if !strings.Contains(string(current), "processors: [memory_limiter, batch]") {
		t.Errorf("file should have memory_limiter first, got: %s", string(current))
	}
}

func TestFixMemLimiterOrder_AlreadyFirst(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "cfg.yaml")
	orig := []byte(`receivers:
  otlp:
    protocols:
      grpc: {}
processors:
  memory_limiter:
    limit_mib: 512
  batch:
    timeout: 200ms
exporters:
  debug: {}
service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [memory_limiter, batch]
      exporters: [debug]
`)
	os.WriteFile(f, orig, 0644)

	fixer := New(true)
	diags := []model.Diagnostic{
		{RuleID: "OTEL-REL-102", Message: "memory_limiter not first"},
	}

	plans, err := fixer.Fix(f, diags)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(plans) != 0 {
		t.Errorf("expected 0 plans when already correct, got %d", len(plans))
	}
}

func TestFixMemLimiterOrder_NoProcessors(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "cfg.yaml")
	orig := []byte(`receivers:
  otlp:
    protocols:
      grpc: {}
exporters:
  debug: {}
service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: []
      exporters: [debug]
`)
	os.WriteFile(f, orig, 0644)

	fixer := New(true)
	diags := []model.Diagnostic{
		{RuleID: "OTEL-REL-102", Message: "memory_limiter not first"},
	}

	plans, err := fixer.Fix(f, diags)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(plans) != 0 {
		t.Errorf("expected 0 plans for empty processors, got %d", len(plans))
	}
}

func TestFixMemLimiterOrder_MultiplePipelines(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "cfg.yaml")
	orig := []byte(`receivers:
  otlp:
    protocols:
      grpc: {}
processors:
  memory_limiter:
    limit_mib: 512
  batch:
    timeout: 200ms
exporters:
  debug: {}
service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [batch, memory_limiter]
      exporters: [debug]
    metrics:
      receivers: [otlp]
      processors: [memory_limiter, batch]
      exporters: [debug]
`)
	os.WriteFile(f, orig, 0644)

	fixer := New(true)
	diags := []model.Diagnostic{
		{RuleID: "OTEL-REL-102", Message: "memory_limiter not first"},
	}

	plans, err := fixer.Fix(f, diags)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(plans) != 1 {
		t.Fatalf("expected 1 plan, got %d", len(plans))
	}

	mod := string(plans[0].Modified)
	if !strings.Contains(mod, "processors: [memory_limiter, batch]") {
		t.Error("traces pipeline should have memory_limiter first")
	}
}

func TestFix_NoRelevantDiags(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "cfg.yaml")
	orig := []byte(`receivers:
  otlp: {}
exporters:
  debug: {}
service:
  pipelines:
    traces:
      receivers: [otlp]
      exporters: [debug]
`)
	os.WriteFile(f, orig, 0644)

	fixer := New(true)
	diags := []model.Diagnostic{
		{RuleID: "OTEL-STRUCT-001", Message: "undefined ref"},
	}

	plans, err := fixer.Fix(f, diags)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(plans) != 0 {
		t.Errorf("expected 0 plans for non-fixable rules, got %d", len(plans))
	}
}

func TestUnifiedDiff(t *testing.T) {
	orig := []byte("line1\nline2\nline3\n")
	mod := []byte("line1\nline2_changed\nline3\n")

	diff := unifiedDiff("test.yaml", orig, mod)

	if !strings.Contains(diff, "--- test.yaml") {
		t.Error("diff should contain --- header")
	}
	if !strings.Contains(diff, "+++ test.yaml") {
		t.Error("diff should contain +++ header")
	}
	if !strings.Contains(diff, "+line2_changed") {
		t.Error("diff should show added line")
	}
	if !strings.Contains(diff, "-line2") {
		t.Error("diff should show removed line")
	}
}

func TestUnifiedDiff_Identical(t *testing.T) {
	orig := []byte("line1\nline2\n")
	mod := []byte("line1\nline2\n")

	diff := unifiedDiff("test.yaml", orig, mod)

	for _, line := range strings.Split(diff, "\n") {
		if line == "" {
			continue
		}
		switch line[0] {
		case '-', '+':
			if strings.HasPrefix(line, "---") || strings.HasPrefix(line, "+++") || strings.HasPrefix(line, "@@") {
				continue
			}
			t.Errorf("identical files should have no change markers, got line: %q", line)
		}
	}
}

func TestFixMemLimiterOrder_DiffHasOneHunk(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "cfg.yaml")
	os.WriteFile(f, []byte(`receivers:
  otlp: {}
processors:
  memory_limiter:
    limit_mib: 512
  batch:
    timeout: 200ms
exporters:
  debug: {}
service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [batch, memory_limiter]
      exporters: [debug]
`), 0644)

	fixer := New(true)
	diags := []model.Diagnostic{{RuleID: "OTEL-REL-102"}}
	plans, _ := fixer.Fix(f, diags)

	if len(plans) != 1 {
		t.Fatalf("expected 1 plan, got %d", len(plans))
	}

	diff := plans[0].Diff
	if !strings.Contains(diff, "---") {
		t.Error("diff should have --- header")
	}
	if !strings.Contains(diff, "+++") {
		t.Error("diff should have +++ header")
	}
	if !strings.Contains(diff, "@@") {
		t.Error("diff should have @@ hunk header")
	}

	addLines := 0
	delLines := 0
	for _, line := range strings.Split(diff, "\n") {
		if strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++") {
			addLines++
		}
		if strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "---") {
			delLines++
		}
	}
	if addLines != 1 {
		t.Errorf("expected exactly 1 added line, got %d", addLines)
	}
	if delLines != 1 {
		t.Errorf("expected exactly 1 deleted line, got %d", delLines)
	}
}

func TestFixMemLimiterOrder_ProducesValidYAML(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "cfg.yaml")
	os.WriteFile(f, []byte(`receivers:
  otlp: {}
processors:
  memory_limiter:
    limit_mib: 512
  batch:
    timeout: 200ms
exporters:
  debug: {}
service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [batch, memory_limiter]
      exporters: [debug]
`), 0644)

	fixer := New(true)
	diags := []model.Diagnostic{{RuleID: "OTEL-REL-102"}}
	plans, _ := fixer.Fix(f, diags)

	modified := plans[0].Modified

	var node yaml.Node
	if err := yaml.Unmarshal(modified, &node); err != nil {
		t.Fatalf("fix produced invalid YAML: %v\n%s", err, string(modified))
	}

	text := string(modified)
	for _, key := range []string{"receivers:", "exporters:", "service:", "pipelines:"} {
		if !strings.Contains(text, key) {
			t.Errorf("modified YAML should contain %q", key)
		}
	}
	if strings.Contains(text, "processors: [batch, memory_limiter]") {
		t.Error("modified YAML should NOT have batch before memory_limiter")
	}
	if !strings.Contains(text, "processors: [memory_limiter, batch]") {
		t.Error("modified YAML should have memory_limiter first")
	}
}

func TestFixMemLimiterOrder_ResolvesDiagnostic(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "cfg.yaml")
	os.WriteFile(f, []byte(`receivers:
  otlp: {}
processors:
  memory_limiter:
    limit_mib: 512
  batch:
    timeout: 200ms
exporters:
  debug: {}
service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [batch, memory_limiter]
      exporters: [debug]
`), 0644)

	fixer := New(true)
	diags := []model.Diagnostic{{RuleID: "OTEL-REL-102"}}
	plans, _ := fixer.Fix(f, diags)
	modified := plans[0].Modified

	// Re-parse the fixed YAML and check processors order
	var doc yaml.Node
	yaml.Unmarshal(modified, &doc)
	root := doc.Content[0]
	svc := findValue(root, "service")
	pipes := findValue(svc, "pipelines")
	traces := findValue(pipes, "traces")
	procs := findValue(traces, "processors")

	if procs == nil || procs.Kind != yaml.SequenceNode {
		t.Fatal("processors not found in fixed YAML")
	}
	if len(procs.Content) < 2 {
		t.Fatal("expected at least 2 processors")
	}
	if procs.Content[0].Value != "memory_limiter" {
		t.Errorf("expected memory_limiter first, got %q", procs.Content[0].Value)
	}
}

func TestFixMemLimiterOrder_WriteProducesValidYAML(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "cfg.yaml")
	os.WriteFile(f, []byte(`receivers:
  otlp: {}
processors:
  memory_limiter:
    limit_mib: 512
  batch:
    timeout: 200ms
exporters:
  debug: {}
service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [batch, memory_limiter]
      exporters: [debug]
`), 0644)

	fixer := New(false)
	diags := []model.Diagnostic{{RuleID: "OTEL-REL-102"}}
	plans, err := fixer.Fix(f, diags)
	if err != nil {
		t.Fatalf("fix error: %v", err)
	}
	if !plans[0].Applied {
		t.Error("expected fix to be applied")
	}

	current, _ := os.ReadFile(f)
	var node yaml.Node
	if err := yaml.Unmarshal(current, &node); err != nil {
		t.Fatalf("written file contains invalid YAML: %v\n%s", err, string(current))
	}
}
