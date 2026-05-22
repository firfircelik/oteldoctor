package output

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/firfircelik/oteldoctor/internal/model"
)

func TestTextFormatter_Empty(t *testing.T) {
	f := &TextFormatter{}
	out, err := f.Format(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out != "No issues found.\n" {
		t.Errorf("expected 'No issues found.', got %q", out)
	}
}

func TestTextFormatter_SingleDiagnostic(t *testing.T) {
	f := &TextFormatter{}
	diags := []model.Diagnostic{
		{
			RuleID:   "OTEL-REL-102",
			Severity: model.SeverityHigh,
			Category: model.CategoryReliability,
			Message:  `memory_limiter should be the first processor in pipeline "traces".`,
			Fix:      "Move memory_limiter before batch.",
			Location: model.SourceLocation{
				File: "collector.yaml",
				Line: 42,
			},
		},
	}

	out, err := f.Format(diags)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(out, "collector.yaml") {
		t.Error("expected file name in output")
	}
	if !strings.Contains(out, "HIGH") {
		t.Error("expected HIGH severity")
	}
	if !strings.Contains(out, "OTEL-REL-102") {
		t.Error("expected rule ID")
	}
	if !strings.Contains(out, "line 42") {
		t.Error("expected line number")
	}
	if !strings.Contains(out, "Fix: Move memory_limiter before batch") {
		t.Error("expected fix message")
	}
	if !strings.Contains(out, "1 issue found") {
		t.Error("expected issue count")
	}
}

func TestTextFormatter_SeverityOrdering(t *testing.T) {
	f := &TextFormatter{}
	diags := []model.Diagnostic{
		{Severity: model.SeverityInfo, RuleID: "R4", Message: "info", Location: model.SourceLocation{File: "f.yaml", Line: 10}},
		{Severity: model.SeverityCritical, RuleID: "R1", Message: "critical", Location: model.SourceLocation{File: "f.yaml", Line: 1}},
		{Severity: model.SeverityLow, RuleID: "R3", Message: "low", Location: model.SourceLocation{File: "f.yaml", Line: 5}},
		{Severity: model.SeverityMedium, RuleID: "R2", Message: "medium", Location: model.SourceLocation{File: "f.yaml", Line: 3}},
		{Severity: model.SeverityHigh, RuleID: "R2b", Message: "high", Location: model.SourceLocation{File: "f.yaml", Line: 3}},
	}

	out, err := f.Format(diags)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	lines := strings.Split(out, "\n")

	var appearances []string
	for _, line := range lines {
		for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} {
			if strings.HasPrefix(strings.TrimSpace(line), sev) {
				appearances = append(appearances, sev)
			}
		}
	}

	expected := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
	if len(appearances) != len(expected) {
		t.Fatalf("expected %d severity lines, got %d: %v", len(expected), len(appearances), appearances)
	}
	for i, got := range appearances {
		if got != expected[i] {
			t.Errorf("position %d: expected %q, got %q", i, expected[i], got)
		}
	}
}

func TestTextFormatter_SameSeverityLineOrdering(t *testing.T) {
	f := &TextFormatter{}
	diags := []model.Diagnostic{
		{Severity: model.SeverityMedium, RuleID: "R3", Message: "line 30", Location: model.SourceLocation{File: "f.yaml", Line: 30}},
		{Severity: model.SeverityMedium, RuleID: "R1", Message: "line 10", Location: model.SourceLocation{File: "f.yaml", Line: 10}},
		{Severity: model.SeverityMedium, RuleID: "R2", Message: "line 20", Location: model.SourceLocation{File: "f.yaml", Line: 20}},
	}

	out, err := f.Format(diags)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	lines := strings.Split(out, "\n")

	var rules []string
	for _, line := range lines {
		for _, r := range []string{"R1", "R2", "R3"} {
			if strings.Contains(line, r) && strings.HasPrefix(strings.TrimSpace(line), "MEDIUM") {
				rules = append(rules, r)
			}
		}
	}

	expected := []string{"R1", "R2", "R3"}
	if len(rules) != len(expected) {
		t.Fatalf("expected %d rules, got %d: %v", len(expected), len(rules), rules)
	}
	for i, got := range rules {
		if got != expected[i] {
			t.Errorf("position %d: expected %q, got %q", i, expected[i], got)
		}
	}
}

func TestTextFormatter_GroupedByFile(t *testing.T) {
	f := &TextFormatter{}
	diags := []model.Diagnostic{
		{Severity: model.SeverityHigh, RuleID: "R1", Message: "a", Location: model.SourceLocation{File: "a.yaml", Line: 1}},
		{Severity: model.SeverityMedium, RuleID: "R2", Message: "b", Location: model.SourceLocation{File: "b.yaml", Line: 2}},
		{Severity: model.SeverityLow, RuleID: "R3", Message: "a2", Location: model.SourceLocation{File: "a.yaml", Line: 3}},
	}

	out, err := f.Format(diags)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	idxA := strings.Index(out, "a.yaml")
	idxB := strings.Index(out, "b.yaml")

	if idxA == -1 || idxB == -1 {
		t.Fatal("expected both file headers")
	}
	if idxA >= idxB {
		t.Error("expected a.yaml before b.yaml (sorted)")
	}

	countA := strings.Count(out, "a.yaml")
	if countA != 1 {
		t.Errorf("expected a.yaml header once (grouped), got %d", countA)
	}

	if !strings.Contains(out, "R1") || !strings.Contains(out, "R3") {
		t.Error("expected both R1 and R3 under a.yaml group")
	}
}

func TestTextFormatter_MultipleIssues(t *testing.T) {
	f := &TextFormatter{}
	diags := []model.Diagnostic{
		{Severity: model.SeverityHigh, RuleID: "R1", Message: "a", Location: model.SourceLocation{File: "f.yaml", Line: 1}},
		{Severity: model.SeverityMedium, RuleID: "R2", Message: "b", Location: model.SourceLocation{File: "f.yaml", Line: 2}},
	}

	out, err := f.Format(diags)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(out, "2 issues found.") {
		t.Errorf("expected '2 issues found.', got %q", out)
	}
}

func TestTextFormatter_NoLineNumber(t *testing.T) {
	f := &TextFormatter{}
	diags := []model.Diagnostic{
		{Severity: model.SeverityInfo, RuleID: "R1", Message: "no line", Location: model.SourceLocation{File: "f.yaml"}},
	}

	out, err := f.Format(diags)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if strings.Contains(out, "line 0") {
		t.Error("should not include 'line 0' when line is zero")
	}
}

func TestTextFormatter_NoFix(t *testing.T) {
	f := &TextFormatter{}
	diags := []model.Diagnostic{
		{Severity: model.SeverityHigh, RuleID: "R1", Message: "no fix", Location: model.SourceLocation{File: "f.yaml", Line: 1}},
	}

	out, err := f.Format(diags)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if strings.Contains(out, "Fix:") {
		t.Error("should not include Fix: when fix is empty")
	}
}

func TestTextFormatter_UnknownFile(t *testing.T) {
	f := &TextFormatter{}
	diags := []model.Diagnostic{
		{Severity: model.SeverityHigh, RuleID: "R1", Message: "msg", Location: model.SourceLocation{Line: 5}},
	}

	out, err := f.Format(diags)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(out, "<unknown>") {
		t.Error("expected <unknown> for empty file path")
	}
}

func TestJSONFormatter_OutputShape(t *testing.T) {
	f := &JSONFormatter{}
	diags := []model.Diagnostic{
		{
			RuleID:   "OTEL-STRUCT-001",
			Severity: model.SeverityCritical,
			Category: model.CategoryStructural,
			Message:  "invalid YAML",
			Fix:      "check syntax",
			Location: model.SourceLocation{
				File:   "config.yaml",
				Line:   10,
				Column: 5,
			},
		},
		{
			RuleID:   "OTEL-REL-102",
			Severity: model.SeverityHigh,
			Category: model.CategoryReliability,
			Message:  `memory_limiter should be first processor in "traces".`,
			Location: model.SourceLocation{
				File: "config.yaml",
				Line: 42,
			},
		},
	}

	out, err := f.Format(diags)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var parsed []map[string]any
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("invalid JSON output: %v\noutput: %s", err, out)
	}

	if len(parsed) != 2 {
		t.Fatalf("expected 2 diagnostics, got %d", len(parsed))
	}

	d0 := parsed[0]
	if d0["rule_id"] != "OTEL-STRUCT-001" {
		t.Errorf("expected first rule_id OTEL-STRUCT-001, got %v", d0["rule_id"])
	}
	if d0["severity"] != "critical" {
		t.Errorf("expected first severity critical, got %v", d0["severity"])
	}
	if d0["category"] != "structural" {
		t.Errorf("expected first category structural, got %v", d0["category"])
	}
	if d0["fix"] != "check syntax" {
		t.Errorf("expected first fix 'check syntax', got %v", d0["fix"])
	}

	loc0, ok := d0["location"].(map[string]any)
	if !ok {
		t.Fatalf("expected location to be object, got %T", d0["location"])
	}
	if loc0["file"] != "config.yaml" {
		t.Errorf("expected file config.yaml, got %v", loc0["file"])
	}
	if int(loc0["line"].(float64)) != 10 {
		t.Errorf("expected line 10, got %v", loc0["line"])
	}
	if int(loc0["column"].(float64)) != 5 {
		t.Errorf("expected column 5, got %v", loc0["column"])
	}

	d1 := parsed[1]
	if d1["rule_id"] != "OTEL-REL-102" {
		t.Errorf("expected second rule_id OTEL-REL-102, got %v", d1["rule_id"])
	}
	if _, hasFix := d1["fix"]; hasFix {
		t.Errorf("expected fix to be omitted when empty, got %v", d1["fix"])
	}
}

func TestJSONFormatter_SeverityOrdering(t *testing.T) {
	f := &JSONFormatter{}
	diags := []model.Diagnostic{
		{Severity: model.SeverityLow, RuleID: "low", Message: "low",Location: model.SourceLocation{File: "f.yaml", Line: 1}},
		{Severity: model.SeverityCritical, RuleID: "crit", Message: "crit", Location: model.SourceLocation{File: "f.yaml", Line: 1}},
		{Severity: model.SeverityMedium, RuleID: "med", Message: "med", Location: model.SourceLocation{File: "f.yaml", Line: 1}},
	}

	out, err := f.Format(diags)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var parsed []map[string]any
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	expected := []string{"crit", "med", "low"}
	for i, exp := range expected {
		if parsed[i]["rule_id"] != exp {
			t.Errorf("position %d: expected rule %q, got %v", i, exp, parsed[i]["rule_id"])
		}
	}
}

func TestJSONFormatter_Stability(t *testing.T) {
	f := &JSONFormatter{}
	diags := []model.Diagnostic{
		{Severity: model.SeverityHigh, RuleID: "A", Message: "a", Location: model.SourceLocation{File: "f.yaml", Line: 1}},
		{Severity: model.SeverityHigh, RuleID: "B", Message: "b", Location: model.SourceLocation{File: "f.yaml", Line: 1}},
	}

	first, err := f.Format(diags)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Re-run with same input
	second, err := f.Format(diags)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if first != second {
		t.Error("JSON output should be stable across identical inputs")
	}

	// Parse and check deterministic order
	var parsed []map[string]any
	json.Unmarshal([]byte(first), &parsed)
	if parsed[0]["rule_id"] != "A" || parsed[1]["rule_id"] != "B" {
		t.Error("stable sort should preserve original order for equal ranks")
	}
}

func TestJSONFormatter_Empty(t *testing.T) {
	f := &JSONFormatter{}
	out, err := f.Format(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should output valid empty JSON array
	if strings.TrimSpace(out) != "[]" {
		t.Errorf("expected '[]' for empty input, got %q", out)
	}
}

func TestTextFormatter_CrossFileSeverityOrder(t *testing.T) {
	f := &TextFormatter{}
	diags := []model.Diagnostic{
		{Severity: model.SeverityLow, RuleID: "R1", Message: "z", Location: model.SourceLocation{File: "z.yaml", Line: 1}},
		{Severity: model.SeverityCritical, RuleID: "R2", Message: "a", Location: model.SourceLocation{File: "a.yaml", Line: 1}},
	}

	out, err := f.Format(diags)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	idxCrit := strings.Index(out, "CRITICAL")
	idxLow := strings.Index(out, "LOW")

	if idxCrit == -1 || idxLow == -1 {
		t.Fatal("expected both severities")
	}
	if idxCrit > idxLow {
		t.Error("CRITICAL should appear before LOW")
	}
}

func TestSARIFFormatter_ValidShape(t *testing.T) {
	f := &SARIFFormatter{}
	diags := []model.Diagnostic{
		{
			RuleID:   "OTEL-REL-102",
			Severity: model.SeverityHigh,
			Category: model.CategoryReliability,
			Message:  "memory_limiter should be first processor.",
			Fix:      "Move memory_limiter before batch.",
			Location: model.SourceLocation{File: "collector.yaml", Line: 42, Column: 5},
		},
		{
			RuleID:   "OTEL-SEC-202",
			Severity: model.SeverityCritical,
			Category: model.CategorySecurity,
			Message:  "Hardcoded secret in headers.",
			Location: model.SourceLocation{File: "collector.yaml", Line: 10},
		},
	}

	out, err := f.Format(diags)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var log map[string]any
	if err := json.Unmarshal([]byte(out), &log); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}

	if v, _ := log["version"].(string); v != "2.1.0" {
		t.Errorf("expected version 2.1.0, got %q", v)
	}

	runs, ok := log["runs"].([]any)
	if !ok || len(runs) != 1 {
		t.Fatal("expected 1 run")
	}

	run, _ := runs[0].(map[string]any)

	tool, ok := run["tool"].(map[string]any)
	if !ok {
		t.Fatal("expected tool section")
	}
	driver, _ := tool["driver"].(map[string]any)
	if driver["name"] != "oteldoctor" {
		t.Error("expected driver name oteldoctor")
	}

	rules, _ := driver["rules"].([]any)
	if len(rules) != 2 {
		t.Errorf("expected 2 rules, got %d", len(rules))
	}

	results, _ := run["results"].([]any)
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	r0 := results[0].(map[string]any)
	if r0["ruleId"] != "OTEL-SEC-202" {
		t.Errorf("expected first result OTEL-SEC-202 (sorted critical), got %v", r0["ruleId"])
	}
	if r0["level"] != "error" {
		t.Errorf("expected error level for critical, got %v", r0["level"])
	}

	locs, _ := r0["locations"].([]any)
	if len(locs) == 0 {
		t.Fatal("expected locations")
	}
	loc := locs[0].(map[string]any)
	pl := loc["physicalLocation"].(map[string]any)
	al := pl["artifactLocation"].(map[string]any)
	if al["uri"] != "collector.yaml" {
		t.Errorf("expected uri collector.yaml, got %v", al["uri"])
	}
	region, _ := pl["region"].(map[string]any)
	if int(region["startLine"].(float64)) != 10 {
		t.Errorf("expected startLine 10, got %v", region["startLine"])
	}

	// Verify rule metadata quality
	rulesList, _ := driver["rules"].([]any)
	found := false
	for _, r := range rulesList {
		rm := r.(map[string]any)
		if rm["id"] == "OTEL-SEC-202" {
			found = true
			sd, _ := rm["shortDescription"].(map[string]any)
			if sd == nil || sd["text"] == "OTEL-SEC-202" {
				t.Error("shortDescription should be rule title, not rule ID")
			}
			if !strings.Contains(fmt.Sprintf("%v", sd["text"]), "secret") {
				t.Error("shortDescription should mention secret detection")
			}

			fd, _ := rm["fullDescription"].(map[string]any)
			if fd == nil || fd["text"] == "OTEL-SEC-202" {
				t.Error("fullDescription should explain why the rule matters, not be the rule ID")
			}

			help, _ := rm["help"].(map[string]any)
			if help == nil {
				t.Error("expected help section with remediation guidance")
			} else if help["text"] == nil || help["text"] == "" {
				t.Error("help.text should contain fix guidance")
			}

			break
		}
	}
	if !found {
		t.Error("OTEL-SEC-202 rule metadata not found in SARIF output")
	}
}

func TestSARIFFormatter_Empty(t *testing.T) {
	f := &SARIFFormatter{}
	out, err := f.Format(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var log map[string]any
	json.Unmarshal([]byte(out), &log)

	runs, _ := log["runs"].([]any)
	run := runs[0].(map[string]any)
	results, _ := run["results"].([]any)
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}

func TestSARIFFormatter_NoLocation(t *testing.T) {
	f := &SARIFFormatter{}
	diags := []model.Diagnostic{
		{
			RuleID:   "OTEL-SEM-401",
			Severity: model.SeverityLow,
			Message:  "service.name not configured.",
		},
	}

	out, err := f.Format(diags)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(out, "\"results\"") {
		t.Error("should have results even without locations")
	}
}
