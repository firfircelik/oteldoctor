package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Golden test 1: good/collector-dev with default profile => 0 diagnostics.
func TestGolden_CollectorDev_ZeroDiagnostics(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "collector-dev.yaml")
	os.WriteFile(f, []byte(`receivers:
  otlp:
    protocols:
      grpc:
        endpoint: "localhost:4317"
processors:
  resource:
    attributes:
      - key: service.name
        value: my-service
        action: upsert
  memory_limiter:
    limit_mib: 512
  batch:
    timeout: 200ms
exporters:
  otlphttp:
    endpoint: "https://backend:4318"
    tls:
      insecure: false
    retry_on_failure:
      enabled: true
    sending_queue:
      num_consumers: 10
extensions:
  health_check:
    endpoint: "localhost:13133"
  pprof:
    endpoint: "localhost:1777"
service:
  extensions: [health_check, pprof]
  pipelines:
    traces:
      receivers: [otlp]
      processors: [memory_limiter, resource, batch]
      exporters: [otlphttp]
`), 0644)

	cmd := newAnalyzeCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	cmd.SetArgs([]string{f})
	err := cmd.Execute()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "No issues found") {
		t.Errorf("expected 'No issues found', got:\n%s", out)
	}
}

// Golden test 2: good/collector-production with production profile => 0 diagnostics.
func TestGolden_CollectorProduction_ZeroDiagnostics(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "collector-production.yaml")
	os.WriteFile(f, []byte(`receivers:
  otlp:
    tls:
      cert_file: /tls/cert.pem
    protocols:
      grpc:
        endpoint: "0.0.0.0:4317"
processors:
  memory_limiter:
    limit_mib: 512
  resource:
    attributes:
      - key: service.name
        value: my-collector
        action: upsert
      - key: deployment.environment
        value: production
        action: upsert
      - key: service.version
        value: 1.0.0
        action: upsert
  tailsampling:
    decision_wait: 10s
    policies:
      - name: keep-all
        type: always_sample
  batch:
    timeout: 200ms
exporters:
  otlphttp:
    endpoint: "https://backend:4318"
    tls:
      insecure: false
    retry_on_failure:
      enabled: true
    sending_queue:
      num_consumers: 10
extensions:
  health_check:
    endpoint: "localhost:13133"
  pprof:
    endpoint: "localhost:1777"
service:
  extensions: [health_check, pprof]
  pipelines:
    traces:
      receivers: [otlp]
      processors: [memory_limiter, resource, tailsampling, batch]
      exporters: [otlphttp]
`), 0644)

	cmd := newAnalyzeCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	cmd.SetArgs([]string{"--profile", "production", f})
	err := cmd.Execute()
	if err != nil {
		t.Fatalf("expected no error with production profile, got: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "No issues found") {
		t.Errorf("expected 'No issues found' in production profile, got:\n%s", out)
	}
}

// Golden test 3: bad/structural => contains OTEL-STRUCT-001/002/003.
func TestGolden_BadStructural_ContainsRules(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "structural.yaml")
	os.WriteFile(f, []byte(`receivers:
  otlp:
    protocols:
      grpc:
        endpoint: "0.0.0.0:4317"
processors:
  batch: {}
exporters:
  debug: {}
service:
  pipelines:
    traces:
      receivers: [otlp, missing_rcv]
      processors: [batch, undefined_proc]
      exporters: [no_such_exp]
`), 0644)

	cmd := newAnalyzeCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	cmd.SetArgs([]string{"--category", "structural", f})
	cmd.Execute()

	out := buf.String()

	required := []string{
		"OTEL-STRUCT-001", // undefined receiver
		"OTEL-STRUCT-002", // undefined processor
		"OTEL-STRUCT-003", // undefined exporter
	}
	for _, rule := range required {
		if !strings.Contains(out, rule) {
			t.Errorf("expected %s in output", rule)
		}
	}
}

// Golden test 4: bad/security with production profile => contains OTEL-SEC rules.
func TestGolden_BadSecurity_ContainsRules(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "security.yaml")
	os.WriteFile(f, []byte(`receivers:
  otlp:
    protocols:
      grpc:
        endpoint: "0.0.0.0:4317"
processors:
  batch: {}
exporters:
  otlphttp:
    endpoint: "http://backend.example.com:4318"
    headers:
      X-API-KEY: "s3cr3t"
  debug:
    verbosity: detailed
extensions:
  pprof:
    endpoint: "0.0.0.0:1777"
service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [batch]
      exporters: [otlphttp, debug]
`), 0644)

	cmd := newAnalyzeCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	cmd.SetArgs([]string{"--profile", "production", "--category", "security", f})
	cmd.Execute()

	out := buf.String()

	required := []string{
		"OTEL-SEC-201", // plain HTTP exporter
		"OTEL-SEC-202", // hardcoded secret
		"OTEL-SEC-203", // receiver bound to 0.0.0.0
		"OTEL-SEC-204", // debug exporter in production
	}
	for _, rule := range required {
		if !strings.Contains(out, rule) {
			t.Errorf("expected %s in output", rule)
		}
	}
}

// Golden test 5: bad/semantic => contains OTEL-SEM-402/405.
func TestGolden_BadSemantic_ContainsRules(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "semantic.yaml")
	os.WriteFile(f, []byte(`receivers:
  otlp:
    protocols:
      grpc:
        endpoint: "0.0.0.0:4317"
processors:
  resource:
    attributes:
      - key: app_name
        value: legacy-name
        action: upsert
      - key: http.method
        action: upsert
  batch:
    timeout: 200ms
exporters:
  debug:
    verbosity: detailed
service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [resource, batch]
      exporters: [debug]
`), 0644)

	cmd := newAnalyzeCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	cmd.SetArgs([]string{"--category", "semantic", f})
	cmd.Execute()

	out := buf.String()

	required := []string{
		"OTEL-SEM-402", // app_name instead of service.name
		"OTEL-SEM-405", // deprecated http.method
	}
	for _, rule := range required {
		if !strings.Contains(out, rule) {
			t.Errorf("expected %s in output", rule)
		}
	}
}

// Golden test 6: debug exporter => does NOT contain OTEL-REL-105 or OTEL-REL-106.
func TestGolden_DebugExporter_NoRetryQueueRules(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "debug-exporter.yaml")
	os.WriteFile(f, []byte(`receivers:
  otlp:
    protocols:
      grpc: {}
processors:
  memory_limiter:
    limit_mib: 512
  batch:
    timeout: 200ms
exporters:
  debug:
    verbosity: detailed
service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [memory_limiter, batch]
      exporters: [debug]
`), 0644)

	cmd := newAnalyzeCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	cmd.SetArgs([]string{"--profile", "production", f})
	cmd.Execute()

	out := buf.String()

	forbidden := []string{
		"OTEL-REL-105",
		"OTEL-REL-106",
	}
	for _, rule := range forbidden {
		if strings.Contains(out, rule) {
			t.Errorf("%s should not appear for debug exporter", rule)
		}
	}
}

// Golden test 7: secret fixture => output must not contain raw secret value.
func TestGolden_SecretRedacted_NoRawValue(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "secret.yaml")
	os.WriteFile(f, []byte(`receivers:
  otlp:
    protocols:
      grpc: {}
exporters:
  otlphttp:
    endpoint: "https://backend:4318"
    headers:
      DD-API-KEY: "abc123secret"
      Authorization: "Bearer token123"
      api-key: "super-secret-value-123"
service:
  pipelines:
    traces:
      receivers: [otlp]
      exporters: [otlphttp]
`), 0644)

	// Text output
	cmd := newAnalyzeCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{f})
	cmd.Execute()
	textOut := buf.String()

	secrets := []string{"abc123secret", "token123", "super-secret-value-123"}
	for _, s := range secrets {
		if strings.Contains(textOut, s) {
			t.Errorf("text output must not contain secret value %q", s)
		}
	}
	if !strings.Contains(textOut, "REDACTED") {
		t.Error("text output must contain REDACTED marker")
	}

	// JSON output
	cmd2 := newAnalyzeCmd()
	buf2 := new(bytes.Buffer)
	cmd2.SetOut(buf2)
	cmd2.SetErr(buf2)
	cmd2.SetArgs([]string{"--format", "json", f})
	cmd2.Execute()
	jsonOut := buf2.String()

	for _, s := range secrets {
		if strings.Contains(jsonOut, s) {
			t.Errorf("JSON output must not contain secret value %q", s)
		}
	}
	if !strings.Contains(jsonOut, "REDACTED") {
		t.Error("JSON output must contain REDACTED marker")
	}
}

func TestGolden_SecretRedacted_AllFormats(t *testing.T) {
	fixture := filepath.Join("..", "..", "examples", "bad", "security.yaml")
	if _, err := os.Stat(fixture); err != nil {
		t.Skipf("fixture not found: %s", fixture)
	}

	secret := "plaintext-secret-here"
	formats := []string{"text", "json", "sarif"}

	for _, f := range formats {
		t.Run(f, func(t *testing.T) {
			cmd := newAnalyzeCmd()
			buf := new(bytes.Buffer)
			cmd.SetOut(buf)
			cmd.SetErr(buf)
			cmd.SetArgs([]string{"--format", f, fixture})
			cmd.Execute()
			out := buf.String()

			if strings.Contains(out, secret) {
				t.Errorf("%s output must not contain secret value %q", f, secret)
			}
			if !strings.Contains(out, "REDACTED") {
				t.Errorf("%s output must contain REDACTED marker", f)
			}
		})
	}
}
