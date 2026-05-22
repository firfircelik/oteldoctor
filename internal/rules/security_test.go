package rules

import (
	"strings"
	"testing"

	"github.com/firfircelik/oteldoctor/internal/graph"
	"github.com/firfircelik/oteldoctor/internal/model"
)

func TestPlainHTTPExporter_Detected(t *testing.T) {
	cfg := relConfig()
	setRelReceiver(cfg, "otlp", 2)
	setRelExporter(cfg, "otlphttp", map[string]any{
		"endpoint": "http://backend.example.com:4318",
	}, 10)
	setRelPipeline(cfg, "traces", []string{"otlp"}, nil, []string{"otlphttp"}, 14)

	g := graph.Build(cfg)
	rule := NewPlainHTTPExporterRule()
	diags := rule.Check(RuleContext{Config: cfg, Graph: g, Profile: "production"})

	if len(diags) != 1 {
		t.Fatalf("expected 1 diagnostic, got %d", len(diags))
	}
}

func TestPlainHTTPExporter_HTTPS_OK(t *testing.T) {
	cfg := relConfig()
	setRelReceiver(cfg, "otlp", 2)
	setRelExporter(cfg, "otlphttp", map[string]any{
		"endpoint": "https://backend.example.com:4318",
	}, 10)
	setRelPipeline(cfg, "traces", []string{"otlp"}, nil, []string{"otlphttp"}, 14)

	g := graph.Build(cfg)
	rule := NewPlainHTTPExporterRule()
	diags := rule.Check(RuleContext{Config: cfg, Graph: g, Profile: "production"})

	if len(diags) != 0 {
		t.Errorf("expected 0 diagnostics for HTTPS, got %d", len(diags))
	}
}

func TestPlainHTTPExporter_Localhost_OK(t *testing.T) {
	cfg := relConfig()
	setRelReceiver(cfg, "otlp", 2)
	setRelExporter(cfg, "otlphttp", map[string]any{
		"endpoint": "http://localhost:8888",
	}, 10)
	setRelPipeline(cfg, "traces", []string{"otlp"}, nil, []string{"otlphttp"}, 14)

	g := graph.Build(cfg)
	rule := NewPlainHTTPExporterRule()
	diags := rule.Check(RuleContext{Config: cfg, Graph: g, Profile: "production"})

	if len(diags) != 0 {
		t.Errorf("expected 0 diagnostics for localhost HTTP, got %d", len(diags))
	}
}

func TestPlainHTTPExporter_Development_Skipped(t *testing.T) {
	cfg := relConfig()
	setRelReceiver(cfg, "otlp", 2)
	setRelExporter(cfg, "otlphttp", map[string]any{
		"endpoint": "http://backend.example.com:4318",
	}, 10)
	setRelPipeline(cfg, "traces", []string{"otlp"}, nil, []string{"otlphttp"}, 14)

	g := graph.Build(cfg)
	rule := NewPlainHTTPExporterRule()
	diags := rule.Check(RuleContext{Config: cfg, Graph: g, Profile: "development"})

	if len(diags) != 0 {
		t.Errorf("expected 0 diagnostics in development, got %d", len(diags))
	}
}

func TestHardcodedSecret_Detected_InHeaders(t *testing.T) {
	cfg := relConfig()
	setRelReceiver(cfg, "otlp", 2)
	setRelExporter(cfg, "otlphttp", map[string]any{
		"endpoint": "https://backend:4318",
		"headers": map[string]any{
			"DD-API-KEY": "abc123secret",
		},
	}, 10)
	setRelPipeline(cfg, "traces", []string{"otlp"}, nil, []string{"otlphttp"}, 14)

	g := graph.Build(cfg)
	rule := NewHardcodedSecretRule()
	diags := rule.Check(RuleContext{Config: cfg, Graph: g})

	if len(diags) != 1 {
		t.Fatalf("expected 1 diagnostic, got %d", len(diags))
	}

	d := diags[0]
	if strings.Contains(d.Message, "abc123") {
		t.Error("diagnostic message must not contain secret value")
	}
	if !strings.Contains(d.Message, "[REDACTED]") {
		t.Error("diagnostic message should contain [REDACTED]")
	}
}

func TestHardcodedSecret_EnvVar_OK(t *testing.T) {
	cfg := relConfig()
	setRelReceiver(cfg, "otlp", 2)
	setRelExporter(cfg, "otlphttp", map[string]any{
		"endpoint": "https://backend:4318",
		"headers": map[string]any{
			"DD-API-KEY": "${env:DD_API_KEY}",
		},
	}, 10)
	setRelPipeline(cfg, "traces", []string{"otlp"}, nil, []string{"otlphttp"}, 14)

	g := graph.Build(cfg)
	rule := NewHardcodedSecretRule()
	diags := rule.Check(RuleContext{Config: cfg, Graph: g})

	if len(diags) != 0 {
		t.Errorf("expected 0 diagnostics for env var refs, got %d", len(diags))
	}
}

func TestHardcodedSecret_NoHeaders(t *testing.T) {
	cfg := relConfig()
	setRelReceiver(cfg, "otlp", 2)
	setRelExporter(cfg, "otlphttp", map[string]any{
		"endpoint": "https://backend:4318",
	}, 10)
	setRelPipeline(cfg, "traces", []string{"otlp"}, nil, []string{"otlphttp"}, 14)

	g := graph.Build(cfg)
	rule := NewHardcodedSecretRule()
	diags := rule.Check(RuleContext{Config: cfg, Graph: g})

	if len(diags) != 0 {
		t.Errorf("expected 0 diagnostics, got %d", len(diags))
	}
}

func TestHardcodedSecret_InReceiverAuth(t *testing.T) {
	cfg := relConfig()
	setRelReceiver(cfg, "otlp", 2)
	cfg.Receivers["otlp"] = model.Component{
		ID: "otlp", Kind: model.ComponentKindReceiver,
		Config: map[string]any{
			"protocols": map[string]any{
				"grpc": map[string]any{
					"endpoint": "0.0.0.0:4317",
				},
			},
			"auth": map[string]any{
				"token": "hardcoded123",
			},
		},
		Location: model.SourceLocation{File: "test.yaml", Line: 2},
	}
	setRelExporter(cfg, "debug", nil, 10)
	setRelPipeline(cfg, "traces", []string{"otlp"}, nil, []string{"debug"}, 14)

	g := graph.Build(cfg)
	rule := NewHardcodedSecretRule()
	diags := rule.Check(RuleContext{Config: cfg, Graph: g})

	if len(diags) != 1 {
		t.Fatalf("expected 1 diagnostic for receiver auth secret, got %d", len(diags))
	}
	if strings.Contains(diags[0].Message, "hardcoded123") {
		t.Error("diagnostic message must not contain secret value")
	}
}

func TestReceiverZeroAddr_Detected(t *testing.T) {
	cfg := relConfig()
	setRelReceiver(cfg, "otlp", 2)
	cfg.Receivers["otlp"] = model.Component{
		ID: "otlp", Kind: model.ComponentKindReceiver,
		Config: map[string]any{
			"protocols": map[string]any{
				"grpc": map[string]any{
					"endpoint": "0.0.0.0:4317",
				},
			},
		},
		Location: model.SourceLocation{File: "test.yaml", Line: 2},
	}
	setRelExporter(cfg, "debug", nil, 10)
	setRelPipeline(cfg, "traces", []string{"otlp"}, nil, []string{"debug"}, 14)

	g := graph.Build(cfg)
	rule := NewReceiverZeroAddrRule()
	diags := rule.Check(RuleContext{Config: cfg, Graph: g, Profile: "production"})

	if len(diags) != 1 {
		t.Fatalf("expected 1 diagnostic, got %d", len(diags))
	}
}

func TestReceiverZeroAddr_WithTLS(t *testing.T) {
	cfg := relConfig()
	setRelReceiver(cfg, "otlp", 2)
	cfg.Receivers["otlp"] = model.Component{
		ID: "otlp", Kind: model.ComponentKindReceiver,
		Config: map[string]any{
			"endpoint": "0.0.0.0:4317",
			"tls": map[string]any{
				"cert_file": "/tls/cert.pem",
			},
		},
		Location: model.SourceLocation{File: "test.yaml", Line: 2},
	}
	setRelExporter(cfg, "debug", nil, 10)
	setRelPipeline(cfg, "traces", []string{"otlp"}, nil, []string{"debug"}, 14)

	g := graph.Build(cfg)
	rule := NewReceiverZeroAddrRule()
	diags := rule.Check(RuleContext{Config: cfg, Graph: g})

	if len(diags) != 0 {
		t.Errorf("expected 0 diagnostics when TLS is configured, got %d", len(diags))
	}
}

func TestReceiverZeroAddr_NotZero(t *testing.T) {
	cfg := relConfig()
	setRelReceiver(cfg, "otlp", 2)
	cfg.Receivers["otlp"] = model.Component{
		ID: "otlp", Kind: model.ComponentKindReceiver,
		Config: map[string]any{
			"endpoint": "localhost:4317",
		},
		Location: model.SourceLocation{File: "test.yaml", Line: 2},
	}
	setRelExporter(cfg, "debug", nil, 10)
	setRelPipeline(cfg, "traces", []string{"otlp"}, nil, []string{"debug"}, 14)

	g := graph.Build(cfg)
	rule := NewReceiverZeroAddrRule()
	diags := rule.Check(RuleContext{Config: cfg, Graph: g})

	if len(diags) != 0 {
		t.Errorf("expected 0 diagnostics for non-0.0.0.0 endpoint, got %d", len(diags))
	}
}

func TestDebugExporterInProd_Detected(t *testing.T) {
	cfg := relConfig()
	setRelReceiver(cfg, "otlp", 2)
	setRelExporter(cfg, "debug", nil, 10)
	setRelPipeline(cfg, "traces", []string{"otlp"}, nil, []string{"debug"}, 14)

	g := graph.Build(cfg)
	rule := NewDebugExporterInProdRule()
	diags := rule.Check(RuleContext{Config: cfg, Graph: g, Profile: "production"})

	if len(diags) != 1 {
		t.Fatalf("expected 1 diagnostic, got %d", len(diags))
	}
	if diags[0].Severity != model.SeverityMedium {
		t.Errorf("expected medium severity, got %q", diags[0].Severity)
	}
}

func TestDebugExporterInProd_Development_Skipped(t *testing.T) {
	cfg := relConfig()
	setRelReceiver(cfg, "otlp", 2)
	setRelExporter(cfg, "debug", nil, 10)
	setRelPipeline(cfg, "traces", []string{"otlp"}, nil, []string{"debug"}, 14)

	g := graph.Build(cfg)
	rule := NewDebugExporterInProdRule()
	diags := rule.Check(RuleContext{Config: cfg, Graph: g, Profile: "development"})

	if len(diags) != 0 {
		t.Errorf("expected 0 diagnostics in development, got %d", len(diags))
	}
}

func TestDebugExtensionExposed_ZeroAddr(t *testing.T) {
	cfg := relConfig()
	setRelReceiver(cfg, "otlp", 2)
	setRelExporter(cfg, "debug", nil, 10)
	setRelExtension(cfg, "pprof", 4)
	cfg.Extensions["pprof"] = model.Component{
		ID: "pprof", Kind: model.ComponentKindExtension,
		Config: map[string]any{
			"endpoint": "0.0.0.0:1777",
		},
		Location: model.SourceLocation{File: "test.yaml", Line: 4},
	}
	setRelPipeline(cfg, "traces", []string{"otlp"}, nil, []string{"debug"}, 14)

	g := graph.Build(cfg)
	rule := NewDebugExtensionExposedRule()
	diags := rule.Check(RuleContext{Config: cfg, Graph: g, Profile: "production"})

	if len(diags) != 1 {
		t.Fatalf("expected 1 diagnostic, got %d", len(diags))
	}
}

func TestDebugExtensionExposed_Localhost_OK(t *testing.T) {
	cfg := relConfig()
	setRelReceiver(cfg, "otlp", 2)
	setRelExporter(cfg, "debug", nil, 10)
	setRelExtension(cfg, "pprof", 4)
	cfg.Extensions["pprof"] = model.Component{
		ID: "pprof", Kind: model.ComponentKindExtension,
		Config: map[string]any{
			"endpoint": "localhost:1777",
		},
		Location: model.SourceLocation{File: "test.yaml", Line: 4},
	}
	setRelPipeline(cfg, "traces", []string{"otlp"}, nil, []string{"debug"}, 14)

	g := graph.Build(cfg)
	rule := NewDebugExtensionExposedRule()
	diags := rule.Check(RuleContext{Config: cfg, Graph: g})

	if len(diags) != 0 {
		t.Errorf("expected 0 diagnostics for localhost, got %d", len(diags))
	}
}

func TestTLSMissingExporter_Detected(t *testing.T) {
	cfg := relConfig()
	setRelReceiver(cfg, "otlp", 2)
	setRelExporter(cfg, "otlphttp", map[string]any{
		"endpoint": "https://backend.example.com:4318",
	}, 10)
	setRelPipeline(cfg, "traces", []string{"otlp"}, nil, []string{"otlphttp"}, 14)

	g := graph.Build(cfg)
	rule := NewTLSMissingExporterRule()
	diags := rule.Check(RuleContext{Config: cfg, Graph: g, Profile: "production"})

	if len(diags) != 1 {
		t.Fatalf("expected 1 diagnostic for missing TLS, got %d", len(diags))
	}
}

func TestTLSMissingExporter_WithTLS(t *testing.T) {
	cfg := relConfig()
	setRelReceiver(cfg, "otlp", 2)
	setRelExporter(cfg, "otlphttp", map[string]any{
		"endpoint": "https://backend.example.com:4318",
		"tls": map[string]any{
			"insecure": false,
		},
	}, 10)
	setRelPipeline(cfg, "traces", []string{"otlp"}, nil, []string{"otlphttp"}, 14)

	g := graph.Build(cfg)
	rule := NewTLSMissingExporterRule()
	diags := rule.Check(RuleContext{Config: cfg, Graph: g})

	if len(diags) != 0 {
		t.Errorf("expected 0 diagnostics when TLS configured, got %d", len(diags))
	}
}

func TestTLSMissingExporter_Localhost_OK(t *testing.T) {
	cfg := relConfig()
	setRelReceiver(cfg, "otlp", 2)
	setRelExporter(cfg, "otlphttp", map[string]any{
		"endpoint": "localhost:4318",
	}, 10)
	setRelPipeline(cfg, "traces", []string{"otlp"}, nil, []string{"otlphttp"}, 14)

	g := graph.Build(cfg)
	rule := NewTLSMissingExporterRule()
	diags := rule.Check(RuleContext{Config: cfg, Graph: g})

	if len(diags) != 0 {
		t.Errorf("expected 0 diagnostics for localhost, got %d", len(diags))
	}
}

func TestTLSMissingExporter_PlainHTTPSkipped(t *testing.T) {
	cfg := relConfig()
	setRelReceiver(cfg, "otlp", 2)
	setRelExporter(cfg, "otlphttp", map[string]any{
		"endpoint": "http://api.example.com:4318",
	}, 10)
	setRelPipeline(cfg, "traces", []string{"otlp"}, nil, []string{"otlphttp"}, 14)

	g := graph.Build(cfg)
	rule := NewTLSMissingExporterRule()
	diags := rule.Check(RuleContext{Config: cfg, Graph: g, Profile: "production"})

	if len(diags) != 0 {
		t.Fatalf("expected 0 SEC-206 diagnostics for plain HTTP (handled by SEC-201), got %d", len(diags))
	}
}

func TestTLSMissingExporter_HTTPSWithoutTLS(t *testing.T) {
	cfg := relConfig()
	setRelReceiver(cfg, "otlp", 2)
	setRelExporter(cfg, "otlphttp", map[string]any{
		"endpoint": "https://api.example.com:4318",
	}, 10)
	setRelPipeline(cfg, "traces", []string{"otlp"}, nil, []string{"otlphttp"}, 14)

	g := graph.Build(cfg)
	rule := NewTLSMissingExporterRule()
	diags := rule.Check(RuleContext{Config: cfg, Graph: g, Profile: "production"})

	if len(diags) != 1 {
		t.Fatalf("expected 1 diagnostic for https:// without tls config, got %d", len(diags))
	}
}

func TestTLSMissingExporter_HTTPAndHTTPS(t *testing.T) {
	cfg := relConfig()
	setRelReceiver(cfg, "otlp", 2)
	setRelExporter(cfg, "otlphttp", map[string]any{
		"endpoint": "http://api.example.com:4318",
		"tls": map[string]any{
			"insecure": true,
		},
	}, 10)
	setRelPipeline(cfg, "traces", []string{"otlp"}, nil, []string{"otlphttp"}, 14)

	g := graph.Build(cfg)
	rule := NewTLSMissingExporterRule()
	diags := rule.Check(RuleContext{Config: cfg, Graph: g, Profile: "production"})

	if len(diags) != 0 {
		t.Fatalf("expected 0 SEC-206 for http:// with tls key (plain HTTP handled by SEC-201), got %d", len(diags))
	}
}

func TestAuthExtensionNotEnabled_Detected(t *testing.T) {
	cfg := relConfig()
	setRelReceiver(cfg, "otlp", 2)
	setRelExporter(cfg, "debug", nil, 10)
	setRelExtension(cfg, "oauth2client", 4)
	cfg.Extensions["oauth2client"] = model.Component{
		ID: "oauth2client", Kind: model.ComponentKindExtension,
		Config:   map[string]any{"client_id": "abc"},
		Location: model.SourceLocation{File: "test.yaml", Line: 4},
	}
	setRelPipeline(cfg, "traces", []string{"otlp"}, nil, []string{"debug"}, 14)
	setRelServiceExts(cfg, []string{})

	g := graph.Build(cfg)
	rule := NewAuthExtensionNotEnabledRule()
	diags := rule.Check(RuleContext{Config: cfg, Graph: g})

	if len(diags) != 1 {
		t.Fatalf("expected 1 diagnostic, got %d", len(diags))
	}
	if diags[0].Location.Line != 4 {
		t.Errorf("expected extension location line 4, got %d", diags[0].Location.Line)
	}
}

func TestAuthExtensionNotEnabled_Enabled(t *testing.T) {
	cfg := relConfig()
	setRelReceiver(cfg, "otlp", 2)
	setRelExporter(cfg, "debug", nil, 10)
	setRelExtension(cfg, "bearertokenauth", 4)
	cfg.Extensions["bearertokenauth"] = model.Component{
		ID: "bearertokenauth", Kind: model.ComponentKindExtension,
		Config:   map[string]any{"token": "abc"},
		Location: model.SourceLocation{File: "test.yaml", Line: 4},
	}
	setRelPipeline(cfg, "traces", []string{"otlp"}, nil, []string{"debug"}, 14)
	setRelServiceExts(cfg, []string{"bearertokenauth"})

	g := graph.Build(cfg)
	rule := NewAuthExtensionNotEnabledRule()
	diags := rule.Check(RuleContext{Config: cfg, Graph: g})

	if len(diags) != 0 {
		t.Errorf("expected 0 diagnostics when enabled, got %d", len(diags))
	}
}

func TestAuthExtensionNotEnabled_NotAuthType(t *testing.T) {
	cfg := relConfig()
	setRelReceiver(cfg, "otlp", 2)
	setRelExporter(cfg, "debug", nil, 10)
	setRelExtension(cfg, "health_check", 4)
	setRelPipeline(cfg, "traces", []string{"otlp"}, nil, []string{"debug"}, 14)

	g := graph.Build(cfg)
	rule := NewAuthExtensionNotEnabledRule()
	diags := rule.Check(RuleContext{Config: cfg, Graph: g})

	if len(diags) != 0 {
		t.Errorf("expected 0 diagnostics for non-auth extension, got %d", len(diags))
	}
}
