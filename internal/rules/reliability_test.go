package rules

import (
	"testing"

	"github.com/firfircelik/oteldoctor/internal/graph"
	"github.com/firfircelik/oteldoctor/internal/model"
)

func relConfig() *model.CollectorConfig {
	return &model.CollectorConfig{
		Receivers:  make(map[string]model.Component),
		Processors: make(map[string]model.Component),
		Exporters:  make(map[string]model.Component),
		Extensions: make(map[string]model.Component),
		Service: model.ServiceConfig{
			Pipelines: make(map[string]model.Pipeline),
		},
	}
}

func setRelReceiver(cfg *model.CollectorConfig, id string, line int) {
	cfg.Receivers[id] = model.Component{
		ID: id, Kind: model.ComponentKindReceiver,
		Location: model.SourceLocation{File: "test.yaml", Line: line},
	}
}

func setRelProcessor(cfg *model.CollectorConfig, id string, line int) {
	cfg.Processors[id] = model.Component{
		ID: id, Kind: model.ComponentKindProcessor,
		Location: model.SourceLocation{File: "test.yaml", Line: line},
	}
}

func setRelExporter(cfg *model.CollectorConfig, id string, config map[string]any, line int) {
	cfg.Exporters[id] = model.Component{
		ID: id, Kind: model.ComponentKindExporter,
		Config:   config,
		Location: model.SourceLocation{File: "test.yaml", Line: line},
	}
}

func setRelExtension(cfg *model.CollectorConfig, id string, line int) {
	cfg.Extensions[id] = model.Component{
		ID: id, Kind: model.ComponentKindExtension,
		Location: model.SourceLocation{File: "test.yaml", Line: line},
	}
}

func setRelPipeline(cfg *model.CollectorConfig, signal string, receivers, processors, exporters []string, line int) {
	cfg.Service.Pipelines[signal] = model.Pipeline{
		SignalType: model.SignalType(signal),
		Receivers:  receivers,
		Processors: processors,
		Exporters:  exporters,
		Location: model.SourceLocation{File: "test.yaml", Line: line},
	}
}

func setRelServiceExts(cfg *model.CollectorConfig, exts []string) {
	cfg.Service.Extensions = exts
}

func TestMemLimiterMissing_Production(t *testing.T) {
	cfg := relConfig()
	setRelReceiver(cfg, "otlp", 2)
	setRelProcessor(cfg, "batch", 8)
	setRelExporter(cfg, "debug", nil, 12)
	setRelPipeline(cfg, "traces", []string{"otlp"}, []string{"batch"}, []string{"debug"}, 16)

	g := graph.Build(cfg)
	rule := NewMemLimiterMissingRule()
	diags := rule.Check(RuleContext{Config: cfg, Graph: g, Profile: "production"})

	if len(diags) != 1 {
		t.Fatalf("expected 1 diagnostic for missing memory_limiter, got %d", len(diags))
	}
	if diags[0].Severity != model.SeverityHigh {
		t.Errorf("expected high severity in production, got %q", diags[0].Severity)
	}
}

func TestMemLimiterMissing_Development(t *testing.T) {
	cfg := relConfig()
	setRelReceiver(cfg, "otlp", 2)
	setRelProcessor(cfg, "batch", 8)
	setRelExporter(cfg, "debug", nil, 12)
	setRelPipeline(cfg, "traces", []string{"otlp"}, []string{"batch"}, []string{"debug"}, 16)

	g := graph.Build(cfg)
	rule := NewMemLimiterMissingRule()
	diags := rule.Check(RuleContext{Config: cfg, Graph: g, Profile: "development"})

	if len(diags) != 0 {
		t.Errorf("expected 0 diagnostics in development, got %d", len(diags))
	}
}

func TestMemLimiterMissing_Present(t *testing.T) {
	cfg := relConfig()
	setRelReceiver(cfg, "otlp", 2)
	setRelProcessor(cfg, "memory_limiter", 6)
	setRelProcessor(cfg, "batch", 8)
	setRelExporter(cfg, "debug", nil, 12)
	setRelPipeline(cfg, "traces", []string{"otlp"}, []string{"memory_limiter", "batch"}, []string{"debug"}, 16)

	g := graph.Build(cfg)
	rule := NewMemLimiterMissingRule()
	diags := rule.Check(RuleContext{Config: cfg, Graph: g, Profile: "production"})

	if len(diags) != 0 {
		t.Errorf("expected 0 diagnostics when memory_limiter is present, got %d", len(diags))
	}
}

func TestMemLimiterOrder_First(t *testing.T) {
	cfg := relConfig()
	setRelReceiver(cfg, "otlp", 2)
	setRelProcessor(cfg, "memory_limiter", 6)
	setRelProcessor(cfg, "batch", 8)
	setRelExporter(cfg, "debug", nil, 12)
	setRelPipeline(cfg, "traces", []string{"otlp"}, []string{"memory_limiter", "batch"}, []string{"debug"}, 16)

	g := graph.Build(cfg)
	rule := NewMemLimiterOrderRule()
	diags := rule.Check(RuleContext{Config: cfg, Graph: g})

	if len(diags) != 0 {
		t.Errorf("expected 0 diagnostics, got %d", len(diags))
	}
}

func TestMemLimiterOrder_NotFirst(t *testing.T) {
	cfg := relConfig()
	setRelReceiver(cfg, "otlp", 2)
	setRelProcessor(cfg, "batch", 8)
	setRelProcessor(cfg, "memory_limiter", 10)
	setRelExporter(cfg, "debug", nil, 12)
	setRelPipeline(cfg, "traces", []string{"otlp"}, []string{"batch", "memory_limiter"}, []string{"debug"}, 16)

	g := graph.Build(cfg)
	rule := NewMemLimiterOrderRule()
	diags := rule.Check(RuleContext{Config: cfg, Graph: g})

	if len(diags) != 1 {
		t.Fatalf("expected 1 diagnostic, got %d", len(diags))
	}
	if diags[0].Location.Line != 16 {
		t.Errorf("expected pipeline location line 16, got %d", diags[0].Location.Line)
	}
}

func TestMemLimiterOrder_NotPresent(t *testing.T) {
	cfg := relConfig()
	setRelReceiver(cfg, "otlp", 2)
	setRelProcessor(cfg, "batch", 8)
	setRelExporter(cfg, "debug", nil, 12)
	setRelPipeline(cfg, "traces", []string{"otlp"}, []string{"batch"}, []string{"debug"}, 16)

	g := graph.Build(cfg)
	rule := NewMemLimiterOrderRule()
	diags := rule.Check(RuleContext{Config: cfg, Graph: g})

	if len(diags) != 0 {
		t.Errorf("expected 0 diagnostics when memory_limiter is absent, got %d", len(diags))
	}
}

func TestBatchMissing_Detected(t *testing.T) {
	cfg := relConfig()
	setRelReceiver(cfg, "otlp", 2)
	setRelProcessor(cfg, "memory_limiter", 6)
	setRelExporter(cfg, "debug", nil, 12)
	setRelPipeline(cfg, "traces", []string{"otlp"}, []string{"memory_limiter"}, []string{"debug"}, 16)

	g := graph.Build(cfg)
	rule := NewBatchMissingRule()
	diags := rule.Check(RuleContext{Config: cfg, Graph: g, Profile: "production"})

	if len(diags) != 1 {
		t.Fatalf("expected 1 diagnostic, got %d", len(diags))
	}
	if diags[0].Severity != model.SeverityMedium {
		t.Errorf("expected medium severity in production, got %q", diags[0].Severity)
	}
}

func TestBatchMissing_Present(t *testing.T) {
	cfg := relConfig()
	setRelReceiver(cfg, "otlp", 2)
	setRelProcessor(cfg, "memory_limiter", 6)
	setRelProcessor(cfg, "batch", 8)
	setRelExporter(cfg, "debug", nil, 12)
	setRelPipeline(cfg, "traces", []string{"otlp"}, []string{"memory_limiter", "batch"}, []string{"debug"}, 16)

	g := graph.Build(cfg)
	rule := NewBatchMissingRule()
	diags := rule.Check(RuleContext{Config: cfg, Graph: g})

	if len(diags) != 0 {
		t.Errorf("expected 0 diagnostics, got %d", len(diags))
	}
}

func TestBatchMissing_LowSeverityDevelopment(t *testing.T) {
	cfg := relConfig()
	setRelReceiver(cfg, "otlp", 2)
	setRelProcessor(cfg, "memory_limiter", 6)
	setRelExporter(cfg, "debug", nil, 12)
	setRelPipeline(cfg, "traces", []string{"otlp"}, []string{"memory_limiter"}, []string{"debug"}, 16)

	g := graph.Build(cfg)
	rule := NewBatchMissingRule()
	diags := rule.Check(RuleContext{Config: cfg, Graph: g, Profile: "development"})

	if len(diags) != 1 {
		t.Fatalf("expected 1 diagnostic in development, got %d", len(diags))
	}
	if diags[0].Severity != model.SeverityLow {
		t.Errorf("expected low severity in development, got %q", diags[0].Severity)
	}
}

func TestBatchMissing_SkipsEmptyPipeline(t *testing.T) {
	cfg := relConfig()
	setRelReceiver(cfg, "otlp", 2)
	setRelProcessor(cfg, "batch", 6)
	setRelExporter(cfg, "debug", nil, 10)
	setRelPipeline(cfg, "empty", nil, nil, nil, 14)

	g := graph.Build(cfg)
	rule := NewBatchMissingRule()
	diags := rule.Check(RuleContext{Config: cfg, Graph: g})

	if len(diags) != 0 {
		t.Fatalf("expected 0 diagnostics for empty pipeline, got %d", len(diags))
	}
}

func TestBatchMissing_ValidPipelineWithoutBatch(t *testing.T) {
	cfg := relConfig()
	setRelReceiver(cfg, "otlp", 2)
	setRelProcessor(cfg, "memory_limiter", 6)
	setRelExporter(cfg, "debug", nil, 10)
	setRelPipeline(cfg, "traces", []string{"otlp"}, []string{"memory_limiter"}, []string{"debug"}, 14)

	g := graph.Build(cfg)
	rule := NewBatchMissingRule()
	diags := rule.Check(RuleContext{Config: cfg, Graph: g, Profile: "production"})

	if len(diags) != 1 {
		t.Fatalf("expected 1 diagnostic for valid pipeline without batch, got %d", len(diags))
	}
}

func TestMemLimiterMissing_SkipsEmptyPipeline(t *testing.T) {
	cfg := relConfig()
	setRelReceiver(cfg, "otlp", 2)
	setRelExporter(cfg, "debug", nil, 10)
	setRelPipeline(cfg, "empty", nil, nil, nil, 14)

	g := graph.Build(cfg)
	rule := NewMemLimiterMissingRule()
	diags := rule.Check(RuleContext{Config: cfg, Graph: g, Profile: "production"})

	if len(diags) != 0 {
		t.Fatalf("expected 0 diagnostics for empty pipeline, got %d", len(diags))
	}
}

func TestBatchBeforeTransform_NoTransform(t *testing.T) {
	cfg := relConfig()
	setRelReceiver(cfg, "otlp", 2)
	setRelProcessor(cfg, "memory_limiter", 6)
	setRelProcessor(cfg, "batch", 8)
	setRelExporter(cfg, "debug", nil, 12)
	setRelPipeline(cfg, "traces", []string{"otlp"}, []string{"memory_limiter", "batch"}, []string{"debug"}, 16)

	g := graph.Build(cfg)
	rule := NewBatchBeforeTransformRule()
	diags := rule.Check(RuleContext{Config: cfg, Graph: g})

	if len(diags) != 0 {
		t.Errorf("expected 0 diagnostics when no transform follows batch, got %d", len(diags))
	}
}

func TestBatchBeforeTransform_BeforeFilter(t *testing.T) {
	cfg := relConfig()
	setRelReceiver(cfg, "otlp", 2)
	setRelProcessor(cfg, "memory_limiter", 6)
	setRelProcessor(cfg, "batch", 8)
	setRelProcessor(cfg, "filter", 10)
	setRelExporter(cfg, "debug", nil, 12)
	setRelPipeline(cfg, "traces", []string{"otlp"}, []string{"memory_limiter", "batch", "filter"}, []string{"debug"}, 16)

	g := graph.Build(cfg)
	rule := NewBatchBeforeTransformRule()
	diags := rule.Check(RuleContext{Config: cfg, Graph: g})

	if len(diags) != 1 {
		t.Fatalf("expected 1 diagnostic when batch is before filter, got %d", len(diags))
	}
}

func TestBatchBeforeTransform_AfterFilter(t *testing.T) {
	cfg := relConfig()
	setRelReceiver(cfg, "otlp", 2)
	setRelProcessor(cfg, "memory_limiter", 6)
	setRelProcessor(cfg, "filter", 8)
	setRelProcessor(cfg, "batch", 10)
	setRelExporter(cfg, "debug", nil, 12)
	setRelPipeline(cfg, "traces", []string{"otlp"}, []string{"memory_limiter", "filter", "batch"}, []string{"debug"}, 16)

	g := graph.Build(cfg)
	rule := NewBatchBeforeTransformRule()
	diags := rule.Check(RuleContext{Config: cfg, Graph: g})

	if len(diags) != 0 {
		t.Errorf("expected 0 diagnostics when batch is after filter, got %d", len(diags))
	}
}

func TestBatchBeforeTransform_NoBatch(t *testing.T) {
	cfg := relConfig()
	setRelReceiver(cfg, "otlp", 2)
	setRelProcessor(cfg, "memory_limiter", 6)
	setRelProcessor(cfg, "filter", 8)
	setRelExporter(cfg, "debug", nil, 12)
	setRelPipeline(cfg, "traces", []string{"otlp"}, []string{"memory_limiter", "filter"}, []string{"debug"}, 16)

	g := graph.Build(cfg)
	rule := NewBatchBeforeTransformRule()
	diags := rule.Check(RuleContext{Config: cfg, Graph: g})

	if len(diags) != 0 {
		t.Errorf("expected 0 diagnostics when no batch, got %d", len(diags))
	}
}

func TestExporterRetryMissing_Detected(t *testing.T) {
	cfg := relConfig()
	setRelReceiver(cfg, "otlp", 2)
	setRelExporter(cfg, "otlphttp", map[string]any{"endpoint": "https://backend:4318"}, 10)
	setRelPipeline(cfg, "traces", []string{"otlp"}, nil, []string{"otlphttp"}, 14)

	g := graph.Build(cfg)
	rule := NewExporterRetryMissingRule()
	diags := rule.Check(RuleContext{Config: cfg, Graph: g, Profile: "production"})

	if len(diags) != 1 {
		t.Fatalf("expected 1 diagnostic, got %d", len(diags))
	}
	if diags[0].Severity != model.SeverityMedium {
		t.Errorf("expected medium severity in production, got %q", diags[0].Severity)
	}
	if diags[0].Location.Line != 10 {
		t.Errorf("expected exporter location line 10, got %d", diags[0].Location.Line)
	}
}

func TestExporterRetryMissing_Present(t *testing.T) {
	cfg := relConfig()
	setRelReceiver(cfg, "otlp", 2)
	setRelExporter(cfg, "otlphttp", map[string]any{
		"endpoint":         "https://backend:4318",
		"retry_on_failure": map[string]any{"enabled": true},
	}, 10)
	setRelPipeline(cfg, "traces", []string{"otlp"}, nil, []string{"otlphttp"}, 14)

	g := graph.Build(cfg)
	rule := NewExporterRetryMissingRule()
	diags := rule.Check(RuleContext{Config: cfg, Graph: g})

	if len(diags) != 0 {
		t.Errorf("expected 0 diagnostics when retry configured, got %d", len(diags))
	}
}

func TestExporterRetryMissing_UnusedExporter(t *testing.T) {
	cfg := relConfig()
	setRelReceiver(cfg, "otlp", 2)
	setRelExporter(cfg, "otlphttp", map[string]any{"endpoint": "https://backend:4318"}, 10)
	setRelExporter(cfg, "zipkin", map[string]any{"endpoint": "https://zipkin:9411"}, 12)
	setRelPipeline(cfg, "traces", []string{"otlp"}, nil, []string{"otlphttp"}, 14)

	g := graph.Build(cfg)
	rule := NewExporterRetryMissingRule()
	diags := rule.Check(RuleContext{Config: cfg, Graph: g, Profile: "production"})

	if len(diags) != 1 {
		t.Fatalf("expected 1 diagnostic for used otlphttp exporter, got %d", len(diags))
	}
	if diags[0].Location.Line != 10 {
		t.Errorf("expected otlphttp exporter line 10, got %d", diags[0].Location.Line)
	}

	for _, d := range diags {
		if d.Location.Line == 12 {
			t.Error("unused zipkin exporter should not be flagged")
		}
	}
}

func TestExporterQueueMissing_Detected(t *testing.T) {
	cfg := relConfig()
	setRelReceiver(cfg, "otlp", 2)
	setRelExporter(cfg, "otlphttp", map[string]any{"endpoint": "https://backend:4318"}, 10)
	setRelPipeline(cfg, "traces", []string{"otlp"}, nil, []string{"otlphttp"}, 14)

	g := graph.Build(cfg)
	rule := NewExporterQueueMissingRule()
	diags := rule.Check(RuleContext{Config: cfg, Graph: g, Profile: "production"})

	if len(diags) != 1 {
		t.Fatalf("expected 1 diagnostic, got %d", len(diags))
	}
	if diags[0].Severity != model.SeverityMedium {
		t.Errorf("expected medium severity in production, got %q", diags[0].Severity)
	}
}

func TestExporterQueueMissing_Present(t *testing.T) {
	cfg := relConfig()
	setRelReceiver(cfg, "otlp", 2)
	setRelExporter(cfg, "otlphttp", map[string]any{
		"endpoint":      "https://backend:4318",
		"sending_queue": map[string]any{"num_consumers": 10},
	}, 10)
	setRelPipeline(cfg, "traces", []string{"otlp"}, nil, []string{"otlphttp"}, 14)

	g := graph.Build(cfg)
	rule := NewExporterQueueMissingRule()
	diags := rule.Check(RuleContext{Config: cfg, Graph: g})

	if len(diags) != 0 {
		t.Errorf("expected 0 diagnostics when queue configured, got %d", len(diags))
	}
}

func TestHealthCheckMissing_Production(t *testing.T) {
	cfg := relConfig()
	setRelReceiver(cfg, "otlp", 2)
	setRelExporter(cfg, "debug", nil, 12)
	setRelPipeline(cfg, "traces", []string{"otlp"}, nil, []string{"debug"}, 16)

	g := graph.Build(cfg)
	rule := NewHealthCheckMissingRule()
	diags := rule.Check(RuleContext{Config: cfg, Graph: g, Profile: "production"})

	if len(diags) != 1 {
		t.Fatalf("expected 1 diagnostic in production, got %d", len(diags))
	}
	if diags[0].Severity != model.SeverityMedium {
		t.Errorf("expected medium severity, got %q", diags[0].Severity)
	}
}

func TestHealthCheckMissing_Development(t *testing.T) {
	cfg := relConfig()
	setRelReceiver(cfg, "otlp", 2)
	setRelExporter(cfg, "debug", nil, 12)
	setRelPipeline(cfg, "traces", []string{"otlp"}, nil, []string{"debug"}, 16)

	g := graph.Build(cfg)
	rule := NewHealthCheckMissingRule()
	diags := rule.Check(RuleContext{Config: cfg, Graph: g, Profile: "development"})

	if len(diags) != 0 {
		t.Errorf("expected 0 diagnostics in development, got %d", len(diags))
	}
}

func TestHealthCheckMissing_Present(t *testing.T) {
	cfg := relConfig()
	setRelReceiver(cfg, "otlp", 2)
	setRelExporter(cfg, "debug", nil, 12)
	setRelExtension(cfg, "health_check", 4)
	setRelPipeline(cfg, "traces", []string{"otlp"}, nil, []string{"debug"}, 16)

	g := graph.Build(cfg)
	rule := NewHealthCheckMissingRule()
	diags := rule.Check(RuleContext{Config: cfg, Graph: g, Profile: "production"})

	if len(diags) != 0 {
		t.Errorf("expected 0 diagnostics when health_check defined, got %d", len(diags))
	}
}

func TestHealthCheckNotEnabled_Detected(t *testing.T) {
	cfg := relConfig()
	setRelReceiver(cfg, "otlp", 2)
	setRelExporter(cfg, "debug", nil, 12)
	setRelExtension(cfg, "health_check", 4)
	setRelPipeline(cfg, "traces", []string{"otlp"}, nil, []string{"debug"}, 16)
	setRelServiceExts(cfg, []string{}) // health_check not in service.extensions

	g := graph.Build(cfg)
	rule := NewHealthCheckNotEnabledRule()
	diags := rule.Check(RuleContext{Config: cfg, Graph: g})

	if len(diags) != 1 {
		t.Fatalf("expected 1 diagnostic, got %d", len(diags))
	}
	if diags[0].Location.Line != 4 {
		t.Errorf("expected extension location line 4, got %d", diags[0].Location.Line)
	}
}

func TestHealthCheckNotEnabled_Enabled(t *testing.T) {
	cfg := relConfig()
	setRelReceiver(cfg, "otlp", 2)
	setRelExporter(cfg, "debug", nil, 12)
	setRelExtension(cfg, "health_check", 4)
	setRelPipeline(cfg, "traces", []string{"otlp"}, nil, []string{"debug"}, 16)
	setRelServiceExts(cfg, []string{"health_check"})

	g := graph.Build(cfg)
	rule := NewHealthCheckNotEnabledRule()
	diags := rule.Check(RuleContext{Config: cfg, Graph: g})

	if len(diags) != 0 {
		t.Errorf("expected 0 diagnostics when enabled, got %d", len(diags))
	}
}

func TestHealthCheckNotEnabled_NotDefined(t *testing.T) {
	cfg := relConfig()
	setRelReceiver(cfg, "otlp", 2)
	setRelExporter(cfg, "debug", nil, 12)
	setRelPipeline(cfg, "traces", []string{"otlp"}, nil, []string{"debug"}, 16)

	g := graph.Build(cfg)
	rule := NewHealthCheckNotEnabledRule()
	diags := rule.Check(RuleContext{Config: cfg, Graph: g})

	if len(diags) != 0 {
		t.Errorf("expected 0 diagnostics when health_check not defined, got %d", len(diags))
	}
}
