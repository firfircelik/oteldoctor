package rules

import (
	"fmt"

	"github.com/firfircelik/oteldoctor/internal/graph"
	"github.com/firfircelik/oteldoctor/internal/model"
)

func pickSeverity(profile string, prod, staging, dev model.Severity) model.Severity {
	switch profile {
	case "production":
		return prod
	case "staging":
		return staging
	default:
		return dev
	}
}

func processorTypes(pipelineID string, g *graph.Graph) []string {
	order := g.PipelineProcessorOrder(pipelineID)
	types := make([]string, len(order))
	for i, id := range order {
		types[i] = processorType(id)
	}
	return types
}

func processorType(id string) string {
	cid, err := model.ParseComponentID(id)
	if err != nil {
		return id
	}
	return cid.Type
}

func hasProcessorType(pipelineID string, g *graph.Graph, typ string) bool {
	for _, t := range processorTypes(pipelineID, g) {
		if t == typ {
			return true
		}
	}
	return false
}

func indexOfProcessorType(pipelineID string, g *graph.Graph, typ string) int {
	for i, t := range processorTypes(pipelineID, g) {
		if t == typ {
			return i
		}
	}
	return -1
}

func exporterConfig(cfg *model.CollectorConfig, id string) map[string]any {
	exp, ok := cfg.Exporters[id]
	if !ok {
		return nil
	}
	m, _ := exp.Config.(map[string]any)
	return m
}

func isEmptyPipeline(pl model.Pipeline) bool {
	return len(pl.Receivers) == 0 || len(pl.Exporters) == 0
}

// --- OTEL-REL-101: memory_limiter missing in production ---

type memLimiterMissingRule struct{}

func NewMemLimiterMissingRule() Rule { return &memLimiterMissingRule{} }

func (r *memLimiterMissingRule) ID() string                   { return "OTEL-REL-101" }
func (r *memLimiterMissingRule) Title() string                { return "memory_limiter processor missing" }
func (r *memLimiterMissingRule) Category() model.Category     { return model.CategoryReliability }
func (r *memLimiterMissingRule) DefaultSeverity() model.Severity {
	return model.SeverityHigh
}

func (r *memLimiterMissingRule) Check(ctx RuleContext) []model.Diagnostic {
	if ctx.Profile != "production" && ctx.Profile != "staging" {
		return nil
	}

	var diags []model.Diagnostic
	sev := pickSeverity(ctx.Profile, model.SeverityHigh, model.SeverityMedium, model.SeverityMedium)

	for signal, pl := range ctx.Config.Service.Pipelines {
		if isEmptyPipeline(pl) {
			continue
		}
		if !hasProcessorType(signal, ctx.Graph, "memory_limiter") {
			diags = append(diags, model.Diagnostic{
				Severity: sev,
				Message:  fmt.Sprintf("Pipeline %q does not include a memory_limiter processor. Without it, a traffic spike may cause OOM and collector restarts.", signal),
				Fix:      "Consider adding a memory_limiter processor with appropriate limit_mib and spike_limit_mib values.",
				Location: pl.Location,
			})
		}
	}

	return diags
}

// --- OTEL-REL-102: memory_limiter not first processor ---

type memLimiterOrderRule struct{}

func NewMemLimiterOrderRule() Rule { return &memLimiterOrderRule{} }

func (r *memLimiterOrderRule) ID() string                   { return "OTEL-REL-102" }
func (r *memLimiterOrderRule) Title() string                { return "memory_limiter not first processor" }
func (r *memLimiterOrderRule) Category() model.Category     { return model.CategoryReliability }
func (r *memLimiterOrderRule) DefaultSeverity() model.Severity {
	return model.SeverityHigh
}

func (r *memLimiterOrderRule) Check(ctx RuleContext) []model.Diagnostic {
	var diags []model.Diagnostic
	sev := pickSeverity(ctx.Profile, model.SeverityHigh, model.SeverityMedium, model.SeverityLow)

	for signal, pl := range ctx.Config.Service.Pipelines {
		idx := indexOfProcessorType(signal, ctx.Graph, "memory_limiter")
		if idx < 0 {
			continue
		}
		if idx == 0 {
			continue
		}
		types := processorTypes(signal, ctx.Graph)
		before := types[0]
		diags = append(diags, model.Diagnostic{
			Severity: sev,
			Message:  fmt.Sprintf("In pipeline %q, memory_limiter is not the first processor (position %d, after %q). This may cause late memory pressure detection.", signal, idx, before),
			Fix:      "Consider moving memory_limiter before all other processors to catch memory spikes early.",
			Location: pl.Location,
		})
	}

	return diags
}

// --- OTEL-REL-103: batch processor missing ---

type batchMissingRule struct{}

func NewBatchMissingRule() Rule { return &batchMissingRule{} }

func (r *batchMissingRule) ID() string                   { return "OTEL-REL-103" }
func (r *batchMissingRule) Title() string                { return "Batch processor missing" }
func (r *batchMissingRule) Category() model.Category     { return model.CategoryReliability }
func (r *batchMissingRule) DefaultSeverity() model.Severity {
	return model.SeverityMedium
}

func (r *batchMissingRule) Check(ctx RuleContext) []model.Diagnostic {
	var diags []model.Diagnostic
	sev := pickSeverity(ctx.Profile, model.SeverityMedium, model.SeverityLow, model.SeverityLow)

	for signal, pl := range ctx.Config.Service.Pipelines {
		if isEmptyPipeline(pl) {
			continue
		}
		if !hasProcessorType(signal, ctx.Graph, "batch") {
			diags = append(diags, model.Diagnostic{
				Severity: sev,
				Message:  fmt.Sprintf("Pipeline %q does not include a batch processor. Without batching, the collector may generate excessive network requests under load.", signal),
				Fix:      "Consider adding a batch processor with appropriate timeout and send_batch_size values.",
				Location: pl.Location,
			})
		}
	}

	return diags
}

// --- OTEL-REL-104: batch appears before transform/filter processors ---

type batchBeforeTransformRule struct{}

func NewBatchBeforeTransformRule() Rule { return &batchBeforeTransformRule{} }

func (r *batchBeforeTransformRule) ID() string                   { return "OTEL-REL-104" }
func (r *batchBeforeTransformRule) Title() string                { return "Batch before transform/filter processors" }
func (r *batchBeforeTransformRule) Category() model.Category     { return model.CategoryReliability }
func (r *batchBeforeTransformRule) DefaultSeverity() model.Severity {
	return model.SeverityMedium
}

var transformTypes = map[string]bool{
	"filter":     true,
	"attributes": true,
	"resource":   true,
	"transform":  true,
	"routing":    true,
}

func (r *batchBeforeTransformRule) Check(ctx RuleContext) []model.Diagnostic {
	var diags []model.Diagnostic
	sev := pickSeverity(ctx.Profile, model.SeverityMedium, model.SeverityLow, model.SeverityLow)

	for signal, pl := range ctx.Config.Service.Pipelines {
		batchIdx := indexOfProcessorType(signal, ctx.Graph, "batch")
		if batchIdx < 0 {
			continue
		}

		types := processorTypes(signal, ctx.Graph)
		for i, t := range types {
			if !transformTypes[t] {
				continue
			}
			if i > batchIdx {
				diags = append(diags, model.Diagnostic{
					Severity: sev,
					Message:  fmt.Sprintf("In pipeline %q, batch processor (position %d) appears before %q processor (position %d). Batching before transformation may result in sending unprocessed data.", signal, batchIdx, t, i),
					Fix:      "Consider moving the batch processor to the end of the processor chain, after all transformation processors.",
					Location: pl.Location,
				})
				break
			}
		}
	}

	return diags
}

// --- OTEL-REL-105: exporter retry_on_failure missing ---

type exporterRetryMissingRule struct{}

func NewExporterRetryMissingRule() Rule { return &exporterRetryMissingRule{} }

func (r *exporterRetryMissingRule) ID() string                   { return "OTEL-REL-105" }
func (r *exporterRetryMissingRule) Title() string                { return "Exporter retry_on_failure not configured" }
func (r *exporterRetryMissingRule) Category() model.Category     { return model.CategoryReliability }
func (r *exporterRetryMissingRule) DefaultSeverity() model.Severity {
	return model.SeverityMedium
}

func (r *exporterRetryMissingRule) Check(ctx RuleContext) []model.Diagnostic {
	if ctx.Profile != "production" && ctx.Profile != "staging" {
		return nil
	}

	var diags []model.Diagnostic
	sev := pickSeverity(ctx.Profile, model.SeverityMedium, model.SeverityLow, model.SeverityLow)

	for id, c := range ctx.Config.Exporters {
		if processorType(id) == "debug" {
			continue
		}
		pipes := ctx.Graph.PipelinesUsingComponent(model.ComponentKindExporter, id)
		if len(pipes) == 0 {
			continue
		}

		cfg := exporterConfig(ctx.Config, id)
		if cfg != nil {
			if _, ok := cfg["retry_on_failure"]; ok {
				continue
			}
		}

		diags = append(diags, model.Diagnostic{
			Severity: sev,
			Message:  fmt.Sprintf("Exporter %q does not have retry_on_failure configured. Transient backend failures may cause data loss.", id),
			Fix:      "Consider adding a retry_on_failure block to this exporter.",
			Location: c.Location,
		})
	}

	return diags
}

// --- OTEL-REL-106: exporter sending_queue missing ---

type exporterQueueMissingRule struct{}

func NewExporterQueueMissingRule() Rule { return &exporterQueueMissingRule{} }

func (r *exporterQueueMissingRule) ID() string                   { return "OTEL-REL-106" }
func (r *exporterQueueMissingRule) Title() string                { return "Exporter sending_queue not configured" }
func (r *exporterQueueMissingRule) Category() model.Category     { return model.CategoryReliability }
func (r *exporterQueueMissingRule) DefaultSeverity() model.Severity {
	return model.SeverityMedium
}

func (r *exporterQueueMissingRule) Check(ctx RuleContext) []model.Diagnostic {
	if ctx.Profile != "production" && ctx.Profile != "staging" {
		return nil
	}

	var diags []model.Diagnostic
	sev := pickSeverity(ctx.Profile, model.SeverityMedium, model.SeverityLow, model.SeverityLow)

	for id, c := range ctx.Config.Exporters {
		if processorType(id) == "debug" {
			continue
		}
		pipes := ctx.Graph.PipelinesUsingComponent(model.ComponentKindExporter, id)
		if len(pipes) == 0 {
			continue
		}

		cfg := exporterConfig(ctx.Config, id)
		if cfg != nil {
			if _, ok := cfg["sending_queue"]; ok {
				continue
			}
		}

		diags = append(diags, model.Diagnostic{
			Severity: sev,
			Message:  fmt.Sprintf("Exporter %q does not have sending_queue configured. Without a queue, backpressure from the backend may cause pipeline stalls.", id),
			Fix:      "Consider adding a sending_queue block to this exporter.",
			Location: c.Location,
		})
	}

	return diags
}

// --- OTEL-REL-107: health_check extension missing in production ---

type healthCheckMissingRule struct{}

func NewHealthCheckMissingRule() Rule { return &healthCheckMissingRule{} }

func (r *healthCheckMissingRule) ID() string                   { return "OTEL-REL-107" }
func (r *healthCheckMissingRule) Title() string                { return "health_check extension missing in production" }
func (r *healthCheckMissingRule) Category() model.Category     { return model.CategoryReliability }
func (r *healthCheckMissingRule) DefaultSeverity() model.Severity {
	return model.SeverityMedium
}

func (r *healthCheckMissingRule) Check(ctx RuleContext) []model.Diagnostic {
	if ctx.Profile != "production" {
		return nil
	}

	_, ok := ctx.Config.Extensions["health_check"]
	if ok {
		return nil
	}

	return []model.Diagnostic{
		{
			Severity: model.SeverityMedium,
			Message:  "The health_check extension is not defined. In production, the collector may be unreachable by orchestrator health probes.",
			Fix:      "Consider adding a health_check extension to enable endpoint health monitoring.",
			Location: model.SourceLocation{File: fileFromCtx(ctx)},
		},
	}
}

// --- OTEL-REL-108: health_check extension not enabled in service.extensions ---

type healthCheckNotEnabledRule struct{}

func NewHealthCheckNotEnabledRule() Rule { return &healthCheckNotEnabledRule{} }

func (r *healthCheckNotEnabledRule) ID() string                   { return "OTEL-REL-108" }
func (r *healthCheckNotEnabledRule) Title() string                { return "health_check extension not enabled" }
func (r *healthCheckNotEnabledRule) Category() model.Category     { return model.CategoryReliability }
func (r *healthCheckNotEnabledRule) DefaultSeverity() model.Severity {
	return model.SeverityLow
}

func (r *healthCheckNotEnabledRule) Check(ctx RuleContext) []model.Diagnostic {
	ext, ok := ctx.Config.Extensions["health_check"]
	if !ok {
		return nil
	}

	for _, id := range ctx.Config.Service.Extensions {
		if id == "health_check" {
			return nil
		}
	}

	return []model.Diagnostic{
		{
			Severity: model.SeverityLow,
			Message:  "The health_check extension is defined but not listed in service.extensions. The health endpoint will not be active.",
			Fix:      "Consider adding \"health_check\" to the service.extensions list.",
			Location: ext.Location,
		},
	}
}
