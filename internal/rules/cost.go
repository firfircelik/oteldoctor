package rules

import (
	"fmt"
	"strings"

	"github.com/firfircelik/oteldoctor/internal/model"
)

var riskyAttributes = []string{
	"user.id",
	"user.email",
	"session.id",
	"request.id",
	"trace_id",
	"span_id",
	"container.id",
	"k8s.pod.uid",
	"http.url",
	"url.full",
	"client.address",
}

func isRiskyAttribute(s string) bool {
	lower := strings.ToLower(s)
	for _, attr := range riskyAttributes {
		if strings.Contains(lower, attr) {
			return true
		}
	}
	return false
}

func findRiskyStringsInConfig(cfg map[string]any, keyName string) []string {
	var found []string
	findRiskyStringsRecursive(cfg, keyName, &found)
	return found
}

func findRiskyStringsRecursive(cfg map[string]any, targetKey string, found *[]string) {
	for k, v := range cfg {
		if k == targetKey {
			if s, ok := v.(string); ok && isRiskyAttribute(s) {
				*found = append(*found, s)
			}
		}

		if sub, ok := v.(map[string]any); ok {
			findRiskyStringsRecursive(sub, targetKey, found)
			continue
		}

		if arr, ok := v.([]any); ok {
			for _, item := range arr {
				if s, ok := item.(string); ok {
					if (targetKey == "" || k == targetKey) && isRiskyAttribute(s) {
						*found = append(*found, s)
					}
				}
				if m, ok := item.(map[string]any); ok {
					findRiskyStringsRecursive(m, targetKey, found)
				}
			}
		}
	}
}

func findSetStatements(cfg map[string]any) bool {
	return searchStringsRecursive(cfg, func(s string) bool {
		return strings.Contains(s, "set(")
	})
}

func findDimensionsKey(cfg map[string]any) ([]string, bool) {
	if dims, ok := cfg["dimensions"]; ok {
		switch v := dims.(type) {
		case []any:
			var result []string
			for _, item := range v {
				if s, ok := item.(string); ok {
					result = append(result, s)
				}
				if m, ok := item.(map[string]any); ok {
					if name, ok := m["name"]; ok {
						if s, ok := name.(string); ok {
							result = append(result, s)
						}
					}
				}
			}
			return result, true
		case map[string]any:
			if def, ok := v["default"]; ok {
				if arr, ok := def.([]any); ok {
					var result []string
					for _, item := range arr {
						if s, ok := item.(string); ok {
							result = append(result, s)
						}
						if m, ok := item.(map[string]any); ok {
							if name, ok := m["name"]; ok {
								if s, ok := name.(string); ok {
									result = append(result, s)
								}
							}
						}
					}
					return result, true
				}
			}
		}
	}
	return nil, false
}

func searchStringsRecursive(cfg map[string]any, pred func(string) bool) bool {
	for _, v := range cfg {
		if s, ok := v.(string); ok {
			if pred(s) {
				return true
			}
		}
		if sub, ok := v.(map[string]any); ok {
			if searchStringsRecursive(sub, pred) {
				return true
			}
		}
		if arr, ok := v.([]any); ok {
			for _, item := range arr {
				if s, ok := item.(string); ok {
					if pred(s) {
						return true
					}
				}
				if m, ok := item.(map[string]any); ok {
					if searchStringsRecursive(m, pred) {
						return true
					}
				}
			}
		}
	}
	return false
}

// --- OTEL-COST-301: high-cardinality attribute in metric dimensions ---

type highCardinalityMetricRule struct{}

func NewHighCardinalityMetricRule() Rule { return &highCardinalityMetricRule{} }

func (r *highCardinalityMetricRule) ID() string { return "OTEL-COST-301" }
func (r *highCardinalityMetricRule) Title() string {
	return "High-cardinality attribute used in metric dimensions"
}
func (r *highCardinalityMetricRule) Category() model.Category        { return model.CategoryCost }
func (r *highCardinalityMetricRule) DefaultSeverity() model.Severity { return model.SeverityMedium }

func (r *highCardinalityMetricRule) Check(ctx RuleContext) []model.Diagnostic {
	var diags []model.Diagnostic
	sev := pickSeverity(ctx.Profile, model.SeverityMedium, model.SeverityLow, model.SeverityLow)

	checkComponent := func(id string, c model.Component, label string) {
		cfg := componentConfig(ctx.Config, c.Kind, id)
		if cfg == nil {
			return
		}

		risky := findRiskyStringsInConfig(cfg, "key")
		if len(risky) == 0 {
			return
		}

		for _, attr := range risky {
			diags = append(diags, model.Diagnostic{
				Severity: sev,
				Message:  fmt.Sprintf("%s %q uses high-cardinality attribute %q as a metric dimension. This may cause unbounded metric series growth and increase storage cost.", label, id, attr),
				Fix:      "Consider removing high-cardinality dimensions, using pre-aggregation, or limiting with a fixed set of values.",
				Location: c.Location,
			})
		}
	}

	for id, c := range ctx.Config.Processors {
		typ := processorType(id)
		if typ == "attributes" || typ == "transform" {
			checkComponent(id, c, "Processor")
		}
	}

	for id, c := range ctx.Config.Connectors {
		typ := processorType(id)
		if typ == "spanmetrics" {
			cfg := componentConfig(ctx.Config, model.ComponentKindConnector, id)
			if cfg == nil {
				continue
			}
			dims, ok := findDimensionsKey(cfg)
			if !ok {
				continue
			}
			for _, dim := range dims {
				if isRiskyAttribute(dim) {
					diags = append(diags, model.Diagnostic{
						Severity: sev,
						Message:  fmt.Sprintf("Spanmetrics connector %q uses high-cardinality dimension %q. This may cause unbounded metric series growth and increase storage cost.", id, dim),
						Fix:      fmt.Sprintf("Consider removing %q from the dimensions list or using a fixed set of known values.", dim),
						Location: c.Location,
					})
				}
			}
		}
	}

	return diags
}

// --- OTEL-COST-302: transform processor creates dynamic attributes ---

type dynamicAttributesRule struct{}

func NewDynamicAttributesRule() Rule { return &dynamicAttributesRule{} }

func (r *dynamicAttributesRule) ID() string { return "OTEL-COST-302" }
func (r *dynamicAttributesRule) Title() string {
	return "Transform processor appears to create dynamic attributes"
}
func (r *dynamicAttributesRule) Category() model.Category        { return model.CategoryCost }
func (r *dynamicAttributesRule) DefaultSeverity() model.Severity { return model.SeverityMedium }

func (r *dynamicAttributesRule) Check(ctx RuleContext) []model.Diagnostic {
	var diags []model.Diagnostic
	sev := pickSeverity(ctx.Profile, model.SeverityMedium, model.SeverityLow, model.SeverityLow)

	for id, c := range ctx.Config.Processors {
		if processorType(id) != "transform" {
			continue
		}

		cfg := componentConfig(ctx.Config, model.ComponentKindProcessor, id)
		if cfg == nil {
			continue
		}

		if !findSetStatements(cfg) {
			continue
		}

		diags = append(diags, model.Diagnostic{
			Severity: sev,
			Message:  fmt.Sprintf("Transform processor %q contains set() statements that may create dynamic attributes at runtime. Dynamic attributes can increase per-metric cardinality and storage cost.", id),
			Fix:      "Consider limiting dynamic attributes to known values or using pre-defined attribute sets.",
			Location: c.Location,
		})
	}

	return diags
}

// --- OTEL-COST-303: spanmetrics connector uses risky dimensions ---

type spanmetricsDimensionsRule struct{}

func NewSpanmetricsDimensionsRule() Rule { return &spanmetricsDimensionsRule{} }

func (r *spanmetricsDimensionsRule) ID() string { return "OTEL-COST-303" }
func (r *spanmetricsDimensionsRule) Title() string {
	return "Spanmetrics connector uses risky dimensions"
}
func (r *spanmetricsDimensionsRule) Category() model.Category        { return model.CategoryCost }
func (r *spanmetricsDimensionsRule) DefaultSeverity() model.Severity { return model.SeverityMedium }

func (r *spanmetricsDimensionsRule) Check(ctx RuleContext) []model.Diagnostic {
	var diags []model.Diagnostic
	sev := pickSeverity(ctx.Profile, model.SeverityMedium, model.SeverityLow, model.SeverityLow)

	for id, c := range ctx.Config.Connectors {
		if processorType(id) != "spanmetrics" {
			continue
		}

		cfg := componentConfig(ctx.Config, model.ComponentKindConnector, id)
		if cfg == nil {
			continue
		}

		dims, ok := findDimensionsKey(cfg)
		if !ok || len(dims) == 0 {
			diags = append(diags, model.Diagnostic{
				Severity: sev,
				Message:  fmt.Sprintf("Spanmetrics connector %q has no explicit dimensions configured. Without explicit dimension limits, all span attributes may become metric dimensions, leading to unbounded cardinality.", id),
				Fix:      "Consider defining an explicit dimensions list to limit which attributes become metric dimensions.",
				Location: c.Location,
			})
			continue
		}

		hasRisky := false
		for _, dim := range dims {
			if isRiskyAttribute(dim) {
				hasRisky = true
				break
			}
		}

		if hasRisky {
			diags = append(diags, model.Diagnostic{
				Severity: sev,
				Message:  fmt.Sprintf("Spanmetrics connector %q dimension list includes potentially high-cardinality attributes. This may cause unbounded metric series growth.", id),
				Fix:      "Consider removing high-cardinality attributes (e.g. trace_id, span_id, http.url) from the dimensions list.",
				Location: c.Location,
			})
		}
	}

	return diags
}

// --- OTEL-COST-304: debug exporter may emit high volume in production ---

type debugExporterVolumeRule struct{}

func NewDebugExporterVolumeRule() Rule { return &debugExporterVolumeRule{} }

func (r *debugExporterVolumeRule) ID() string                      { return "OTEL-COST-304" }
func (r *debugExporterVolumeRule) Title() string                   { return "Debug exporter may emit high volume" }
func (r *debugExporterVolumeRule) Category() model.Category        { return model.CategoryCost }
func (r *debugExporterVolumeRule) DefaultSeverity() model.Severity { return model.SeverityMedium }

func (r *debugExporterVolumeRule) Check(ctx RuleContext) []model.Diagnostic {
	if ctx.Profile != "production" && ctx.Profile != "staging" {
		return nil
	}

	var diags []model.Diagnostic

	for id, c := range ctx.Config.Exporters {
		pipes := ctx.Graph.PipelinesUsingComponent(model.ComponentKindExporter, id)
		if len(pipes) == 0 {
			continue
		}

		if processorType(id) != "debug" {
			continue
		}

		diags = append(diags, model.Diagnostic{
			Severity: model.SeverityMedium,
			Message:  fmt.Sprintf("Debug exporter %q is active in pipeline(s) %v in a production-like profile. The debug exporter writes every span to stdout, which may generate excessive I/O volume and increase infrastructure cost.", id, pipes),
			Fix:      "Consider removing the debug exporter from production pipelines to reduce log volume and infrastructure cost.",
			Location: c.Location,
		})
	}

	return diags
}

// --- OTEL-COST-305: traces pipeline has no sampling/filtering in production ---

type tracesNoSamplingRule struct{}

func NewTracesNoSamplingRule() Rule { return &tracesNoSamplingRule{} }

func (r *tracesNoSamplingRule) ID() string                      { return "OTEL-COST-305" }
func (r *tracesNoSamplingRule) Title() string                   { return "Traces pipeline has no sampling or filtering" }
func (r *tracesNoSamplingRule) Category() model.Category        { return model.CategoryCost }
func (r *tracesNoSamplingRule) DefaultSeverity() model.Severity { return model.SeverityHigh }

func (r *tracesNoSamplingRule) Check(ctx RuleContext) []model.Diagnostic {
	if ctx.Profile != "production" {
		return nil
	}

	var diags []model.Diagnostic

	samplingTypes := map[string]bool{
		"tailsampling":         true,
		"probabilisticsampler": true,
		"filter":               true,
	}

	for signal, pl := range ctx.Config.Service.Pipelines {
		if signal != "traces" {
			continue
		}

		hasSampling := false
		for _, t := range processorTypes(signal, ctx.Graph) {
			if samplingTypes[t] {
				hasSampling = true
				break
			}
		}

		if hasSampling {
			continue
		}

		diags = append(diags, model.Diagnostic{
			Severity: model.SeverityHigh,
			Message:  fmt.Sprintf("Traces pipeline %q has no sampling or filtering processor configured in production. Without collector-level sampling, all received traces are exported, which may cause high backend costs and network egress charges. Note: SDK-level head sampling may already reduce trace volume.", signal),
			Fix:      "Consider adding a tailsampling, probabilisticsampler, or filter processor to control trace volume at the collector level.",
			Location: pl.Location,
		})
	}

	return diags
}
