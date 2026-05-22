package rules

import (
	"fmt"
	"strings"

	"github.com/firfircelik/oteldoctor/internal/model"
)

var secretKeyPatterns = []string{
	"token",
	"api_key",
	"apikey",
	"password",
	"secret",
	"authorization",
}

func looksLikeSecretKey(k string) bool {
	normalized := strings.ReplaceAll(strings.ToLower(k), "-", "_")
	for _, pat := range secretKeyPatterns {
		if strings.Contains(normalized, pat) {
			return true
		}
	}
	return false
}

func isEnvVarRef(v string) bool {
	return strings.HasPrefix(v, "${") && strings.HasSuffix(v, "}")
}

func findEndpoints(cfg map[string]any) []string {
	var eps []string
	findEndpointsRecursive(cfg, &eps)
	return eps
}

func findEndpointsRecursive(cfg map[string]any, eps *[]string) {
	if ep, ok := cfg["endpoint"]; ok {
		if s, ok := ep.(string); ok {
			*eps = append(*eps, s)
		}
	}

	for _, v := range cfg {
		sub, ok := v.(map[string]any)
		if !ok {
			continue
		}
		findEndpointsRecursive(sub, eps)
	}
}

func hasConfigKey(cfg map[string]any, key string) bool {
	_, ok := cfg[key]
	return ok
}

func extractHost(ep string) string {
	s := ep
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexByte(s, ':'); i >= 0 {
		s = s[:i]
	}
	return s
}

func isPlainHTTP(ep string) bool {
	return strings.HasPrefix(ep, "http://")
}

const localhost = "localhost"

func isLocalhostEndpoint(ep string) bool {
	host := extractHost(ep)
	return host == localhost || host == "127.0.0.1" || host == "::1"
}

func isZeroAddr(ep string) bool {
	return strings.Contains(ep, "0.0.0.0")
}

func findEndpointProblem(eps []string, check func(string) bool) string {
	for _, ep := range eps {
		if check(ep) {
			return ep
		}
	}
	return ""
}

func componentConfig(cfg *model.CollectorConfig, kind model.ComponentKind, id string) map[string]any {
	var c model.Component
	var ok bool
	switch kind {
	case model.ComponentKindReceiver:
		c, ok = cfg.Receivers[id]
	case model.ComponentKindProcessor:
		c, ok = cfg.Processors[id]
	case model.ComponentKindExporter:
		c, ok = cfg.Exporters[id]
	case model.ComponentKindConnector:
		c, ok = cfg.Connectors[id]
	case model.ComponentKindExtension:
		c, ok = cfg.Extensions[id]
	}
	if !ok {
		return nil
	}
	m, _ := c.Config.(map[string]any)
	return m
}

func redactedKey(k string) string {
	return fmt.Sprintf("%s: [REDACTED]", k)
}

// --- OTEL-SEC-201: exporter endpoint uses plain HTTP in production ---

type plainHTTPExporterRule struct{}

func NewPlainHTTPExporterRule() Rule { return &plainHTTPExporterRule{} }

func (r *plainHTTPExporterRule) ID() string               { return "OTEL-SEC-201" }
func (r *plainHTTPExporterRule) Title() string             { return "Plain HTTP exporter endpoint in production" }
func (r *plainHTTPExporterRule) Category() model.Category  { return model.CategorySecurity }
func (r *plainHTTPExporterRule) DefaultSeverity() model.Severity { return model.SeverityHigh }

func (r *plainHTTPExporterRule) Check(ctx RuleContext) []model.Diagnostic {
	if ctx.Profile != "production" {
		return nil
	}

	var diags []model.Diagnostic

	for id, c := range ctx.Config.Exporters {
		pipes := ctx.Graph.PipelinesUsingComponent(model.ComponentKindExporter, id)
		if len(pipes) == 0 {
			continue
		}

		cfg := componentConfig(ctx.Config, model.ComponentKindExporter, id)
		if cfg == nil {
			continue
		}

		eps := findEndpoints(cfg)
		for _, ep := range eps {
			if isPlainHTTP(ep) && !isLocalhostEndpoint(ep) {
				diags = append(diags, model.Diagnostic{
					Severity: model.SeverityHigh,
					Message:  fmt.Sprintf("Exporter %q uses plain HTTP endpoint %q in production. Traffic may be intercepted.", id, ep),
					Fix:      fmt.Sprintf("Consider using HTTPS for the exporter endpoint, or enable TLS."),
					Location: c.Location,
				})
			}
		}
	}

	return diags
}

// --- OTEL-SEC-202: possible hardcoded secret in headers/auth ---

type hardcodedSecretRule struct{}

func NewHardcodedSecretRule() Rule { return &hardcodedSecretRule{} }

func (r *hardcodedSecretRule) ID() string               { return "OTEL-SEC-202" }
func (r *hardcodedSecretRule) Title() string             { return "Possible hardcoded secret" }
func (r *hardcodedSecretRule) Category() model.Category  { return model.CategorySecurity }
func (r *hardcodedSecretRule) DefaultSeverity() model.Severity { return model.SeverityCritical }

func (r *hardcodedSecretRule) Check(ctx RuleContext) []model.Diagnostic {
	var diags []model.Diagnostic
	sev := pickSeverity(ctx.Profile, model.SeverityCritical, model.SeverityHigh, model.SeverityHigh)

	for id, c := range ctx.Config.Exporters {
		cfg := componentConfig(ctx.Config, model.ComponentKindExporter, id)
		if cfg == nil {
			continue
		}

		headers, ok := cfg["headers"]
		if !ok {
			continue
		}

		headersMap, ok := headers.(map[string]any)
		if !ok {
			continue
		}

		var redacted []string
		for k, v := range headersMap {
			if !looksLikeSecretKey(k) {
				continue
			}
			vs, ok := v.(string)
			if !ok {
				continue
			}
			if isEnvVarRef(vs) {
				continue
			}
			redacted = append(redacted, redactedKey(k))
		}

		if len(redacted) == 0 {
			continue
		}

		evidence := strings.Join(redacted, ", ")
		diags = append(diags, model.Diagnostic{
			Severity: sev,
			Message:  fmt.Sprintf("Exporter %q contains possible hardcoded secrets in headers: %s. Hardcoded secrets in configuration files are a security risk.", id, evidence),
			Fix:      "Consider using environment variable expansion (e.g. ${env:API_KEY}) or a secret store instead of hardcoded values.",
			Location: c.Location,
		})
	}

	// Also check receivers for auth/authenticator sections
	for id, c := range ctx.Config.Receivers {
		cfg := componentConfig(ctx.Config, model.ComponentKindReceiver, id)
		if cfg == nil {
			continue
		}

		for _, authKey := range []string{"auth", "authenticator"} {
			authSection, ok := cfg[authKey]
			if !ok {
				continue
			}
			authMap, ok := authSection.(map[string]any)
			if !ok {
				continue
			}
			var redacted []string
			for k, v := range authMap {
				if !looksLikeSecretKey(k) {
					continue
				}
				vs, ok := v.(string)
				if !ok {
					continue
				}
				if isEnvVarRef(vs) {
					continue
				}
				redacted = append(redacted, redactedKey(k))
			}
			if len(redacted) == 0 {
				continue
			}
			evidence := strings.Join(redacted, ", ")
			diags = append(diags, model.Diagnostic{
				Severity: sev,
				Message:  fmt.Sprintf("Receiver %q contains possible hardcoded secrets in %s: %s.", id, authKey, evidence),
				Fix:      "Consider using environment variable expansion or a secret store.",
				Location: c.Location,
			})
		}
	}

	return diags
}

// --- OTEL-SEC-203: receiver bound to 0.0.0.0 without auth/TLS ---

type receiverZeroAddrRule struct{}

func NewReceiverZeroAddrRule() Rule { return &receiverZeroAddrRule{} }

func (r *receiverZeroAddrRule) ID() string               { return "OTEL-SEC-203" }
func (r *receiverZeroAddrRule) Title() string             { return "Receiver bound to 0.0.0.0 without auth or TLS" }
func (r *receiverZeroAddrRule) Category() model.Category  { return model.CategorySecurity }
func (r *receiverZeroAddrRule) DefaultSeverity() model.Severity { return model.SeverityMedium }

func (r *receiverZeroAddrRule) Check(ctx RuleContext) []model.Diagnostic {
	if ctx.Profile != "production" {
		return nil
	}

	var diags []model.Diagnostic
	sev := model.SeverityHigh

	for id, c := range ctx.Config.Receivers {
		pipes := ctx.Graph.PipelinesUsingComponent(model.ComponentKindReceiver, id)
		if len(pipes) == 0 {
			continue
		}

		cfg := componentConfig(ctx.Config, model.ComponentKindReceiver, id)
		if cfg == nil {
			continue
		}

		eps := findEndpoints(cfg)
		problem := findEndpointProblem(eps, isZeroAddr)
		if problem == "" {
			continue
		}

		if hasConfigKey(cfg, "tls") || hasConfigKey(cfg, "auth") || hasConfigKey(cfg, "authenticator") {
			continue
		}

		diags = append(diags, model.Diagnostic{
			Severity: sev,
			Message:  fmt.Sprintf("Receiver %q is bound to %q without apparent TLS or authentication configuration. This may expose the collector to untrusted traffic.", id, problem),
			Fix:      "Consider adding TLS configuration, enabling authentication, or binding to a specific internal interface.",
			Location: c.Location,
		})
	}

	return diags
}

// --- OTEL-SEC-204: debug exporter used in production ---

type debugExporterInProdRule struct{}

func NewDebugExporterInProdRule() Rule { return &debugExporterInProdRule{} }

func (r *debugExporterInProdRule) ID() string               { return "OTEL-SEC-204" }
func (r *debugExporterInProdRule) Title() string             { return "Debug exporter used in production" }
func (r *debugExporterInProdRule) Category() model.Category  { return model.CategorySecurity }
func (r *debugExporterInProdRule) DefaultSeverity() model.Severity { return model.SeverityMedium }

func (r *debugExporterInProdRule) Check(ctx RuleContext) []model.Diagnostic {
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
			Message:  fmt.Sprintf("Debug exporter %q is used in pipeline(s) %v in production. The debug exporter may leak sensitive telemetry data to stdout.", id, pipes),
			Fix:      "Consider removing the debug exporter from production pipelines.",
			Location: c.Location,
		})
	}

	return diags
}

// --- OTEL-SEC-205: pprof/zpages extension exposed on public interface ---

type debugExtensionExposedRule struct{}

func NewDebugExtensionExposedRule() Rule { return &debugExtensionExposedRule{} }

func (r *debugExtensionExposedRule) ID() string               { return "OTEL-SEC-205" }
func (r *debugExtensionExposedRule) Title() string             { return "Pprof or zpages extension on public interface" }
func (r *debugExtensionExposedRule) Category() model.Category  { return model.CategorySecurity }
func (r *debugExtensionExposedRule) DefaultSeverity() model.Severity { return model.SeverityMedium }

func (r *debugExtensionExposedRule) Check(ctx RuleContext) []model.Diagnostic {
	if ctx.Profile != "production" && ctx.Profile != "staging" {
		return nil
	}
	var diags []model.Diagnostic
	sev := pickSeverity(ctx.Profile, model.SeverityHigh, model.SeverityMedium, model.SeverityLow)

	for id, c := range ctx.Config.Extensions {
		typ := processorType(id)
		if typ != "pprof" && typ != "zpages" {
			continue
		}

		cfg := componentConfig(ctx.Config, model.ComponentKindExtension, id)
		if cfg == nil {
			continue
		}

		eps := findEndpoints(cfg)
		problem := findEndpointProblem(eps, func(ep string) bool {
			return isZeroAddr(ep) || (!isLocalhostEndpoint(ep) && extractHost(ep) != "")
		})
		if problem == "" {
			continue
		}

		diags = append(diags, model.Diagnostic{
			Severity: sev,
			Message:  fmt.Sprintf("Extension %q (%s) is exposed on %q which may be reachable from untrusted networks.", id, typ, problem),
			Fix:      "Consider binding to localhost or an internal network interface only.",
			Location: c.Location,
		})
	}

	return diags
}

// --- OTEL-SEC-206: TLS config missing for remote exporter endpoint ---

type tlsMissingExporterRule struct{}

func NewTLSMissingExporterRule() Rule { return &tlsMissingExporterRule{} }

func (r *tlsMissingExporterRule) ID() string               { return "OTEL-SEC-206" }
func (r *tlsMissingExporterRule) Title() string             { return "TLS configuration missing for remote exporter" }
func (r *tlsMissingExporterRule) Category() model.Category  { return model.CategorySecurity }
func (r *tlsMissingExporterRule) DefaultSeverity() model.Severity { return model.SeverityHigh }

func (r *tlsMissingExporterRule) Check(ctx RuleContext) []model.Diagnostic {
	if ctx.Profile != "production" && ctx.Profile != "staging" {
		return nil
	}

	var diags []model.Diagnostic
	sev := pickSeverity(ctx.Profile, model.SeverityHigh, model.SeverityMedium, model.SeverityMedium)

	for id, c := range ctx.Config.Exporters {
		pipes := ctx.Graph.PipelinesUsingComponent(model.ComponentKindExporter, id)
		if len(pipes) == 0 {
			continue
		}

		cfg := componentConfig(ctx.Config, model.ComponentKindExporter, id)
		if cfg == nil {
			continue
		}

		eps := findEndpoints(cfg)
		hasRemote := false
		hasPlainHTTP := false
		for _, ep := range eps {
			if isPlainHTTP(ep) {
				hasPlainHTTP = true
			}
			if !isLocalhostEndpoint(ep) && extractHost(ep) != "" {
				hasRemote = true
			}
		}
		if !hasRemote {
			continue
		}
		if hasPlainHTTP {
			continue
		}

		if hasConfigKey(cfg, "tls") {
			continue
		}

		diags = append(diags, model.Diagnostic{
			Severity: sev,
			Message:  fmt.Sprintf("Exporter %q targets a remote endpoint without TLS configuration. Traffic may be sent in plaintext.", id),
			Fix:      "Consider adding TLS configuration (insecure: false, or custom CA/cert settings) to this exporter.",
			Location: c.Location,
		})
	}

	return diags
}

// --- OTEL-SEC-207: auth extension defined but not enabled ---

type authExtensionNotEnabledRule struct{}

func NewAuthExtensionNotEnabledRule() Rule { return &authExtensionNotEnabledRule{} }

func (r *authExtensionNotEnabledRule) ID() string               { return "OTEL-SEC-207" }
func (r *authExtensionNotEnabledRule) Title() string             { return "Auth extension not enabled" }
func (r *authExtensionNotEnabledRule) Category() model.Category  { return model.CategorySecurity }
func (r *authExtensionNotEnabledRule) DefaultSeverity() model.Severity { return model.SeverityMedium }

func (r *authExtensionNotEnabledRule) Check(ctx RuleContext) []model.Diagnostic {
	var diags []model.Diagnostic

	for id, c := range ctx.Config.Extensions {
		typ := processorType(id)
		if typ != "auth" && typ != "oauth2client" && typ != "oidc" && typ != "bearertokenauth" {
			continue
		}

		enabled := false
		for _, eid := range ctx.Config.Service.Extensions {
			if eid == id {
				enabled = true
				break
			}
		}

		if enabled {
			continue
		}

		diags = append(diags, model.Diagnostic{
			Severity: model.SeverityMedium,
			Message:  fmt.Sprintf("Authentication extension %q is defined but not listed in service.extensions. It will not be active.", id),
			Fix:      fmt.Sprintf("Consider adding %q to the service.extensions list to enable authentication.", id),
			Location: c.Location,
		})
	}

	return diags
}
