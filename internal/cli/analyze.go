package cli

import (
	"fmt"
	"os"

	"github.com/firfircelik/oteldoctor/internal/extractor"
	"github.com/firfircelik/oteldoctor/internal/graph"
	"github.com/firfircelik/oteldoctor/internal/k8s"
	"github.com/firfircelik/oteldoctor/internal/model"
	"github.com/firfircelik/oteldoctor/internal/output"
	"github.com/firfircelik/oteldoctor/internal/parser"
	"github.com/firfircelik/oteldoctor/internal/policy"
	"github.com/firfircelik/oteldoctor/internal/rules"
	"github.com/firfircelik/oteldoctor/internal/scanner"
	"github.com/spf13/cobra"
)

func newAnalyzeCmd() *cobra.Command {
	var format string
	var profile string
	var failOn string
	var policyPath string
	var showSuppressed bool
	var recursive bool
	var include []string
	var exclude []string
	var category string
	var ruleFilter string

	cmd := &cobra.Command{
		Use:   "analyze <path>",
		Short: "Analyze an OpenTelemetry Collector configuration",
		Long: `analyze parses an OpenTelemetry Collector configuration file and reports
structural, reliability, security, cost/cardinality, semantic, and
Kubernetes readiness issues.

If <path> is a directory, all YAML files are scanned and analyzed.`,
		Args: cobra.ExactArgs(1),
		RunE: runAnalyze,
	}

	cmd.Flags().StringVarP(&format, "format", "f", "text", "Output format: text, json, sarif")
	cmd.Flags().StringVar(&profile, "profile", "", "Analysis profile: development, staging, production")
	cmd.Flags().StringVar(&failOn, "fail-on", "", "Exit with code 1 if issues are at or above: critical, high, medium, low")
	cmd.Flags().StringVar(&policyPath, "policy", "", "Path to policy file (default: discover .oteldoctor.yaml)")
	cmd.Flags().BoolVar(&showSuppressed, "show-suppressed", false, "Show diagnostics that are suppressed by policy")
	cmd.Flags().BoolVar(&recursive, "recursive", true, "Recursively scan subdirectories")
	cmd.Flags().StringArrayVar(&include, "include", nil, "Include files matching glob pattern (can repeat)")
	cmd.Flags().StringArrayVar(&exclude, "exclude", nil, "Exclude files matching glob pattern (can repeat)")
	cmd.Flags().StringVar(&category, "category", "", "Filter by category: structural, reliability, security, cost, semantic, kubernetes")
	cmd.Flags().StringVar(&ruleFilter, "rule", "", "Filter by specific rule ID (e.g. OTEL-REL-102)")

	return cmd
}

var failRank = map[string]int{
	"critical": 0,
	"high":     1,
	"medium":   2,
	"low":      3,
}

func severityInt(s model.Severity) int {
	switch s {
	case model.SeverityCritical:
		return 0
	case model.SeverityHigh:
		return 1
	case model.SeverityMedium:
		return 2
	case model.SeverityLow:
		return 3
	default:
		return 4
	}
}

func runAnalyze(cmd *cobra.Command, args []string) error {
	path := args[0]
	format, _ := cmd.Flags().GetString("format")
	profile, _ := cmd.Flags().GetString("profile")
	failOn, _ := cmd.Flags().GetString("fail-on")
	policyPath, _ := cmd.Flags().GetString("policy")
	showSuppressed, _ := cmd.Flags().GetBool("show-suppressed")
	recursive, _ := cmd.Flags().GetBool("recursive")
	include, _ := cmd.Flags().GetStringArray("include")
	exclude, _ := cmd.Flags().GetStringArray("exclude")
	category, _ := cmd.Flags().GetString("category")
	ruleFilter, _ := cmd.Flags().GetString("rule")

	var pol *policy.Policy
	if policyPath != "" {
		var err error
		pol, err = policy.Load(policyPath)
		if err != nil {
			return fmt.Errorf("loading policy: %w", err)
		}
	} else {
		p, err := policy.Discover(".")
		if err == nil {
			pol = p
		}
	}

	if profile == "" && pol != nil && pol.Profile != "" {
		profile = pol.Profile
	}
	if profile == "" {
		profile = "development"
	}

	if failOn == "" && pol != nil && pol.FailOn != "" {
		failOn = pol.FailOn
	}
	if failOn == "" {
		failOn = "low"
	}

	threshold, ok := failRank[failOn]
	if !ok {
		return fmt.Errorf("invalid --fail-on value %q: must be critical, high, medium, or low", failOn)
	}

	files, err := resolveFiles(path, recursive, include, exclude)
	if err != nil {
		return fmt.Errorf("scanning: %w", err)
	}

	files, displayPaths, extractedConfigs, err := extractConfigMaps(files)
	if err != nil {
		return fmt.Errorf("extracting: %w", err)
	}
	defer extractor.Cleanup(extractedConfigs)

	isSingleFile := !fiIsDir(path) && len(files) == 1

	var k8sWorkloads []*k8s.Workload
	var k8sServices []*k8s.ServiceInfo

	if !isSingleFile {
		k8sWorkloads, k8sServices = parseK8sManifests(files)
		files, err = scanner.FilterCollectorConfigs(files)
		if err != nil {
			return fmt.Errorf("scanning: %w", err)
		}
	}

	if len(files) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "No collector configuration files found.")
		return nil
	}

	reg := rules.NewRegistry()
	for _, r := range rules.AllRules() {
		reg.Register(r)
	}

	var allDiags []model.Diagnostic

	for _, f := range files {
		displayPath := f
		if dp, ok := displayPaths[f]; ok && dp != f {
			displayPath = dp
		}

		p := parser.New(displayPath)
		var cfg *model.CollectorConfig
		var err error
		if displayPath != f {
			cfg, err = p.ParseFile(f, displayPath)
		} else {
			cfg, err = p.Parse()
		}
		if err != nil {
			if isSingleFile {
				return fmt.Errorf("parse error: %w", err)
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "Warning: skipping %s: %v\n", f, err)
			continue
		}

		g := graph.Build(cfg)

		ctx := rules.RuleContext{
			Config:     cfg,
			Graph:      g,
			Profile:    profile,
			Policy:     pol,
			Workload:   findLinkedWorkload(f, k8sWorkloads),
			K8sService: findLinkedService(f, k8sServices),
		}

		diags := reg.RunAll(ctx, showSuppressed)
		allDiags = append(allDiags, diags...)
	}

	allDiags = filterDiagnostics(allDiags, category, ruleFilter)

	var formatter output.Formatter
	switch format {
	case "json":
		formatter = &output.JSONFormatter{}
	case "sarif":
		formatter = &output.SARIFFormatter{}
	default:
		formatter = &output.TextFormatter{}
	}

	out, err := formatter.Format(allDiags)
	if err != nil {
		return fmt.Errorf("formatting output: %w", err)
	}

	fmt.Fprint(cmd.OutOrStdout(), out)

	hasIssueAtThreshold := false
	for _, d := range allDiags {
		if severityInt(d.Severity) <= threshold {
			hasIssueAtThreshold = true
			break
		}
	}

	if hasIssueAtThreshold {
		return &ExitError{Code: 1}
	}

	return nil
}

func fiIsDir(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir()
}

func resolveFiles(path string, recursive bool, include, exclude []string) ([]string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	if !fi.IsDir() {
		return []string{path}, nil
	}

	s := scanner.New()
	s.Recursive = recursive
	files, err := s.Scan(path)
	if err != nil {
		return nil, err
	}

	files = scanner.FilterByGlob(files, include, false)
	files = scanner.FilterByGlob(files, exclude, true)

	return files, nil
}

func extractConfigMaps(files []string) ([]string, map[string]string, []extractor.EmbeddedConfig, error) {
	result := []string{}
	displayPaths := map[string]string{}
	var extracted []extractor.EmbeddedConfig

	for _, f := range files {
		ok, err := extractor.IsConfigMap(f)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("checking ConfigMap %s: %w", f, err)
		}
		if !ok {
			result = append(result, f)
			displayPaths[f] = f
			continue
		}

		configs, err := extractor.Extract(f)
		if err != nil {
			extractor.Cleanup(extracted)
			return nil, nil, nil, fmt.Errorf("extracting ConfigMap %s: %w", f, err)
		}
		for _, c := range configs {
			result = append(result, c.Path)
			displayPaths[c.Path] = extractor.SourcePathDisplay(c.SourceFile, c.ConfigMapName, c.DataKey)
		}
		extracted = append(extracted, configs...)
	}

	return result, displayPaths, extracted, nil
}

func parseK8sManifests(files []string) ([]*k8s.Workload, []*k8s.ServiceInfo) {
	var workloads []*k8s.Workload
	var services []*k8s.ServiceInfo

	for _, f := range files {
		if w, err := k8s.ParseWorkload(f); err == nil && w != nil {
			workloads = append(workloads, w)
		}
		if svc, err := k8s.ParseService(f); err == nil && svc != nil {
			services = append(services, svc)
		}
	}

	return workloads, services
}

func findLinkedWorkload(configFile string, workloads []*k8s.Workload) *k8s.Workload {
	if len(workloads) == 1 {
		return workloads[0]
	}
	return nil
}

func findLinkedService(configFile string, services []*k8s.ServiceInfo) *k8s.ServiceInfo {
	if len(services) == 1 {
		return services[0]
	}
	return nil
}

func filterDiagnostics(diags []model.Diagnostic, category, ruleID string) []model.Diagnostic {
	if category == "" && ruleID == "" {
		return diags
	}

	result := make([]model.Diagnostic, 0, len(diags))
	for _, d := range diags {
		if category != "" && string(d.Category) != category {
			continue
		}
		if ruleID != "" && d.RuleID != ruleID {
			continue
		}
		result = append(result, d)
	}
	return result
}
