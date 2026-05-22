package cli

import (
	"github.com/spf13/cobra"
)

var version = "0.1.0-dev"
var commit = "unknown"
var date = "unknown"

func SetVersion(v string) {
	version = v
}

func Execute() error {
	return newRootCmd().Execute()
}

func newRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "oteldoctor",
		Short: "Analyze OpenTelemetry Collector configurations",
		Long: `oteldoctor is a static analysis tool for OpenTelemetry Collector configuration files.

It detects structural, reliability, security, cost/cardinality, semantic,
and Kubernetes readiness issues and reports them with actionable guidance.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.AddCommand(newAnalyzeCmd())
	cmd.AddCommand(newExplainCmd())
	cmd.AddCommand(newFixCmd())
	cmd.AddCommand(newGraphCmd())
	cmd.AddCommand(newVersionCmd())

	return cmd
}