package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version of oteldoctor",
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmt.Fprintf(cmd.OutOrStdout(), "oteldoctor version %s\n", version)
			if commit != "unknown" {
				fmt.Fprintf(cmd.OutOrStdout(), "  commit: %s\n", commit)
			}
			if date != "unknown" {
				fmt.Fprintf(cmd.OutOrStdout(), "  date:   %s\n", date)
			}
			return nil
		},
	}
}
