package cmd

import (
	"github.com/spf13/cobra"
)

func CreateRootCmd() *cobra.Command {
	var rootCmd = &cobra.Command{
		Use:   "aws-security-checker",
		Short: "AWS Security Checker",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := cmd.Help(); err != nil {
				return err
			}
			return nil
		},
	}
	rootCmd.AddCommand(GetVersionCmd())
	return rootCmd
}
