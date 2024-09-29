package cmd

import "github.com/spf13/cobra"

var version = "VERSION"

func GetVersionCmd() *cobra.Command {
	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print the version number of aws-security-checker",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Printf("aws-security-checker version -  %s\n", version)
		},
	}
	return versionCmd
}
