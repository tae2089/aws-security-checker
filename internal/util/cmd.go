package util

import "github.com/spf13/cobra"

type GeneratorCmdFn func() (*cobra.Command, *cobra.Group)

func RegisterSubCommandsWithGroup(parent *cobra.Command, generateCommands ...GeneratorCmdFn) {
	for _, gc := range generateCommands {
		c, g := gc()
		generateGroups(parent, g)
		parent.AddCommand(c)
	}
}

func RegisterSubCommands(parent *cobra.Command, childCmds ...*cobra.Command) {
	for _, childCmd := range childCmds {
		parent.AddCommand(childCmd)
	}
}

func generateGroups(parent *cobra.Command, groups ...*cobra.Group) {
	for _, g := range groups {
		parent.AddGroup(g)
	}
}
