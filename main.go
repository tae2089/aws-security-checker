package main

import (
	"github.com/tae2089/aws-security-checker/cmd"
	"github.com/tae2089/aws-security-checker/internal/util"
)

func main() {
	rootCmd := cmd.CreateRootCmd()
	util.RegisterSubCommandsWithGroup(rootCmd, cmd.InitCheckerCmd)
	if err := rootCmd.Execute(); err != nil {
		panic(err)
	}
}
