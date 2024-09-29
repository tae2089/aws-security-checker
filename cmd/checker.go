package cmd

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/tae2089/aws-security-checker/internal/driver"
	"github.com/tae2089/aws-security-checker/internal/util"
)

func InitCheckerCmd() (*cobra.Command, *cobra.Group) {
	checkerCmd := createCheckerCmd()
	util.RegisterSubCommands(checkerCmd, createCheckIamCmd())
	return checkerCmd, &cobra.Group{ID: "check", Title: "Check Commands"}
}

func createCheckerCmd() *cobra.Command {
	checkerCmd := &cobra.Command{
		Use:   "checker",
		Short: "Check AWS Security",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := cmd.Help(); err != nil {
				return err
			}
			return nil
		},
	}
	checkerCmd.GroupID = "check"
	checkerCmd.PersistentFlags().StringP("region", "r", "ap-northeast-2", "AWS region")
	checkerCmd.PersistentFlags().StringP("profile", "p", "default", "AWS profile")
	return checkerCmd
}

func createCheckIamCmd() *cobra.Command {
	checkIamCmd := &cobra.Command{
		Use:           "iam",
		Short:         "Check IAM",
		SilenceUsage:  true,
		SilenceErrors: true,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if err := viper.BindPFlags(cmd.Flags()); err != nil {
				return err
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			region := viper.GetString("region")
			profile := viper.GetString("profile")
			awsManager := driver.NewAwsManager(profile, region)
			if err := awsManager.CheckIam(); err != nil {
				return err
			}
			return nil
		},
	}
	return checkIamCmd
}
