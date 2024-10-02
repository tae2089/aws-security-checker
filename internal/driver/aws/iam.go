package aws

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/olekukonko/tablewriter"
)

type IamDriver struct {
	client *iam.Client
}

func NewIamDriver(iamClient *iam.Client) *IamDriver {
	return &IamDriver{
		client: iamClient,
	}
}

func (i *IamDriver) ListUsers() error {
	output, err := i.client.ListUsers(context.Background(), &iam.ListUsersInput{})
	if err != nil {
		return err
	}
	fmt.Println("\n-----Start Checking Users-----")
	// Create a new table writer
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"UserName", "CreateDate", "LastAccess", "ConsoleActive", "MFAEnabled", "Message"})

	for _, user := range output.Users {
		isConsoleActive := false
		consoleStatus := "false"
		mfaEnabled := ""
		message := ""
		passwordLastUser := ""
		if user.PasswordLastUsed != nil {
			passwordLastUser = user.PasswordLastUsed.Format(time.RFC3339)
		} else {
			passwordLastUser = "this user has never used password"
		}
		// Check if the user has a console login profile
		loginProfileOutput, err := i.client.GetLoginProfile(context.Background(), &iam.GetLoginProfileInput{
			UserName: user.UserName,
		})
		if err != nil {
			message = fmt.Sprintf("Error getting login profile for user %s: %v\n", *user.UserName, err)
		} else {
			if loginProfileOutput.LoginProfile.CreateDate != nil {
				// If no error, console login profile exists
				isConsoleActive = true
				consoleStatus = "true"
			}

			// Check if the user was created more than 1 year ago and has console access
			if user.CreateDate.Before(time.Now().AddDate(-1, 0, 0)) && isConsoleActive {
				message = "Please check; created more than 1 year ago;"
			}
		}

		mfaOutput, err := i.client.ListMFADevices(context.Background(), &iam.ListMFADevicesInput{
			UserName: user.UserName,
		})
		if err != nil {
			message = message + fmt.Sprintf("; Error getting MFA device for user %s: %v\n", *user.UserName, err)
		} else {
			for _, mfa := range mfaOutput.MFADevices {
				if mfa.EnableDate == nil && isConsoleActive {
					message = message + "No MFA device; \n"
				} else {
					msg := *mfa.SerialNumber + "(true)\n"
					mfaEnabled = mfaEnabled + msg
				}
			}
		}

		// Append row to the table
		table.Append([]string{
			*user.UserName,
			user.CreateDate.Format(time.RFC3339),
			passwordLastUser,
			consoleStatus,
			mfaEnabled,
			message,
		})
	}

	// Render the table
	table.Render()
	fmt.Println("\n-----End Checking Users-----")
	return nil
}

func (i *IamDriver) ListGroups() error {
	output, err := i.client.ListGroups(context.Background(), &iam.ListGroupsInput{})
	if err != nil {
		return err
	}
	// Create a new table writer
	fmt.Println("\n-----Start Checking Groups-----")
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"GroupID", "GroupName", "CreateDate", "Users", "Message"})
	for _, group := range output.Groups {
		var m string = ""
		groupUserCount := 0
		groupCreateDated := "NONE"
		gOutput, err := i.client.GetGroup(context.Background(), &iam.GetGroupInput{
			GroupName: group.GroupName,
		})
		if err != nil {
			m = fmt.Sprintf("Error getting group %s: %v\n", *group.GroupName, err)
		} else {

			if gOutput.Users == nil {
				m = "No users in the group"
			} else {
				groupUserCount = len(gOutput.Users)
			}

			if gOutput.Group.CreateDate != nil {
				groupCreateDated = gOutput.Group.CreateDate.Format(time.RFC3339)
			}
		}
		table.Append([]string{
			*group.GroupId,
			*group.GroupName,
			groupCreateDated,
			fmt.Sprintf("%d", groupUserCount),
			m})
	}
	table.Render()
	fmt.Println("\n-----End Checking Groups-----")
	return nil
}

func (i *IamDriver) ListAccessKey() error {
	output, err := i.client.ListAccessKeys(context.Background(), &iam.ListAccessKeysInput{})
	if err != nil {
		return err
	}
	fmt.Println("\n-----Start Checking Access Key-----")
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"UserName", "AccessKeyId", "Status", "Message"})
	for _, key := range output.AccessKeyMetadata {
		var errMsg string = ""
		akOutput, err := i.client.GetAccessKeyLastUsed(context.Background(), &iam.GetAccessKeyLastUsedInput{
			AccessKeyId: key.AccessKeyId,
		})
		if err != nil {
			errMsg = fmt.Sprintf("Error getting access key last used for key %s: %v\n", *key.AccessKeyId, err)
		} else {
			if key.CreateDate.Before(time.Now().AddDate(0, 0, -60)) {
				errMsg = "Key is older than 60 days"
			}
			if akOutput.AccessKeyLastUsed.LastUsedDate.Before(time.Now().AddDate(0, 0, -30)) {
				errMsg = errMsg + "; Access key last used is older than 30 days"
			}
		}
		table.Append([]string{*key.UserName, *key.AccessKeyId, string(key.Status), errMsg})
	}
	table.Render()
	fmt.Println("\n-----End Checking Access Key-----")
	return nil
}

func (i *IamDriver) CheckingSoureIpForConsole() error {
	output, err := i.client.ListPolicies(context.Background(), &iam.ListPoliciesInput{
		OnlyAttached: true,
		Scope:        types.PolicyScopeTypeLocal,
	})
	if err != nil {
		return err
	}
	fmt.Println("\n-----Start Checking Source IP for Console-----")
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"PolicyName", "PolicyArn", "Enabled-SourceIp", "Message"})
	for _, policy := range output.Policies {
		enabledSourceIp := "false"
		message := "No Source IP restriction"
		// Get the policy version to access the actual policy document
		policyVersionOutput, err := i.client.GetPolicyVersion(context.Background(), &iam.GetPolicyVersionInput{
			PolicyArn: policy.Arn,
			VersionId: policy.DefaultVersionId, // Get the default version of the policy
		})
		if err != nil {
			message = fmt.Sprintf("Error getting policy version for policy %s: %v\n", *policy.PolicyName, err)
		} else {
			// Check if the policy contains a "SourceIp" condition
			if i.isSourceIPRestricted(policyVersionOutput.PolicyVersion.Document) {
				enabledSourceIp = "true"
				message = ""
			}
		}
		table.Append([]string{*policy.PolicyName, *policy.Arn, enabledSourceIp, message})
	}
	table.Render()
	fmt.Println("\n-----End Checking Source IP for Console-----")
	return nil
}

func (i *IamDriver) CheckPasswordPolicy() error {
	fmt.Println("\n-----Start Checking Password Policy-----")
	defer func() {
		fmt.Println("\n-----End Checking Password Policy-----")
	}()
	output, err := i.client.GetAccountPasswordPolicy(context.Background(), &iam.GetAccountPasswordPolicyInput{})
	var re *awshttp.ResponseError
	if err != nil {
		if errors.As(err, &re) {
			if re.ResponseError.HTTPStatusCode() == 404 {
				fmt.Println("Password policy not found")
			}
			return nil
		}
		return nil
	}
	if *output.PasswordPolicy.MinimumPasswordLength < 8 {
		fmt.Println("Password length is greater than 8")
	}
	if !output.PasswordPolicy.RequireSymbols {
		fmt.Println("Require symbols")
	}
	if !output.PasswordPolicy.RequireNumbers {
		fmt.Println("Require numbers")
	}
	if !output.PasswordPolicy.RequireLowercaseCharacters {
		fmt.Println("Require lowercase characters")
	}
	if !output.PasswordPolicy.RequireUppercaseCharacters {
		fmt.Println("Require uppercase characters")
	}
	if *output.PasswordPolicy.MaxPasswordAge < 90 {
		fmt.Println("Password age is less than 90 days")
	}
	if *output.PasswordPolicy.PasswordReusePrevention < 1 {
		fmt.Println("Password reuse prevention is less than 1")
	}
	if output.PasswordPolicy.HardExpiry == aws.Bool(false) {
		fmt.Println("Password hard expiry is disabled, please change to true")
	}
	if !output.PasswordPolicy.AllowUsersToChangePassword {
		fmt.Println("Allow users to change password is disabled, please change to true")
	}

	return nil
}

func (i *IamDriver) isSourceIPRestricted(policyDocument *string) bool {
	// 간단한 문자열 검색을 통해 "aws:SourceIp" 확인
	if policyDocument != nil && strings.Contains(*policyDocument, "aws:SourceIp") {
		return true
	}
	return false
}
