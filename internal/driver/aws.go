package driver

import (
	"context"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	awsDriver "github.com/tae2089/aws-security-checker/internal/driver/aws"
)

type AwsManager struct {
	ec2Client *ec2.Client
	s3Client  *s3.Client
	iamClient *awsDriver.IamDriver
}

func NewAwsManager(profile, region string) *AwsManager {
	conf := getAwsConfig(profile, region)
	ec2Client := getEc2Client(conf)
	s3Client := getS3Client(conf)
	iamClient := getIamClient(conf)

	return &AwsManager{
		ec2Client: ec2Client,
		s3Client:  s3Client,
		iamClient: iamClient,
	}
}

func getAwsConfig(profile, region string) aws.Config {
	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithSharedConfigProfile(profile), config.WithRegion(region))
	if err != nil {
		fmt.Println("Error loading AWS config:", err)
		os.Exit(1)
	}
	return cfg
}

func getEc2Client(cfg aws.Config) *ec2.Client {
	ec2Client := ec2.NewFromConfig(cfg)
	return ec2Client
}

func getS3Client(cfg aws.Config) *s3.Client {
	s3Client := s3.NewFromConfig(cfg)
	return s3Client
}

func getIamClient(cfg aws.Config) *awsDriver.IamDriver {
	iamClient := iam.NewFromConfig(cfg)
	return awsDriver.NewIamDriver(iamClient)
}

func (a *AwsManager) CheckIam() error {
	if err := a.iamClient.ListUsers(); err != nil {
		return err
	}

	if err := a.iamClient.ListGroups(); err != nil {
		return err
	}

	if err := a.iamClient.ListAccessKey(); err != nil {
		return err
	}

	if err := a.iamClient.CheckingSoureIpForConsole(); err != nil {
		return err
	}

	if err := a.iamClient.CheckPasswordPolicy(); err != nil {
		return err
	}
	return nil
}
