// Copyright 2021 Masaya Suzuki
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package awssts

import (
	"context"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/crewjam/saml"
	"gopkg.in/ini.v1"
)

// RoleProviderPair is a pair in SAML Role Attribute.
//
// See
// https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_saml_assertions.html#saml_role-attribute.
type RoleProviderPair struct {
	RoleARN      string
	PrincipalARN string
}

type SAMLAttributes struct {
	Roles           []RoleProviderPair
	SessionDuration time.Duration
}

type AWSAuthRequest struct {
	PrincipalARN    string
	RoleARN         string
	SAMLAssertion   string
	SessionDuration time.Duration
}

type AWSAuthResponse struct {
	AWSAccessKeyID     string
	AWSSecretAccessKey string
	AWSSessionToken    string
}

func ParseBase64EncodedSAMLResponse(s string) (*SAMLAttributes, error) {
	bs, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("cannot decode the base64 encoded SAML assertion: %v", err)
	}
	return ParseSAMLResponse(bs)
}

func ParseSAMLResponse(bs []byte) (*SAMLAttributes, error) {
	var response saml.Response
	if err := xml.Unmarshal(bs, &response); err != nil {
		return nil, fmt.Errorf("cannot parse the SAML response: %v", err)
	}

	var ret SAMLAttributes
	for _, stmt := range response.Assertion.AttributeStatements {
		for _, attr := range stmt.Attributes {
			var err error
			switch attr.Name {
			case "https://aws.amazon.com/SAML/Attributes/SessionDuration":
				ret.SessionDuration, err = parseSessionDurationValue(attr.Values)
				if err != nil {
					return nil, err
				}
			case "https://aws.amazon.com/SAML/Attributes/Role":
				ret.Roles, err = parseRoleValue(attr.Values)
				if err != nil {
					return nil, err
				}
			}
		}
	}
	return &ret, nil
}

func parseSessionDurationValue(values []saml.AttributeValue) (time.Duration, error) {
	if len(values) != 1 {
		return time.Duration(0), fmt.Errorf("SessionDuration should have only one value")
	}

	sec, err := strconv.ParseInt(values[0].Value, 10, 64)
	if err != nil {
		return time.Duration(0), fmt.Errorf("SessionDuration %s cannot be parsed as an integer: %v", values[0].Value, err)
	}
	if sec < 0 {
		return time.Duration(0), fmt.Errorf("SessionDuration %d must be non-negative", sec)
	}
	return time.Duration(sec) * time.Second, nil
}

func parseRoleValue(values []saml.AttributeValue) ([]RoleProviderPair, error) {
	var ret []RoleProviderPair
	for _, value := range values {
		ss := strings.Split(value.Value, ",")
		if len(ss) != 2 {
			return nil, fmt.Errorf("A role-provider pair should have exactly two comma-separated elements")
		}
		ret = append(ret, RoleProviderPair{
			RoleARN:      ss[0],
			PrincipalARN: ss[1],
		})
	}
	return ret, nil
}

func AWSSTSExchange(ctx context.Context, req *AWSAuthRequest) (*AWSAuthResponse, error) {
	input := &sts.AssumeRoleWithSAMLInput{
		PrincipalArn:  aws.String(req.PrincipalARN),
		RoleArn:       aws.String(req.RoleARN),
		SAMLAssertion: aws.String(req.SAMLAssertion),
	}

	if req.SessionDuration != time.Duration(0) {
		input.DurationSeconds = aws.Int32(int32(req.SessionDuration.Seconds()))
	}

	output, err := sts.New(sts.Options{Region: "aws-global"}).AssumeRoleWithSAML(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("AWS STS returns an error: %v", err)
	}
	return &AWSAuthResponse{
		AWSAccessKeyID:     *output.Credentials.AccessKeyId,
		AWSSecretAccessKey: *output.Credentials.SecretAccessKey,
		AWSSessionToken:    *output.Credentials.SessionToken,
	}, nil
}

func UpdateCredentialFile(fp, profileName string, resp *AWSAuthResponse) error {
	config, err := ini.Load(fp)
	if err != nil {
		return fmt.Errorf("cannot parse the existing config: %v", err)
	}
	section := config.Section(profileName)
	section.DeleteKey("aws_access_key_id")
	section.DeleteKey("aws_secret_access_key")
	section.DeleteKey("aws_session_token")
	section.NewKey("aws_access_key_id", resp.AWSAccessKeyID)
	section.NewKey("aws_secret_access_key", resp.AWSSecretAccessKey)
	section.NewKey("aws_session_token", resp.AWSSessionToken)
	if err := config.SaveTo(fp); err != nil {
		return fmt.Errorf("cannot save the credential: %v", err)
	}
	return nil
}
