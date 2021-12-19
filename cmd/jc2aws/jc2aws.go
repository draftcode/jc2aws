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

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"

	"github.com/AlecAivazis/survey/v2"
	"github.com/adrg/xdg"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/draftcode/jc2aws/pkg/awssts"
	"github.com/draftcode/jc2aws/pkg/jumpcloud"
	"github.com/draftcode/jc2aws/pkg/sshagent"
	"github.com/draftcode/jc2aws/pkg/webauthn"
	"golang.org/x/crypto/ssh/agent"
)

var (
	startWebAuthnSSHAgent = flag.Bool("start_webauthn_ssh_agent", false, "If true, start ssh-agent that responds to WebAuthn Public Key request. It prints export SSH_AUTH_SOCK=... and exit, running an agent in the background. This automatically wraps existing SSH_AUTH_SOCK if exists. It outputs the shell command for the updated SSH_AUTH_SOCK address.")
	runWebAuthnSSHAgent   = flag.Bool("run_webauthn_ssh_agent", false, "If true, run ssh-agent that responds to WebAuthn Public Key request foreground.")
	webAuthnSSHAgentPath  = flag.String("web_authn_ssh_agent_path", "", "The Unix Domain Socket file path for WebAuthn SSH agent. This is used for start_webauthn_ssh_agent, run_webauthn_ssh_agent, and use_webauthn_ssh_agent. If empty, it'll be generated for XDG_RUNTIME_DIR (for server) or use SSH_AUTH_SOCK (for client).")
	credentialFilePath    = flag.String("credential_file_path", "", "The credential file path that the token is written to. If unspecified, it uses the file specified by AWS_SHARED_CREDENTIALS_FILE environment variable. If it's also empty, use the default location specified by https://docs.aws.amazon.com/sdkref/latest/guide/file-location.html.")
	profileName           = flag.String("profile_name", "", "The profile name of the credential file. It writes the auth tokens for this profile. If unspecified, it uses AWS_PROFILE if available.")
	useWebAuthnSSHAgent   = flag.Bool("use_webauthn_ssh_agent", true, "If true, use the ssh-agent protocol to query the WebAuthn Public Key. This uses SSH_AUTH_SOCK to get the ssh-agent Unix Domain Socket. The ssh-agent behind SSH_AUTH_SOCK should be the jc2aws ssh-agent.")
	email                 = flag.String("email", "", "Email address")
	mfa                   = flag.String("mfa", "", "MFA method to use when it's requested. If the specified MFA is not available, the CLI fails. If unspecified, if only one method is available, use that method. Otherwise, it shows a prompt to choose.")
	totp                  = flag.String("totp", "", "TOTP when MFA is requested and TOTP is used. If unspecified, it shows a prompt for one.")
)

func main() {
	flag.Parse()

	if *startWebAuthnSSHAgent {
		startAgent()
		return
	}
	if *runWebAuthnSSHAgent {
		runAgent()
		return
	}

	if *email == "" {
		if err := survey.AskOne(&survey.Input{Message: "Email"}, email); err != nil {
			log.Fatalf("Cannot get the email: %v", err)
		}
	}
	var password string
	if err := survey.AskOne(&survey.Password{Message: "Password"}, &password); err != nil {
		log.Fatalf("Cannot get the password: %v", err)
	}
	if *profileName == "" {
		env := os.Getenv("AWS_PROFILE")
		if env != "" {
			*profileName = env
		} else if err := survey.AskOne(&survey.Input{Message: "Profile"}, profileName); err != nil {
			log.Fatalf("Cannot get the profile: %v", err)
		}
	}

	client := jumpcloud.JumpCloudClient{}
	assertion, err := client.Authenticate(*email, password, mfaHandler)
	if err != nil {
		log.Fatalf("Cannot get the SAML assertion: %v", err)
	}
	attrs, err := awssts.ParseBase64EncodedSAMLResponse(assertion)
	if err != nil {
		log.Fatalf("Cannot parse the SAML response: %v", err)
	}
	role, err := chooseRole(attrs.Roles)
	if err != nil {
		log.Fatalf("Cannot choose the AWS role: %v", err)
	}
	resp, err := awssts.AWSSTSExchange(context.Background(), &awssts.AWSAuthRequest{
		PrincipalARN:    role.PrincipalARN,
		RoleARN:         role.RoleARN,
		SAMLAssertion:   assertion,
		SessionDuration: attrs.SessionDuration,
	})
	if err != nil {
		log.Fatalf("Cannot exchange the SAML assertion with an AWS STS token: %v", err)
	}
	if err := awssts.UpdateCredentialFile(getCredentialFilePath(), *profileName, resp); err != nil {
		log.Fatalf("Cannot update the credential file: %v", err)
	}
}

func startAgent() {
	fp, err := getAgentRDSPath()
	if err != nil {
		log.Fatalf("Cannot create a Unix Domain Socket file path: %v", err)
	}
	// Remove the remnant.
	os.Remove(fp)
	cmd := exec.Command("/proc/self/exe", "--run_webauthn_ssh_agent=true", "--web_authn_ssh_agent_path="+fp)
	cmd.Args[0] = os.Args[0]
	cmd.Stdin = nil
	cmd.Stderr = nil
	cmd.Stdout = nil
	if err := cmd.Start(); err != nil {
		log.Fatalf("Cannot execute the agent in the backround: %v", err)
	}
	fmt.Println("export SSH_AUTH_SOCK=" + fp)
}

func runAgent() {
	// Always use the local provider. Not sure if there's a need for
	// forwarding the request further.
	provider := webauthn.NewLibFido2PublicKeyProvider()
	ag, err := sshagent.NewAgentWrappingSSHAuthSock(provider)
	if err != nil {
		log.Fatal(err)
	}

	fp, err := getAgentRDSPath()
	if err != nil {
		log.Fatalf("Cannot create a Unix Domain Socket file path: %v", err)
	}
	// Remove the remnant.
	os.Remove(fp)
	defer os.Remove(fp)

	ln, err := net.Listen("unix", fp)
	if err != nil {
		log.Fatalf("Cannot listen on %s: %v", fp, err)
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Fatalf("Cannot accept a new connection: %v", err)
		}
		go agent.ServeAgent(ag, conn)
	}
}

func getAgentRDSPath() (string, error) {
	if *webAuthnSSHAgentPath != "" {
		return *webAuthnSSHAgentPath, nil
	}
	fp, err := xdg.RuntimeFile(fmt.Sprintf("%s/agent-%d", os.Args[0], os.Getpid()))
	if err != nil {
		return "", fmt.Errorf("cannot create a Unix Domain Socket file path: %v", err)
	}
	return fp, nil
}

func chooseRole(roles []awssts.RoleProviderPair) (awssts.RoleProviderPair, error) {
	if len(roles) == 0 {
		return awssts.RoleProviderPair{}, fmt.Errorf("no roles available")
	}
	if len(roles) == 1 {
		return roles[0], nil
	}
	var opts []string
	for _, role := range roles {
		opts = append(opts, string(role.RoleARN))
	}
	var resp string
	survey.AskOne(&survey.Select{Message: "Choose the AWS role", Options: opts}, &resp)
	for _, role := range roles {
		if role.RoleARN == resp {
			return role, nil
		}
	}
	return awssts.RoleProviderPair{}, fmt.Errorf("AWS role not chosen")
}

func mfaHandler(client *jumpcloud.JumpCloudClient, availableMFATypes []jumpcloud.MFAType) (jumpcloud.MFAResponse, error) {
	var chosen jumpcloud.MFAType
	if *mfa != "" {
		for _, ty := range availableMFATypes {
			if string(ty) == *mfa {
				chosen = ty
			}
		}
		if string(chosen) == "" {
			return nil, fmt.Errorf("specified MFA is not available for use")
		}
	} else if len(availableMFATypes) == 1 {
		chosen = availableMFATypes[0]
	} else {
		var opts []string
		for _, ty := range availableMFATypes {
			opts = append(opts, string(ty))
		}
		var resp string
		survey.AskOne(&survey.Select{Message: "Choose the MTP method", Options: opts}, &resp)
		chosen = jumpcloud.MFAType(resp)
	}

	switch chosen {
	case jumpcloud.MFATypeTOTP:
		return handleTOTP()
	case jumpcloud.MFATypeWebAuthn:
		return handleWebAuthn(client)
	default:
		return nil, fmt.Errorf("cannot handle MFA request for %v", chosen)
	}
}

func handleTOTP() (jumpcloud.MFAResponse, error) {
	var otp string
	if *totp != "" {
		otp = *totp
	} else if err := survey.AskOne(&survey.Input{Message: "TOTP"}, &otp); err != nil {
		return nil, fmt.Errorf("cannot get the TOTP: %v", err)
	}
	return jumpcloud.TOTPMFAResponse{OTP: otp}, nil
}

func handleWebAuthn(client *jumpcloud.JumpCloudClient) (jumpcloud.MFAResponse, error) {
	fmt.Fprintln(os.Stderr, "Waiting for touch...")
	var providers []webauthn.PublicKeyProvider
	if *useWebAuthnSSHAgent {
		sock := *webAuthnSSHAgentPath
		if sock == "" {
			sock = os.Getenv("SSH_AUTH_SOCK")
		}
		if sock != "" {
			p, err := sshagent.NewProviderFromSSHAuthSock()
			if err == nil {
				providers = append(providers, p)
			}
		}
	}
	providers = append(providers, webauthn.NewLibFido2PublicKeyProvider())
	return jumpcloud.NewWebAuthnMFAResponse(client, webauthn.MultiplePublicKeyProvider(providers))
}

func getCredentialFilePath() string {
	if *credentialFilePath != "" {
		return *credentialFilePath
	}
	env := os.Getenv("AWS_SHARED_CREDENTIALS_FILE")
	if env != "" {
		return env
	}
	return config.DefaultSharedCredentialsFilename()
}
