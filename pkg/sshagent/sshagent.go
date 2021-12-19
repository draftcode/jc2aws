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

// sshagent provides an ssh-agent implementation that can handle the WebAuthn
// PublicKey API.
//
// ssh-agent can have a custom extension, and this package utilize this to
// forward WebAuthn's Public Key credential API
// (https://www.w3.org/TR/webauthn-2/). Note that this is a custom protocol and
// can be used only with package.
package sshagent

import (
	"encoding/json"
	"fmt"
	"net"
	"os"

	"github.com/draftcode/jc2aws/pkg/webauthn"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const webauthnPublicKeyExt = "webauthnPublicKeyExt"

type publicKeyRequest struct {
	Origin string                                     `json:"origin"`
	Option webauthn.PublicKeyCredentialRequestOptions `json:"option"`
}

type publicKeyResponse struct {
	Credential webauthn.PublicKeyCredential `json:"credential"`
	Error      string                       `json:"error"`
}

type Agent struct {
	agent.ExtendedAgent
	provider webauthn.PublicKeyProvider
}

// NewAgentWrappingSSHAuthSock creates a new SSH Agent that responds to WebAuthn
// request, wrapping the existing SSH_AUTH_SOCK.
//
// If SSH_AUTH_SOCK is not defined, it won't respond to anything other than
// WebAuthn requests.
func NewAgentWrappingSSHAuthSock(provider webauthn.PublicKeyProvider) (*Agent, error) {
	socket := os.Getenv("SSH_AUTH_SOCK")
	var delegate agent.ExtendedAgent
	if socket == "" {
		delegate = &emptyAgent{}
	} else {
		conn, err := net.Dial("unix", socket)
		if err != nil {
			return nil, fmt.Errorf("canot dial SSH_AUTH_SOCK %v: %v", socket, err)
		}
		delegate = agent.NewClient(conn)
	}
	return NewAgent(delegate, provider), nil
}

// NewAgent creates a new SSH Agent that responds to WebAuthn request.
func NewAgent(delegate agent.ExtendedAgent, provider webauthn.PublicKeyProvider) *Agent {
	return &Agent{
		ExtendedAgent: delegate,
		provider:      provider,
	}
}

func (agent *Agent) Extension(extensionType string, contents []byte) ([]byte, error) {
	if extensionType != webauthnPublicKeyExt {
		return agent.ExtendedAgent.Extension(extensionType, contents)
	}

	cred, err := agent.extensionInternal(contents)
	// Even if we return an error here, the message is not sent back to the
	// client. We'll reply the error inside the response.
	var resp publicKeyResponse
	if err != nil {
		resp.Error = err.Error()
	} else {
		resp.Credential = *cred
	}

	bs, err := json.Marshal(resp)
	if err != nil {
		return nil, fmt.Errorf("cannot unmarshal the response: %v", err)
	}
	return bs, nil
}

func (agent *Agent) extensionInternal(contents []byte) (*webauthn.PublicKeyCredential, error) {
	var req publicKeyRequest
	if err := json.Unmarshal(contents, &req); err != nil {
		return nil, fmt.Errorf("cannot unmarshal the request: %v", err)
	}
	return agent.provider.PublicKey(req.Origin, &req.Option)
}

type Provider struct {
	agent agent.ExtendedAgent
}

func NewProviderFromSSHAuthSock() (*Provider, error) {
	socket := os.Getenv("SSH_AUTH_SOCK")
	conn, err := net.Dial("unix", socket)
	if err != nil {
		return nil, fmt.Errorf("canot dial SSH_AUTH_SOCK %v: %v", socket, err)
	}
	return NewProvider(agent.NewClient(conn)), nil
}

func NewProvider(agent agent.ExtendedAgent) *Provider {
	return &Provider{agent: agent}
}

func (p *Provider) PublicKey(origin string, opt *webauthn.PublicKeyCredentialRequestOptions) (*webauthn.PublicKeyCredential, error) {
	reqBS, err := json.Marshal(publicKeyRequest{
		Origin: origin,
		Option: *opt,
	})
	if err != nil {
		return nil, fmt.Errorf("cannot marshal the request: %v", err)
	}
	respBS, err := p.agent.Extension(webauthnPublicKeyExt, reqBS)
	if err != nil {
		return nil, fmt.Errorf("cannot get a public key from the remote WebAuthn client: %v", err)
	}
	var resp publicKeyResponse
	if err := json.Unmarshal(respBS, &resp); err != nil {
		return nil, fmt.Errorf("cannot unmarshal the response: %v", err)
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("%s", resp.Error)
	}
	return &resp.Credential, nil
}

type emptyAgent struct{}

func (emptyAgent) List() ([]*agent.Key, error) { return nil, nil }
func (emptyAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return nil, fmt.Errorf("unsupported")
}
func (emptyAgent) Add(key agent.AddedKey) error   { return fmt.Errorf("unsupported") }
func (emptyAgent) Remove(key ssh.PublicKey) error { return nil }
func (emptyAgent) RemoveAll() error               { return nil }
func (emptyAgent) Lock(passphrase []byte) error   { return nil }
func (emptyAgent) Unlock(passphrase []byte) error { return nil }
func (emptyAgent) Signers() ([]ssh.Signer, error) { return nil, nil }
func (emptyAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	return nil, fmt.Errorf("unsupported")
}
func (emptyAgent) Extension(extensionType string, contents []byte) ([]byte, error) {
	return nil, agent.ErrExtensionUnsupported
}
