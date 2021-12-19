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

package webauthn

import (
	"fmt"
	"strings"
)

// https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialdescriptor
type PublicKeyCredentialDescriptor struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialrequestoptions
type PublicKeyCredentialRequestOptions struct {
	Challenge        string                          `json:"challenge"`
	Timeout          uint64                          `json:"timeout"`
	RPID             string                          `json:"rpId"`
	AllowCredentials []PublicKeyCredentialDescriptor `json:"allowCredentials"`
	UserVerification string                          `json:"userVerification"`
}

// https://www.w3.org/TR/webauthn-2/#authenticatorassertionresponse
type AuthenticatorAssertionResponse struct {
	ClientDataJSON    string `json:"clientDataJSON"`
	AuthenticatorData string `json:"authenticatorData"`
	Signature         string `json:"signature"`
}

// https://www.w3.org/TR/webauthn-2/#publickeycredential
type PublicKeyCredential struct {
	ID       string                         `json:"id"`
	Type     string                         `json:"type"`
	RawID    string                         `json:"rawId"`
	Response AuthenticatorAssertionResponse `json:"response"`
}

type PublicKeyProvider interface {
	PublicKey(origin string, opt *PublicKeyCredentialRequestOptions) (*PublicKeyCredential, error)
}

type MultiplePublicKeyProvider []PublicKeyProvider

func (provider MultiplePublicKeyProvider) PublicKey(origin string, opt *PublicKeyCredentialRequestOptions) (*PublicKeyCredential, error) {
	var errs []string
	for _, p := range provider {
		cred, err := p.PublicKey(origin, opt)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		return cred, nil
	}
	return nil, fmt.Errorf("no PublicKeyProvider returns a cred: [%s]", strings.Join(errs, ", "))
}
