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

package jumpcloud

import (
	"encoding/json"
	"fmt"

	"github.com/draftcode/jc2aws/pkg/webauthn"
)

const (
	webAuthnURL = "https://console.jumpcloud.com/userconsole/auth/webauthn"
)

type MFAResponse interface {
	mfaResponse()
}

type TOTPMFAResponse struct {
	OTP string
}

func (TOTPMFAResponse) mfaResponse() {}

type WebAuthnMFAResponse struct {
	Assertion []byte
}

func (WebAuthnMFAResponse) mfaResponse() {}

func NewWebAuthnMFAResponse(client *JumpCloudClient, provider webauthn.PublicKeyProvider) (MFAResponse, error) {
	httpResp, err := client.HTTPClient.Get(webAuthnURL)
	if err != nil {
		return nil, fmt.Errorf("cannot get a challenge for WebAuthn: %v", err)
	}
	defer httpResp.Body.Close()
	challengeResp := struct {
		PublicKey webauthn.PublicKeyCredentialRequestOptions `json:"publicKey"`
		Token     string                                     `json:"token"`
	}{}
	if err := json.NewDecoder(httpResp.Body).Decode(&challengeResp); err != nil {
		return nil, fmt.Errorf("cannot parse a challenge for WebAuthn: %v", err)
	}

	cred, err := provider.PublicKey("https://console.jumpcloud.com", &challengeResp.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("cannot get the WebAuthn credential: %v", err)
	}

	assertionReq := struct {
		PublicKeyCredential *webauthn.PublicKeyCredential `json:"publicKeyCredential"`
		Token               string                        `json:"token"`
	}{
		PublicKeyCredential: cred,
		Token:               challengeResp.Token,
	}
	assertion, err := json.Marshal(assertionReq)
	if err != nil {
		return nil, fmt.Errorf("cannot make a WebAuthn response: %v", err)
	}
	return WebAuthnMFAResponse{Assertion: assertion}, nil
}
