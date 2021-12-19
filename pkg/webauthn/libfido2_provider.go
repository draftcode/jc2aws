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
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/fxamacker/cbor"
	"github.com/draftcode/jc2aws/pkg/fido2"
)

type LibFido2PublicKeyProvider struct{}

func NewLibFido2PublicKeyProvider() *LibFido2PublicKeyProvider {
	return &LibFido2PublicKeyProvider{}
}

func (p LibFido2PublicKeyProvider) PublicKey(origin string, opt *PublicKeyCredentialRequestOptions) (*PublicKeyCredential, error) {
	allowCred, err := p.findAllowCred(opt.AllowCredentials)
	if err != nil {
		return nil, err
	}
	credentialIDs, err := p.parseCredentialIDs(opt.AllowCredentials)
	if err != nil {
		return nil, err
	}
	clientDataJSON, clientDataHash, err := p.newClientDataJSON(origin, opt.Challenge)
	if err != nil {
		return nil, err
	}

	locs, err := fido2.DeviceLocations()
	if err != nil {
		return nil, fmt.Errorf("cannot get a list of devices: %v", err)
	}
	if len(locs) == 0 {
		return nil, fmt.Errorf("cannot find any FIDO2 devices")
	}
	for _, loc := range locs {
		var assertion *fido2.Assertion
		assertion, err = p.publicKeyInternal(loc, opt.RPID, clientDataHash, credentialIDs)
		if err != nil {
			continue
		}

		var authData []byte
		if err := cbor.Unmarshal(assertion.AuthDataCBOR, &authData); err != nil {
			return nil, fmt.Errorf("cannot unmarshal AuthDataCBOR: %v", err)
		}

		return &PublicKeyCredential{
			ID:    allowCred.ID,
			Type:  allowCred.Type,
			RawID: allowCred.ID,
			Response: AuthenticatorAssertionResponse{
				ClientDataJSON:    base64.RawURLEncoding.EncodeToString([]byte(clientDataJSON)),
				AuthenticatorData: base64.RawURLEncoding.EncodeToString(authData),
				Signature:         base64.RawURLEncoding.EncodeToString(assertion.Sig),
			},
		}, nil
	}
	// Return the last error. It's likely that the user doesn't have
	// multiple keys, so this will give the right error message most of the
	// cases.
	return nil, err
}

func (p LibFido2PublicKeyProvider) findAllowCred(allowCredentials []PublicKeyCredentialDescriptor) (PublicKeyCredentialDescriptor, error) {
	var ret []PublicKeyCredentialDescriptor
	for _, ac := range allowCredentials {
		if ac.Type == "public-key" {
			ret = append(ret, ac)
		}
	}
	if len(ret) > 1 {
		// Since Assertion from libfido2 won't return the credential
		// data, we cannot handle multiple credentials.
		return PublicKeyCredentialDescriptor{}, fmt.Errorf("cannot handle multiple allowCredentials")
	}
	if len(ret) == 0 {
		return PublicKeyCredentialDescriptor{}, fmt.Errorf("there should be at least one allowCredentials")
	}
	return ret[0], nil
}

func (p LibFido2PublicKeyProvider) publicKeyInternal(loc string, rpID string, clientDataHash []byte, credentialIDs [][]byte) (*fido2.Assertion, error) {
	assertion, err := fido2.NewAssertion(loc, rpID, clientDataHash, credentialIDs)
	if err != nil {
		return nil, fmt.Errorf("cannot make an assertion: %v", err)
	}
	return assertion, nil

}

func (p LibFido2PublicKeyProvider) parseCredentialIDs(allowCredentials []PublicKeyCredentialDescriptor) ([][]byte, error) {
	var ret [][]byte
	for _, ac := range allowCredentials {
		if ac.Type != "public-key" {
			continue
		}
		bs, err := base64.RawURLEncoding.DecodeString(ac.ID)
		if err != nil {
			return nil, fmt.Errorf("cannot decode allowCredentials.ID %q: %v", ac.ID, err)
		}
		ret = append(ret, bs)
	}
	return ret, nil
}

func (p LibFido2PublicKeyProvider) newClientDataJSON(origin string, challenge string) (string, []byte, error) {
	type clientData struct {
		Type        string `json:"type"`
		Challenge   string `json:"challenge"`
		Origin      string `json:"origin"`
		CrossOrigin bool   `json:"crossOrigin"`
	}
	bs, err := json.Marshal(&clientData{
		Type:        "webauthn.get",
		Challenge:   challenge,
		Origin:      origin,
		CrossOrigin: false,
	})
	if err != nil {
		return "", nil, fmt.Errorf("cannot make a ClientDataJSON: %v", err)
	}
	hash := sha256.Sum256(bs)
	return string(bs), hash[:], nil
}
