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

// Package jumpcloud provides a way to get a SAML assertion from JumpCloud.
//
// This is a stripped version of https://github.com/Versent/saml2aws/. The login
// process is well described in https://github.com/Versent/saml2aws/issues/230.
package jumpcloud

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"

	"github.com/PuerkitoBio/goquery"
)

type MFAType string

const (
	MFATypeWebAuthn MFAType = "webauthn"
	MFATypeTOTP             = "totp"
)

type mfaRequiredError struct {
	availableMFATypes []MFAType
}

func (mfaRequiredError) Error() string {
	return "MFA Required"
}

type JumpCloudClient struct {
	HTTPClient http.Client
}

func (c *JumpCloudClient) Authenticate(email, password string, mfaHandler func(*JumpCloudClient, []MFAType) (MFAResponse, error)) (string, error) {
	if c.HTTPClient.Jar == nil {
		jar, err := cookiejar.New(nil)
		if err != nil {
			return "", fmt.Errorf("cannot make a cookiejar: %v", err)
		}
		c.HTTPClient.Jar = jar
	}
	xsrfToken, err := c.getXSRFToken()
	if err != nil {
		return "", err
	}
	redirectURL, err := c.makeAuthRequest(xsrfToken, email, password, "")
	if err != nil {
		var mfaRequiredError mfaRequiredError
		if errors.As(err, &mfaRequiredError) {
			mfaResp, err := mfaHandler(c, mfaRequiredError.availableMFATypes)
			if err != nil {
				return "", err
			}
			redirectURL, err = c.handleMFAResponse(xsrfToken, email, password, mfaResp)
			if err != nil {
				return "", err
			}
		} else {
			return "", err
		}
	}
	ret, err := c.getSAMLAssertion(redirectURL)
	if err != nil {
		return "", err
	}
	return ret, nil
}

func (c *JumpCloudClient) getXSRFToken() (string, error) {
	httpResp, err := c.HTTPClient.Get("https://console.jumpcloud.com/userconsole/xsrf")
	if err != nil {
		return "", fmt.Errorf("cannot obtain an XSRF token: %v", err)
	}
	defer httpResp.Body.Close()
	resp := struct {
		Token string `json:"xsrf"`
	}{}
	if err := json.NewDecoder(httpResp.Body).Decode(&resp); err != nil {
		return "", fmt.Errorf("cannot decode the XSRF token response: %v", err)
	}
	return resp.Token, nil
}

// makeAuthRequest makes a request to the auth endpoint and returns a redirect
// URL.
//
// It returns mfaRequiredError if JumpCloud requires MFA auth for the user.
func (c *JumpCloudClient) makeAuthRequest(xsrfToken, email, password, otp string) (string, error) {
	req := struct {
		Context    string `json:"context"`
		RedirectTo string `json:"redirectTo"`
		Email      string `json:"email"`
		Password   string `json:"password"`
		OTP        string `json:"otp"`
	}{
		Context:    "sso",
		RedirectTo: "saml2/aws",
		Email:      email,
		Password:   password,
		OTP:        otp,
	}
	reqBody, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("cannot make an auth request body: %v", err)
	}
	httpReq, err := http.NewRequest("POST", "https://console.jumpcloud.com/userconsole/auth", bytes.NewReader(reqBody))
	if err != nil {
		return "", fmt.Errorf("cannot make an auth request body: %v", err)
	}
	httpReq.Header.Add("X-Xsrftoken", xsrfToken)
	httpReq.Header.Add("Accept", "application/json")
	httpReq.Header.Add("Content-Type", "application/json")

	httpResp, err := c.HTTPClient.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("cannot make an HTTP request to the auth request endpoint: %v", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode == http.StatusUnauthorized {
		resp := struct {
			Message string `json:"message"`
			Factors []struct {
				Type   string `json:"type"`
				Status string `json:"status"`
			} `json:"factors"`
		}{}
		if err := json.NewDecoder(httpResp.Body).Decode(&resp); err != nil {
			return "", fmt.Errorf("cannot parse the 401 Unauthorized response body: %v", err)
		}
		if resp.Message != "MFA required." {
			return "", fmt.Errorf("the auth endpoint returns 401 Unauthorized: %v", resp.Message)
		}
		var availableMFATypes []MFAType
		for _, factor := range resp.Factors {
			if factor.Status != "available" {
				continue
			}
			switch ty := MFAType(factor.Type); ty {
			case MFATypeWebAuthn, MFATypeTOTP:
				availableMFATypes = append(availableMFATypes, ty)
			}
		}
		return "", mfaRequiredError{availableMFATypes}
	} else if httpResp.StatusCode != http.StatusOK {
		bs, _ := ioutil.ReadAll(httpResp.Body)
		return "", fmt.Errorf("the auth endpoint returned %s: %s", httpResp.Status, string(bs))
	}

	resp := struct {
		RedirectTo string `json:"redirectTo"`
	}{}
	if err := json.NewDecoder(httpResp.Body).Decode(&resp); err != nil {
		return "", fmt.Errorf("cannot parse the auth endpoint response body: %v", err)
	}
	return resp.RedirectTo, nil
}

func (c *JumpCloudClient) getSAMLAssertion(redirectURL string) (string, error) {
	resp, err := c.HTTPClient.Get(redirectURL)
	if err != nil {
		return "", fmt.Errorf("cannot access the redirect URL: %v", err)
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return "", fmt.Errorf("cannot parse the redirect URL document: %v", err)
	}
	var ret string
	doc.Find("input").Each(func(i int, selection *goquery.Selection) {
		name, ok := selection.Attr("name")
		if !ok {
			return
		}
		if name != "SAMLResponse" {
			return
		}
		value, ok := selection.Attr("value")
		if !ok {
			return
		}
		ret = value
	})
	if ret == "" {
		return "", fmt.Errorf("cannot find the SAML assertion in the redirected URL: %v", err)
	}
	return ret, nil
}

func (c *JumpCloudClient) handleMFAResponse(xsrfToken, email, password string, rawResp MFAResponse) (string, error) {
	switch resp := rawResp.(type) {
	case TOTPMFAResponse:
		return c.makeAuthRequest(xsrfToken, email, password, resp.OTP)
	case WebAuthnMFAResponse:
		httpReq, err := http.NewRequest("POST", webAuthnURL, bytes.NewReader(resp.Assertion))
		if err != nil {
			return "", fmt.Errorf("cannot make an WebAuthn auth request body: %v", err)
		}
		httpReq.Header.Add("X-Xsrftoken", xsrfToken)
		httpReq.Header.Add("Accept", "application/json")
		httpReq.Header.Add("Content-Type", "application/json")

		httpResp, err := c.HTTPClient.Do(httpReq)
		if err != nil {
			return "", fmt.Errorf("cannot make an HTTP request to the WebAuthn auth request endpoint: %v", err)
		}
		defer httpResp.Body.Close()

		if httpResp.StatusCode != http.StatusOK {
			bs, _ := ioutil.ReadAll(httpResp.Body)
			return "", fmt.Errorf("the auth endpoint returned %s: %s", httpResp.Status, string(bs))
		}

		redirectResp := struct {
			RedirectTo string `json:"redirectTo"`
		}{}
		if err := json.NewDecoder(httpResp.Body).Decode(&redirectResp); err != nil {
			return "", fmt.Errorf("cannot parse the WebAuthn auth endpoint response body: %v", err)
		}
		return redirectResp.RedirectTo, nil
	default:
		return "", fmt.Errorf("unknown MFAResponse: %T", rawResp)
	}
}
