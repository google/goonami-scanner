/*
 * Copyright 2026 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package adkweakcreds

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/log"
	goohttp "github.com/google/goonami-scanner/core/net/http"

	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
)

var (
	errRegexpTooWeak = errors.New("regexp was not robust enough: it failed to extract the error message from the HTTP response for an unknown username and invalid password; this caused the system to falsely believe the login was successful; please ensure the regex matches generic invalid login errors")
	errRateLimited   = errors.New("login endpoint returned 429 Too Many Requests")
)

type confidenceLevel int

const (
	confidenceNone confidenceLevel = iota
	confidenceLow
	confidenceHigh
)

// credential is a username and password pair.
type credential struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// validCredential contains a valid credential and the confidence of its success.
type validCredential struct {
	*credential
	Confidence confidenceLevel `json:"confidence"`
}

// authDetails contains the details required when authentication is supported.
type authDetails struct {
	CsrfRequest       *request      `json:"csrf_request"`
	LoginRequest      *request      `json:"login_request"`
	CredentialsToTest []*credential `json:"credentials_to_test"`
}

// authStrategy is the structure that defines how to perform a full end-to-end authentication.
type authStrategy struct {
	SupportsAuthentication bool         `json:"supports_authentication"`
	AuthDetails            *authDetails `json:"authentication_details"`
}

// strategyFromJSON parses the LLM output into an authStrategy and validates it.
func strategyFromJSON(content string) (*authStrategy, error) {
	var result authStrategy
	if err := json.Unmarshal([]byte(content), &result); err != nil {
		return nil, err
	}

	if err := result.compileAndValidate(); err != nil {
		return nil, err
	}

	return &result, nil
}

// compileAndValidate validates the strategy to ensure it contains all the information to perform authentication.
func (a *authStrategy) compileAndValidate() error {
	if !a.SupportsAuthentication {
		// There is no authentication.
		return nil
	}

	if a.AuthDetails == nil {
		return errors.New("strategy supports authentication but provided no authentication_details")
	}

	if len(a.AuthDetails.CredentialsToTest) == 0 {
		return errors.New("strategy supports authentication but provided no credentials to test")
	}

	if a.AuthDetails.LoginRequest == nil {
		return errors.New("strategy supports authentication but provided no login_request")
	}

	if err := a.AuthDetails.LoginRequest.compileAndValidate(); err != nil {
		return fmt.Errorf("login_request is invalid: %w", err)
	}

	loginReq := a.AuthDetails.LoginRequest

	if !loginReq.containsPlaceholder("[[password]]") && !loginReq.containsPlaceholder("[[basic_auth]]") {
		return errors.New("login_request must contain the [[password]] or [[basic_auth]] placeholder in the Path, Body, or Headers")
	}

	if a.AuthDetails.CsrfRequest != nil {
		if err := a.AuthDetails.CsrfRequest.compileAndValidate(); err != nil {
			return fmt.Errorf("csrf_request is invalid: %w", err)
		}

		if !loginReq.containsPlaceholder("[[csrftoken]]") {
			return errors.New("csrf_request is defined, but login_request is missing the [[csrftoken]] placeholder")
		}
	}

	return nil
}

// bruteforce iterates through the provided credentials to find a valid pair.
func (a *authStrategy) bruteforce(ctx context.Context, cfg *config.Config, service *nspb.NetworkService) (*finding, error) {
	if !a.SupportsAuthentication {
		return nil, nil
	}

	var validCreds []*validCredential

	for _, cred := range a.AuthDetails.CredentialsToTest {
		valid, confidence, err := a.validateCredential(ctx, cfg, service, cred)
		if err != nil {
			if errors.Is(err, errRateLimited) {
				log.WarnContextf(ctx, "rate limit reached testing credential %v; stopping brute force early", cred)
				break
			}
			return nil, err
		}

		if valid {
			log.DebugContextf(ctx, log.DebugLevelService, "valid credentials found: %v (confidence: %v)", cred, confidence)
			validCreds = append(validCreds, &validCredential{
				credential: cred,
				Confidence: confidence,
			})
		}
	}

	if len(validCreds) == 0 {
		return nil, nil
	}

	return &finding{
		ValidCredentials: validCreds,
		LoginRequest:     a.AuthDetails.LoginRequest,
		CsrfRequest:      a.AuthDetails.CsrfRequest,
	}, nil
}

// isAuthFailure reports whether the response indicates an authentication failure
// either through regex extraction match or protocol status codes (401 Unauthorized / 403 Forbidden).
func isAuthFailure(resp *response) bool {
	return resp.Extraction != nil || resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden
}

// validateCredential tests a single credential and confirms it via negative validation.
func (a *authStrategy) validateCredential(ctx context.Context, cfg *config.Config, service *nspb.NetworkService, cred *credential) (bool, confidenceLevel, error) {
	resp, err := a.login(ctx, cfg, service, cred)
	if err != nil {
		return false, confidenceNone, fmt.Errorf("failed to test credentials %v: %w", cred, err)
	}

	if isAuthFailure(resp) {
		return false, confidenceNone, nil
	}

	// Validate that the username with an invalid password does not authenticate.
	invalidCred := &credential{
		Username: cred.Username,
		Password: mutateCredentialString(cred.Password),
	}
	invalidCredResp, err := a.login(ctx, cfg, service, invalidCred)
	if err != nil {
		return false, confidenceNone, fmt.Errorf("failed negative validation for %v: %w", cred, err)
	}
	if !isAuthFailure(invalidCredResp) {
		log.DebugContextf(ctx, log.DebugLevelService, "Credentials %v appeared valid but failed negative validation test", cred)
		return false, confidenceNone, nil
	}

	// If login form persists or status is an error, mark confidenceLow.
	if isLoginFormPersisting(resp.Body) || resp.StatusCode >= 400 {
		return true, confidenceLow, nil
	}
	return true, confidenceHigh, nil
}

// getInvalidCredential returns a credential for negative validation. If candidate credentials
// are provided, it derives a probe by mutating both the username and password from the first
// candidate to preserve schema validity (e.g. email syntax) while ensuring invalidity.
// If no candidate credentials are provided, it returns nil.
func (a *authStrategy) getInvalidCredential() *credential {
	if a.AuthDetails == nil || len(a.AuthDetails.CredentialsToTest) == 0 {
		return nil
	}
	first := a.AuthDetails.CredentialsToTest[0]
	return &credential{
		Username: mutateCredentialString(first.Username),
		Password: mutateCredentialString(first.Password),
	}
}

// mutateCredentialString deterministically alters a credential string (username or password)
// by shifting alphanumeric characters while preserving string length, character classes, and punctuation.
// If the string is an email address, only the local part is mutated to preserve domain syntax.
func mutateCredentialString(s string) string {
	if parts := strings.Split(s, "@"); len(parts) == 2 && parts[0] != "" && strings.Contains(parts[1], ".") {
		return shiftAlphaNumeric(parts[0]) + "@" + parts[1]
	}
	return shiftAlphaNumeric(s)
}

func shiftAlphaNumeric(s string) string {
	if s == "" {
		return "x"
	}
	mutated := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return 'a' + (r-'a'+13)%26
		case r >= 'A' && r <= 'Z':
			return 'A' + (r-'A'+13)%26
		case r >= '0' && r <= '9':
			return '0' + (r-'0'+5)%10
		default:
			return r
		}
	}, s)
	if mutated == s {
		return "x" + s
	}
	return mutated
}

// fetchCSRFToken executes the CSRF request (if defined) to retrieve the token.
// It returns an error if the request fails or if the extraction regex matches nothing.
func (a *authStrategy) fetchCSRFToken(ctx context.Context, cfg *config.Config, service *nspb.NetworkService, client goohttp.Client) (string, error) {
	if a.AuthDetails == nil || a.AuthDetails.CsrfRequest == nil {
		return "", nil
	}

	resp, err := a.AuthDetails.CsrfRequest.do(ctx, cfg, service, client, nil)
	if err != nil {
		return "", fmt.Errorf("csrf_request failed: %w", err)
	}
	if resp.Extraction == nil {
		return "", errors.New("csrf_request extraction_regex did not match anything in the response; please verify your regex")
	}

	return *resp.Extraction, nil
}

// login performs the login request with credential substitutions and CSRF handling,
// returning the server response. Note that compileAndValidate() is expected to have
// been called before this method to ensure the strategy is in a valid state.
func (a *authStrategy) login(ctx context.Context, cfg *config.Config, service *nspb.NetworkService, cred *credential) (*response, error) {
	basicAuth := base64.StdEncoding.EncodeToString([]byte(cred.Username + ":" + cred.Password))
	substitutions := map[string]string{
		"username":   cred.Username,
		"password":   cred.Password,
		"basic_auth": basicAuth,
	}

	// Initialize HTTP client. Store cookies for all login attempts so redirect chains
	// preserve session state, isolated per credential attempt.
	opts := &goohttp.ClientOptions{
		StoreCookies: true,
	}
	if err := opts.LoadAuthorities(service); err != nil {
		return nil, err
	}

	client, err := goohttp.NewClient(cfg, opts)
	if err != nil {
		return nil, err
	}

	// Fetch the CSRF token if needed and add it to the substitutions.
	if a.AuthDetails.CsrfRequest != nil {
		token, err := a.fetchCSRFToken(ctx, cfg, service, client)
		if err != nil {
			return nil, err
		}

		substitutions["csrftoken"] = token
	}

	// Attempt the login with the provided credentials.
	resp, err := a.AuthDetails.LoginRequest.do(ctx, cfg, service, client, substitutions)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, errRateLimited
	}
	return resp, nil
}
