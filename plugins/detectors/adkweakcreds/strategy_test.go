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
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/google/goonami-scanner/core/config"
	goohttp "github.com/google/goonami-scanner/core/net/http"
	_ "github.com/google/goonami-scanner/core/net/http/simpleclient"
	"google.golang.org/protobuf/proto"

	cpb "github.com/google/goonami-scanner/core/config/config_go_proto"
	npb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
)

func setupMockServer(t *testing.T, handler http.HandlerFunc) (*config.Config, *nspb.NetworkService) {
	t.Helper()
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)

	host, portStr, _ := net.SplitHostPort(ts.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	service := nspb.NetworkService_builder{
		ServiceName: "http",
		NetworkEndpoint: npb.NetworkEndpoint_builder{
			Type: npb.NetworkEndpoint_IP_PORT,
			IpAddress: npb.IpAddress_builder{
				Address: host,
			}.Build(),
			Port: npb.Port_builder{
				PortNumber: uint32(port),
			}.Build(),
		}.Build(),
	}.Build()

	cfg := config.FromProto(cpb.Config_builder{
		Globalcfg: cpb.GlobalConfig_builder{
			Performance: cpb.GlobalConfig_Performance_builder{
				HttpRetryInitialBackoffSeconds: proto.Int32(0),
			}.Build(),
		}.Build(),
	}.Build())
	return cfg, service
}

func TestAuthStrategy_Validate(t *testing.T) {
	tests := []struct {
		name    string
		auth    *authStrategy
		wantErr bool
	}{
		{
			name: "when_valid_strategy_returns_no_error",
			auth: &authStrategy{
				SupportsAuthentication: true,
				AuthDetails: &authDetails{
					LoginRequest: &request{
						Path:            "/login",
						Body:            "user=[[username]]&pass=[[password]]",
						ExtractionRegex: "error",
						Headers: []*header{
							{Name: "Content-Type", Value: "application/x-www-form-urlencoded"},
						},
					},
					CredentialsToTest: []*credential{
						{Username: "admin", Password: "password"},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "when_basic_auth_strategy_without_password_placeholder_returns_no_error",
			auth: &authStrategy{
				SupportsAuthentication: true,
				AuthDetails: &authDetails{
					LoginRequest: &request{
						Method:          "GET",
						Path:            "/admin",
						ExtractionRegex: "error",
						Headers: []*header{
							{Name: "Authorization", Value: "Basic [[basic_auth]]"},
						},
					},
					CredentialsToTest: []*credential{
						{Username: "admin", Password: "secret"},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "when_no_auth_returns_no_error",
			auth: &authStrategy{
				SupportsAuthentication: false,
			},
			wantErr: false,
		},
		{
			name: "when_auth_supported_but_no_credentials_returns_error",
			auth: &authStrategy{
				SupportsAuthentication: true,
				AuthDetails: &authDetails{
					LoginRequest: &request{
						Path:            "/login",
						ExtractionRegex: "error",
						Headers: []*header{
							{Name: "Content-Type", Value: "application/x-www-form-urlencoded"},
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "when_invalid_login_request_returns_error",
			auth: &authStrategy{
				SupportsAuthentication: true,
				AuthDetails: &authDetails{
					LoginRequest: &request{
						Path: "http://example.com/login",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "when_invalid_csrf_request_returns_error",
			auth: &authStrategy{
				SupportsAuthentication: true,
				AuthDetails: &authDetails{
					LoginRequest: &request{
						Path:            "/login",
						ExtractionRegex: "error",
						Headers: []*header{
							{Name: "Content-Type", Value: "application/x-www-form-urlencoded"},
						},
					},
					CsrfRequest: &request{
						Path: "http://example.com/csrf",
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.auth.compileAndValidate()
			if (err != nil) != tc.wantErr {
				t.Errorf("compileAndValidate() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestAuthStrategy_ValidateCredential(t *testing.T) {
	cfg, service := setupMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/csrf":
			w.Write([]byte("csrf: token123"))
		case "/login":
			user := r.FormValue("user")
			pass := r.FormValue("pass")
			csrf := r.FormValue("csrf")

			if user == "admin" && pass == "password" {
				if csrf != "" && csrf != "token123" {
					w.Write([]byte("error: invalid csrf"))
					return
				}
				w.Write([]byte("success"))
			} else {
				w.Write([]byte("error: invalid credentials"))
			}
		case "/csrf_stateful":
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "123"})
			w.Write([]byte("csrf: token456"))
		case "/login_stateful":
			cookie, err := r.Cookie("session")
			if err != nil || cookie.Value != "123" {
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte("error: missing or invalid session cookie"))
				return
			}
			user := r.FormValue("user")
			pass := r.FormValue("pass")
			csrf := r.FormValue("csrf")

			if user == "admin" && pass == "password" {
				if csrf != "token456" {
					w.Write([]byte("error: invalid csrf"))
					return
				}
				w.Write([]byte("success"))
			} else {
				w.Write([]byte("error: invalid credentials"))
			}
		case "/login_present":
			user := r.FormValue("user")
			pass := r.FormValue("pass")

			if user == "admin" && pass == "password" {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("success_but_500"))
			} else {
				w.Write([]byte("error: invalid credentials"))
			}
		case "/login_unauthorized":
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("unauthorized"))
		case "/login_forbidden":
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("forbidden"))
		case "/login_form_persisting":
			user := r.FormValue("user")
			pass := r.FormValue("pass")

			if user == "admin" && pass == "password" {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`<html><body><form><input type="text" name="user"><input type="password" name="pass"></form></body></html>`))
			} else {
				w.Write([]byte("error: invalid credentials"))
			}
		case "/login_cookie_redirect":
			user := r.FormValue("user")
			pass := r.FormValue("pass")
			if user == "admin" && pass == "password" {
				http.SetCookie(w, &http.Cookie{Name: "auth_token", Value: "valid_session", Path: "/"})
				http.Redirect(w, r, "/dashboard_cookie_protected", http.StatusFound)
				return
			}
			w.Write([]byte("error: invalid credentials"))
		case "/dashboard_cookie_protected":
			cookie, err := r.Cookie("auth_token")
			if err != nil || cookie.Value != "valid_session" {
				// Re-render login form if cookie is missing on redirect
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`<html><body><form><input type="password" name="pass"></form></body></html>`))
				return
			}
			w.Write([]byte("<html><body>Welcome to Dashboard</body></html>"))
		case "/login_basic_auth":
			user, pass, ok := r.BasicAuth()
			if ok && user == "admin" && pass == "secret" {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("welcome basic auth admin"))
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("unauthorized basic auth"))
		case "/login_basic_auth_empty_body":
			user, pass, ok := r.BasicAuth()
			if ok && user == "admin" && pass == "secret" {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("welcome basic auth admin"))
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
		}
	})

	tests := []struct {
		name      string
		auth      *authStrategy
		cred      *credential
		wantValid bool
		wantConf  confidenceLevel
		wantErr   bool
	}{
		{
			name: "when_valid_credentials_returns_true",
			auth: &authStrategy{
				SupportsAuthentication: true,
				AuthDetails: &authDetails{
					LoginRequest: &request{
						Method:          "POST",
						Path:            "/login",
						Body:            "user=[[username]]&pass=[[password]]",
						ExtractionRegex: "error: (.*)",
						Headers: []*header{
							{Name: "Content-Type", Value: "application/x-www-form-urlencoded"},
						},
					},
				},
			},
			cred:      &credential{Username: "admin", Password: "password"},
			wantValid: true,
			wantConf:  confidenceHigh,
		},
		{
			name: "when_invalid_credentials_returns_false",
			auth: &authStrategy{
				SupportsAuthentication: true,
				AuthDetails: &authDetails{
					LoginRequest: &request{
						Method:          "POST",
						Path:            "/login",
						Body:            "user=[[username]]&pass=[[password]]",
						ExtractionRegex: "error: (.*)",
						Headers: []*header{
							{Name: "Content-Type", Value: "application/x-www-form-urlencoded"},
						},
					},
				},
			},
			cred:      &credential{Username: "admin", Password: "wrong"},
			wantValid: false,
			wantConf:  confidenceNone,
		},
		{
			name: "when_csrf_required_and_valid_returns_true",
			auth: &authStrategy{
				SupportsAuthentication: true,
				AuthDetails: &authDetails{
					CsrfRequest: &request{
						Method:          "GET",
						Path:            "/csrf",
						ExtractionRegex: "csrf: (.*)",
						Headers: []*header{
							{Name: "Content-Type", Value: "text/plain"},
						},
					},
					LoginRequest: &request{
						Method:          "POST",
						Path:            "/login",
						Body:            "user=[[username]]&pass=[[password]]&csrf=[[csrftoken]]",
						ExtractionRegex: "error: (.*)",
						Headers: []*header{
							{Name: "Content-Type", Value: "application/x-www-form-urlencoded"},
						},
					},
				},
			},
			cred:      &credential{Username: "admin", Password: "password"},
			wantValid: true,
			wantConf:  confidenceHigh,
		},
		{
			name: "when_identifier_has_no_capturing_group_returns_false",
			auth: &authStrategy{
				SupportsAuthentication: true,
				AuthDetails: &authDetails{
					LoginRequest: &request{
						Method: "POST",
						Path:   "/login",
						Body:   "user=[[username]]&pass=[[password]]",
						// This regex has no capturing group "(...)"
						ExtractionRegex: "error: invalid credentials",
						Headers: []*header{
							{Name: "Content-Type", Value: "application/x-www-form-urlencoded"},
						},
					},
				},
			},
			cred:      &credential{Username: "admin", Password: "wrong"},
			wantValid: false,
			wantConf:  confidenceNone,
		},
		{
			name: "when_identifier_has_no_capturing_group_returns_true",
			auth: &authStrategy{
				SupportsAuthentication: true,
				AuthDetails: &authDetails{
					LoginRequest: &request{
						Method: "POST",
						Path:   "/login",
						Body:   "user=[[username]]&pass=[[password]]",
						// This regex has no capturing group "(...)"
						ExtractionRegex: "error: invalid credentials",
						Headers: []*header{
							{Name: "Content-Type", Value: "application/x-www-form-urlencoded"},
						},
					},
				},
			},
			cred:      &credential{Username: "admin", Password: "password"},
			wantValid: true,
			wantConf:  confidenceHigh,
		},
		{
			name: "when_csrf_requires_cookie_login_succeeds",
			auth: &authStrategy{
				SupportsAuthentication: true,
				AuthDetails: &authDetails{
					CsrfRequest: &request{
						Method:          "GET",
						Path:            "/csrf_stateful",
						ExtractionRegex: "csrf: (.*)",
						Headers: []*header{
							{Name: "Content-Type", Value: "text/plain"},
						},
					},
					LoginRequest: &request{
						Method:          "POST",
						Path:            "/login_stateful",
						Body:            "user=[[username]]&pass=[[password]]&csrf=[[csrftoken]]",
						ExtractionRegex: "error: (.*)",
						Headers: []*header{
							{Name: "Content-Type", Value: "application/x-www-form-urlencoded"},
						},
					},
				},
			},
			cred:      &credential{Username: "admin", Password: "password"},
			wantValid: true,
			wantConf:  confidenceHigh,
		},
		{
			name: "when_status_500_returns_auth_present",
			auth: &authStrategy{
				SupportsAuthentication: true,
				AuthDetails: &authDetails{
					LoginRequest: &request{
						Method:          "POST",
						Path:            "/login_present",
						Body:            "user=[[username]]&pass=[[password]]",
						ExtractionRegex: "error: (.*)",
						Headers: []*header{
							{Name: "Content-Type", Value: "application/x-www-form-urlencoded"},
						},
					},
				},
			},
			cred:      &credential{Username: "admin", Password: "password"},
			wantValid: true,
			wantConf:  confidenceLow,
		},
		{
			name: "when_form_auth_with_status_401_returns_failure",
			auth: &authStrategy{
				SupportsAuthentication: true,
				AuthDetails: &authDetails{
					LoginRequest: &request{
						Method:          "POST",
						Path:            "/login_unauthorized",
						Body:            "user=[[username]]&pass=[[password]]",
						ExtractionRegex: "error: (.*)",
						Headers: []*header{
							{Name: "Content-Type", Value: "application/x-www-form-urlencoded"},
						},
					},
				},
			},
			cred:      &credential{Username: "admin", Password: "wrong"},
			wantValid: false,
			wantConf:  confidenceNone,
		},
		{
			name: "when_form_auth_with_status_403_returns_failure",
			auth: &authStrategy{
				SupportsAuthentication: true,
				AuthDetails: &authDetails{
					LoginRequest: &request{
						Method:          "POST",
						Path:            "/login_forbidden",
						Body:            "user=[[username]]&pass=[[password]]",
						ExtractionRegex: "error: (.*)",
						Headers: []*header{
							{Name: "Content-Type", Value: "application/x-www-form-urlencoded"},
						},
					},
				},
			},
			cred:      &credential{Username: "admin", Password: "wrong"},
			wantValid: false,
			wantConf:  confidenceNone,
		},
		{
			name: "when_form_persists_with_status_200_returns_auth_present",
			auth: &authStrategy{
				SupportsAuthentication: true,
				AuthDetails: &authDetails{
					LoginRequest: &request{
						Method:          "POST",
						Path:            "/login_form_persisting",
						Body:            "user=[[username]]&pass=[[password]]",
						ExtractionRegex: "error: (.*)",
						Headers: []*header{
							{Name: "Content-Type", Value: "application/x-www-form-urlencoded"},
						},
					},
				},
			},
			cred:      &credential{Username: "admin", Password: "password"},
			wantValid: true,
			wantConf:  confidenceLow,
		},
		{
			name: "when_non_csrf_login_redirects_with_cookie_preserves_session",
			auth: &authStrategy{
				SupportsAuthentication: true,
				AuthDetails: &authDetails{
					LoginRequest: &request{
						Method:          "POST",
						Path:            "/login_cookie_redirect",
						Body:            "user=[[username]]&pass=[[password]]",
						ExtractionRegex: "error: (.*)",
						Headers: []*header{
							{Name: "Content-Type", Value: "application/x-www-form-urlencoded"},
						},
					},
				},
			},
			cred:      &credential{Username: "admin", Password: "password"},
			wantValid: true,
			wantConf:  confidenceHigh,
		},
		{
			name: "when_non_csrf_login_redirects_with_cookie_invalid_password_returns_false",
			auth: &authStrategy{
				SupportsAuthentication: true,
				AuthDetails: &authDetails{
					LoginRequest: &request{
						Method:          "POST",
						Path:            "/login_cookie_redirect",
						Body:            "user=[[username]]&pass=[[password]]",
						ExtractionRegex: "error: (.*)",
						Headers: []*header{
							{Name: "Content-Type", Value: "application/x-www-form-urlencoded"},
						},
					},
				},
			},
			cred:      &credential{Username: "admin", Password: "wrong"},
			wantValid: false,
			wantConf:  confidenceNone,
		},
		{
			name: "when_basic_auth_valid_credentials_succeeds",
			auth: &authStrategy{
				SupportsAuthentication: true,
				AuthDetails: &authDetails{
					LoginRequest: &request{
						Method:          "GET",
						Path:            "/login_basic_auth",
						ExtractionRegex: "unauthorized (.*)",
						Headers: []*header{
							{Name: "Authorization", Value: "Basic [[basic_auth]]"},
						},
					},
				},
			},
			cred:      &credential{Username: "admin", Password: "secret"},
			wantValid: true,
			wantConf:  confidenceHigh,
		},
		{
			name: "when_basic_auth_invalid_credentials_fails",
			auth: &authStrategy{
				SupportsAuthentication: true,
				AuthDetails: &authDetails{
					LoginRequest: &request{
						Method:          "GET",
						Path:            "/login_basic_auth",
						ExtractionRegex: "unauthorized (.*)",
						Headers: []*header{
							{Name: "Authorization", Value: "Basic [[basic_auth]]"},
						},
					},
				},
			},
			cred:      &credential{Username: "admin", Password: "wrong"},
			wantValid: false,
			wantConf:  confidenceNone,
		},
		{
			name: "when_basic_auth_with_empty_failure_response_valid_credentials_succeeds",
			auth: &authStrategy{
				SupportsAuthentication: true,
				AuthDetails: &authDetails{
					LoginRequest: &request{
						Method:          "GET",
						Path:            "/login_basic_auth_empty_body",
						ExtractionRegex: `^\s*$`,
						Headers: []*header{
							{Name: "Authorization", Value: "Basic [[basic_auth]]"},
						},
					},
				},
			},
			cred:      &credential{Username: "admin", Password: "secret"},
			wantValid: true,
			wantConf:  confidenceHigh,
		},
		{
			name: "when_basic_auth_with_empty_failure_response_invalid_credentials_fails",
			auth: &authStrategy{
				SupportsAuthentication: true,
				AuthDetails: &authDetails{
					LoginRequest: &request{
						Method:          "GET",
						Path:            "/login_basic_auth_empty_body",
						ExtractionRegex: `^\s*$`,
						Headers: []*header{
							{Name: "Authorization", Value: "Basic [[basic_auth]]"},
						},
					},
				},
			},
			cred:      &credential{Username: "admin", Password: "wrong"},
			wantValid: false,
			wantConf:  confidenceNone,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.auth.AuthDetails != nil {
				tc.auth.AuthDetails.LoginRequest.compileAndValidate()
				if tc.auth.AuthDetails.CsrfRequest != nil {
					tc.auth.AuthDetails.CsrfRequest.compileAndValidate()
				}
			}

			gotValid, gotConf, err := tc.auth.validateCredential(t.Context(), cfg, service, tc.cred)
			if (err != nil) != tc.wantErr {
				t.Errorf("validateCredential() error = %v, wantErr %v", err, tc.wantErr)
			}
			if gotValid != tc.wantValid {
				t.Errorf("validateCredential() valid = %v, want %v", gotValid, tc.wantValid)
			}
			if gotConf != tc.wantConf {
				t.Errorf("validateCredential() conf = %v, want %v", gotConf, tc.wantConf)
			}
		})
	}
}

func TestAuthStrategy_Login(t *testing.T) {
	cfg, service := setupMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login_direct" {
			user := r.FormValue("user")
			pass := r.FormValue("pass")
			if user == "admin" && pass == "secret" {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("welcome admin"))
				return
			}
			if user == "admin" && pass == "rate" {
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("error: invalid credentials"))
		}
	})

	strat := &authStrategy{
		SupportsAuthentication: true,
		AuthDetails: &authDetails{
			LoginRequest: &request{
				Method:          "POST",
				Path:            "/login_direct",
				Body:            "user=[[username]]&pass=[[password]]",
				ExtractionRegex: "error: (.*)",
				Headers: []*header{
					{Name: "Content-Type", Value: "application/x-www-form-urlencoded"},
				},
			},
		},
	}
	if err := strat.AuthDetails.LoginRequest.compileAndValidate(); err != nil {
		t.Fatalf("compileAndValidate failed: %v", err)
	}

	tests := []struct {
		name           string
		cred           *credential
		wantStatusCode int
		wantExtraction string
		wantErr        error
	}{
		{
			name:           "when_valid_credentials_returns_200_and_nil_extraction",
			cred:           &credential{Username: "admin", Password: "secret"},
			wantStatusCode: http.StatusOK,
			wantExtraction: "",
			wantErr:        nil,
		},
		{
			name:           "when_invalid_credentials_returns_401_and_extracted_error",
			cred:           &credential{Username: "admin", Password: "wrong"},
			wantStatusCode: http.StatusUnauthorized,
			wantExtraction: "invalid credentials",
			wantErr:        nil,
		},
		{
			name:    "when_rate_limited_returns_errRateLimited",
			cred:    &credential{Username: "admin", Password: "rate"},
			wantErr: goohttp.ErrRateLimited,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := strat.login(t.Context(), cfg, service, tc.cred)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("login() error = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantErr != nil {
				return
			}
			if resp.StatusCode != tc.wantStatusCode {
				t.Errorf("login() StatusCode = %d, want %d", resp.StatusCode, tc.wantStatusCode)
			}
			if tc.wantExtraction == "" && resp.Extraction != nil {
				t.Errorf("login() Extraction = %v, want nil", *resp.Extraction)
			}
			if tc.wantExtraction != "" {
				if resp.Extraction == nil {
					t.Fatalf("login() Extraction = nil, want %q", tc.wantExtraction)
				}
				if *resp.Extraction != tc.wantExtraction {
					t.Errorf("login() Extraction = %q, want %q", *resp.Extraction, tc.wantExtraction)
				}
			}
		})
	}
}

func TestStrategyFromJSON(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		wantErr bool
	}{
		{
			name: "when_valid_json_returns_no_error",
			json: `{
				"supports_authentication": true,
				"authentication_details": {
					"login_request": {
						"method": "POST",
						"path": "/login",
						"body": "user=[[username]]&pass=[[password]]",
						"extraction_regex": "error",
						"headers": [
							{ "name": "Content-Type", "value": "application/x-www-form-urlencoded" }
						]
					},
					"credentials_to_test": [{"username": "admin", "password": "password"}]
				}
			}`,
			wantErr: false,
		},
		{
			name:    "when_invalid_json_returns_error",
			json:    `invalid json`,
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := strategyFromJSON(tc.json)
			if (err != nil) != tc.wantErr {
				t.Errorf("strategyFromJSON() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestAuthStrategy_FetchCSRFToken(t *testing.T) {
	cfg, service := setupMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/error" {
			hj, _ := w.(http.Hijacker)
			conn, _, _ := hj.Hijack()
			conn.Close()
			return
		}
		if r.URL.Path == "/fail" {
			w.Write([]byte("no token here"))
			return
		}
		w.Write([]byte("token is abc123def"))
	})

	tests := []struct {
		name       string
		auth       *authStrategy
		wantToken  string
		wantErr    bool
		wantErrSub string
	}{
		{
			name: "when_auth_details_is_nil_returns_empty_token",
			auth: &authStrategy{
				AuthDetails: nil,
			},
			wantToken: "",
			wantErr:   false,
		},
		{
			name: "when_csrf_request_is_nil_returns_empty_token",
			auth: &authStrategy{
				SupportsAuthentication: true,
				AuthDetails: &authDetails{
					LoginRequest:      &request{Path: "/[[password]]", ExtractionRegex: "dummy"},
					CredentialsToTest: []*credential{{Username: "admin", Password: "password"}},
					CsrfRequest:       nil,
				},
			},
			wantToken: "",
			wantErr:   false,
		},
		{
			name: "when_regex_matches_returns_token",
			auth: &authStrategy{
				SupportsAuthentication: true,
				AuthDetails: &authDetails{
					LoginRequest:      &request{Path: "/[[password]]", Body: "token=[[csrftoken]]", ExtractionRegex: "dummy"},
					CredentialsToTest: []*credential{{Username: "admin", Password: "password"}},
					CsrfRequest: &request{
						Method:          "GET",
						Path:            "/",
						ExtractionRegex: "token is ([a-z0-9]+)",
						Headers: []*header{
							{Name: "Content-Type", Value: "text/plain"},
						},
					},
				},
			},
			wantToken: "abc123def",
			wantErr:   false,
		},
		{
			name: "when_regex_misses_returns_error",
			auth: &authStrategy{
				SupportsAuthentication: true,
				AuthDetails: &authDetails{
					LoginRequest:      &request{Path: "/[[password]]", Body: "token=[[csrftoken]]", ExtractionRegex: "dummy"},
					CredentialsToTest: []*credential{{Username: "admin", Password: "password"}},
					CsrfRequest: &request{
						Method:          "GET",
						Path:            "/fail",
						ExtractionRegex: "token is ([a-z0-9]+)",
					},
				},
			},
			wantToken:  "",
			wantErr:    true,
			wantErrSub: "did not match anything",
		},
		{
			name: "when_request_fails_returns_error",
			auth: &authStrategy{
				SupportsAuthentication: true,
				AuthDetails: &authDetails{
					LoginRequest:      &request{Path: "/[[password]]", Body: "token=[[csrftoken]]", ExtractionRegex: "dummy"},
					CredentialsToTest: []*credential{{Username: "admin", Password: "password"}},
					CsrfRequest: &request{
						Method:          "GET",
						Path:            "/error",
						ExtractionRegex: "token",
					},
				},
			},
			wantToken:  "",
			wantErr:    true,
			wantErrSub: "csrf_request failed",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.auth.compileAndValidate(); err != nil {
				t.Fatalf("compileAndValidate failed: %v", err)
			}

			client, err := goohttp.NewClient(cfg, &goohttp.ClientOptions{StoreCookies: true})
			if err != nil {
				t.Fatalf("NewClient failed: %v", err)
			}

			got, err := tc.auth.fetchCSRFToken(t.Context(), service, client)

			if (err != nil) != tc.wantErr {
				t.Fatalf("FetchCSRFToken() error = %v, wantErr %v", err, tc.wantErr)
			}
			if err != nil && tc.wantErrSub != "" && !strings.Contains(err.Error(), tc.wantErrSub) {
				t.Errorf("FetchCSRFToken() error = %v, want error containing %q", err, tc.wantErrSub)
			}
			if got != tc.wantToken {
				t.Errorf("FetchCSRFToken() got = %v, want %q", got, tc.wantToken)
			}
		})
	}
}

func TestAuthStrategy_Login_RedirectOutOfScope(t *testing.T) {
	externalVisited := false
	externalServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		externalVisited = true
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("external login"))
	}))
	defer externalServer.Close()

	cfg, service := setupMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			http.Redirect(w, r, externalServer.URL+"/external_login", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})

	auth := &authStrategy{
		SupportsAuthentication: true,
		AuthDetails: &authDetails{
			LoginRequest: &request{
				Method:          "POST",
				Path:            "/login",
				Body:            "username=[[username]]&password=[[password]]",
				ExtractionRegex: "invalid",
			},
			CredentialsToTest: []*credential{
				{Username: "admin", Password: "password"},
			},
		},
	}

	if err := auth.compileAndValidate(); err != nil {
		t.Fatalf("compileAndValidate failed: %v", err)
	}

	if _, err := auth.login(t.Context(), cfg, service, &credential{Username: "admin", Password: "password"}); err != nil {
		t.Fatalf("login failed: %v", err)
	}

	if externalVisited {
		t.Errorf("externalServer was visited on out-of-scope redirect during login")
	}
}

func TestAuthStrategy_Bruteforce(t *testing.T) {
	cfg, service := setupMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login_standard":
			user := r.FormValue("username")
			pass := r.FormValue("password")
			if user == "admin" && pass == "admin" {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("welcome admin"))
				return
			}
			if user == "guest" && pass == "guest" {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("welcome guest"))
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("invalid credentials"))
		case "/login_always_succeeds":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("welcome anyone"))
		case "/login_length_capped_passwordless":
			pass := r.FormValue("password")
			if len(pass) <= 10 {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("welcome anyone"))
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("invalid format: max length 10"))
		case "/login_rate_limited":
			user := r.FormValue("username")
			pass := r.FormValue("password")
			if user == "admin" {
				if pass == "admin" {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte("welcome admin"))
					return
				}
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("invalid credentials"))
				return
			}
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte("too many requests"))
		case "/login_immediate_429":
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte("too many requests"))
		case "/csrf_fail":
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("csrf server error"))
		}
	})

	tests := []struct {
		name        string
		auth        *authStrategy
		ctx         func(t *testing.T) context.Context
		wantFinding bool
		wantCreds   []*credential
		wantErr     bool
	}{
		{
			name: "when_supports_authentication_is_false_returns_nil",
			auth: &authStrategy{
				SupportsAuthentication: false,
			},
			wantFinding: false,
		},
		{
			name: "when_no_credentials_match_returns_nil",
			auth: &authStrategy{
				SupportsAuthentication: true,
				AuthDetails: &authDetails{
					LoginRequest: &request{
						Method:          "POST",
						Path:            "/login_standard",
						Body:            "username=[[username]]&password=[[password]]",
						ExtractionRegex: "invalid (.*)",
						Headers: []*header{
							{Name: "Content-Type", Value: "application/x-www-form-urlencoded"},
						},
					},
					CredentialsToTest: []*credential{
						{Username: "baduser", Password: "badpassword"},
					},
				},
			},
			wantFinding: false,
		},
		{
			name: "when_valid_credentials_found_returns_finding",
			auth: &authStrategy{
				SupportsAuthentication: true,
				AuthDetails: &authDetails{
					LoginRequest: &request{
						Method:          "POST",
						Path:            "/login_standard",
						Body:            "username=[[username]]&password=[[password]]",
						ExtractionRegex: "invalid (.*)",
						Headers: []*header{
							{Name: "Content-Type", Value: "application/x-www-form-urlencoded"},
						},
					},
					CredentialsToTest: []*credential{
						{Username: "baduser", Password: "badpassword"},
						{Username: "admin", Password: "admin"},
					},
				},
			},
			wantFinding: true,
			wantCreds: []*credential{
				{Username: "admin", Password: "admin"},
			},
		},
		{
			name: "when_multiple_valid_credentials_found_returns_all",
			auth: &authStrategy{
				SupportsAuthentication: true,
				AuthDetails: &authDetails{
					LoginRequest: &request{
						Method:          "POST",
						Path:            "/login_standard",
						Body:            "username=[[username]]&password=[[password]]",
						ExtractionRegex: "invalid (.*)",
						Headers: []*header{
							{Name: "Content-Type", Value: "application/x-www-form-urlencoded"},
						},
					},
					CredentialsToTest: []*credential{
						{Username: "admin", Password: "admin"},
						{Username: "baduser", Password: "badpassword"},
						{Username: "guest", Password: "guest"},
					},
				},
			},
			wantFinding: true,
			wantCreds: []*credential{
				{Username: "admin", Password: "admin"},
				{Username: "guest", Password: "guest"},
			},
		},
		{
			name: "when_negative_validation_fails_discards_credential",
			auth: &authStrategy{
				SupportsAuthentication: true,
				AuthDetails: &authDetails{
					LoginRequest: &request{
						Method:          "POST",
						Path:            "/login_always_succeeds",
						Body:            "username=[[username]]&password=[[password]]",
						ExtractionRegex: "invalid (.*)",
						Headers: []*header{
							{Name: "Content-Type", Value: "application/x-www-form-urlencoded"},
						},
					},
					CredentialsToTest: []*credential{
						{Username: "admin", Password: "admin"},
					},
				},
			},
			wantFinding: false,
		},
		{
			name: "when_negative_validation_on_length_capped_endpoint_preserves_length_and_discards",
			auth: &authStrategy{
				SupportsAuthentication: true,
				AuthDetails: &authDetails{
					LoginRequest: &request{
						Method:          "POST",
						Path:            "/login_length_capped_passwordless",
						Body:            "username=[[username]]&password=[[password]]",
						ExtractionRegex: "invalid (.*)",
						Headers: []*header{
							{Name: "Content-Type", Value: "application/x-www-form-urlencoded"},
						},
					},
					CredentialsToTest: []*credential{
						{Username: "admin", Password: "admin"},
					},
				},
			},
			wantFinding: false,
		},
		{
			name: "when_csrf_request_fails_returns_error",
			auth: &authStrategy{
				SupportsAuthentication: true,
				AuthDetails: &authDetails{
					CsrfRequest: &request{
						Method:          "GET",
						Path:            "/csrf_fail",
						ExtractionRegex: "csrf: (.*)",
					},
					LoginRequest: &request{
						Method:          "POST",
						Path:            "/login_standard",
						Body:            "username=[[username]]&password=[[password]]&csrf=[[csrftoken]]",
						ExtractionRegex: "invalid (.*)",
						Headers: []*header{
							{Name: "Content-Type", Value: "application/x-www-form-urlencoded"},
						},
					},
					CredentialsToTest: []*credential{
						{Username: "admin", Password: "admin"},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "when_context_canceled_returns_error",
			auth: &authStrategy{
				SupportsAuthentication: true,
				AuthDetails: &authDetails{
					LoginRequest: &request{
						Method:          "POST",
						Path:            "/login_standard",
						Body:            "username=[[username]]&password=[[password]]",
						ExtractionRegex: "invalid (.*)",
						Headers: []*header{
							{Name: "Content-Type", Value: "application/x-www-form-urlencoded"},
						},
					},
					CredentialsToTest: []*credential{
						{Username: "admin", Password: "admin"},
					},
				},
			},
			ctx: func(t *testing.T) context.Context {
				ctx, cancel := context.WithCancel(t.Context())
				cancel()
				return ctx
			},
			wantErr: true,
		},
		{
			name: "when_rate_limited_after_valid_credentials_halts_and_preserves_findings",
			auth: &authStrategy{
				SupportsAuthentication: true,
				AuthDetails: &authDetails{
					LoginRequest: &request{
						Method:          "POST",
						Path:            "/login_rate_limited",
						Body:            "username=[[username]]&password=[[password]]",
						ExtractionRegex: "invalid (.*)",
						Headers: []*header{
							{Name: "Content-Type", Value: "application/x-www-form-urlencoded"},
						},
					},
					CredentialsToTest: []*credential{
						{Username: "admin", Password: "admin"},
						{Username: "root", Password: "root"},
						{Username: "guest", Password: "guest"},
					},
				},
			},
			wantFinding: true,
			wantCreds: []*credential{
				{Username: "admin", Password: "admin"},
			},
		},
		{
			name: "when_rate_limited_before_any_valid_credentials_returns_nil",
			auth: &authStrategy{
				SupportsAuthentication: true,
				AuthDetails: &authDetails{
					LoginRequest: &request{
						Method:          "POST",
						Path:            "/login_immediate_429",
						Body:            "username=[[username]]&password=[[password]]",
						ExtractionRegex: "invalid (.*)",
						Headers: []*header{
							{Name: "Content-Type", Value: "application/x-www-form-urlencoded"},
						},
					},
					CredentialsToTest: []*credential{
						{Username: "root", Password: "root"},
					},
				},
			},
			wantFinding: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.auth.SupportsAuthentication {
				if err := tc.auth.compileAndValidate(); err != nil {
					t.Fatalf("compileAndValidate failed: %v", err)
				}
			}

			testCtx := t.Context()
			if tc.ctx != nil {
				testCtx = tc.ctx(t)
			}

			finding, err := tc.auth.bruteforce(testCtx, cfg, service)
			if (err != nil) != tc.wantErr {
				t.Fatalf("bruteforce() error = %v, wantErr = %v", err, tc.wantErr)
			}

			if !tc.wantFinding {
				if finding != nil {
					t.Fatalf("bruteforce() returned finding %v, want nil", finding)
				}
				return
			}

			if finding == nil {
				t.Fatalf("bruteforce() returned nil, want finding")
			}

			if len(finding.ValidCredentials) != len(tc.wantCreds) {
				t.Fatalf("len(ValidCredentials) = %d, want %d", len(finding.ValidCredentials), len(tc.wantCreds))
			}

			for i, want := range tc.wantCreds {
				got := finding.ValidCredentials[i].credential
				if got.Username != want.Username || got.Password != want.Password {
					t.Errorf("ValidCredentials[%d] = %v:%v, want %v:%v", i, got.Username, got.Password, want.Username, want.Password)
				}
			}
		})
	}
}

func TestMutateCredentialString(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "when_empty_returns_x",
			in:   "",
			want: "x",
		},
		{
			name: "when_lowercase_rotates_rot13",
			in:   "admin",
			want: "nqzva",
		},
		{
			name: "when_uppercase_rotates_rot13",
			in:   "SECRET",
			want: "FRPERG",
		},
		{
			name: "when_digits_shift_by_5",
			in:   "0123456789",
			want: "5678901234",
		},
		{
			name: "when_mixed_case_shifts_case_sensitively",
			in:   "AdminUser",
			want: "NqzvaHfre",
		},
		{
			name: "when_alphanumeric_with_symbols_preserves_symbols",
			in:   "user_123!",
			want: "hfre_678!",
		},
		{
			name: "when_email_preserves_domain_and_shifts_local_part",
			in:   "admin@example.com",
			want: "nqzva@example.com",
		},
		{
			name: "when_email_with_dots_preserves_domain_structure",
			in:   "john.doe@corp.example.org",
			want: "wbua.qbr@corp.example.org",
		},
		{
			name: "when_symbols_only_prepends_x",
			in:   "---",
			want: "x---",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := mutateCredentialString(tc.in)
			if got != tc.want {
				t.Errorf("mutateCredentialString(%q) = %q, want %q", tc.in, got, tc.want)
			}
			if tc.in != "" && got == tc.in {
				t.Errorf("mutateCredentialString(%q) = %q, want different value", tc.in, got)
			}
		})
	}
}

func TestGetInvalidCredential(t *testing.T) {
	tests := []struct {
		name     string
		strategy *authStrategy
		wantNil  bool
		wantUser string
		wantPass string
	}{
		{
			name: "when_candidate_credentials_provided_uses_first_candidate_mutated_username_and_password",
			strategy: &authStrategy{
				SupportsAuthentication: true,
				AuthDetails: &authDetails{
					CredentialsToTest: []*credential{
						{Username: "admin@example.com", Password: "secret123"},
						{Username: "root", Password: "toor"},
					},
				},
			},
			wantNil:  false,
			wantUser: "nqzva@example.com",
			wantPass: "frperg678",
		},
		{
			name: "when_nil_auth_details_returns_nil",
			strategy: &authStrategy{
				SupportsAuthentication: false,
			},
			wantNil: true,
		},
		{
			name: "when_empty_credentials_to_test_returns_nil",
			strategy: &authStrategy{
				SupportsAuthentication: true,
				AuthDetails: &authDetails{
					CredentialsToTest: []*credential{},
				},
			},
			wantNil: true,
		},
		{
			name: "when_first_candidate_has_empty_username_returns_mutated_username_and_password",
			strategy: &authStrategy{
				SupportsAuthentication: true,
				AuthDetails: &authDetails{
					CredentialsToTest: []*credential{
						{Username: "", Password: "password"},
					},
				},
			},
			wantNil:  false,
			wantUser: "x",
			wantPass: "cnffjbeq",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.strategy.getInvalidCredential()
			if tc.wantNil {
				if got != nil {
					t.Errorf("getInvalidCredential() = %v, want nil", got)
				}
				return
			}
			if got == nil {
				t.Fatalf("getInvalidCredential() = nil, want non-nil")
			}
			if got.Username != tc.wantUser {
				t.Errorf("getInvalidCredential().Username = %q, want %q", got.Username, tc.wantUser)
			}
			if got.Password != tc.wantPass {
				t.Errorf("getInvalidCredential().Password = %q, want %q", got.Password, tc.wantPass)
			}
		})
	}
}
