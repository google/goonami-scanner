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
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	goohttp "github.com/google/goonami-scanner/core/net/http"
	_ "github.com/google/goonami-scanner/core/net/http/simpleclient"
	npb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
)

func TestRequest_Validate(t *testing.T) {
	tests := []struct {
		name       string
		req        *request
		wantErr    error
		wantAnyErr bool
	}{
		{
			name: "when_valid_request_returns_no_error",
			req: &request{
				Path:            "/login",
				ExtractionRegex: "error",
				Headers: []*header{
					{Name: "Content-Type", Value: "application/x-www-form-urlencoded"},
				},
			},
			wantErr: nil,
		},
		{
			name: "when_invalid_url_returns_error",
			req: &request{
				Path:            "http://example.com/login",
				ExtractionRegex: "error",
				Headers: []*header{
					{Name: "Content-Type", Value: "application/x-www-form-urlencoded"},
				},
			},
			wantErr: errInvalidURL,
		},
		{
			name: "when_url_contains_colon_in_query_returns_no_error",
			req: &request{
				Path:            "/login?scope=user:email",
				ExtractionRegex: "error",
				Headers: []*header{
					{Name: "Content-Type", Value: "application/x-www-form-urlencoded"},
				},
			},
			wantErr: nil,
		},
		{
			name: "when_url_contains_redirect_url_in_query_returns_no_error",
			req: &request{
				Path:            "/login?redirect=https://example.com/dashboard",
				ExtractionRegex: "error",
				Headers: []*header{
					{Name: "Content-Type", Value: "application/x-www-form-urlencoded"},
				},
			},
			wantErr: nil,
		},
		{
			name: "when_url_contains_colon_in_path_returns_no_error",
			req: &request{
				Path:            "/api/v1/namespaces/default/services/app:80/proxy",
				ExtractionRegex: "error",
				Headers: []*header{
					{Name: "Content-Type", Value: "application/x-www-form-urlencoded"},
				},
			},
			wantErr: nil,
		},
		{
			name: "when_url_is_scheme_relative_returns_error",
			req: &request{
				Path:            "//example.com/login",
				ExtractionRegex: "error",
				Headers: []*header{
					{Name: "Content-Type", Value: "application/x-www-form-urlencoded"},
				},
			},
			wantErr: errInvalidURL,
		},
		{
			name: "when_url_parse_fails_returns_error",
			req: &request{
				Path:            "/\x7f",
				ExtractionRegex: "error",
				Headers: []*header{
					{Name: "Content-Type", Value: "application/x-www-form-urlencoded"},
				},
			},
			wantErr: errInvalidURL,
		},
		{
			name: "when_no_identifier_returns_error",
			req: &request{
				Path:            "/login",
				ExtractionRegex: "",
				Headers: []*header{
					{Name: "Content-Type", Value: "application/x-www-form-urlencoded"},
				},
			},
			wantErr: errNoExtractionRegex,
		},
		{
			name: "when_invalid_regexp_returns_error",
			req: &request{
				Path:            "/login",
				ExtractionRegex: "[",
				Headers: []*header{
					{Name: "Content-Type", Value: "application/x-www-form-urlencoded"},
				},
			},
			wantAnyErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.req.compileAndValidate()
			if tc.wantErr != nil {
				if err != tc.wantErr {
					t.Errorf("compileAndValidate() error = %v, want %v", err, tc.wantErr)
				}
			} else if tc.wantAnyErr {
				if err == nil {
					t.Errorf("compileAndValidate() error = nil, want error")
				}
			} else if err != nil {
				t.Errorf("compileAndValidate() error = %v, want nil", err)
			}
		})
	}
}

func TestRequest_Do(t *testing.T) {
	cfg, service := setupMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("response with token: abc123def"))
	})

	req := &request{
		Method:          "GET",
		Path:            "/",
		ExtractionRegex: "token: ([a-z0-9]+)",
		Headers: []*header{
			{Name: "Content-Type", Value: "text/plain"},
		},
	}

	if err := req.compileAndValidate(); err != nil {
		t.Fatalf("compileAndValidate() failed: %v", err)
	}

	client, err := goohttp.NewClient(cfg, nil)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	resp, err := req.do(t.Context(), service, client, nil)
	if err != nil {
		t.Fatalf("do() failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("do() StatusCode = %v, want %v", resp.StatusCode, http.StatusOK)
	}
	if want := "abc123def"; resp.Extraction == nil || *resp.Extraction != want {
		t.Errorf("do() Extraction = %v, want %v", resp.Extraction, want)
	}
	if !strings.Contains(string(resp.Body), "abc123def") {
		t.Errorf("do() Body = %q, want containing 'abc123def'", string(resp.Body))
	}
}

func TestRequest_Do_NoMatch(t *testing.T) {
	cfg, service := setupMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("response without any match"))
	})

	req := &request{
		Method:          "GET",
		Path:            "/",
		ExtractionRegex: "token: ([a-z0-9]+)",
		Headers: []*header{
			{Name: "Content-Type", Value: "text/plain"},
		},
	}

	if err := req.compileAndValidate(); err != nil {
		t.Fatalf("compileAndValidate() failed: %v", err)
	}

	client, err := goohttp.NewClient(cfg, nil)
	if err != nil {
		t.Fatalf("NewClient() failed: %v", err)
	}

	resp, err := req.do(t.Context(), service, client, nil)
	if err != nil {
		t.Fatalf("do() failed: %v", err)
	}
	if resp.Extraction != nil {
		t.Errorf("do() Extraction = %v, want nil", *resp.Extraction)
	}
}

func TestRequest_Do_EmptyResponseMatching(t *testing.T) {
	tests := []struct {
		name          string
		body          string
		regex         string
		wantExtracted bool
		wantValue     string
	}{
		{
			name:          "when_body_empty_matches",
			body:          "",
			regex:         `^\s*$`,
			wantExtracted: true,
			wantValue:     "",
		},
		{
			name:          "when_body_whitespace_matches",
			body:          "\r\n",
			regex:         `^\s*$`,
			wantExtracted: true,
			wantValue:     "\r\n",
		},
		{
			name:          "when_body_non_empty_does_not_match",
			body:          `{"status":"ok"}`,
			regex:         `^\s*$`,
			wantExtracted: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, service := setupMockServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(tc.body))
			})

			req := &request{
				Method:          "GET",
				Path:            "/",
				ExtractionRegex: tc.regex,
			}

			if err := req.compileAndValidate(); err != nil {
				t.Fatalf("compileAndValidate() failed: %v", err)
			}

			client, err := goohttp.NewClient(cfg, nil)
			if err != nil {
				t.Fatalf("NewClient failed: %v", err)
			}

			resp, err := req.do(t.Context(), service, client, nil)
			if err != nil {
				t.Fatalf("do() failed: %v", err)
			}

			if tc.wantExtracted {
				if resp.Extraction == nil {
					t.Fatalf("resp.Extraction = nil, want extracted %q", tc.wantValue)
				}
				if *resp.Extraction != tc.wantValue {
					t.Errorf("resp.Extraction = %q, want %q", *resp.Extraction, tc.wantValue)
				}
			} else {
				if resp.Extraction != nil {
					t.Errorf("resp.Extraction = %q, want nil", *resp.Extraction)
				}
			}
		})
	}
}

func TestRequest_BuildHTTPRequest(t *testing.T) {
	host := "127.0.0.1"
	port := 8080

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

	req := &request{
		Method:          "GET",
		Path:            "/",
		ExtractionRegex: "token: ([a-z0-9]+)",
		Headers: []*header{
			{Name: "Authorization", Value: "Basic [[password]]"},
			{Name: "X-CSRF-Token", Value: "[[csrftoken]]"},
			{Name: "Empty", Value: "Should stay"},
			{Name: "", Value: "Should be ignored"},
		},
	}

	substitutions := map[string]string{
		"password":  "secret",
		"csrftoken": "token123",
	}

	httpReq, err := req.buildHTTPRequest(t.Context(), service, substitutions)
	if err != nil {
		t.Fatalf("buildHTTPRequest() failed: %v", err)
	}

	if got := httpReq.Header.Get("Authorization"); got != "Basic secret" {
		t.Errorf("Authorization header = %q, want %q", got, "Basic secret")
	}
	if got := httpReq.Header.Get("X-CSRF-Token"); got != "token123" {
		t.Errorf("X-CSRF-Token header = %q, want %q", got, "token123")
	}
	if got := httpReq.Header.Get("Empty"); got != "Should stay" {
		t.Errorf("Empty header = %q, want %q", got, "Should stay")
	}
	if got := httpReq.Header.Get(""); got != "" {
		t.Errorf("Empty header name was incorrectly set")
	}
	if httpReq.Body != nil {
		t.Errorf("httpReq.Body = %v, want nil for empty body", httpReq.Body)
	}
}

func TestRequest_BuildHTTPRequest_WithBody(t *testing.T) {
	host := "127.0.0.1"
	port := 8080

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

	req := &request{
		Method: "POST",
		Path:   "/login",
		Body:   "user=[[username]]&pass=[[password]]",
	}

	substitutions := map[string]string{
		"username": "admin",
		"password": "secretpassword",
	}

	httpReq, err := req.buildHTTPRequest(t.Context(), service, substitutions)
	if err != nil {
		t.Fatalf("buildHTTPRequest() failed: %v", err)
	}

	if httpReq.Body == nil {
		t.Fatalf("httpReq.Body is nil, expected a body")
	}

	bodyBytes, err := io.ReadAll(httpReq.Body)
	if err != nil {
		t.Fatalf("failed to read body: %v", err)
	}
	defer httpReq.Body.Close()

	wantBody := "user=admin&pass=secretpassword"
	if string(bodyBytes) != wantBody {
		t.Errorf("httpReq.Body = %q, want %q", string(bodyBytes), wantBody)
	}
}

func TestBuildHTTPRequest_FormURLEncodesBody(t *testing.T) {
	service := nspb.NetworkService_builder{
		NetworkEndpoint: npb.NetworkEndpoint_builder{
			Port: npb.Port_builder{
				PortNumber: 80,
			}.Build(),
			IpAddress: npb.IpAddress_builder{
				Address: "127.0.0.1",
			}.Build(),
		}.Build(),
	}.Build()

	req := &request{
		Method: "POST",
		Path:   "/login",
		Body:   "token=[[csrftoken]]&user=[[username]]&pass=[[password]]",
		Headers: []*header{
			{Name: "Content-Type", Value: "application/x-www-form-urlencoded"},
		},
	}

	substitutions := map[string]string{
		"csrftoken": "qIUKKsS5QctY+LZcyvbnU+2BtKzeJuZ7EWtYT9ZqFSnwNRdSoxfdiyDfCTvn6gJcmBgP6rkD2L6ZCiiZ8UJ93Q==",
		"username":  "admin@example.com",
		"password":  "p@ss&word+1",
	}

	httpReq, err := req.buildHTTPRequest(t.Context(), service, substitutions)
	if err != nil {
		t.Fatalf("buildHTTPRequest() failed: %v", err)
	}

	bodyBytes, err := io.ReadAll(httpReq.Body)
	if err != nil {
		t.Fatalf("failed to read body: %v", err)
	}
	defer httpReq.Body.Close()

	wantBody := "token=qIUKKsS5QctY%2BLZcyvbnU%2B2BtKzeJuZ7EWtYT9ZqFSnwNRdSoxfdiyDfCTvn6gJcmBgP6rkD2L6ZCiiZ8UJ93Q%3D%3D&user=admin%40example.com&pass=p%40ss%26word%2B1"
	if string(bodyBytes) != wantBody {
		t.Errorf("httpReq.Body = %q, want %q", string(bodyBytes), wantBody)
	}
}

func TestBuildHTTPRequest_JSONPreservesRawBody(t *testing.T) {
	service := nspb.NetworkService_builder{
		NetworkEndpoint: npb.NetworkEndpoint_builder{
			Port: npb.Port_builder{
				PortNumber: 80,
			}.Build(),
			IpAddress: npb.IpAddress_builder{
				Address: "127.0.0.1",
			}.Build(),
		}.Build(),
	}.Build()

	req := &request{
		Method: "POST",
		Path:   "/api/auth/login",
		Body:   `{"username":"[[username]]","password":"[[password]]"}`,
		Headers: []*header{
			{Name: "Content-Type", Value: "application/json"},
		},
	}

	substitutions := map[string]string{
		"username": "admin@example.com",
		"password": "p@ss&word+1",
	}

	httpReq, err := req.buildHTTPRequest(t.Context(), service, substitutions)
	if err != nil {
		t.Fatalf("buildHTTPRequest() failed: %v", err)
	}

	bodyBytes, err := io.ReadAll(httpReq.Body)
	if err != nil {
		t.Fatalf("failed to read body: %v", err)
	}
	defer httpReq.Body.Close()

	wantBody := `{"username":"admin@example.com","password":"p@ss&word+1"}`
	if string(bodyBytes) != wantBody {
		t.Errorf("httpReq.Body = %q, want %q", string(bodyBytes), wantBody)
	}
}

func TestSubstitute(t *testing.T) {
	tests := []struct {
		name          string
		s             string
		substitutions map[string]string
		escape        bool
		want          string
	}{
		{
			name: "when_escape_false_returns_raw_string",
			s:    "user=[[username]]&pass=[[password]]&token=[[csrftoken]]",
			substitutions: map[string]string{
				"username":  "admin",
				"password":  "pass123",
				"csrftoken": "token+abc==",
			},
			escape: false,
			want:   "user=admin&pass=pass123&token=token+abc==",
		},
		{
			name: "when_escape_true_encodes_special_characters",
			s:    "token=[[csrftoken]]&pass=[[password]]",
			substitutions: map[string]string{
				"csrftoken": "token+abc==",
				"password":  "p@ss&word+1",
			},
			escape: true,
			want:   "token=token%2Babc%3D%3D&pass=p%40ss%26word%2B1",
		},
		{
			name: "when_no_substitutions_returns_original_string",
			s:    "no substitutions",
			substitutions: map[string]string{
				"foo": "bar",
			},
			escape: false,
			want:   "no substitutions",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := substitute(tc.s, tc.substitutions, tc.escape); got != tc.want {
				t.Errorf("substitute() = %v, want %v", got, tc.want)
			}
		})
	}
}

type staticHTTPClient struct {
	resp *http.Response
}

func (c *staticHTTPClient) Do(*http.Request) (*http.Response, error) {
	return c.resp, nil
}

func TestRequest_Do_FinalURI(t *testing.T) {
	externalServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected request to external server: %s", r.URL.Path)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(externalServer.Close)

	cfg, service := setupMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			http.Redirect(w, r, "/dashboard?ok=1", http.StatusFound)
		case "/dashboard":
			w.Write([]byte("welcome"))
		case "/external_redirect":
			http.Redirect(w, r, externalServer.URL+"/sso", http.StatusFound)
		case "/plain":
			w.Write([]byte("plain"))
		}
	})

	opts := goohttp.DefaultClientOptions()
	if err := opts.LoadAuthorities(service); err != nil {
		t.Fatalf("LoadAuthorities() failed: %v", err)
	}
	defaultClient, err := goohttp.NewClient(cfg, opts)
	if err != nil {
		t.Fatalf("NewClient() failed: %v", err)
	}

	tests := []struct {
		name          string
		path          string
		substitutions map[string]string
		client        goohttp.Client
		wantFinalURI  string
	}{
		{
			name:         "when_redirect_followed_returns_final_uri",
			path:         "/login",
			wantFinalURI: "/dashboard?ok=1",
		},
		{
			name:         "when_redirect_targets_external_host_keeps_in_scope_final_uri",
			path:         "/external_redirect",
			wantFinalURI: "/external_redirect",
		},
		{
			name:         "when_no_redirect_returns_request_uri",
			path:         "/plain",
			wantFinalURI: "/plain",
		},
		{
			name:          "when_response_request_nil_falls_back_to_substituted_request_uri",
			path:          "/login?user=[[username]]",
			substitutions: map[string]string{"username": "admin"},
			client: &staticHTTPClient{
				resp: &http.Response{
					StatusCode: http.StatusOK,
					Body:       http.NoBody,
				},
			},
			wantFinalURI: "/login?user=admin",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := &request{
				Method:          http.MethodGet,
				Path:            tc.path,
				ExtractionRegex: "error: (.*)",
			}
			if err := req.compileAndValidate(); err != nil {
				t.Fatalf("compileAndValidate() failed: %v", err)
			}
			client := tc.client
			if client == nil {
				client = defaultClient
			}
			resp, err := req.do(t.Context(), service, client, tc.substitutions)
			if err != nil {
				t.Fatalf("do() failed: %v", err)
			}
			if resp.FinalURI != tc.wantFinalURI {
				t.Errorf("resp.FinalURI = %q, want %q", resp.FinalURI, tc.wantFinalURI)
			}
		})
	}
}

func TestExtractSetCookies(t *testing.T) {
	hop1 := &http.Response{
		Header: http.Header{
			"Set-Cookie": []string{
				"a=1; Path=/",
				"b=2; Path=/",
			},
		},
		Request: &http.Request{},
	}
	hop2 := &http.Response{
		Request: &http.Request{
			Response: hop1,
		},
	}
	hop3 := &http.Response{
		Header: http.Header{
			"Set-Cookie": []string{
				"c=3; Path=/; HttpOnly",
			},
		},
		Request: &http.Request{
			Response: hop2,
		},
	}

	tests := []struct {
		name string
		resp *http.Response
		want []string
	}{
		{
			name: "when_redirect_chain_has_cookies_collects_chronologically",
			resp: hop3,
			want: []string{
				"a=1; Path=/",
				"b=2; Path=/",
				"c=3; Path=/; HttpOnly",
			},
		},
		{
			name: "when_no_cookies_returns_nil",
			resp: &http.Response{},
		},
		{
			name: "when_response_is_nil_returns_nil",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if diff := cmp.Diff(tc.want, extractSetCookies(tc.resp)); diff != "" {
				t.Errorf("extractSetCookies() diff (-want +got):\n%s", diff)
			}
		})
	}
}
