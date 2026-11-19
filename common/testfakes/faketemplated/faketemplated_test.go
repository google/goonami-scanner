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

package faketemplated

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/google/goonami-scanner/common/templatedengine/environment"
	"github.com/google/goonami-scanner/core/config"

	ttpb "github.com/google/tsunami-security-scanner-plugins/templated/templateddetector/proto/templated_plugin_go_proto"
)

func TestNewHTTPServer(t *testing.T) {
	env := environment.New(config.Default())
	env.Set("EXPECTED_TOKEN", "secret123")

	mockServer := ttpb.MockHttpServer_builder{
		MockResponses: []*ttpb.MockHttpServer_MockResponse{
			ttpb.MockHttpServer_MockResponse_builder{
				Uri:         "api/login?mode=test",
				Status:      http.StatusOK,
				BodyContent: "ok:{{ EXPECTED_TOKEN }}",
				Headers: []*ttpb.MockHttpServer_HttpHeader{
					ttpb.MockHttpServer_HttpHeader_builder{Name: "X-Reply", Value: "{{ EXPECTED_TOKEN }}"}.Build(),
				},
				Condition: ttpb.MockHttpServer_HttpCondition_builder{
					RequestType: ttpb.MockHttpServer_POST,
					Headers: []*ttpb.MockHttpServer_HttpHeader{
						ttpb.MockHttpServer_HttpHeader_builder{Name: "X-Auth", Value: "{{ EXPECTED_TOKEN }}"}.Build(),
					},
					GetParameter: []*ttpb.MockHttpServer_HttpParameter{
						ttpb.MockHttpServer_HttpParameter_builder{Name: "mode", Value: "test"}.Build(),
					},
					BodyContent: []string{"token={{ EXPECTED_TOKEN }}"},
				}.Build(),
			}.Build(),
		},
	}.Build()

	srv := NewHTTPServer(t.Context(), mockServer, env)
	defer srv.Close()

	tests := []struct {
		name       string
		method     string
		path       string
		header     string
		body       string
		wantStatus int
		wantBody   string
	}{
		{
			name:       "when_all_conditions_match_returns_configured_response",
			method:     http.MethodPost,
			path:       "/api/login?mode=test",
			header:     "secret123",
			body:       "token=secret123",
			wantStatus: http.StatusOK,
			wantBody:   "ok:secret123",
		},
		{
			name:       "when_uri_does_not_match_returns_404",
			method:     http.MethodPost,
			path:       "/other",
			header:     "secret123",
			body:       "token=secret123",
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "when_header_condition_fails_returns_404",
			method:     http.MethodPost,
			path:       "/api/login?mode=test",
			header:     "wrong",
			body:       "token=secret123",
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "when_query_parameter_condition_fails_returns_404",
			method:     http.MethodPost,
			path:       "/api/login?mode=prod",
			header:     "secret123",
			body:       "token=secret123",
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "when_method_condition_fails_returns_404",
			method:     http.MethodGet,
			path:       "/api/login?mode=test",
			header:     "secret123",
			body:       "token=secret123",
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "when_body_condition_fails_returns_404",
			method:     http.MethodPost,
			path:       "/api/login?mode=test",
			header:     "secret123",
			body:       "token=wrong",
			wantStatus: http.StatusNotFound,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(t.Context(), tc.method, srv.URL+tc.path, strings.NewReader(tc.body))
			if err != nil {
				t.Fatalf("http.NewRequestWithContext() error = %v", err)
			}
			if tc.header != "" {
				req.Header.Set("X-Auth", tc.header)
			}

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("Do() error = %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tc.wantStatus {
				t.Errorf("StatusCode = %d, want %d", resp.StatusCode, tc.wantStatus)
			}
			if tc.wantBody != "" {
				gotBody, _ := io.ReadAll(resp.Body)
				if string(gotBody) != tc.wantBody {
					t.Errorf("body = %q, want %q", string(gotBody), tc.wantBody)
				}
			}
		})
	}
}

func TestNewHTTPServerMagicURIs(t *testing.T) {
	precedenceResponses := []*ttpb.MockHttpServer_MockResponse{
		ttpb.MockHttpServer_MockResponse_builder{
			Uri: environment.VarTestingMagicEchoServer,
		}.Build(),
		ttpb.MockHttpServer_MockResponse_builder{
			Uri:         environment.VarTestingMagicAnyURI,
			Status:      http.StatusOK,
			BodyContent: "from-any",
			Condition: ttpb.MockHttpServer_HttpCondition_builder{
				Headers: []*ttpb.MockHttpServer_HttpHeader{
					ttpb.MockHttpServer_HttpHeader_builder{Name: "X-Fallback", Value: "any"}.Build(),
				},
			}.Build(),
		}.Build(),
		ttpb.MockHttpServer_MockResponse_builder{
			Uri:         "exact",
			Status:      http.StatusAccepted,
			BodyContent: "from-exact",
		}.Build(),
	}

	conditionalEchoResponses := []*ttpb.MockHttpServer_MockResponse{
		ttpb.MockHttpServer_MockResponse_builder{
			Uri:    environment.VarTestingMagicEchoServer,
			Status: http.StatusCreated,
			Headers: []*ttpb.MockHttpServer_HttpHeader{
				ttpb.MockHttpServer_HttpHeader_builder{Name: "X-Echo-Mode", Value: "{{ EXPECTED_TOKEN }}"}.Build(),
			},
			Condition: ttpb.MockHttpServer_HttpCondition_builder{
				BodyContent: []string{"must-match"},
			}.Build(),
		}.Build(),
	}

	tests := []struct {
		name               string
		mockResponses      []*ttpb.MockHttpServer_MockResponse
		method             string
		path               string
		reqHeaders         map[string]string
		reqBody            string
		wantStatus         int
		wantRespHeaders    map[string]string
		wantBodySubstrings []string
	}{
		{
			name: "when_echo_server_status_unset_defaults_to_200_and_echoes_request_line_headers_and_body",
			mockResponses: []*ttpb.MockHttpServer_MockResponse{
				ttpb.MockHttpServer_MockResponse_builder{
					Uri: environment.VarTestingMagicEchoServer,
				}.Build(),
			},
			method:     http.MethodPost,
			path:       "/cgi-bin/status?probe=1",
			reqHeaders: map[string]string{"X-Payload": "() { :; }; echo 123"},
			reqBody:    "raw-body-payload",
			wantStatus: http.StatusOK,
			wantBodySubstrings: []string{
				"POST /cgi-bin/status?probe=1 HTTP/1.1\n",
				"X-Payload: () { :; }; echo 123\n",
				"\n\nraw-body-payload",
			},
		},
		{
			name:               "when_echo_server_has_custom_status_headers_and_body_condition_echoes_matching_request",
			mockResponses:      conditionalEchoResponses,
			method:             http.MethodPost,
			path:               "/echo",
			reqBody:            "payload:must-match",
			wantStatus:         http.StatusCreated,
			wantRespHeaders:    map[string]string{"X-Echo-Mode": "secret123"},
			wantBodySubstrings: []string{"POST /echo HTTP/1.1\n", "\n\npayload:must-match"},
		},
		{
			name:          "when_echo_server_condition_fails_returns_404",
			mockResponses: conditionalEchoResponses,
			method:        http.MethodPost,
			path:          "/echo",
			reqBody:       "other-body",
			wantStatus:    http.StatusNotFound,
		},
		{
			name:               "when_specific_uri_and_magic_uris_configured_prefers_specific_uri",
			mockResponses:      precedenceResponses,
			method:             http.MethodGet,
			path:               "/exact",
			reqHeaders:         map[string]string{"X-Fallback": "any"},
			wantStatus:         http.StatusAccepted,
			wantBodySubstrings: []string{"from-exact"},
		},
		{
			name:               "when_any_uri_and_echo_server_configured_prefers_any_uri_when_conditions_match",
			mockResponses:      precedenceResponses,
			method:             http.MethodGet,
			path:               "/unmatched",
			reqHeaders:         map[string]string{"X-Fallback": "any"},
			wantStatus:         http.StatusOK,
			wantBodySubstrings: []string{"from-any"},
		},
		{
			name:               "when_any_uri_condition_fails_falls_back_to_echo_server",
			mockResponses:      precedenceResponses,
			method:             http.MethodGet,
			path:               "/unmatched",
			wantStatus:         http.StatusOK,
			wantBodySubstrings: []string{"GET /unmatched HTTP/1.1\n"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			env := environment.New(config.Default())
			env.Set("EXPECTED_TOKEN", "secret123")

			mockServer := ttpb.MockHttpServer_builder{
				MockResponses: tc.mockResponses,
			}.Build()
			srv := NewHTTPServer(ctx, mockServer, env)
			defer srv.Close()

			req, err := http.NewRequestWithContext(ctx, tc.method, srv.URL+tc.path, strings.NewReader(tc.reqBody))
			if err != nil {
				t.Fatalf("http.NewRequestWithContext(%q, %q) error = %v", tc.method, tc.path, err)
			}
			for k, v := range tc.reqHeaders {
				req.Header.Set(k, v)
			}

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("Do(%q %q) error = %v", tc.method, tc.path, err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tc.wantStatus {
				t.Errorf("NewHTTPServer(%s %s) status = %d, want %d", tc.method, tc.path, resp.StatusCode, tc.wantStatus)
			}
			for k, want := range tc.wantRespHeaders {
				if got := resp.Header.Get(k); got != want {
					t.Errorf("NewHTTPServer(%s %s) header %q = %q, want %q", tc.method, tc.path, k, got, want)
				}
			}
			if len(tc.wantBodySubstrings) > 0 {
				gotBytes, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatalf("io.ReadAll(resp.Body) error = %v", err)
				}
				gotBody := string(gotBytes)
				for _, sub := range tc.wantBodySubstrings {
					if !strings.Contains(gotBody, sub) {
						t.Errorf("NewHTTPServer(%s %s) body = %q, want substring %q", tc.method, tc.path, gotBody, sub)
					}
				}
			}
		})
	}
}

func TestLoadPluginsAndTests(t *testing.T) {
	tests := []struct {
		name        string
		fsys        fstest.MapFS
		wantPlugins int
		wantTests   int
		wantErr     bool
	}{
		{
			name: "when_valid_files_present_loads_plugins_and_tests",
			fsys: fstest.MapFS{
				"plugin.textproto":      &fstest.MapFile{Data: []byte(`info { name: "TestPlugin" }`)},
				"plugin_test.textproto": &fstest.MapFile{Data: []byte(`config { tested_plugin: "TestPlugin" }`)},
				"readme.txt":            &fstest.MapFile{Data: []byte(`ignored`)},
			},
			wantPlugins: 1,
			wantTests:   1,
		},
		{
			name: "when_invalid_plugin_proto_returns_error",
			fsys: fstest.MapFS{
				"bad.textproto": &fstest.MapFile{Data: []byte(`invalid proto`)},
			},
			wantErr: true,
		},
		{
			name: "when_invalid_test_proto_returns_error",
			fsys: fstest.MapFS{
				"bad_test.textproto": &fstest.MapFile{Data: []byte(`invalid test proto`)},
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			plugins, pluginTests, err := LoadPluginsAndTests(tc.fsys)
			if (err != nil) != tc.wantErr {
				t.Fatalf("LoadPluginsAndTests() error = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}
			if len(plugins) != tc.wantPlugins {
				t.Errorf("len(plugins) = %d, want %d", len(plugins), tc.wantPlugins)
			}
			if len(pluginTests) != tc.wantTests {
				t.Errorf("len(pluginTests) = %d, want %d", len(pluginTests), tc.wantTests)
			}
		})
	}
}

func TestServiceForServer(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()

	tests := []struct {
		name    string
		server  *httptest.Server
		wantErr bool
	}{
		{
			name:   "when_valid_server_url_returns_network_service",
			server: srv,
		},
		{
			name:    "when_invalid_server_url_returns_error",
			server:  &httptest.Server{URL: "http://invalid-no-port"},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc, err := ServiceForServer(tc.server)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ServiceForServer() error = %v, wantErr %v", err, tc.wantErr)
			}
			if !tc.wantErr && svc.GetNetworkEndpoint().GetPort().GetPortNumber() == 0 {
				t.Errorf("ServiceForServer() returned port 0, want non-zero")
			}
		})
	}
}
