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
