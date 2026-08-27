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

package httpclient

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/goonami-scanner/core/config"
	goohttp "github.com/google/goonami-scanner/core/net/http"
	_ "github.com/google/goonami-scanner/core/net/http/simpleclient"
	"google.golang.org/protobuf/proto"

	llmcpb "github.com/google/goonami-scanner/common/clients/llm/llm_client_config_go_proto"
	cpb "github.com/google/goonami-scanner/core/config/config_go_proto"
	npb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg == nil {
		t.Fatal("DefaultConfig() returned nil")
	}
	if len(cfg.GetAllowedMethods()) == 0 {
		t.Errorf("DefaultConfig().GetAllowedMethods() is empty, want non-empty")
	}
	if cfg.GetMaxRequestsPerService() == 0 {
		t.Errorf("DefaultConfig().GetMaxRequestsPerService() is 0, want non-zero")
	}
	if cfg.GetMaxAnswerSizeBytes() == 0 {
		t.Errorf("DefaultConfig().GetMaxAnswerSizeBytes() is 0, want non-zero")
	}
	if len(cfg.GetForbiddenPaths()) == 0 {
		t.Errorf("DefaultConfig().GetForbiddenPaths() is empty, want non-empty")
	}
}

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		config  *config.Config
		wantErr error
		verify  func(t *testing.T, got *Tool)
	}{
		{
			name: "when_has_client_config_returns_tool_with_merged_config",
			config: config.FromProto(cpb.Config_builder{
				Clients: cpb.ClientsConfig_builder{
					Llm: llmcpb.LlmClientConfig_builder{
						Tools: llmcpb.ToolConfig_builder{
							HttpClientConfig: llmcpb.HttpClientConfig_builder{
								MaxRequestsPerService: proto.Int32(100),
							}.Build(),
						}.Build(),
					}.Build(),
				}.Build(),
			}.Build()),
			wantErr: nil,
			verify: func(t *testing.T, got *Tool) {
				if got.config.GetMaxRequestsPerService() != 100 {
					t.Errorf("MaxRequestsPerService = %d, want 100", got.config.GetMaxRequestsPerService())
				}
				if diff := cmp.Diff([]string{"GET", "POST"}, got.config.GetAllowedMethods()); diff != "" {
					t.Errorf("AllowedMethods mismatch (-want +got):\n%s", diff)
				}
			},
		},
		{
			name:    "when_no_client_config_returns_tool_with_default_config",
			config:  config.FromProto(cpb.Config_builder{}.Build()),
			wantErr: nil,
			verify: func(t *testing.T, got *Tool) {
				if got.config.GetMaxRequestsPerService() != 50 {
					t.Errorf("MaxRequestsPerService = %d, want 50", got.config.GetMaxRequestsPerService())
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tl, err := New(tc.config, &nspb.NetworkService{})
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("New() error = %v, want %v", err, tc.wantErr)
			}
			if tc.wantErr != nil {
				return
			}
			if tl == nil {
				t.Fatal("New() returned nil tool")
			}

			got, err := newTool(tc.config, &nspb.NetworkService{})
			if err != nil {
				t.Fatalf("newTool() unexpected error: %v", err)
			}
			if tc.verify != nil {
				tc.verify(t, got)
			}
		})
	}
}

func makeService(t *testing.T, svrURL string) *nspb.NetworkService {
	t.Helper()
	u, err := url.Parse(svrURL)
	if err != nil {
		t.Fatalf("failed to parse test server URL: %v", err)
	}
	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatalf("failed to split host port: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("failed to parse port: %v", err)
	}
	return nspb.NetworkService_builder{
		NetworkEndpoint: npb.NetworkEndpoint_builder{
			IpAddress: npb.IpAddress_builder{Address: host}.Build(),
			Port:      npb.Port_builder{PortNumber: uint32(port)}.Build(),
		}.Build(),
	}.Build()
}

func TestDo(t *testing.T) {
	tests := []struct {
		name       string
		req        *Request
		handler    http.HandlerFunc
		cfg        *llmcpb.HttpClientConfig
		presetReqs int // to preset request count for testing limits
		want       *Response
		wantErr    error
	}{
		{
			name: "when_simple_get_returns_response",
			req: &Request{
				Method: "GET",
				URI:    "/",
			},
			handler: func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, "ok")
			},
			cfg: DefaultConfig(),
			want: &Response{
				StatusCode: 200,
				Content:    "ok",
			},
		},
		{
			name: "when_post_with_data_and_headers_returns_response",
			req: &Request{
				Method:  "POST",
				URI:     "/post",
				Headers: map[string]string{"Content-Type": "text/plain"},
				Data:    "data",
			},
			handler: func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "POST" {
					http.Error(w, "wrong method", http.StatusBadRequest)
					return
				}
				if r.Header.Get("Content-Type") != "text/plain" {
					http.Error(w, "wrong header", http.StatusBadRequest)
					return
				}
				body, err := io.ReadAll(r.Body)
				if err != nil {
					http.Error(w, "cannot read body", http.StatusInternalServerError)
					return
				}
				fmt.Fprintf(w, "received:%s", string(body))
			},
			cfg: DefaultConfig(),
			want: &Response{
				StatusCode: 200,
				Content:    "received:data",
			},
		},
		{
			name: "when_empty_header_is_ignored",
			req: &Request{
				Method: "GET",
				URI:    "/",
				Headers: map[string]string{
					"": "value",
				},
			},
			handler: func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, "ok")
			},
			cfg: DefaultConfig(),
			want: &Response{
				StatusCode: 200,
				Content:    "ok",
			},
		},
		{
			name: "when_uri_has_protocol_returns_error",
			req: &Request{
				Method: "GET",
				URI:    "http://example.com/",
			},
			handler: func(w http.ResponseWriter, r *http.Request) {},
			cfg:     DefaultConfig(),
			wantErr: ErrInvalidURI,
		},
		{
			name: "when_uri_has_colon_returns_error",
			req: &Request{
				Method: "GET",
				URI:    "/foo:bar",
			},
			handler: func(w http.ResponseWriter, r *http.Request) {},
			cfg:     DefaultConfig(),
			wantErr: ErrInvalidURI,
		},
		{
			name: "when_uri_is_not_absolute_returns_error",
			req: &Request{
				Method: "GET",
				URI:    "index.html",
			},
			handler: func(w http.ResponseWriter, r *http.Request) {},
			cfg:     DefaultConfig(),
			wantErr: ErrInvalidURI,
		},
		{
			name: "when_method_is_invalid_returns_error",
			req: &Request{
				Method: "PUT",
				URI:    "/",
			},
			handler: func(w http.ResponseWriter, r *http.Request) {},
			cfg:     DefaultConfig(),
			wantErr: ErrInvalidMethod,
		},
		{
			name: "when_path_is_forbidden_returns_error",
			req: &Request{
				Method: "GET",
				URI:    "/quit",
			},
			handler: func(w http.ResponseWriter, r *http.Request) {},
			cfg:     DefaultConfig(),
			wantErr: ErrContentDenied,
		},
		{
			name: "when_too_many_requests_returns_error",
			req: &Request{
				Method: "GET",
				URI:    "/",
			},
			handler: func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, "ok")
			},
			cfg: llmcpb.HttpClientConfig_builder{
				AllowedMethods:        []string{"GET"},
				MaxRequestsPerService: proto.Int32(1),
				ForbiddenPaths:        []string{},
			}.Build(),
			presetReqs: 1,
			wantErr:    ErrTooManyRequests,
		},
		{
			name: "when_response_is_too_large_returns_error",
			req: &Request{
				Method: "GET",
				URI:    "/",
			},
			handler: func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, "1234567890a")
			},
			cfg: llmcpb.HttpClientConfig_builder{
				AllowedMethods:        []string{"GET"},
				MaxRequestsPerService: proto.Int32(1),
				MaxAnswerSizeBytes:    proto.Int32(10),
				ForbiddenPaths:        []string{},
			}.Build(),
			wantErr: goohttp.ErrPageTooBig,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svr := httptest.NewServer(tc.handler)
			defer svr.Close()

			service := makeService(t, svr.URL)
			coreConfig := config.FromProto(cpb.Config_builder{
				Globalcfg: cpb.GlobalConfig_builder{
					Performance: cpb.GlobalConfig_Performance_builder{
						TimeoutPerRequestSeconds: proto.Int32(10),
						MaxConcurrency:           proto.Int32(1),
					}.Build(),
				}.Build(),
				Clients: cpb.ClientsConfig_builder{
					Llm: llmcpb.LlmClientConfig_builder{
						Tools: llmcpb.ToolConfig_builder{
							HttpClientConfig: tc.cfg,
						}.Build(),
					}.Build(),
				}.Build(),
			}.Build())

			tool, err := newTool(coreConfig, service)
			if err != nil {
				t.Fatalf("newTool() unexpected error: %v", err)
			}
			tool.countRequests = tc.presetReqs

			got, err := tool.Do(nil, tc.req)

			if !errors.Is(err, tc.wantErr) {
				t.Errorf("Do() error = %v, want %v", err, tc.wantErr)
			}

			if tc.wantErr != nil {
				return
			}

			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("Do() response mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestTool_Do_MaintainSession(t *testing.T) {
	cfg := config.FromProto(cpb.Config_builder{
		Globalcfg: cpb.GlobalConfig_builder{
			Performance: cpb.GlobalConfig_Performance_builder{
				MaxHttpRequestsPerSecond: proto.Int32(10),
			}.Build(),
		}.Build(),
	}.Build())

	// The default client options are handled by newTool

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "123"})
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("cookie set"))
			return
		}
		if r.URL.Path == "/verify" {
			cookie, err := r.Cookie("session")
			if err != nil || cookie.Value != "123" {
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte("missing cookie"))
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("success"))
			return
		}
	}))
	defer ts.Close()

	service := makeService(t, ts.URL)
	toolInstance, err := newTool(cfg, service)
	if err != nil {
		t.Fatalf("newTool() unexpected error: %v", err)
	}

	// Test 1: MaintainSession = false
	// Request 1: Get the cookie
	req1 := &Request{Method: "GET", URI: "/login", MaintainSession: false}
	resp1, err := toolInstance.Do(nil, req1)
	if err != nil || resp1.StatusCode != 200 {
		t.Fatalf("Stateless request 1 failed: %v", err)
	}

	// Request 2: Verify cookie (should fail because it's stateless)
	req2 := &Request{Method: "GET", URI: "/verify", MaintainSession: false}
	resp2, err := toolInstance.Do(nil, req2)
	if err != nil {
		t.Fatalf("Stateless request 2 failed: %v", err)
	}
	if resp2.StatusCode != 403 {
		t.Fatalf("Stateless request 2 should have failed with 403, got: %v", resp2.StatusCode)
	}

	// Test 2: MaintainSession = true
	// Request 3: Get the cookie with session tracking
	req3 := &Request{Method: "GET", URI: "/login", MaintainSession: true}
	resp3, err := toolInstance.Do(nil, req3)
	if err != nil || resp3.StatusCode != 200 {
		t.Fatalf("Stateful request 1 failed: %v", err)
	}

	// Request 4: Verify cookie (should succeed because it's stateful)
	req4 := &Request{Method: "GET", URI: "/verify", MaintainSession: true}
	resp4, err := toolInstance.Do(nil, req4)
	if err != nil {
		t.Fatalf("Stateful request 2 failed: %v", err)
	}
	if resp4.StatusCode != 200 {
		t.Fatalf("Stateful request 2 should have succeeded with 200, got: %v", resp4.StatusCode)
	}
}

func TestTool_Do_ClearSession(t *testing.T) {
	cfg := config.FromProto(cpb.Config_builder{
		Globalcfg: cpb.GlobalConfig_builder{
			Performance: cpb.GlobalConfig_Performance_builder{
				MaxHttpRequestsPerSecond: proto.Int32(10),
			}.Build(),
		}.Build(),
	}.Build())

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/set" {
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "123"})
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("cookie set"))
			return
		}
		if r.URL.Path == "/verify" {
			cookie, err := r.Cookie("session")
			if err != nil || cookie.Value != "123" {
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte("missing cookie"))
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("success"))
			return
		}
	}))
	defer ts.Close()

	service := makeService(t, ts.URL)
	toolInstance, err := newTool(cfg, service)
	if err != nil {
		t.Fatalf("newTool() unexpected error: %v", err)
	}

	// 1. Set the cookie
	req1 := &Request{Method: "GET", URI: "/set", MaintainSession: true}
	resp1, err := toolInstance.Do(nil, req1)
	if err != nil || resp1.StatusCode != 200 {
		t.Fatalf("Failed to set cookie: %v", err)
	}

	// 2. Verify cookie exists
	req2 := &Request{Method: "GET", URI: "/verify", MaintainSession: true}
	resp2, err := toolInstance.Do(nil, req2)
	if err != nil || resp2.StatusCode != 200 {
		t.Fatalf("Failed to verify cookie: %v", err)
	}

	// 3. Clear session and verify cookie is gone
	req3 := &Request{Method: "GET", URI: "/verify", MaintainSession: true, ClearSession: true}
	resp3, err := toolInstance.Do(nil, req3)
	if err != nil {
		t.Fatalf("Request with ClearSession failed: %v", err)
	}
	if resp3.StatusCode != 403 {
		t.Fatalf("ClearSession failed to wipe cookies, got status: %v", resp3.StatusCode)
	}
}

func TestTool_Do_RedirectOutOfScope(t *testing.T) {
	externalVisited := false
	externalServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		externalVisited = true
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("external content"))
	}))
	defer externalServer.Close()

	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redirect_in_scope":
			http.Redirect(w, r, "/destination", http.StatusFound)
		case "/redirect_out_of_scope":
			http.Redirect(w, r, externalServer.URL+"/external", http.StatusFound)
		case "/destination":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("in-scope destination"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer targetServer.Close()

	cfg := config.FromProto(cpb.Config_builder{
		Globalcfg: cpb.GlobalConfig_builder{
			Performance: cpb.GlobalConfig_Performance_builder{
				MaxHttpRequestsPerSecond: proto.Int32(10),
			}.Build(),
		}.Build(),
	}.Build())

	service := makeService(t, targetServer.URL)
	toolInstance, err := newTool(cfg, service)
	if err != nil {
		t.Fatalf("newTool() unexpected error: %v", err)
	}

	tests := []struct {
		name                string
		req                 *Request
		wantStatus          int32
		wantContent         string
		wantExternalVisited bool
	}{
		{
			name: "when_redirect_in_scope_follows_redirect",
			req: &Request{
				Method: "GET",
				URI:    "/redirect_in_scope",
			},
			wantStatus:          http.StatusOK,
			wantContent:         "in-scope destination",
			wantExternalVisited: false,
		},
		{
			name: "when_redirect_out_of_scope_stops_and_returns_redirect_response",
			req: &Request{
				Method: "GET",
				URI:    "/redirect_out_of_scope",
			},
			wantStatus:          http.StatusFound,
			wantContent:         "",
			wantExternalVisited: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			externalVisited = false

			resp, err := toolInstance.Do(nil, tt.req)
			if err != nil {
				t.Fatalf("Do(%v) unexpected error: %v", tt.req.URI, err)
			}

			if resp.StatusCode != tt.wantStatus {
				t.Errorf("Do() status = %d, want %d", resp.StatusCode, tt.wantStatus)
			}

			if tt.wantContent != "" && resp.Content != tt.wantContent {
				t.Errorf("Do() content = %q, want %q", resp.Content, tt.wantContent)
			}

			if externalVisited != tt.wantExternalVisited {
				t.Errorf("externalVisited = %v, want %v", externalVisited, tt.wantExternalVisited)
			}
		})
	}
}
