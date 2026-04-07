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
	"regexp"
	"strconv"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/goonami-scanner/core/config"
	goohttp "github.com/google/goonami-scanner/core/net/http"
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
				Clients: map[string]*cpb.ClientsConfig{
					"all": cpb.ClientsConfig_builder{
						Llm: llmcpb.LlmClientConfig_builder{
							Tools: llmcpb.ToolConfig_builder{
								HttpClientConfig: llmcpb.HttpClientConfig_builder{
									MaxRequestsPerService: proto.Int32(100),
								}.Build(),
							}.Build(),
						}.Build(),
					}.Build(),
				},
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

			got := newTool(tc.config, &nspb.NetworkService{})
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

func buildTool(t *testing.T, cfg *llmcpb.HttpClientConfig, coreConfig *config.Config, service *nspb.NetworkService) *Tool {
	t.Helper()
	var badPaths []*regexp.Regexp
	for _, path := range cfg.GetForbiddenPaths() {
		badPaths = append(badPaths, regexp.MustCompile(path))
	}
	return &Tool{
		config:     cfg,
		coreConfig: coreConfig,
		service:    service,
		badPaths:   badPaths,
	}
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
			}.Build())

			if err := goohttp.InitializeDefaults(coreConfig); err != nil {
				t.Fatalf("failed to initialize default HTTP client: %v", err)
			}

			tool := buildTool(t, tc.cfg, coreConfig, service)
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
