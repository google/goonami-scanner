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
	"encoding/json"
	"errors"
	"io"
	"iter"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/google/goonami-scanner/common/testfakes/fakellmagent"
	"github.com/google/goonami-scanner/core/config"
	_ "github.com/google/goonami-scanner/core/net/http/simpleclient"
	"github.com/google/goonami-scanner/plugins/detectors/adkweakcreds/cache"
	"google.golang.org/adk/v2/agent"
	"google.golang.org/adk/v2/session"
	"google.golang.org/protobuf/proto"

	lccpb "github.com/google/goonami-scanner/common/clients/llm/llm_client_config_go_proto"
	cpb "github.com/google/goonami-scanner/core/config/config_go_proto"
	dpb "github.com/google/tsunami-security-scanner/proto/go/detection_go_proto"
	npb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
)

type mockServerHTTP struct{}

func (m *mockServerHTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/csrf":
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><input name="csrf" value="token123"></html>`))
	case "/login":
		b, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		body := string(b)
		query := r.URL.Query()

		user := query.Get("user")
		pass := query.Get("pass")
		csrf := query.Get("csrf")

		if strings.Contains(body, "user=admin") {
			user = "admin"
		} else if strings.Contains(body, "user=root") {
			user = "root"
		}

		if strings.Contains(body, "pass=password") {
			pass = "password"
		} else if strings.Contains(body, "pass=toor") {
			pass = "toor"
		}

		if strings.Contains(body, "csrf=token123") {
			csrf = "token123"
		}

		validCreds := (user == "admin" && pass == "password") || (user == "root" && pass == "toor")
		csrfRequired := strings.Contains(body, "csrf=") || query.Has("csrf")
		csrfValid := !csrfRequired || csrf == "token123"

		if validCreds && csrfValid {
			w.Write([]byte("success"))
		} else {
			w.Write([]byte("error"))
		}
	case "/login_broken_auth":
		b, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		body := string(b)
		query := r.URL.Query()

		user := query.Get("user")
		if strings.Contains(body, "user=admin") {
			user = "admin"
		}

		// Broken auth: If the user is admin, any password works.
		// If the user is not admin (e.g. invalidUsername from verifyStrategy), it fails.
		if user != "admin" {
			w.Write([]byte("error"))
			return
		}
		w.Write([]byte("success"))
	case "/login_always_success":
		w.Write([]byte("success"))
	case "/rate_limited":
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte("rate limited"))
	case "/fail":
		w.WriteHeader(http.StatusInternalServerError)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func TestDetect(t *testing.T) {
	ts := httptest.NewServer(&mockServerHTTP{})
	defer ts.Close()

	host, portStr, _ := net.SplitHostPort(ts.Listener.Addr().String())
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("Failed to parse port number: %v", err)
	}

	service := nspb.NetworkService_builder{
		ServiceName:          "http",
		SupportedHttpMethods: []string{"GET", "POST"},
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

	errBuilder := errors.New("builder error")

	tests := []struct {
		name                          string
		testdataFile                  string
		wantErr                       error
		wantFindings                  bool
		expectedValidCredentialsCount int
		customService                 *nspb.NetworkService
	}{
		{
			name:         "when_no_auth_returns_no_findings",
			testdataFile: "no_auth.json",
			wantErr:      nil,
			wantFindings: false,
		},
		{
			name:         "when_valid_credentials_returns_findings",
			testdataFile: "valid_creds.json",
			wantErr:      nil,
			wantFindings: true,
		},
		{
			name:         "when_valid_credentials_with_csrf_returns_findings",
			testdataFile: "valid_creds_csrf.json",
			wantErr:      nil,
			wantFindings: true,
		},
		{
			name:         "when_valid_credentials_get_method_returns_findings",
			testdataFile: "valid_creds_get.json",
			wantErr:      nil,
			wantFindings: true,
		},
		{
			name:         "when_invalid_credentials_returns_no_findings",
			testdataFile: "invalid_creds.json",
			wantErr:      nil,
			wantFindings: false,
		},
		{
			name:         "when_regexp_too_weak_returns_no_findings",
			testdataFile: "weak_regexp.json",
			wantErr:      nil,
			wantFindings: false,
		},
		{
			name:         "when_empty_header_name_is_ignored",
			testdataFile: "empty_header_name.json",
			wantErr:      nil,
			wantFindings: true,
		},
		{
			name: "when_non_web_service_returns_no_findings",
			customService: nspb.NetworkService_builder{
				ServiceName: "ssh",
				NetworkEndpoint: npb.NetworkEndpoint_builder{
					Type: npb.NetworkEndpoint_IP_PORT,
					IpAddress: npb.IpAddress_builder{
						Address: "1.2.3.4",
					}.Build(),
					Port: npb.Port_builder{
						PortNumber: 22,
					}.Build(),
				}.Build(),
			}.Build(),
			wantErr:      nil,
			wantFindings: false,
		},
		{
			name:         "when_csrf_request_fails_returns_no_findings",
			testdataFile: "csrf_fail.json",
			wantErr:      nil,
			wantFindings: false,
		},
		{
			name: "when_build_web_root_fails_returns_no_findings",
			customService: nspb.NetworkService_builder{
				ServiceName: "http",
				NetworkEndpoint: npb.NetworkEndpoint_builder{
					Type: npb.NetworkEndpoint_IP_PORT,
					// IP address is missing, which should trigger a failure in BuildWebRoot
				}.Build(),
			}.Build(),
			testdataFile: "valid_creds.json",
			wantErr:      nil,
			wantFindings: false,
		},
		{
			name:         "when_login_request_fails_returns_no_findings",
			testdataFile: "login_fail.json",
			wantErr:      nil,
			wantFindings: false,
		},
		{
			name:         "when_rate_limited_returns_no_findings",
			testdataFile: "login_rate_limited.json",
			wantErr:      nil,
			wantFindings: false,
		},
		{
			name:         "when_strategy_quality_negative_validation_fails_returns_no_findings",
			testdataFile: "negative_validation_fail.json",
			wantErr:      nil,
			wantFindings: false,
		},
		{
			name:         "when_bruteforce_negative_validation_fails_returns_no_findings",
			testdataFile: "bruteforce_negative_validation_fail.json",
			wantErr:      nil,
			wantFindings: false,
		},
		{
			name:                          "when_exhaustive_credentials_returns_multiple_findings",
			testdataFile:                  "exhaustive_creds.json",
			wantErr:                       nil,
			wantFindings:                  true,
			expectedValidCredentialsCount: 2,
		},
		{
			name:    "when_builder_fails_returns_error",
			wantErr: errBuilder,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			cfg := config.FromProto(cpb.Config_builder{
				Globalcfg: cpb.GlobalConfig_builder{
					Performance: cpb.GlobalConfig_Performance_builder{
						HttpRetryInitialBackoffSeconds: proto.Int32(0),
					}.Build(),
				}.Build(),
				Clients: cpb.ClientsConfig_builder{
					Llm: lccpb.LlmClientConfig_builder{
						MaxAttempts: proto.Int32(1),
					}.Build(),
				}.Build(),
			}.Build())

			var agentResponse string
			if tc.testdataFile != "" {
				content, err := os.ReadFile(filepath.Join("testdata", tc.testdataFile))
				if err != nil {
					t.Fatalf("Failed to read testdata file %s: %v", tc.testdataFile, err)
				}
				agentResponse = string(content)
			}

			m, _ := New(ctx, cfg)
			module := m.(*Module)
			module.agentBuilder = func(ctx context.Context, config *config.Config, service *nspb.NetworkService) (agent.Agent, error) {
				if errors.Is(tc.wantErr, errBuilder) {
					return nil, errBuilder
				}
				return fakellmagent.NewWithSimpleAnswer(agentResponse), nil
			}

			svc := service
			if tc.customService != nil {
				svc = tc.customService
			}

			reports, err := module.Detect(ctx, svc)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Detect() error = %v, want %v", err, tc.wantErr)
			}

			if tc.wantFindings {
				if reports == nil || len(reports.GetDetectionReports()) == 0 {
					t.Errorf("Detect() returned no reports, want some")
				}

				if tc.expectedValidCredentialsCount > 0 {
					extraDetails := reports.GetDetectionReports()[0].GetVulnerability().GetAdditionalDetails()[0].GetTextData().GetText()
					var parsed struct {
						ValidCredentials []*credential `json:"valid_credentials"`
					}
					if err := json.Unmarshal([]byte(extraDetails), &parsed); err != nil {
						t.Fatalf("Failed to parse extraDetails: %v", err)
					}
					if len(parsed.ValidCredentials) != tc.expectedValidCredentialsCount {
						t.Errorf("Detect() returned %d valid credentials, want %d", len(parsed.ValidCredentials), tc.expectedValidCredentialsCount)
					}
				}

				return
			}

			if reports != nil && len(reports.GetDetectionReports()) > 0 {
				t.Errorf("Detect() returned reports, want none")
			}
		})
	}
}

func TestDetect_AgentError(t *testing.T) {
	ctx := t.Context()
	cfg := config.FromProto(cpb.Config_builder{
		Clients: cpb.ClientsConfig_builder{
			Llm: lccpb.LlmClientConfig_builder{
				MaxAttempts: proto.Int32(1),
			}.Build(),
		}.Build(),
	}.Build())
	service := nspb.NetworkService_builder{
		NetworkEndpoint: npb.NetworkEndpoint_builder{
			Type: npb.NetworkEndpoint_IP_PORT,
			IpAddress: npb.IpAddress_builder{
				Address: "127.0.0.1",
			}.Build(),
			Port: npb.Port_builder{
				PortNumber: 80,
			}.Build(),
		}.Build(),
		ServiceName:          "http",
		SupportedHttpMethods: []string{"GET", "POST"},
	}.Build()

	m, _ := New(ctx, cfg)
	module := m.(*Module)
	module.agentBuilder = func(ctx context.Context, config *config.Config, service *nspb.NetworkService) (agent.Agent, error) {
		return fakellmagent.NewWithError(errors.New("agent error")), nil
	}

	reports, err := module.Detect(ctx, service)
	if !errors.Is(err, nil) {
		t.Errorf("Detect() returned error %v, want nil (as per implementation which swallows agent errors)", err)
	}
	if reports != nil && len(reports.GetDetectionReports()) > 0 {
		t.Errorf("Detect() returned reports, want none")
	}
}

func TestDetect_CacheHit(t *testing.T) {
	ts := httptest.NewServer(&mockServerHTTP{})
	defer ts.Close()

	host, portStr, _ := net.SplitHostPort(ts.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	service := nspb.NetworkService_builder{
		ServiceName:          "http",
		SupportedHttpMethods: []string{"GET", "POST"},
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

	workDir := t.TempDir()

	cfg := config.FromProto(cpb.Config_builder{
		Clients: cpb.ClientsConfig_builder{
			Llm: lccpb.LlmClientConfig_builder{
				MaxAttempts: proto.Int32(1),
			}.Build(),
		}.Build(),
	}.Build())
	if err := cfg.CreateDirectories(workDir); err != nil {
		t.Fatalf("CreateDirectories() failed: %v", err)
	}

	cacheDir, err := cfg.GetCacheForModule(moduleName)
	if err != nil {
		t.Fatalf("GetCacheForModule() failed: %v", err)
	}

	strategyJSON := `{
  "supports_authentication": true,
  "authentication_details": {
    "login_request": {
      "method": "POST",
      "path": "/login",
      "body": "user=[[username]]&pass=[[password]]",
      "extraction_regex": "(error)",
      "headers": [
        {
          "name": "Content-Type",
          "value": "application/x-www-form-urlencoded"
        }
      ]
    },
    "credentials_to_test": [
      {
        "username": "admin",
        "password": "password"
      }
    ]
  }
}`

	idx := cache.Load(t.Context(), cacheDir)
	if err := idx.Add(t.Context(), cfg, service, "/login", []byte(strategyJSON)); err != nil {
		t.Fatalf("failed to populate cache: %v", err)
	}

	m, _ := New(t.Context(), cfg)
	module := m.(*Module)
	module.agentBuilder = func(ctx context.Context, config *config.Config, service *nspb.NetworkService) (agent.Agent, error) {
		t.Fatal("agent builder should not be called when cache hits")
		return nil, errors.New("should not be called")
	}

	reports, err := module.Detect(t.Context(), service)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}

	if reports == nil || len(reports.GetDetectionReports()) == 0 {
		t.Error("Detect() returned no reports, expected cache-based finding")
	}
}

func TestDetect_CacheMiss_ThenWritesBack(t *testing.T) {
	ts := httptest.NewServer(&mockServerHTTP{})
	defer ts.Close()

	host, portStr, _ := net.SplitHostPort(ts.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	service := nspb.NetworkService_builder{
		ServiceName:          "http",
		SupportedHttpMethods: []string{"GET", "POST"},
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

	workDir := t.TempDir()

	cfg := config.FromProto(cpb.Config_builder{
		Clients: cpb.ClientsConfig_builder{
			Llm: lccpb.LlmClientConfig_builder{
				MaxAttempts: proto.Int32(1),
			}.Build(),
		}.Build(),
	}.Build())
	if err := cfg.CreateDirectories(workDir); err != nil {
		t.Fatalf("CreateDirectories() failed: %v", err)
	}

	cacheDir, err := cfg.GetCacheForModule(moduleName)
	if err != nil {
		t.Fatalf("GetCacheForModule() failed: %v", err)
	}

	strategyJSON, err := os.ReadFile(filepath.Join("testdata", "valid_creds.json"))
	if err != nil {
		t.Fatalf("Failed to read testdata: %v", err)
	}

	m, _ := New(t.Context(), cfg)
	module := m.(*Module)
	module.agentBuilder = func(ctx context.Context, config *config.Config, service *nspb.NetworkService) (agent.Agent, error) {
		return fakellmagent.NewWithSimpleAnswer(string(strategyJSON)), nil
	}

	reports, err := module.Detect(t.Context(), service)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}

	if reports == nil || len(reports.GetDetectionReports()) == 0 {
		t.Error("Detect() returned no reports, expected finding")
	}

	loadedIdx := cache.Load(t.Context(), cacheDir)
	if len(loadedIdx.HashToPath) == 0 {
		t.Error("expected cache index to be written, but it's empty")
	}

	cachedStrategy, ok := loadedIdx.FindForService(t.Context(), cfg, service)
	if !ok {
		t.Error("expected cached strategy to be retrievable")
	}
	if string(cachedStrategy) != string(strategyJSON) {
		t.Errorf("cached strategy = %q, want %q", cachedStrategy, strategyJSON)
	}
}

func TestDetect_NoCachePath_SkipsCache(t *testing.T) {
	ts := httptest.NewServer(&mockServerHTTP{})
	defer ts.Close()

	host, portStr, _ := net.SplitHostPort(ts.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	service := nspb.NetworkService_builder{
		ServiceName:          "http",
		SupportedHttpMethods: []string{"GET", "POST"},
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
		Clients: cpb.ClientsConfig_builder{
			Llm: lccpb.LlmClientConfig_builder{
				MaxAttempts: proto.Int32(1),
			}.Build(),
		}.Build(),
	}.Build())

	strategyJSON, err := os.ReadFile(filepath.Join("testdata", "valid_creds.json"))
	if err != nil {
		t.Fatalf("Failed to read testdata: %v", err)
	}

	agentCalled := false
	m, _ := New(t.Context(), cfg)
	module := m.(*Module)
	module.agentBuilder = func(ctx context.Context, config *config.Config, service *nspb.NetworkService) (agent.Agent, error) {
		agentCalled = true
		return fakellmagent.NewWithSimpleAnswer(string(strategyJSON)), nil
	}

	reports, err := module.Detect(t.Context(), service)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}

	if !agentCalled {
		t.Error("expected agent to be called when no cache path is set")
	}

	if reports == nil || len(reports.GetDetectionReports()) == 0 {
		t.Error("Detect() returned no reports, expected finding")
	}
}

func TestDetermineStatus(t *testing.T) {
	tests := []struct {
		name    string
		finding finding
		want    dpb.DetectionStatus
	}{
		{
			name: "when_confidence_is_present_returns_present",
			finding: finding{
				ValidCredentials: []*validCredential{
					{Confidence: confidenceLow},
				},
			},
			want: dpb.DetectionStatus_VULNERABILITY_PRESENT,
		},
		{
			name: "when_confidence_is_verified_returns_verified",
			finding: finding{
				ValidCredentials: []*validCredential{
					{Confidence: confidenceLow},
					{Confidence: confidenceHigh},
				},
			},
			want: dpb.DetectionStatus_VULNERABILITY_VERIFIED,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := determineStatus(tc.finding); got != tc.want {
				t.Errorf("determineStatus() = %v, want %v", got, tc.want)
			}
		})
	}
}

type capturingAgent struct {
	*fakellmagent.FakeAgent
	onRun func(string)
}

func (c *capturingAgent) Run(ctx agent.InvocationContext) iter.Seq2[*session.Event, error] {
	if c.onRun != nil && ctx.UserContent() != nil && len(ctx.UserContent().Parts) > 0 {
		c.onRun(ctx.UserContent().Parts[0].Text)
	}
	return c.FakeAgent.Run(ctx)
}

func TestDetect_PromptEnrichment(t *testing.T) {
	tests := []struct {
		name       string
		service    *nspb.NetworkService
		wantPrompt string
	}{
		{
			name: "when_service_has_hostname_and_port_prompt_contains_web_root",
			service: nspb.NetworkService_builder{
				ServiceName: "http",
				NetworkEndpoint: npb.NetworkEndpoint_builder{
					Hostname: npb.Hostname_builder{Name: "jenkins.example"}.Build(),
					Port:     npb.Port_builder{PortNumber: 8080}.Build(),
				}.Build(),
				SupportedHttpMethods: []string{"GET"},
			}.Build(),
			wantPrompt: "Identify whether the web service at http://jenkins.example:8080 supports authentication and determine the credential testing strategy",
		},
		{
			name: "when_service_has_tls_and_port_prompt_contains_https_web_root",
			service: nspb.NetworkService_builder{
				ServiceName: "http",
				NetworkEndpoint: npb.NetworkEndpoint_builder{
					Hostname: npb.Hostname_builder{Name: "example.com"}.Build(),
					Port:     npb.Port_builder{PortNumber: 443}.Build(),
				}.Build(),
				SupportedSslVersions: []string{"TLSv1.3"},
				SupportedHttpMethods: []string{"GET"},
			}.Build(),
			wantPrompt: "Identify whether the web service at https://example.com:443 supports authentication and determine the credential testing strategy",
		},
		{
			name: "when_service_has_no_endpoint_host_prompt_is_generic",
			service: nspb.NetworkService_builder{
				ServiceName: "http",
				NetworkEndpoint: npb.NetworkEndpoint_builder{
					Port: npb.Port_builder{PortNumber: 9090}.Build(),
				}.Build(),
				SupportedHttpMethods: []string{"GET"},
			}.Build(),
			wantPrompt: "Identify whether the web service supports authentication and determine the credential testing strategy",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			cfg := config.FromProto(cpb.Config_builder{
				Clients: cpb.ClientsConfig_builder{
					Llm: lccpb.LlmClientConfig_builder{
						MaxAttempts: proto.Int32(1),
					}.Build(),
				}.Build(),
			}.Build())

			var capturedPrompt string
			m, _ := New(ctx, cfg)
			module := m.(*Module)
			module.agentBuilder = func(ctx context.Context, config *config.Config, service *nspb.NetworkService) (agent.Agent, error) {
				return &capturingAgent{
					FakeAgent: fakellmagent.New(nil, nil),
					onRun: func(prompt string) {
						capturedPrompt = prompt
					},
				}, nil
			}

			_, _ = module.Detect(ctx, tc.service)
			if capturedPrompt != tc.wantPrompt {
				t.Errorf("prompt = %q, want %q", capturedPrompt, tc.wantPrompt)
			}
		})
	}
}

func TestAssertStrategyQuality(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       string
		strategy   string
		wantErr    error
	}{
		{
			name:       "when_protocol_401_with_regex_match_succeeds",
			statusCode: http.StatusUnauthorized,
			body:       "Unauthorized: Bad Credentials",
			strategy: `{
				"supports_authentication": true,
				"authentication_details": {
					"login_request": {
						"method": "POST",
						"path": "/login",
						"body": "user=[[username]]&pass=[[password]]",
						"extraction_regex": "Bad Credentials"
					},
					"credentials_to_test": [
						{"username": "admin", "password": "password"}
					]
				}
			}`,
			wantErr: nil,
		},
		{
			name:       "when_protocol_401_without_regex_match_fails",
			statusCode: http.StatusUnauthorized,
			body:       "Unauthorized: Bad Credentials",
			strategy: `{
				"supports_authentication": true,
				"authentication_details": {
					"login_request": {
						"method": "POST",
						"path": "/login",
						"body": "user=[[username]]&pass=[[password]]",
						"extraction_regex": "non_matching_pattern"
					},
					"credentials_to_test": [
						{"username": "admin", "password": "password"}
					]
				}
			}`,
			wantErr: errRegexpTooWeak,
		},
		{
			name: "when_supports_authentication_false_succeeds",
			strategy: `{
				"supports_authentication": false
			}`,
			wantErr: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.statusCode)
				w.Write([]byte(tc.body))
			}))
			defer ts.Close()

			host, portStr, _ := net.SplitHostPort(ts.Listener.Addr().String())
			port, _ := strconv.Atoi(portStr)

			service := nspb.NetworkService_builder{
				ServiceName:          "http",
				SupportedHttpMethods: []string{"GET", "POST"},
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

			cfg := config.FromProto(cpb.Config_builder{}.Build())
			m, _ := New(ctx, cfg)
			mod := m.(*Module)

			err := mod.assertStrategyQuality(ctx, service, tc.strategy)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("assertStrategyQuality() error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}
