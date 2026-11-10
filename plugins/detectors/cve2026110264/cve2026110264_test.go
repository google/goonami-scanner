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

package cve2026110264

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/module"
	goohttp "github.com/google/goonami-scanner/core/net/http"
	"github.com/google/goonami-scanner/core/net/http/simpleclient"
	"google.golang.org/protobuf/testing/protocmp"

	dpb "github.com/google/tsunami-security-scanner/proto/go/detection_go_proto"
	npb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
	vpb "github.com/google/tsunami-security-scanner/proto/go/vulnerability_go_proto"
)

const testSignInHTML = `<!DOCTYPE html>
<html>
<head>
<title>Sign in · GitLab</title>
<meta content="GitLab" property="og:site_name">
<meta name="csrf-token" content="test-csrf-token-12345" />
</head>
<body>Sign in</body>
</html>`

const testVulnerablePreviewHTML = `<div class="file-content md">
<h1 id="user-content-tsunami_verified-headingend">TSUNAMI_VERIFIED HeadingEnd<a class="anchor" href="#tsunami_verified-headingend"></a></h1>
</div>`

func serviceForServer(t *testing.T, ts *httptest.Server) *nspb.NetworkService {
	t.Helper()
	host, portStr, err := net.SplitHostPort(ts.Listener.Addr().String())
	if err != nil {
		t.Fatalf("net.SplitHostPort() unexpected error: %v", err)
	}
	port, err := strconv.ParseUint(portStr, 10, 32)
	if err != nil {
		t.Fatalf("strconv.ParseUint() unexpected error: %v", err)
	}
	return nspb.NetworkService_builder{
		ServiceName:          "http",
		SupportedHttpMethods: []string{"GET", "POST"},
		TransportProtocol:    npb.TransportProtocol_TCP,
		NetworkEndpoint: npb.NetworkEndpoint_builder{
			Type: npb.NetworkEndpoint_IP_PORT,
			IpAddress: npb.IpAddress_builder{
				Address:       host,
				AddressFamily: npb.AddressFamily_IPV4,
			}.Build(),
			Port: npb.Port_builder{
				PortNumber: uint32(port),
			}.Build(),
		}.Build(),
	}.Build()
}

func TestAdvisoriesAndRegistration(t *testing.T) {
	ctx := t.Context()
	cfg := config.Default()

	detectors, err := module.AllDetectors(ctx, cfg)
	if err != nil {
		t.Fatalf("module.AllDetectors() unexpected error: %v", err)
	}
	var found module.VulnDetector
	for _, d := range detectors {
		if d.Name() == moduleName {
			found = d
			break
		}
	}
	if found == nil {
		t.Fatalf("module.AllDetectors() did not contain %q", moduleName)
	}

	advisories := found.Advisories()
	want := []*vpb.Vulnerability{baseVulnerability()}
	if diff := cmp.Diff(want, advisories, protocmp.Transform()); diff != "" {
		t.Errorf("Advisories() diff (-want +got):\n%s", diff)
	}
}

func TestDetect(t *testing.T) {
	tests := []struct {
		name         string
		handler      http.HandlerFunc
		overrideSvc  *nspb.NetworkService
		wantFindings int
	}{
		{
			name: "when_vulnerable_gitlab_via_api_projects_returns_verified_finding",
			handler: func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/users/sign_in":
					http.SetCookie(w, &http.Cookie{Name: "_gitlab_session", Value: "sess123", Path: "/"})
					w.Write([]byte(testSignInHTML))
				case "/api/v4/projects":
					w.Header().Set("Content-Type", "application/json")
					w.Write([]byte(`[{"path_with_namespace":""},{"path_with_namespace":"public-group/public-repo","default_branch":""}]`))
				case "/public-group/public-repo/-/preview/main/README.org":
					if err := r.ParseForm(); err != nil {
						http.Error(w, err.Error(), http.StatusBadRequest)
						return
					}
					if r.Header.Get("X-CSRF-Token") != "test-csrf-token-12345" && r.FormValue("authenticity_token") != "test-csrf-token-12345" {
						http.Error(w, "422 Unprocessable Content", http.StatusUnprocessableEntity)
						return
					}
					content := r.FormValue("content")
					if strings.Count(content, rangeRepeatAtom) >= rangeRepeatCount*2 && strings.Contains(content, ".+:|") {
						w.Write([]byte(testVulnerablePreviewHTML))
						return
					}
					http.Error(w, "unexpected payload", http.StatusBadRequest)
				default:
					http.NotFound(w, r)
				}
			},
			wantFindings: 1,
		},
		{
			name: "when_vulnerable_gitlab_via_explore_projects_fallback_on_master_returns_verified_finding",
			handler: func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/users/sign_in":
					w.Write([]byte(`<html><head><meta content="GitLab" property="og:site_name"><meta name="csrf-token" content="initial-csrf"></head></html>`))
				case "/api/v4/projects":
					http.Error(w, "403 Forbidden", http.StatusForbidden)
				case "/explore/projects":
					w.Write([]byte(`<html>
<head><meta name="csrf-token" content="refreshed-csrf-token"></head>
<body>
<a href="/users/sign_in">Sign in</a>
<a href="/explore/projects">Explore</a>
<a href="/help/docs">Help</a>
<a href="/team-alpha/subgroup-beta/legacy-repo/-/starrers">Starrers</a>
<a href="/team-alpha/subgroup-beta/legacy-repo/-">Dash</a>
<a href="/team-alpha/subgroup-beta/legacy-repo">Legacy Repo</a>
<a href="/team-alpha/subgroup-beta/legacy-repo">Duplicate Link</a>
</body></html>`))
				case "/team-alpha/subgroup-beta/legacy-repo/-/preview/main/README.org":
					http.NotFound(w, r)
				case "/team-alpha/subgroup-beta/legacy-repo/-/preview/master/README.org":
					if r.Header.Get("X-CSRF-Token") == "refreshed-csrf-token" {
						w.Write([]byte(testVulnerablePreviewHTML))
						return
					}
					http.Error(w, "bad csrf", http.StatusUnprocessableEntity)
				default:
					http.NotFound(w, r)
				}
			},
			wantFindings: 1,
		},
		{
			name: "when_patched_onigmo_rejects_range_repeats_with_500_returns_no_findings",
			handler: func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/users/sign_in":
					w.Write([]byte(`<html><head><script>window.gon={};gon.gitlab_url="http://localhost";</script><meta name="csrf-token" content="csrf-1"></head></html>`))
				case "/api/v4/projects":
					w.Write([]byte(`[{"path_with_namespace":"public-group/public-repo","default_branch":"main"}]`))
				case "/public-group/public-repo/-/preview/main/README.org":
					http.Error(w, "500 Internal Server Error: RegexpError (too many range repeat)", http.StatusInternalServerError)
				default:
					http.NotFound(w, r)
				}
			},
			wantFindings: 0,
		},
		{
			name: "when_patched_org_ruby_escapes_todo_keyword_returns_no_findings",
			handler: func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/users/sign_in":
					w.Write([]byte(`<html><head><title>Sign in · GitLab</title><meta name="csrf-token" content="csrf-1"></head></html>`))
				case "/api/v4/projects":
					w.Write([]byte(`[{"path_with_namespace":"public-group/public-repo","default_branch":"main"}]`))
				case "/public-group/public-repo/-/preview/main/README.org":
					w.Write([]byte(`<div class="file-content md"><h1>HeadingEnd</h1></div>`))
				default:
					http.NotFound(w, r)
				}
			},
			wantFindings: 0,
		},
		{
			name: "when_echo_server_reflects_raw_request_body_returns_no_findings",
			handler: func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/users/sign_in":
					w.Write([]byte(testSignInHTML))
				case "/api/v4/projects":
					w.Write([]byte(`[{"path_with_namespace":"public-group/public-repo","default_branch":"main"}]`))
				default:
					b, _ := io.ReadAll(r.Body)
					w.Write([]byte("<h1>Echo</h1><pre>" + string(b) + "</pre>"))
				}
			},
			wantFindings: 0,
		},
		{
			name: "when_non_gitlab_server_returns_no_findings",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(`<html><head><title>Welcome to nginx!</title></head></html>`))
			},
			wantFindings: 0,
		},
		{
			name: "when_gitlab_sign_in_lacks_csrf_token_returns_no_findings",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(`<html><head><title>Sign in · GitLab</title></head></html>`))
			},
			wantFindings: 0,
		},
		{
			name: "when_sign_in_returns_non_200_returns_no_findings",
			handler: func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "404 Not Found", http.StatusNotFound)
			},
			wantFindings: 0,
		},
		{
			name: "when_no_public_projects_and_explore_fails_returns_no_findings",
			handler: func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/users/sign_in":
					w.Write([]byte(testSignInHTML))
				case "/api/v4/projects":
					w.Write([]byte(`[]`))
				default:
					http.Error(w, "403 Forbidden", http.StatusForbidden)
				}
			},
			wantFindings: 0,
		},
		{
			name: "when_non_web_service_returns_no_findings",
			overrideSvc: nspb.NetworkService_builder{
				ServiceName:       "ssh",
				TransportProtocol: npb.TransportProtocol_TCP,
				NetworkEndpoint: npb.NetworkEndpoint_builder{
					Type:      npb.NetworkEndpoint_IP_PORT,
					IpAddress: npb.IpAddress_builder{Address: "127.0.0.1"}.Build(),
					Port:      npb.Port_builder{PortNumber: 22}.Build(),
				}.Build(),
			}.Build(),
			wantFindings: 0,
		},
		{
			name: "when_build_web_root_fails_returns_no_findings",
			overrideSvc: nspb.NetworkService_builder{
				ServiceName:          "http",
				SupportedHttpMethods: []string{"GET"},
				NetworkEndpoint: npb.NetworkEndpoint_builder{
					Type: npb.NetworkEndpoint_IP_PORT,
				}.Build(),
			}.Build(),
			wantFindings: 0,
		},
		{
			name: "when_hostname_creates_invalid_request_url_returns_no_findings",
			overrideSvc: nspb.NetworkService_builder{
				ServiceName:          "http",
				SupportedHttpMethods: []string{"GET"},
				NetworkEndpoint: npb.NetworkEndpoint_builder{
					Type:     npb.NetworkEndpoint_HOSTNAME_PORT,
					Hostname: npb.Hostname_builder{Name: "bad host name"}.Build(),
					Port:     npb.Port_builder{PortNumber: 80}.Build(),
				}.Build(),
			}.Build(),
			wantFindings: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			det, err := New(ctx, config.Default())
			if err != nil {
				t.Fatalf("New() unexpected error: %v", err)
			}

			svc := tc.overrideSvc
			if svc == nil {
				ts := httptest.NewServer(tc.handler)
				defer ts.Close()
				svc = serviceForServer(t, ts)
			}

			reports, err := det.Detect(ctx, svc)
			if err != nil {
				t.Fatalf("Detect() unexpected error: %v", err)
			}
			gotCount := len(reports.GetDetectionReports())
			if gotCount != tc.wantFindings {
				t.Fatalf("Detect() got %d reports, want %d", gotCount, tc.wantFindings)
			}
			if tc.wantFindings > 0 {
				report := reports.GetDetectionReports()[0]
				if report.GetDetectionStatus() != dpb.DetectionStatus_VULNERABILITY_VERIFIED {
					t.Errorf("DetectionStatus = %v, want %v", report.GetDetectionStatus(), dpb.DetectionStatus_VULNERABILITY_VERIFIED)
				}
				if report.GetVulnerability().GetMainId().GetValue() != "CVE-2026-110264" {
					t.Errorf("MainId = %q, want %q", report.GetVulnerability().GetMainId().GetValue(), "CVE-2026-110264")
				}
			}
		})
	}
}

type failingReadCloser struct{}

func (failingReadCloser) Read([]byte) (int, error) {
	return 0, errors.New("simulated body read error")
}

func (failingReadCloser) Close() error {
	return nil
}

type fakeBrokenBodyClient struct{}

func (fakeBrokenBodyClient) Do(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       failingReadCloser{},
		Request:    req,
	}, nil
}

type fakeBrokenDoClient struct{}

func (fakeBrokenDoClient) Do(*http.Request) (*http.Response, error) {
	return nil, errors.New("simulated network dial error")
}

func TestDetect_ClientAndReadErrors(t *testing.T) {
	svc := nspb.NetworkService_builder{
		ServiceName:          "http",
		SupportedHttpMethods: []string{"GET"},
		NetworkEndpoint: npb.NetworkEndpoint_builder{
			Type:      npb.NetworkEndpoint_IP_PORT,
			IpAddress: npb.IpAddress_builder{Address: "127.0.0.1"}.Build(),
			Port:      npb.Port_builder{PortNumber: 80}.Build(),
		}.Build(),
	}.Build()

	t.Run("when_http_client_config_is_nil_returns_error", func(t *testing.T) {
		det, err := New(t.Context(), nil)
		if err != nil {
			t.Fatalf("New() unexpected error: %v", err)
		}
		if _, err := det.Detect(t.Context(), svc); err == nil {
			t.Fatal("Detect() with nil config returned nil error, want non-nil")
		}
	})

	t.Run("when_http_client_do_fails_returns_no_findings", func(t *testing.T) {
		clientName := goohttp.CurrentClientName(config.Default())
		goohttp.Register(clientName, func(*config.Config, *goohttp.ClientOptions) (goohttp.Client, error) {
			return fakeBrokenDoClient{}, nil
		})
		t.Cleanup(func() {
			goohttp.Register(clientName, func(cfg *config.Config, opts *goohttp.ClientOptions) (goohttp.Client, error) {
				return simpleclient.New(cfg, opts)
			})
		})

		det, err := New(t.Context(), config.Default())
		if err != nil {
			t.Fatalf("New() unexpected error: %v", err)
		}
		reports, err := det.Detect(t.Context(), svc)
		if err != nil {
			t.Fatalf("Detect() unexpected error: %v", err)
		}
		if len(reports.GetDetectionReports()) != 0 {
			t.Fatalf("Detect() got %d reports, want 0", len(reports.GetDetectionReports()))
		}
	})

	t.Run("when_response_body_read_fails_returns_no_findings", func(t *testing.T) {
		clientName := goohttp.CurrentClientName(config.Default())
		goohttp.Register(clientName, func(*config.Config, *goohttp.ClientOptions) (goohttp.Client, error) {
			return fakeBrokenBodyClient{}, nil
		})
		t.Cleanup(func() {
			goohttp.Register(clientName, func(cfg *config.Config, opts *goohttp.ClientOptions) (goohttp.Client, error) {
				return simpleclient.New(cfg, opts)
			})
		})

		det, err := New(t.Context(), config.Default())
		if err != nil {
			t.Fatalf("New() unexpected error: %v", err)
		}
		reports, err := det.Detect(t.Context(), svc)
		if err != nil {
			t.Fatalf("Detect() unexpected error: %v", err)
		}
		if len(reports.GetDetectionReports()) != 0 {
			t.Fatalf("Detect() got %d reports, want 0", len(reports.GetDetectionReports()))
		}
	})
}
