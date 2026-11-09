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

package cameloauthbypass

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/module"
	_ "github.com/google/goonami-scanner/core/net/http/simpleclient"
	"github.com/google/goonami-scanner/core/net/netendpoint"
	"github.com/google/goonami-scanner/core/net/netservice"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"

	cpb "github.com/google/goonami-scanner/core/config/config_go_proto"
	dpb "github.com/google/tsunami-security-scanner/proto/go/detection_go_proto"
	npb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
	vpb "github.com/google/tsunami-security-scanner/proto/go/vulnerability_go_proto"
	wcpb "github.com/google/tsunami-security-scanner/proto/go/web_crawl_go_proto"
)

const oidcRedirectLocation = "http://127.0.0.1:8080/oidc/protocol/openid-connect/auth?flow=authorization_code&scope=openid&response_type=code&client_id=camel-client&redirect_uri=http%3A%2F%2F127.0.0.1%3A8080%2Fauth"

func newWebServiceForServer(t *testing.T, srv *httptest.Server) *nspb.NetworkService {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("url.Parse(%q) failed: %v", srv.URL, err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatalf("strconv.Atoi(%q) failed: %v", u.Port(), err)
	}
	return nspb.NetworkService_builder{
		ServiceName:          "http",
		SupportedHttpMethods: []string{"GET"},
		NetworkEndpoint: npb.NetworkEndpoint_builder{
			Type: npb.NetworkEndpoint_IP_PORT,
			IpAddress: npb.IpAddress_builder{
				Address:       u.Hostname(),
				AddressFamily: npb.AddressFamily_IPV4,
			}.Build(),
			Port: npb.Port_builder{
				PortNumber: uint32(port),
			}.Build(),
		}.Build(),
	}.Build()
}

func TestRegistration(t *testing.T) {
	detectors, err := module.AllDetectors(t.Context(), config.Default())
	if err != nil {
		t.Fatalf("module.AllDetectors() unexpected error: %v", err)
	}
	found := false
	for _, d := range detectors {
		if d.Name() == moduleName {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("module.AllDetectors() does not contain %q", moduleName)
	}
}

func TestNew(t *testing.T) {
	detector, err := New(t.Context(), config.Default())
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}
	if detector == nil {
		t.Fatal("New() returned nil detector")
	}
	if got := detector.Name(); got != moduleName {
		t.Errorf("detector.Name() = %q, want %q", got, moduleName)
	}

	badCfg := config.FromProto(cpb.Config_builder{
		Globalcfg: cpb.GlobalConfig_builder{
			HttpClient: proto.String("unregistered-http-client"),
		}.Build(),
	}.Build())
	if _, err := New(t.Context(), badCfg); err == nil {
		t.Fatal("New() with unregistered HTTP client succeeded, want error")
	}
}

func TestAdvisories(t *testing.T) {
	want := []*vpb.Vulnerability{
		vpb.Vulnerability_builder{
			MainId: vpb.VulnerabilityId_builder{
				Publisher: "GOOGLE",
				Value:     "APACHE_CAMEL_OAUTH_AUTH_BYPASS",
			}.Build(),
			RelatedId: []*vpb.VulnerabilityId{
				vpb.VulnerabilityId_builder{
					Publisher: "CVE",
					Value:     "CVE-2026-80312",
				}.Build(),
			},
			Severity:       vpb.Severity_CRITICAL,
			Title:          "Apache Camel camel-oauth Fail-Open Authentication Bypass (CVE-2026-80312)",
			Description:    "The Apache Camel application using camel-oauth (versions 4.11.0 to 4.18.4 and 4.19.0 to 4.22.0) is vulnerable to an authentication bypass. When OAuthBearerTokenProcessor, OAuthCodeFlowProcessor, or OAuthCodeFlowCallback rejects an unauthenticated request or initiates an OIDC redirect, it returns from process(Exchange) without calling exchange.setRouteStop(true), allowing downstream protected route steps to execute and return protected response data.",
			Recommendation: "Upgrade Apache Camel (org.apache.camel:camel-oauth) to version 4.18.5, 4.22.1, or 4.23.0 or later.",
		}.Build(),
	}

	m, err := New(t.Context(), config.Default())
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	mod := m.(*Module)

	got := mod.Advisories()
	if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
		t.Errorf("Advisories() mismatch (-want +got):\n%s", diff)
	}

	got[0].SetTitle("mutated title")
	if mod.Advisories()[0].GetTitle() == "mutated title" {
		t.Error("Advisories() returned a mutable shared reference, want isolated proto")
	}
}

func TestSendGet_InvalidURL(t *testing.T) {
	m, err := New(t.Context(), config.Default())
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	mod := m.(*Module)
	if _, _, err := mod.sendGet(t.Context(), "://invalid-url", ""); err == nil {
		t.Fatal("sendGet() with invalid URL returned nil error, want non-nil")
	}
}

func TestIsSupportedService(t *testing.T) {
	testCases := []struct {
		name    string
		service *nspb.NetworkService
		want    bool
	}{
		{
			name: "when_udp_service_returns_false",
			service: nspb.NetworkService_builder{
				ServiceName:          "http",
				TransportProtocol:    npb.TransportProtocol_UDP,
				SupportedHttpMethods: []string{"GET"},
			}.Build(),
			want: false,
		},
		{
			name: "when_tcp_web_service_with_custom_service_name_returns_true",
			service: nspb.NetworkService_builder{
				ServiceName:          "custom-service",
				TransportProtocol:    npb.TransportProtocol_TCP,
				SupportedHttpMethods: []string{"GET"},
			}.Build(),
			want: true,
		},
		{
			name: "when_empty_service_name_without_methods_returns_true",
			service: nspb.NetworkService_builder{
				ServiceName: "",
			}.Build(),
			want: true,
		},
		{
			name: "when_unknown_service_name_without_methods_returns_true",
			service: nspb.NetworkService_builder{
				ServiceName: "unknown",
			}.Build(),
			want: true,
		},
		{
			name: "when_tcpwrapped_service_name_without_methods_returns_true",
			service: nspb.NetworkService_builder{
				ServiceName: "tcpwrapped",
			}.Build(),
			want: true,
		},
		{
			name: "when_ssl_unknown_service_name_without_methods_returns_true",
			service: nspb.NetworkService_builder{
				ServiceName: "ssl/unknown",
			}.Build(),
			want: true,
		},
		{
			name: "when_rtsp_service_name_without_methods_returns_true",
			service: nspb.NetworkService_builder{
				ServiceName: "rtsp",
			}.Build(),
			want: true,
		},
		{
			name: "when_sip_service_name_without_methods_returns_true",
			service: nspb.NetworkService_builder{
				ServiceName: "sip",
			}.Build(),
			want: true,
		},
		{
			name: "when_http_alt_service_name_without_methods_returns_true",
			service: nspb.NetworkService_builder{
				ServiceName: "http-alt",
			}.Build(),
			want: true,
		},
		{
			name: "when_ssh_service_name_without_methods_returns_false",
			service: nspb.NetworkService_builder{
				ServiceName: "ssh",
			}.Build(),
			want: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isSupportedService(tc.service); got != tc.want {
				t.Errorf("isSupportedService(%v) = %v, want %v", tc.service, got, tc.want)
			}
		})
	}
}

func TestDetect(t *testing.T) {
	testCases := []struct {
		name         string
		setup        func(t *testing.T) (context.Context, *nspb.NetworkService)
		wantFindings bool
		wantErr      error
		wantAnyErr   bool
	}{
		{
			name: "when_oauth_code_flow_processor_fails_open_returns_verified_finding",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService) {
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path != "/protected" {
						w.WriteHeader(http.StatusNotFound)
						return
					}
					http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "session-uuid-123", Path: "/"})
					w.Header().Set("Location", oidcRedirectLocation)
					w.WriteHeader(http.StatusFound)
					_, _ = w.Write([]byte(`{"resource":"protected-camel-route","authenticated":true}`))
				}))
				t.Cleanup(srv.Close)
				return t.Context(), newWebServiceForServer(t, srv)
			},
			wantFindings: true,
		},
		{
			name: "when_crawled_path_is_vulnerable_oauth_code_flow_processor_returns_verified_finding",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService) {
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path != "/custom/camel/orders" {
						w.WriteHeader(http.StatusNotFound)
						return
					}
					http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "session-uuid-456", Path: "/"})
					w.Header().Set("Location", oidcRedirectLocation)
					w.WriteHeader(http.StatusFound)
					_, _ = w.Write([]byte(`{"orders":["ord-1"]}`))
				}))
				t.Cleanup(srv.Close)
				svc := newWebServiceForServer(t, srv)
				netservice.AddCrawlResults(svc, []*wcpb.CrawlResult{
					wcpb.CrawlResult_builder{
						CrawlTarget: wcpb.CrawlTarget_builder{Url: "://invalid-url"}.Build(),
					}.Build(),
					wcpb.CrawlResult_builder{
						CrawlTarget: wcpb.CrawlTarget_builder{Url: srv.URL}.Build(),
					}.Build(),
					wcpb.CrawlResult_builder{
						CrawlTarget: wcpb.CrawlTarget_builder{Url: srv.URL + "/custom/camel/orders?filter=all"}.Build(),
					}.Build(),
					wcpb.CrawlResult_builder{
						CrawlTarget: wcpb.CrawlTarget_builder{Url: srv.URL + "/custom/camel/orders"}.Build(),
					}.Build(),
				})
				return t.Context(), svc
			},
			wantFindings: true,
		},
		{
			name: "when_oauth_code_flow_callback_fails_open_with_500_on_code_returns_verified_finding",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService) {
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path != "/auth" {
						w.WriteHeader(http.StatusNotFound)
						return
					}
					if r.URL.Query().Get("code") != "" {
						http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "cb-session-uuid", Path: "/"})
						w.WriteHeader(http.StatusInternalServerError)
						return
					}
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(`{"callback":"completed","sessionEstablished":true}`))
				}))
				t.Cleanup(srv.Close)
				return t.Context(), newWebServiceForServer(t, srv)
			},
			wantFindings: true,
		},
		{
			name: "when_oauth_code_flow_callback_fails_open_with_400_no_flow_in_progress_returns_verified_finding",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService) {
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path != "/callback" {
						w.WriteHeader(http.StatusNotFound)
						return
					}
					if r.URL.Query().Get("code") != "" {
						http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "cb-session-uuid-2", Path: "/"})
						w.WriteHeader(http.StatusBadRequest)
						_, _ = w.Write([]byte("No authorization code flow in progress"))
						return
					}
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(`{"callback":"completed"}`))
				}))
				t.Cleanup(srv.Close)
				return t.Context(), newWebServiceForServer(t, srv)
			},
			wantFindings: true,
		},
		{
			name: "when_oauth_bearer_token_processor_fails_open_returns_verified_finding",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService) {
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path != "/bearer" {
						w.WriteHeader(http.StatusNotFound)
						return
					}
					auth := r.Header.Get("Authorization")
					toks := strings.Split(auth, " ")
					if auth != "" && len(toks) == 2 && toks[0] == "Bearer" {
						w.WriteHeader(http.StatusInternalServerError)
						return
					}
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(`{"resource":"bearer-protected-api","authenticated":true}`))
				}))
				t.Cleanup(srv.Close)
				return t.Context(), newWebServiceForServer(t, srv)
			},
			wantFindings: true,
		},
		{
			name: "when_oauth_bearer_token_processor_returns_oauth_exception_stack_trace_in_500_returns_verified_finding",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService) {
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path != "/bearer" {
						w.WriteHeader(http.StatusNotFound)
						return
					}
					auth := r.Header.Get("Authorization")
					toks := strings.Split(auth, " ")
					if auth != "" && len(toks) == 2 && toks[0] == "Bearer" {
						w.WriteHeader(http.StatusInternalServerError)
						_, _ = w.Write([]byte("at org.apache.camel.oauth.OAuthBearerTokenProcessor.process"))
						return
					}
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(`{"resource":"bearer-protected-api","authenticated":true}`))
				}))
				t.Cleanup(srv.Close)
				return t.Context(), newWebServiceForServer(t, srv)
			},
			wantFindings: true,
		},
		{
			name: "when_patched_camel_oauth_server_halts_routes_returns_no_findings",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService) {
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					switch r.URL.Path {
					case "/protected":
						http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "patched-uuid", Path: "/"})
						w.Header().Set("Location", oidcRedirectLocation)
						w.WriteHeader(http.StatusFound)
					case "/bearer":
						w.Header().Set("WWW-Authenticate", "Bearer")
						w.WriteHeader(http.StatusUnauthorized)
						_, _ = w.Write([]byte("Authorization header"))
					case "/auth":
						w.WriteHeader(http.StatusBadRequest)
						_, _ = w.Write([]byte("Authorization code missing"))
					default:
						w.WriteHeader(http.StatusNotFound)
					}
				}))
				t.Cleanup(srv.Close)
				return t.Context(), newWebServiceForServer(t, srv)
			},
			wantFindings: false,
		},
		{
			name: "when_redirect_guards_reject_non_camel_or_standard_302_responses_returns_no_findings",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService) {
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					switch r.URL.Path {
					case "/":
						// Missing camel.oauth.session cookie.
						w.Header().Set("Location", oidcRedirectLocation)
						w.WriteHeader(http.StatusFound)
						_, _ = w.Write([]byte(`{"data":"no-cookie"}`))
					case "/protected":
						// Empty camel.oauth.session cookie value.
						http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "", Path: "/"})
						w.Header().Set("Location", oidcRedirectLocation)
						w.WriteHeader(http.StatusFound)
						_, _ = w.Write([]byte(`{"data":"empty-cookie"}`))
					case "/bearer":
						// Missing response_type=code in Location.
						http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "uuid-1", Path: "/"})
						w.Header().Set("Location", "http://127.0.0.1:8080/login?client_id=camel-client")
						w.WriteHeader(http.StatusFound)
						_, _ = w.Write([]byte(`{"data":"no-response-type"}`))
					case "/api":
						// Missing client_id= in Location.
						http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "uuid-2", Path: "/"})
						w.Header().Set("Location", "http://127.0.0.1:8080/login?response_type=code")
						w.WriteHeader(http.StatusFound)
						_, _ = w.Write([]byte(`{"data":"no-client-id"}`))
					case "/auth":
						// Echoes query parameter nonce in 302 body.
						http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "uuid-3", Path: "/"})
						w.Header().Set("Location", oidcRedirectLocation)
						w.WriteHeader(http.StatusFound)
						_, _ = w.Write([]byte("echo: " + r.URL.Query().Get("camel_probe")))
					case "/callback":
						// Body contains Location URL.
						http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "uuid-4", Path: "/"})
						w.Header().Set("Location", oidcRedirectLocation)
						w.WriteHeader(http.StatusFound)
						_, _ = w.Write([]byte("<a href=\"" + oidcRedirectLocation + "\">link</a>"))
					case "/oauth/callback":
						// Standard "Found" redirect text.
						http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "uuid-5", Path: "/"})
						w.Header().Set("Location", oidcRedirectLocation)
						w.WriteHeader(http.StatusFound)
						_, _ = w.Write([]byte("Found. Please wait."))
					case "/admin":
						// Standard "Redirecting" redirect text.
						http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "uuid-6", Path: "/"})
						w.Header().Set("Location", oidcRedirectLocation)
						w.WriteHeader(http.StatusFound)
						_, _ = w.Write([]byte("Redirecting to identity provider"))
					case "/login":
						// Standard "Moved" redirect text.
						http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "uuid-7", Path: "/"})
						w.Header().Set("Location", oidcRedirectLocation)
						w.WriteHeader(http.StatusFound)
						_, _ = w.Write([]byte("Moved Temporarily"))
					}
				}))
				t.Cleanup(srv.Close)
				return t.Context(), newWebServiceForServer(t, srv)
			},
			wantFindings: false,
		},
		{
			name: "when_redirect_guards_reject_missing_redirect_uri_nonce_or_html_302_boilerplate_returns_no_findings",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService) {
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					switch r.URL.Path {
					case "/":
						http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "uuid-8", Path: "/"})
						w.Header().Set("Location", "http://127.0.0.1:8080/login?response_type=code&client_id=camel-client")
						w.WriteHeader(http.StatusFound)
						_, _ = w.Write([]byte(`{"data":"no-redirect-uri"}`))
					case "/protected":
						http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "uuid-9", Path: "/"})
						w.Header().Set("Location", oidcRedirectLocation+"&"+r.URL.RawQuery)
						w.WriteHeader(http.StatusFound)
						_, _ = w.Write([]byte(`{"data":"nonce-in-location"}`))
					case "/bearer":
						http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "uuid-10", Path: "/"})
						w.Header().Set("Location", oidcRedirectLocation)
						w.WriteHeader(http.StatusFound)
						_, _ = w.Write([]byte("<html><body><a href=\"" + strings.ReplaceAll(oidcRedirectLocation, "&", "&amp;") + "\">Found</a></body></html>"))
					case "/api":
						http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "uuid-11", Path: "/"})
						w.Header().Set("Location", oidcRedirectLocation)
						w.WriteHeader(http.StatusFound)
						_, _ = w.Write([]byte("<html><head><title>302 Found</title></head></html>"))
					case "/auth":
						http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "uuid-12", Path: "/"})
						w.Header().Set("Location", oidcRedirectLocation)
						w.WriteHeader(http.StatusFound)
						_, _ = w.Write([]byte("<html><head><title>Moved Temporarily</title></head></html>"))
					default:
						w.WriteHeader(http.StatusNotFound)
					}
				}))
				t.Cleanup(srv.Close)
				return t.Context(), newWebServiceForServer(t, srv)
			},
			wantFindings: false,
		},
		{
			name: "when_400_pre_filters_reject_standard_rejections_and_echoes_returns_no_findings",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService) {
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					switch r.URL.Path {
					case "/":
						w.Header().Set("WWW-Authenticate", "Bearer")
						w.WriteHeader(http.StatusBadRequest)
						_, _ = w.Write([]byte(`{"data":"has-www-auth"}`))
					case "/protected":
						w.WriteHeader(http.StatusBadRequest)
					case "/bearer":
						w.WriteHeader(http.StatusBadRequest)
						_, _ = w.Write([]byte("echo: " + r.URL.Query().Get("camel_probe")))
					case "/api":
						w.WriteHeader(http.StatusBadRequest)
						_, _ = w.Write([]byte("Authorization header"))
					case "/auth":
						w.WriteHeader(http.StatusBadRequest)
						_, _ = w.Write([]byte("Invalid Authorization header"))
					case "/callback":
						w.WriteHeader(http.StatusBadRequest)
						_, _ = w.Write([]byte("Authorization code missing"))
					case "/oauth/callback":
						w.WriteHeader(http.StatusBadRequest)
						_, _ = w.Write([]byte("No authorization code flow in progress"))
					default:
						w.WriteHeader(http.StatusNotFound)
					}
				}))
				t.Cleanup(srv.Close)
				return t.Context(), newWebServiceForServer(t, srv)
			},
			wantFindings: false,
		},
		{
			name: "when_callback_and_bearer_follow_up_probes_do_not_match_returns_no_findings",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService) {
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					auth := r.Header.Get("Authorization")
					code := r.URL.Query().Get("code")
					switch r.URL.Path {
					case "/":
						// Callback returns same baselineBody even with camel.oauth.session cookie;
						// Basic probe returns 401.
						if code != "" {
							http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "uuid-1", Path: "/"})
							w.WriteHeader(http.StatusInternalServerError)
							_, _ = w.Write([]byte(`{"same":"body"}`))
							return
						}
						if strings.HasPrefix(auth, "Basic ") {
							w.WriteHeader(http.StatusUnauthorized)
							return
						}
						w.WriteHeader(http.StatusBadRequest)
						_, _ = w.Write([]byte(`{"same":"body"}`))
					case "/protected":
						// Callback sets cookie and returns 400 with non-Camel message;
						// Basic probe sets WWW-Authenticate header.
						if code != "" {
							http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "uuid-2", Path: "/"})
							w.WriteHeader(http.StatusBadRequest)
							_, _ = w.Write([]byte("different error message"))
							return
						}
						if strings.HasPrefix(auth, "Basic ") {
							w.Header().Set("WWW-Authenticate", "Basic")
							w.WriteHeader(http.StatusBadRequest)
							_, _ = w.Write([]byte(`{"baseline":"protected"}`))
							return
						}
						w.WriteHeader(http.StatusBadRequest)
						_, _ = w.Write([]byte(`{"baseline":"protected"}`))
					case "/bearer":
						// Callback sets cookie and returns 403 with "No authorization code flow in progress";
						// Basic probe returns a different body.
						if code != "" {
							http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "uuid-3", Path: "/"})
							w.WriteHeader(http.StatusForbidden)
							_, _ = w.Write([]byte("No authorization code flow in progress"))
							return
						}
						if strings.HasPrefix(auth, "Basic ") {
							w.WriteHeader(http.StatusBadRequest)
							_, _ = w.Write([]byte(`{"different":"basic-body"}`))
							return
						}
						w.WriteHeader(http.StatusBadRequest)
						_, _ = w.Write([]byte(`{"baseline":"bearer"}`))
					case "/api":
						// Basic matches, but 2-space Bearer returns 401.
						if strings.HasPrefix(auth, "Bearer  ") {
							w.WriteHeader(http.StatusUnauthorized)
							return
						}
						w.WriteHeader(http.StatusBadRequest)
						_, _ = w.Write([]byte(`{"baseline":"api"}`))
					case "/auth":
						// Basic matches, but 2-space Bearer sets WWW-Authenticate.
						if strings.HasPrefix(auth, "Bearer  ") {
							w.Header().Set("WWW-Authenticate", "Bearer")
						}
						w.WriteHeader(http.StatusBadRequest)
						_, _ = w.Write([]byte(`{"baseline":"auth"}`))
					case "/callback":
						// Basic matches, but 2-space Bearer returns different body.
						if strings.HasPrefix(auth, "Bearer  ") {
							w.WriteHeader(http.StatusBadRequest)
							_, _ = w.Write([]byte(`{"different":"two-space"}`))
							return
						}
						w.WriteHeader(http.StatusBadRequest)
						_, _ = w.Write([]byte(`{"baseline":"callback"}`))
					case "/oauth/callback":
						// Basic and 2-space Bearer match, but 1-space Bearer also returns 400 (generic 400 server).
						w.WriteHeader(http.StatusBadRequest)
						_, _ = w.Write([]byte(`{"baseline":"generic-400"}`))
					case "/admin":
						// Basic and 2-space Bearer match, and 1-space Bearer returns 500 with non-empty body.
						if strings.HasPrefix(auth, "Bearer ") && !strings.HasPrefix(auth, "Bearer  ") {
							w.WriteHeader(http.StatusInternalServerError)
							_, _ = w.Write([]byte("non-empty 500 error page"))
							return
						}
						w.WriteHeader(http.StatusBadRequest)
						_, _ = w.Write([]byte(`{"baseline":"admin"}`))
					default:
						w.WriteHeader(http.StatusNotFound)
					}
				}))
				t.Cleanup(srv.Close)
				return t.Context(), newWebServiceForServer(t, srv)
			},
			wantFindings: false,
		},
		{
			name: "when_non_web_service_returns_no_findings",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService) {
				svc := nspb.NetworkService_builder{
					ServiceName: "ssh",
					NetworkEndpoint: npb.NetworkEndpoint_builder{
						Type: npb.NetworkEndpoint_IP_PORT,
						IpAddress: npb.IpAddress_builder{
							Address: "127.0.0.1",
						}.Build(),
						Port: npb.Port_builder{
							PortNumber: 22,
						}.Build(),
					}.Build(),
				}.Build()
				return t.Context(), svc
			},
			wantFindings: false,
		},
		{
			name: "when_invalid_network_endpoint_returns_error",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService) {
				svc := nspb.NetworkService_builder{
					ServiceName:          "http",
					SupportedHttpMethods: []string{"GET"},
					NetworkEndpoint:      npb.NetworkEndpoint_builder{}.Build(),
				}.Build()
				return t.Context(), svc
			},
			wantErr: netendpoint.ErrEndpointMissingAddress,
		},
		{
			name: "when_context_canceled_before_start_returns_error",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService) {
				ctx, cancel := context.WithCancel(t.Context())
				cancel()
				svc := nspb.NetworkService_builder{
					ServiceName:          "http",
					SupportedHttpMethods: []string{"GET"},
				}.Build()
				return ctx, svc
			},
			wantErr: context.Canceled,
		},
		{
			name: "when_context_canceled_during_initial_probe_returns_error",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService) {
				ctx, cancel := context.WithCancel(t.Context())
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					cancel()
				}))
				t.Cleanup(srv.Close)
				return ctx, newWebServiceForServer(t, srv)
			},
			wantAnyErr: true,
		},
		{
			name: "when_context_canceled_during_callback_probe_returns_error",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService) {
				ctx, cancel := context.WithCancel(t.Context())
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Query().Get("code") != "" {
						cancel()
						return
					}
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(`{"baseline":"ok"}`))
				}))
				t.Cleanup(srv.Close)
				return ctx, newWebServiceForServer(t, srv)
			},
			wantAnyErr: true,
		},
		{
			name: "when_context_canceled_during_basic_auth_probe_returns_error",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService) {
				ctx, cancel := context.WithCancel(t.Context())
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if strings.HasPrefix(r.Header.Get("Authorization"), "Basic ") {
						cancel()
						return
					}
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(`{"baseline":"ok"}`))
				}))
				t.Cleanup(srv.Close)
				return ctx, newWebServiceForServer(t, srv)
			},
			wantAnyErr: true,
		},
		{
			name: "when_context_canceled_during_two_space_bearer_probe_returns_error",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService) {
				ctx, cancel := context.WithCancel(t.Context())
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer  ") {
						cancel()
						return
					}
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(`{"baseline":"ok"}`))
				}))
				t.Cleanup(srv.Close)
				return ctx, newWebServiceForServer(t, srv)
			},
			wantAnyErr: true,
		},
		{
			name: "when_context_canceled_during_single_space_bearer_probe_returns_error",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService) {
				ctx, cancel := context.WithCancel(t.Context())
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					auth := r.Header.Get("Authorization")
					if strings.HasPrefix(auth, "Bearer ") && !strings.HasPrefix(auth, "Bearer  ") {
						cancel()
						return
					}
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(`{"baseline":"ok"}`))
				}))
				t.Cleanup(srv.Close)
				return ctx, newWebServiceForServer(t, srv)
			},
			wantAnyErr: true,
		},
		{
			name: "when_response_body_truncated_mid_read_returns_error",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService) {
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					hj, ok := w.(http.Hijacker)
					if !ok {
						t.Fatal("ResponseWriter does not support hijacking")
					}
					conn, buf, err := hj.Hijack()
					if err != nil {
						t.Fatalf("Hijack() failed: %v", err)
					}
					_, _ = buf.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort")
					_ = buf.Flush()
					_ = conn.Close()
				}))
				t.Cleanup(srv.Close)
				return t.Context(), newWebServiceForServer(t, srv)
			},
			wantAnyErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, svc := tc.setup(t)
			detector, err := New(t.Context(), config.Default())
			if err != nil {
				t.Fatalf("New() unexpected error: %v", err)
			}

			reports, err := detector.Detect(ctx, svc)
			if tc.wantAnyErr {
				if err == nil {
					t.Fatal("Detect() error = nil, want non-nil error")
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Detect() error = %v, want %v", err, tc.wantErr)
			}

			if tc.wantFindings {
				if reports == nil || len(reports.GetDetectionReports()) != 1 {
					t.Fatalf("Detect() reports = %v, want 1 report", reports)
				}
				report := reports.GetDetectionReports()[0]
				if got := report.GetDetectionStatus(); got != dpb.DetectionStatus_VULNERABILITY_VERIFIED {
					t.Errorf("report.GetDetectionStatus() = %v, want %v", got, dpb.DetectionStatus_VULNERABILITY_VERIFIED)
				}
				vuln := report.GetVulnerability()
				if got := vuln.GetSeverity(); got != vpb.Severity_CRITICAL {
					t.Errorf("vuln.GetSeverity() = %v, want %v", got, vpb.Severity_CRITICAL)
				}
				if got := vuln.GetMainId().GetValue(); got != "APACHE_CAMEL_OAUTH_AUTH_BYPASS" {
					t.Errorf("vuln.GetMainId().GetValue() = %q, want %q", got, "APACHE_CAMEL_OAUTH_AUTH_BYPASS")
				}
				relatedIDs := vuln.GetRelatedId()
				if len(relatedIDs) != 1 || relatedIDs[0].GetPublisher() != "CVE" || relatedIDs[0].GetValue() != "CVE-2026-80312" {
					t.Errorf("vuln.GetRelatedId() = %v, want [publisher:\"CVE\" value:\"CVE-2026-80312\"]", relatedIDs)
				}
				if len(vuln.GetAdditionalDetails()) == 0 {
					t.Error("vuln.GetAdditionalDetails() is empty, want details")
				}
				return
			}

			if reports != nil && len(reports.GetDetectionReports()) > 0 {
				t.Errorf("Detect() returned unexpected reports: %v", reports)
			}
		})
	}
}
