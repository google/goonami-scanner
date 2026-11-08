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

package jenkins

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/goonami-scanner/core/config"
	_ "github.com/google/goonami-scanner/core/net/http/simpleclient"
	"github.com/google/goonami-scanner/core/net/netendpoint"
	"google.golang.org/protobuf/proto"

	cpb "github.com/google/goonami-scanner/core/config/config_go_proto"
	dpb "github.com/google/tsunami-security-scanner/proto/go/detection_go_proto"
	npb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
	vpb "github.com/google/tsunami-security-scanner/proto/go/vulnerability_go_proto"
)

const jenkinsLoginHTML = `<!DOCTYPE html><html><head><title>Sign in [Jenkins]</title></head><body>` +
	`<form method="post" action="j_spring_security_check">` +
	`<input name="j_username" type="text"><input name="j_password" type="password">` +
	`</form></body></html>`

func fastTestConfig() *config.Config {
	return config.FromProto(cpb.Config_builder{
		Globalcfg: cpb.GlobalConfig_builder{
			Performance: cpb.GlobalConfig_Performance_builder{
				TimeoutPerRequestSeconds: proto.Int32(2),
			}.Build(),
		}.Build(),
	}.Build())
}

func buildServiceForServer(t *testing.T, rawAddr, serviceName, appRoot string) *nspb.NetworkService {
	t.Helper()
	host, portStr, err := net.SplitHostPort(rawAddr)
	if err != nil {
		t.Fatalf("net.SplitHostPort(%q) unexpected error: %v", rawAddr, err)
	}
	port, err := strconv.ParseUint(portStr, 10, 32)
	if err != nil {
		t.Fatalf("strconv.ParseUint(%q) unexpected error: %v", portStr, err)
	}

	builder := nspb.NetworkService_builder{
		ServiceName:       serviceName,
		TransportProtocol: npb.TransportProtocol_TCP,
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
	}
	if appRoot != "" {
		builder.ServiceContext = nspb.ServiceContext_builder{
			WebServiceContext: nspb.WebServiceContext_builder{
				ApplicationRoot: appRoot,
			}.Build(),
		}.Build()
	}
	return builder.Build()
}

func startFakeJenkinsServer(t *testing.T, validPassword, prefix string, unauthStatus int) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var reqCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqCount.Add(1)
		w.Header().Set("X-Jenkins", "2.479.3")
		switch r.URL.Path {
		case prefix + loginPath:
			w.Header().Set("Content-Type", "text/html;charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(jenkinsLoginHTML))
		case prefix + whoAmIPath:
			user, pass, hasAuth := r.BasicAuth()
			if !hasAuth {
				if unauthStatus != http.StatusOK {
					w.WriteHeader(unauthStatus)
					return
				}
				w.Header().Set("Content-Type", "application/json;charset=utf-8")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"_class":"hudson.security.WhoAmI","anonymous":true,"authenticated":true,"authorities":["anonymous"],"name":"anonymous"}`))
				return
			}
			if user == defaultUsername && pass == validPassword {
				w.Header().Set("Content-Type", "application/json;charset=utf-8")
				w.WriteHeader(http.StatusOK)
				_, _ = fmt.Fprintf(w, `{"_class":"hudson.security.WhoAmI","anonymous":false,"authenticated":true,"authorities":["authenticated"],"name":%q}`, user)
				return
			}
			w.Header().Set("WWW-Authenticate", `Basic realm="Jenkins"`)
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"message":"Unauthorized","status":"401"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &reqCount
}

func TestNewAndOptions_Success(t *testing.T) {
	fifteenPasswords := []string{
		"p1", "p2", "p3", "p4", "p5", "p6", "p7", "p8", "p9", "p10",
		"p11", "p12", "p13", "p14", "p15",
	}

	tests := []struct {
		name          string
		opts          *Options
		useDefaultNew bool
		wantPasswords []string
	}{
		{
			name:          "when_default_constructor_used_loads_ten_default_passwords",
			useDefaultNew: true,
			wantPasswords: defaultWeakPasswords,
		},
		{
			name:          "when_custom_passwords_exceed_ten_truncates_to_ten",
			opts:          &Options{Passwords: fifteenPasswords},
			wantPasswords: fifteenPasswords[:MaxPasswordAttempts],
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var (
				m   *Module
				err error
			)
			if tc.useDefaultNew {
				det, newErr := New(t.Context(), fastTestConfig())
				if newErr != nil {
					t.Fatalf("New() unexpected error: %v", newErr)
				}
				var ok bool
				m, ok = det.(*Module)
				if !ok {
					t.Fatalf("New() type = %T, want *Module", det)
				}
			} else {
				m, err = NewWithOptions(t.Context(), fastTestConfig(), tc.opts)
				if err != nil {
					t.Fatalf("NewWithOptions() unexpected error: %v", err)
				}
			}

			if got := m.Name(); got != moduleName {
				t.Errorf("m.Name() = %q, want %q", got, moduleName)
			}
			if diff := cmp.Diff(tc.wantPasswords, m.Passwords()); diff != "" {
				t.Errorf("m.Passwords() diff (-want +got):\n%s", diff)
			}
			advisories := m.Advisories()
			if len(advisories) != 1 {
				t.Fatalf("len(m.Advisories()) = %d, want 1", len(advisories))
			}
			if got := advisories[0].GetMainId().GetValue(); got != "WEAK_CREDENTIALS_FOR_JENKINS" {
				t.Errorf("Advisory MainId.Value = %q, want %q", got, "WEAK_CREDENTIALS_FOR_JENKINS")
			}
			if got := advisories[0].GetSeverity(); got != vpb.Severity_CRITICAL {
				t.Errorf("Advisory Severity = %v, want %v", got, vpb.Severity_CRITICAL)
			}
		})
	}
}

func TestNewWithOptions_Errors(t *testing.T) {
	badClientCfg := config.FromProto(cpb.Config_builder{
		Globalcfg: cpb.GlobalConfig_builder{
			HttpClient: proto.String("nonexistent-client"),
		}.Build(),
	}.Build())

	tests := []struct {
		name          string
		cfg           *config.Config
		wantIsNilErr  bool
		wantErrSubstr string
	}{
		{
			name:         "when_config_is_nil_returns_err_config_nil",
			cfg:          nil,
			wantIsNilErr: true,
		},
		{
			name:          "when_http_client_name_is_unknown_returns_error",
			cfg:           badClientCfg,
			wantErrSubstr: "creating HTTP client",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewWithOptions(t.Context(), tc.cfg, nil)
			if err == nil {
				t.Fatalf("NewWithOptions(%v, nil) = nil error, want non-nil error", tc.cfg)
			}
			if tc.wantIsNilErr && !errors.Is(err, ErrConfigNil) {
				t.Errorf("NewWithOptions(nil, nil) error = %v, want %v", err, ErrConfigNil)
			}
			if tc.wantErrSubstr != "" && !strings.Contains(err.Error(), tc.wantErrSubstr) {
				t.Errorf("NewWithOptions() error = %q, want substring %q", err.Error(), tc.wantErrSubstr)
			}
		})
	}
}

func TestDetect_WeakPasswordVerified(t *testing.T) {
	tests := []struct {
		name         string
		validPass    string
		serviceName  string
		httpMethods  []string
		appRoot      string
		unauthStatus int
		wantCred     string
		wantRequests int32
	}{
		{
			name:         "when_second_weak_password_matches_reports_finding_and_stops_immediately",
			validPass:    "password",
			serviceName:  "http",
			unauthStatus: http.StatusOK,
			wantCred:     "admin:password",
			// 1 (/login) + 1 (unauth /whoAmI) + 2 (admin, password) = 4 requests total.
			wantRequests: 4,
		},
		{
			name:         "when_tenth_weak_password_matches_on_tcpwrapped_subpath_reports_finding",
			validPass:    "welcome",
			serviceName:  "tcpwrapped",
			appRoot:      "/ci/",
			unauthStatus: http.StatusUnauthorized,
			wantCred:     "admin:welcome",
			// 1 (/ci/login) + 1 (unauth 401) + 10 password probes = 12 requests total.
			wantRequests: 12,
		},
		{
			name:         "when_custom_service_name_marked_as_web_service_reports_finding",
			validPass:    "admin",
			serviceName:  "custom-ci",
			httpMethods:  []string{"GET"},
			unauthStatus: http.StatusForbidden,
			wantCred:     "admin:admin",
			// 1 (/login) + 1 (unauth 403) + 1 (admin) = 3 requests total.
			wantRequests: 3,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			prefix := ""
			if tc.appRoot != "" {
				prefix = "/" + strings.Trim(tc.appRoot, "/")
			}
			srv, reqCount := startFakeJenkinsServer(t, tc.validPass, prefix, tc.unauthStatus)
			svc := buildServiceForServer(t, srv.Listener.Addr().String(), tc.serviceName, tc.appRoot)
			if len(tc.httpMethods) > 0 {
				svc.SetSupportedHttpMethods(tc.httpMethods)
			}

			det, err := New(t.Context(), fastTestConfig())
			if err != nil {
				t.Fatalf("New() unexpected error: %v", err)
			}

			reports, err := det.Detect(t.Context(), svc)
			if err != nil {
				t.Fatalf("Detect() unexpected error: %v", err)
			}
			if len(reports.GetDetectionReports()) != 1 {
				t.Fatalf("len(Detect().GetDetectionReports()) = %d, want 1", len(reports.GetDetectionReports()))
			}

			report := reports.GetDetectionReports()[0]
			if got := report.GetDetectionStatus(); got != dpb.DetectionStatus_VULNERABILITY_VERIFIED {
				t.Errorf("DetectionStatus = %v, want %v", got, dpb.DetectionStatus_VULNERABILITY_VERIFIED)
			}
			if got := report.GetVulnerability().GetMainId().GetValue(); got != "WEAK_CREDENTIALS_FOR_JENKINS" {
				t.Errorf("MainId.Value = %q, want %q", got, "WEAK_CREDENTIALS_FOR_JENKINS")
			}
			details := report.GetVulnerability().GetAdditionalDetails()
			if len(details) != 1 || details[0].GetTextData().GetText() != tc.wantCred {
				t.Errorf("AdditionalDetails = %v, want single TextData %q", details, tc.wantCred)
			}
			if got := reqCount.Load(); got != tc.wantRequests {
				t.Errorf("HTTP request count = %d, want %d", got, tc.wantRequests)
			}
		})
	}
}

func TestDetect_NoFindingsAndBoundedRequests(t *testing.T) {
	tests := []struct {
		name         string
		handler      http.HandlerFunc
		options      *Options
		wantRequests int32
	}{
		{
			name: "when_strong_password_configured_tests_at_most_ten_passwords_and_returns_no_finding",
			options: &Options{
				Passwords: []string{
					"p1", "p2", "p3", "p4", "p5", "p6", "p7", "p8", "p9", "p10", "eleventh-valid",
				},
			},
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Jenkins", "2.479.3")
				if r.URL.Path == loginPath {
					_, _ = w.Write([]byte(jenkinsLoginHTML))
					return
				}
				_, pass, hasAuth := r.BasicAuth()
				if !hasAuth {
					_, _ = w.Write([]byte(`{"anonymous":true,"authenticated":true,"name":"anonymous"}`))
					return
				}
				if pass == "eleventh-valid" {
					_, _ = w.Write([]byte(`{"anonymous":false,"authenticated":true,"name":"admin"}`))
					return
				}
				w.WriteHeader(http.StatusUnauthorized)
			},
			// 1 (/login) + 1 (unauth /whoAmI) + 10 capped password attempts = 12 requests.
			wantRequests: 12,
		},
		{
			name: "when_non_jenkins_http_server_short_circuits_after_single_login_request",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`<html><title>Welcome to nginx!</title></html>`))
			},
			wantRequests: 1,
		},
		{
			name: "when_login_endpoint_returns_404_short_circuits_after_single_request",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Jenkins", "2.479.3")
				w.WriteHeader(http.StatusNotFound)
			},
			wantRequests: 1,
		},
		{
			name: "when_sso_jenkins_has_no_password_form_short_circuits_after_single_request",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Jenkins", "2.479.3")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`<html><head><title>Sign in [Jenkins]</title></head><body><a href="/securityRealm/commenceLogin">SSO</a></body></html>`))
			},
			wantRequests: 1,
		},
		{
			name: "when_unauthenticated_whoami_already_admin_aborts_without_false_positive",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Jenkins", "2.479.3")
				if r.URL.Path == loginPath {
					_, _ = w.Write([]byte(jenkinsLoginHTML))
					return
				}
				_, _ = w.Write([]byte(`{"anonymous":false,"authenticated":true,"name":"admin"}`))
			},
			wantRequests: 2,
		},
		{
			name: "when_unauthenticated_whoami_returns_invalid_json_aborts_after_two_requests",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Jenkins", "2.479.3")
				if r.URL.Path == loginPath {
					_, _ = w.Write([]byte(jenkinsLoginHTML))
					return
				}
				_, _ = w.Write([]byte(`<html>not json</html>`))
			},
			wantRequests: 2,
		},
		{
			name: "when_unauthenticated_whoami_returns_404_aborts_after_two_requests",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Jenkins", "2.479.3")
				if r.URL.Path == loginPath {
					_, _ = w.Write([]byte(jenkinsLoginHTML))
					return
				}
				w.WriteHeader(http.StatusNotFound)
			},
			wantRequests: 2,
		},
		{
			name: "when_authenticated_probe_is_rate_limited_stops_early",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Jenkins", "2.479.3")
				if r.URL.Path == loginPath {
					_, _ = w.Write([]byte(jenkinsLoginHTML))
					return
				}
				if _, _, hasAuth := r.BasicAuth(); !hasAuth {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				w.WriteHeader(http.StatusTooManyRequests)
			},
			wantRequests: 3,
		},
		{
			name: "when_authenticated_probe_returns_anonymous_200_stops_without_false_positive",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Jenkins", "2.479.3")
				if r.URL.Path == loginPath {
					_, _ = w.Write([]byte(jenkinsLoginHTML))
					return
				}
				_, _ = w.Write([]byte(`{"anonymous":true,"authenticated":true,"name":"anonymous"}`))
			},
			wantRequests: 3,
		},
		{
			name: "when_authenticated_probe_returns_malformed_json_stops_without_false_positive",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Jenkins", "2.479.3")
				if r.URL.Path == loginPath {
					_, _ = w.Write([]byte(jenkinsLoginHTML))
					return
				}
				if _, _, hasAuth := r.BasicAuth(); !hasAuth {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				_, _ = w.Write([]byte(`{invalid`))
			},
			wantRequests: 3,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var count atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				count.Add(1)
				tc.handler(w, r)
			}))
			t.Cleanup(srv.Close)

			svc := buildServiceForServer(t, srv.Listener.Addr().String(), "http", "")
			det, err := NewWithOptions(t.Context(), fastTestConfig(), tc.options)
			if err != nil {
				t.Fatalf("NewWithOptions() unexpected error: %v", err)
			}

			reports, err := det.Detect(t.Context(), svc)
			if err != nil {
				t.Fatalf("Detect() unexpected error: %v", err)
			}
			if len(reports.GetDetectionReports()) != 0 {
				t.Errorf("len(Detect().GetDetectionReports()) = %d, want 0", len(reports.GetDetectionReports()))
			}
			if got := count.Load(); got != tc.wantRequests {
				t.Errorf("HTTP request count = %d, want %d", got, tc.wantRequests)
			}
		})
	}
}

func TestDetect_ServiceFilteringAndUnreachableTarget(t *testing.T) {
	closedLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() unexpected error: %v", err)
	}
	closedAddr := closedLn.Addr().String()
	_ = closedLn.Close()

	udpSvc := buildServiceForServer(t, closedAddr, "http", "")
	udpSvc.SetTransportProtocol(npb.TransportProtocol_UDP)

	sshSvc := buildServiceForServer(t, closedAddr, "ssh", "")
	closedHTTPSvc := buildServiceForServer(t, closedAddr, "http", "")

	tests := []struct {
		name string
		svc  *nspb.NetworkService
	}{
		{name: "when_service_is_nil_skips_cleanly", svc: nil},
		{name: "when_transport_protocol_is_udp_skips_cleanly", svc: udpSvc},
		{name: "when_service_name_is_ssh_skips_cleanly", svc: sshSvc},
		{name: "when_http_port_is_closed_returns_no_findings_and_no_error", svc: closedHTTPSvc},
	}

	det, err := New(t.Context(), fastTestConfig())
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reports, err := det.Detect(t.Context(), tc.svc)
			if err != nil {
				t.Fatalf("Detect(%v) unexpected error: %v", tc.svc, err)
			}
			if len(reports.GetDetectionReports()) != 0 {
				t.Errorf("len(Detect(%v).GetDetectionReports()) = %d, want 0", tc.svc, len(reports.GetDetectionReports()))
			}
		})
	}
}

func TestDetect_ErrorCases(t *testing.T) {
	invalidEndpointSvc := nspb.NetworkService_builder{
		ServiceName:     "http",
		NetworkEndpoint: &npb.NetworkEndpoint{},
	}.Build()

	tests := []struct {
		name          string
		cancelOnReq   int32
		invalidTarget bool
		wantErr       error
	}{
		{
			name:    "when_context_canceled_before_detect_returns_context_canceled",
			wantErr: context.Canceled,
		},
		{
			name:          "when_endpoint_missing_address_returns_error",
			invalidTarget: true,
			wantErr:       netendpoint.ErrEndpointMissingAddress,
		},
		{
			name:        "when_context_canceled_during_login_request_returns_context_canceled",
			cancelOnReq: 1,
			wantErr:     context.Canceled,
		},
		{
			name:        "when_context_canceled_during_unauthenticated_control_returns_context_canceled",
			cancelOnReq: 2,
			wantErr:     context.Canceled,
		},
		{
			name:        "when_context_canceled_during_credential_attempt_returns_context_canceled",
			cancelOnReq: 3,
			wantErr:     context.Canceled,
		},
	}

	det, err := New(t.Context(), fastTestConfig())
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			svc := invalidEndpointSvc
			if !tc.invalidTarget {
				var count atomic.Int32
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					n := count.Add(1)
					if n == tc.cancelOnReq {
						cancel()
						<-r.Context().Done()
						return
					}
					w.Header().Set("X-Jenkins", "2.479.3")
					if r.URL.Path == loginPath {
						_, _ = w.Write([]byte(jenkinsLoginHTML))
						return
					}
					w.WriteHeader(http.StatusUnauthorized)
				}))
				t.Cleanup(srv.Close)
				svc = buildServiceForServer(t, srv.Listener.Addr().String(), "http", "")
				if tc.cancelOnReq == 0 {
					cancel()
				}
			}

			_, err := det.Detect(ctx, svc)
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("Detect() error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}
