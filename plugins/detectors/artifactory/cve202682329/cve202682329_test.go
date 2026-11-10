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

package cve202682329

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/module"
	_ "github.com/google/goonami-scanner/core/net/http/simpleclient"

	configpb "github.com/google/goonami-scanner/core/config/config_go_proto"
	detectionpb "github.com/google/tsunami-security-scanner/proto/go/detection_go_proto"
	networkpb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
	networkservicepb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
	vulnerabilitypb "github.com/google/tsunami-security-scanner/proto/go/vulnerability_go_proto"
)

func TestNewAndRegistration(t *testing.T) {
	ctx := t.Context()
	detector, err := New(ctx, config.Default())
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}
	if detector.Name() != moduleName {
		t.Errorf("detector.Name() = %q, want %q", detector.Name(), moduleName)
	}

	advisories := detector.Advisories()
	if len(advisories) != 1 {
		t.Fatalf("len(Advisories()) = %d, want 1", len(advisories))
	}
	if advisories[0].GetMainId().GetValue() != "CVE_2026_82329" {
		t.Errorf("MainId = %q, want %q", advisories[0].GetMainId().GetValue(), "CVE_2026_82329")
	}
	if advisories[0].GetSeverity() != vulnerabilitypb.Severity_CRITICAL {
		t.Errorf("Severity = %v, want %v", advisories[0].GetSeverity(), vulnerabilitypb.Severity_CRITICAL)
	}

	allDetectors, err := module.AllDetectors(ctx, config.Default())
	if err != nil {
		t.Fatalf("module.AllDetectors() error: %v", err)
	}
	found := false
	for _, dt := range allDetectors {
		if dt.Name() == moduleName {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("module %q was not registered in module.DefaultRegistry", moduleName)
	}
}

func TestIsCandidateService(t *testing.T) {
	tests := []struct {
		name    string
		service *networkservicepb.NetworkService
		want    bool
	}{
		{
			name: "when_nil_service_returns_false",
			want: false,
		},
		{
			name: "when_udp_service_returns_false",
			service: networkservicepb.NetworkService_builder{
				TransportProtocol:    networkpb.TransportProtocol_UDP,
				ServiceName:          "http",
				SupportedHttpMethods: []string{"GET"},
			}.Build(),
			want: false,
		},
		{
			name: "when_supported_http_methods_only_returns_true",
			service: networkservicepb.NetworkService_builder{
				TransportProtocol:    networkpb.TransportProtocol_TCP,
				ServiceName:          "custom-unknown",
				SupportedHttpMethods: []string{"GET"},
				NetworkEndpoint: networkpb.NetworkEndpoint_builder{
					Port: networkpb.Port_builder{PortNumber: 9999}.Build(),
				}.Build(),
			}.Build(),
			want: true,
		},
		{
			name: "when_port_8082_without_service_name_returns_true",
			service: networkservicepb.NetworkService_builder{
				TransportProtocol: networkpb.TransportProtocol_TCP,
				NetworkEndpoint: networkpb.NetworkEndpoint_builder{
					Port: networkpb.Port_builder{PortNumber: 8082}.Build(),
				}.Build(),
			}.Build(),
			want: true,
		},
		{
			name: "when_port_8081_without_service_name_returns_true",
			service: networkservicepb.NetworkService_builder{
				NetworkEndpoint: networkpb.NetworkEndpoint_builder{
					Port: networkpb.Port_builder{PortNumber: 8081}.Build(),
				}.Build(),
			}.Build(),
			want: true,
		},
		{
			name: "when_blackice_icecap_service_name_returns_true",
			service: networkservicepb.NetworkService_builder{
				ServiceName: "blackice-icecap",
				NetworkEndpoint: networkpb.NetworkEndpoint_builder{
					Port: networkpb.Port_builder{PortNumber: 9000}.Build(),
				}.Build(),
			}.Build(),
			want: true,
		},
		{
			name: "when_http_service_name_returns_true",
			service: networkservicepb.NetworkService_builder{
				ServiceName: "HTTP-ALT",
				NetworkEndpoint: networkpb.NetworkEndpoint_builder{
					Port: networkpb.Port_builder{PortNumber: 9000}.Build(),
				}.Build(),
			}.Build(),
			want: true,
		},
		{
			name: "when_ssh_service_on_port_22_returns_false",
			service: networkservicepb.NetworkService_builder{
				TransportProtocol: networkpb.TransportProtocol_TCP,
				ServiceName:       "ssh",
				NetworkEndpoint: networkpb.NetworkEndpoint_builder{
					Port: networkpb.Port_builder{PortNumber: 22}.Build(),
				}.Build(),
			}.Build(),
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isCandidateService(tc.service); got != tc.want {
				t.Errorf("isCandidateService(%v) = %v, want %v", tc.service, got, tc.want)
			}
		})
	}
}

func mintTestAdminJWT(alg, sub, scp string) string {
	hdr := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"alg":%q,"typ":"JWT"}`, alg)))
	claims := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"sub":%q,"scp":%q,"aud":"jfac@01test"}`, sub, scp)))
	return hdr + "." + claims + ".c2lnbmF0dXJl"
}

func verifySentJoinJWT(body []byte) (string, string, bool) {
	parts := strings.Split(string(body), ".")
	if len(parts) != 3 {
		return "", "", false
	}
	mac := hmac.New(sha256.New, defaultSigningSecret)
	_, _ = mac.Write([]byte(parts[0] + "." + parts[1]))
	wantSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", "", false
	}
	var parsed struct {
		ServiceID string `json:"service_id"`
		Kid       string `json:"kid"`
		Skip      bool   `json:"skip_node_registration"`
	}
	if err := json.Unmarshal(payloadBytes, &parsed); err != nil || !parsed.Skip {
		return "", "", false
	}
	return parsed.ServiceID, parsed.Kid, parts[2] == wantSig
}

func serviceForServer(t *testing.T, srv *httptest.Server) *networkservicepb.NetworkService {
	t.Helper()
	host, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort() failed: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("Atoi() failed: %v", err)
	}
	return networkservicepb.NetworkService_builder{
		TransportProtocol:    networkpb.TransportProtocol_TCP,
		ServiceName:          "http",
		SupportedHttpMethods: []string{"GET", "POST"},
		NetworkEndpoint: networkpb.NetworkEndpoint_builder{
			Type:      networkpb.NetworkEndpoint_IP_PORT,
			IpAddress: networkpb.IpAddress_builder{Address: host}.Build(),
			Port:      networkpb.Port_builder{PortNumber: uint32(port)}.Build(),
		}.Build(),
	}.Build()
}

func TestDetect(t *testing.T) {
	fixedTime := time.Unix(1770000000, 0)

	tests := []struct {
		name         string
		handler      http.HandlerFunc
		wantFindings bool
	}{
		{
			name: "when_vulnerable_on_root_join_endpoint_returns_verified_finding",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.Path != "/access/api/v1/registry/join" {
					w.WriteHeader(http.StatusNotFound)
					_, _ = w.Write([]byte(`{"token":""}`))
					return
				}
				if r.Header.Get("Content-Type") != "text/plain" {
					w.WriteHeader(http.StatusUnsupportedMediaType)
					return
				}
				reqBody, _ := io.ReadAll(r.Body)
				sub, kid, validSig := verifySentJoinJWT(reqBody)
				if kid == defaultKeyID && validSig {
					w.WriteHeader(http.StatusCreated)
					_, _ = fmt.Fprintf(w, `{"token":%q}`, mintTestAdminJWT("RS256", sub, "admin"))
					return
				}
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"errors":[{"code":"BAD_REQUEST"}]}`))
			},
			wantFindings: true,
		},
		{
			name: "when_vulnerable_on_artifactory_subpath_with_http_200_returns_verified_finding",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/artifactory/access/api/v1/registry/join" {
					w.WriteHeader(http.StatusNotFound)
					_, _ = w.Write([]byte(`{"errors":[{"code":"NOT_FOUND"}]}`))
					return
				}
				reqBody, _ := io.ReadAll(r.Body)
				sub, kid, validSig := verifySentJoinJWT(reqBody)
				if kid == defaultKeyID && validSig {
					w.WriteHeader(http.StatusOK)
					_, _ = fmt.Fprintf(w, `{"token":%q}`, mintTestAdminJWT("RS256", sub, "applied-permissions/admin"))
					return
				}
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"errors":[{"code":"BAD_REQUEST"}]}`))
			},
			wantFindings: true,
		},
		{
			name: "when_patched_server_returns_400_even_with_valid_token_json_returns_no_findings",
			handler: func(w http.ResponseWriter, r *http.Request) {
				reqBody, _ := io.ReadAll(r.Body)
				sub, _, _ := verifySentJoinJWT(reqBody)
				w.WriteHeader(http.StatusBadRequest)
				_, _ = fmt.Fprintf(w, `{"token":%q}`, mintTestAdminJWT("RS256", sub, "admin"))
			},
			wantFindings: false,
		},
		{
			name: "when_echo_server_reflects_request_jwt_returns_no_findings",
			handler: func(w http.ResponseWriter, r *http.Request) {
				reqBody, _ := io.ReadAll(r.Body)
				w.WriteHeader(http.StatusOK)
				_, _ = fmt.Fprintf(w, `{"token":%q}`, string(reqBody))
			},
			wantFindings: false,
		},
		{
			name: "when_accept_all_honeypot_mints_admin_token_for_invalid_kid_returns_no_findings",
			handler: func(w http.ResponseWriter, r *http.Request) {
				reqBody, _ := io.ReadAll(r.Body)
				sub, _, _ := verifySentJoinJWT(reqBody)
				w.WriteHeader(http.StatusCreated)
				_, _ = fmt.Fprintf(w, `{"token":%q}`, mintTestAdminJWT("RS256", sub, "admin"))
			},
			wantFindings: false,
		},
		{
			name: "when_server_mints_non_admin_scope_token_returns_no_findings",
			handler: func(w http.ResponseWriter, r *http.Request) {
				reqBody, _ := io.ReadAll(r.Body)
				sub, kid, _ := verifySentJoinJWT(reqBody)
				if kid == defaultKeyID {
					w.WriteHeader(http.StatusOK)
					_, _ = fmt.Fprintf(w, `{"token":%q}`, mintTestAdminJWT("RS256", sub, "applied-permissions/user"))
					return
				}
				w.WriteHeader(http.StatusBadRequest)
			},
			wantFindings: false,
		},
		{
			name: "when_server_returns_empty_body_returns_no_findings",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			},
			wantFindings: false,
		},
		{
			name: "when_server_returns_oversized_body_returns_no_findings",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(strings.Repeat("A", maxResponseBytes+1024)))
			},
			wantFindings: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(tc.handler)
			defer srv.Close()

			det, err := New(t.Context(), config.Default())
			if err != nil {
				t.Fatalf("New() failed: %v", err)
			}
			det.(*Module).now = func() time.Time { return fixedTime }

			reports, err := det.Detect(t.Context(), serviceForServer(t, srv))
			if err != nil {
				t.Fatalf("Detect() unexpected error: %v", err)
			}
			gotFindings := len(reports.GetDetectionReports()) > 0
			if gotFindings != tc.wantFindings {
				t.Fatalf("Detect() findings = %v, want %v", gotFindings, tc.wantFindings)
			}
			if tc.wantFindings {
				rep := reports.GetDetectionReports()[0]
				if rep.GetDetectionStatus() != detectionpb.DetectionStatus_VULNERABILITY_VERIFIED {
					t.Errorf("DetectionStatus = %v, want VULNERABILITY_VERIFIED", rep.GetDetectionStatus())
				}
			}
		})
	}
}

func TestDetect_CanceledContextReturnsError(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	det, err := New(t.Context(), config.Default())
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	svc := networkservicepb.NetworkService_builder{
		ServiceName: "http",
	}.Build()
	if _, err := det.Detect(ctx, svc); err == nil {
		t.Errorf("Detect(%v) with canceled context = nil error, want non-nil error", svc)
	}
}

func TestDetect_NonCandidateServiceReturnsNil(t *testing.T) {
	det, err := New(t.Context(), config.Default())
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	svc := networkservicepb.NetworkService_builder{
		TransportProtocol: networkpb.TransportProtocol_TCP,
		ServiceName:       "ssh",
		NetworkEndpoint: networkpb.NetworkEndpoint_builder{
			Port: networkpb.Port_builder{PortNumber: 22}.Build(),
		}.Build(),
	}.Build()
	reports, err := det.Detect(t.Context(), svc)
	if err != nil || reports != nil {
		t.Errorf("Detect(%v) = (%v, %v), want (nil, nil)", svc, reports, err)
	}
}

func TestDetect_InvalidNetworkEndpointReturnsError(t *testing.T) {
	det, err := New(t.Context(), config.Default())
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	svc := networkservicepb.NetworkService_builder{
		ServiceName:          "http",
		SupportedHttpMethods: []string{"GET"},
	}.Build()
	if _, err := det.Detect(t.Context(), svc); err == nil {
		t.Errorf("Detect(%v) with missing endpoint = nil error, want non-nil error", svc)
	}
}

func TestDetect_UnregisteredHTTPClientReturnsError(t *testing.T) {
	cfg := config.FromProto(configpb.Config_builder{
		Globalcfg: configpb.GlobalConfig_builder{
			HttpClient: new("nonexistent-client"),
		}.Build(),
	}.Build())
	det, err := New(t.Context(), cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	svc := networkservicepb.NetworkService_builder{
		ServiceName:          "http",
		SupportedHttpMethods: []string{"GET"},
		NetworkEndpoint: networkpb.NetworkEndpoint_builder{
			IpAddress: networkpb.IpAddress_builder{Address: "127.0.0.1"}.Build(),
			Port:      networkpb.Port_builder{PortNumber: 8082}.Build(),
		}.Build(),
	}.Build()
	if _, err := det.Detect(t.Context(), svc); err == nil {
		t.Errorf("Detect(%v) with unregistered HTTP client = nil error, want non-nil error", svc)
	}
}

func TestDetect_ConnectionRefusedReturnsNilWithoutError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	svc := serviceForServer(t, srv)
	srv.Close()

	det, err := New(t.Context(), config.Default())
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	reports, err := det.Detect(t.Context(), svc)
	if err != nil || reports != nil {
		t.Errorf("Detect(%v) on closed server = (%v, %v), want (nil, nil)", svc, reports, err)
	}
}

func TestDetect_ContextCanceledDuringPositiveProbeReturnsError(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cancel()
		srv.CloseClientConnections()
	}))
	defer srv.Close()

	det, err := New(t.Context(), config.Default())
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	svc := serviceForServer(t, srv)
	if _, err := det.Detect(ctx, svc); err == nil {
		t.Errorf("Detect(%v) during positive probe cancellation = nil error, want non-nil error", svc)
	}
}

func TestDetect_ContextCanceledDuringNegativeProbeReturnsError(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqBody, _ := io.ReadAll(r.Body)
		sub, kid, validSig := verifySentJoinJWT(reqBody)
		if kid == defaultKeyID && validSig {
			w.WriteHeader(http.StatusCreated)
			_, _ = fmt.Fprintf(w, `{"token":%q}`, mintTestAdminJWT("RS256", sub, "admin"))
			return
		}
		cancel()
		srv.CloseClientConnections()
	}))
	defer srv.Close()

	det, err := New(t.Context(), config.Default())
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	svc := serviceForServer(t, srv)
	if _, err := det.Detect(ctx, svc); err == nil {
		t.Errorf("Detect(%v) during negative probe cancellation = nil error, want non-nil error", svc)
	}
}

func TestSendJoinRequest_InvalidURLReturnsError(t *testing.T) {
	if _, _, err := sendJoinRequest(t.Context(), nil, "://invalid-url", "payload"); err == nil {
		t.Error("sendJoinRequest(\"://invalid-url\") = nil error, want non-nil error")
	}
}

func TestIsValidAdminJoinToken(t *testing.T) {
	sub := "goonami-test@scanner"
	validJWT := mintTestAdminJWT("RS256", sub, "admin")

	tests := []struct {
		name string
		body string
		sent string
		sub  string
		want bool
	}{
		{
			name: "when_valid_rs256_admin_token_returns_true",
			body: fmt.Sprintf(`{"token":%q}`, validJWT),
			sent: "different-sent-token",
			sub:  sub,
			want: true,
		},
		{
			name: "when_invalid_json_returns_false",
			body: `not-json`,
			sent: "sent",
			sub:  sub,
			want: false,
		},
		{
			name: "when_empty_token_returns_false",
			body: `{"token":""}`,
			sent: "sent",
			sub:  sub,
			want: false,
		},
		{
			name: "when_token_matches_sent_returns_false",
			body: fmt.Sprintf(`{"token":%q}`, validJWT),
			sent: validJWT,
			sub:  sub,
			want: false,
		},
		{
			name: "when_token_has_two_segments_returns_false",
			body: `{"token":"a.b"}`,
			sent: "sent",
			sub:  sub,
			want: false,
		},
		{
			name: "when_token_has_empty_signature_segment_returns_false",
			body: `{"token":"a.b."}`,
			sent: "sent",
			sub:  sub,
			want: false,
		},
		{
			name: "when_invalid_base64_header_returns_false",
			body: `{"token":"!!!.b.c"}`,
			sent: "sent",
			sub:  sub,
			want: false,
		},
		{
			name: "when_non_json_header_returns_false",
			body: fmt.Sprintf(`{"token":"%s.b.c"}`, base64.RawURLEncoding.EncodeToString([]byte("not-json"))),
			sent: "sent",
			sub:  sub,
			want: false,
		},
		{
			name: "when_alg_none_returns_false",
			body: fmt.Sprintf(`{"token":%q}`, mintTestAdminJWT("none", sub, "admin")),
			sent: "sent",
			sub:  sub,
			want: false,
		},
		{
			name: "when_alg_empty_returns_false",
			body: fmt.Sprintf(`{"token":%q}`, mintTestAdminJWT("", sub, "admin")),
			sent: "sent",
			sub:  sub,
			want: false,
		},
		{
			name: "when_invalid_base64_claims_returns_false",
			body: fmt.Sprintf(`{"token":"%s.!!!.c"}`, base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`))),
			sent: "sent",
			sub:  sub,
			want: false,
		},
		{
			name: "when_non_json_claims_returns_false",
			body: fmt.Sprintf(`{"token":"%s.%s.c"}`,
				base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`)),
				base64.RawURLEncoding.EncodeToString([]byte("not-json"))),
			sent: "sent",
			sub:  sub,
			want: false,
		},
		{
			name: "when_subject_mismatch_returns_false",
			body: fmt.Sprintf(`{"token":%q}`, mintTestAdminJWT("RS256", "other@scanner", "admin")),
			sent: "sent",
			sub:  sub,
			want: false,
		},
		{
			name: "when_scope_is_not_admin_returns_false",
			body: fmt.Sprintf(`{"token":%q}`, mintTestAdminJWT("RS256", sub, "notadmin reader")),
			sent: "sent",
			sub:  sub,
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isValidAdminJoinToken([]byte(tc.body), tc.sent, tc.sub); got != tc.want {
				t.Errorf("isValidAdminJoinToken(%q, %q, %q) = %v, want %v", tc.body, tc.sent, tc.sub, got, tc.want)
			}
		})
	}
}
