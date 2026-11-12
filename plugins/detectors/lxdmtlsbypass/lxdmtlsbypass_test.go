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

package lxdmtlsbypass

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/module"
	"google.golang.org/protobuf/testing/protocmp"

	dpb "github.com/google/tsunami-security-scanner/proto/go/detection_go_proto"
	npb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
	vpb "github.com/google/tsunami-security-scanner/proto/go/vulnerability_go_proto"
)

type fakeLXDMode int

const (
	modeVulnerableChainLoop fakeLXDMode = iota
	modePatchedLeafOnly
	modeHardenedStandaloneUntrusted
	modeMisconfiguredAlwaysTrusted
	modeNonLXDServer
	modeInvalidLXDJSON
	modeHTTPNotFound
	modeFailOnSecondProbe
)

func startFakeLXDServer(t *testing.T, mode fakeLXDMode, probeCount *atomic.Int32) (string, uint32) {
	t.Helper()

	srvCertDER, srvKey, err := generateEphemeralLeafCert()
	if err != nil {
		t.Fatalf("generateEphemeralLeafCert() unexpected error: %v", err)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		currentProbe := probeCount.Add(1)
		if r.URL.Path != "/1.0" || r.Header.Get("Accept") != "application/json" || r.Header.Get("User-Agent") != "TsunamiSecurityScanner" {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		if mode == modeHTTPNotFound || (mode == modeFailOnSecondProbe && currentProbe >= 2) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"type":        "sync",
				"status":      "Success",
				"status_code": 200,
				"metadata": map[string]any{
					"api_version": "1.0",
					"auth":        "trusted",
				},
			})
			return
		}
		if mode == modeNonLXDServer {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("OK"))
			return
		}
		if mode == modeInvalidLXDJSON {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"type":        "error",
				"status":      "Failure",
				"status_code": 200,
				"metadata": map[string]any{
					"api_version": "1.0",
					"auth":        "untrusted",
				},
			})
			return
		}

		trusted := false
		switch mode {
		case modeVulnerableChainLoop:
			// Vulnerable (*Daemon).Authenticate loops over all r.TLS.PeerCertificates.
			if r.TLS != nil {
				for _, cert := range r.TLS.PeerCertificates {
					if bytes.Equal(cert.Raw, srvCertDER) {
						trusted = true
						break
					}
				}
			}
		case modePatchedLeafOnly:
			// Patched (*Daemon).Authenticate inspects only r.TLS.PeerCertificates[0].
			if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
				if bytes.Equal(r.TLS.PeerCertificates[0].Raw, srvCertDER) {
					trusted = true
				}
			}
		case modeHardenedStandaloneUntrusted:
			trusted = false
		case modeMisconfiguredAlwaysTrusted:
			trusted = true
		}

		authState := "untrusted"
		if trusted {
			authState = "trusted"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"type":        "sync",
			"status":      "Success",
			"status_code": 200,
			"metadata": map[string]any{
				"api_version": "1.0",
				"auth":        authState,
			},
		})
	})

	ts := httptest.NewUnstartedServer(handler)
	ts.TLS = &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{srvCertDER},
				PrivateKey:  srvKey,
			},
		},
		ClientAuth: tls.RequestClientCert,
	}
	ts.StartTLS()
	t.Cleanup(ts.Close)

	host, portStr, err := net.SplitHostPort(ts.Listener.Addr().String())
	if err != nil {
		t.Fatalf("net.SplitHostPort(%q) unexpected error: %v", ts.Listener.Addr().String(), err)
	}
	port, err := strconv.ParseUint(portStr, 10, 32)
	if err != nil {
		t.Fatalf("strconv.ParseUint(%q) unexpected error: %v", portStr, err)
	}
	return host, uint32(port)
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
	if got := detector.(*Module).timeout; got != defaultTimeout {
		t.Errorf("detector.timeout = %v, want %v", got, defaultTimeout)
	}

	registered, err := module.AllDetectors(t.Context(), config.Default())
	if err != nil {
		t.Fatalf("module.AllDetectors() unexpected error: %v", err)
	}
	found := false
	for _, d := range registered {
		if d.Name() == moduleName {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("module.AllDetectors() did not contain registered detector %q", moduleName)
	}
}

func TestDetect(t *testing.T) {
	tests := []struct {
		name          string
		mode          fakeLXDMode
		serviceName   string
		wantReports   int
		wantMinProbes int32
		wantMaxProbes int32
	}{
		{
			name:          "vulnerable_lxd_cluster_accepts_appended_server_cert_in_chain",
			mode:          modeVulnerableChainLoop,
			serviceName:   "https-alt",
			wantReports:   1,
			wantMinProbes: 2,
			wantMaxProbes: 2,
		},
		{
			name:          "vulnerable_service_labeled_tcpwrapped_is_scanned",
			mode:          modeVulnerableChainLoop,
			serviceName:   "tcpwrapped",
			wantReports:   1,
			wantMinProbes: 2,
			wantMaxProbes: 2,
		},
		{
			name:          "patched_incus_checks_only_leaf_certificate",
			mode:          modePatchedLeafOnly,
			serviceName:   "https",
			wantReports:   0,
			wantMinProbes: 2,
			wantMaxProbes: 2,
		},
		{
			name:          "hardened_standalone_server_cert_not_in_trust_store",
			mode:          modeHardenedStandaloneUntrusted,
			serviceName:   "https",
			wantReports:   0,
			wantMinProbes: 2,
			wantMaxProbes: 2,
		},
		{
			name:          "misconfigured_always_trusted_server_rejected_by_negative_control",
			mode:          modeMisconfiguredAlwaysTrusted,
			serviceName:   "https",
			wantReports:   0,
			wantMinProbes: 1,
			wantMaxProbes: 1,
		},
		{
			name:          "non_lxd_https_server_short_circuits_after_probe_one",
			mode:          modeNonLXDServer,
			serviceName:   "https",
			wantReports:   0,
			wantMinProbes: 1,
			wantMaxProbes: 1,
		},
		{
			name:          "invalid_lxd_json_metadata_short_circuits_after_probe_one",
			mode:          modeInvalidLXDJSON,
			serviceName:   "https",
			wantReports:   0,
			wantMinProbes: 1,
			wantMaxProbes: 1,
		},
		{
			name:          "http_not_found_status_short_circuits_after_probe_one",
			mode:          modeHTTPNotFound,
			serviceName:   "https",
			wantReports:   0,
			wantMinProbes: 1,
			wantMaxProbes: 1,
		},
		{
			name:          "second_probe_http_failure_returns_zero_findings",
			mode:          modeFailOnSecondProbe,
			serviceName:   "https",
			wantReports:   0,
			wantMinProbes: 2,
			wantMaxProbes: 2,
		},
		{
			name:          "unsupported_service_is_skipped",
			mode:          modeVulnerableChainLoop,
			serviceName:   "ssh",
			wantReports:   0,
			wantMinProbes: 0,
			wantMaxProbes: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var probeCount atomic.Int32
			host, port := startFakeLXDServer(t, tc.mode, &probeCount)

			ep := npb.NetworkEndpoint_builder{
				Type: npb.NetworkEndpoint_IP_PORT,
				IpAddress: npb.IpAddress_builder{
					Address:       host,
					AddressFamily: npb.AddressFamily_IPV4,
				}.Build(),
				Port: npb.Port_builder{
					PortNumber: port,
				}.Build(),
			}.Build()
			service := nspb.NetworkService_builder{
				NetworkEndpoint:   ep,
				TransportProtocol: npb.TransportProtocol_TCP,
				ServiceName:       tc.serviceName,
			}.Build()

			rawDet, err := New(t.Context(), config.Default())
			if err != nil {
				t.Fatalf("New() unexpected error: %v", err)
			}
			det := rawDet.(*Module)
			det.timeout = 2 * time.Second

			got, err := det.Detect(t.Context(), service)
			if err != nil {
				t.Fatalf("Detect() unexpected error: %v", err)
			}
			if len(got.GetDetectionReports()) != tc.wantReports {
				t.Fatalf("Detect() got %d reports, want %d", len(got.GetDetectionReports()), tc.wantReports)
			}

			probes := probeCount.Load()
			if probes < tc.wantMinProbes || probes > tc.wantMaxProbes {
				t.Errorf("Detect() made %d probes, want between %d and %d", probes, tc.wantMinProbes, tc.wantMaxProbes)
			}

			if tc.wantReports == 1 {
				report := got.GetDetectionReports()[0]
				if report.GetDetectionStatus() != dpb.DetectionStatus_VULNERABILITY_VERIFIED {
					t.Errorf("DetectionStatus = %v, want %v", report.GetDetectionStatus(), dpb.DetectionStatus_VULNERABILITY_VERIFIED)
				}
				wantMainID := vpb.VulnerabilityId_builder{
					Publisher: "GOOGLE",
					Value:     "LXD_INCUS_MTLS_CERT_CHAIN_AUTH_BYPASS",
				}.Build()
				if diff := cmp.Diff(wantMainID, report.GetVulnerability().GetMainId(), protocmp.Transform()); diff != "" {
					t.Errorf("MainId diff (-want +got):\n%s", diff)
				}
				wantRelated := []*vpb.VulnerabilityId{
					vpb.VulnerabilityId_builder{
						Publisher: "CVE",
						Value:     "CVE-2026-112816",
					}.Build(),
				}
				if diff := cmp.Diff(wantRelated, report.GetVulnerability().GetRelatedId(), protocmp.Transform()); diff != "" {
					t.Errorf("RelatedId diff (-want +got):\n%s", diff)
				}
				if report.GetVulnerability().GetSeverity() != vpb.Severity_CRITICAL {
					t.Errorf("Severity = %v, want %v", report.GetVulnerability().GetSeverity(), vpb.Severity_CRITICAL)
				}
				details := report.GetVulnerability().GetAdditionalDetails()
				if len(details) != 1 || !strings.Contains(details[0].GetTextData().GetText(), "/1.0") {
					t.Errorf("AdditionalDetails = %v, want 1 detail referencing /1.0", details)
				}
			}
		})
	}
}

func TestGenerateEphemeralLeafCert(t *testing.T) {
	certDER, privKey, err := generateEphemeralLeafCert()
	if err != nil {
		t.Fatalf("generateEphemeralLeafCert() unexpected error: %v", err)
	}
	if privKey == nil {
		t.Fatal("generateEphemeralLeafCert() returned nil private key")
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("x509.ParseCertificate() unexpected error: %v", err)
	}
	if cert.SerialNumber.Cmp(big.NewInt(1)) != 0 {
		t.Errorf("cert.SerialNumber = %v, want 1", cert.SerialNumber)
	}
	if cert.Subject.CommonName != "tsunami-ephemeral-probe" {
		t.Errorf("cert.Subject.CommonName = %q, want %q", cert.Subject.CommonName, "tsunami-ephemeral-probe")
	}
	if cert.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Errorf("cert.KeyUsage = %v, want %v", cert.KeyUsage, x509.KeyUsageDigitalSignature)
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("cert.ExtKeyUsage = %v, want [ExtKeyUsageClientAuth]", cert.ExtKeyUsage)
	}
	if !cert.BasicConstraintsValid {
		t.Error("cert.BasicConstraintsValid = false, want true")
	}
	now := time.Now()
	if !cert.NotBefore.Before(now) {
		t.Errorf("cert.NotBefore = %v, want before %v", cert.NotBefore, now)
	}
	if !cert.NotAfter.After(now) {
		t.Errorf("cert.NotAfter = %v, want after %v", cert.NotAfter, now)
	}
}

func TestAdvisories(t *testing.T) {
	m, err := New(t.Context(), config.Default())
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}
	mod := m.(*Module)
	got := mod.Advisories()
	if len(got) != 1 {
		t.Fatalf("Advisories() len = %d, want 1", len(got))
	}
	if got[0].GetMainId().GetValue() != "LXD_INCUS_MTLS_CERT_CHAIN_AUTH_BYPASS" {
		t.Errorf("Advisories()[0].MainId = %q, want %q", got[0].GetMainId().GetValue(), "LXD_INCUS_MTLS_CERT_CHAIN_AUTH_BYPASS")
	}
}

func TestIsSupportedService(t *testing.T) {
	tests := []struct {
		name    string
		service *nspb.NetworkService
		want    bool
	}{
		{
			name:    "when_service_is_nil_returns_false",
			service: nil,
			want:    false,
		},
		{
			name: "when_transport_protocol_is_udp_returns_false",
			service: nspb.NetworkService_builder{
				TransportProtocol: npb.TransportProtocol_UDP,
				ServiceName:       "https",
			}.Build(),
			want: false,
		},
		{
			name: "when_web_service_has_supported_http_methods_returns_true",
			service: nspb.NetworkService_builder{
				TransportProtocol:    npb.TransportProtocol_TCP,
				ServiceName:          "custom-web",
				SupportedHttpMethods: []string{"GET"},
			}.Build(),
			want: true,
		},
		{
			name: "when_port_is_default_lxd_port_8443_returns_true",
			service: nspb.NetworkService_builder{
				NetworkEndpoint: npb.NetworkEndpoint_builder{
					Port: npb.Port_builder{PortNumber: defaultLXDPort}.Build(),
				}.Build(),
				TransportProtocol: npb.TransportProtocol_TCP,
				ServiceName:       "custom-daemon",
			}.Build(),
			want: true,
		},
		{
			name: "when_service_name_is_in_supported_map_returns_true",
			service: nspb.NetworkService_builder{
				TransportProtocol: npb.TransportProtocol_TRANSPORT_PROTOCOL_UNSPECIFIED,
				ServiceName:       "  LXD  ",
			}.Build(),
			want: true,
		},
		{
			name: "when_service_name_is_unsupported_and_not_default_port_returns_false",
			service: nspb.NetworkService_builder{
				NetworkEndpoint: npb.NetworkEndpoint_builder{
					Port: npb.Port_builder{PortNumber: 22}.Build(),
				}.Build(),
				TransportProtocol: npb.TransportProtocol_TCP,
				ServiceName:       "ssh",
			}.Build(),
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isSupportedService(tc.service); got != tc.want {
				t.Errorf("isSupportedService() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestIsValidLXDResponse(t *testing.T) {
	tests := []struct {
		name string
		resp *lxdAPIResponse
		want bool
	}{
		{
			name: "when_response_is_nil_returns_false",
			resp: nil,
			want: false,
		},
		{
			name: "when_sync_200_v1_response_returns_true",
			resp: &lxdAPIResponse{
				Type:       "sync",
				StatusCode: http.StatusOK,
				Metadata:   lxdAPIMetadata{APIVersion: "1.0"},
			},
			want: true,
		},
		{
			name: "when_type_is_not_sync_returns_false",
			resp: &lxdAPIResponse{
				Type:       "error",
				StatusCode: http.StatusOK,
				Metadata:   lxdAPIMetadata{APIVersion: "1.0"},
			},
			want: false,
		},
		{
			name: "when_status_code_is_not_200_returns_false",
			resp: &lxdAPIResponse{
				Type:       "sync",
				StatusCode: http.StatusForbidden,
				Metadata:   lxdAPIMetadata{APIVersion: "1.0"},
			},
			want: false,
		},
		{
			name: "when_api_version_is_not_1_0_returns_false",
			resp: &lxdAPIResponse{
				Type:       "sync",
				StatusCode: http.StatusOK,
				Metadata:   lxdAPIMetadata{APIVersion: "2.0"},
			},
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isValidLXDResponse(tc.resp); got != tc.want {
				t.Errorf("isValidLXDResponse() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDetectErrorPaths(t *testing.T) {
	rawDet, err := New(t.Context(), config.Default())
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}
	det := rawDet.(*Module)
	det.timeout = 500 * time.Millisecond

	t.Run("when_context_is_canceled_returns_error", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		svc := nspb.NetworkService_builder{
			TransportProtocol: npb.TransportProtocol_TCP,
			ServiceName:       "https",
		}.Build()
		if _, err := det.Detect(ctx, svc); err == nil {
			t.Fatal("Detect() with canceled context returned nil error, want non-nil")
		}
	})

	t.Run("when_endpoint_is_invalid_returns_error", func(t *testing.T) {
		svc := nspb.NetworkService_builder{
			TransportProtocol: npb.TransportProtocol_TCP,
			ServiceName:       "https",
		}.Build()
		if _, err := det.Detect(t.Context(), svc); err == nil {
			t.Fatal("Detect() with empty endpoint returned nil error, want non-nil")
		}
	})

	t.Run("when_plain_tcp_server_fails_tls_handshake_returns_nil_findings", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("net.Listen() unexpected error: %v", err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		go func() {
			conn, err := ln.Accept()
			if err == nil {
				_, _ = conn.Write([]byte("NOT_TLS\r\n"))
				_ = conn.Close()
			}
		}()

		host, portStr, err := net.SplitHostPort(ln.Addr().String())
		if err != nil {
			t.Fatalf("net.SplitHostPort() unexpected error: %v", err)
		}
		port, err := strconv.ParseUint(portStr, 10, 32)
		if err != nil {
			t.Fatalf("strconv.ParseUint() unexpected error: %v", err)
		}
		svc := nspb.NetworkService_builder{
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
			TransportProtocol: npb.TransportProtocol_TCP,
			ServiceName:       "https",
		}.Build()
		got, err := det.Detect(t.Context(), svc)
		if err != nil {
			t.Fatalf("Detect() unexpected error: %v", err)
		}
		if len(got.GetDetectionReports()) != 0 {
			t.Fatalf("Detect() got %d reports, want 0", len(got.GetDetectionReports()))
		}
	})

	t.Run("when_dial_fails_on_closed_port_returns_nil_findings", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("net.Listen() unexpected error: %v", err)
		}
		host, portStr, err := net.SplitHostPort(ln.Addr().String())
		if err != nil {
			t.Fatalf("net.SplitHostPort() unexpected error: %v", err)
		}
		port, err := strconv.ParseUint(portStr, 10, 32)
		if err != nil {
			t.Fatalf("strconv.ParseUint() unexpected error: %v", err)
		}
		_ = ln.Close()

		svc := nspb.NetworkService_builder{
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
			TransportProtocol: npb.TransportProtocol_TCP,
			ServiceName:       "https",
		}.Build()
		got, err := det.Detect(t.Context(), svc)
		if err != nil {
			t.Fatalf("Detect() unexpected error: %v", err)
		}
		if len(got.GetDetectionReports()) != 0 {
			t.Fatalf("Detect() got %d reports, want 0", len(got.GetDetectionReports()))
		}
	})

	t.Run("when_context_canceled_during_probe_one_returns_error", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("net.Listen() unexpected error: %v", err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		go func() {
			conn, err := ln.Accept()
			if err == nil {
				cancel()
				_ = conn.Close()
			}
		}()

		host, portStr, err := net.SplitHostPort(ln.Addr().String())
		if err != nil {
			t.Fatalf("net.SplitHostPort() unexpected error: %v", err)
		}
		port, err := strconv.ParseUint(portStr, 10, 32)
		if err != nil {
			t.Fatalf("strconv.ParseUint() unexpected error: %v", err)
		}
		svc := nspb.NetworkService_builder{
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
			TransportProtocol: npb.TransportProtocol_TCP,
			ServiceName:       "https",
		}.Build()
		if _, err := det.Detect(ctx, svc); err == nil {
			t.Fatal("Detect() with context canceled during Probe 1 returned nil error, want non-nil")
		}
	})

	t.Run("when_context_canceled_during_probe_two_returns_error", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		srvCertDER, srvKey, err := generateEphemeralLeafCert()
		if err != nil {
			t.Fatalf("generateEphemeralLeafCert() unexpected error: %v", err)
		}
		var reqCount atomic.Int32
		ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if reqCount.Add(1) == 1 {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{
					"type":        "sync",
					"status":      "Success",
					"status_code": 200,
					"metadata": map[string]any{
						"api_version": "1.0",
						"auth":        "untrusted",
					},
				})
				return
			}
			cancel()
			http.Error(w, "canceled", http.StatusInternalServerError)
		}))
		ts.TLS = &tls.Config{
			Certificates: []tls.Certificate{
				{
					Certificate: [][]byte{srvCertDER},
					PrivateKey:  srvKey,
				},
			},
			ClientAuth: tls.RequestClientCert,
		}
		ts.StartTLS()
		t.Cleanup(ts.Close)

		host, portStr, err := net.SplitHostPort(ts.Listener.Addr().String())
		if err != nil {
			t.Fatalf("net.SplitHostPort() unexpected error: %v", err)
		}
		port, err := strconv.ParseUint(portStr, 10, 32)
		if err != nil {
			t.Fatalf("strconv.ParseUint() unexpected error: %v", err)
		}
		svc := nspb.NetworkService_builder{
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
			TransportProtocol: npb.TransportProtocol_TCP,
			ServiceName:       "https",
		}.Build()
		if _, err := det.Detect(ctx, svc); err == nil {
			t.Fatal("Detect() with context canceled during Probe 2 returned nil error, want non-nil")
		}
	})
}
