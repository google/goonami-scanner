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

package opensshauthbypass

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/goonami-scanner/common/testfakes/fakessh"
	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/net/netendpoint"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"

	sccpb "github.com/google/goonami-scanner/common/clients/sshclient/ssh_client_config_go_proto"
	cpb "github.com/google/goonami-scanner/core/config/config_go_proto"
	dpb "github.com/google/tsunami-security-scanner/proto/go/detection_go_proto"
	npb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
	vpb "github.com/google/tsunami-security-scanner/proto/go/vulnerability_go_proto"
)

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
}

func TestDetect(t *testing.T) {
	testCases := []struct {
		name         string
		cfg          *config.Config
		setup        func(t *testing.T) (context.Context, *nspb.NetworkService)
		wantFindings bool
		wantErr      error
		wantAnyErr   bool
	}{
		{
			name: "when_vulnerable_ssh_server_returns_verified_finding",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService) {
				srv, err := fakessh.New(&ssh.ServerConfig{
					PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
						if c.User() == targetUser && len(pass) > 256 {
							return nil, nil
						}
						return nil, fmt.Errorf("auth failed")
					},
				})
				if err != nil {
					t.Fatalf("fakessh.New failed: %v", err)
				}
				t.Cleanup(func() { _ = srv.Close() })
				return t.Context(), srv.NetworkService()
			},
			wantFindings: true,
			wantErr:      nil,
		},
		{
			name: "when_vulnerable_ssh_server_requires_second_attempt_in_connection_returns_verified_finding",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService) {
				var attempts atomic.Int32
				srv, err := fakessh.New(&ssh.ServerConfig{
					PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
						// Simulates pick_salt() clobbering getspnam()'s static buffer on the
						// 1st attempt of each connection and succeeding on the 2nd attempt.
						n := attempts.Add(1)
						if n%2 == 0 && c.User() == targetUser && len(pass) > 256 {
							return nil, nil
						}
						return nil, fmt.Errorf("auth failed")
					},
				})
				if err != nil {
					t.Fatalf("fakessh.New failed: %v", err)
				}
				t.Cleanup(func() { _ = srv.Close() })
				return t.Context(), srv.NetworkService()
			},
			wantFindings: true,
			wantErr:      nil,
		},
		{
			name: "when_patched_ssh_server_rejects_long_password_returns_no_findings",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService) {
				srv, err := fakessh.NewWithPasswordAuth("dummy", "StrongPassword123!")
				if err != nil {
					t.Fatalf("fakessh.NewWithPasswordAuth failed: %v", err)
				}
				t.Cleanup(func() { _ = srv.Close() })
				return t.Context(), srv.NetworkService()
			},
			wantFindings: false,
			wantErr:      nil,
		},
		{
			name: "when_second_long_password_rejected_returns_no_findings",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService) {
				srv, err := fakessh.NewWithPasswordAuth(targetUser, strings.Repeat("A", probePasswordLen))
				if err != nil {
					t.Fatalf("fakessh.NewWithPasswordAuth failed: %v", err)
				}
				t.Cleanup(func() { _ = srv.Close() })
				return t.Context(), srv.NetworkService()
			},
			wantFindings: false,
			wantErr:      nil,
		},
		{
			name: "when_honeypot_accepts_short_password_returns_no_findings",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService) {
				srv, err := fakessh.New(&ssh.ServerConfig{
					PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
						return nil, nil
					},
				})
				if err != nil {
					t.Fatalf("fakessh.New failed: %v", err)
				}
				t.Cleanup(func() { _ = srv.Close() })
				return t.Context(), srv.NetworkService()
			},
			wantFindings: false,
			wantErr:      nil,
		},
		{
			name: "when_public_key_only_ssh_server_returns_no_findings",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService) {
				srv, err := fakessh.NewPublicKeyOnly()
				if err != nil {
					t.Fatalf("fakessh.NewPublicKeyOnly failed: %v", err)
				}
				t.Cleanup(func() { _ = srv.Close() })
				return t.Context(), srv.NetworkService()
			},
			wantFindings: false,
			wantErr:      nil,
		},
		{
			name: "when_non_ssh_service_returns_no_findings",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService) {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatalf("net.Listen failed: %v", err)
				}
				port := listener.Addr().(*net.TCPAddr).Port
				_ = listener.Close()

				svc := nspb.NetworkService_builder{
					ServiceName: "ssh",
					NetworkEndpoint: npb.NetworkEndpoint_builder{
						Type: npb.NetworkEndpoint_IP_PORT,
						IpAddress: npb.IpAddress_builder{
							Address:       "127.0.0.1",
							AddressFamily: npb.AddressFamily_IPV4,
						}.Build(),
						Port: npb.Port_builder{
							PortNumber: uint32(port),
						}.Build(),
					}.Build(),
				}.Build()
				return t.Context(), svc
			},
			wantFindings: false,
			wantErr:      nil,
		},
		{
			name: "when_web_service_returns_no_findings",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService) {
				svc := nspb.NetworkService_builder{
					ServiceName:          "http",
					SupportedHttpMethods: []string{"GET"},
					NetworkEndpoint: npb.NetworkEndpoint_builder{
						Type: npb.NetworkEndpoint_IP_PORT,
						IpAddress: npb.IpAddress_builder{
							Address: "127.0.0.1",
						}.Build(),
						Port: npb.Port_builder{
							PortNumber: 80,
						}.Build(),
					}.Build(),
				}.Build()
				return t.Context(), svc
			},
			wantFindings: false,
			wantErr:      nil,
		},
		{
			name: "when_udp_service_returns_no_findings",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService) {
				svc := nspb.NetworkService_builder{
					ServiceName:       "ssh",
					TransportProtocol: npb.TransportProtocol_UDP,
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
			wantErr:      nil,
		},
		{
			name: "when_invalid_network_endpoint_returns_error",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService) {
				svc := nspb.NetworkService_builder{
					ServiceName:     "ssh",
					NetworkEndpoint: npb.NetworkEndpoint_builder{}.Build(),
				}.Build()
				return t.Context(), svc
			},
			wantFindings: false,
			wantErr:      netendpoint.ErrEndpointMissingAddress,
		},
		{
			name: "when_context_canceled_before_start_returns_error",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService) {
				ctx, cancel := context.WithCancel(t.Context())
				cancel()
				svc := nspb.NetworkService_builder{
					ServiceName: "ssh",
				}.Build()
				return ctx, svc
			},
			wantFindings: false,
			wantErr:      context.Canceled,
		},
		{
			name: "when_context_canceled_during_first_probe_returns_error",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService) {
				ctx, cancel := context.WithCancel(t.Context())
				srv, err := fakessh.New(&ssh.ServerConfig{
					PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
						cancel()
						return nil, fmt.Errorf("aborted")
					},
				})
				if err != nil {
					t.Fatalf("fakessh.New failed: %v", err)
				}
				t.Cleanup(func() { _ = srv.Close() })
				return ctx, srv.NetworkService()
			},
			wantFindings: false,
			wantErr:      context.Canceled,
		},
		{
			name: "when_context_canceled_during_second_probe_returns_error",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService) {
				ctx, cancel := context.WithCancel(t.Context())
				var attempts atomic.Int32
				srv, err := fakessh.New(&ssh.ServerConfig{
					PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
						if attempts.Add(1) == 1 {
							return nil, nil
						}
						cancel()
						return nil, fmt.Errorf("aborted")
					},
				})
				if err != nil {
					t.Fatalf("fakessh.New failed: %v", err)
				}
				t.Cleanup(func() { _ = srv.Close() })
				return ctx, srv.NetworkService()
			},
			wantFindings: false,
			wantErr:      context.Canceled,
		},
		{
			name: "when_context_canceled_during_short_probe_returns_error",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService) {
				ctx, cancel := context.WithCancel(t.Context())
				var attempts atomic.Int32
				srv, err := fakessh.New(&ssh.ServerConfig{
					PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
						if attempts.Add(1) <= 2 {
							return nil, nil
						}
						cancel()
						return nil, fmt.Errorf("aborted")
					},
				})
				if err != nil {
					t.Fatalf("fakessh.New failed: %v", err)
				}
				t.Cleanup(func() { _ = srv.Close() })
				return ctx, srv.NetworkService()
			},
			wantFindings: false,
			wantErr:      context.Canceled,
		},
		{
			name: "when_connection_times_out_returns_error",
			cfg: config.FromProto(cpb.Config_builder{
				Clients: cpb.ClientsConfig_builder{
					Ssh: sccpb.SSHClientConfig_builder{
						TimeoutSeconds: proto.Int32(1),
					}.Build(),
				}.Build(),
			}.Build()),
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService) {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatalf("net.Listen failed: %v", err)
				}
				done := make(chan struct{})
				t.Cleanup(func() {
					close(done)
					_ = listener.Close()
				})
				go func() {
					conn, err := listener.Accept()
					if err != nil {
						return
					}
					defer conn.Close()
					<-done
				}()
				port := listener.Addr().(*net.TCPAddr).Port
				svc := nspb.NetworkService_builder{
					ServiceName: "ssh",
					NetworkEndpoint: npb.NetworkEndpoint_builder{
						Type: npb.NetworkEndpoint_IP_PORT,
						IpAddress: npb.IpAddress_builder{
							Address:       "127.0.0.1",
							AddressFamily: npb.AddressFamily_IPV4,
						}.Build(),
						Port: npb.Port_builder{
							PortNumber: uint32(port),
						}.Build(),
					}.Build(),
				}.Build()
				return t.Context(), svc
			},
			wantFindings: false,
			wantAnyErr:   true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, svc := tc.setup(t)
			cfg := tc.cfg
			if cfg == nil {
				cfg = config.Default()
			}
			detector, err := New(ctx, cfg)
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
				if got := vuln.GetMainId().GetValue(); got != "OPENSSH_MUSL_PASSWORD_AUTH_BYPASS" {
					t.Errorf("vuln.GetMainId().GetValue() = %q, want %q", got, "OPENSSH_MUSL_PASSWORD_AUTH_BYPASS")
				}
				relatedIDs := vuln.GetRelatedId()
				if len(relatedIDs) != 1 || relatedIDs[0].GetPublisher() != "CVE" || relatedIDs[0].GetValue() != "CVE-2026-123158" {
					t.Errorf("vuln.GetRelatedId() = %v, want [publisher:\"CVE\" value:\"CVE-2026-123158\"]", relatedIDs)
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

func TestAdvisories(t *testing.T) {
	want := []*vpb.Vulnerability{
		vpb.Vulnerability_builder{
			MainId: vpb.VulnerabilityId_builder{
				Publisher: "GOOGLE",
				Value:     "OPENSSH_MUSL_PASSWORD_AUTH_BYPASS",
			}.Build(),
			RelatedId: []*vpb.VulnerabilityId{
				vpb.VulnerabilityId_builder{
					Publisher: "CVE",
					Value:     "CVE-2026-123158",
				}.Build(),
			},
			Severity:       vpb.Severity_CRITICAL,
			Title:          "OpenSSH Password Authentication Bypass on musl-based Systems",
			Description:    "The OpenSSH server is vulnerable to a password authentication bypass when linked against musl libc. When authenticating an account whose shadow password field is '*' (such as the default root entry on Alpine Linux) and at least one other account on the system has a modular crypt password hash (such as SHA-512), supplying a password longer than 256 bytes causes musl's crypt() implementation to fail and return '*', matching the locked shadow entry and granting unauthorized access.",
			Recommendation: "Upgrade OpenSSH to a patched version (such as openssh 9.9_p2-r1 or later on Alpine Linux), or disable password authentication (PasswordAuthentication no) in sshd_config.",
		}.Build(),
	}

	tests := []struct {
		name string
	}{
		{
			name: "when_initialized_with_default_config_returns_base_advisory",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, err := New(t.Context(), config.Default())
			if err != nil {
				t.Fatalf("New() failed: %v", err)
			}
			mod := m.(*Module)

			got := mod.Advisories()
			if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
				t.Errorf("Advisories() mismatch (-want +got):\n%s", diff)
			}

			if len(got) > 0 {
				got[0].SetTitle("mutated title")
				second := mod.Advisories()
				if second[0].GetTitle() == "mutated title" {
					t.Errorf("Advisories() returned a mutable reference, expected an isolated clone")
				}
			}
		})
	}
}
