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
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/goonami-scanner/common/testfakes/fakessh"
	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/module"
	"github.com/google/goonami-scanner/core/net/netendpoint"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"

	sccpb "github.com/google/goonami-scanner/common/clients/sshclient/ssh_client_config_go_proto"
	cpb "github.com/google/goonami-scanner/core/config/config_go_proto"
	dpb "github.com/google/tsunami-security-scanner/proto/go/detection_go_proto"
	npb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
	spb "github.com/google/tsunami-security-scanner/proto/go/software_go_proto"
	vpb "github.com/google/tsunami-security-scanner/proto/go/vulnerability_go_proto"
)

const testOpenSSHBanner = "SSH-2.0-OpenSSH_9.8"

func newFakeOpenSSH(t *testing.T, cfg *ssh.ServerConfig) *fakessh.Server {
	t.Helper()
	if cfg.ServerVersion == "" {
		cfg.ServerVersion = testOpenSSHBanner
	}
	srv, err := fakessh.New(cfg)
	if err != nil {
		t.Fatalf("fakessh.New failed: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	return srv
}

func newFakeOpenSSHWithPassword(t *testing.T, user, password string) *fakessh.Server {
	t.Helper()
	return newFakeOpenSSH(t, &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == user && string(pass) == password {
				return nil, nil
			}
			return nil, fmt.Errorf("auth failed")
		},
	})
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
	if got := detector.(*Module).cooldownSleep; got != defaultPenaltyCooldownSleep {
		t.Errorf("detector.cooldownSleep = %v, want %v", got, defaultPenaltyCooldownSleep)
	}

	allDetectors, err := module.AllDetectors(t.Context(), config.Default())
	if err != nil {
		t.Fatalf("module.AllDetectors() unexpected error: %v", err)
	}
	found := false
	for _, d := range allDetectors {
		if d.Name() == moduleName {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("module.AllDetectors() missing registered detector %q", moduleName)
	}
}

func TestIsSupportedService(t *testing.T) {
	buildService := func(serviceName string, port uint32, proto npb.TransportProtocol) *nspb.NetworkService {
		return nspb.NetworkService_builder{
			ServiceName:       serviceName,
			TransportProtocol: proto,
			NetworkEndpoint: npb.NetworkEndpoint_builder{
				Type: npb.NetworkEndpoint_IP_PORT,
				IpAddress: npb.IpAddress_builder{
					Address:       "127.0.0.1",
					AddressFamily: npb.AddressFamily_IPV4,
				}.Build(),
				Port: npb.Port_builder{
					PortNumber: port,
				}.Build(),
			}.Build(),
		}.Build()
	}

	testCases := []struct {
		name    string
		service *nspb.NetworkService
		want    bool
	}{
		{
			name:    "when_ssh_service_on_tcp_returns_true",
			service: buildService("ssh", 2224, npb.TransportProtocol_TCP),
			want:    true,
		},
		{
			name:    "when_uppercase_ssh_on_unspecified_protocol_returns_true",
			service: buildService(" SSH ", 2224, npb.TransportProtocol_TRANSPORT_PROTOCOL_UNSPECIFIED),
			want:    true,
		},
		{
			name:    "when_empty_service_name_returns_true",
			service: buildService("", 2200, npb.TransportProtocol_TCP),
			want:    true,
		},
		{
			name:    "when_unknown_service_name_returns_true",
			service: buildService("unknown", 2200, npb.TransportProtocol_TCP),
			want:    true,
		},
		{
			name: "when_openssh_software_on_non_standard_service_name_returns_true",
			service: nspb.NetworkService_builder{
				ServiceName:       "di-drm",
				TransportProtocol: npb.TransportProtocol_TCP,
				Software: spb.Software_builder{
					Name: " OpenSSH ",
				}.Build(),
			}.Build(),
			want: true,
		},
		{
			name: "when_non_openssh_software_on_ssh_port_returns_false",
			service: nspb.NetworkService_builder{
				ServiceName:       "ssh",
				TransportProtocol: npb.TransportProtocol_TCP,
				Software: spb.Software_builder{
					Name: "Dropbear sshd",
				}.Build(),
				NetworkEndpoint: npb.NetworkEndpoint_builder{
					Type: npb.NetworkEndpoint_IP_PORT,
					Port: npb.Port_builder{
						PortNumber: 22,
					}.Build(),
				}.Build(),
			}.Build(),
			want: false,
		},
		{
			name:    "when_tcpwrapped_on_port_22_returns_true",
			service: buildService("tcpwrapped", 22, npb.TransportProtocol_TCP),
			want:    true,
		},
		{
			name:    "when_tcpwrapped_on_port_26_returns_true",
			service: buildService("tcpwrapped", 26, npb.TransportProtocol_TCP),
			want:    true,
		},
		{
			name:    "when_tcpwrapped_on_port_222_returns_true",
			service: buildService("tcpwrapped", 222, npb.TransportProtocol_TCP),
			want:    true,
		},
		{
			name:    "when_tcpwrapped_on_port_1022_returns_true",
			service: buildService("tcpwrapped", 1022, npb.TransportProtocol_TCP),
			want:    true,
		},
		{
			name:    "when_tcpwrapped_on_port_2022_returns_true",
			service: buildService("tcpwrapped", 2022, npb.TransportProtocol_TCP),
			want:    true,
		},
		{
			name:    "when_tcpwrapped_on_port_2222_returns_true",
			service: buildService("tcpwrapped", 2222, npb.TransportProtocol_TCP),
			want:    true,
		},
		{
			name:    "when_tcpwrapped_on_port_3389_returns_true",
			service: buildService("tcpwrapped", 3389, npb.TransportProtocol_TCP),
			want:    true,
		},
		{
			name:    "when_tcpwrapped_on_non_ssh_port_returns_false",
			service: buildService("tcpwrapped", 8443, npb.TransportProtocol_TCP),
			want:    false,
		},
		{
			name:    "when_non_ssh_service_name_returns_false",
			service: buildService("mysql", 3306, npb.TransportProtocol_TCP),
			want:    false,
		},
		{
			name:    "when_udp_protocol_returns_false",
			service: buildService("ssh", 22, npb.TransportProtocol_UDP),
			want:    false,
		},
		{
			name:    "when_sctp_protocol_returns_false",
			service: buildService("ssh", 22, npb.TransportProtocol_SCTP),
			want:    false,
		},
		{
			name: "when_web_service_with_ssh_name_returns_false",
			service: nspb.NetworkService_builder{
				ServiceName:          "ssh",
				TransportProtocol:    npb.TransportProtocol_TCP,
				SupportedHttpMethods: []string{"GET"},
			}.Build(),
			want: false,
		},
		{
			name: "when_tls_service_with_ssh_name_returns_false",
			service: nspb.NetworkService_builder{
				ServiceName:          "ssh",
				TransportProtocol:    npb.TransportProtocol_TCP,
				SupportedSslVersions: []string{"TLSv1.3"},
			}.Build(),
			want: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isSupportedService(tc.service); got != tc.want {
				t.Errorf("isSupportedService() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDetect_CandidateUsernames(t *testing.T) {
	testCases := []struct {
		name     string
		username string
	}{
		{name: "when_root_vulnerable_returns_verified_finding", username: "root"},
		{name: "when_alpine_vulnerable_returns_verified_finding", username: "alpine"},
		{name: "when_sshuser_vulnerable_returns_verified_finding", username: "sshuser"},
		{name: "when_admin_vulnerable_returns_verified_finding", username: "admin"},
		{name: "when_user_vulnerable_returns_verified_finding", username: "user"},
		{name: "when_guest_vulnerable_returns_verified_finding", username: "guest"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newFakeOpenSSH(t, &ssh.ServerConfig{
				PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
					if c.User() == tc.username && len(pass) > 256 {
						return nil, nil
					}
					return nil, fmt.Errorf("auth failed")
				},
			})

			detector, err := New(t.Context(), config.Default())
			if err != nil {
				t.Fatalf("New() unexpected error: %v", err)
			}
			reports, err := detector.Detect(t.Context(), srv.NetworkService())
			if err != nil {
				t.Fatalf("Detect() unexpected error: %v", err)
			}
			if reports == nil || len(reports.GetDetectionReports()) != 1 {
				t.Fatalf("Detect() reports = %v, want 1 report", reports)
			}
			detailText := reports.GetDetectionReports()[0].GetVulnerability().GetAdditionalDetails()[0].GetTextData().GetText()
			wantSubstr := fmt.Sprintf("Successfully authenticated as %q", tc.username)
			if !strings.Contains(detailText, wantSubstr) {
				t.Errorf("AdditionalDetails[0] text = %q, want substring %q", detailText, wantSubstr)
			}
		})
	}
}

func TestDetect(t *testing.T) {
	testCases := []struct {
		name             string
		cfg              *config.Config
		cooldownSleep    time.Duration
		setup            func(t *testing.T) (context.Context, *nspb.NetworkService)
		wantFindings     bool
		wantVerifiedUser string
		wantErr          error
		wantAnyErr       bool
	}{
		{
			name: "when_vulnerable_ssh_server_returns_verified_finding",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService) {
				srv := newFakeOpenSSH(t, &ssh.ServerConfig{
					PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
						if c.User() == "root" && len(pass) > 256 {
							return nil, nil
						}
						return nil, fmt.Errorf("auth failed")
					},
				})
				return t.Context(), srv.NetworkService()
			},
			wantFindings:     true,
			wantVerifiedUser: "root",
			wantErr:          nil,
		},
		{
			name: "when_vulnerable_ssh_server_requires_second_attempt_in_connection_returns_verified_finding",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService) {
				var attempts atomic.Int32
				srv := newFakeOpenSSH(t, &ssh.ServerConfig{
					PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
						// Simulates pick_salt() clobbering getspnam()'s static buffer on the
						// 1st attempt of each connection and succeeding on the 2nd attempt.
						n := attempts.Add(1)
						if n%2 == 0 && c.User() == "root" && len(pass) > 256 {
							return nil, nil
						}
						return nil, fmt.Errorf("auth failed")
					},
				})
				return t.Context(), srv.NetworkService()
			},
			wantFindings:     true,
			wantVerifiedUser: "root",
			wantErr:          nil,
		},
		{
			name: "when_non_root_candidate_user_vulnerable_returns_verified_finding",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService) {
				srv := newFakeOpenSSH(t, &ssh.ServerConfig{
					PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
						if c.User() == "admin" && len(pass) > 256 {
							return nil, nil
						}
						return nil, fmt.Errorf("auth failed")
					},
				})
				return t.Context(), srv.NetworkService()
			},
			wantFindings:     true,
			wantVerifiedUser: "admin",
			wantErr:          nil,
		},
		{
			name: "when_pre_banner_connection_drop_recovers_after_cooldown_returns_verified_finding",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService) {
				backend := newFakeOpenSSH(t, &ssh.ServerConfig{
					PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
						if c.User() == "root" && len(pass) > 256 {
							return nil, nil
						}
						return nil, fmt.Errorf("auth failed")
					},
				})
				backendAddr, err := netendpoint.ToURIAuthority(backend.NetworkService().GetNetworkEndpoint())
				if err != nil {
					t.Fatalf("netendpoint.ToURIAuthority failed: %v", err)
				}

				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatalf("net.Listen failed: %v", err)
				}

				var acceptedConns atomic.Int32
				var clientClosedWG sync.WaitGroup
				acceptDone := make(chan struct{})
				go func() {
					defer close(acceptDone)
					for {
						clientConn, err := listener.Accept()
						if err != nil {
							return
						}
						if acceptedConns.Add(1) <= 2 {
							_, _ = clientConn.Write([]byte("Not allowed at this time\r\n"))
							_ = clientConn.Close()
							continue
						}
						clientClosedWG.Add(1)
						go func(c net.Conn) {
							defer clientClosedWG.Done()
							defer c.Close()
							bConn, err := net.Dial("tcp", backendAddr)
							if err != nil {
								return
							}
							defer bConn.Close()
							go func() { _, _ = io.Copy(c, bConn) }()
							_, _ = io.Copy(bConn, c)
						}(clientConn)
					}
				}()
				t.Cleanup(func() {
					closedCh := make(chan struct{})
					go func() {
						_ = listener.Close()
						<-acceptDone
						clientClosedWG.Wait()
						close(closedCh)
					}()
					select {
					case <-closedCh:
					case <-time.After(500 * time.Millisecond):
						t.Errorf("detector did not close accepted SSH client connections")
					}
				})

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
			wantFindings:     true,
			wantVerifiedUser: "root",
			wantErr:          nil,
		},
		{
			name: "when_pre_banner_connection_drop_exceeds_max_retries_returns_no_findings",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService) {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatalf("net.Listen failed: %v", err)
				}
				t.Cleanup(func() { _ = listener.Close() })

				var acceptedConns atomic.Int32
				go func() {
					for {
						clientConn, err := listener.Accept()
						if err != nil {
							return
						}
						acceptedConns.Add(1)
						_ = clientConn.Close()
					}
				}()
				t.Cleanup(func() {
					if got, want := int(acceptedConns.Load()), maxPenaltyCooldownRetries+1; got != want {
						t.Errorf("accepted connections = %d, want %d", got, want)
					}
				})

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
			wantErr:      nil,
		},
		{
			name:          "when_context_canceled_during_cooldown_sleep_returns_error",
			cooldownSleep: 500 * time.Millisecond,
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService) {
				ctx, cancel := context.WithCancel(t.Context())
				t.Cleanup(cancel)

				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatalf("net.Listen failed: %v", err)
				}
				t.Cleanup(func() { _ = listener.Close() })

				go func() {
					clientConn, err := listener.Accept()
					if err != nil {
						return
					}
					_ = clientConn.Close()
					time.AfterFunc(10*time.Millisecond, cancel)
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
				return ctx, svc
			},
			wantFindings: false,
			wantErr:      context.Canceled,
		},
		{
			name: "when_first_long_password_rejected_skips_second_long_password_returns_no_findings",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService) {
				srv := newFakeOpenSSHWithPassword(t, "root", strings.Repeat("B", probePasswordLen))
				return t.Context(), srv.NetworkService()
			},
			wantFindings: false,
			wantErr:      nil,
		},
		{
			name: "when_patched_ssh_server_rejects_long_password_returns_no_findings",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService) {
				srv := newFakeOpenSSHWithPassword(t, "dummy", "StrongPassword123!")
				return t.Context(), srv.NetworkService()
			},
			wantFindings: false,
			wantErr:      nil,
		},
		{
			name: "when_second_long_password_rejected_returns_no_findings",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService) {
				srv := newFakeOpenSSHWithPassword(t, "root", strings.Repeat("A", probePasswordLen))
				return t.Context(), srv.NetworkService()
			},
			wantFindings: false,
			wantErr:      nil,
		},
		{
			name: "when_honeypot_accepts_short_password_returns_no_findings",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService) {
				srv := newFakeOpenSSH(t, &ssh.ServerConfig{
					PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
						return nil, nil
					},
				})
				return t.Context(), srv.NetworkService()
			},
			wantFindings: false,
			wantErr:      nil,
		},
		{
			name: "when_public_key_only_ssh_server_returns_no_findings",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService) {
				srv := newFakeOpenSSH(t, &ssh.ServerConfig{
					PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
						return nil, fmt.Errorf("public key rejected")
					},
				})
				return t.Context(), srv.NetworkService()
			},
			wantFindings: false,
			wantErr:      nil,
		},
		{
			name:          "when_non_openssh_banner_aborts_immediately_returns_no_findings",
			cooldownSleep: time.Hour,
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService) {
				var authAttempts atomic.Int32
				srv, err := fakessh.New(&ssh.ServerConfig{
					ServerVersion: "SSH-2.0-Dropbear_2022.83",
					PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
						authAttempts.Add(1)
						return nil, nil
					},
				})
				if err != nil {
					t.Fatalf("fakessh.New failed: %v", err)
				}
				t.Cleanup(func() {
					_ = srv.Close()
					if got := authAttempts.Load(); got != 0 {
						t.Errorf("authAttempts = %d, want 0 for non-OpenSSH banner", got)
					}
				})
				return t.Context(), srv.NetworkService()
			},
			wantFindings: false,
			wantErr:      nil,
		},
		{
			name:          "when_http_response_closes_connection_aborts_without_retry_returns_no_findings",
			cooldownSleep: time.Hour,
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService) {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatalf("net.Listen failed: %v", err)
				}
				t.Cleanup(func() { _ = listener.Close() })

				var acceptedConns atomic.Int32
				go func() {
					for {
						conn, err := listener.Accept()
						if err != nil {
							return
						}
						acceptedConns.Add(1)
						_, _ = conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
						_ = conn.Close()
					}
				}()
				t.Cleanup(func() {
					if got := acceptedConns.Load(); got != 1 {
						t.Errorf("acceptedConns = %d, want 1 (no cooldown retry on non-SSH response)", got)
					}
				})

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
			wantErr:      nil,
		},
		{
			name:          "when_post_banner_kex_eof_aborts_without_retry_returns_no_findings",
			cooldownSleep: time.Hour,
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService) {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatalf("net.Listen failed: %v", err)
				}
				t.Cleanup(func() { _ = listener.Close() })

				var acceptedConns atomic.Int32
				go func() {
					for {
						conn, err := listener.Accept()
						if err != nil {
							return
						}
						acceptedConns.Add(1)
						_, _ = conn.Write([]byte(testOpenSSHBanner + "\r\n"))
						_ = conn.Close()
					}
				}()
				t.Cleanup(func() {
					if got := acceptedConns.Load(); got != 1 {
						t.Errorf("acceptedConns = %d, want 1 (no cooldown retry on post-banner EOF)", got)
					}
				})

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
			name: "when_tls_service_returns_no_findings",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService) {
				svc := nspb.NetworkService_builder{
					ServiceName:          "ssh",
					SupportedSslVersions: []string{"TLSv1.3"},
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
			name: "when_tcpwrapped_on_non_ssh_port_returns_no_findings",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService) {
				svc := nspb.NetworkService_builder{
					ServiceName: "tcpwrapped",
					NetworkEndpoint: npb.NetworkEndpoint_builder{
						Type: npb.NetworkEndpoint_IP_PORT,
						IpAddress: npb.IpAddress_builder{
							Address: "127.0.0.1",
						}.Build(),
						Port: npb.Port_builder{
							PortNumber: 8443,
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
				srv := newFakeOpenSSH(t, &ssh.ServerConfig{
					PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
						cancel()
						return nil, fmt.Errorf("aborted")
					},
				})
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
				srv := newFakeOpenSSH(t, &ssh.ServerConfig{
					PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
						if attempts.Add(1) == 1 {
							return nil, nil
						}
						cancel()
						return nil, fmt.Errorf("aborted")
					},
				})
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
				srv := newFakeOpenSSH(t, &ssh.ServerConfig{
					PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
						if attempts.Add(1) <= 2 {
							return nil, nil
						}
						cancel()
						return nil, fmt.Errorf("aborted")
					},
				})
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
			cooldown := tc.cooldownSleep
			if cooldown == 0 {
				cooldown = time.Millisecond
			}
			detector.(*Module).cooldownSleep = cooldown

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
					t.Fatal("vuln.GetAdditionalDetails() is empty, want details")
				}
				detailText := vuln.GetAdditionalDetails()[0].GetTextData().GetText()
				wantDetailSubstr := fmt.Sprintf("Successfully authenticated as %q", tc.wantVerifiedUser)
				if !strings.Contains(detailText, wantDetailSubstr) {
					t.Errorf("AdditionalDetails[0] text = %q, want substring %q", detailText, wantDetailSubstr)
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
