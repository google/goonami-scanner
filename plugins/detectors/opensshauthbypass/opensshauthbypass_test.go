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

const testOpenSSHBanner = "SSH-2.0-OpenSSH_9.9"

func startCountingTCPProxy(t *testing.T, upstreamAddr string, shouldDropPreBanner func(connNum int32) bool) (string, *atomic.Int32) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen failed: %v", err)
	}
	var connCount atomic.Int32
	var wg sync.WaitGroup
	t.Cleanup(func() {
		_ = listener.Close()
		wg.Wait()
	})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			clientConn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			n := connCount.Add(1)
			if shouldDropPreBanner != nil && shouldDropPreBanner(n) {
				_ = clientConn.Close()
				continue
			}
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				defer c.Close()
				upstream, dialErr := net.Dial("tcp", upstreamAddr)
				if dialErr != nil {
					return
				}
				defer upstream.Close()
				done := make(chan struct{})
				go func() {
					_, _ = io.Copy(upstream, c)
					_ = upstream.Close()
					_ = c.Close()
					close(done)
				}()
				_, _ = io.Copy(c, upstream)
				_ = c.Close()
				_ = upstream.Close()
				<-done
			}(clientConn)
		}
	}()
	return listener.Addr().String(), &connCount
}

func makeServiceForAddr(t *testing.T, addr, serviceName string) *nspb.NetworkService {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("net.SplitHostPort(%q) failed: %v", addr, err)
	}
	var port int
	if _, scanErr := fmt.Sscanf(portStr, "%d", &port); scanErr != nil {
		t.Fatalf("fmt.Sscanf(%q) failed: %v", portStr, scanErr)
	}
	return nspb.NetworkService_builder{
		ServiceName: serviceName,
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

func TestNew(t *testing.T) {
	testCases := []struct {
		name string
		cfg  *config.Config
	}{
		{
			name: "when_default_config_returns_named_detector",
			cfg:  config.Default(),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			detector, err := New(t.Context(), tc.cfg)
			if err != nil {
				t.Fatalf("New() unexpected error: %v", err)
			}
			if detector == nil {
				t.Fatal("New() returned nil detector")
			}
			if got := detector.Name(); got != moduleName {
				t.Errorf("detector.Name() = %q, want %q", got, moduleName)
			}
		})
	}
}

func TestDetect(t *testing.T) {
	testCases := []struct {
		name          string
		cfg           *config.Config
		customSleepFn func(t *testing.T, sleepCalls *atomic.Int32) func(context.Context, time.Duration) error
		setup         func(t *testing.T) (context.Context, *nspb.NetworkService, func(t *testing.T, sleepCalls int32))
		wantFindings  bool
		wantUsername  string
		wantErr       error
	}{
		{
			name: "when_vulnerable_openssh_server_for_root_returns_verified_finding",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService, func(t *testing.T, sleepCalls int32)) {
				srv, err := fakessh.New(&ssh.ServerConfig{
					ServerVersion: testOpenSSHBanner,
					PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
						if c.User() == "root" && len(pass) == probePasswordLen {
							return nil, nil
						}
						return nil, fmt.Errorf("auth failed")
					},
				})
				if err != nil {
					t.Fatalf("fakessh.New failed: %v", err)
				}
				t.Cleanup(func() { _ = srv.Close() })
				return t.Context(), srv.NetworkService(), nil
			},
			wantFindings: true,
			wantUsername: "root",
		},
		{
			name: "when_vulnerable_openssh_requires_second_attempt_in_connection_returns_verified_finding",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService, func(t *testing.T, sleepCalls int32)) {
				var attempts atomic.Int32
				srv, err := fakessh.New(&ssh.ServerConfig{
					ServerVersion: testOpenSSHBanner,
					PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
						n := attempts.Add(1)
						if n%2 == 0 && c.User() == "root" && len(pass) == probePasswordLen {
							return nil, nil
						}
						return nil, fmt.Errorf("auth failed")
					},
				})
				if err != nil {
					t.Fatalf("fakessh.New failed: %v", err)
				}
				t.Cleanup(func() { _ = srv.Close() })
				return t.Context(), srv.NetworkService(), nil
			},
			wantFindings: true,
			wantUsername: "root",
		},
		{
			name: "when_root_rejected_and_non_root_alpine_vulnerable_on_second_prompt_returns_verified_finding",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService, func(t *testing.T, sleepCalls int32)) {
				var alpinePrompts atomic.Int32
				var sawShortNegativeControl atomic.Bool
				srv, err := fakessh.New(&ssh.ServerConfig{
					ServerVersion: testOpenSSHBanner,
					PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
						if c.User() != "alpine" {
							return nil, fmt.Errorf("root login prohibited")
						}
						if string(pass) == shortProbePassword {
							sawShortNegativeControl.Store(true)
							return nil, fmt.Errorf("short password rejected")
						}
						p := alpinePrompts.Add(1)
						if p%2 == 0 && len(pass) == probePasswordLen {
							return nil, nil
						}
						return nil, fmt.Errorf("first prompt caches salt")
					},
				})
				if err != nil {
					t.Fatalf("fakessh.New failed: %v", err)
				}
				t.Cleanup(func() { _ = srv.Close() })
				return t.Context(), srv.NetworkService(), func(t *testing.T, _ int32) {
					if !sawShortNegativeControl.Load() {
						t.Error("expected shortProbePassword negative control to be evaluated for alpine")
					}
				}
			},
			wantFindings: true,
			wantUsername: "alpine",
		},
		{
			name: "when_only_final_guest_candidate_is_vulnerable_verifies_guest_account",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService, func(t *testing.T, sleepCalls int32)) {
				srv, err := fakessh.New(&ssh.ServerConfig{
					ServerVersion: testOpenSSHBanner,
					PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
						if c.User() == "guest" && len(pass) == probePasswordLen {
							return nil, nil
						}
						return nil, fmt.Errorf("auth failed")
					},
				})
				if err != nil {
					t.Fatalf("fakessh.New failed: %v", err)
				}
				t.Cleanup(func() { _ = srv.Close() })
				return t.Context(), srv.NetworkService(), nil
			},
			wantFindings: true,
			wantUsername: "guest",
		},
		{
			name: "when_patched_openssh_rejects_long_password_returns_no_findings",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService, func(t *testing.T, sleepCalls int32)) {
				srv, err := fakessh.New(&ssh.ServerConfig{
					ServerVersion: testOpenSSHBanner,
					PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
						if c.User() == "dummy" && string(pass) == "StrongPassword123!" {
							return nil, nil
						}
						return nil, fmt.Errorf("auth failed")
					},
				})
				if err != nil {
					t.Fatalf("fakessh.New failed: %v", err)
				}
				t.Cleanup(func() { _ = srv.Close() })
				return t.Context(), srv.NetworkService(), nil
			},
			wantFindings: false,
		},
		{
			name: "when_second_long_password_rejected_returns_no_findings",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService, func(t *testing.T, sleepCalls int32)) {
				srv, err := fakessh.New(&ssh.ServerConfig{
					ServerVersion: testOpenSSHBanner,
					PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
						if c.User() == "root" && string(pass) == strings.Repeat("A", probePasswordLen) {
							return nil, nil
						}
						return nil, fmt.Errorf("auth failed")
					},
				})
				if err != nil {
					t.Fatalf("fakessh.New failed: %v", err)
				}
				t.Cleanup(func() { _ = srv.Close() })
				return t.Context(), srv.NetworkService(), nil
			},
			wantFindings: false,
		},
		{
			name: "when_honeypot_accepts_short_password_returns_no_findings",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService, func(t *testing.T, sleepCalls int32)) {
				srv, err := fakessh.New(&ssh.ServerConfig{
					ServerVersion: testOpenSSHBanner,
					PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
						return nil, nil
					},
				})
				if err != nil {
					t.Fatalf("fakessh.New failed: %v", err)
				}
				t.Cleanup(func() { _ = srv.Close() })
				return t.Context(), srv.NetworkService(), nil
			},
			wantFindings: false,
		},
		{
			name: "when_first_user_accepts_short_password_continues_and_verifies_later_locked_user",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService, func(t *testing.T, sleepCalls int32)) {
				srv, err := fakessh.New(&ssh.ServerConfig{
					ServerVersion: testOpenSSHBanner,
					PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
						if c.User() == "root" {
							return nil, nil
						}
						if c.User() == "alpine" && len(pass) == probePasswordLen {
							return nil, nil
						}
						return nil, fmt.Errorf("auth failed")
					},
				})
				if err != nil {
					t.Fatalf("fakessh.New failed: %v", err)
				}
				t.Cleanup(func() { _ = srv.Close() })
				return t.Context(), srv.NetworkService(), nil
			},
			wantFindings: true,
			wantUsername: "alpine",
		},
		{
			name: "when_non_openssh_dropbear_banner_aborts_after_single_connection",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService, func(t *testing.T, sleepCalls int32)) {
				srv, err := fakessh.New(&ssh.ServerConfig{
					ServerVersion: "SSH-2.0-dropbear_2024.85",
					PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
						if len(pass) > 256 {
							return nil, nil
						}
						return nil, fmt.Errorf("auth failed")
					},
				})
				if err != nil {
					t.Fatalf("fakessh.New failed: %v", err)
				}
				t.Cleanup(func() { _ = srv.Close() })
				proxyAddr, connCount := startCountingTCPProxy(t, srv.Addr(), nil)
				return t.Context(), makeServiceForAddr(t, proxyAddr, "ssh"), func(t *testing.T, sleepCalls int32) {
					if got := connCount.Load(); got != 1 {
						t.Errorf("connection count on Dropbear banner = %d, want 1", got)
					}
					if sleepCalls != 0 {
						t.Errorf("sleepCalls = %d, want 0", sleepCalls)
					}
				}
			},
			wantFindings: false,
		},
		{
			name: "when_password_auth_unsupported_aborts_after_single_connection",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService, func(t *testing.T, sleepCalls int32)) {
				srv, err := fakessh.New(&ssh.ServerConfig{
					ServerVersion: testOpenSSHBanner,
					PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
						return nil, fmt.Errorf("publickey only")
					},
				})
				if err != nil {
					t.Fatalf("fakessh.New failed: %v", err)
				}
				t.Cleanup(func() { _ = srv.Close() })
				proxyAddr, connCount := startCountingTCPProxy(t, srv.Addr(), nil)
				return t.Context(), makeServiceForAddr(t, proxyAddr, "ssh"), func(t *testing.T, sleepCalls int32) {
					if got := connCount.Load(); got != 1 {
						t.Errorf("connection count on PublicKeyOnly server = %d, want 1", got)
					}
					if sleepCalls != 0 {
						t.Errorf("sleepCalls = %d, want 0", sleepCalls)
					}
				}
			},
			wantFindings: false,
		},
		{
			name: "when_connection_refused_aborts_immediately_with_zero_sleeps",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService, func(t *testing.T, sleepCalls int32)) {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatalf("net.Listen failed: %v", err)
				}
				addr := listener.Addr().String()
				_ = listener.Close()
				return t.Context(), makeServiceForAddr(t, addr, "ssh"), func(t *testing.T, sleepCalls int32) {
					if sleepCalls != 0 {
						t.Errorf("sleepCalls = %d, want 0 on ECONNREFUSED", sleepCalls)
					}
				}
			},
			wantFindings: false,
		},
		{
			name: "when_unconfirmed_endpoint_drops_with_zero_bytes_performs_zero_retries_even_when_labeled_ssh",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService, func(t *testing.T, sleepCalls int32)) {
				proxyAddr, connCount := startCountingTCPProxy(t, "127.0.0.1:1", func(int32) bool { return true })
				return t.Context(), makeServiceForAddr(t, proxyAddr, "ssh"), func(t *testing.T, sleepCalls int32) {
					if got := connCount.Load(); got != 1 {
						t.Errorf("connection count on unconfirmed 0-byte drop = %d, want 1", got)
					}
					if sleepCalls != 0 {
						t.Errorf("sleepCalls = %d, want 0 on unconfirmed 0-byte drop", sleepCalls)
					}
				}
			},
			wantFindings: false,
		},
		{
			name: "when_openssh_banner_confirmed_on_any_port_retries_subsequent_zero_byte_drops",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService, func(t *testing.T, sleepCalls int32)) {
				srv, err := fakessh.New(&ssh.ServerConfig{
					ServerVersion: testOpenSSHBanner,
					PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
						if c.User() == "alpine" && len(pass) == probePasswordLen {
							return nil, nil
						}
						return nil, fmt.Errorf("auth failed")
					},
				})
				if err != nil {
					t.Fatalf("fakessh.New failed: %v", err)
				}
				t.Cleanup(func() { _ = srv.Close() })
				// Conn #1 ("root") reaches OpenSSH and gets rejected; Conns #2-#3 drop with 0 bytes; Conn #4+ reach "alpine".
				proxyAddr, _ := startCountingTCPProxy(t, srv.Addr(), func(n int32) bool {
					return n == 2 || n == 3
				})
				return t.Context(), makeServiceForAddr(t, proxyAddr, ""), func(t *testing.T, sleepCalls int32) {
					if sleepCalls != 2 {
						t.Errorf("sleepCalls = %d, want 2", sleepCalls)
					}
				}
			},
			wantFindings: true,
			wantUsername: "alpine",
		},
		{
			name: "when_cumulative_penalty_retries_exhausted_across_users_stops_at_per_service_cap",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService, func(t *testing.T, sleepCalls int32)) {
				srv, err := fakessh.New(&ssh.ServerConfig{
					ServerVersion: testOpenSSHBanner,
					PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
						return nil, fmt.Errorf("auth failed")
					},
				})
				if err != nil {
					t.Fatalf("fakessh.New failed: %v", err)
				}
				t.Cleanup(func() { _ = srv.Close() })
				// Conn #1 ("root") reaches OpenSSH and gets rejected (confirming OpenSSH); Conns #2+ drop forever (10 sleeps, then abort).
				proxyAddr, connCount := startCountingTCPProxy(t, srv.Addr(), func(n int32) bool {
					return n >= 2
				})
				return t.Context(), makeServiceForAddr(t, proxyAddr, ""), func(t *testing.T, sleepCalls int32) {
					if sleepCalls != maxPenaltyCooldownRetries {
						t.Errorf("sleepCalls = %d, want cumulative cap %d", sleepCalls, maxPenaltyCooldownRetries)
					}
					if got, want := connCount.Load(), int32(2+maxPenaltyCooldownRetries); got != want {
						t.Errorf("connCount = %d, want %d", got, want)
					}
				}
			},
			wantFindings: false,
		},
		{
			name: "when_context_canceled_during_penalty_sleep_returns_canceled_error",
			customSleepFn: func(t *testing.T, sleepCalls *atomic.Int32) func(context.Context, time.Duration) error {
				return func(ctx context.Context, _ time.Duration) error {
					sleepCalls.Add(1)
					return context.Canceled
				}
			},
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService, func(t *testing.T, sleepCalls int32)) {
				srv, err := fakessh.New(&ssh.ServerConfig{
					ServerVersion: testOpenSSHBanner,
					PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
						return nil, fmt.Errorf("auth failed")
					},
				})
				if err != nil {
					t.Fatalf("fakessh.New failed: %v", err)
				}
				t.Cleanup(func() { _ = srv.Close() })
				proxyAddr, connCount := startCountingTCPProxy(t, srv.Addr(), func(n int32) bool {
					return n >= 2
				})
				return t.Context(), makeServiceForAddr(t, proxyAddr, ""), func(t *testing.T, sleepCalls int32) {
					if sleepCalls != 1 {
						t.Errorf("sleepCalls = %d, want 1", sleepCalls)
					}
					if got := connCount.Load(); got != 2 {
						t.Errorf("connCount = %d, want 2", got)
					}
				}
			},
			wantFindings: false,
			wantErr:      context.Canceled,
		},
		{
			name: "when_web_service_returns_no_findings",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService, func(t *testing.T, sleepCalls int32)) {
				svc := nspb.NetworkService_builder{
					ServiceName:          "http",
					SupportedHttpMethods: []string{"GET"},
					NetworkEndpoint: npb.NetworkEndpoint_builder{
						Type:      npb.NetworkEndpoint_IP_PORT,
						IpAddress: npb.IpAddress_builder{Address: "127.0.0.1"}.Build(),
						Port:      npb.Port_builder{PortNumber: 80}.Build(),
					}.Build(),
				}.Build()
				return t.Context(), svc, nil
			},
			wantFindings: false,
		},
		{
			name: "when_tls_service_returns_no_findings",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService, func(t *testing.T, sleepCalls int32)) {
				svc := nspb.NetworkService_builder{
					ServiceName:          "unknown",
					SupportedSslVersions: []string{"TLSv1.3"},
					NetworkEndpoint: npb.NetworkEndpoint_builder{
						Type:      npb.NetworkEndpoint_IP_PORT,
						IpAddress: npb.IpAddress_builder{Address: "127.0.0.1"}.Build(),
						Port:      npb.Port_builder{PortNumber: 2222}.Build(),
					}.Build(),
				}.Build()
				return t.Context(), svc, nil
			},
			wantFindings: false,
		},
		{
			name: "when_udp_service_returns_no_findings",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService, func(t *testing.T, sleepCalls int32)) {
				svc := nspb.NetworkService_builder{
					ServiceName:       "ssh",
					TransportProtocol: npb.TransportProtocol_UDP,
					NetworkEndpoint: npb.NetworkEndpoint_builder{
						Type:      npb.NetworkEndpoint_IP_PORT,
						IpAddress: npb.IpAddress_builder{Address: "127.0.0.1"}.Build(),
						Port:      npb.Port_builder{PortNumber: 22}.Build(),
					}.Build(),
				}.Build()
				return t.Context(), svc, nil
			},
			wantFindings: false,
		},
		{
			name: "when_invalid_network_endpoint_returns_error",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService, func(t *testing.T, sleepCalls int32)) {
				svc := nspb.NetworkService_builder{
					ServiceName:     "ssh",
					NetworkEndpoint: npb.NetworkEndpoint_builder{}.Build(),
				}.Build()
				return t.Context(), svc, nil
			},
			wantFindings: false,
			wantErr:      netendpoint.ErrEndpointMissingAddress,
		},
		{
			name: "when_context_canceled_before_start_returns_error",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService, func(t *testing.T, sleepCalls int32)) {
				ctx, cancel := context.WithCancel(t.Context())
				cancel()
				svc := nspb.NetworkService_builder{ServiceName: "ssh"}.Build()
				return ctx, svc, nil
			},
			wantFindings: false,
			wantErr:      context.Canceled,
		},
		{
			name: "when_context_canceled_during_first_probe_returns_error",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService, func(t *testing.T, sleepCalls int32)) {
				ctx, cancel := context.WithCancel(t.Context())
				srv, err := fakessh.New(&ssh.ServerConfig{
					ServerVersion: testOpenSSHBanner,
					PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
						cancel()
						return nil, fmt.Errorf("aborted")
					},
				})
				if err != nil {
					t.Fatalf("fakessh.New failed: %v", err)
				}
				t.Cleanup(func() { _ = srv.Close() })
				return ctx, srv.NetworkService(), nil
			},
			wantFindings: false,
			wantErr:      context.Canceled,
		},
		{
			name: "when_context_canceled_during_second_probe_returns_error",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService, func(t *testing.T, sleepCalls int32)) {
				ctx, cancel := context.WithCancel(t.Context())
				var attempts atomic.Int32
				srv, err := fakessh.New(&ssh.ServerConfig{
					ServerVersion: testOpenSSHBanner,
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
				return ctx, srv.NetworkService(), nil
			},
			wantFindings: false,
			wantErr:      context.Canceled,
		},
		{
			name: "when_context_canceled_during_short_probe_returns_error",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService, func(t *testing.T, sleepCalls int32)) {
				ctx, cancel := context.WithCancel(t.Context())
				var attempts atomic.Int32
				srv, err := fakessh.New(&ssh.ServerConfig{
					ServerVersion: testOpenSSHBanner,
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
				return ctx, srv.NetworkService(), nil
			},
			wantFindings: false,
			wantErr:      context.Canceled,
		},
		{
			name: "when_non_ssh_service_hangs_past_timeout_returns_no_findings_with_zero_sleeps",
			cfg: config.FromProto(cpb.Config_builder{
				Clients: cpb.ClientsConfig_builder{
					Ssh: sccpb.SSHClientConfig_builder{
						TimeoutSeconds: proto.Int32(1),
					}.Build(),
				}.Build(),
			}.Build()),
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService, func(t *testing.T, sleepCalls int32)) {
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
					conn, acceptErr := listener.Accept()
					if acceptErr != nil {
						return
					}
					defer conn.Close()
					<-done
				}()
				return t.Context(), makeServiceForAddr(t, listener.Addr().String(), "ssh"), func(t *testing.T, sleepCalls int32) {
					if sleepCalls != 0 {
						t.Errorf("sleepCalls = %d, want 0 on silent timeout", sleepCalls)
					}
				}
			},
			wantFindings: false,
		},
		{
			name: "when_non_ssh_service_sends_http_banner_returns_no_findings_after_one_connection",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService, func(t *testing.T, sleepCalls int32)) {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatalf("net.Listen failed: %v", err)
				}
				var accepts atomic.Int32
				t.Cleanup(func() { _ = listener.Close() })
				go func() {
					for {
						conn, acceptErr := listener.Accept()
						if acceptErr != nil {
							return
						}
						accepts.Add(1)
						_, _ = conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
						_ = conn.Close()
					}
				}()
				return t.Context(), makeServiceForAddr(t, listener.Addr().String(), "ssh"), func(t *testing.T, sleepCalls int32) {
					if got := accepts.Load(); got != 1 {
						t.Errorf("accepts = %d, want 1", got)
					}
					if sleepCalls != 0 {
						t.Errorf("sleepCalls = %d, want 0", sleepCalls)
					}
				}
			},
			wantFindings: false,
		},
		{
			name: "when_short_probe_connection_refused_returns_no_findings",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService, func(t *testing.T, sleepCalls int32)) {
				ready := make(chan struct{})
				var attempts atomic.Int32
				var srv *fakessh.Server
				var err error
				srv, err = fakessh.New(&ssh.ServerConfig{
					ServerVersion: testOpenSSHBanner,
					PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
						<-ready
						if attempts.Add(1) == 2 {
							_ = srv.Close()
						}
						return nil, nil
					},
				})
				if err != nil {
					t.Fatalf("fakessh.New failed: %v", err)
				}
				close(ready)
				t.Cleanup(func() { _ = srv.Close() })
				return t.Context(), srv.NetworkService(), nil
			},
			wantFindings: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, svc, verifyHook := tc.setup(t)
			cfg := tc.cfg
			if cfg == nil {
				cfg = config.Default()
			}
			detector, err := New(ctx, cfg)
			if err != nil {
				t.Fatalf("New() unexpected error: %v", err)
			}
			mod := detector.(*Module)
			var sleepCalls atomic.Int32
			if tc.customSleepFn != nil {
				mod.sleepFn = tc.customSleepFn(t, &sleepCalls)
			} else {
				mod.sleepFn = func(ctx context.Context, _ time.Duration) error {
					sleepCalls.Add(1)
					return ctx.Err()
				}
			}

			reports, err := mod.Detect(ctx, svc)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Detect() error = %v, want %v", err, tc.wantErr)
			}
			if verifyHook != nil {
				verifyHook(t, sleepCalls.Load())
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
				wantText := fmt.Sprintf("Successfully authenticated as %q with distinct %d-byte passwords while rejecting <=256-byte passwords.", tc.wantUsername, probePasswordLen)
				details := vuln.GetAdditionalDetails()
				if len(details) != 1 || details[0].GetTextData().GetText() != wantText {
					t.Errorf("AdditionalDetails = %v, want text %q", details, wantText)
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
			Description:    "The OpenSSH server is vulnerable to a password authentication bypass when linked against musl libc. When authenticating an account whose shadow password field is '*' (such as default root or service accounts on Alpine Linux, OpenWrt, Buildroot, or Yocto) and at least one account on the system has a modular crypt password hash (such as SHA-512), supplying a password longer than 256 bytes causes musl's crypt() implementation to fail and return '*', matching the locked shadow entry and granting unauthorized access.",
			Recommendation: "Upgrade OpenSSH to a patched version (OpenSSH 10.6p2 or later upstream, or distro backports such as openssh 9.9_p2-r1 or later on Alpine Linux) and restart sshd, or disable password authentication (PasswordAuthentication no) in sshd_config.",
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
