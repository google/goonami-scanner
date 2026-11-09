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

package sshclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/goonami-scanner/common/testfakes/fakessh"
	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/log"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"

	sccpb "github.com/google/goonami-scanner/common/clients/sshclient/ssh_client_config_go_proto"
	cpb "github.com/google/goonami-scanner/core/config/config_go_proto"
)

func TestNew(t *testing.T) {
	testCases := []struct {
		name            string
		cfg             *config.Config
		expectedTimeout time.Duration
	}{
		{
			name:            "when_nil_config_uses_default_timeout",
			cfg:             nil,
			expectedTimeout: DefaultTimeout,
		},
		{
			name:            "when_empty_config_uses_global_performance_timeout",
			cfg:             config.Default(),
			expectedTimeout: 10 * time.Second,
		},
		{
			name: "when_global_performance_timeout_configured_uses_it",
			cfg: config.FromProto(
				cpb.Config_builder{
					Globalcfg: cpb.GlobalConfig_builder{
						Performance: cpb.GlobalConfig_Performance_builder{
							TimeoutPerRequestSeconds: proto.Int32(25),
						}.Build(),
					}.Build(),
				}.Build(),
			),
			expectedTimeout: 25 * time.Second,
		},
		{
			name: "when_client_ssh_timeout_configured_overrides_global",
			cfg: config.FromProto(
				cpb.Config_builder{
					Globalcfg: cpb.GlobalConfig_builder{
						Performance: cpb.GlobalConfig_Performance_builder{
							TimeoutPerRequestSeconds: proto.Int32(25),
						}.Build(),
					}.Build(),
					Clients: cpb.ClientsConfig_builder{
						Ssh: sccpb.SSHClientConfig_builder{
							TimeoutSeconds: proto.Int32(5),
						}.Build(),
					}.Build(),
				}.Build(),
			),
			expectedTimeout: 5 * time.Second,
		},
		{
			name: "when_client_ssh_timeout_explicitly_zero_uses_default_timeout",
			cfg: config.FromProto(
				cpb.Config_builder{
					Clients: cpb.ClientsConfig_builder{
						Ssh: sccpb.SSHClientConfig_builder{
							TimeoutSeconds: proto.Int32(0),
						}.Build(),
					}.Build(),
				}.Build(),
			),
			expectedTimeout: DefaultTimeout,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := New(tc.cfg)
			if client == nil {
				t.Fatal("New() returned nil client")
			}
			if got := client.Timeout(); got != tc.expectedTimeout {
				t.Errorf("client.Timeout() = %v, expected %v", got, tc.expectedTimeout)
			}
		})
	}
}

func TestDial(t *testing.T) {
	log.SetLogger(&log.DefaultLogger{VerboseLevel: log.DebugLevelRequest})
	testCases := []struct {
		name        string
		serverSetup func(t *testing.T) (string, func())
		clientSetup func(t *testing.T) (context.Context, *ssh.ClientConfig)
		wantErr     bool
	}{
		{
			name: "when_valid_config_dials_and_establishes_client",
			serverSetup: func(t *testing.T) (string, func()) {
				srv, err := fakessh.NewWithPasswordAuth("admin", "secret")
				if err != nil {
					t.Fatalf("fakessh.NewWithPasswordAuth failed: %v", err)
				}
				return srv.Addr(), func() { _ = srv.Close() }
			},
			clientSetup: func(t *testing.T) (context.Context, *ssh.ClientConfig) {
				return t.Context(), &ssh.ClientConfig{
					User: "admin",
					Auth: []ssh.AuthMethod{
						ssh.Password("secret"),
					},
					HostKeyCallback: ssh.InsecureIgnoreHostKey(),
					Timeout:         5 * time.Second,
				}
			},
			wantErr: false,
		},
		{
			name: "when_connection_refused_returns_error",
			serverSetup: func(t *testing.T) (string, func()) {
				l, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatalf("net.Listen failed: %v", err)
				}
				addr := l.Addr().String()
				_ = l.Close()
				return addr, func() {}
			},
			clientSetup: func(t *testing.T) (context.Context, *ssh.ClientConfig) {
				return t.Context(), &ssh.ClientConfig{
					User:            "admin",
					HostKeyCallback: ssh.InsecureIgnoreHostKey(),
				}
			},
			wantErr: true,
		},
		{
			name: "when_invalid_ciphers_returns_error",
			serverSetup: func(t *testing.T) (string, func()) {
				srv, err := fakessh.NewWithPasswordAuth("admin", "secret")
				if err != nil {
					t.Fatalf("fakessh.NewWithPasswordAuth failed: %v", err)
				}
				return srv.Addr(), func() { _ = srv.Close() }
			},
			clientSetup: func(t *testing.T) (context.Context, *ssh.ClientConfig) {
				return t.Context(), &ssh.ClientConfig{
					User: "admin",
					Auth: []ssh.AuthMethod{
						ssh.Password("secret"),
					},
					HostKeyCallback: ssh.InsecureIgnoreHostKey(),
					Config: ssh.Config{
						Ciphers: []string{"nonexistent-cipher"},
					},
				}
			},
			wantErr: true,
		},
		{
			name: "when_target_not_ssh_returns_error",
			serverSetup: func(t *testing.T) (string, func()) {
				ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
				return ts.Listener.Addr().String(), ts.Close
			},
			clientSetup: func(t *testing.T) (context.Context, *ssh.ClientConfig) {
				return t.Context(), &ssh.ClientConfig{
					User:            "admin",
					HostKeyCallback: ssh.InsecureIgnoreHostKey(),
				}
			},
			wantErr: true,
		},
		{
			name: "when_context_canceled_returns_error",
			serverSetup: func(t *testing.T) (string, func()) {
				srv, err := fakessh.NewWithPasswordAuth("admin", "secret")
				if err != nil {
					t.Fatalf("fakessh.NewWithPasswordAuth failed: %v", err)
				}
				return srv.Addr(), func() { _ = srv.Close() }
			},
			clientSetup: func(t *testing.T) (context.Context, *ssh.ClientConfig) {
				ctx, cancel := context.WithCancel(t.Context())
				cancel()
				return ctx, &ssh.ClientConfig{
					User: "admin",
					Auth: []ssh.AuthMethod{
						ssh.Password("secret"),
					},
					HostKeyCallback: ssh.InsecureIgnoreHostKey(),
				}
			},
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			addr, cleanup := tc.serverSetup(t)
			defer cleanup()

			ctx, clientCfg := tc.clientSetup(t)
			client := New(nil)
			sshClient, err := client.dial(ctx, addr, "", clientCfg)
			if tc.wantErr {
				if err == nil {
					_ = sshClient.Close()
					t.Fatal("dial() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("dial() unexpected error: %v", err)
			}
			if sshClient == nil {
				t.Fatal("dial() returned nil *ssh.Client")
			}
			if closeErr := sshClient.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
				t.Logf("failed to close sshClient: %v", closeErr)
			}
		})
	}
}

func TestConnect(t *testing.T) {
	log.SetLogger(&log.DefaultLogger{VerboseLevel: log.DebugLevelRequest})
	testCases := []struct {
		name        string
		serverSetup func(t *testing.T) (string, func())
		username    string
		password    string
		clientCfg   *config.Config
		expectedErr error
	}{
		{
			name: "when_valid_credentials_returns_client",
			serverSetup: func(t *testing.T) (string, func()) {
				srv, err := fakessh.NewWithPasswordAuth("admin", "secret")
				if err != nil {
					t.Fatalf("fakessh.NewWithPasswordAuth failed: %v", err)
				}
				return srv.Addr(), func() { _ = srv.Close() }
			},
			username:    "admin",
			password:    "secret",
			expectedErr: nil,
		},
		{
			name: "when_invalid_password_returns_auth_failed",
			serverSetup: func(t *testing.T) (string, func()) {
				srv, err := fakessh.NewWithPasswordAuth("admin", "secret")
				if err != nil {
					t.Fatalf("fakessh.NewWithPasswordAuth failed: %v", err)
				}
				return srv.Addr(), func() { _ = srv.Close() }
			},
			username:    "admin",
			password:    "wrongpass",
			expectedErr: ErrAuthFailed,
		},
		{
			name: "when_invalid_username_returns_auth_failed",
			serverSetup: func(t *testing.T) (string, func()) {
				srv, err := fakessh.NewWithPasswordAuth("admin", "secret")
				if err != nil {
					t.Fatalf("fakessh.NewWithPasswordAuth failed: %v", err)
				}
				return srv.Addr(), func() { _ = srv.Close() }
			},
			username:    "unknown",
			password:    "secret",
			expectedErr: ErrAuthFailed,
		},
		{
			name: "when_password_auth_unsupported_returns_unsupported_error",
			serverSetup: func(t *testing.T) (string, func()) {
				srv, err := fakessh.NewPublicKeyOnly()
				if err != nil {
					t.Fatalf("fakessh.NewPublicKeyOnly failed: %v", err)
				}
				return srv.Addr(), func() { _ = srv.Close() }
			},
			username:    "root",
			password:    "anypass",
			expectedErr: ErrPasswordAuthUnsupported,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			addr, cleanup := tc.serverSetup(t)
			defer cleanup()

			client := New(tc.clientCfg)
			sshClient, err := client.Connect(t.Context(), addr, tc.username, tc.password)
			if tc.expectedErr == nil {
				if err != nil {
					t.Fatalf("Connect() unexpected error = %v", err)
				}
				if sshClient == nil {
					t.Fatal("Connect() returned nil *ssh.Client on success")
				}
				if closeErr := sshClient.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
					t.Logf("failed to close sshClient: %v", closeErr)
				}
			} else {
				if sshClient != nil {
					_ = sshClient.Close()
					t.Fatalf("Connect() returned unexpected *ssh.Client on failure")
				}
				if !errors.Is(err, tc.expectedErr) {
					t.Fatalf("Connect() error = %v, expected errors.Is %v", err, tc.expectedErr)
				}
			}
		})
	}
}

func TestConnectWithPasswords(t *testing.T) {
	testCases := []struct {
		name        string
		serverSetup func(t *testing.T) (string, func())
		username    string
		passwords   []string
		expectedErr error
	}{
		{
			name: "when_second_password_in_connection_succeeds_returns_client",
			serverSetup: func(t *testing.T) (string, func()) {
				var attempts atomic.Int32
				srv, err := fakessh.New(&ssh.ServerConfig{
					PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
						if attempts.Add(1) == 2 && c.User() == "root" && string(pass) == "second" {
							return nil, nil
						}
						return nil, fmt.Errorf("auth failed")
					},
				})
				if err != nil {
					t.Fatalf("fakessh.New failed: %v", err)
				}
				return srv.Addr(), func() { _ = srv.Close() }
			},
			username:    "root",
			passwords:   []string{"first", "second"},
			expectedErr: nil,
		},
		{
			name: "when_all_passwords_fail_returns_auth_failed",
			serverSetup: func(t *testing.T) (string, func()) {
				srv, err := fakessh.NewWithPasswordAuth("root", "secret")
				if err != nil {
					t.Fatalf("fakessh.NewWithPasswordAuth failed: %v", err)
				}
				return srv.Addr(), func() { _ = srv.Close() }
			},
			username:    "root",
			passwords:   []string{"wrong1", "wrong2"},
			expectedErr: ErrAuthFailed,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			addr, cleanup := tc.serverSetup(t)
			defer cleanup()

			client := New(nil)
			sshClient, err := client.ConnectWithPasswords(t.Context(), addr, tc.username, tc.passwords...)
			if tc.expectedErr == nil {
				if err != nil {
					t.Fatalf("ConnectWithPasswords() unexpected error = %v", err)
				}
				if sshClient == nil {
					t.Fatal("ConnectWithPasswords() returned nil *ssh.Client on success")
				}
				_ = sshClient.Close()
			} else {
				if sshClient != nil {
					_ = sshClient.Close()
					t.Fatalf("ConnectWithPasswords() returned unexpected *ssh.Client on failure")
				}
				if !errors.Is(err, tc.expectedErr) {
					t.Fatalf("ConnectWithPasswords() error = %v, expected errors.Is %v", err, tc.expectedErr)
				}
			}
		})
	}
}

func TestConnect_NonSSHAndNetworkErrors(t *testing.T) {
	testCases := []struct {
		name        string
		setup       func(t *testing.T) string
		expectedErr error
	}{
		{
			name: "when_service_is_http_returns_not_ssh_service",
			setup: func(t *testing.T) string {
				ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
				t.Cleanup(ts.Close)
				return ts.Listener.Addr().String()
			},
			expectedErr: ErrNotSSHService,
		},
		{
			name: "when_connection_refused_returns_not_ssh_service",
			setup: func(t *testing.T) string {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatalf("net.Listen failed: %v", err)
				}
				addr := listener.Addr().String()
				if err := listener.Close(); err != nil {
					t.Fatalf("listener.Close failed: %v", err)
				}
				return addr
			},
			expectedErr: ErrNotSSHService,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			addr := tc.setup(t)
			client := New(nil)
			sshClient, err := client.Connect(t.Context(), addr, "root", "root")
			if sshClient != nil {
				_ = sshClient.Close()
				t.Fatal("Connect() returned non-nil *ssh.Client on non-SSH target")
			}
			if !errors.Is(err, tc.expectedErr) {
				t.Fatalf("Connect() error = %v, expected errors.Is %v", err, tc.expectedErr)
			}
			if errors.Is(err, ErrConnectionDropped) {
				t.Fatalf("Connect() error = %v, unexpected ErrConnectionDropped", err)
			}
		})
	}
}

func TestConnectWithBannerPrefix(t *testing.T) {
	testCases := []struct {
		name         string
		bannerPrefix string
		serverSetup  func(t *testing.T) (string, func())
		wantErr      error
		wantDropped  bool
	}{
		{
			name:         "when_matching_banner_prefix_succeeds_returns_client",
			bannerPrefix: "SSH-2.0-OpenSSH",
			serverSetup: func(t *testing.T) (string, func()) {
				srv, err := fakessh.New(&ssh.ServerConfig{
					ServerVersion: "SSH-2.0-OpenSSH_9.8",
					PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
						if c.User() == "root" && string(pass) == "secret" {
							return nil, nil
						}
						return nil, fmt.Errorf("auth failed")
					},
				})
				if err != nil {
					t.Fatalf("fakessh.New failed: %v", err)
				}
				return srv.Addr(), func() { _ = srv.Close() }
			},
			wantErr: nil,
		},
		{
			name:         "when_empty_banner_prefix_allows_any_ssh_banner_returns_client",
			bannerPrefix: "",
			serverSetup: func(t *testing.T) (string, func()) {
				srv, err := fakessh.New(&ssh.ServerConfig{
					ServerVersion: "SSH-2.0-Dropbear_2022.83",
					PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
						return nil, nil
					},
				})
				if err != nil {
					t.Fatalf("fakessh.New failed: %v", err)
				}
				return srv.Addr(), func() { _ = srv.Close() }
			},
			wantErr: nil,
		},
		{
			name:         "when_mismatched_banner_prefix_aborts_before_auth_returns_not_ssh_service",
			bannerPrefix: "SSH-2.0-OpenSSH",
			serverSetup: func(t *testing.T) (string, func()) {
				var authCalled atomic.Bool
				srv, err := fakessh.New(&ssh.ServerConfig{
					ServerVersion: "SSH-2.0-Dropbear_2022.83",
					PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
						authCalled.Store(true)
						return nil, nil
					},
				})
				if err != nil {
					t.Fatalf("fakessh.New failed: %v", err)
				}
				return srv.Addr(), func() {
					_ = srv.Close()
					if authCalled.Load() {
						t.Errorf("PasswordCallback was invoked despite banner mismatch")
					}
				}
			},
			wantErr:     ErrNotSSHService,
			wantDropped: false,
		},
		{
			name:         "when_rfc4253_pre_banner_lines_precede_matching_banner_returns_client",
			bannerPrefix: "SSH-2.0-OpenSSH",
			serverSetup: func(t *testing.T) (string, func()) {
				backend, err := fakessh.New(&ssh.ServerConfig{
					ServerVersion: "SSH-2.0-OpenSSH_10.6",
					PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
						return nil, nil
					},
				})
				if err != nil {
					t.Fatalf("fakessh.New failed: %v", err)
				}
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					_ = backend.Close()
					t.Fatalf("net.Listen failed: %v", err)
				}
				go func() {
					conn, err := listener.Accept()
					if err != nil {
						return
					}
					defer conn.Close()
					bConn, err := net.Dial("tcp", backend.Addr())
					if err != nil {
						return
					}
					defer bConn.Close()
					_, _ = conn.Write([]byte("Authorized users only\r\n"))
					go func() { _, _ = io.Copy(conn, bConn) }()
					_, _ = io.Copy(bConn, conn)
				}()
				return listener.Addr().String(), func() {
					_ = listener.Close()
					_ = backend.Close()
				}
			},
			wantErr: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			addr, cleanup := tc.serverSetup(t)
			defer cleanup()

			client := New(nil)
			sshClient, err := client.ConnectWithBannerPrefix(t.Context(), addr, "root", tc.bannerPrefix, "secret")
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("ConnectWithBannerPrefix() unexpected error = %v", err)
				}
				if sshClient == nil {
					t.Fatal("ConnectWithBannerPrefix() returned nil *ssh.Client on success")
				}
				_ = sshClient.Close()
				return
			}
			if sshClient != nil {
				_ = sshClient.Close()
				t.Fatal("ConnectWithBannerPrefix() returned non-nil *ssh.Client on error")
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("ConnectWithBannerPrefix() error = %v, want errors.Is %v", err, tc.wantErr)
			}
			if got := errors.Is(err, ErrConnectionDropped); got != tc.wantDropped {
				t.Fatalf("errors.Is(err, ErrConnectionDropped) = %v, want %v (err = %v)", got, tc.wantDropped, err)
			}
		})
	}
}

func TestConnect_PreBannerDrops(t *testing.T) {
	testCases := []struct {
		name        string
		handleConn  func(conn net.Conn)
		wantDropped bool
	}{
		{
			name: "when_empty_pre_banner_eof_returns_connection_dropped",
			handleConn: func(conn net.Conn) {
				_ = conn.Close()
			},
			wantDropped: true,
		},
		{
			name: "when_openssh_penalty_message_before_eof_returns_connection_dropped",
			handleConn: func(conn net.Conn) {
				_, _ = conn.Write([]byte("Not allowed at this time\r\n"))
				_ = conn.Close()
			},
			wantDropped: true,
		},
		{
			name: "when_openssh_maxstartups_message_before_eof_returns_connection_dropped",
			handleConn: func(conn net.Conn) {
				_, _ = conn.Write([]byte("Exceeded MaxStartups\r\n"))
				_ = conn.Close()
			},
			wantDropped: true,
		},
		{
			name: "when_pre_banner_tcp_rst_returns_connection_dropped",
			handleConn: func(conn net.Conn) {
				var buf [4]byte
				_, _ = conn.Read(buf[:])
				if tcpConn, ok := conn.(*net.TCPConn); ok {
					_ = tcpConn.SetLinger(0)
				}
				_ = conn.Close()
			},
			wantDropped: true,
		},
		{
			name: "when_non_ssh_banner_before_eof_returns_not_ssh_without_connection_dropped",
			handleConn: func(conn net.Conn) {
				_, _ = conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
				_ = conn.Close()
			},
			wantDropped: false,
		},
		{
			name: "when_oversized_non_ssh_response_before_eof_returns_not_ssh_without_connection_dropped",
			handleConn: func(conn net.Conn) {
				_, _ = conn.Write([]byte(strings.Repeat("X", 300) + "\r\n"))
				_ = conn.Close()
			},
			wantDropped: false,
		},
		{
			name: "when_post_banner_kex_eof_returns_not_ssh_without_connection_dropped",
			handleConn: func(conn net.Conn) {
				_, _ = conn.Write([]byte("SSH-2.0-OpenSSH_9.8\r\n"))
				_ = conn.Close()
			},
			wantDropped: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("net.Listen failed: %v", err)
			}
			t.Cleanup(func() { _ = listener.Close() })
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				tc.handleConn(conn)
			}()

			client := New(nil)
			sshClient, err := client.ConnectWithBannerPrefix(t.Context(), listener.Addr().String(), "root", "SSH-2.0-OpenSSH", "pass")
			if sshClient != nil {
				_ = sshClient.Close()
				t.Fatal("ConnectWithBannerPrefix() returned unexpected non-nil *ssh.Client")
			}
			if !errors.Is(err, ErrNotSSHService) {
				t.Fatalf("ConnectWithBannerPrefix() error = %v, want errors.Is(ErrNotSSHService)", err)
			}
			if got := errors.Is(err, ErrConnectionDropped); got != tc.wantDropped {
				t.Fatalf("errors.Is(err, ErrConnectionDropped) = %v, want %v (err = %v)", got, tc.wantDropped, err)
			}
		})
	}
}

func TestIsConnectionDropError(t *testing.T) {
	testCases := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "when_io_eof_returns_true",
			err:  io.EOF,
			want: true,
		},
		{
			name: "when_io_err_unexpected_eof_returns_true",
			err:  io.ErrUnexpectedEOF,
			want: true,
		},
		{
			name: "when_connection_reset_by_peer_returns_true",
			err:  errors.New("read tcp 127.0.0.1:1234->127.0.0.1:22: read: connection reset by peer"),
			want: true,
		},
		{
			name: "when_connection_refused_returns_false",
			err:  errors.New("dial tcp 127.0.0.1:22: connect: connection refused"),
			want: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isConnectionDropError(tc.err); got != tc.want {
				t.Errorf("isConnectionDropError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestBannerConn_IsPreBannerDrop(t *testing.T) {
	canceledCtx, cancel := context.WithCancel(t.Context())
	cancel()

	testCases := []struct {
		name       string
		bc         *bannerConn
		ctx        context.Context
		err        error
		wantResult bool
	}{
		{
			name:       "when_empty_pre_banner_and_eof_returns_true",
			bc:         &bannerConn{},
			ctx:        t.Context(),
			err:        io.EOF,
			wantResult: true,
		},
		{
			name: "when_banner_already_seen_returns_false",
			bc: &bannerConn{
				bannerSeen: true,
				preBanner:  []byte("Not allowed at this time\r\n"),
			},
			ctx:        t.Context(),
			err:        io.ErrUnexpectedEOF,
			wantResult: false,
		},
		{
			name:       "when_context_canceled_returns_false",
			bc:         &bannerConn{},
			ctx:        canceledCtx,
			err:        io.EOF,
			wantResult: false,
		},
		{
			name:       "when_non_drop_error_returns_false",
			bc:         &bannerConn{},
			ctx:        t.Context(),
			err:        net.ErrClosed,
			wantResult: false,
		},
		{
			name: "when_unrelated_pre_banner_payload_returns_false",
			bc: &bannerConn{
				preBanner: []byte("220 smtp.example.com ESMTP\r\n"),
			},
			ctx:        t.Context(),
			err:        io.EOF,
			wantResult: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.bc.isPreBannerDrop(tc.ctx, tc.err); got != tc.wantResult {
				t.Errorf("isPreBannerDrop() = %v, want %v", got, tc.wantResult)
			}
		})
	}
}

func TestConnect_ContextErrors(t *testing.T) {
	testCases := []struct {
		name        string
		setupClient func(t *testing.T) (*Client, context.Context)
		expectedErr error
	}{
		{
			name: "when_context_canceled_returns_canceled_error",
			setupClient: func(t *testing.T) (*Client, context.Context) {
				ctx, cancel := context.WithCancel(t.Context())
				cancel()
				client := New(nil)
				return client, ctx
			},
			expectedErr: context.Canceled,
		},
		{
			name: "when_context_deadline_exceeded_returns_deadline_error",
			setupClient: func(t *testing.T) (*Client, context.Context) {
				ctx, cancel := context.WithTimeout(t.Context(), 1*time.Nanosecond)
				defer cancel()
				time.Sleep(2 * time.Millisecond)
				client := New(nil)
				return client, ctx
			},
			expectedErr: context.DeadlineExceeded,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client, ctx := tc.setupClient(t)
			sshClient, err := client.Connect(ctx, "127.0.0.1:22", "user", "pass")
			if sshClient != nil {
				_ = sshClient.Close()
				t.Fatal("Connect() returned non-nil *ssh.Client on context error")
			}
			if !errors.Is(err, tc.expectedErr) {
				t.Fatalf("Connect() error = %v, expected errors.Is %v", err, tc.expectedErr)
			}
			if errors.Is(err, ErrConnectionDropped) {
				t.Fatalf("Connect() error = %v, unexpected ErrConnectionDropped", err)
			}
		})
	}
}

func TestClassifyError(t *testing.T) {
	testCases := []struct {
		name        string
		inputErr    error
		expectedErr error
	}{
		{
			name:        "when_nil_error_returns_nil",
			inputErr:    nil,
			expectedErr: nil,
		},
		{
			name:        "when_already_err_password_auth_unsupported_returns_same",
			inputErr:    ErrPasswordAuthUnsupported,
			expectedErr: ErrPasswordAuthUnsupported,
		},
		{
			name:        "when_already_err_auth_failed_returns_same",
			inputErr:    ErrAuthFailed,
			expectedErr: ErrAuthFailed,
		},
		{
			name:        "when_already_err_not_ssh_service_returns_same",
			inputErr:    ErrNotSSHService,
			expectedErr: ErrNotSSHService,
		},
		{
			name:        "when_context_canceled_returns_same",
			inputErr:    context.Canceled,
			expectedErr: context.Canceled,
		},
		{
			name:        "when_context_deadline_exceeded_returns_same",
			inputErr:    context.DeadlineExceeded,
			expectedErr: context.DeadlineExceeded,
		},
		{
			name:        "when_attempted_methods_none_returns_password_auth_unsupported",
			inputErr:    errors.New("ssh: handshake failed: ssh: unable to authenticate, attempted methods [none], no supported methods remain"),
			expectedErr: ErrPasswordAuthUnsupported,
		},
		{
			name:        "when_attempted_methods_password_returns_auth_failed",
			inputErr:    errors.New("ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password], no supported methods remain"),
			expectedErr: ErrAuthFailed,
		},
		{
			name:        "when_unable_to_authenticate_returns_auth_failed",
			inputErr:    errors.New("ssh: unable to authenticate"),
			expectedErr: ErrAuthFailed,
		},
		{
			name:        "when_password_auth_failed_returns_auth_failed",
			inputErr:    errors.New("ssh: password auth failed"),
			expectedErr: ErrAuthFailed,
		},
		{
			name:        "when_failed_authentication_returns_auth_failed",
			inputErr:    errors.New("failed authentication for user root"),
			expectedErr: ErrAuthFailed,
		},
		{
			name:        "when_too_many_authentication_failures_returns_auth_failed",
			inputErr:    errors.New("ssh: disconnect, reason 2: too many authentication failures"),
			expectedErr: ErrAuthFailed,
		},
		{
			name:        "when_no_version_identifier_returns_not_ssh_service",
			inputErr:    errors.New("ssh: no version identifier in server response"),
			expectedErr: ErrNotSSHService,
		},
		{
			name:        "when_banner_illegal_returns_not_ssh_service",
			inputErr:    errors.New("ssh: banner header contains illegal character"),
			expectedErr: ErrNotSSHService,
		},
		{
			name:        "when_overflow_version_returns_not_ssh_service",
			inputErr:    errors.New("ssh: overflow reading version string"),
			expectedErr: ErrNotSSHService,
		},
		{
			name:        "when_no_common_algorithm_returns_not_ssh_service",
			inputErr:    errors.New("ssh: no common algorithm for key exchange"),
			expectedErr: ErrNotSSHService,
		},
		{
			name:        "when_protocol_version_mismatch_returns_not_ssh_service",
			inputErr:    errors.New("ssh: protocol version mismatch"),
			expectedErr: ErrNotSSHService,
		},
		{
			name:        "when_connection_refused_returns_not_ssh_service",
			inputErr:    errors.New("dial tcp 127.0.0.1:22: connect: connection refused"),
			expectedErr: ErrNotSSHService,
		},
		{
			name:        "when_connection_reset_by_peer_returns_not_ssh_service",
			inputErr:    errors.New("read tcp 127.0.0.1:22: read: connection reset by peer"),
			expectedErr: ErrNotSSHService,
		},
		{
			name:        "when_io_eof_returns_not_ssh_service",
			inputErr:    io.EOF,
			expectedErr: ErrNotSSHService,
		},
		{
			name:        "when_io_err_unexpected_eof_returns_not_ssh_service",
			inputErr:    io.ErrUnexpectedEOF,
			expectedErr: ErrNotSSHService,
		},
		{
			name:        "when_wrapped_err_connection_dropped_preserves_dropped_sentinel",
			inputErr:    fmt.Errorf("%w: %w: %w", ErrNotSSHService, ErrConnectionDropped, io.EOF),
			expectedErr: ErrConnectionDropped,
		},
		{
			name:        "when_no_route_to_host_returns_not_ssh_service",
			inputErr:    errors.New("dial tcp 10.0.0.1:22: connect: no route to host"),
			expectedErr: ErrNotSSHService,
		},
		{
			name:        "when_unrecognized_error_returns_verbatim",
			inputErr:    errors.New("something totally unexpected"),
			expectedErr: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyError(tc.inputErr)
			if tc.expectedErr == nil {
				if tc.inputErr == nil && got != nil {
					t.Errorf("ClassifyError(nil) = %v, expected nil", got)
				}
				if tc.inputErr != nil && (got == nil || got.Error() != tc.inputErr.Error()) {
					t.Errorf("ClassifyError(%v) = %v, expected verbatim error", tc.inputErr, got)
				}
				return
			}
			if !errors.Is(got, tc.expectedErr) {
				t.Errorf("ClassifyError(%v) = %v, expected errors.Is %v", tc.inputErr, got, tc.expectedErr)
			}
			if tc.inputErr != nil && !errors.Is(got, tc.inputErr) && !strings.Contains(got.Error(), tc.inputErr.Error()) {
				t.Errorf("ClassifyError(%v) = %v, expected to contain original error message", tc.inputErr, got)
			}
		})
	}
}
