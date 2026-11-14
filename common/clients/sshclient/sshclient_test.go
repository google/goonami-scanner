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
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"weak"

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
		name                 string
		serverSetup          func(t *testing.T) (string, func())
		clientSetup          func(t *testing.T) (context.Context, *ssh.ClientConfig)
		wantErr              bool
		wantDroppedPreBanner bool
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
		{
			name: "when_peer_closes_before_banner_sets_dropped_pre_banner_true",
			serverSetup: func(t *testing.T) (string, func()) {
				addr := startFakeTCPServer(t, func(conn net.Conn) {
					_ = conn.Close()
				})
				return addr, func() {}
			},
			clientSetup: func(t *testing.T) (context.Context, *ssh.ClientConfig) {
				return t.Context(), &ssh.ClientConfig{
					User:            "admin",
					HostKeyCallback: ssh.InsecureIgnoreHostKey(),
				}
			},
			wantErr:              true,
			wantDroppedPreBanner: true,
		},
		{
			name: "when_context_deadline_exceeded_on_silent_tarpit_sets_dropped_pre_banner_false",
			serverSetup: func(t *testing.T) (string, func()) {
				done := make(chan struct{})
				addr := startFakeTCPServer(t, func(conn net.Conn) {
					<-done
				})
				return addr, func() { close(done) }
			},
			clientSetup: func(t *testing.T) (context.Context, *ssh.ClientConfig) {
				ctx, cancel := context.WithTimeout(t.Context(), 25*time.Millisecond)
				t.Cleanup(cancel)
				return ctx, &ssh.ClientConfig{
					User:            "admin",
					HostKeyCallback: ssh.InsecureIgnoreHostKey(),
				}
			},
			wantErr:              true,
			wantDroppedPreBanner: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			addr, cleanup := tc.serverSetup(t)
			defer cleanup()

			ctx, clientCfg := tc.clientSetup(t)
			client := New(nil)
			sshClient, _, droppedPreBanner, err := client.dial(ctx, addr, clientCfg)
			if tc.wantErr {
				if err == nil {
					_ = sshClient.Close()
					t.Fatal("dial() expected error, got nil")
				}
				if droppedPreBanner != tc.wantDroppedPreBanner {
					t.Errorf("dial() droppedPreBanner = %v, want %v (err=%v)", droppedPreBanner, tc.wantDroppedPreBanner, err)
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
		{
			name: "when_keyboard_interactive_valid_credentials_returns_client",
			serverSetup: func(t *testing.T) (string, func()) {
				srv, err := fakessh.NewWithKeyboardInteractiveAuth("admin", "secret")
				if err != nil {
					t.Fatalf("fakessh.NewWithKeyboardInteractiveAuth failed: %v", err)
				}
				return srv.Addr(), func() { _ = srv.Close() }
			},
			username:    "admin",
			password:    "secret",
			expectedErr: nil,
		},
		{
			name: "when_keyboard_interactive_invalid_password_returns_auth_failed",
			serverSetup: func(t *testing.T) (string, func()) {
				srv, err := fakessh.NewWithKeyboardInteractiveAuth("admin", "secret")
				if err != nil {
					t.Fatalf("fakessh.NewWithKeyboardInteractiveAuth failed: %v", err)
				}
				return srv.Addr(), func() { _ = srv.Close() }
			},
			username:    "admin",
			password:    "wrongpass",
			expectedErr: ErrAuthFailed,
		},
		{
			name: "when_keyboard_interactive_with_info_banners_and_valid_password_returns_client",
			serverSetup: func(t *testing.T) (string, func()) {
				srv, err := fakessh.New(&ssh.ServerConfig{
					KeyboardInteractiveCallback: func(c ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
						if _, err := client("Notice", "Banner line", nil, nil); err != nil {
							return nil, err
						}
						answers, err := client("", "", []string{"Password: "}, []bool{false})
						if err != nil {
							return nil, err
						}
						if _, err := client("Authenticated", "Welcome", nil, nil); err != nil {
							return nil, err
						}
						if len(answers) == 1 && c.User() == "admin" && answers[0] == "secret" {
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
			username:    "admin",
			password:    "secret",
			expectedErr: nil,
		},
		{
			name: "when_keyboard_interactive_zero_prompt_passwordless_account_authenticates_empty_password",
			serverSetup: func(t *testing.T) (string, func()) {
				srv, err := fakessh.New(&ssh.ServerConfig{
					KeyboardInteractiveCallback: func(c ssh.ConnMetadata, _ ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
						if c.User() == "alpine" {
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
			username:    "alpine",
			password:    "",
			expectedErr: nil,
		},
		{
			name: "when_keyboard_interactive_zero_prompt_passwordless_account_rejects_non_empty_password",
			serverSetup: func(t *testing.T) (string, func()) {
				srv, err := fakessh.New(&ssh.ServerConfig{
					KeyboardInteractiveCallback: func(c ssh.ConnMetadata, _ ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
						if c.User() == "alpine" {
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
			username:    "alpine",
			password:    "non-empty-canary",
			expectedErr: ErrAuthFailed,
		},
		{
			name: "when_keyboard_interactive_excessive_empty_prompts_returns_auth_failed",
			serverSetup: func(t *testing.T) (string, func()) {
				srv, err := fakessh.New(&ssh.ServerConfig{
					KeyboardInteractiveCallback: func(c ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
						for range maxKeyboardInteractiveEmptyPrompts + 2 {
							if _, err := client("", "info", nil, nil); err != nil {
								return nil, err
							}
						}
						return nil, fmt.Errorf("auth failed")
					},
				})
				if err != nil {
					t.Fatalf("fakessh.New failed: %v", err)
				}
				return srv.Addr(), func() { _ = srv.Close() }
			},
			username:    "admin",
			password:    "secret",
			expectedErr: ErrAuthFailed,
		},
		{
			name: "when_keyboard_interactive_multi_question_prompt_returns_auth_failed",
			serverSetup: func(t *testing.T) (string, func()) {
				srv, err := fakessh.New(&ssh.ServerConfig{
					KeyboardInteractiveCallback: func(c ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
						if _, err := client("", "", []string{"Password: ", "OTP: "}, []bool{false, false}); err != nil {
							return nil, err
						}
						return nil, fmt.Errorf("auth failed")
					},
				})
				if err != nil {
					t.Fatalf("fakessh.New failed: %v", err)
				}
				return srv.Addr(), func() { _ = srv.Close() }
			},
			username:    "admin",
			password:    "secret",
			expectedErr: ErrAuthFailed,
		},
		{
			name: "when_keyboard_interactive_second_prompt_in_same_attempt_returns_auth_failed",
			serverSetup: func(t *testing.T) (string, func()) {
				srv, err := fakessh.New(&ssh.ServerConfig{
					KeyboardInteractiveCallback: func(c ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
						if _, err := client("", "", []string{"Password: "}, []bool{false}); err != nil {
							return nil, err
						}
						if _, err := client("", "", []string{"Verification code: "}, []bool{false}); err != nil {
							return nil, err
						}
						return nil, fmt.Errorf("auth failed")
					},
				})
				if err != nil {
					t.Fatalf("fakessh.New failed: %v", err)
				}
				return srv.Addr(), func() { _ = srv.Close() }
			},
			username:    "admin",
			password:    "secret",
			expectedErr: ErrAuthFailed,
		},
		{
			name: "when_partial_success_leaves_only_publickey_returns_auth_failed",
			serverSetup: func(t *testing.T) (string, func()) {
				srv, err := fakessh.New(&ssh.ServerConfig{
					PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
						return nil, &ssh.PartialSuccessError{
							Next: ssh.ServerAuthCallbacks{
								PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
									return nil, fmt.Errorf("publickey required")
								},
							},
						}
					},
				})
				if err != nil {
					t.Fatalf("fakessh.New failed: %v", err)
				}
				return srv.Addr(), func() { _ = srv.Close() }
			},
			username:    "admin",
			password:    "secret",
			expectedErr: ErrAuthFailed,
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
		{
			name: "when_keyboard_interactive_second_password_in_connection_succeeds_returns_client",
			serverSetup: func(t *testing.T) (string, func()) {
				var attempts atomic.Int32
				srv, err := fakessh.New(&ssh.ServerConfig{
					KeyboardInteractiveCallback: func(c ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
						answers, err := client("", "", []string{"Password: "}, []bool{false})
						if err != nil {
							return nil, err
						}
						if attempts.Add(1) == 2 && c.User() == "root" && len(answers) == 1 && answers[0] == "second" {
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
			name: "when_keyboard_interactive_all_passwords_fail_returns_auth_failed",
			serverSetup: func(t *testing.T) (string, func()) {
				srv, err := fakessh.NewWithKeyboardInteractiveAuth("root", "secret")
				if err != nil {
					t.Fatalf("fakessh.NewWithKeyboardInteractiveAuth failed: %v", err)
				}
				return srv.Addr(), func() { _ = srv.Close() }
			},
			username:    "root",
			passwords:   []string{"wrong1", "wrong2"},
			expectedErr: ErrAuthFailed,
		},
		{
			name: "when_server_accepts_rfc4252_none_auth_rejects_non_empty_passwords",
			serverSetup: func(t *testing.T) (string, func()) {
				srv, err := fakessh.New(&ssh.ServerConfig{
					NoClientAuth: true,
				})
				if err != nil {
					t.Fatalf("fakessh.New failed: %v", err)
				}
				return srv.Addr(), func() { _ = srv.Close() }
			},
			username:    "root",
			passwords:   []string{"non-empty-password"},
			expectedErr: ErrAuthFailed,
		},
		{
			name: "when_server_accepts_rfc4252_none_auth_succeeds_for_explicit_empty_password",
			serverSetup: func(t *testing.T) (string, func()) {
				srv, err := fakessh.New(&ssh.ServerConfig{
					NoClientAuth: true,
				})
				if err != nil {
					t.Fatalf("fakessh.New failed: %v", err)
				}
				return srv.Addr(), func() { _ = srv.Close() }
			},
			username:    "root",
			passwords:   []string{""},
			expectedErr: nil,
		},
		{
			name: "when_zero_prompt_keyboard_interactive_server_receives_non_empty_then_empty_password_succeeds",
			serverSetup: func(t *testing.T) (string, func()) {
				srv, err := fakessh.New(&ssh.ServerConfig{
					KeyboardInteractiveCallback: func(c ssh.ConnMetadata, _ ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
						if c.User() == "alpine" {
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
			username:    "alpine",
			passwords:   []string{"alpine", ""},
			expectedErr: nil,
		},
		{
			name: "when_zero_prompt_keyboard_interactive_server_receives_only_non_empty_passwords_returns_auth_failed",
			serverSetup: func(t *testing.T) (string, func()) {
				srv, err := fakessh.New(&ssh.ServerConfig{
					KeyboardInteractiveCallback: func(c ssh.ConnMetadata, _ ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
						return nil, nil
					},
				})
				if err != nil {
					t.Fatalf("fakessh.New failed: %v", err)
				}
				return srv.Addr(), func() { _ = srv.Close() }
			},
			username:    "alpine",
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
	timeoutCfg := config.FromProto(cpb.Config_builder{
		Clients: cpb.ClientsConfig_builder{
			Ssh: sccpb.SSHClientConfig_builder{
				TimeoutSeconds: proto.Int32(1),
			}.Build(),
		}.Build(),
	}.Build())

	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(httpServer.Close)

	resetAddr := startFakeTCPServer(t, func(conn net.Conn) {
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			// SetLinger(0) forces a TCP RST on Close() instead of FIN.
			_ = tcpConn.SetLinger(0)
		}
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 16)
		_, _ = conn.Read(buf)
	})
	hangingBannerAddr := startFakeTCPServer(t, func(conn net.Conn) {
		_, _ = conn.Write([]byte("-ERR unknown command\r\n"))
		_, _ = io.Copy(io.Discard, conn)
	})
	malformedPacketAddr := startFakeTCPServer(t, func(conn net.Conn) {
		_, _ = conn.Write([]byte("SSH-2.0-Fake\r\n\x00\x00\x00\x01\x00"))
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = io.Copy(io.Discard, conn)
	})

	testCases := []struct {
		name        string
		addr        string
		expectedErr error
		wantDropped bool
	}{
		{
			name:        "when_service_is_http_returns_not_ssh_service",
			addr:        httpServer.Listener.Addr().String(),
			expectedErr: ErrNotSSHService,
		},
		{
			name:        "when_connection_refused_returns_not_ssh_service",
			addr:        closedTCPAddr(t),
			expectedErr: ErrNotSSHService,
		},
		{
			name:        "when_connection_reset_by_peer_returns_not_ssh_service_and_connection_dropped",
			addr:        resetAddr,
			expectedErr: ErrNotSSHService,
			wantDropped: true,
		},
		{
			name:        "when_non_ssh_banner_hangs_past_timeout_returns_not_ssh_service",
			addr:        hangingBannerAddr,
			expectedErr: ErrNotSSHService,
		},
		{
			name:        "when_malformed_ssh_packet_after_banner_returns_not_ssh_service",
			addr:        malformedPacketAddr,
			expectedErr: ErrNotSSHService,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := New(timeoutCfg)
			sshClient, err := client.Connect(t.Context(), tc.addr, "root", "root")
			if sshClient != nil {
				_ = sshClient.Close()
				t.Fatal("Connect() returned non-nil *ssh.Client on non-SSH target")
			}
			if !errors.Is(err, tc.expectedErr) {
				t.Fatalf("Connect() error = %v, expected errors.Is %v", err, tc.expectedErr)
			}
			if gotDropped := errors.Is(err, ErrConnectionDropped); gotDropped != tc.wantDropped {
				t.Errorf("errors.Is(%v, ErrConnectionDropped) = %v, want %v", err, gotDropped, tc.wantDropped)
			}
		})
	}

	t.Run("when_dns_error_contains_eof_in_hostname_does_not_classify_as_pre_banner_drop", func(t *testing.T) {
		dnsErr := &net.OpError{
			Op:  "dial",
			Net: "tcp",
			Err: &net.DNSError{Err: "no such host", Name: "geofence.example.invalid"},
		}
		if isPreBannerDropError(dnsErr) {
			t.Errorf("isPreBannerDropError(%v) = true, want false for DNS lookup failure", dnsErr)
		}
	})
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
		})
	}
}

func TestConnect_ContextCanceledDuringHandshake(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen failed: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	t.Cleanup(func() {
		cancel()
		close(done)
		_ = listener.Close()
		wg.Wait()
	})
	go func() {
		defer wg.Done()
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		cancel()
		<-done
	}()

	addr := listener.Addr().String()
	client := New(nil)
	sshClient, err := client.Connect(ctx, addr, "user", "pass")
	if sshClient != nil {
		_ = sshClient.Close()
		t.Fatalf("Connect(%q) = %v, want nil on context error", addr, sshClient)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Connect(%q) error = %v, want %v", addr, err, context.Canceled)
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
			name:        "when_attempted_methods_keyboard_interactive_returns_auth_failed",
			inputErr:    errors.New("ssh: handshake failed: ssh: unable to authenticate, attempted methods [none keyboard-interactive], no supported methods remain"),
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
			name:        "when_no_route_to_host_returns_not_ssh_service",
			inputErr:    errors.New("dial tcp 10.0.0.1:22: connect: no route to host"),
			expectedErr: ErrNotSSHService,
		},
		{
			name:        "when_connection_reset_by_peer_returns_not_ssh_service",
			inputErr:    errors.New("ssh: handshake failed: read tcp 172.16.0.109:56382->34.224.167.227:3389: read: connection reset by peer"),
			expectedErr: ErrNotSSHService,
		},
		{
			name:        "when_syscall_econnreset_returns_not_ssh_service",
			inputErr:    fmt.Errorf("read failed: %w", syscall.ECONNRESET),
			expectedErr: ErrNotSSHService,
		},
		{
			name:        "when_broken_pipe_returns_not_ssh_service",
			inputErr:    errors.New("write tcp 127.0.0.1:22: write: broken pipe"),
			expectedErr: ErrNotSSHService,
		},
		{
			name:        "when_network_unreachable_returns_not_ssh_service",
			inputErr:    errors.New("dial tcp 10.0.0.1:22: connect: network is unreachable"),
			expectedErr: ErrNotSSHService,
		},
		{
			name:        "when_io_timeout_returns_not_ssh_service",
			inputErr:    errors.New("read tcp 10.0.0.1:22: i/o timeout"),
			expectedErr: ErrNotSSHService,
		},
		{
			name:        "when_closed_network_connection_returns_not_ssh_service",
			inputErr:    net.ErrClosed,
			expectedErr: ErrNotSSHService,
		},
		{
			name:        "when_invalid_packet_length_returns_not_ssh_service",
			inputErr:    errors.New("ssh: handshake failed: ssh: invalid packet length, packet too large"),
			expectedErr: ErrNotSSHService,
		},
		{
			name:        "when_non_auth_disconnect_returns_not_ssh_service",
			inputErr:    errors.New(`ssh: disconnect, reason 11: "connection rejected"`),
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

func startFakeTCPServer(t *testing.T, handler func(conn net.Conn)) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen failed: %v", err)
	}
	done := make(chan struct{})
	t.Cleanup(func() {
		_ = listener.Close()
		<-done
	})
	go func() {
		defer close(done)
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		stop := context.AfterFunc(t.Context(), func() {
			_ = conn.Close()
		})
		defer stop()
		handler(conn)
	}()
	return listener.Addr().String()
}

func closedTCPAddr(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen failed: %v", err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("listener.Close failed: %v", err)
	}
	return addr
}

func startPreambleSSHProxy(t *testing.T, preamble string, upstreamAddr string) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen failed: %v", err)
	}
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
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				defer c.Close()
				upstream, dialErr := net.Dial("tcp", upstreamAddr)
				if dialErr != nil {
					return
				}
				defer upstream.Close()
				if preamble != "" {
					_, _ = c.Write([]byte(preamble))
				}
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
	return listener.Addr().String()
}

func TestConnectAndReturnServerVersion_BannerAndDropClassification(t *testing.T) {
	shortTimeoutCfg := config.FromProto(cpb.Config_builder{
		Clients: cpb.ClientsConfig_builder{
			Ssh: sccpb.SSHClientConfig_builder{
				TimeoutSeconds: proto.Int32(1),
			}.Build(),
		}.Build(),
	}.Build())

	eofPreBannerAddr := startFakeTCPServer(t, func(conn net.Conn) {
		_ = conn.Close()
	})
	rstPreBannerAddr := startFakeTCPServer(t, func(conn net.Conn) {
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			_ = tcpConn.SetLinger(0)
		}
		_ = conn.Close()
	})
	penaltyBannerAddr := startFakeTCPServer(t, func(conn net.Conn) {
		_, _ = conn.Write([]byte("Not allowed at this time\r\n"))
		_ = conn.Close()
	})
	maxStartupsBannerAddr := startFakeTCPServer(t, func(conn net.Conn) {
		_, _ = conn.Write([]byte("Exceeded MaxStartups\r\n"))
		_ = conn.Close()
	})
	httpBannerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(httpBannerServer.Close)

	silentTarpitDone := make(chan struct{})
	silentTarpitAddr := startFakeTCPServer(t, func(conn net.Conn) {
		<-silentTarpitDone
	})
	t.Cleanup(func() { close(silentTarpitDone) })

	passwordOpenSSH, err := fakessh.New(&ssh.ServerConfig{
		ServerVersion: "SSH-2.0-OpenSSH_9.9",
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == "alpine" && string(pass) == "validpass" {
				return nil, nil
			}
			return nil, fmt.Errorf("rejected")
		},
	})
	if err != nil {
		t.Fatalf("fakessh.New failed: %v", err)
	}
	t.Cleanup(func() { _ = passwordOpenSSH.Close() })

	pubKeyOpenSSH, err := fakessh.New(&ssh.ServerConfig{
		ServerVersion: "SSH-2.0-OpenSSH_9.9",
		PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
			return nil, fmt.Errorf("rejected")
		},
	})
	if err != nil {
		t.Fatalf("fakessh.New failed: %v", err)
	}
	t.Cleanup(func() { _ = pubKeyOpenSSH.Close() })

	preamble := "Authorized uses only.\r\nNotice: activity is logged.\n"
	preamblePasswordAddr := startPreambleSSHProxy(t, preamble, passwordOpenSSH.Addr())
	preamblePubKeyAddr := startPreambleSSHProxy(t, preamble, pubKeyOpenSSH.Addr())

	excessivePreambleAddr := startFakeTCPServer(t, func(conn net.Conn) {
		for range maxBannerPreambleLines + 2 {
			_, _ = conn.Write([]byte("Not an SSH banner line\r\n"))
		}
		_ = conn.Close()
	})

	testCases := []struct {
		name              string
		cfg               *config.Config
		addr              string
		username          string
		passwords         []string
		wantServerVersion string
		wantErr           error
		wantDropped       bool
	}{
		{
			name:              "when_peer_closes_immediately_with_eof_wraps_not_ssh_and_connection_dropped",
			cfg:               shortTimeoutCfg,
			addr:              eofPreBannerAddr,
			username:          "root",
			passwords:         []string{"pass"},
			wantServerVersion: "",
			wantErr:           ErrNotSSHService,
			wantDropped:       true,
		},
		{
			name:              "when_peer_resets_before_banner_wraps_not_ssh_and_connection_dropped",
			cfg:               shortTimeoutCfg,
			addr:              rstPreBannerAddr,
			username:          "root",
			passwords:         []string{"pass"},
			wantServerVersion: "",
			wantErr:           ErrNotSSHService,
			wantDropped:       true,
		},
		{
			name:              "when_openssh_sends_not_allowed_at_this_time_penalty_banner_wraps_connection_dropped",
			cfg:               shortTimeoutCfg,
			addr:              penaltyBannerAddr,
			username:          "root",
			passwords:         []string{"pass"},
			wantServerVersion: "",
			wantErr:           ErrNotSSHService,
			wantDropped:       true,
		},
		{
			name:              "when_openssh_sends_exceeded_maxstartups_banner_wraps_connection_dropped",
			cfg:               shortTimeoutCfg,
			addr:              maxStartupsBannerAddr,
			username:          "root",
			passwords:         []string{"pass"},
			wantServerVersion: "",
			wantErr:           ErrNotSSHService,
			wantDropped:       true,
		},
		{
			name:              "when_non_ssh_http_banner_wraps_not_ssh_without_connection_dropped",
			cfg:               shortTimeoutCfg,
			addr:              httpBannerServer.Listener.Addr().String(),
			username:          "root",
			passwords:         []string{"pass"},
			wantServerVersion: "",
			wantErr:           ErrNotSSHService,
			wantDropped:       false,
		},
		{
			name:              "when_silent_tarpit_hits_timeout_wraps_not_ssh_without_connection_dropped",
			cfg:               shortTimeoutCfg,
			addr:              silentTarpitAddr,
			username:          "root",
			passwords:         []string{"pass"},
			wantServerVersion: "",
			wantErr:           ErrNotSSHService,
			wantDropped:       false,
		},
		{
			name:              "when_connection_refused_wraps_not_ssh_without_connection_dropped",
			cfg:               shortTimeoutCfg,
			addr:              closedTCPAddr(t),
			username:          "root",
			passwords:         []string{"pass"},
			wantServerVersion: "",
			wantErr:           ErrNotSSHService,
			wantDropped:       false,
		},
		{
			name:              "when_multiline_preamble_before_openssh_banner_and_auth_succeeds_returns_exact_banner",
			addr:              preamblePasswordAddr,
			username:          "alpine",
			passwords:         []string{"validpass"},
			wantServerVersion: "SSH-2.0-OpenSSH_9.9",
			wantErr:           nil,
			wantDropped:       false,
		},
		{
			name:              "when_multiline_preamble_before_openssh_banner_and_auth_fails_returns_exact_banner",
			addr:              preamblePasswordAddr,
			username:          "alpine",
			passwords:         []string{"wrongpass"},
			wantServerVersion: "SSH-2.0-OpenSSH_9.9",
			wantErr:           ErrAuthFailed,
			wantDropped:       false,
		},
		{
			name:              "when_multiline_preamble_before_openssh_banner_and_pubkey_only_returns_exact_banner",
			addr:              preamblePubKeyAddr,
			username:          "alpine",
			passwords:         []string{"anypass"},
			wantServerVersion: "SSH-2.0-OpenSSH_9.9",
			wantErr:           ErrPasswordAuthUnsupported,
			wantDropped:       false,
		},
		{
			name:              "when_preamble_exceeds_max_lines_without_ssh_banner_returns_not_ssh_without_dropped",
			cfg:               shortTimeoutCfg,
			addr:              excessivePreambleAddr,
			username:          "root",
			passwords:         []string{"pass"},
			wantServerVersion: "",
			wantErr:           ErrNotSSHService,
			wantDropped:       false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := New(tc.cfg)
			sshClient, gotBanner, err := client.ConnectAndReturnServerVersion(t.Context(), tc.addr, tc.username, tc.passwords...)
			if sshClient != nil {
				_ = sshClient.Close()
			}
			if gotBanner != tc.wantServerVersion {
				t.Errorf("ConnectAndReturnServerVersion() banner = %q, want %q", gotBanner, tc.wantServerVersion)
			}
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("ConnectAndReturnServerVersion() unexpected error = %v", err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("ConnectAndReturnServerVersion() error = %v, want errors.Is %v", err, tc.wantErr)
			}
			if gotDropped := errors.Is(err, ErrConnectionDropped); gotDropped != tc.wantDropped {
				t.Errorf("errors.Is(%v, ErrConnectionDropped) = %v, want %v", err, gotDropped, tc.wantDropped)
			}
		})
	}
}

func TestHasConfirmedSSH(t *testing.T) {
	shortTimeoutCfg := config.FromProto(cpb.Config_builder{
		Clients: cpb.ClientsConfig_builder{
			Ssh: sccpb.SSHClientConfig_builder{
				TimeoutSeconds: proto.Int32(1),
			}.Build(),
		}.Build(),
	}.Build())

	sshSrv, err := fakessh.New(&ssh.ServerConfig{
		ServerVersion: "SSH-2.0-OpenSSH_9.9",
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == "alpine" && string(pass) == "secret" {
				return nil, nil
			}
			return nil, fmt.Errorf("rejected")
		},
	})
	if err != nil {
		t.Fatalf("fakessh.New failed: %v", err)
	}
	t.Cleanup(func() { _ = sshSrv.Close() })

	startLoopingTCPServer := func(t *testing.T, handler func(conn net.Conn)) string {
		t.Helper()
		ln, listenErr := net.Listen("tcp", "127.0.0.1:0")
		if listenErr != nil {
			t.Fatalf("net.Listen failed: %v", listenErr)
		}
		var wg sync.WaitGroup
		t.Cleanup(func() {
			_ = ln.Close()
			wg.Wait()
		})
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				conn, acceptErr := ln.Accept()
				if acceptErr != nil {
					return
				}
				wg.Add(1)
				go func(c net.Conn) {
					defer wg.Done()
					defer c.Close()
					handler(c)
				}(conn)
			}
		}()
		return ln.Addr().String()
	}

	zeroByteDropAddr := startLoopingTCPServer(t, func(conn net.Conn) {
		_ = conn.Close()
	})
	penaltyNoticeAddr := startLoopingTCPServer(t, func(conn net.Conn) {
		_, _ = conn.Write([]byte("Not allowed at this time\r\n"))
	})
	maxStartupsNoticeAddr := startLoopingTCPServer(t, func(conn net.Conn) {
		_, _ = conn.Write([]byte("Exceeded MaxStartups\r\n"))
	})
	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	t.Cleanup(httpSrv.Close)

	t.Run("when_empty_or_non_ssh_peers_probed_returns_false", func(t *testing.T) {
		client := New(shortTimeoutCfg)
		if client.HasConfirmedSSH("") {
			t.Error("HasConfirmedSSH(\"\") = true, want false")
		}
		for _, addr := range []string{zeroByteDropAddr, httpSrv.Listener.Addr().String(), closedTCPAddr(t)} {
			_, _ = client.Connect(t.Context(), addr, "root", "pass")
			if client.HasConfirmedSSH(addr) {
				t.Errorf("HasConfirmedSSH(%q) = true after non-SSH probe, want false", addr)
			}
		}
	})

	t.Run("when_ssh_banner_observed_shares_confirmation_across_same_config_only", func(t *testing.T) {
		sharedCfg := config.Default()
		clientA := New(sharedCfg)
		clientB := New(sharedCfg)
		isolatedCfgClient := New(config.Default())
		nilClient := New(nil)

		if clientA.HasConfirmedSSH(sshSrv.Addr()) {
			t.Fatalf("HasConfirmedSSH(%q) = true before dial, want false", sshSrv.Addr())
		}
		if _, authErr := clientA.Connect(t.Context(), sshSrv.Addr(), "alpine", "wrong"); !errors.Is(authErr, ErrAuthFailed) {
			t.Fatalf("Connect() error = %v, want %v", authErr, ErrAuthFailed)
		}
		if !clientA.HasConfirmedSSH(sshSrv.Addr()) {
			t.Errorf("clientA.HasConfirmedSSH(%q) = false after SSH banner, want true", sshSrv.Addr())
		}
		if !clientB.HasConfirmedSSH(sshSrv.Addr()) {
			t.Errorf("clientB.HasConfirmedSSH(%q) = false on shared *config.Config, want true", sshSrv.Addr())
		}
		if isolatedCfgClient.HasConfirmedSSH(sshSrv.Addr()) {
			t.Errorf("isolatedCfgClient.HasConfirmedSSH(%q) = true on distinct *config.Config, want false", sshSrv.Addr())
		}
		if nilClient.HasConfirmedSSH(sshSrv.Addr()) {
			t.Errorf("nilClient.HasConfirmedSSH(%q) = true on nil config, want false", sshSrv.Addr())
		}
	})

	t.Run("when_successful_ssh_handshake_completed_marks_confirmed", func(t *testing.T) {
		client := New(nil)
		conn, connErr := client.Connect(t.Context(), sshSrv.Addr(), "alpine", "secret")
		if connErr != nil {
			t.Fatalf("Connect() unexpected error: %v", connErr)
		}
		_ = conn.Close()
		if !client.HasConfirmedSSH(sshSrv.Addr()) {
			t.Errorf("client.HasConfirmedSSH(%q) = false after successful auth, want true", sshSrv.Addr())
		}
	})

	t.Run("when_openssh_rate_limit_notices_observed_marks_confirmed_without_leaking_across_nil_clients", func(t *testing.T) {
		for _, addr := range []string{penaltyNoticeAddr, maxStartupsNoticeAddr} {
			nilA := New(nil)
			nilB := New(nil)
			_, dropErr := nilA.Connect(t.Context(), addr, "root", "pass")
			if !errors.Is(dropErr, ErrConnectionDropped) {
				t.Fatalf("Connect(%q) error = %v, want errors.Is %v", addr, dropErr, ErrConnectionDropped)
			}
			if !nilA.HasConfirmedSSH(addr) {
				t.Errorf("nilA.HasConfirmedSSH(%q) = false after OpenSSH rate-limit notice, want true", addr)
			}
			if nilB.HasConfirmedSSH(addr) {
				t.Errorf("nilB.HasConfirmedSSH(%q) = true on separate nil-config client, want false", addr)
			}
		}
	})

	t.Run("when_concurrent_clients_share_config_synchronizes_without_races", func(t *testing.T) {
		sharedCfg := config.Default()
		var wg sync.WaitGroup
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				c := New(sharedCfg)
				_, _ = c.Connect(t.Context(), sshSrv.Addr(), "alpine", "wrong")
				if !c.HasConfirmedSSH(sshSrv.Addr()) {
					t.Errorf("HasConfirmedSSH(%q) = false after concurrent Connect, want true", sshSrv.Addr())
				}
			}()
		}
		wg.Wait()
	})

	t.Run("when_config_garbage_collected_evicts_confirmed_endpoints", func(t *testing.T) {
		var wp weak.Pointer[config.Config]
		func() {
			ephemeralCfg := config.Default()
			wp = weak.Make(ephemeralCfg)
			c := New(ephemeralCfg)
			_, _ = c.Connect(t.Context(), sshSrv.Addr(), "alpine", "wrong")
			if !c.HasConfirmedSSH(sshSrv.Addr()) {
				t.Fatalf("HasConfirmedSSH(%q) = false before GC, want true", sshSrv.Addr())
			}
		}()

		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			runtime.GC()
			confirmedSSHMu.RLock()
			_, exists := confirmedSSHByConfig[wp]
			confirmedSSHMu.RUnlock()
			if !exists {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		t.Fatal("confirmedSSHByConfig entry was not evicted after *config.Config GC")
	})
}

func TestSleepContext(t *testing.T) {
	testCases := []struct {
		name     string
		setupCtx func(t *testing.T) context.Context
		duration time.Duration
		wantErr  error
	}{
		{
			name:     "when_duration_elapses_returns_nil",
			setupCtx: func(t *testing.T) context.Context { return t.Context() },
			duration: time.Millisecond,
			wantErr:  nil,
		},
		{
			name: "when_context_canceled_returns_canceled_error",
			setupCtx: func(t *testing.T) context.Context {
				ctx, cancel := context.WithCancel(t.Context())
				cancel()
				return ctx
			},
			duration: time.Hour,
			wantErr:  context.Canceled,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if err := SleepContext(tc.setupCtx(t), tc.duration); !errors.Is(err, tc.wantErr) {
				t.Errorf("SleepContext() error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}
