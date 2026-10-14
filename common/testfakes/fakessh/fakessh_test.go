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

package fakessh

import (
	"errors"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestNew(t *testing.T) {
	testCases := []struct {
		name        string
		serverSetup func(t *testing.T) *Server
		authSetup   func() *ssh.ClientConfig
		wantErr     bool
	}{
		{
			name: "when_password_auth_configured_authenticates_valid_credentials",
			serverSetup: func(t *testing.T) *Server {
				s, err := NewWithPasswordAuth("admin", "secret")
				if err != nil {
					t.Fatalf("NewWithPasswordAuth failed: %v", err)
				}
				return s
			},
			authSetup: func() *ssh.ClientConfig {
				return &ssh.ClientConfig{
					User: "admin",
					Auth: []ssh.AuthMethod{
						ssh.Password("secret"),
					},
					HostKeyCallback: ssh.InsecureIgnoreHostKey(),
					Timeout:         2 * time.Second,
				}
			},
			wantErr: false,
		},
		{
			name: "when_password_auth_invalid_password_fails_handshake",
			serverSetup: func(t *testing.T) *Server {
				s, err := NewWithPasswordAuth("admin", "secret")
				if err != nil {
					t.Fatalf("NewWithPasswordAuth failed: %v", err)
				}
				return s
			},
			authSetup: func() *ssh.ClientConfig {
				return &ssh.ClientConfig{
					User: "admin",
					Auth: []ssh.AuthMethod{
						ssh.Password("wrongpassword"),
					},
					HostKeyCallback: ssh.InsecureIgnoreHostKey(),
					Timeout:         2 * time.Second,
				}
			},
			wantErr: true,
		},
		{
			name: "when_public_key_only_configured_rejects_password_auth",
			serverSetup: func(t *testing.T) *Server {
				s, err := NewPublicKeyOnly()
				if err != nil {
					t.Fatalf("NewPublicKeyOnly failed: %v", err)
				}
				return s
			},
			authSetup: func() *ssh.ClientConfig {
				return &ssh.ClientConfig{
					User: "root",
					Auth: []ssh.AuthMethod{
						ssh.Password("anypassword"),
					},
					HostKeyCallback: ssh.InsecureIgnoreHostKey(),
					Timeout:         2 * time.Second,
				}
			},
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			server := tc.serverSetup(t)
			defer func() {
				if err := server.Close(); err != nil {
					t.Logf("failed to close server: %v", err)
				}
			}()

			if server.Addr() == "" {
				t.Error("server.Addr() is empty")
			}
			if server.Port() <= 0 {
				t.Errorf("server.Port() = %d, want > 0", server.Port())
			}
			svc := server.NetworkService()
			if svc.GetServiceName() != "ssh" {
				t.Errorf("server.NetworkService() = %v, want valid ssh service", svc)
			}

			client, err := ssh.Dial("tcp", server.Addr(), tc.authSetup())
			if tc.wantErr {
				if err == nil {
					_ = client.Close()
					t.Fatal("ssh.Dial expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("ssh.Dial unexpected error: %v", err)
			}
			if client == nil {
				t.Fatal("ssh.Dial returned nil client")
			}
			if closeErr := client.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
				t.Logf("failed to close client: %v", closeErr)
			}
		})
	}
}
