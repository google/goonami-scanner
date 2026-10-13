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

package sshbruteforce

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/google/goonami-scanner/common/clients/sshclient"
	"github.com/google/goonami-scanner/common/credentialstore"
	"github.com/google/goonami-scanner/common/testfakes/fakessh"
	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/log"
	"github.com/google/goonami-scanner/core/module"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"

	cpb "github.com/google/goonami-scanner/core/config/config_go_proto"
	sbpb "github.com/google/goonami-scanner/plugins/detectors/sshbruteforce/sshbruteforce_config_go_proto"
	dpb "github.com/google/tsunami-security-scanner/proto/go/detection_go_proto"
	npb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
	vpb "github.com/google/tsunami-security-scanner/proto/go/vulnerability_go_proto"
)

func createTestDetector(t *testing.T, store *credentialstore.CredentialStore, cfg *config.Config) *Detector {
	t.Helper()
	if cfg == nil {
		cfg = config.Default()
	}
	if store == nil {
		var err error
		store, err = credentialstore.NewWithDefaults()
		if err != nil {
			t.Fatalf("credentialstore.NewWithDefaults failed: %v", err)
		}
	}
	return &Detector{
		BaseModule: module.NewBaseModule(ModuleName),
		cfg:        cfg,
		store:      store,
		client:     sshclient.New(cfg),
	}
}

func TestNew(t *testing.T) {
	tests := []struct {
		name string
		cfg  *config.Config
	}{
		{
			name: "when_default_config_creates_detector",
			cfg:  config.Default(),
		},
		{
			name: "when_plugin_config_provided_creates_detector",
			cfg: config.FromProto(
				cpb.Config_builder{
					Plugins: cpb.PluginsConfig_builder{
						Sshbruteforce: sbpb.SshBruteForceConfig_builder{
							MaxAttemptsPerService: proto.Int32(10),
							MaxConcurrency:        proto.Int32(3),
							MaxAttemptsPerSecond:  proto.Int32(20),
						}.Build(),
					}.Build(),
				}.Build(),
			),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			detector, err := New(t.Context(), tc.cfg)
			if err != nil {
				t.Fatalf("New() failed: %v", err)
			}
			if detector == nil {
				t.Fatal("New() returned nil detector")
			}
			if detector.Name() != ModuleName {
				t.Errorf("detector.Name() = %q, want %q", detector.Name(), ModuleName)
			}
		})
	}
}

func TestDetector_Detect_VulnerableServer(t *testing.T) {
	log.SetLogger(&log.DefaultLogger{VerboseLevel: log.DebugLevelRequest})
	tests := []struct {
		name          string
		user          string
		password      string
		storeUsers    map[string][]string
		cfg           *config.Config
		wantReport    bool
		wantCredMatch string
	}{
		{
			name:     "when_valid_credentials_in_store_reports_vulnerability",
			user:     "admin",
			password: "secretpassword",
			storeUsers: map[string][]string{
				"admin": {"wrong1", "secretpassword"},
			},
			wantReport:    true,
			wantCredMatch: "admin:secretpassword",
		},
		{
			name:     "when_second_user_matches_reports_vulnerability",
			user:     "root",
			password: "toor",
			storeUsers: map[string][]string{
				"admin": {"admin", "123456"},
				"root":  {"toor"},
			},
			wantReport:    true,
			wantCredMatch: "root:toor",
		},
		{
			name:     "when_no_credentials_match_returns_nil",
			user:     "targetuser",
			password: "unguessablepassword123!",
			storeUsers: map[string][]string{
				"admin": {"admin", "123456"},
				"root":  {"root", "toor"},
			},
			wantReport: false,
		},
		{
			name:     "when_concurrent_attempts_configured_finds_valid_credential",
			user:     "operator",
			password: "validpass123",
			storeUsers: map[string][]string{
				"user1":    {"p1", "p2", "p3"},
				"user2":    {"p4", "p5"},
				"operator": {"wrong", "validpass123"},
				"user3":    {"p6", "p7"},
			},
			cfg: config.FromProto(
				cpb.Config_builder{
					Plugins: cpb.PluginsConfig_builder{
						Sshbruteforce: sbpb.SshBruteForceConfig_builder{
							MaxConcurrency: proto.Int32(4),
						}.Build(),
					}.Build(),
				}.Build(),
			),
			wantReport:    true,
			wantCredMatch: "operator:validpass123",
		},
		{
			name:     "when_rate_limiting_configured_finds_valid_credential",
			user:     "support",
			password: "supportpass",
			storeUsers: map[string][]string{
				"user1":   {"p1", "p2"},
				"support": {"supportpass"},
			},
			cfg: config.FromProto(
				cpb.Config_builder{
					Plugins: cpb.PluginsConfig_builder{
						Sshbruteforce: sbpb.SshBruteForceConfig_builder{
							MaxConcurrency:       proto.Int32(2),
							MaxAttemptsPerSecond: proto.Int32(100),
						}.Build(),
					}.Build(),
				}.Build(),
			),
			wantReport:    true,
			wantCredMatch: "support:supportpass",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			serverCfg := &ssh.ServerConfig{
				PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
					if c.User() == tc.user && string(pass) == tc.password {
						return nil, nil
					}
					return nil, fmt.Errorf("authentication failed")
				},
			}
			server, err := fakessh.New(serverCfg)
			if err != nil {
				t.Fatalf("fakessh.New failed: %v", err)
			}
			defer func() {
				if err := server.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
					t.Logf("failed to close SSH server: %v", err)
				}
			}()

			store := credentialstore.New()
			for u, passes := range tc.storeUsers {
				if err := store.AddUser(u); err != nil {
					t.Fatalf("AddUser failed: %v", err)
				}
				for _, p := range passes {
					if err := store.AddPasswordForUser(u, p); err != nil {
						t.Fatalf("AddPasswordForUser failed: %v", err)
					}
				}
			}

			d := createTestDetector(t, store, tc.cfg)
			reports, err := d.Detect(t.Context(), server.NetworkService())
			if err != nil {
				t.Fatalf("Detect() unexpected error: %v", err)
			}

			if !tc.wantReport {
				if reports != nil && len(reports.GetDetectionReports()) > 0 {
					t.Fatalf("Detect() returned unexpected reports: %v", reports)
				}
				return
			}

			if reports == nil || len(reports.GetDetectionReports()) == 0 {
				t.Fatal("Detect() returned nil or empty reports, want vulnerability report")
			}

			report := reports.GetDetectionReports()[0]
			if report.GetDetectionStatus() != dpb.DetectionStatus_VULNERABILITY_VERIFIED {
				t.Errorf("DetectionStatus = %v, want %v", report.GetDetectionStatus(), dpb.DetectionStatus_VULNERABILITY_VERIFIED)
			}

			vuln := report.GetVulnerability()
			if vuln.GetMainId().GetValue() != "SSH_WEAK_CREDENTIALS" {
				t.Errorf("Vulnerability ID = %q, want %q", vuln.GetMainId().GetValue(), "SSH_WEAK_CREDENTIALS")
			}
			if vuln.GetSeverity() != vpb.Severity_HIGH {
				t.Errorf("Severity = %v, want %v", vuln.GetSeverity(), vpb.Severity_HIGH)
			}

			if len(vuln.GetAdditionalDetails()) > 0 {
				gotCred := vuln.GetAdditionalDetails()[0].GetTextData().GetText()
				if gotCred != tc.wantCredMatch {
					t.Errorf("AdditionalDetails text = %q, want %q", gotCred, tc.wantCredMatch)
				}
			} else {
				t.Error("Vulnerability has no AdditionalDetails")
			}
		})
	}
}

func TestDetector_Detect_SafeServer(t *testing.T) {
	tests := []struct {
		name string
	}{
		{
			name: "when_password_auth_unsupported_stops_early_returns_nil",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server, err := fakessh.NewPublicKeyOnly()
			if err != nil {
				t.Fatalf("fakessh.NewPublicKeyOnly failed: %v", err)
			}
			defer func() {
				if err := server.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
					t.Logf("failed to close server: %v", err)
				}
			}()

			store := credentialstore.New()
			for i := range 10 {
				u := fmt.Sprintf("user%d", i)
				if err := store.AddUser(u); err != nil {
					t.Fatalf("AddUser failed: %v", err)
				}
				for j := range 10 {
					if err := store.AddPasswordForUser(u, fmt.Sprintf("pass%d", j)); err != nil {
						t.Fatalf("AddPasswordForUser failed: %v", err)
					}
				}
			}

			d := createTestDetector(t, store, nil)
			reports, err := d.Detect(t.Context(), server.NetworkService())
			if err != nil {
				t.Fatalf("Detect() unexpected error: %v", err)
			}
			if reports != nil && len(reports.GetDetectionReports()) > 0 {
				t.Fatalf("Detect() returned unexpected reports for safe server: %v", reports)
			}
		})
	}
}

func TestDetector_Detect_NonSSHAndUnreachable(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T) *nspb.NetworkService
	}{
		{
			name: "when_service_is_http_returns_nil",
			setup: func(t *testing.T) *nspb.NetworkService {
				ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusBadRequest)
				}))
				t.Cleanup(ts.Close)

				_, portStr, err := net.SplitHostPort(ts.Listener.Addr().String())
				if err != nil {
					t.Fatalf("net.SplitHostPort failed: %v", err)
				}
				port, err := strconv.Atoi(portStr)
				if err != nil {
					t.Fatalf("strconv.Atoi failed: %v", err)
				}
				return nspb.NetworkService_builder{
					ServiceName: "http",
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
			},
		},
		{
			name: "when_service_is_unreachable_returns_nil",
			setup: func(t *testing.T) *nspb.NetworkService {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatalf("net.Listen failed: %v", err)
				}
				addr := listener.Addr().String()
				_, portStr, _ := net.SplitHostPort(addr)
				port, _ := strconv.Atoi(portStr)
				if err := listener.Close(); err != nil {
					t.Fatalf("listener.Close failed: %v", err)
				}
				return nspb.NetworkService_builder{
					ServiceName: "ssh",
					NetworkEndpoint: npb.NetworkEndpoint_builder{
						Type: npb.NetworkEndpoint_IP_PORT,
						IpAddress: npb.IpAddress_builder{
							Address:       "127.0.0.1",
							AddressFamily: npb.AddressFamily_IPV4,
						}.Build(),
						Port: npb.Port_builder{PortNumber: uint32(port)}.Build(),
					}.Build(),
				}.Build()
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc := tc.setup(t)
			d := createTestDetector(t, nil, nil)
			reports, err := d.Detect(t.Context(), svc)
			if err != nil {
				t.Fatalf("Detect() unexpected error: %v", err)
			}
			if reports != nil && len(reports.GetDetectionReports()) > 0 {
				t.Fatalf("Detect() returned reports for non-SSH service: %v", reports)
			}
		})
	}
}

func TestDetector_Detect_BudgetAndLimits(t *testing.T) {
	tests := []struct {
		name        string
		maxAttempts int32
		storeUsers  map[string][]string
	}{
		{
			name:        "when_max_attempts_reached_aborts_search",
			maxAttempts: 3,
			storeUsers: map[string][]string{
				"user1": {"p1", "p2"},
				"user2": {"p3", "p4"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			serverCfg := &ssh.ServerConfig{
				PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
					return nil, fmt.Errorf("auth failed")
				},
			}
			server, err := fakessh.New(serverCfg)
			if err != nil {
				t.Fatalf("fakessh.New failed: %v", err)
			}
			defer func() {
				if err := server.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
					t.Logf("failed to close server: %v", err)
				}
			}()

			store := credentialstore.New()
			for u, passes := range tc.storeUsers {
				if err := store.AddUser(u); err != nil {
					t.Fatalf("AddUser failed: %v", err)
				}
				for _, p := range passes {
					if err := store.AddPasswordForUser(u, p); err != nil {
						t.Fatalf("AddPasswordForUser failed: %v", err)
					}
				}
			}

			cfg := config.FromProto(
				cpb.Config_builder{
					Plugins: cpb.PluginsConfig_builder{
						Sshbruteforce: sbpb.SshBruteForceConfig_builder{
							MaxAttemptsPerService: proto.Int32(tc.maxAttempts),
							MaxConcurrency:        proto.Int32(2),
						}.Build(),
					}.Build(),
				}.Build(),
			)

			d := createTestDetector(t, store, cfg)
			reports, err := d.Detect(t.Context(), server.NetworkService())
			if err != nil {
				t.Fatalf("Detect() unexpected error: %v", err)
			}
			if reports != nil {
				t.Fatalf("Detect() returned reports: %v, want nil", reports)
			}
		})
	}
}

func TestDetector_Detect_EmptyStore(t *testing.T) {
	tests := []struct {
		name string
	}{
		{
			name: "when_store_has_no_users_returns_nil",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := credentialstore.New()
			d := createTestDetector(t, store, nil)
			svc := nspb.NetworkService_builder{
				ServiceName: "ssh",
				NetworkEndpoint: npb.NetworkEndpoint_builder{
					Port: npb.Port_builder{PortNumber: 22}.Build(),
				}.Build(),
			}.Build()

			reports, err := d.Detect(t.Context(), svc)
			if err != nil {
				t.Fatalf("Detect() error = %v, want nil", err)
			}
			if reports != nil {
				t.Fatalf("Detect() = %v, want nil", reports)
			}
		})
	}
}

func TestDetector_Detect_ContextCanceled(t *testing.T) {
	tests := []struct {
		name string
	}{
		{
			name: "when_context_canceled_returns_error",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := credentialstore.New()
			if err := store.AddUser("root"); err != nil {
				t.Fatalf("AddUser failed: %v", err)
				return
			}
			if err := store.AddPasswordForUser("root", "pass1"); err != nil {
				t.Fatalf("AddPasswordForUser failed: %v", err)
			}

			ctx, cancel := context.WithCancel(t.Context())
			cancel()

			d := createTestDetector(t, store, nil)
			svc := nspb.NetworkService_builder{
				ServiceName: "ssh",
				NetworkEndpoint: npb.NetworkEndpoint_builder{
					Type: npb.NetworkEndpoint_IP_PORT,
					IpAddress: npb.IpAddress_builder{
						Address:       "127.0.0.1",
						AddressFamily: npb.AddressFamily_IPV4,
					}.Build(),
					Port: npb.Port_builder{
						PortNumber: 8022,
					}.Build(),
				}.Build(),
			}.Build()

			_, err := d.Detect(ctx, svc)
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("Detect() error = %v, want context.Canceled", err)
			}
		})
	}
}

func TestDetector_Concurrency(t *testing.T) {
	tests := []struct {
		name string
		cfg  *config.Config
		want int
	}{
		{
			name: "when_plugin_max_concurrency_set_uses_plugin_value",
			cfg: config.FromProto(
				cpb.Config_builder{
					Plugins: cpb.PluginsConfig_builder{
						Sshbruteforce: sbpb.SshBruteForceConfig_builder{
							MaxConcurrency: proto.Int32(8),
						}.Build(),
					}.Build(),
				}.Build(),
			),
			want: 8,
		},
		{
			name: "when_global_max_concurrency_set_uses_global_value",
			cfg: config.FromProto(
				cpb.Config_builder{
					Globalcfg: cpb.GlobalConfig_builder{
						Performance: cpb.GlobalConfig_Performance_builder{
							MaxConcurrency: proto.Int32(6),
						}.Build(),
					}.Build(),
				}.Build(),
			),
			want: 6,
		},
		{
			name: "when_no_concurrency_configured_defaults_to_five",
			cfg:  config.Default(),
			want: 5,
		},
		{
			name: "when_config_is_nil_defaults_to_five",
			cfg:  nil,
			want: 5,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := &Detector{cfg: tc.cfg}
			if got := d.concurrency(); got != tc.want {
				t.Errorf("concurrency() = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestDetector_AttemptsPerSecond(t *testing.T) {
	tests := []struct {
		name string
		cfg  *config.Config
		want int
	}{
		{
			name: "when_plugin_max_attempts_per_second_set_uses_plugin_value",
			cfg: config.FromProto(
				cpb.Config_builder{
					Plugins: cpb.PluginsConfig_builder{
						Sshbruteforce: sbpb.SshBruteForceConfig_builder{
							MaxAttemptsPerSecond: proto.Int32(25),
						}.Build(),
					}.Build(),
				}.Build(),
			),
			want: 25,
		},
		{
			name: "when_global_max_packets_per_second_set_uses_global_value",
			cfg: config.FromProto(
				cpb.Config_builder{
					Globalcfg: cpb.GlobalConfig_builder{
						Performance: cpb.GlobalConfig_Performance_builder{
							MaxPacketsPerSecond: proto.Int32(15),
						}.Build(),
					}.Build(),
				}.Build(),
			),
			want: 15,
		},
		{
			name: "when_no_rate_limit_configured_returns_zero",
			cfg:  config.Default(),
			want: 0,
		},
		{
			name: "when_config_is_nil_returns_zero",
			cfg:  nil,
			want: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := &Detector{cfg: tc.cfg}
			if got := d.attemptsPerSecond(); got != tc.want {
				t.Errorf("attemptsPerSecond() = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestIsSSHService(t *testing.T) {
	tests := []struct {
		name    string
		service *nspb.NetworkService
		want    bool
	}{
		{
			name: "when_service_with_endpoint_returns_true",
			service: nspb.NetworkService_builder{
				ServiceName: "ssh",
				NetworkEndpoint: npb.NetworkEndpoint_builder{
					Port: npb.Port_builder{PortNumber: 22}.Build(),
				}.Build(),
			}.Build(),
			want: true,
		},
		{
			name: "when_service_name_is_http_with_endpoint_returns_true",
			service: nspb.NetworkService_builder{
				ServiceName: "http",
				NetworkEndpoint: npb.NetworkEndpoint_builder{
					Port: npb.Port_builder{PortNumber: 80}.Build(),
				}.Build(),
			}.Build(),
			want: true,
		},
		{
			name: "when_service_name_is_unknown_with_endpoint_returns_true",
			service: nspb.NetworkService_builder{
				ServiceName: "unknown",
				NetworkEndpoint: npb.NetworkEndpoint_builder{
					Port: npb.Port_builder{PortNumber: 9999}.Build(),
				}.Build(),
			}.Build(),
			want: true,
		},
		{
			name:    "when_service_is_nil_returns_false",
			service: nil,
			want:    false,
		},
		{
			name: "when_service_has_no_endpoint_returns_false",
			service: nspb.NetworkService_builder{
				ServiceName: "ssh",
			}.Build(),
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsSSHService(tc.service); got != tc.want {
				t.Errorf("IsSSHService() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestTargetAddress(t *testing.T) {
	tests := []struct {
		name     string
		endpoint *npb.NetworkEndpoint
		want     string
		wantErr  bool
	}{
		{
			name: "when_ip_and_port_returns_ip_port",
			endpoint: npb.NetworkEndpoint_builder{
				Type: npb.NetworkEndpoint_IP_PORT,
				IpAddress: npb.IpAddress_builder{
					Address:       "192.168.1.1",
					AddressFamily: npb.AddressFamily_IPV4,
				}.Build(),
				Port: npb.Port_builder{PortNumber: 8022}.Build(),
			}.Build(),
			want: "192.168.1.1:8022",
		},
		{
			name: "when_ip_without_port_defaults_to_port_22",
			endpoint: npb.NetworkEndpoint_builder{
				Type: npb.NetworkEndpoint_IP,
				IpAddress: npb.IpAddress_builder{
					Address:       "192.168.1.1",
					AddressFamily: npb.AddressFamily_IPV4,
				}.Build(),
			}.Build(),
			want: "192.168.1.1:22",
		},
		{
			name: "when_hostname_and_port_returns_host_port",
			endpoint: npb.NetworkEndpoint_builder{
				Type: npb.NetworkEndpoint_HOSTNAME,
				Hostname: npb.Hostname_builder{
					Name: "ssh.example.com",
				}.Build(),
				Port: npb.Port_builder{PortNumber: 2222}.Build(),
			}.Build(),
			want: "ssh.example.com:2222",
		},
		{
			name: "when_ipv6_and_port_formats_properly",
			endpoint: npb.NetworkEndpoint_builder{
				Type: npb.NetworkEndpoint_IP_PORT,
				IpAddress: npb.IpAddress_builder{
					Address:       "::1",
					AddressFamily: npb.AddressFamily_IPV6,
				}.Build(),
				Port: npb.Port_builder{PortNumber: 8022}.Build(),
			}.Build(),
			want: "[::1]:8022",
		},
		{
			name:     "when_endpoint_is_nil_returns_error",
			endpoint: nil,
			wantErr:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := targetAddress(tc.endpoint)
			if (err != nil) != tc.wantErr {
				t.Fatalf("targetAddress() error = %v, wantErr = %v", err, tc.wantErr)
			}
			if !tc.wantErr && got != tc.want {
				t.Errorf("targetAddress() = %q, want %q", got, tc.want)
			}
		})
	}
}
