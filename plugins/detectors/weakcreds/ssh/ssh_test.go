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

package ssh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/goonami-scanner/common/bruteforce"
	"github.com/google/goonami-scanner/common/clients/sshclient"
	"github.com/google/goonami-scanner/common/credentialstore"
	"github.com/google/goonami-scanner/common/testfakes/fakessh"
	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/net/netendpoint"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"

	bruteforceconfigpb "github.com/google/goonami-scanner/common/bruteforce/bruteforce_config_go_proto"
	configpb "github.com/google/goonami-scanner/core/config/config_go_proto"
	detectionpb "github.com/google/tsunami-security-scanner/proto/go/detection_go_proto"
	networkpb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
	networkservicepb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
	vulnerabilitypb "github.com/google/tsunami-security-scanner/proto/go/vulnerability_go_proto"
)

func smallStore(users, passes []string) *credentialstore.CredentialStore {
	s := credentialstore.New()
	for _, u := range users {
		_ = s.AddUser(u)
		for _, p := range passes {
			_ = s.AddPasswordForUser(u, p)
		}
	}
	return s
}

func fastBruteForceConfig(stopAtFirst bool) *config.Config {
	return config.FromProto(configpb.Config_builder{
		Globalcfg: configpb.GlobalConfig_builder{
			Performance: configpb.GlobalConfig_Performance_builder{
				TimeoutPerRequestSeconds: proto.Int32(2),
			}.Build(),
		}.Build(),
		Plugins: configpb.PluginsConfig_builder{
			Bruteforce: bruteforceconfigpb.BruteForceConfig_builder{
				MaxRequestsPerSecond:        proto.Int32(0),
				MaxConcurrency:              proto.Int32(1),
				StopAtFirstValidCredentials: proto.Bool(stopAtFirst),
			}.Build(),
		}.Build(),
	}.Build())
}

func startFakePasswordSSHServer(t *testing.T, validCreds map[string]string, acceptAll bool) *networkservicepb.NetworkService {
	t.Helper()
	srv, err := fakessh.New(&ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if acceptAll {
				return nil, nil
			}
			wantPass, ok := validCreds[c.User()]
			if ok && string(pass) == wantPass {
				return nil, nil
			}
			return nil, fmt.Errorf("auth failed")
		},
	})
	if err != nil {
		t.Fatalf("fakessh.New() failed: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })

	svc := proto.CloneOf(srv.NetworkService())
	return svc
}

func startFakeKeyboardInteractiveSSHServer(t *testing.T, validCreds map[string]string) *networkservicepb.NetworkService {
	t.Helper()
	srv, err := fakessh.New(&ssh.ServerConfig{
		KeyboardInteractiveCallback: func(c ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			answers, err := client("", "", []string{"Password: "}, []bool{false})
			if err != nil {
				return nil, err
			}
			wantPass, ok := validCreds[c.User()]
			if ok && len(answers) == 1 && answers[0] == wantPass {
				return nil, nil
			}
			return nil, fmt.Errorf("auth failed")
		},
	})
	if err != nil {
		t.Fatalf("fakessh.New() failed: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	return srv.NetworkService()
}

func startCancelingSSHServer(t *testing.T, cancel context.CancelFunc) *networkservicepb.NetworkService {
	t.Helper()
	srv, err := fakessh.New(&ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			cancel()
			return nil, fmt.Errorf("aborted")
		},
	})
	if err != nil {
		t.Fatalf("fakessh.New() failed: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	return srv.NetworkService()
}

func extractFoundCredentials(reports *detectionpb.DetectionReportList) []string {
	var creds []string
	for _, r := range reports.GetDetectionReports() {
		for _, ad := range r.GetVulnerability().GetAdditionalDetails() {
			creds = append(creds, ad.GetTextData().GetText())
		}
	}
	return creds
}

func TestNewAndOptions(t *testing.T) {
	tests := []struct {
		name      string
		cfg       *config.Config
		opts      *bruteforce.Options
		wantErr   error
		wantUsers []string
	}{
		{
			name:    "when_config_is_nil_returns_err_config_nil",
			cfg:     nil,
			wantErr: bruteforce.ErrConfigNil,
		},
		{
			name:    "when_default_options_used_loads_default_store",
			cfg:     config.Default(),
			wantErr: nil,
		},
		{
			name: "when_custom_store_provided_uses_custom_store",
			cfg:  config.Default(),
			opts: &bruteforce.Options{
				CredentialStore: smallStore([]string{"admin", "test"}, []string{"123456"}),
			},
			wantUsers: []string{"admin", "test"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			var (
				d   any
				err error
			)
			if tc.opts == nil && tc.cfg != nil {
				d, err = New(ctx, tc.cfg)
			} else {
				d, err = NewWithOptions(ctx, tc.cfg, tc.opts)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("NewWithOptions(%v, %v) error = %v, want %v", tc.cfg, tc.opts, err, tc.wantErr)
			}
			if tc.wantErr != nil {
				return
			}

			bfDetector, ok := d.(*bruteforce.Detector)
			if !ok {
				t.Fatalf("NewWithOptions(%v, %v) type = %T, want *bruteforce.Detector", tc.cfg, tc.opts, d)
			}
			if got := bfDetector.Name(); got != moduleName {
				t.Errorf("Detector.Name() = %q, want %q", got, moduleName)
			}
			if tc.wantUsers != nil {
				store := bfDetector.CredentialStore()
				if diff := cmp.Diff(tc.wantUsers, store.Usernames()); diff != "" {
					t.Errorf("CredentialStore().Usernames() diff (-want +got):\n%s", diff)
				}
			}

			h := &Handler{client: sshclient.New(tc.cfg)}
			if got := h.Name(); got != moduleName {
				t.Errorf("Handler.Name() = %q, want %q", got, moduleName)
			}
			if err := h.NewWorker().Close(); err != nil {
				t.Errorf("Worker.Close() = %v, want nil", err)
			}
			vuln := h.Vulnerability()
			if got := vuln.GetMainId().GetValue(); got != "WEAK_CREDENTIALS_FOR_SSH" {
				t.Errorf("Vulnerability().GetMainId().GetValue() = %q, want %q", got, "WEAK_CREDENTIALS_FOR_SSH")
			}
			if got := vuln.GetSeverity(); got != vulnerabilitypb.Severity_CRITICAL {
				t.Errorf("Vulnerability().GetSeverity() = %v, want %v", got, vulnerabilitypb.Severity_CRITICAL)
			}
		})
	}
}

func TestNew_DefaultStorePrependsEmptyPassword(t *testing.T) {
	testCases := []struct {
		name string
	}{
		{
			name: "when_default_store_built_prepends_empty_and_matching_username_plus_linux_defaults",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			d, err := New(t.Context(), config.Default())
			if err != nil {
				t.Fatalf("New() unexpected error: %v", err)
			}
			bfDetector, ok := d.(*bruteforce.Detector)
			if !ok {
				t.Fatalf("New() type = %T, want *bruteforce.Detector", d)
			}
			store := bfDetector.CredentialStore()
			users := store.Usernames()
			if len(users) == 0 {
				t.Fatal("CredentialStore().Usernames() is empty, want default usernames")
			}
			for _, extraUser := range []string{"ubuntu", "debian", "alpine"} {
				if !slices.Contains(users, extraUser) {
					t.Errorf("CredentialStore().Usernames() missing %q", extraUser)
				}
			}
			for _, u := range users {
				passes := store.Passwords(u)
				if len(passes) < 2 {
					t.Errorf("CredentialStore().Passwords(%q) len = %d, want >= 2", u, len(passes))
					continue
				}
				if passes[0] != "" {
					t.Errorf("CredentialStore().Passwords(%q)[0] = %q, want empty password", u, passes[0])
				}
				if passes[1] != u {
					t.Errorf("CredentialStore().Passwords(%q)[1] = %q, want username %q", u, passes[1], u)
				}
			}
			if rootPasses := store.Passwords("root"); len(rootPasses) < 3 || rootPasses[2] != "toor" {
				t.Errorf("CredentialStore().Passwords(\"root\") = %v, want \"toor\" at index 2", rootPasses)
			}
			if piPasses := store.Passwords("pi"); len(piPasses) < 3 || piPasses[2] != "raspberry" {
				t.Errorf("CredentialStore().Passwords(\"pi\") = %v, want \"raspberry\" at index 2", piPasses)
			}
		})
	}
}

func TestDetect_WeakCredentialsFound(t *testing.T) {
	tests := []struct {
		name        string
		validCreds  map[string]string
		acceptAll   bool
		stopAtFirst bool
		store       *credentialstore.CredentialStore
		wantCreds   []string
	}{
		{
			name:        "when_root_weak_password_matches_returns_verified_finding",
			validCreds:  map[string]string{"root": "123456"},
			stopAtFirst: true,
			store:       smallStore([]string{"root", "admin"}, []string{"wrong", "123456"}),
			wantCreds:   []string{"root:123456"},
		},
		{
			name:        "when_service_name_is_unknown_fingerprints_and_returns_verified_finding",
			validCreds:  map[string]string{"admin": "password"},
			stopAtFirst: true,
			store:       smallStore([]string{"admin"}, []string{"password"}),
			wantCreds:   []string{"admin:password"},
		},
		{
			name:        "when_service_name_is_empty_fingerprints_and_returns_verified_finding",
			validCreds:  map[string]string{"test": "test"},
			stopAtFirst: true,
			store:       smallStore([]string{"test"}, []string{"test"}),
			wantCreds:   []string{"test:test"},
		},
		{
			name: "when_stop_at_first_disabled_reports_all_valid_credentials",
			validCreds: map[string]string{
				"root":  "000000",
				"admin": "123456",
			},
			stopAtFirst: false,
			store:       smallStore([]string{"root", "admin"}, []string{"000000", "123456"}),
			wantCreds:   []string{"root:000000", "admin:123456"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			svc := startFakePasswordSSHServer(t, tc.validCreds, tc.acceptAll)
			if tc.name == "when_service_name_is_empty_fingerprints_and_returns_verified_finding" {
				svc.SetServiceName("")
			}
			if tc.name == "when_service_name_is_unknown_fingerprints_and_returns_verified_finding" {
				svc.SetServiceName("unknown")
			}

			detector, err := NewWithOptions(ctx, fastBruteForceConfig(tc.stopAtFirst), &bruteforce.Options{
				CredentialStore: tc.store,
			})
			if err != nil {
				t.Fatalf("NewWithOptions() unexpected error: %v", err)
			}

			reports, err := detector.Detect(ctx, svc)
			if err != nil {
				t.Fatalf("Detect(%v) unexpected error: %v", svc, err)
			}
			if len(reports.GetDetectionReports()) != 1 {
				t.Fatalf("len(Detect(%v).GetDetectionReports()) = %d, want 1", svc, len(reports.GetDetectionReports()))
			}

			report := reports.GetDetectionReports()[0]
			if got := report.GetDetectionStatus(); got != detectionpb.DetectionStatus_VULNERABILITY_VERIFIED {
				t.Errorf("report.GetDetectionStatus() = %v, want %v", got, detectionpb.DetectionStatus_VULNERABILITY_VERIFIED)
			}

			gotCreds := extractFoundCredentials(reports)
			if diff := cmp.Diff(tc.wantCreds, gotCreds); diff != "" {
				t.Errorf("Detect(%v) credentials diff (-want +got):\n%s", svc, diff)
			}
		})
	}
}

func TestDetect_KeyboardInteractiveAndEmptyPassword(t *testing.T) {
	tests := []struct {
		name        string
		serverSetup func(t *testing.T) *networkservicepb.NetworkService
		opts        *bruteforce.Options
		wantCreds   []string
	}{
		{
			name: "when_keyboard_interactive_weak_password_matches_returns_verified_finding",
			serverSetup: func(t *testing.T) *networkservicepb.NetworkService {
				return startFakeKeyboardInteractiveSSHServer(t, map[string]string{"root": "Password"})
			},
			opts: &bruteforce.Options{
				CredentialStore: smallStore([]string{"root"}, []string{"wrong", "Password"}),
			},
			wantCreds: []string{"root:Password"},
		},
		{
			name: "when_keyboard_interactive_password_is_strong_returns_no_findings",
			serverSetup: func(t *testing.T) *networkservicepb.NetworkService {
				return startFakeKeyboardInteractiveSSHServer(t, map[string]string{"root": "Str0ng_UnGu3ssable_P@ssw0rd!"})
			},
			opts: &bruteforce.Options{
				CredentialStore: smallStore([]string{"root"}, []string{"123456", "Password"}),
			},
			wantCreds: nil,
		},
		{
			name: "when_empty_password_matches_with_default_store_returns_verified_finding",
			serverSetup: func(t *testing.T) *networkservicepb.NetworkService {
				return startFakePasswordSSHServer(t, map[string]string{"root": ""}, false)
			},
			opts:      nil,
			wantCreds: []string{"root:"},
		},
		{
			name: "when_pam_keyboard_interactive_zero_prompt_passwordless_user_exists_reports_empty_password_not_honeypot",
			serverSetup: func(t *testing.T) *networkservicepb.NetworkService {
				srv, err := fakessh.New(&ssh.ServerConfig{
					KeyboardInteractiveCallback: func(c ssh.ConnMetadata, _ ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
						if c.User() == "alpine" {
							return nil, nil
						}
						return nil, fmt.Errorf("auth failed")
					},
				})
				if err != nil {
					t.Fatalf("fakessh.New() failed: %v", err)
				}
				t.Cleanup(func() { _ = srv.Close() })
				return srv.NetworkService()
			},
			opts: &bruteforce.Options{
				CredentialStore: smallStore([]string{"alpine"}, []string{"alpine", ""}),
			},
			wantCreds: []string{"alpine:"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			svc := tc.serverSetup(t)

			detector, err := NewWithOptions(ctx, fastBruteForceConfig(true), tc.opts)
			if err != nil {
				t.Fatalf("NewWithOptions() unexpected error: %v", err)
			}

			reports, err := detector.Detect(ctx, svc)
			if err != nil {
				t.Fatalf("Detect(%v) unexpected error: %v", svc, err)
			}

			gotCreds := extractFoundCredentials(reports)
			if diff := cmp.Diff(tc.wantCreds, gotCreds); diff != "" {
				t.Errorf("Detect(%v) credentials diff (-want +got):\n%s", svc, diff)
			}
		})
	}
}

func TestDetect_NoWeakCredentials(t *testing.T) {
	tests := []struct {
		name        string
		validCreds  map[string]string
		protocol    networkpb.TransportProtocol
		httpMethods []string
	}{
		{
			name:       "when_password_is_strong_returns_no_findings",
			validCreds: map[string]string{"root": "Str0ng_UnGu3ssable_P@ssw0rd!"},
			protocol:   networkpb.TransportProtocol_TCP,
		},
		{
			name:        "when_service_is_web_service_skips_without_findings",
			validCreds:  map[string]string{"root": "123456"},
			protocol:    networkpb.TransportProtocol_TCP,
			httpMethods: []string{"GET"},
		},
		{
			name:       "when_transport_protocol_is_udp_skips_without_findings",
			validCreds: map[string]string{"root": "123456"},
			protocol:   networkpb.TransportProtocol_UDP,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			svc := startFakePasswordSSHServer(t, tc.validCreds, false)
			svc.SetTransportProtocol(tc.protocol)
			if len(tc.httpMethods) > 0 {
				svc.SetSupportedHttpMethods(tc.httpMethods)
			}

			detector, err := NewWithOptions(ctx, fastBruteForceConfig(true), &bruteforce.Options{
				CredentialStore: smallStore([]string{"root"}, []string{"123456"}),
			})
			if err != nil {
				t.Fatalf("NewWithOptions() unexpected error: %v", err)
			}

			reports, err := detector.Detect(ctx, svc)
			if err != nil {
				t.Fatalf("Detect(%v) unexpected error: %v", svc, err)
			}
			if len(reports.GetDetectionReports()) != 0 {
				t.Errorf("Detect(%v) returned %d reports, want 0", svc, len(reports.GetDetectionReports()))
			}
		})
	}
}

func TestDetect_PublicKeyOnlyAndNonSSHService(t *testing.T) {
	pubKeySrv, err := fakessh.NewPublicKeyOnly()
	if err != nil {
		t.Fatalf("fakessh.NewPublicKeyOnly() failed: %v", err)
	}
	t.Cleanup(func() { _ = pubKeySrv.Close() })

	closedLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() failed: %v", err)
	}
	closedPort := uint32(closedLn.Addr().(*net.TCPAddr).Port)
	_ = closedLn.Close()

	closedSvc := networkservicepb.NetworkService_builder{
		ServiceName: "ssh",
		NetworkEndpoint: networkpb.NetworkEndpoint_builder{
			Type: networkpb.NetworkEndpoint_IP_PORT,
			IpAddress: networkpb.IpAddress_builder{
				Address:       "127.0.0.1",
				AddressFamily: networkpb.AddressFamily_IPV4,
			}.Build(),
			Port: networkpb.Port_builder{
				PortNumber: closedPort,
			}.Build(),
		}.Build(),
	}.Build()

	tests := []struct {
		name string
		svc  *networkservicepb.NetworkService
	}{
		{
			name: "when_public_key_only_ssh_server_skips_brute_forcing",
			svc:  pubKeySrv.NetworkService(),
		},
		{
			name: "when_closed_port_non_ssh_service_skips_brute_forcing",
			svc:  closedSvc,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			detector, err := NewWithOptions(ctx, fastBruteForceConfig(true), &bruteforce.Options{
				CredentialStore: smallStore([]string{"root"}, []string{"123456"}),
			})
			if err != nil {
				t.Fatalf("NewWithOptions() unexpected error: %v", err)
			}

			reports, err := detector.Detect(ctx, tc.svc)
			if err != nil {
				t.Fatalf("Detect(%v) unexpected error: %v", tc.svc, err)
			}
			if len(reports.GetDetectionReports()) != 0 {
				t.Errorf("Detect(%v) returned %d reports, want 0", tc.svc, len(reports.GetDetectionReports()))
			}
		})
	}
}

func TestHandler_FingerprintErrors(t *testing.T) {
	h := &Handler{client: sshclient.New(fastBruteForceConfig(true))}
	invalidSvc := networkservicepb.NetworkService_builder{
		ServiceName:     "ssh",
		NetworkEndpoint: &networkpb.NetworkEndpoint{},
	}.Build()

	tests := []struct {
		name                string
		cancelBeforeCall    bool
		cancelDuringConnect bool
		wantErr             error
	}{
		{
			name:             "when_context_canceled_before_call_returns_context_canceled",
			cancelBeforeCall: true,
			wantErr:          context.Canceled,
		},
		{
			name:    "when_endpoint_missing_address_returns_error",
			wantErr: netendpoint.ErrEndpointMissingAddress,
		},
		{
			name:                "when_context_canceled_during_connect_returns_context_canceled",
			cancelDuringConnect: true,
			wantErr:             context.Canceled,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			svc := invalidSvc
			if tc.cancelDuringConnect {
				svc = startCancelingSSHServer(t, cancel)
			}
			if tc.cancelBeforeCall {
				cancel()
			}

			_, err := h.Fingerprint(ctx, svc)
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("Fingerprint(%v) error = %v, want %v", svc, err, tc.wantErr)
			}
		})
	}
}

func TestHandler_TestCredentialErrors(t *testing.T) {
	h := &Handler{client: sshclient.New(fastBruteForceConfig(true))}
	invalidSvc := networkservicepb.NetworkService_builder{
		ServiceName:     "ssh",
		NetworkEndpoint: &networkpb.NetworkEndpoint{},
	}.Build()
	cred := bruteforce.Credential{Username: "root", Password: "123"}

	tests := []struct {
		name                string
		cancelBeforeCall    bool
		cancelDuringConnect bool
		wantErr             error
	}{
		{
			name:             "when_context_canceled_before_call_returns_context_canceled",
			cancelBeforeCall: true,
			wantErr:          context.Canceled,
		},
		{
			name:    "when_endpoint_missing_address_returns_error",
			wantErr: netendpoint.ErrEndpointMissingAddress,
		},
		{
			name:                "when_context_canceled_during_connect_returns_context_canceled",
			cancelDuringConnect: true,
			wantErr:             context.Canceled,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			svc := invalidSvc
			if tc.cancelDuringConnect {
				svc = startCancelingSSHServer(t, cancel)
			}
			if tc.cancelBeforeCall {
				cancel()
			}

			_, err := h.TestCredential(ctx, svc, cred)
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("TestCredential(%v, %v) error = %v, want %v", svc, cred, err, tc.wantErr)
			}
		})
	}
}

func TestDetect_StopsCleanlyOnMidRunTransportFailure(t *testing.T) {
	targetSvc := startFakePasswordSSHServer(t, nil, false)

	// Proxy TCP connections: forward the first connection (fingerprint probe), then
	// send a malformed post-banner SSH packet on subsequent connections to simulate
	// a non-penalty mid-run transport failure.
	targetAddr, err := netendpoint.ToURIAuthority(targetSvc.GetNetworkEndpoint())
	if err != nil {
		t.Fatalf("ToURIAuthority() failed: %v", err)
	}
	svc, connCount := startCustomDropSSHProxy(t, targetAddr, "SSH-2.0-Broken\r\n\x00\x00\x00\x01\x00", func(n int32) bool {
		return n > 1
	})

	detector, err := NewWithOptions(t.Context(), fastBruteForceConfig(true), &bruteforce.Options{
		CredentialStore: smallStore([]string{"root", "admin", "user"}, []string{"p1", "p2", "p3"}),
	})
	if err != nil {
		t.Fatalf("NewWithOptions() unexpected error: %v", err)
	}

	reports, err := detector.Detect(t.Context(), svc)
	if err != nil {
		t.Fatalf("Detect() unexpected error: %v", err)
	}
	if len(reports.GetDetectionReports()) != 0 {
		t.Errorf("len(Detect().GetDetectionReports()) = %d, want 0", len(reports.GetDetectionReports()))
	}
	// 1 fingerprint probe + maxConsecutiveTransportErrors (3) failed attempts = 4 connections, not 1+9=10.
	if got, want := connCount.Load(), int32(1+maxConsecutiveTransportErrors); got != want {
		t.Errorf("connection count = %d, want %d", got, want)
	}
}

func startPenaltyDropSSHProxy(t *testing.T, upstreamAddr string, shouldDropPreBanner func(connNum int32) bool) (*networkservicepb.NetworkService, *atomic.Int32) {
	t.Helper()
	return startCustomDropSSHProxy(t, upstreamAddr, "Not allowed at this time\r\n", shouldDropPreBanner)
}

func startZeroByteDropSSHProxy(t *testing.T, upstreamAddr string, shouldDropPreBanner func(connNum int32) bool) (*networkservicepb.NetworkService, *atomic.Int32) {
	t.Helper()
	return startCustomDropSSHProxy(t, upstreamAddr, "", shouldDropPreBanner)
}

func startCustomDropSSHProxy(t *testing.T, upstreamAddr, dropBanner string, shouldDropPreBanner func(connNum int32) bool) (*networkservicepb.NetworkService, *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() failed: %v", err)
	}
	var connCount atomic.Int32
	var wg sync.WaitGroup
	t.Cleanup(func() {
		_ = ln.Close()
		wg.Wait()
	})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			clientConn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			n := connCount.Add(1)
			if shouldDropPreBanner != nil && shouldDropPreBanner(n) {
				if dropBanner != "" {
					_, _ = clientConn.Write([]byte(dropBanner))
				}
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

	proxyAddr := ln.Addr().(*net.TCPAddr)
	svc := networkservicepb.NetworkService_builder{
		ServiceName:       "ssh",
		TransportProtocol: networkpb.TransportProtocol_TCP,
		NetworkEndpoint: networkpb.NetworkEndpoint_builder{
			Type: networkpb.NetworkEndpoint_IP_PORT,
			IpAddress: networkpb.IpAddress_builder{
				Address:       proxyAddr.IP.String(),
				AddressFamily: networkpb.AddressFamily_IPV4,
			}.Build(),
			Port: networkpb.Port_builder{
				PortNumber: uint32(proxyAddr.Port),
			}.Build(),
		}.Build(),
	}.Build()
	return svc, &connCount
}

func TestPenaltyCooldownRetries(t *testing.T) {
	targetSvc := startFakePasswordSSHServer(t, map[string]string{"ubuntu": "ubuntu"}, false)
	targetAddr, err := netendpoint.ToURIAuthority(targetSvc.GetNetworkEndpoint())
	if err != nil {
		t.Fatalf("ToURIAuthority() failed: %v", err)
	}

	testCases := []struct {
		name               string
		serviceName        string
		zeroByteDrop       bool
		preConfirmViaShare bool
		shouldDrop         func(connNum int32) bool
		customSleepFn      func(sleepCalls *atomic.Int32) func(context.Context, time.Duration) error
		store              *credentialstore.CredentialStore
		wantCreds          []string
		wantSleepCalls     int32
		wantDetectErr      error
		directCredCheck    bool
		wantCredErr        error
	}{
		{
			name:        "when_penalty_notices_occur_during_fingerprint_and_brute_force_within_budget_recovers_and_finds_cred",
			serviceName: "",
			shouldDrop: func(n int32) bool {
				// 4 drops during Fingerprint (conns 1..4), conn 5 succeeds Fingerprint,
				// 4 drops during TestCredential (conns 6..9), conn 10 tests root:wrong, conn 11 finds ubuntu:ubuntu.
				return (n >= 1 && n <= 4) || (n >= 6 && n <= 9)
			},
			store:          smallStore([]string{"root", "ubuntu"}, []string{"ubuntu"}),
			wantCreds:      []string{"ubuntu:ubuntu"},
			wantSleepCalls: 8,
		},
		{
			name:           "when_unconfirmed_endpoint_drops_with_zero_bytes_performs_zero_sleeps_even_when_labeled_ssh",
			serviceName:    "ssh",
			zeroByteDrop:   true,
			shouldDrop:     func(int32) bool { return true },
			store:          smallStore([]string{"ubuntu"}, []string{"ubuntu"}),
			wantCreds:      nil,
			wantSleepCalls: 0,
		},
		{
			name:         "when_ssh_confirmed_in_fingerprint_retries_subsequent_zero_byte_drops_in_test_credential",
			serviceName:  "",
			zeroByteDrop: true,
			shouldDrop: func(n int32) bool {
				// Conn 1 succeeds Fingerprint; Conns 2..5 drop with 0 bytes during TestCredential; Conn 6 authenticates.
				return n >= 2 && n <= 5
			},
			store:          smallStore([]string{"ubuntu"}, []string{"ubuntu"}),
			wantCreds:      []string{"ubuntu:ubuntu"},
			wantSleepCalls: 4,
		},
		{
			name:               "when_prior_detector_sharing_config_confirmed_ssh_retries_zero_byte_drops_in_fingerprint",
			serviceName:        "unknown",
			zeroByteDrop:       true,
			preConfirmViaShare: true,
			shouldDrop: func(n int32) bool {
				// Conn 1 is used by prior detector sharing cfg; Conns 2..4 drop with 0 bytes in Fingerprint; Conn 5 passes Fingerprint; Conn 6 authenticates.
				return n >= 2 && n <= 4
			},
			store:          smallStore([]string{"ubuntu"}, []string{"ubuntu"}),
			wantCreds:      []string{"ubuntu:ubuntu"},
			wantSleepCalls: 3,
		},
		{
			name:        "when_cumulative_penalty_budget_exhausted_across_fingerprint_and_test_credential_returns_stop_brute_force",
			serviceName: "",
			shouldDrop: func(n int32) bool {
				// Conns 1..5 drop in Fingerprint (5 sleeps), Conn 6 passes Fingerprint, Conns 7+ drop forever (10 more sleeps = 15 total, then ErrStopBruteForce).
				return n != 6
			},
			store:           smallStore([]string{"root", "admin", "ubuntu"}, []string{"p1", "p2", "ubuntu"}),
			wantCreds:       nil,
			wantSleepCalls:  maxPenaltyCooldownRetries,
			directCredCheck: true,
			wantCredErr:     bruteforce.ErrStopBruteForce,
		},
		{
			name:        "when_context_canceled_during_fingerprint_penalty_sleep_returns_canceled_error",
			serviceName: "",
			shouldDrop:  func(int32) bool { return true },
			customSleepFn: func(sleepCalls *atomic.Int32) func(context.Context, time.Duration) error {
				return func(_ context.Context, _ time.Duration) error {
					sleepCalls.Add(1)
					return context.Canceled
				}
			},
			store:          smallStore([]string{"ubuntu"}, []string{"ubuntu"}),
			wantSleepCalls: 1,
			wantDetectErr:  context.Canceled,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var svc *networkservicepb.NetworkService
			if tc.zeroByteDrop {
				svc, _ = startZeroByteDropSSHProxy(t, targetAddr, tc.shouldDrop)
			} else {
				svc, _ = startPenaltyDropSSHProxy(t, targetAddr, tc.shouldDrop)
			}
			svc.SetServiceName(tc.serviceName)

			cfg := fastBruteForceConfig(true)
			if tc.preConfirmViaShare {
				proxyAddr, addrErr := netendpoint.ToURIAuthority(svc.GetNetworkEndpoint())
				if addrErr != nil {
					t.Fatalf("ToURIAuthority() failed: %v", addrErr)
				}
				if _, authErr := sshclient.New(cfg).Connect(t.Context(), proxyAddr, "probe", "invalid"); !errors.Is(authErr, sshclient.ErrAuthFailed) {
					t.Fatalf("prior Connect() error = %v, want %v", authErr, sshclient.ErrAuthFailed)
				}
			}
			h := newHandler(cfg)
			var sleepCalls atomic.Int32
			if tc.customSleepFn != nil {
				h.sleepFn = tc.customSleepFn(&sleepCalls)
			} else {
				h.sleepFn = func(ctx context.Context, _ time.Duration) error {
					sleepCalls.Add(1)
					return ctx.Err()
				}
			}

			if tc.directCredCheck {
				ok, err := h.Fingerprint(t.Context(), svc)
				if err != nil || !ok {
					t.Fatalf("Fingerprint() = (%v, %v), want (true, nil)", ok, err)
				}
				_, credErr := h.TestCredential(t.Context(), svc, bruteforce.Credential{Username: "root", Password: "p1"})
				if !errors.Is(credErr, tc.wantCredErr) {
					t.Errorf("TestCredential() error = %v, want errors.Is %v", credErr, tc.wantCredErr)
				}
				if got := sleepCalls.Load(); got != tc.wantSleepCalls {
					t.Errorf("sleepCalls = %d, want %d", got, tc.wantSleepCalls)
				}
				return
			}

			detector, err := bruteforce.New(t.Context(), cfg, h, &bruteforce.Options{
				CredentialStore: tc.store,
			})
			if err != nil {
				t.Fatalf("bruteforce.New() unexpected error: %v", err)
			}

			reports, err := detector.Detect(t.Context(), svc)
			if !errors.Is(err, tc.wantDetectErr) {
				t.Fatalf("Detect() error = %v, want %v", err, tc.wantDetectErr)
			}
			if got := sleepCalls.Load(); got != tc.wantSleepCalls {
				t.Errorf("sleepCalls = %d, want %d", got, tc.wantSleepCalls)
			}
			if tc.wantDetectErr != nil {
				return
			}
			gotCreds := extractFoundCredentials(reports)
			if diff := cmp.Diff(tc.wantCreds, gotCreds); diff != "" {
				t.Errorf("Detect() credentials diff (-want +got):\n%s", diff)
			}
		})
	}

	t.Run("when_concurrent_workers_hit_same_penalty_wave_coalesces_into_single_sleep_and_close_clears_state", func(t *testing.T) {
		const workers = 4
		allDropped := make(chan struct{})
		var droppedInWave atomic.Int32
		svc, _ := startCustomDropSSHProxy(t, targetAddr, "Not allowed at this time\r\n", func(n int32) bool {
			// Conn 1 passes Fingerprint; Conns 2..5 are the 4 concurrent workers hitting the same penalty wave; Conn 6+ succeed.
			if n >= 2 && n <= 1+workers {
				if droppedInWave.Add(1) == workers {
					close(allDropped)
				}
				return true
			}
			return false
		})
		svc.SetServiceName("")

		cfg := fastBruteForceConfig(false)
		h := newHandler(cfg)
		var sleepCalls atomic.Int32
		h.sleepFn = func(ctx context.Context, _ time.Duration) error {
			sleepCalls.Add(1)
			select {
			case <-allDropped:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}

		ok, fpErr := h.Fingerprint(t.Context(), svc)
		if fpErr != nil || !ok {
			t.Fatalf("Fingerprint() = (%v, %v), want (true, nil)", ok, fpErr)
		}

		var wg sync.WaitGroup
		for i := range workers {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				pass := fmt.Sprintf("wrong-%d", idx)
				if idx == workers-1 {
					pass = "ubuntu"
				}
				matched, credErr := h.NewWorker().TestCredential(t.Context(), svc, bruteforce.Credential{Username: "ubuntu", Password: pass})
				if credErr != nil {
					t.Errorf("worker %d TestCredential() unexpected error: %v", idx, credErr)
				}
				if want := idx == workers-1; matched != want {
					t.Errorf("worker %d matched = %v, want %v", idx, matched, want)
				}
			}(i)
		}
		wg.Wait()

		if got := sleepCalls.Load(); got != 1 {
			t.Errorf("sleepCalls across %d concurrent workers = %d, want 1 coalesced sleep", workers, got)
		}
		proxyAddr, addrErr := netendpoint.ToURIAuthority(svc.GetNetworkEndpoint())
		if addrErr != nil {
			t.Fatalf("ToURIAuthority() failed: %v", addrErr)
		}
		st := h.getPenaltyState(proxyAddr)
		st.mu.Lock()
		gotRemaining := st.remaining
		st.mu.Unlock()
		if gotRemaining != maxPenaltyCooldownRetries-1 {
			t.Errorf("remaining penalty budget = %d, want %d", gotRemaining, maxPenaltyCooldownRetries-1)
		}
		if closeErr := h.Close(); closeErr != nil {
			t.Fatalf("Close() unexpected error: %v", closeErr)
		}
		h.mu.Lock()
		remainingEntries := len(h.penaltyStates)
		h.mu.Unlock()
		if remainingEntries != 0 {
			t.Errorf("len(h.penaltyStates) after Close() = %d, want 0", remainingEntries)
		}
	})
}

func TestHandler_TestCredential_MidRunPasswordAuthUnsupportedAndSleepCancel(t *testing.T) {
	pubKeySrv, err := fakessh.NewPublicKeyOnly()
	if err != nil {
		t.Fatalf("fakessh.NewPublicKeyOnly() failed: %v", err)
	}
	t.Cleanup(func() { _ = pubKeySrv.Close() })

	dropSvc, _ := startPenaltyDropSSHProxy(t, pubKeySrv.Addr(), func(int32) bool { return true })

	testCases := []struct {
		name    string
		svc     *networkservicepb.NetworkService
		sleepFn func(context.Context, time.Duration) error
		wantErr error
	}{
		{
			name:    "when_server_disables_password_auth_returns_stop_brute_force",
			svc:     pubKeySrv.NetworkService(),
			sleepFn: func(ctx context.Context, _ time.Duration) error { return ctx.Err() },
			wantErr: bruteforce.ErrStopBruteForce,
		},
		{
			name: "when_context_canceled_during_test_credential_sleep_returns_canceled",
			svc:  dropSvc,
			sleepFn: func(_ context.Context, _ time.Duration) error {
				return context.Canceled
			},
			wantErr: context.Canceled,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			h := newHandler(fastBruteForceConfig(true))
			h.sleepFn = func(c context.Context, d time.Duration) error {
				err := tc.sleepFn(c, d)
				if errors.Is(err, context.Canceled) {
					cancel()
				}
				return err
			}
			w := h.NewWorker()
			_, gotErr := w.TestCredential(ctx, tc.svc, bruteforce.Credential{Username: "root", Password: "x"})
			if !errors.Is(gotErr, tc.wantErr) {
				t.Errorf("Worker.TestCredential() error = %v, want errors.Is %v", gotErr, tc.wantErr)
			}
		})
	}

	t.Run("when_sleep_fn_is_nil_falls_back_to_default_sleep_with_canceled_context", func(t *testing.T) {
		h := &Handler{client: sshclient.New(fastBruteForceConfig(true))}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if err := h.sleep(ctx, time.Second); !errors.Is(err, context.Canceled) {
			t.Errorf("h.sleep() error = %v, want %v", err, context.Canceled)
		}
	})
}

func TestDetect_RejectsAcceptAllAndPerUserWildcardHoneypots(t *testing.T) {
	globalAcceptAllSvc := startFakePasswordSSHServer(t, nil, true)

	cowrieRootWildcardSrv, err := fakessh.New(&ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, _ []byte) (*ssh.Permissions, error) {
			if c.User() == "root" {
				return nil, nil
			}
			return nil, fmt.Errorf("rejected")
		},
	})
	if err != nil {
		t.Fatalf("fakessh.New() failed: %v", err)
	}
	t.Cleanup(func() { _ = cowrieRootWildcardSrv.Close() })

	noneAuthHoneypotSrv, err := fakessh.New(&ssh.ServerConfig{
		NoClientAuth: true,
	})
	if err != nil {
		t.Fatalf("fakessh.New() failed: %v", err)
	}
	t.Cleanup(func() { _ = noneAuthHoneypotSrv.Close() })

	store := smallStore([]string{"root", "admin"}, []string{"", "root", "admin"})
	for _, tc := range []struct {
		name string
		svc  *networkservicepb.NetworkService
	}{
		{name: "when_global_accept_all_honeypot_returns_zero_findings", svc: globalAcceptAllSvc},
		{name: "when_per_user_wildcard_cowrie_honeypot_returns_zero_findings", svc: cowrieRootWildcardSrv.NetworkService()},
		{name: "when_global_none_auth_honeypot_returns_zero_findings", svc: noneAuthHoneypotSrv.NetworkService()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			detector, err := NewWithOptions(t.Context(), fastBruteForceConfig(true), &bruteforce.Options{
				CredentialStore: store,
			})
			if err != nil {
				t.Fatalf("NewWithOptions() failed: %v", err)
			}
			reports, err := detector.Detect(t.Context(), tc.svc)
			if err != nil {
				t.Fatalf("Detect() unexpected error: %v", err)
			}
			if len(reports.GetDetectionReports()) != 0 {
				t.Errorf("Detect() returned %d reports on honeypot, want 0: %v", len(reports.GetDetectionReports()), reports)
			}
		})
	}
}
