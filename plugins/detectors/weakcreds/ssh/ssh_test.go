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
	"sync/atomic"
	"testing"

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
	d, err := New(t.Context(), config.Default())
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}
	bfDetector, ok := d.(*bruteforce.Detector)
	if !ok {
		t.Fatalf("New() type = %T, want *bruteforce.Detector", d)
	}
	store := bfDetector.CredentialStore()
	if len(store.Usernames()) == 0 {
		t.Fatal("CredentialStore().Usernames() is empty, want default usernames")
	}
	for _, u := range store.Usernames() {
		passes := store.Passwords(u)
		if len(passes) == 0 {
			t.Errorf("CredentialStore().Passwords(%q) is empty, want empty password first", u)
			continue
		}
		if passes[0] != "" {
			t.Errorf("CredentialStore().Passwords(%q)[0] = %q, want %q", u, passes[0], "")
		}
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
			name:        "when_accept_all_ssh_server_fingerprints_and_returns_verified_finding",
			acceptAll:   true,
			stopAtFirst: true,
			store:       smallStore([]string{"admin"}, []string{"admin"}),
			wantCreds:   []string{"admin:admin"},
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
	// close subsequent connections immediately to simulate a target dropping SSH traffic.
	targetAddr, err := netendpoint.ToURIAuthority(targetSvc.GetNetworkEndpoint())
	if err != nil {
		t.Fatalf("ToURIAuthority() failed: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() failed: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	var connCount atomic.Int32
	go func() {
		for {
			clientConn, err := ln.Accept()
			if err != nil {
				return
			}
			n := connCount.Add(1)
			if n > 1 {
				_ = clientConn.Close()
				continue
			}
			go func(c net.Conn) {
				defer c.Close()
				upstream, err := net.Dial("tcp", targetAddr)
				if err != nil {
					return
				}
				defer upstream.Close()
				done := make(chan struct{})
				go func() {
					_, _ = io.Copy(upstream, c)
					close(done)
				}()
				_, _ = io.Copy(c, upstream)
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
