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

package mysql

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/goonami-scanner/common/bruteforce"
	"github.com/google/goonami-scanner/common/clients/mysqlclient"
	"github.com/google/goonami-scanner/common/credentialstore"
	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/net/netendpoint"
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

func writeFakePacket(w io.Writer, seq byte, payload []byte) error {
	header := []byte{
		byte(len(payload)),
		byte(len(payload) >> 8),
		byte(len(payload) >> 16),
		seq,
	}
	if _, err := w.Write(header); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func readFakePacket(r io.Reader) ([]byte, byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, 0, err
	}
	length := int(header[0]) | int(header[1])<<8 | int(header[2])<<16
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, 0, err
	}
	return payload, header[3], nil
}

func buildClearPasswordGreeting() []byte {
	const (
		capLongPassword              uint32 = 1 << 0
		capProtocol41                uint32 = 1 << 9
		capSecureConn                uint32 = 1 << 15
		capPluginAuth                uint32 = 1 << 19
		capPluginAuthLenEncClientDat uint32 = 1 << 21
	)
	caps := capLongPassword | capProtocol41 | capSecureConn | capPluginAuth | capPluginAuthLenEncClientDat

	var buf []byte
	buf = append(buf, 0x0a)
	buf = append(buf, "8.0.36\x00"...)
	buf = append(buf, 1, 0, 0, 0)
	buf = append(buf, "01234567"...)
	buf = append(buf, 0x00)

	var lowerCaps [2]byte
	binary.LittleEndian.PutUint16(lowerCaps[:], uint16(caps&0xffff))
	buf = append(buf, lowerCaps[:]...)
	buf = append(buf, 45)
	buf = append(buf, 0x02, 0x00)

	var upperCaps [2]byte
	binary.LittleEndian.PutUint16(upperCaps[:], uint16(caps>>16))
	buf = append(buf, upperCaps[:]...)
	buf = append(buf, 21)
	buf = append(buf, make([]byte, 10)...)
	buf = append(buf, "890123456789\x00"...)
	buf = append(buf, "mysql_clear_password\x00"...)
	return buf
}

func parseCleartextAuth(pkt []byte) (user, pass string, ok bool) {
	if len(pkt) < 33 {
		return "", "", false
	}
	pos := 32
	userEnd := bytes.IndexByte(pkt[pos:], 0x00)
	if userEnd < 0 {
		return "", "", false
	}
	user = string(pkt[pos : pos+userEnd])
	pos += userEnd + 1
	if pos >= len(pkt) {
		return "", "", false
	}
	authLen := int(pkt[pos])
	pos++
	if pos+authLen > len(pkt) {
		return "", "", false
	}
	rawAuth := pkt[pos : pos+authLen]
	pass = string(bytes.TrimSuffix(rawAuth, []byte{0x00}))
	return user, pass, true
}

func startFakeMySQLService(t *testing.T, handler func(conn net.Conn)) *networkservicepb.NetworkService {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() failed: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				handler(c)
			}(conn)
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		<-done
	})

	port := uint32(ln.Addr().(*net.TCPAddr).Port)
	return networkservicepb.NetworkService_builder{
		ServiceName:       "mysql",
		TransportProtocol: networkpb.TransportProtocol_TCP,
		NetworkEndpoint: networkpb.NetworkEndpoint_builder{
			Type: networkpb.NetworkEndpoint_IP_PORT,
			IpAddress: networkpb.IpAddress_builder{
				Address:       "127.0.0.1",
				AddressFamily: networkpb.AddressFamily_IPV4,
			}.Build(),
			Port: networkpb.Port_builder{
				PortNumber: port,
			}.Build(),
		}.Build(),
	}.Build()
}

func startFakePasswordMySQLServer(t *testing.T, validCreds map[string]string, acceptAll bool) *networkservicepb.NetworkService {
	t.Helper()
	return startFakeMySQLService(t, func(conn net.Conn) {
		if err := writeFakePacket(conn, 0, buildClearPasswordGreeting()); err != nil {
			return
		}
		resp, seq, err := readFakePacket(conn)
		if err != nil {
			return
		}
		user, pass, ok := parseCleartextAuth(resp)
		wantPass, userExists := validCreds[user]
		if ok && (acceptAll || (userExists && pass == wantPass)) {
			if err := writeFakePacket(conn, seq+1, []byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00}); err != nil {
				return
			}
			for {
				_, cmdSeq, err := readFakePacket(conn)
				if err != nil {
					return
				}
				if err := writeFakePacket(conn, cmdSeq+1, []byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00}); err != nil {
					return
				}
			}
		}
		errPkt := append([]byte{0xff, 0x15, 0x04}, "#28000Access denied"...)
		_ = writeFakePacket(conn, seq+1, errPkt)
	})
}

func startCancelingMySQLServer(t *testing.T, cancel context.CancelFunc) *networkservicepb.NetworkService {
	t.Helper()
	return startFakeMySQLService(t, func(conn net.Conn) {
		cancel()
		time.Sleep(20 * time.Millisecond)
	})
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

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *config.Config
		wantErr error
	}{
		{
			name:    "when_config_is_nil_returns_err_config_nil",
			wantErr: bruteforce.ErrConfigNil,
		},
		{
			name: "when_valid_config_provided_returns_detector",
			cfg:  config.Default(),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := New(t.Context(), tc.cfg)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("New(%v) error = %v, want %v", tc.cfg, err, tc.wantErr)
			}
			if tc.wantErr != nil {
				return
			}
			if got.Name() != moduleName {
				t.Errorf("New(%v).Name() = %q, want %q", tc.cfg, got.Name(), moduleName)
			}
		})
	}
}

func TestNewWithOptions(t *testing.T) {
	defaultStore, err := credentialstore.NewWithDefaults()
	if err != nil {
		t.Fatalf("credentialstore.NewWithDefaults() failed: %v", err)
	}
	if err := defaultStore.PrependUser("root"); err != nil {
		t.Fatalf("defaultStore.PrependUser(%q) failed: %v", "root", err)
	}
	if err := defaultStore.PrependPasswordForUser("root", ""); err != nil {
		t.Fatalf("defaultStore.PrependPasswordForUser(%q, %q) failed: %v", "root", "", err)
	}

	tests := []struct {
		name                string
		cfg                 *config.Config
		opts                *bruteforce.Options
		wantUsers           []string
		wantFirstUserPasses []string
		wantErr             error
	}{
		{
			name:    "when_config_is_nil_returns_err_config_nil",
			wantErr: bruteforce.ErrConfigNil,
		},
		{
			name:                "when_default_options_used_loads_default_store_with_root_empty_password",
			cfg:                 config.Default(),
			wantUsers:           defaultStore.Usernames(),
			wantFirstUserPasses: defaultStore.Passwords("root"),
		},
		{
			name: "when_custom_store_provided_uses_custom_store",
			cfg:  config.Default(),
			opts: &bruteforce.Options{
				CredentialStore: smallStore([]string{"admin", "test"}, []string{"123456"}),
			},
			wantUsers:           []string{"admin", "test"},
			wantFirstUserPasses: []string{"123456"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NewWithOptions(t.Context(), tc.cfg, tc.opts)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("NewWithOptions(%v, %v) error = %v, want %v", tc.cfg, tc.opts, err, tc.wantErr)
			}
			if tc.wantErr != nil {
				return
			}
			if got.Name() != moduleName {
				t.Errorf("NewWithOptions(%v, %v).Name() = %q, want %q", tc.cfg, tc.opts, got.Name(), moduleName)
			}
			store := got.CredentialStore()
			if diff := cmp.Diff(tc.wantUsers, store.Usernames()); diff != "" {
				t.Errorf("CredentialStore().Usernames() diff (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tc.wantFirstUserPasses, store.Passwords(tc.wantUsers[0])); diff != "" {
				t.Errorf("CredentialStore().Passwords(%q) diff (-want +got):\n%s", tc.wantUsers[0], diff)
			}
		})
	}
}

func TestHandler(t *testing.T) {
	h := &Handler{client: mysqlclient.New(config.Default())}
	if got := h.Name(); got != moduleName {
		t.Errorf("Handler.Name() = %q, want %q", got, moduleName)
	}
	if err := h.NewWorker().Close(); err != nil {
		t.Errorf("Handler.NewWorker().Close() = %v, want nil", err)
	}
	vuln := h.Vulnerability()
	if got := vuln.GetMainId().GetValue(); got != "WEAK_CREDENTIALS_FOR_MYSQL" {
		t.Errorf("Handler.Vulnerability().GetMainId().GetValue() = %q, want %q", got, "WEAK_CREDENTIALS_FOR_MYSQL")
	}
	if got := vuln.GetSeverity(); got != vulnerabilitypb.Severity_CRITICAL {
		t.Errorf("Handler.Vulnerability().GetSeverity() = %v, want %v", got, vulnerabilitypb.Severity_CRITICAL)
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
			name:        "when_accept_all_mysql_server_fingerprints_and_returns_verified_finding",
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
			svc := startFakePasswordMySQLServer(t, tc.validCreds, tc.acceptAll)

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
			svc := startFakePasswordMySQLServer(t, tc.validCreds, false)
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

func TestDetect_HostBlockedAndNonMySQLService(t *testing.T) {
	hostBlockedSvc := startFakeMySQLService(t, func(conn net.Conn) {
		errPkt := append([]byte{0xff, 0x6a, 0x04}, "#HY000Host is not allowed to connect"...)
		_ = writeFakePacket(conn, 0, errPkt)
	})
	closedSvc := closedPortService(t)

	tests := []struct {
		name string
		svc  *networkservicepb.NetworkService
	}{
		{
			name: "when_host_not_privileged_mysql_server_skips_brute_forcing",
			svc:  hostBlockedSvc,
		},
		{
			name: "when_closed_port_non_mysql_service_skips_brute_forcing",
			svc:  closedSvc,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			detector, err := NewWithOptions(ctx, fastBruteForceConfig(true), &bruteforce.Options{
				CredentialStore: smallStore([]string{"root", "admin"}, []string{"123456", "password"}),
			})
			if err != nil {
				t.Fatalf("NewWithOptions() unexpected error: %v", err)
			}

			reports, err := detector.Detect(ctx, tc.svc)
			if err != nil {
				t.Fatalf("Detect(%v) unexpected error: %v", tc.svc, err)
			}
			if len(reports.GetDetectionReports()) != 0 {
				t.Errorf("len(Detect(%v).GetDetectionReports()) = %d, want 0", tc.svc, len(reports.GetDetectionReports()))
			}
		})
	}
}

func TestDetect_NonAuthErrorStopsBruteForcingEarly(t *testing.T) {
	var connCount atomic.Int32
	stopsEarlySvc := startFakeMySQLService(t, func(conn net.Conn) {
		n := connCount.Add(1)
		if n == 1 {
			if err := writeFakePacket(conn, 0, buildClearPasswordGreeting()); err != nil {
				return
			}
			_, seq, err := readFakePacket(conn)
			if err != nil {
				return
			}
			errPkt := append([]byte{0xff, 0x15, 0x04}, "#28000Access denied"...)
			_ = writeFakePacket(conn, seq+1, errPkt)
			return
		}
		errPkt := append([]byte{0xff, 0x6a, 0x04}, "#HY000Host is not allowed to connect"...)
		_ = writeFakePacket(conn, 0, errPkt)
	})

	ctx := t.Context()
	detector, err := NewWithOptions(ctx, fastBruteForceConfig(true), &bruteforce.Options{
		CredentialStore: smallStore([]string{"root", "admin"}, []string{"123456", "password"}),
	})
	if err != nil {
		t.Fatalf("NewWithOptions() unexpected error: %v", err)
	}

	reports, err := detector.Detect(ctx, stopsEarlySvc)
	if !errors.Is(err, mysqlclient.ErrPasswordAuthUnsupported) {
		t.Fatalf("Detect(%v) error = %v, want %v", stopsEarlySvc, err, mysqlclient.ErrPasswordAuthUnsupported)
	}
	if len(reports.GetDetectionReports()) != 0 {
		t.Errorf("len(Detect(%v).GetDetectionReports()) = %d, want 0", stopsEarlySvc, len(reports.GetDetectionReports()))
	}
	if got := connCount.Load(); got != 2 {
		t.Errorf("stopsEarlySvc connection count = %d, want 2", got)
	}
}

func TestHandler_Fingerprint_ContextCanceledBeforeCall(t *testing.T) {
	h := &Handler{client: mysqlclient.New(fastBruteForceConfig(true))}
	svc := invalidEndpointService()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if _, err := h.Fingerprint(ctx, svc); !errors.Is(err, context.Canceled) {
		t.Errorf("Fingerprint(%v) error = %v, want %v", svc, err, context.Canceled)
	}
}

func TestHandler_Fingerprint_EndpointMissingAddress(t *testing.T) {
	h := &Handler{client: mysqlclient.New(fastBruteForceConfig(true))}
	svc := invalidEndpointService()

	if _, err := h.Fingerprint(t.Context(), svc); !errors.Is(err, netendpoint.ErrEndpointMissingAddress) {
		t.Errorf("Fingerprint(%v) error = %v, want %v", svc, err, netendpoint.ErrEndpointMissingAddress)
	}
}

func TestHandler_Fingerprint_ContextCanceledDuringConnect(t *testing.T) {
	h := &Handler{client: mysqlclient.New(fastBruteForceConfig(true))}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	svc := startCancelingMySQLServer(t, cancel)

	if _, err := h.Fingerprint(ctx, svc); !errors.Is(err, context.Canceled) {
		t.Errorf("Fingerprint(%v) error = %v, want %v", svc, err, context.Canceled)
	}
}

func TestHandler_TestCredential_ContextCanceledBeforeCall(t *testing.T) {
	h := &Handler{client: mysqlclient.New(fastBruteForceConfig(true))}
	svc := invalidEndpointService()
	cred := bruteforce.Credential{Username: "root", Password: "123"}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if _, err := h.TestCredential(ctx, svc, cred); !errors.Is(err, context.Canceled) {
		t.Errorf("TestCredential(%v, %v) error = %v, want %v", svc, cred, err, context.Canceled)
	}
}

func TestHandler_TestCredential_ContextCanceledDuringConnect(t *testing.T) {
	h := &Handler{client: mysqlclient.New(fastBruteForceConfig(true))}
	cred := bruteforce.Credential{Username: "root", Password: "123"}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	svc := startCancelingMySQLServer(t, cancel)

	if _, err := h.TestCredential(ctx, svc, cred); !errors.Is(err, context.Canceled) {
		t.Errorf("TestCredential(%v, %v) error = %v, want %v", svc, cred, err, context.Canceled)
	}
}

func TestHandler_TestCredential_Errors(t *testing.T) {
	h := &Handler{client: mysqlclient.New(fastBruteForceConfig(true))}
	cred := bruteforce.Credential{Username: "root", Password: "123"}
	invalidSvc := invalidEndpointService()
	closedSvc := closedPortService(t)

	tests := []struct {
		name    string
		svc     *networkservicepb.NetworkService
		wantErr error
	}{
		{
			name:    "when_endpoint_missing_address_returns_error",
			svc:     invalidSvc,
			wantErr: netendpoint.ErrEndpointMissingAddress,
		},
		{
			name:    "when_connection_fails_with_non_auth_error_returns_classified_error",
			svc:     closedSvc,
			wantErr: mysqlclient.ErrNotMySQLService,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := h.TestCredential(t.Context(), tc.svc, cred); !errors.Is(err, tc.wantErr) {
				t.Errorf("TestCredential(%v, %v) error = %v, want %v", tc.svc, cred, err, tc.wantErr)
			}
		})
	}
}

func invalidEndpointService() *networkservicepb.NetworkService {
	return networkservicepb.NetworkService_builder{
		ServiceName:     "mysql",
		NetworkEndpoint: &networkpb.NetworkEndpoint{},
	}.Build()
}

func closedPortService(t *testing.T) *networkservicepb.NetworkService {
	t.Helper()
	closedLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() failed: %v", err)
	}
	closedPort := uint32(closedLn.Addr().(*net.TCPAddr).Port)
	_ = closedLn.Close()

	return networkservicepb.NetworkService_builder{
		ServiceName: "mysql",
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
}
