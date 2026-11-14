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

package ftp

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/goonami-scanner/common/bruteforce"
	"github.com/google/goonami-scanner/common/credentialstore"
	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/module"
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

func testServerTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.StartTLS()
	cert := srv.TLS.Certificates[0]
	srv.Close()
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
}

type fakeFTPOptions struct {
	validCreds        map[string]string
	acceptAll         bool
	passwordlessUser  map[string]bool
	multiLineBanner   bool
	preliminary120    bool
	requireExplicit   bool
	disallowAnonInTLS bool
	implicitTLS       bool
	allowlistOnly     bool
	denyWith550       bool
	featDisabled      bool
	pwdMode           string // "", "xpwd", "cwd", "550_cwd"
	tlsCfg            *tls.Config
}

func startRawTCPService(t *testing.T, serviceName string, handler func(net.Conn)) *networkservicepb.NetworkService {
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
		ServiceName:       serviceName,
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

func startFakeFTPServer(t *testing.T, opts fakeFTPOptions) *networkservicepb.NetworkService {
	t.Helper()
	svcName := "ftp"
	if opts.implicitTLS {
		svcName = "ftps"
	}
	if (opts.implicitTLS || opts.requireExplicit) && opts.tlsCfg == nil {
		opts.tlsCfg = testServerTLSConfig(t)
	}

	return startRawTCPService(t, svcName, func(rawConn net.Conn) {
		conn := rawConn
		inTLS := false
		if opts.implicitTLS {
			tlsConn := tls.Server(rawConn, opts.tlsCfg)
			if err := tlsConn.Handshake(); err != nil {
				return
			}
			conn = tlsConn
			inTLS = true
		}

		if opts.preliminary120 {
			_, _ = io.WriteString(conn, "120 Service ready in 1 minute.\r\n")
		}
		if opts.multiLineBanner {
			_, _ = io.WriteString(conn, "220-Welcome to FakeFTP\r\n220-Authorized users only\r\n220 FakeFTP ready.\r\n")
		} else {
			_, _ = io.WriteString(conn, "220 (vsFTPd 3.0.5)\r\n")
		}

		reader := bufio.NewReader(conn)
		var pendingUser string
		loggedIn := false

		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")
			cmd, arg, _ := strings.Cut(line, " ")
			upper := strings.ToUpper(cmd)

			switch upper {
			case "AUTH":
				if strings.EqualFold(arg, "TLS") && opts.tlsCfg != nil && !inTLS {
					_, _ = io.WriteString(conn, "234 Proceed with negotiation.\r\n")
					tlsConn := tls.Server(conn, opts.tlsCfg)
					if err := tlsConn.Handshake(); err != nil {
						return
					}
					conn = tlsConn
					reader = bufio.NewReader(conn)
					inTLS = true
					continue
				}
				_, _ = io.WriteString(conn, "504 Unknown AUTH mechanism.\r\n")
			case "FEAT":
				if opts.featDisabled {
					_, _ = io.WriteString(conn, "500 FEAT not understood.\r\n")
					continue
				}
				_, _ = io.WriteString(conn, "211-Features:\r\n UTF8\r\n211 End\r\n")
			case "SYST":
				_, _ = io.WriteString(conn, "215 UNIX Type: L8\r\n")
			case "USER":
				loggedIn = false
				if opts.disallowAnonInTLS && inTLS && (strings.EqualFold(arg, "anonymous") || strings.EqualFold(arg, "ftp")) {
					_, _ = io.WriteString(conn, "530 Anonymous sessions may not use encryption.\r\n")
					continue
				}
				if opts.requireExplicit && !inTLS && !strings.EqualFold(arg, "anonymous") {
					_, _ = io.WriteString(conn, "421 Sorry, cleartext sessions are not accepted on this server.\r\n")
					return
				}
				if opts.allowlistOnly {
					_, okPwdless := opts.passwordlessUser[arg]
					_, okValid := opts.validCreds[arg]
					if !okPwdless && !okValid {
						if opts.denyWith550 {
							_, _ = io.WriteString(conn, "550 Permission denied.\r\n")
						} else {
							_, _ = io.WriteString(conn, "530 Permission denied.\r\n")
						}
						continue
					}
				}
				if opts.passwordlessUser[arg] {
					loggedIn = true
					_, _ = io.WriteString(conn, "230 Login successful.\r\n")
					continue
				}
				pendingUser = arg
				_, _ = io.WriteString(conn, "331 Please specify the password.\r\n")
			case "PASS":
				if pendingUser == "" {
					_, _ = io.WriteString(conn, "503 Login with USER first.\r\n")
					continue
				}
				wantPass, ok := opts.validCreds[pendingUser]
				pendingUser = ""
				if opts.acceptAll || (ok && arg == wantPass) {
					loggedIn = true
					_, _ = io.WriteString(conn, "230 Login successful.\r\n")
					continue
				}
				if opts.denyWith550 {
					_, _ = io.WriteString(conn, "550 User cannot log in.\r\n")
				} else {
					_, _ = io.WriteString(conn, "530 Login incorrect.\r\n")
				}
			case "PWD":
				if !loggedIn {
					_, _ = io.WriteString(conn, "530 Please login with USER and PASS.\r\n")
					continue
				}
				switch opts.pwdMode {
				case "xpwd", "cwd":
					_, _ = io.WriteString(conn, "502 Command not implemented.\r\n")
				case "550_cwd":
					_, _ = io.WriteString(conn, "550 Permission denied.\r\n")
				default:
					_, _ = io.WriteString(conn, "257 \"/\" is the current directory\r\n")
				}
			case "XPWD":
				if !loggedIn {
					_, _ = io.WriteString(conn, "530 Please login with USER and PASS.\r\n")
					continue
				}
				if opts.pwdMode == "xpwd" {
					_, _ = io.WriteString(conn, "257 \"/home\" is the current directory\r\n")
					continue
				}
				_, _ = io.WriteString(conn, "502 Command not implemented.\r\n")
			case "CWD":
				if !loggedIn {
					_, _ = io.WriteString(conn, "530 Please login with USER and PASS.\r\n")
					continue
				}
				_, _ = io.WriteString(conn, "250 Directory successfully changed.\r\n")
			case "NOOP":
				// Pre-auth NOOP returns 200 in RFC 959; verifyLoggedIn must NOT rely on NOOP.
				_, _ = io.WriteString(conn, "200 NOOP ok.\r\n")
			case "QUIT":
				_, _ = io.WriteString(conn, "221 Goodbye.\r\n")
				return
			default:
				_, _ = io.WriteString(conn, "500 Unknown command.\r\n")
			}
		}
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

func TestInitRegistersDetector(t *testing.T) {
	detectors, err := module.AllDetectors(t.Context(), config.Default())
	if err != nil {
		t.Fatalf("module.AllDetectors() unexpected error: %v", err)
	}
	found := false
	for _, d := range detectors {
		if d.Name() == moduleName {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("detector %q not registered in module.DefaultRegistry", moduleName)
	}
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

			h := NewHandler(tc.cfg)
			if got := h.Name(); got != moduleName {
				t.Errorf("Handler.Name() = %q, want %q", got, moduleName)
			}
			if err := h.NewWorker().Close(); err != nil {
				t.Errorf("Worker.Close() = %v, want nil", err)
			}
			vuln := h.Vulnerability()
			if got := vuln.GetMainId().GetPublisher(); got != "GOOGLE" {
				t.Errorf("Vulnerability().GetMainId().GetPublisher() = %q, want %q", got, "GOOGLE")
			}
			if got := vuln.GetMainId().GetValue(); got != "WEAK_CREDENTIALS_FOR_FTP" {
				t.Errorf("Vulnerability().GetMainId().GetValue() = %q, want %q", got, "WEAK_CREDENTIALS_FOR_FTP")
			}
			if got := vuln.GetSeverity(); got != vulnerabilitypb.Severity_CRITICAL {
				t.Errorf("Vulnerability().GetSeverity() = %v, want %v", got, vulnerabilitypb.Severity_CRITICAL)
			}
		})
	}
}

func TestNew_DefaultStoreScopesAnonymousAndPrependsEmptyPasswords(t *testing.T) {
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
		t.Fatal("CredentialStore().Usernames() is empty")
	}
	if users[0] != "anonymous" {
		t.Errorf("CredentialStore().Usernames()[0] = %q, want %q", users[0], "anonymous")
	}
	wantAnonPasses := []string{"", "anonymous", "anonymous@example.com"}
	if diff := cmp.Diff(wantAnonPasses, store.Passwords("anonymous")); diff != "" {
		t.Errorf("CredentialStore().Passwords(\"anonymous\") diff (-want +got):\n%s", diff)
	}
	for _, u := range users {
		passes := store.Passwords(u)
		if !containsString(passes, "") {
			t.Errorf("CredentialStore().Passwords(%q) missing empty password", u)
		}
	}
}

func containsString(items []string, target string) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}

func TestDetect_WeakCredentialsFound(t *testing.T) {
	tests := []struct {
		name        string
		ftpOpts     fakeFTPOptions
		stopAtFirst bool
		store       *credentialstore.CredentialStore
		wantCreds   []string
	}{
		{
			name: "when_cleartext_weak_password_matches_returns_verified_finding",
			ftpOpts: fakeFTPOptions{
				validCreds: map[string]string{"admin": "123456"},
			},
			stopAtFirst: true,
			store:       smallStore([]string{"root", "admin"}, []string{"wrong", "123456"}),
			wantCreds:   []string{"admin:123456"},
		},
		{
			name: "when_preliminary_120_multiline_banner_and_xpwd_fallback_returns_verified_finding",
			ftpOpts: fakeFTPOptions{
				validCreds:      map[string]string{"ftp": "ftp"},
				preliminary120:  true,
				multiLineBanner: true,
				pwdMode:         "xpwd",
			},
			stopAtFirst: true,
			store:       smallStore([]string{"ftp"}, []string{"ftp"}),
			wantCreds:   []string{"ftp:ftp"},
		},
		{
			name: "when_pwd_and_xpwd_unsupported_falls_back_to_cwd_and_returns_verified_finding",
			ftpOpts: fakeFTPOptions{
				validCreds: map[string]string{"ftp": "ftp"},
				pwdMode:    "cwd",
			},
			stopAtFirst: true,
			store:       smallStore([]string{"ftp"}, []string{"ftp"}),
			wantCreds:   []string{"ftp:ftp"},
		},
		{
			name: "when_pwd_denied_with_550_falls_back_to_cwd_and_returns_verified_finding",
			ftpOpts: fakeFTPOptions{
				validCreds: map[string]string{"ftp": "ftp"},
				pwdMode:    "550_cwd",
			},
			stopAtFirst: true,
			store:       smallStore([]string{"ftp"}, []string{"ftp"}),
			wantCreds:   []string{"ftp:ftp"},
		},
		{
			name: "when_550_allowlist_and_syst_fallback_continues_past_denied_users",
			ftpOpts: fakeFTPOptions{
				validCreds:    map[string]string{"admin": "123456"},
				allowlistOnly: true,
				denyWith550:   true,
				featDisabled:  true,
			},
			stopAtFirst: true,
			store:       smallStore([]string{"anonymous", "root", "admin"}, []string{"", "123456"}),
			wantCreds:   []string{"admin:123456"},
		},
		{
			name: "when_anonymous_passwordless_allowlist_server_returns_verified_finding",
			ftpOpts: fakeFTPOptions{
				passwordlessUser: map[string]bool{"anonymous": true},
				allowlistOnly:    true,
			},
			stopAtFirst: true,
			store:       smallStore([]string{"anonymous"}, []string{""}),
			wantCreds:   []string{"anonymous:"},
		},
		{
			name: "when_mandatory_explicit_ftps_drops_cleartext_user_negotiates_auth_tls_first",
			ftpOpts: fakeFTPOptions{
				validCreds:      map[string]string{"admin": "password"},
				requireExplicit: true,
			},
			stopAtFirst: true,
			store:       smallStore([]string{"admin"}, []string{"wrong", "password"}),
			wantCreds:   []string{"admin:password"},
		},
		{
			name: "when_vsftpd_explicit_tls_disallows_anon_ssl_falls_back_to_cleartext_for_anonymous",
			ftpOpts: fakeFTPOptions{
				passwordlessUser:  map[string]bool{"anonymous": true},
				requireExplicit:   true,
				disallowAnonInTLS: true,
			},
			stopAtFirst: true,
			store:       smallStore([]string{"anonymous"}, []string{""}),
			wantCreds:   []string{"anonymous:"},
		},
		{
			name: "when_implicit_ftps_server_returns_verified_finding",
			ftpOpts: fakeFTPOptions{
				validCreds:  map[string]string{"root": "toor"},
				implicitTLS: true,
			},
			stopAtFirst: true,
			store:       smallStore([]string{"root"}, []string{"toor"}),
			wantCreds:   []string{"root:toor"},
		},
		{
			name: "when_accept_all_ftp_server_supports_pwd_returns_verified_finding",
			ftpOpts: fakeFTPOptions{
				acceptAll: true,
			},
			stopAtFirst: true,
			store:       smallStore([]string{"admin"}, []string{"admin"}),
			wantCreds:   []string{"admin:admin"},
		},
		{
			name: "when_stop_at_first_disabled_reports_all_valid_credentials",
			ftpOpts: fakeFTPOptions{
				validCreds: map[string]string{
					"root":  "000000",
					"admin": "123456",
				},
			},
			stopAtFirst: false,
			store:       smallStore([]string{"root", "admin"}, []string{"000000", "123456"}),
			wantCreds:   []string{"root:000000", "admin:123456"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			svc := startFakeFTPServer(t, tc.ftpOpts)

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

func TestDetect_ImplicitTLSAndSNIServerName(t *testing.T) {
	tlsCfg := testServerTLSConfig(t)
	var gotSNI atomic.Value
	tlsCfg.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		gotSNI.Store(hello.ServerName)
		return nil, nil
	}

	svc := startRawTCPService(t, "unknown", func(rawConn net.Conn) {
		tlsConn := tls.Server(rawConn, tlsCfg)
		if err := tlsConn.Handshake(); err != nil {
			return
		}
		_, _ = io.WriteString(tlsConn, "220 Ready\r\n")
		r := bufio.NewReader(tlsConn)
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")
			switch {
			case strings.HasPrefix(line, "USER admin"):
				_, _ = io.WriteString(tlsConn, "230 Logged in\r\n")
			case strings.HasPrefix(line, "USER "):
				_, _ = io.WriteString(tlsConn, "331 Password required\r\n")
			case strings.HasPrefix(line, "PASS "):
				_, _ = io.WriteString(tlsConn, "530 Login incorrect\r\n")
			case line == "PWD":
				_, _ = io.WriteString(tlsConn, "257 \"/\"\r\n")
			case line == "QUIT":
				_, _ = io.WriteString(tlsConn, "221 Bye\r\n")
				return
			}
		}
	})
	svc.SetSupportedSslVersions([]string{"TLSv1.3"})
	svc.SetTransportProtocol(networkpb.TransportProtocol_TRANSPORT_PROTOCOL_UNSPECIFIED)
	svc.GetNetworkEndpoint().SetType(networkpb.NetworkEndpoint_IP_HOSTNAME_PORT)
	svc.GetNetworkEndpoint().SetHostname(networkpb.Hostname_builder{Name: "ftp.internal.example"}.Build())

	detector, err := NewWithOptions(t.Context(), fastBruteForceConfig(true), &bruteforce.Options{
		CredentialStore: smallStore([]string{"admin"}, []string{""}),
	})
	if err != nil {
		t.Fatalf("NewWithOptions() unexpected error: %v", err)
	}
	reports, err := detector.Detect(t.Context(), svc)
	if err != nil {
		t.Fatalf("Detect() unexpected error: %v", err)
	}
	if diff := cmp.Diff([]string{"admin:"}, extractFoundCredentials(reports)); diff != "" {
		t.Errorf("Detect() credentials diff (-want +got):\n%s", diff)
	}
	if sni, _ := gotSNI.Load().(string); sni != "ftp.internal.example" {
		t.Errorf("TLS SNI ServerName = %q, want %q", sni, "ftp.internal.example")
	}
}

func TestDetect_NoWeakCredentialsAndFalsePositiveGuards(t *testing.T) {
	strongFTPSvc := startFakeFTPServer(t, fakeFTPOptions{
		validCreds: map[string]string{"admin": "Str0ng_UnGu3ssable_P@ssw0rd!"},
	})
	webSvc := proto.CloneOf(strongFTPSvc)
	webSvc.SetServiceName("radan-http")
	webSvc.SetSupportedHttpMethods([]string{"GET"})

	udpSvc := proto.CloneOf(strongFTPSvc)
	udpSvc.SetTransportProtocol(networkpb.TransportProtocol_UDP)

	smtpBannerSvc := startRawTCPService(t, "ftp", func(conn net.Conn) {
		_, _ = io.WriteString(conn, "220 mail.example.com ESMTP Postfix\r\n")
	})

	smtpStartTLSSvc := startRawTCPService(t, "ftp", func(conn net.Conn) {
		_, _ = io.WriteString(conn, "220 mx.example.com Ready\r\n")
		r := bufio.NewReader(conn)
		for {
			if _, err := r.ReadString('\n'); err != nil {
				return
			}
			_, _ = io.WriteString(conn, "530 5.7.0 Must issue a STARTTLS command first\r\n")
		}
	})

	echoSvc := startRawTCPService(t, "ftp", func(conn net.Conn) {
		_, _ = io.Copy(conn, conn)
	})

	blind230WithNoopTarpitSvc := startRawTCPService(t, "ftp", func(conn net.Conn) {
		_, _ = io.WriteString(conn, "220\r\n")
		r := bufio.NewReader(conn)
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")
			switch {
			case strings.HasPrefix(line, "AUTH"):
				_, _ = io.WriteString(conn, "500 Unknown\r\n")
			case line == "PWD" || line == "XPWD" || strings.HasPrefix(line, "CWD"):
				_, _ = io.WriteString(conn, "500 Unknown\r\n")
			case line == "NOOP":
				_, _ = io.WriteString(conn, "200 OK\r\n")
			default:
				_, _ = io.WriteString(conn, "230 ok\r\n")
			}
		}
	})

	sshBannerSvc := startRawTCPService(t, "ftp", func(conn net.Conn) {
		_, _ = io.WriteString(conn, "SSH-2.0-OpenSSH_9.6\r\n")
	})

	closedLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() failed: %v", err)
	}
	closedPort := uint32(closedLn.Addr().(*net.TCPAddr).Port)
	_ = closedLn.Close()
	closedSvc := networkservicepb.NetworkService_builder{
		ServiceName: "ftp",
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
			name: "when_password_is_strong_returns_no_findings",
			svc:  strongFTPSvc,
		},
		{
			name: "when_service_is_web_service_skips_without_findings",
			svc:  webSvc,
		},
		{
			name: "when_transport_protocol_is_udp_skips_without_findings",
			svc:  udpSvc,
		},
		{
			name: "when_smtp_esmtp_banner_skips_without_findings",
			svc:  smtpBannerSvc,
		},
		{
			name: "when_smtp_530_starttls_rejection_skips_without_findings",
			svc:  smtpStartTLSSvc,
		},
		{
			name: "when_echo_server_skips_without_findings",
			svc:  echoSvc,
		},
		{
			name: "when_blind_230_plus_noop_200_tarpit_fails_authenticated_pwd_cwd_verification",
			svc:  blind230WithNoopTarpitSvc,
		},
		{
			name: "when_ssh_banner_skips_without_findings",
			svc:  sshBannerSvc,
		},
		{
			name: "when_closed_port_skips_without_findings",
			svc:  closedSvc,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			detector, err := NewWithOptions(t.Context(), fastBruteForceConfig(true), &bruteforce.Options{
				CredentialStore: smallStore([]string{"admin"}, []string{"123456"}),
			})
			if err != nil {
				t.Fatalf("NewWithOptions() unexpected error: %v", err)
			}
			reports, err := detector.Detect(t.Context(), tc.svc)
			if err != nil {
				t.Fatalf("Detect(%v) unexpected error: %v", tc.svc, err)
			}
			if len(reports.GetDetectionReports()) != 0 {
				t.Errorf("Detect(%v) returned %d findings, want 0", tc.svc, len(reports.GetDetectionReports()))
			}
		})
	}
}

func TestHandler_FingerprintAndTestCredentialErrors(t *testing.T) {
	h := NewHandler(fastBruteForceConfig(true))
	invalidSvc := networkservicepb.NetworkService_builder{
		ServiceName:     "ftp",
		NetworkEndpoint: &networkpb.NetworkEndpoint{},
	}.Build()

	t.Run("when_fingerprint_context_canceled_returns_context_canceled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if _, err := h.Fingerprint(ctx, invalidSvc); !errors.Is(err, context.Canceled) {
			t.Errorf("Fingerprint() error = %v, want %v", err, context.Canceled)
		}
	})

	t.Run("when_fingerprint_endpoint_missing_address_returns_error", func(t *testing.T) {
		if _, err := h.Fingerprint(t.Context(), invalidSvc); !errors.Is(err, netendpoint.ErrEndpointMissingAddress) {
			t.Errorf("Fingerprint() error = %v, want %v", err, netendpoint.ErrEndpointMissingAddress)
		}
	})

	t.Run("when_fingerprint_canceled_during_probe_returns_context_canceled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		svc := startRawTCPService(t, "ftp", func(conn net.Conn) {
			_, _ = io.WriteString(conn, "220 Ready\r\n")
			r := bufio.NewReader(conn)
			_, _ = r.ReadString('\n')
			cancel()
		})
		if _, err := h.Fingerprint(ctx, svc); !errors.Is(err, context.Canceled) {
			t.Errorf("Fingerprint() error = %v, want %v", err, context.Canceled)
		}
	})

	t.Run("when_test_credential_context_canceled_returns_context_canceled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if _, err := h.TestCredential(ctx, invalidSvc, bruteforce.Credential{Username: "admin", Password: "123"}); !errors.Is(err, context.Canceled) {
			t.Errorf("TestCredential() error = %v, want %v", err, context.Canceled)
		}
	})

	t.Run("when_test_credential_contains_crlf_returns_false_without_error", func(t *testing.T) {
		ok, err := h.TestCredential(t.Context(), invalidSvc, bruteforce.Credential{Username: "admin\r\n", Password: "123"})
		if err != nil || ok {
			t.Errorf("TestCredential(CRLF) = (%v, %v), want (false, nil)", ok, err)
		}
	})

	t.Run("when_test_credential_endpoint_missing_address_returns_error", func(t *testing.T) {
		if _, err := h.TestCredential(t.Context(), invalidSvc, bruteforce.Credential{Username: "admin", Password: "123"}); !errors.Is(err, netendpoint.ErrEndpointMissingAddress) {
			t.Errorf("TestCredential() error = %v, want %v", err, netendpoint.ErrEndpointMissingAddress)
		}
	})

	t.Run("when_test_credential_receives_534_policy_requires_ssl_returns_stop_brute_force", func(t *testing.T) {
		svc := startRawTCPService(t, "ftp", func(conn net.Conn) {
			_, _ = io.WriteString(conn, "220 Ready\r\n")
			r := bufio.NewReader(conn)
			_, _ = r.ReadString('\n')
			_, _ = io.WriteString(conn, "534 Policy requires SSL.\r\n")
		})
		_, err := h.TestCredential(t.Context(), svc, bruteforce.Credential{Username: "admin", Password: "123"})
		if !errors.Is(err, bruteforce.ErrStopBruteForce) {
			t.Errorf("TestCredential() error = %v, want %v", err, bruteforce.ErrStopBruteForce)
		}
	})

	t.Run("when_empty_password_receives_553_or_501_continues_brute_force_to_find_valid_credential", func(t *testing.T) {
		svc := startRawTCPService(t, "ftp", func(conn net.Conn) {
			_, _ = io.WriteString(conn, "220 vsftpsd 3.0.5\r\n")
			r := bufio.NewReader(conn)
			var pending string
			for {
				line, err := r.ReadString('\n')
				if err != nil {
					return
				}
				cmdLine := strings.TrimRight(line, "\r\n")
				verb, arg, _ := strings.Cut(cmdLine, " ")
				switch strings.ToUpper(verb) {
				case "AUTH":
					_, _ = io.WriteString(conn, "550 Action not taken\r\n")
				case "USER":
					if arg == "" {
						_, _ = io.WriteString(conn, "501 Syntax error in parameters\r\n")
						continue
					}
					pending = arg
					_, _ = io.WriteString(conn, "331 User name ok, password required\r\n")
				case "PASS":
					if arg == "" {
						pending = ""
						_, _ = io.WriteString(conn, "553 action aborted, required param missing\r\n")
						continue
					}
					if pending == "admin" && arg == "123456" {
						_, _ = io.WriteString(conn, "230 User logged in\r\n")
						continue
					}
					pending = ""
					_, _ = io.WriteString(conn, "530 Incorrect password, not logged in\r\n")
				case "PWD":
					_, _ = io.WriteString(conn, "257 \"/\" is current directory\r\n")
				case "QUIT":
					_, _ = io.WriteString(conn, "221 Goodbye\r\n")
					return
				}
			}
		})
		detector, err := NewWithOptions(t.Context(), fastBruteForceConfig(true), &bruteforce.Options{
			CredentialStore: smallStore([]string{"admin"}, []string{"", "123456"}),
			DefaultCredentials: []bruteforce.Credential{
				{Username: "anonymous", Password: ""},
			},
		})
		if err != nil {
			t.Fatalf("NewWithOptions() unexpected error: %v", err)
		}
		reports, err := detector.Detect(t.Context(), svc)
		if err != nil {
			t.Fatalf("Detect() unexpected error: %v", err)
		}
		if got := extractFoundCredentials(reports); len(got) != 1 || got[0] != "admin:123456" {
			t.Errorf("Detect() credentials = %v, want [\"admin:123456\"]", got)
		}
	})
}

func TestDetect_StopsCleanlyOnMidRunTransportFailure(t *testing.T) {
	var connCount atomic.Int32
	svc := startRawTCPService(t, "ftp", func(conn net.Conn) {
		n := connCount.Add(1)
		if n == 1 {
			_, _ = io.WriteString(conn, "220 Ready\r\n")
			r := bufio.NewReader(conn)
			_, _ = r.ReadString('\n') // AUTH TLS
			_, _ = io.WriteString(conn, "502 AUTH TLS unsupported\r\n")
			_, _ = r.ReadString('\n') // USER
			_, _ = io.WriteString(conn, "331 Password required\r\n")
			_, _ = r.ReadString('\n') // PASS
			_, _ = io.WriteString(conn, "530 Login incorrect\r\n")
			return
		}
		_ = conn.Close()
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
	if got, want := connCount.Load(), int32(1+maxConsecutiveTransportErrors); got != want {
		t.Errorf("connection count = %d, want %d", got, want)
	}
}

func TestParseReplyPrefix(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		wantCode int
		wantSep  byte
		wantOK   bool
	}{
		{name: "when_short_line_returns_false", line: "22", wantOK: false},
		{name: "when_non_numeric_code_returns_false", line: "SSH-2.0", wantOK: false},
		{name: "when_code_below_100_returns_false", line: "099 bad", wantOK: false},
		{name: "when_code_above_599_returns_false", line: "600 bad", wantOK: false},
		{name: "when_invalid_separator_returns_false", line: "220:bad", wantOK: false},
		{name: "when_three_digit_bare_code_returns_space", line: "220", wantCode: 220, wantSep: ' ', wantOK: true},
		{name: "when_single_line_reply_returns_space", line: "230 Login ok", wantCode: 230, wantSep: ' ', wantOK: true},
		{name: "when_multiline_start_returns_hyphen", line: "220-Welcome", wantCode: 220, wantSep: '-', wantOK: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, sep, ok := parseReplyPrefix(tc.line)
			if ok != tc.wantOK || code != tc.wantCode || sep != tc.wantSep {
				t.Errorf("parseReplyPrefix(%q) = (%d, %q, %v), want (%d, %q, %v)",
					tc.line, code, sep, ok, tc.wantCode, tc.wantSep, tc.wantOK)
			}
		})
	}
}

func TestProtocolEdgeCasesAndWorkerEarlyStop(t *testing.T) {
	h := NewHandler(fastBruteForceConfig(true))
	cred := bruteforce.Credential{Username: "admin", Password: "123"}

	t.Run("when_implicit_tls_handshake_fails_on_plaintext_server_skips", func(t *testing.T) {
		svc := startRawTCPService(t, "ftps", func(conn net.Conn) {
			_, _ = io.WriteString(conn, "220 Plaintext not TLS\r\n")
		})
		matched, err := h.Fingerprint(t.Context(), svc)
		if err != nil || matched {
			t.Errorf("Fingerprint(implicit TLS on plaintext) = (%v, %v), want (false, nil)", matched, err)
		}
	})

	t.Run("when_server_drops_conn_on_auth_tls_redials_cleartext_and_fingerprints", func(t *testing.T) {
		var connNum atomic.Int32
		svc := startRawTCPService(t, "ftp", func(conn net.Conn) {
			n := connNum.Add(1)
			_, _ = io.WriteString(conn, "220 Ready\r\n")
			r := bufio.NewReader(conn)
			line, _ := r.ReadString('\n')
			if n == 1 && strings.HasPrefix(line, "AUTH") {
				_ = conn.Close()
				return
			}
			_, _ = io.WriteString(conn, "331 Password\r\n")
			_, _ = r.ReadString('\n')
			_, _ = io.WriteString(conn, "530 Login incorrect\r\n")
		})
		matched, err := h.Fingerprint(t.Context(), svc)
		if err != nil || !matched {
			t.Errorf("Fingerprint(redial after AUTH TLS drop) = (%v, %v), want (true, nil)", matched, err)
		}
	})

	t.Run("when_explicit_tls_subsequent_upgrade_fails_returns_stop_brute_force", func(t *testing.T) {
		tlsCfg := testServerTLSConfig(t)
		var failSubsequentTLS atomic.Bool
		svc := startRawTCPService(t, "ftp", func(rawConn net.Conn) {
			_, _ = io.WriteString(rawConn, "220 FTPS Ready\r\n")
			r := bufio.NewReader(rawConn)
			line, err := r.ReadString('\n')
			if err != nil || strings.TrimRight(line, "\r\n") != "AUTH TLS" {
				return
			}
			if failSubsequentTLS.Load() {
				_, _ = io.WriteString(rawConn, "504 AUTH TLS disabled\r\n")
				return
			}
			_, _ = io.WriteString(rawConn, "234 Proceed\r\n")
			tlsConn := tls.Server(rawConn, tlsCfg)
			if err := tlsConn.Handshake(); err != nil {
				return
			}
			tr := bufio.NewReader(tlsConn)
			_, _ = tr.ReadString('\n')
			_, _ = io.WriteString(tlsConn, "550 Disallowed user\r\n")
			_, _ = tr.ReadString('\n')
			_, _ = io.WriteString(tlsConn, "211-Features:\r\n AUTH TLS\r\n211 End\r\n")
		})
		matched, err := h.Fingerprint(t.Context(), svc)
		if err != nil || !matched {
			t.Fatalf("Fingerprint() = (%v, %v), want (true, nil)", matched, err)
		}
		failSubsequentTLS.Store(true)
		if _, err := h.TestCredential(t.Context(), svc, cred); !errors.Is(err, bruteforce.ErrStopBruteForce) {
			t.Errorf("TestCredential() = %v, want %v", err, bruteforce.ErrStopBruteForce)
		}
	})

	t.Run("when_multiline_banner_exceeds_max_lines_skips", func(t *testing.T) {
		svc := startRawTCPService(t, "ftp", func(conn net.Conn) {
			_, _ = io.WriteString(conn, "220-Line 0\r\n")
			for i := range maxReplyLines + 2 {
				_, _ = fmt.Fprintf(conn, "220-Line %d\r\n", i+1)
			}
		})
		matched, err := h.Fingerprint(t.Context(), svc)
		if err != nil || matched {
			t.Errorf("Fingerprint(excessive multiline) = (%v, %v), want (false, nil)", matched, err)
		}
	})

	t.Run("when_probe_pass_returns_unexpected_504_returns_false", func(t *testing.T) {
		svc := startRawTCPService(t, "ftp", func(conn net.Conn) {
			_, _ = io.WriteString(conn, "220 Ready\r\n")
			r := bufio.NewReader(conn)
			_, _ = r.ReadString('\n') // AUTH TLS
			_, _ = io.WriteString(conn, "502 Unsupported\r\n")
			_, _ = r.ReadString('\n') // USER
			_, _ = io.WriteString(conn, "331 Password\r\n")
			_, _ = r.ReadString('\n') // PASS
			_, _ = io.WriteString(conn, "504 Unsupported\r\n")
		})
		matched, err := h.Fingerprint(t.Context(), svc)
		if err != nil || matched {
			t.Errorf("Fingerprint(PASS 504) = (%v, %v), want (false, nil)", matched, err)
		}
	})

	replyCases := []struct {
		name      string
		userReply string
		passReply string
		wantErr   error
	}{
		{name: "when_user_returns_530_returns_nil_auth_failed", userReply: "530 Disallowed\r\n", wantErr: nil},
		{name: "when_user_returns_550_returns_nil_auth_failed", userReply: "550 Disallowed\r\n", wantErr: nil},
		{name: "when_user_returns_421_returns_not_ftp", userReply: "421 Too many connections\r\n", wantErr: ErrNotFTPService},
		{name: "when_user_returns_500_returns_not_ftp", userReply: "500 Syntax error\r\n", wantErr: ErrNotFTPService},
		{name: "when_pass_returns_550_returns_nil_auth_failed", userReply: "331 Password\r\n", passReply: "550 Denied\r\n", wantErr: nil},
		{name: "when_pass_returns_421_returns_not_ftp", userReply: "331 Password\r\n", passReply: "421 Closing\r\n", wantErr: ErrNotFTPService},
		{name: "when_pass_returns_504_returns_stop_brute_force", userReply: "331 Password\r\n", passReply: "504 Mechanism unsupported\r\n", wantErr: bruteforce.ErrStopBruteForce},
	}

	for _, rc := range replyCases {
		t.Run(rc.name, func(t *testing.T) {
			svc := startRawTCPService(t, "ftp", func(conn net.Conn) {
				_, _ = io.WriteString(conn, "220 Ready\r\n")
				r := bufio.NewReader(conn)
				_, _ = r.ReadString('\n')
				_, _ = io.WriteString(conn, rc.userReply)
				if rc.passReply != "" {
					_, _ = r.ReadString('\n')
					_, _ = io.WriteString(conn, rc.passReply)
				}
			})
			ok, err := h.TestCredential(t.Context(), svc, cred)
			if ok {
				t.Errorf("TestCredential() = true, want false")
			}
			if !errors.Is(err, rc.wantErr) {
				t.Errorf("TestCredential() error = %v, want %v", err, rc.wantErr)
			}
		})
	}

	t.Run("when_worker_encounters_534_stops_brute_forcing_immediately", func(t *testing.T) {
		var connCount atomic.Int32
		svc := startRawTCPService(t, "ftp", func(conn net.Conn) {
			n := connCount.Add(1)
			_, _ = io.WriteString(conn, "220 Ready\r\n")
			r := bufio.NewReader(conn)
			if n == 1 {
				_, _ = r.ReadString('\n') // AUTH TLS
				_, _ = io.WriteString(conn, "502 Unsupported\r\n")
				_, _ = r.ReadString('\n') // USER
				_, _ = io.WriteString(conn, "331 Password\r\n")
				_, _ = r.ReadString('\n') // PASS
				_, _ = io.WriteString(conn, "530 Login incorrect\r\n")
				return
			}
			_, _ = r.ReadString('\n') // USER
			_, _ = io.WriteString(conn, "534 Policy requires SSL\r\n")
		})
		detector, err := NewWithOptions(t.Context(), fastBruteForceConfig(true), &bruteforce.Options{
			CredentialStore: smallStore([]string{"root", "admin"}, []string{"123", "456"}),
		})
		if err != nil {
			t.Fatalf("NewWithOptions() failed: %v", err)
		}
		reports, err := detector.Detect(t.Context(), svc)
		if err != nil || len(reports.GetDetectionReports()) != 0 {
			t.Errorf("Detect() = (%v, %v), want (0 reports, nil)", reports, err)
		}
		if got := connCount.Load(); got != 2 {
			t.Errorf("connCount = %d, want 2", got)
		}
	})
}
