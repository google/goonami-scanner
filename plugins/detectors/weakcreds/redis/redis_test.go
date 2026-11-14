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

package redis

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/goonami-scanner/common/bruteforce"
	bfpb "github.com/google/goonami-scanner/common/bruteforce/bruteforce_config_go_proto"
	"github.com/google/goonami-scanner/common/credentialstore"
	"github.com/google/goonami-scanner/core/config"
	cpb "github.com/google/goonami-scanner/core/config/config_go_proto"
	"github.com/google/goonami-scanner/core/module"
	"github.com/google/goonami-scanner/core/net/netendpoint"
	drpb "github.com/google/tsunami-security-scanner/proto/go/detection_go_proto"
	npb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
	"google.golang.org/protobuf/proto"
)

const testCertPEM = `-----BEGIN CERTIFICATE-----
MIIDbTCCAlWgAwIBAgIUefPI++ucyn9Al9u/fpQ/PKio9NkwDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAgFw0yNTExMTMxNTU4MzVaGA8yMTI1
MTAyMDE1NTgzNVowRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUx
ITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBAPCf8JOVBvrakP4zPO/Wcp6GCKLjmD+6YHmlli3j
JRvtnyWdPWeHH3BUcuTL0HKR96Rp+U75GenDGaCvtzwGjxO6hpWLNcHf5l0mK3xI
vEQoAC5TQYE1B8B+KxhipklvEWfJMTdrJCp5RqKnBVNTVyuPAoT7sQXUMxzZlqVO
x3pjcUOrXnCYtGwYVEyc9fRUDjlfGQaIyPveSx53VLuNoVZayIjJ003hA0JGJFq2
+UD6CQ7lBqXngaUroHgmExhSEcYR4b12aeQTMdGOPPH2gNsH6f00mfGxRz/mbsHU
2fyKWpwI7WaOs89tWI57y6WvJ3EvQlpM59g3OvrT8VJ2uMECAwEAAaNTMFEwHQYD
VR0OBBYEFE617ntUBNKvmc2Te89HFgBisai8MB8GA1UdIwQYMBaAFE617ntUBNKv
mc2Te89HFgBisai8MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEB
ALHmqXbewpi0g2JeeOr+jlcgW3/Yfivlj9DO1qoD0MndBMupHDbeGE0rVPw21UZ8
DlkX7bBKNs5JibBMfEtueakjDgshW3E1GLZwBf0j2czUC+RRc8iiZc5YM13ze+2b
S66AS4Zj2+Y8Vk3X2OTqR70rtLVbWAJ2q114jKVukF6oveS4PwIQV6j37aIEZWkh
ApQTmfnG2gjW9yL562oDBMdB9HmbUo5W6ZD4xeunrwP1ArNgoUpKjiHn9tUrLFM0
9deL70gWyz9b1RIawUSPUPWsHd+fIFwx6lrX5DZpp5mRjvGplJdDrkkcOgNPJqiq
kh727mhik6Yg9a2SuTc6vhQ=
-----END CERTIFICATE-----`

const testKeyPEM = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDwn/CTlQb62pD+
Mzzv1nKehgii45g/umB5pZYt4yUb7Z8lnT1nhx9wVHLky9BykfekaflO+Rnpwxmg
r7c8Bo8TuoaVizXB3+ZdJit8SLxEKAAuU0GBNQfAfisYYqZJbxFnyTE3ayQqeUai
pwVTU1crjwKE+7EF1DMc2ZalTsd6Y3FDq15wmLRsGFRMnPX0VA45XxkGiMj73kse
d1S7jaFWWsiIydNN4QNCRiRatvlA+gkO5Qal54GlK6B4JhMYUhHGEeG9dmnkEzHR
jjzx9oDbB+n9NJnxsUc/5m7B1Nn8ilqcCO1mjrPPbViOe8ulrydxL0JaTOfYNzr6
0/FSdrjBAgMBAAECggEAAX/FQhMfgdXuTRWutIOCqIio3SDgBNhYHJ911AAmYXzE
On8+AK+NlK3xrQ1Gw8xMYfgLlAvXpvPBWSAtIFMIf2YdGdszVO8KsEsAWwjt//NJ
fIBmBU4hWZ2HKw10Hlt16zkhwH8LspZZmf634BaD1xOchOLXg1W/tb5r3/pYt4pW
ny/aIoOC9ng/eBypAUyewoBUmwk0+gn6MqBzMWOLsKD5BOxHy1+ZNWp48DFzABFy
v4TScr2JsGPz/dFZDckj/m9/N8ll22g6CjApR4/iWQCGrZtgtcBV87p8jSz6cEw1
RypB34x/p4YkqCnKXiebJBpkRxb9w0AQSMpycCAMkQKBgQD8LDZASdeLEXLYcQDy
c9Ravxypf/wlJNjH3c0AkeEJVZapb7ib7c77/YlWPrAvg2A0GSgwKo8Z6MjIcgcF
wSH+RjRtIZnK+1Ufa1157A/GfIVwikP4F6icsbGFzF+lB+vlqfXh7qo4AC0iEg1E
Q3D+GfWpJWb1DAM8ZD7VD5+kUQKBgQD0RtwRvlsL1hNGtlt107/SZxe8zakjb3US
yBXy/jSeeh4g2BBlevM//T0DDmCURRtmL5KmVGkw5+33aIiUmrlznL9NiAagS0nu
3urKK/0Rp0NnwwvzlsBndj/qdH8cRNRvaIcTRUGSyhihIFy6KTLXtHpukdef228P
/LGXQ1ThcQKBgQD41TOvWm4bp1sZIuEZXZy08xJ4W3dWu7ZB+qbYohpaGJ+zkC+t
hgsR8wu7E97M86lRn2VdqhFNMrw1tvchAYPmoiYHbfmRJ1LGzy4NKhgi9yrBc15A
iC/0dw9ChPn4IgnvtTeQ+u3ylpHypbd7ncT4qGsVvneK5JCo3g52NZWFEQKBgBgu
y6qWBb1uPApME1He3KafviHa2lu/tP9e/41GzT7DKChoO3dQbLRxBZE/4x/Kl6PO
Id6FjMRisZRErQDJMILZibbLOJy112Pmfaf2It+Uh3/GN3CuA+46LqmvTsYlqkI9
PuIRgSRfDYEmCwgC/B2OqHA5z/braltS0OIAsG6BAoGBAOpSM60GpM7zAC1tW8Am
dFS6MDct7h4eOKxrLxtO44ALO+KG4L20a3f9ZuFIUaQ9/msN5VI8eod2f0OYJoLI
vZXWp65Vs80qa81f6VLMVjh1CqPGbnGtCPK+gpAUiBhwtPV4rA0qfik785wOZY2f
9K6jjFOm1TQ68+su8AG9jWLb
-----END PRIVATE KEY-----`

func testConfig(timeoutSecs int32) *config.Config {
	return config.FromProto(cpb.Config_builder{
		Globalcfg: cpb.GlobalConfig_builder{
			Performance: cpb.GlobalConfig_Performance_builder{
				TimeoutPerRequestSeconds: proto.Int32(timeoutSecs),
			}.Build(),
		}.Build(),
		Plugins: cpb.PluginsConfig_builder{
			Bruteforce: bfpb.BruteForceConfig_builder{
				MaxAttemptsPerService:       proto.Int32(200),
				MaxConcurrency:              proto.Int32(2),
				MaxRequestsPerSecond:        proto.Int32(0),
				StopAtFirstValidCredentials: proto.Bool(true),
			}.Build(),
		}.Build(),
	}.Build())
}

func makeRedisService(t *testing.T, addr string, protocol npb.TransportProtocol) *nspb.NetworkService {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("net.SplitHostPort(%q) failed: %v", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("strconv.Atoi(%q) failed: %v", portStr, err)
	}
	ep, err := netendpoint.WithPort(netendpoint.FromString(host), uint32(port))
	if err != nil {
		t.Fatalf("netendpoint.WithPort() failed: %v", err)
	}
	return nspb.NetworkService_builder{
		NetworkEndpoint:   ep,
		ServiceName:       "redis",
		TransportProtocol: protocol,
	}.Build()
}

func TestInitRegistrationAndNew(t *testing.T) {
	detectors, err := module.AllDetectors(t.Context(), config.Default())
	if err != nil {
		t.Fatalf("module.AllDetectors() failed: %v", err)
	}
	found := false
	for _, d := range detectors {
		if d.Name() == ModuleName {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("module %q was not registered in module.DefaultRegistry", ModuleName)
	}

	det, err := New(t.Context(), testConfig(1))
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}
	if det.Name() != ModuleName {
		t.Errorf("det.Name() = %q, want %q", det.Name(), ModuleName)
	}
	if _, err := New(t.Context(), nil); !errors.Is(err, bruteforce.ErrConfigNil) {
		t.Errorf("New(nil) error = %v, want ErrConfigNil", err)
	}
}

func TestDefaultCredentialsAndMetadata(t *testing.T) {
	creds := DefaultCredentials()
	if len(creds) < 5 {
		t.Fatalf("DefaultCredentials() returned %d credentials, want at least 5", len(creds))
	}
	if creds[0].Username != "default" || creds[0].Password != "" {
		t.Errorf("DefaultCredentials()[0] = %+v, want default:<empty>", creds[0])
	}

	h1 := NewHandler(testConfig(1))
	if h1.timeout != 1*time.Second {
		t.Errorf("NewHandler(1s).timeout = %v, want 1s", h1.timeout)
	}
	h2 := NewHandler(testConfig(30))
	if h2.timeout != defaultTimeout {
		t.Errorf("NewHandler(30s).timeout = %v, want %v", h2.timeout, defaultTimeout)
	}
	h3 := NewHandler(nil)
	if h3.timeout != defaultTimeout {
		t.Errorf("NewHandler(nil).timeout = %v, want %v", h3.timeout, defaultTimeout)
	}
	if got := h1.Name(); got != ModuleName {
		t.Errorf("Name() = %q, want %q", got, ModuleName)
	}
	vuln := h1.Vulnerability()
	if vuln.GetMainId().GetValue() != "WEAK_CREDENTIALS_FOR_REDIS" {
		t.Errorf("Vulnerability() = %v, want WEAK_CREDENTIALS_FOR_REDIS", vuln)
	}
}

func TestFingerprint(t *testing.T) {
	tests := []struct {
		name        string
		protocol    npb.TransportProtocol
		isWeb       bool
		badEndpoint bool
		cancelCtx   bool
		closedPort  bool
		serverFunc  func(conn net.Conn)
		wantMatch   bool
		wantErr     bool
	}{
		{
			name:       "when_context_canceled_returns_error",
			protocol:   npb.TransportProtocol_TCP,
			cancelCtx:  true,
			serverFunc: func(conn net.Conn) { _ = conn.Close() },
			wantMatch:  false,
			wantErr:    true,
		},
		{
			name:       "when_service_is_web_service_returns_false",
			protocol:   npb.TransportProtocol_TCP,
			isWeb:      true,
			serverFunc: func(conn net.Conn) { _ = conn.Close() },
			wantMatch:  false,
			wantErr:    false,
		},
		{
			name:       "when_protocol_is_udp_returns_false",
			protocol:   npb.TransportProtocol_UDP,
			serverFunc: func(conn net.Conn) { _ = conn.Close() },
			wantMatch:  false,
			wantErr:    false,
		},
		{
			name:        "when_endpoint_is_invalid_returns_error",
			protocol:    npb.TransportProtocol_TCP,
			badEndpoint: true,
			serverFunc:  func(conn net.Conn) { _ = conn.Close() },
			wantMatch:   false,
			wantErr:     true,
		},
		{
			name:       "when_target_port_closed_returns_false_without_error",
			protocol:   npb.TransportProtocol_TCP,
			closedPort: true,
			wantMatch:  false,
			wantErr:    false,
		},
		{
			name:     "when_server_requires_auth_and_rejects_probe_with_wrongpass_returns_true",
			protocol: npb.TransportProtocol_TRANSPORT_PROTOCOL_UNSPECIFIED,
			serverFunc: func(conn net.Conn) {
				defer conn.Close()
				r := bufio.NewReader(conn)
				if _, err := readClientCommand(r); err != nil {
					return
				}
				_, _ = conn.Write([]byte("-NOAUTH Authentication required.\r\n"))
				if _, err := readClientCommand(r); err != nil {
					return
				}
				_, _ = conn.Write([]byte("-WRONGPASS invalid username-password pair or user is disabled.\r\n"))
			},
			wantMatch: true,
			wantErr:   false,
		},
		{
			name:     "when_redis5_rejects_probe_with_err_invalid_password_returns_true",
			protocol: npb.TransportProtocol_TCP,
			serverFunc: func(conn net.Conn) {
				defer conn.Close()
				r := bufio.NewReader(conn)
				if _, err := readClientCommand(r); err != nil {
					return
				}
				_, _ = conn.Write([]byte("-NOAUTH Authentication required.\r\n"))
				if _, err := readClientCommand(r); err != nil {
					return
				}
				_, _ = conn.Write([]byte("-ERR invalid password\r\n"))
			},
			wantMatch: true,
			wantErr:   false,
		},
		{
			name:     "when_user_default_off_returns_nopass_on_1arg_and_wrongpass_on_2arg_returns_true",
			protocol: npb.TransportProtocol_TCP,
			serverFunc: func(conn net.Conn) {
				defer conn.Close()
				r := bufio.NewReader(conn)
				if _, err := readClientCommand(r); err != nil {
					return
				}
				_, _ = conn.Write([]byte("-NOAUTH Authentication required.\r\n"))
				if _, err := readClientCommand(r); err != nil {
					return
				}
				_, _ = conn.Write([]byte("-ERR AUTH <password> called without any password configured for the default user. Are you sure your configuration is correct?\r\n"))
				if _, err := readClientCommand(r); err != nil {
					return
				}
				_, _ = conn.Write([]byte("-WRONGPASS invalid username-password pair or user is disabled.\r\n"))
			},
			wantMatch: true,
			wantErr:   false,
		},
		{
			name:     "when_user_default_nopass_minus_all_returns_noperm_on_ping_and_wrongpass_on_2arg_returns_true",
			protocol: npb.TransportProtocol_TCP,
			serverFunc: func(conn net.Conn) {
				defer conn.Close()
				r := bufio.NewReader(conn)
				if _, err := readClientCommand(r); err != nil {
					return
				}
				_, _ = conn.Write([]byte("-NOPERM this user has no permissions to run the 'ping' command\r\n"))
				if _, err := readClientCommand(r); err != nil {
					return
				}
				_, _ = conn.Write([]byte("-WRONGPASS invalid username-password pair or user is disabled.\r\n"))
			},
			wantMatch: true,
			wantErr:   false,
		},
		{
			name:     "when_honeypot_accepts_invalid_probe_password_returns_false",
			protocol: npb.TransportProtocol_TCP,
			serverFunc: func(conn net.Conn) {
				defer conn.Close()
				r := bufio.NewReader(conn)
				if _, err := readClientCommand(r); err != nil {
					return
				}
				_, _ = conn.Write([]byte("-NOAUTH Authentication required.\r\n"))
				if _, err := readClientCommand(r); err != nil {
					return
				}
				_, _ = conn.Write([]byte("+OK\r\n"))
			},
			wantMatch: false,
			wantErr:   false,
		},
		{
			name:     "when_server_drops_after_noauth_returns_false",
			protocol: npb.TransportProtocol_TCP,
			serverFunc: func(conn net.Conn) {
				defer conn.Close()
				r := bufio.NewReader(conn)
				if _, err := readClientCommand(r); err != nil {
					return
				}
				_, _ = conn.Write([]byte("-NOAUTH Authentication required.\r\n"))
			},
			wantMatch: false,
			wantErr:   false,
		},
		{
			name:     "when_unauthenticated_redis_allows_info_server_returns_false",
			protocol: npb.TransportProtocol_TCP,
			serverFunc: func(conn net.Conn) {
				defer conn.Close()
				r := bufio.NewReader(conn)
				if _, err := readClientCommand(r); err != nil {
					return
				}
				_, _ = conn.Write([]byte("+PONG\r\n"))
				if _, err := readClientCommand(r); err != nil {
					return
				}
				info := "# Server\r\nredis_version:7.4.0\r\n"
				_, _ = fmt.Fprintf(conn, "$%d\r\n%s\r\n", len(info), info)
			},
			wantMatch: false,
			wantErr:   false,
		},
		{
			name:     "when_default_user_noperm_on_info_and_acl_auth_active_returns_true",
			protocol: npb.TransportProtocol_TCP,
			serverFunc: func(conn net.Conn) {
				defer conn.Close()
				r := bufio.NewReader(conn)
				if _, err := readClientCommand(r); err != nil {
					return
				}
				_, _ = conn.Write([]byte("+PONG\r\n"))
				if _, err := readClientCommand(r); err != nil {
					return
				}
				_, _ = conn.Write([]byte("-NOPERM this user has no permissions to run the 'info' command\r\n"))
				if _, err := readClientCommand(r); err != nil {
					return
				}
				_, _ = conn.Write([]byte("-WRONGPASS invalid username-password pair\r\n"))
			},
			wantMatch: true,
			wantErr:   false,
		},
		{
			name:     "when_pong_then_info_drops_connection_returns_false",
			protocol: npb.TransportProtocol_TCP,
			serverFunc: func(conn net.Conn) {
				defer conn.Close()
				r := bufio.NewReader(conn)
				if _, err := readClientCommand(r); err != nil {
					return
				}
				_, _ = conn.Write([]byte("+PONG\r\n"))
			},
			wantMatch: false,
			wantErr:   false,
		},
		{
			name:     "when_pong_and_noperm_then_auth_drops_connection_returns_false",
			protocol: npb.TransportProtocol_TCP,
			serverFunc: func(conn net.Conn) {
				defer conn.Close()
				r := bufio.NewReader(conn)
				if _, err := readClientCommand(r); err != nil {
					return
				}
				_, _ = conn.Write([]byte("+PONG\r\n"))
				if _, err := readClientCommand(r); err != nil {
					return
				}
				_, _ = conn.Write([]byte("-NOPERM denied\r\n"))
			},
			wantMatch: false,
			wantErr:   false,
		},
		{
			name:     "when_protected_mode_denied_returns_false",
			protocol: npb.TransportProtocol_TCP,
			serverFunc: func(conn net.Conn) {
				defer conn.Close()
				_, _ = conn.Write([]byte("-DENIED Redis is running in protected mode\r\n"))
			},
			wantMatch: false,
			wantErr:   false,
		},
		{
			name:     "when_echo_server_reflects_payload_returns_false",
			protocol: npb.TransportProtocol_TCP,
			serverFunc: func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			},
			wantMatch: false,
			wantErr:   false,
		},
		{
			name:     "when_non_redis_banner_returns_false",
			protocol: npb.TransportProtocol_TCP,
			serverFunc: func(conn net.Conn) {
				defer conn.Close()
				_, _ = conn.Write([]byte("SSH-2.0-OpenSSH_9.0\r\n"))
			},
			wantMatch: false,
			wantErr:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var addr string
			if tc.closedPort {
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatalf("net.Listen() failed: %v", err)
				}
				addr = ln.Addr().String()
				_ = ln.Close()
			} else {
				addr = startFakeRedisServer(t, tc.serverFunc)
			}

			svc := makeRedisService(t, addr, tc.protocol)
			if tc.isWeb {
				svc.SetSupportedHttpMethods([]string{"GET"})
			}
			if tc.badEndpoint {
				svc.ClearNetworkEndpoint()
			}

			ctx := context.Background()
			if tc.cancelCtx {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}

			h := NewHandler(testConfig(1))
			got, err := h.Fingerprint(ctx, svc)
			if (err != nil) != tc.wantErr {
				t.Fatalf("Fingerprint() error = %v, wantErr %v", err, tc.wantErr)
			}
			if got != tc.wantMatch {
				t.Errorf("Fingerprint() = %v, want %v", got, tc.wantMatch)
			}
		})
	}
}

func TestFingerprintAndDetectTLS(t *testing.T) {
	cert, err := tls.X509KeyPair([]byte(testCertPEM), []byte(testKeyPEM))
	if err != nil {
		t.Fatalf("tls.X509KeyPair() failed: %v", err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatalf("tls.Listen() failed: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			go serveStatefulRedis(conn, map[string]string{"default": "redis", "admin": "s3cret"}, false)
		}
	}()

	svc := makeRedisService(t, ln.Addr().String(), npb.TransportProtocol_TCP)
	svc.SetSupportedSslVersions([]string{"TLSv1.3"})

	store := credentialstore.New()
	_ = store.AddUser("admin")
	store.AddMultiplePasswordsForUser("admin", []string{"wrong", "s3cret"})

	det, err := NewWithOptions(t.Context(), testConfig(1), &bruteforce.Options{
		CredentialStore: store,
	})
	if err != nil {
		t.Fatalf("NewWithOptions() failed: %v", err)
	}
	reports, err := det.Detect(t.Context(), svc)
	if err != nil {
		t.Fatalf("Detect() over TLS failed: %v", err)
	}
	if len(reports.GetDetectionReports()) != 1 {
		t.Fatalf("Detect() over TLS findings = %d, want 1", len(reports.GetDetectionReports()))
	}
}

func TestTestCredential(t *testing.T) {
	tests := []struct {
		name        string
		cred        bruteforce.Credential
		badEndpoint bool
		cancelCtx   bool
		serverFunc  func(conn net.Conn)
		wantOK      bool
		wantErr     error
	}{
		{
			name:       "when_context_canceled_returns_error",
			cred:       bruteforce.Credential{Username: "default", Password: "password"},
			cancelCtx:  true,
			serverFunc: func(conn net.Conn) { _ = conn.Close() },
			wantOK:     false,
			wantErr:    context.Canceled,
		},
		{
			name:        "when_endpoint_invalid_returns_error",
			cred:        bruteforce.Credential{Username: "default", Password: "password"},
			badEndpoint: true,
			serverFunc:  func(conn net.Conn) { _ = conn.Close() },
			wantOK:      false,
			wantErr:     netendpoint.ErrEndpointMissingAddress,
		},
		{
			name: "when_default_user_valid_password_returns_true",
			cred: bruteforce.Credential{Username: "default", Password: "password"},
			serverFunc: func(conn net.Conn) {
				serveStatefulRedis(conn, map[string]string{"default": "password"}, false)
			},
			wantOK:  true,
			wantErr: nil,
		},
		{
			name: "when_acl_user_valid_password_with_noperm_ping_returns_true",
			cred: bruteforce.Credential{Username: "admin", Password: "secret"},
			serverFunc: func(conn net.Conn) {
				serveStatefulRedis(conn, map[string]string{"admin": "secret"}, true)
			},
			wantOK:  true,
			wantErr: nil,
		},
		{
			name: "when_invalid_password_returns_false",
			cred: bruteforce.Credential{Username: "default", Password: "wrong"},
			serverFunc: func(conn net.Conn) {
				serveStatefulRedis(conn, map[string]string{"default": "password"}, false)
			},
			wantOK:  false,
			wantErr: nil,
		},
		{
			name: "when_redis5_rejects_two_arg_auth_returns_false_without_error",
			cred: bruteforce.Credential{Username: "admin", Password: "admin"},
			serverFunc: func(conn net.Conn) {
				defer conn.Close()
				r := bufio.NewReader(conn)
				if _, err := readClientCommand(r); err != nil {
					return
				}
				_, _ = conn.Write([]byte("-ERR wrong number of arguments for 'auth' command\r\n"))
			},
			wantOK:  false,
			wantErr: nil,
		},
		{
			name: "when_two_arg_auth_returns_syntax_error_returns_false_without_error",
			cred: bruteforce.Credential{Username: "admin", Password: "admin"},
			serverFunc: func(conn net.Conn) {
				defer conn.Close()
				r := bufio.NewReader(conn)
				if _, err := readClientCommand(r); err != nil {
					return
				}
				_, _ = conn.Write([]byte("-ERR syntax error\r\n"))
			},
			wantOK:  false,
			wantErr: nil,
		},
		{
			name: "when_no_password_configured_returns_stop_bruteforce",
			cred: bruteforce.Credential{Username: "default", Password: "password"},
			serverFunc: func(conn net.Conn) {
				defer conn.Close()
				r := bufio.NewReader(conn)
				if _, err := readClientCommand(r); err != nil {
					return
				}
				_, _ = conn.Write([]byte("-ERR Client sent AUTH, but no password is set\r\n"))
			},
			wantOK:  false,
			wantErr: bruteforce.ErrStopBruteForce,
		},
		{
			name: "when_max_clients_denied_returns_stop_bruteforce",
			cred: bruteforce.Credential{Username: "default", Password: "password"},
			serverFunc: func(conn net.Conn) {
				defer conn.Close()
				r := bufio.NewReader(conn)
				if _, err := readClientCommand(r); err != nil {
					return
				}
				_, _ = conn.Write([]byte("-ERR max number of clients reached\r\n"))
			},
			wantOK:  false,
			wantErr: bruteforce.ErrStopBruteForce,
		},
		{
			name: "when_auth_ok_followed_by_unauthenticated_noauth_returns_false",
			cred: bruteforce.Credential{Username: "default", Password: "password"},
			serverFunc: func(conn net.Conn) {
				defer conn.Close()
				r := bufio.NewReader(conn)
				if _, err := readClientCommand(r); err != nil {
					return
				}
				_, _ = conn.Write([]byte("+OK\r\n"))
				if _, err := readClientCommand(r); err != nil {
					return
				}
				_, _ = conn.Write([]byte("-NOAUTH still unauthenticated\r\n"))
			},
			wantOK:  false,
			wantErr: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			addr := startFakeRedisServer(t, tc.serverFunc)
			svc := makeRedisService(t, addr, npb.TransportProtocol_TCP)
			if tc.badEndpoint {
				svc.ClearNetworkEndpoint()
			}

			ctx := context.Background()
			if tc.cancelCtx {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}

			h := NewHandler(testConfig(1))
			worker := h.NewWorker()
			defer worker.Close()

			gotOK, err := worker.TestCredential(ctx, svc, tc.cred)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("TestCredential() error = %v, want errors.Is(_, %v)", err, tc.wantErr)
				}
			} else if err != nil {
				t.Fatalf("TestCredential() unexpected error: %v", err)
			}
			if gotOK != tc.wantOK {
				t.Errorf("TestCredential() = %v, want %v", gotOK, tc.wantOK)
			}
		})
	}
}

func TestWorkerConnectionReuseAndConsecutiveErrors(t *testing.T) {
	t.Run("when_reused_connection_dropped_by_server_reconnects_transparently", func(t *testing.T) {
		var accepts atomic.Int32
		addr := startFakeRedisServer(t, func(conn net.Conn) {
			defer conn.Close()
			connNum := accepts.Add(1)
			r := bufio.NewReader(conn)
			args, err := readClientCommand(r)
			if err != nil {
				return
			}
			if connNum == 1 {
				// Answer first attempt, then close socket so second attempt must reconnect.
				_, _ = conn.Write([]byte("-WRONGPASS invalid\r\n"))
				return
			}
			if len(args) == 2 && args[1] == "goodpass" {
				_, _ = conn.Write([]byte("+OK\r\n"))
				if _, err := readClientCommand(r); err == nil {
					_, _ = conn.Write([]byte("+PONG\r\n"))
				}
			}
		})

		svc := makeRedisService(t, addr, npb.TransportProtocol_TCP)
		h := NewHandler(testConfig(1))
		w := h.NewWorker()
		defer w.Close()

		ok1, err1 := w.TestCredential(t.Context(), svc, bruteforce.Credential{Username: "default", Password: "bad"})
		if err1 != nil || ok1 {
			t.Fatalf("attempt 1 = (%v, %v), want (false, nil)", ok1, err1)
		}
		ok2, err2 := w.TestCredential(t.Context(), svc, bruteforce.Credential{Username: "default", Password: "goodpass"})
		if err2 != nil || !ok2 {
			t.Fatalf("attempt 2 after reconnect = (%v, %v), want (true, nil)", ok2, err2)
		}
	})

	t.Run("when_three_consecutive_transport_errors_stops_bruteforce", func(t *testing.T) {
		addr := startFakeRedisServer(t, func(conn net.Conn) {
			defer conn.Close()
			_, _ = conn.Write([]byte("INVALID_NON_RESP\r\n"))
		})
		svc := makeRedisService(t, addr, npb.TransportProtocol_TCP)
		h := NewHandler(testConfig(1))
		w := h.NewWorker()
		defer w.Close()

		for i := 1; i < maxConsecutiveTransportErrors; i++ {
			ok, err := w.TestCredential(t.Context(), svc, bruteforce.Credential{Username: "default", Password: "p"})
			if err != nil || ok {
				t.Fatalf("attempt %d = (%v, %v), want (false, nil)", i, ok, err)
			}
		}
		_, err := w.TestCredential(t.Context(), svc, bruteforce.Credential{Username: "default", Password: "p"})
		if !errors.Is(err, bruteforce.ErrStopBruteForce) {
			t.Fatalf("attempt %d error = %v, want ErrStopBruteForce", maxConsecutiveTransportErrors, err)
		}
	})
}

func TestDetector_Detect(t *testing.T) {
	tests := []struct {
		name         string
		accounts     map[string]string
		wantFindings int
	}{
		{
			name:         "when_vulnerable_default_password_reports_finding",
			accounts:     map[string]string{"default": "foobared"},
			wantFindings: 1,
		},
		{
			name:         "when_strong_password_configured_reports_no_findings",
			accounts:     map[string]string{"default": "Str0ng_Unbruteforceable_9f8e7d6c5b4a!"},
			wantFindings: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			addr := startFakeRedisServer(t, func(conn net.Conn) {
				serveStatefulRedis(conn, tc.accounts, false)
			})
			store := credentialstore.New()
			_ = store.AddUser("default")
			store.AddMultiplePasswordsForUser("default", []string{"wrong1", "password"})

			det, err := NewWithOptions(t.Context(), testConfig(1), &bruteforce.Options{
				CredentialStore:    store,
				DefaultCredentials: DefaultCredentials(),
			})
			if err != nil {
				t.Fatalf("NewWithOptions() failed: %v", err)
			}

			svc := makeRedisService(t, addr, npb.TransportProtocol_TCP)
			reports, err := det.Detect(t.Context(), svc)
			if err != nil {
				t.Fatalf("Detect() unexpected error: %v", err)
			}
			if len(reports.GetDetectionReports()) != tc.wantFindings {
				t.Fatalf("Detect() findings = %d, want %d", len(reports.GetDetectionReports()), tc.wantFindings)
			}
			if tc.wantFindings > 0 {
				rep := reports.GetDetectionReports()[0]
				if rep.GetDetectionStatus() != drpb.DetectionStatus_VULNERABILITY_VERIFIED {
					t.Errorf("DetectionStatus = %v, want VULNERABILITY_VERIFIED", rep.GetDetectionStatus())
				}
			}
		})
	}

	t.Run("when_redis6_default_nopass_and_weak_named_acl_account_reports_finding", func(t *testing.T) {
		addr := startFakeRedisServer(t, func(conn net.Conn) {
			defer conn.Close()
			r := bufio.NewReader(conn)
			currentUser := "default"
			for {
				args, err := readClientCommand(r)
				if err != nil || len(args) == 0 {
					return
				}
				switch strings.ToUpper(args[0]) {
				case "PING":
					_, _ = conn.Write([]byte("+PONG\r\n"))
				case "INFO":
					if currentUser == "default" {
						_, _ = conn.Write([]byte("-NOPERM this user has no permissions to run the 'info' command\r\n"))
					} else {
						info := "# Server\r\nredis_version:7.4.0\r\n"
						_, _ = fmt.Fprintf(conn, "$%d\r\n%s\r\n", len(info), info)
					}
				case "AUTH":
					if len(args) == 2 {
						_, _ = conn.Write([]byte("-ERR AUTH <password> called without any password configured for the default user. Are you sure your configuration is correct?\r\n"))
					} else if len(args) == 3 && args[1] == "admin" && args[2] == "admin" {
						currentUser = "admin"
						_, _ = conn.Write([]byte("+OK\r\n"))
					} else {
						_, _ = conn.Write([]byte("-WRONGPASS invalid username-password pair or user is disabled.\r\n"))
					}
				}
			}
		})

		det, err := New(t.Context(), testConfig(1))
		if err != nil {
			t.Fatalf("New() failed: %v", err)
		}
		svc := makeRedisService(t, addr, npb.TransportProtocol_TCP)
		reports, err := det.Detect(t.Context(), svc)
		if err != nil {
			t.Fatalf("Detect() unexpected error: %v", err)
		}
		if len(reports.GetDetectionReports()) != 1 {
			t.Fatalf("Detect() findings = %d, want 1", len(reports.GetDetectionReports()))
		}
	})
}

func TestReadRESPReplyEdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    respReply
		wantErr bool
	}{
		{
			name:    "when_null_bulk_string_returns_empty_bulk",
			raw:     "$-1\r\n",
			want:    respReply{kind: '$', text: ""},
			wantErr: false,
		},
		{
			name:    "when_valid_bulk_string_returns_payload",
			raw:     "$5\r\nhello\r\n",
			want:    respReply{kind: '$', text: "hello"},
			wantErr: false,
		},
		{
			name:    "when_missing_crlf_returns_error",
			raw:     "+OK\n",
			wantErr: true,
		},
		{
			name:    "when_bulk_length_oversized_returns_error",
			raw:     "$999999\r\n",
			wantErr: true,
		},
		{
			name:    "when_bulk_missing_trailing_crlf_returns_error",
			raw:     "$3\r\nabcXX",
			wantErr: true,
		},
		{
			name:    "when_bulk_truncated_returns_error",
			raw:     "$10\r\nabc",
			wantErr: true,
		},
		{
			name:    "when_integer_reply_type_returns_error",
			raw:     ":1\r\n",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := bufio.NewReader(strings.NewReader(tc.raw))
			got, err := readRESPReply(r)
			if (err != nil) != tc.wantErr {
				t.Fatalf("readRESPReply() error = %v, wantErr %v", err, tc.wantErr)
			}
			if !tc.wantErr && got != tc.want {
				t.Errorf("readRESPReply() = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func startFakeRedisServer(t *testing.T, handler func(conn net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() failed: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			go handler(conn)
		}
	}()
	return ln.Addr().String()
}

func serveStatefulRedis(conn net.Conn, accounts map[string]string, noPermPing bool) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	authenticated := false

	for {
		args, err := readClientCommand(r)
		if err != nil || len(args) == 0 {
			return
		}
		switch strings.ToUpper(args[0]) {
		case "AUTH":
			user := "default"
			pass := ""
			if len(args) == 2 {
				pass = args[1]
			} else if len(args) == 3 {
				user = args[1]
				pass = args[2]
			}
			expected, exists := accounts[user]
			if exists && pass == expected {
				authenticated = true
				_, _ = conn.Write([]byte("+OK\r\n"))
			} else {
				authenticated = false
				_, _ = conn.Write([]byte("-WRONGPASS invalid username-password pair or user is disabled.\r\n"))
			}
		case "PING":
			if !authenticated {
				_, _ = conn.Write([]byte("-NOAUTH Authentication required.\r\n"))
			} else if noPermPing {
				_, _ = conn.Write([]byte("-NOPERM no permissions to run 'ping'\r\n"))
			} else {
				_, _ = conn.Write([]byte("+PONG\r\n"))
			}
		default:
			_, _ = conn.Write([]byte("-ERR unknown command\r\n"))
		}
	}
}

func readClientCommand(r *bufio.Reader) ([]string, error) {
	hdr, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	hdr = strings.TrimSuffix(hdr, "\r\n")
	if len(hdr) < 2 || hdr[0] != '*' {
		return nil, errors.New("expected RESP array")
	}
	count, err := strconv.Atoi(hdr[1:])
	if err != nil || count < 0 || count > 16 {
		return nil, errors.New("invalid array count")
	}
	args := make([]string, 0, count)
	for range count {
		lenLine, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		lenLine = strings.TrimSuffix(lenLine, "\r\n")
		if len(lenLine) < 2 || lenLine[0] != '$' {
			return nil, errors.New("expected bulk string")
		}
		n, err := strconv.Atoi(lenLine[1:])
		if err != nil || n < 0 || n > 4096 {
			return nil, errors.New("invalid bulk length")
		}
		buf := make([]byte, n+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		args = append(args, string(buf[:n]))
	}
	return args, nil
}
