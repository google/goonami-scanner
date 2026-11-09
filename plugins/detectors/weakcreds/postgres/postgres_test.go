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

package postgres

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/goonami-scanner/common/bruteforce"
	"github.com/google/goonami-scanner/common/clients/postgresclient"
	pgcfgpb "github.com/google/goonami-scanner/common/clients/postgresclient/postgres_client_config_go_proto"
	"github.com/google/goonami-scanner/common/credentialstore"
	"github.com/google/goonami-scanner/core/config"
	cpb "github.com/google/goonami-scanner/core/config/config_go_proto"
	"github.com/google/goonami-scanner/core/net/netendpoint"
	drpb "github.com/google/tsunami-security-scanner/proto/go/detection_go_proto"
	npb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
	"google.golang.org/protobuf/proto"
)

func testConfig() *config.Config {
	return config.FromProto(cpb.Config_builder{
		Clients: cpb.ClientsConfig_builder{
			Postgres: pgcfgpb.PostgresClientConfig_builder{
				TimeoutSeconds: proto.Int32(1),
			}.Build(),
		}.Build(),
	}.Build())
}

func makePostgresService(t *testing.T, addr string, protocol npb.TransportProtocol) *nspb.NetworkService {
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
		ServiceName:       "postgresql",
		TransportProtocol: protocol,
	}.Build()
}

func TestDefaultCredentials(t *testing.T) {
	creds := DefaultCredentials()
	if len(creds) < 2 {
		t.Fatalf("DefaultCredentials() returned %d credentials, want at least 2", len(creds))
	}
	if creds[0].Username != "postgres" || creds[0].Password != "" {
		t.Errorf("DefaultCredentials()[0] = %+v, want postgres:<empty>", creds[0])
	}
	if creds[1].Username != "postgres" || creds[1].Password != "postgres" {
		t.Errorf("DefaultCredentials()[1] = %+v, want postgres:postgres", creds[1])
	}
}

func TestHandlerMetadata(t *testing.T) {
	h := NewHandler(testConfig())
	if got := h.Name(); got != ModuleName {
		t.Errorf("Name() = %q, want %q", got, ModuleName)
	}
	if vuln := h.Vulnerability(); vuln == nil || vuln.GetMainId().GetValue() != "POSTGRES_WEAK_CREDENTIALS" {
		t.Errorf("Vulnerability() = %v, want POSTGRES_WEAK_CREDENTIALS", vuln)
	}
}

func TestFingerprint(t *testing.T) {
	tests := []struct {
		name        string
		protocol    npb.TransportProtocol
		isWeb       bool
		badEndpoint bool
		cancelCtx   bool
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
			name:     "when_server_returns_auth_ok_returns_true",
			protocol: npb.TransportProtocol_TCP,
			serverFunc: func(conn net.Conn) {
				defer conn.Close()
				_, isSSL, err := readStartupOrSSL(conn)
				if err != nil {
					return
				}
				if isSSL {
					_, _ = conn.Write([]byte{'N'})
					return
				}
				writeAuthPacket(conn, 0, nil)
				writeReadyForQuery(conn)
				handlePingQuery(conn)
			},
			wantMatch: true,
			wantErr:   false,
		},
		{
			name:     "when_server_rejects_probe_password_with_28p01_returns_true",
			protocol: npb.TransportProtocol_TCP,
			serverFunc: func(conn net.Conn) {
				defer conn.Close()
				_, isSSL, err := readStartupOrSSL(conn)
				if err != nil {
					return
				}
				if isSSL {
					_, _ = conn.Write([]byte{'N'})
					return
				}
				writeAuthPacket(conn, 3, nil)
				_, _, err = readFrontendMessage(conn)
				if err != nil {
					return
				}
				writeErrorResponse(conn, "28P01", "password authentication failed")
			},
			wantMatch: true,
			wantErr:   false,
		},
		{
			name:     "when_server_requests_unsupported_auth_method_returns_false",
			protocol: npb.TransportProtocol_TCP,
			serverFunc: func(conn net.Conn) {
				defer conn.Close()
				_, isSSL, err := readStartupOrSSL(conn)
				if err != nil {
					return
				}
				if isSSL {
					_, _ = conn.Write([]byte{'N'})
					return
				}
				writeAuthPacket(conn, 2, nil)
			},
			wantMatch: false,
			wantErr:   false,
		},
		{
			name:     "when_server_sends_non_postgres_banner_returns_false",
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
			addr := startFakePostgresServer(t, tc.serverFunc)
			svc := makePostgresService(t, addr, tc.protocol)
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

			h := NewHandler(testConfig())
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
			cred:       bruteforce.Credential{Username: "postgres", Password: "postgres"},
			cancelCtx:  true,
			serverFunc: func(conn net.Conn) { _ = conn.Close() },
			wantOK:     false,
			wantErr:    context.Canceled,
		},
		{
			name:        "when_endpoint_invalid_returns_error",
			cred:        bruteforce.Credential{Username: "postgres", Password: "postgres"},
			badEndpoint: true,
			serverFunc:  func(conn net.Conn) { _ = conn.Close() },
			wantOK:      false,
			wantErr:     netendpoint.ErrEndpointMissingAddress,
		},
		{
			name: "when_valid_cleartext_credentials_returns_true",
			cred: bruteforce.Credential{Username: "postgres", Password: "secret"},
			serverFunc: func(conn net.Conn) {
				defer conn.Close()
				_, isSSL, err := readStartupOrSSL(conn)
				if err != nil {
					return
				}
				if isSSL {
					_, _ = conn.Write([]byte{'N'})
					return
				}
				writeAuthPacket(conn, 3, nil)
				typ, payload, err := readFrontendMessage(conn)
				if err != nil || typ != 'p' {
					return
				}
				gotPass := strings.TrimRight(string(payload), "\x00")
				if gotPass != "secret" {
					writeErrorResponse(conn, "28P01", "invalid password")
					return
				}
				writeAuthPacket(conn, 0, nil)
				writeReadyForQuery(conn)
				handlePingQuery(conn)
			},
			wantOK:  true,
			wantErr: nil,
		},
		{
			name: "when_invalid_credentials_returns_false_without_error",
			cred: bruteforce.Credential{Username: "postgres", Password: "wrong"},
			serverFunc: func(conn net.Conn) {
				defer conn.Close()
				_, isSSL, err := readStartupOrSSL(conn)
				if err != nil {
					return
				}
				if isSSL {
					_, _ = conn.Write([]byte{'N'})
					return
				}
				writeAuthPacket(conn, 3, nil)
				_, _, err = readFrontendMessage(conn)
				if err != nil {
					return
				}
				writeErrorResponse(conn, "28P01", "password authentication failed")
			},
			wantOK:  false,
			wantErr: nil,
		},
		{
			name: "when_non_postgres_service_error_returns_classified_error",
			cred: bruteforce.Credential{Username: "postgres", Password: "postgres"},
			serverFunc: func(conn net.Conn) {
				defer conn.Close()
				_, _ = conn.Write([]byte("NOT_POSTGRES\r\n"))
			},
			wantOK:  false,
			wantErr: postgresclient.ErrNotPostgresService,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			addr := startFakePostgresServer(t, tc.serverFunc)
			svc := makePostgresService(t, addr, npb.TransportProtocol_TCP)
			if tc.badEndpoint {
				svc.ClearNetworkEndpoint()
			}

			ctx := context.Background()
			if tc.cancelCtx {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}

			h := NewHandler(testConfig())
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

func TestDetector_Detect(t *testing.T) {
	ctx := context.Background()
	if _, err := New(ctx, testConfig()); err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}

	tests := []struct {
		name         string
		validUser    string
		validPass    string
		wantFindings int
	}{
		{
			name:         "when_vulnerable_default_credentials_reports_finding",
			validUser:    "postgres",
			validPass:    "postgres",
			wantFindings: 1,
		},
		{
			name:         "when_strong_credentials_configured_reports_no_findings",
			validUser:    "postgres",
			validPass:    "unbruteforceable_9f8e7d6c5b4a3210",
			wantFindings: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			addr := startFakePostgresServer(t, func(conn net.Conn) {
				defer conn.Close()
				msg, isSSL, err := readStartupOrSSL(conn)
				if err != nil {
					return
				}
				if isSSL {
					_, _ = conn.Write([]byte{'N'})
					return
				}
				user := parseStartupParam(msg, "user")
				writeAuthPacket(conn, 3, nil)
				typ, payload, err := readFrontendMessage(conn)
				if err != nil || typ != 'p' {
					return
				}
				pass := strings.TrimRight(string(payload), "\x00")
				if user == tc.validUser && pass == tc.validPass {
					writeAuthPacket(conn, 0, nil)
					writeReadyForQuery(conn)
					handlePingQuery(conn)
					return
				}
				writeErrorResponse(conn, "28P01", "password authentication failed")
			})

			store := credentialstore.New()
			_ = store.AddUser("postgres")
			store.AddMultiplePasswordsForUser("postgres", []string{"", "postgres"})

			det, err := NewWithOptions(ctx, testConfig(), &bruteforce.Options{
				CredentialStore:    store,
				DefaultCredentials: DefaultCredentials(),
			})
			if err != nil {
				t.Fatalf("NewWithOptions() unexpected error: %v", err)
			}

			svc := makePostgresService(t, addr, npb.TransportProtocol_TCP)
			reports, err := det.Detect(ctx, svc)
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

	t.Run("when_test_credential_encounters_non_postgres_error_stops_brute_forcing_early", func(t *testing.T) {
		var nonSSLConns atomic.Int32
		addr := startFakePostgresServer(t, func(conn net.Conn) {
			defer conn.Close()
			_, isSSL, err := readStartupOrSSL(conn)
			if err != nil {
				return
			}
			if isSSL {
				_, _ = conn.Write([]byte{'N'})
				return
			}
			if nonSSLConns.Add(1) == 1 {
				writeAuthPacket(conn, 3, nil)
				_, _, err = readFrontendMessage(conn)
				if err != nil {
					return
				}
				writeErrorResponse(conn, "28P01", "password authentication failed")
				return
			}
			_, _ = conn.Write([]byte("NOT_POSTGRES\r\n"))
		})

		store := credentialstore.New()
		_ = store.AddUser("postgres")
		store.AddMultiplePasswordsForUser("postgres", []string{"", "postgres", "123456"})

		det, err := NewWithOptions(ctx, testConfig(), &bruteforce.Options{
			CredentialStore:    store,
			DefaultCredentials: DefaultCredentials(),
		})
		if err != nil {
			t.Fatalf("NewWithOptions() unexpected error: %v", err)
		}

		svc := makePostgresService(t, addr, npb.TransportProtocol_TCP)
		_, err = det.Detect(ctx, svc)
		if !errors.Is(err, postgresclient.ErrNotPostgresService) {
			t.Fatalf("Detect() error = %v, want %v", err, postgresclient.ErrNotPostgresService)
		}
		if got := nonSSLConns.Load(); got != 2 {
			t.Errorf("non-SSL connections = %d, want 2 (1 fingerprint + 1 aborted credential attempt)", got)
		}
	})
}

func startFakePostgresServer(t *testing.T, handler func(conn net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() failed: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handler(conn)
		}
	}()
	return ln.Addr().String()
}

func readStartupOrSSL(r io.Reader) ([]byte, bool, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, false, err
	}
	length := binary.BigEndian.Uint32(lenBuf[:])
	if length < 8 || length > 10000 {
		return nil, false, errors.New("invalid startup length")
	}
	body := make([]byte, length-4)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, false, err
	}
	code := binary.BigEndian.Uint32(body[:4])
	if length == 8 && code == 80877103 {
		return body, true, nil
	}
	return body, false, nil
}

func parseStartupParam(startupBody []byte, key string) string {
	if len(startupBody) <= 4 {
		return ""
	}
	parts := bytes.Split(startupBody[4:], []byte{0})
	for i := 0; i+1 < len(parts); i += 2 {
		if len(parts[i]) == 0 {
			break
		}
		if string(parts[i]) == key {
			return string(parts[i+1])
		}
	}
	return ""
}

func readFrontendMessage(r io.Reader) (byte, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	length := binary.BigEndian.Uint32(hdr[1:5])
	if length < 4 {
		return 0, nil, errors.New("invalid message length")
	}
	payload := make([]byte, length-4)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return hdr[0], payload, nil
}

func writeAuthPacket(w io.Writer, authType uint32, extra []byte) {
	var buf bytes.Buffer
	buf.WriteByte('R')
	_ = binary.Write(&buf, binary.BigEndian, uint32(8+len(extra)))
	_ = binary.Write(&buf, binary.BigEndian, authType)
	buf.Write(extra)
	_, _ = w.Write(buf.Bytes())
}

func writeReadyForQuery(w io.Writer) {
	_, _ = w.Write([]byte{'Z', 0, 0, 0, 5, 'I'})
}

func handlePingQuery(rw io.ReadWriter) {
	typ, _, err := readFrontendMessage(rw)
	if err != nil || typ != 'Q' {
		return
	}
	_, _ = rw.Write([]byte{'I', 0, 0, 0, 4})
	writeReadyForQuery(rw)
}

func writeErrorResponse(w io.Writer, code, msg string) {
	var payload bytes.Buffer
	payload.WriteByte('S')
	payload.WriteString("FATAL\x00")
	payload.WriteByte('C')
	payload.WriteString(code + "\x00")
	payload.WriteByte('M')
	payload.WriteString(msg + "\x00")
	payload.WriteByte(0)

	var buf bytes.Buffer
	buf.WriteByte('E')
	_ = binary.Write(&buf, binary.BigEndian, uint32(4+payload.Len()))
	buf.Write(payload.Bytes())
	_, _ = w.Write(buf.Bytes())
}
