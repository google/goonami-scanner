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

package postgresclient

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	pgcfgpb "github.com/google/goonami-scanner/common/clients/postgresclient/postgres_client_config_go_proto"
	"github.com/google/goonami-scanner/core/config"
	cpb "github.com/google/goonami-scanner/core/config/config_go_proto"
	"github.com/lib/pq"
	"google.golang.org/protobuf/proto"
)

func TestNew_Timeout(t *testing.T) {
	tests := []struct {
		name        string
		cfg         *config.Config
		wantTimeout time.Duration
	}{
		{
			name:        "when_config_is_nil_uses_default_timeout",
			cfg:         nil,
			wantTimeout: 5 * time.Second,
		},
		{
			name: "when_postgres_config_is_set_uses_configured_timeout",
			cfg: config.FromProto(cpb.Config_builder{
				Clients: cpb.ClientsConfig_builder{
					Postgres: pgcfgpb.PostgresClientConfig_builder{
						TimeoutSeconds: proto.Int32(12),
					}.Build(),
				}.Build(),
			}.Build()),
			wantTimeout: 12 * time.Second,
		},
		{
			name: "when_timeout_seconds_is_non_positive_uses_default_timeout",
			cfg: config.FromProto(cpb.Config_builder{
				Clients: cpb.ClientsConfig_builder{
					Postgres: pgcfgpb.PostgresClientConfig_builder{
						TimeoutSeconds: proto.Int32(0),
					}.Build(),
				}.Build(),
			}.Build()),
			wantTimeout: 5 * time.Second,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client := New(tc.cfg)
			if got := client.Timeout(); got != tc.wantTimeout {
				t.Errorf("Timeout() = %v, want %v", got, tc.wantTimeout)
			}
		})
	}
}

func TestClassifyError(t *testing.T) {
	unclassifiedErr := errors.New("some unexpected database error")

	tests := []struct {
		name    string
		inErr   error
		wantErr error
	}{
		{
			name:    "when_err_is_nil_returns_nil",
			inErr:   nil,
			wantErr: nil,
		},
		{
			name:    "when_err_is_context_canceled_returns_context_canceled",
			inErr:   context.Canceled,
			wantErr: context.Canceled,
		},
		{
			name:    "when_err_is_context_deadline_exceeded_returns_deadline_exceeded",
			inErr:   context.DeadlineExceeded,
			wantErr: context.DeadlineExceeded,
		},
		{
			name:    "when_err_is_already_sentinel_returns_unchanged",
			inErr:   ErrAuthFailed,
			wantErr: ErrAuthFailed,
		},
		{
			name:    "when_pq_error_28p01_returns_err_auth_failed",
			inErr:   &pq.Error{Code: "28P01", Message: "password authentication failed for user \"postgres\""},
			wantErr: ErrAuthFailed,
		},
		{
			name:    "when_pq_error_28000_role_does_not_exist_returns_err_auth_failed",
			inErr:   &pq.Error{Code: "28000", Message: "role \"goonami_fp_probe\" does not exist"},
			wantErr: ErrAuthFailed,
		},
		{
			name:    "when_pq_error_28000_no_pg_hba_entry_returns_err_password_auth_unsupported",
			inErr:   &pq.Error{Code: "28000", Message: "no pg_hba.conf entry for host \"127.0.0.1\", user \"postgres\""},
			wantErr: ErrPasswordAuthUnsupported,
		},
		{
			name:    "when_pq_error_08p01_returns_err_not_postgres_service",
			inErr:   &pq.Error{Code: "08P01", Message: "invalid startup packet layout"},
			wantErr: ErrNotPostgresService,
		},
		{
			name:    "when_pq_error_0a000_returns_err_password_auth_unsupported",
			inErr:   &pq.Error{Code: "0A000", Message: "authentication method not supported"},
			wantErr: ErrPasswordAuthUnsupported,
		},
		{
			name:    "when_io_eof_returns_err_not_postgres_service",
			inErr:   io.EOF,
			wantErr: ErrNotPostgresService,
		},
		{
			name:    "when_string_unsupported_authentication_returns_err_password_auth_unsupported",
			inErr:   errors.New("pq: unsupported authentication request: kerberosv5 (2)"),
			wantErr: ErrPasswordAuthUnsupported,
		},
		{
			name:    "when_string_password_auth_failed_returns_err_auth_failed",
			inErr:   errors.New("pq: password authentication failed for user"),
			wantErr: ErrAuthFailed,
		},
		{
			name:    "when_string_network_or_protocol_error_returns_err_not_postgres_service",
			inErr:   errors.New("pq: unknown response for startup: 'H'"),
			wantErr: ErrNotPostgresService,
		},
		{
			name:    "when_unclassified_error_returns_original_error",
			inErr:   unclassifiedErr,
			wantErr: unclassifiedErr,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyError(tc.inErr)
			if tc.wantErr == nil {
				if got != nil {
					t.Fatalf("ClassifyError(%v) = %v, want nil", tc.inErr, got)
				}
				return
			}
			if !errors.Is(got, tc.wantErr) {
				t.Errorf("ClassifyError(%v) = %v, want errors.Is(_, %v)", tc.inErr, got, tc.wantErr)
			}
		})
	}
}

func TestConnect(t *testing.T) {
	shortTimeoutCfg := config.FromProto(cpb.Config_builder{
		Clients: cpb.ClientsConfig_builder{
			Postgres: pgcfgpb.PostgresClientConfig_builder{
				TimeoutSeconds: proto.Int32(1),
			}.Build(),
		}.Build(),
	}.Build())

	tests := []struct {
		name      string
		cancelCtx bool
		override  string
		username  string
		password  string
		database  string
		handler   func(conn net.Conn)
		wantErr   error
	}{
		{
			name:      "when_context_is_already_canceled_returns_context_canceled",
			cancelCtx: true,
			username:  "postgres",
			password:  "postgres",
			handler:   func(conn net.Conn) { _ = conn.Close() },
			wantErr:   context.Canceled,
		},
		{
			name:     "when_address_is_invalid_returns_err_not_postgres_service",
			override: "invalid-address-without-port",
			username: "postgres",
			password: "postgres",
			handler:  func(conn net.Conn) { _ = conn.Close() },
			wantErr:  ErrNotPostgresService,
		},
		{
			name:     "when_authentication_ok_succeeds",
			username: "postgres",
			password: "",
			database: "",
			handler: func(conn net.Conn) {
				defer conn.Close()
				msg, isSSL, err := readStartupOrSSL(conn)
				if err != nil {
					return
				}
				if isSSL {
					_, _ = conn.Write([]byte{'N'})
					return
				}
				_ = msg
				writeAuthPacket(conn, 0, nil)
				writeReadyForQuery(conn)
				handlePingQuery(conn)
			},
			wantErr: nil,
		},
		{
			name:     "when_cleartext_password_matches_succeeds",
			username: "postgres",
			password: `p'a\ss`,
			database: "customdb",
			handler: func(conn net.Conn) {
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
				if gotPass != `p'a\ss` {
					writeErrorResponse(conn, "28P01", "password authentication failed")
					return
				}
				writeAuthPacket(conn, 0, nil)
				writeReadyForQuery(conn)
				handlePingQuery(conn)
			},
			wantErr: nil,
		},
		{
			name:     "when_cleartext_password_fails_returns_err_auth_failed",
			username: "postgres",
			password: "wrong",
			handler: func(conn net.Conn) {
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
				writeErrorResponse(conn, "28P01", "password authentication failed for user \"postgres\"")
			},
			wantErr: ErrAuthFailed,
		},
		{
			name:     "when_server_requests_unsupported_auth_method_returns_err_password_auth_unsupported",
			username: "postgres",
			password: "postgres",
			handler: func(conn net.Conn) {
				defer conn.Close()
				_, isSSL, err := readStartupOrSSL(conn)
				if err != nil {
					return
				}
				if isSSL {
					_, _ = conn.Write([]byte{'N'})
					return
				}
				// AuthReqKrb5 = 2
				writeAuthPacket(conn, 2, nil)
			},
			wantErr: ErrPasswordAuthUnsupported,
		},
		{
			name:     "when_server_sends_non_postgres_banner_returns_err_not_postgres_service",
			username: "postgres",
			password: "postgres",
			handler: func(conn net.Conn) {
				defer conn.Close()
				_, _ = conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
			},
			wantErr: ErrNotPostgresService,
		},
		{
			name:     "when_server_sends_malformed_frame_triggering_driver_panic_recovers_and_returns_err_not_postgres_service",
			username: "postgres",
			password: "postgres",
			handler: func(conn net.Conn) {
				defer conn.Close()
				_, isSSL, err := readStartupOrSSL(conn)
				if err != nil {
					return
				}
				if isSSL {
					_, _ = conn.Write([]byte{'N'})
					return
				}
				// Send a 5-byte frame with length = 0 (< 4), causing pq's recvMessage to slice cn.scratch[: -4].
				_, _ = conn.Write([]byte{'R', 0x00, 0x00, 0x00, 0x00})
			},
			wantErr: ErrNotPostgresService,
		},
		{
			name:     "when_server_hangs_past_timeout_returns_err_not_postgres_service",
			username: "postgres",
			password: "postgres",
			handler: func(conn net.Conn) {
				defer conn.Close()
				time.Sleep(2 * time.Second)
			},
			wantErr: ErrNotPostgresService,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			addr := startFakeServer(t, tc.handler)
			if tc.override != "" {
				addr = tc.override
			}

			ctx := context.Background()
			if tc.cancelCtx {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}

			client := New(shortTimeoutCfg)
			db, err := client.Connect(ctx, addr, tc.username, tc.password, tc.database)
			if db != nil {
				defer db.Close()
			}

			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("Connect() unexpected error: %v", err)
				}
				if db == nil {
					t.Fatal("Connect() returned nil *sql.DB on success")
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("Connect() error = %v, want errors.Is(_, %v)", err, tc.wantErr)
			}
		})
	}
}

func startFakeServer(t *testing.T, handler func(conn net.Conn)) string {
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
