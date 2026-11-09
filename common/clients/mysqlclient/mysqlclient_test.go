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

package mysqlclient

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/log"
	"google.golang.org/protobuf/proto"

	mccpb "github.com/google/goonami-scanner/common/clients/mysqlclient/mysql_client_config_go_proto"
	cpb "github.com/google/goonami-scanner/core/config/config_go_proto"
)

func writeMySQLPacket(w io.Writer, seq byte, payload []byte) error {
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

func readMySQLPacket(r io.Reader) ([]byte, byte, error) {
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

func buildFakeGreeting(plugin string) []byte {
	const (
		capLongPassword              uint32 = 1 << 0
		capProtocol41                uint32 = 1 << 9
		capSecureConn                uint32 = 1 << 15
		capPluginAuth                uint32 = 1 << 19
		capPluginAuthLenEncClientDat uint32 = 1 << 21
	)
	caps := capLongPassword | capProtocol41 | capSecureConn | capPluginAuth | capPluginAuthLenEncClientDat

	var buf []byte
	buf = append(buf, 0x0a) // protocol v10
	buf = append(buf, "8.0.36\x00"...)
	buf = append(buf, 1, 0, 0, 0) // connection ID
	buf = append(buf, "01234567"...)
	buf = append(buf, 0x00) // filler

	var lowerCaps [2]byte
	binary.LittleEndian.PutUint16(lowerCaps[:], uint16(caps&0xffff))
	buf = append(buf, lowerCaps[:]...)
	buf = append(buf, 45)         // utf8mb4_general_ci
	buf = append(buf, 0x02, 0x00) // status flags

	var upperCaps [2]byte
	binary.LittleEndian.PutUint16(upperCaps[:], uint16(caps>>16))
	buf = append(buf, upperCaps[:]...)
	buf = append(buf, 21)                  // auth plugin data len
	buf = append(buf, make([]byte, 10)...) // 10 reserved bytes
	buf = append(buf, "890123456789\x00"...)
	buf = append(buf, plugin...)
	buf = append(buf, 0x00)
	return buf
}

func buildFakeERRPacket(code uint16, sqlState string, msg string) []byte {
	pkt := []byte{0xff, byte(code), byte(code >> 8)}
	if len(sqlState) == 5 {
		pkt = append(pkt, '#')
		pkt = append(pkt, sqlState...)
	}
	pkt = append(pkt, msg...)
	return pkt
}

func startFakeMySQLServer(t *testing.T, handler func(conn net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() unexpected error: %v", err)
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
	return ln.Addr().String()
}

func hasCleartextCredentials(resp []byte, wantUser, wantPass string) bool {
	if len(resp) <= 32 {
		return false
	}
	body := resp[32:]
	hasUser := bytes.Contains(body, append([]byte(wantUser), 0x00))
	hasPass := bytes.Contains(body, append([]byte(wantPass), 0x00))
	return hasUser && hasPass
}

func startPasswordMySQLServer(t *testing.T, wantUser, wantPass string) string {
	t.Helper()
	return startFakeMySQLServer(t, func(conn net.Conn) {
		if err := writeMySQLPacket(conn, 0, buildFakeGreeting("mysql_clear_password")); err != nil {
			return
		}
		resp, seq, err := readMySQLPacket(conn)
		if err != nil {
			return
		}
		// Client handshake response has 32-byte header before NUL-terminated username and length-encoded cleartext password.
		if hasCleartextCredentials(resp, wantUser, wantPass) {
			if err := writeMySQLPacket(conn, seq+1, []byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00}); err != nil {
				return
			}
			// Respond to any follow-up command (such as COM_PING) with OK.
			for {
				_, cmdSeq, err := readMySQLPacket(conn)
				if err != nil {
					return
				}
				if err := writeMySQLPacket(conn, cmdSeq+1, []byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00}); err != nil {
					return
				}
			}
		}
		_ = writeMySQLPacket(conn, seq+1, buildFakeERRPacket(1045, "28000", "Access denied"))
	})
}

func closedTCPAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() unexpected error: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("ln.Close() unexpected error: %v", err)
	}
	return addr
}

func TestNew(t *testing.T) {
	testCases := []struct {
		name        string
		cfg         *config.Config
		wantTimeout time.Duration
	}{
		{
			name:        "when_nil_config_uses_default_timeout",
			cfg:         nil,
			wantTimeout: DefaultTimeout,
		},
		{
			name:        "when_empty_config_uses_global_performance_timeout",
			cfg:         config.Default(),
			wantTimeout: 10 * time.Second,
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
			wantTimeout: 25 * time.Second,
		},
		{
			name: "when_client_mysql_timeout_configured_overrides_global",
			cfg: config.FromProto(
				cpb.Config_builder{
					Globalcfg: cpb.GlobalConfig_builder{
						Performance: cpb.GlobalConfig_Performance_builder{
							TimeoutPerRequestSeconds: proto.Int32(25),
						}.Build(),
					}.Build(),
					Clients: cpb.ClientsConfig_builder{
						Mysql: mccpb.MySQLClientConfig_builder{
							TimeoutSeconds: proto.Int32(5),
						}.Build(),
					}.Build(),
				}.Build(),
			),
			wantTimeout: 5 * time.Second,
		},
		{
			name: "when_client_mysql_timeout_is_non_positive_falls_back_to_default_timeout",
			cfg: config.FromProto(
				cpb.Config_builder{
					Clients: cpb.ClientsConfig_builder{
						Mysql: mccpb.MySQLClientConfig_builder{
							TimeoutSeconds: proto.Int32(0),
						}.Build(),
					}.Build(),
				}.Build(),
			),
			wantTimeout: DefaultTimeout,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := New(tc.cfg)
			if client == nil {
				t.Fatalf("New(%v) = nil, want non-nil *Client", tc.cfg)
			}
			if got := client.Timeout(); got != tc.wantTimeout {
				t.Errorf("New(%v).Timeout() = %v, want %v", tc.cfg, got, tc.wantTimeout)
			}
		})
	}
}

func TestConnect_Success(t *testing.T) {
	log.SetLogger(&log.DefaultLogger{VerboseLevel: log.DebugLevelRequest})
	addr := startPasswordMySQLServer(t, "admin", "secret")
	client := New(nil)

	db, err := client.Connect(t.Context(), addr, "admin", "secret")
	if err != nil {
		t.Fatalf("Connect(%q, %q, %q) unexpected error: %v", addr, "admin", "secret", err)
	}
	if db == nil {
		t.Fatalf("Connect(%q, %q, %q) = nil, want non-nil *sql.DB", addr, "admin", "secret")
	}
	_ = db.Close()
}

func TestConnect_Errors(t *testing.T) {
	log.SetLogger(&log.DefaultLogger{VerboseLevel: log.DebugLevelRequest})
	shortTimeoutCfg := config.FromProto(
		cpb.Config_builder{
			Clients: cpb.ClientsConfig_builder{
				Mysql: mccpb.MySQLClientConfig_builder{
					TimeoutSeconds: proto.Int32(1),
				}.Build(),
			}.Build(),
		}.Build(),
	)
	client := New(shortTimeoutCfg)

	authAddr := startPasswordMySQLServer(t, "admin", "secret")
	hostBlockedAddr := startFakeMySQLServer(t, func(conn net.Conn) {
		_ = writeMySQLPacket(conn, 0, buildFakeERRPacket(1130, "HY000", "Host '127.0.0.1' is not allowed to connect"))
	})
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(httpServer.Close)
	httpAddr := httpServer.Listener.Addr().String()
	refusedAddr := closedTCPAddr(t)
	closedImmediatelyAddr := startFakeMySQLServer(t, func(conn net.Conn) {})
	truncatedGreetingAddr := startFakeMySQLServer(t, func(conn net.Conn) {
		_ = writeMySQLPacket(conn, 0, []byte{0x0a, 'a', 'b', 'c'})
	})

	testCases := []struct {
		name     string
		addr     string
		username string
		password string
		wantErr  error
	}{
		{
			name:     "when_invalid_password_returns_auth_failed",
			addr:     authAddr,
			username: "admin",
			password: "wrongpass",
			wantErr:  ErrAuthFailed,
		},
		{
			name:     "when_invalid_username_returns_auth_failed",
			addr:     authAddr,
			username: "unknown",
			password: "secret",
			wantErr:  ErrAuthFailed,
		},
		{
			name:     "when_host_not_privileged_returns_password_auth_unsupported",
			addr:     hostBlockedAddr,
			username: "root",
			password: "anypass",
			wantErr:  ErrPasswordAuthUnsupported,
		},
		{
			name:     "when_service_is_http_returns_not_mysql_service",
			addr:     httpAddr,
			username: "root",
			password: "root",
			wantErr:  ErrNotMySQLService,
		},
		{
			name:     "when_connection_refused_returns_not_mysql_service",
			addr:     refusedAddr,
			username: "root",
			password: "root",
			wantErr:  ErrNotMySQLService,
		},
		{
			name:     "when_connection_closed_immediately_returns_not_mysql_service",
			addr:     closedImmediatelyAddr,
			username: "root",
			password: "root",
			wantErr:  ErrNotMySQLService,
		},
		{
			name:     "when_malformed_truncated_greeting_packet_returns_not_mysql_service",
			addr:     truncatedGreetingAddr,
			username: "root",
			password: "root",
			wantErr:  ErrNotMySQLService,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			db, err := client.Connect(t.Context(), tc.addr, tc.username, tc.password)
			if db != nil {
				_ = db.Close()
				t.Fatalf("Connect(%q, %q, %q) = non-nil *sql.DB, want nil", tc.addr, tc.username, tc.password)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Connect(%q, %q, %q) error = %v, want %v", tc.addr, tc.username, tc.password, err, tc.wantErr)
			}
		})
	}
}

func TestConnect_ContextCanceledBeforeConnect(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	db, err := New(nil).Connect(ctx, "127.0.0.1:3306", "user", "pass")
	if db != nil {
		_ = db.Close()
		t.Fatal("Connect(canceledCtx, \"127.0.0.1:3306\", \"user\", \"pass\") = non-nil *sql.DB, want nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Connect(canceledCtx, \"127.0.0.1:3306\", \"user\", \"pass\") error = %v, want %v", err, context.Canceled)
	}
}

func TestConnect_ContextDeadlineExceededBeforeConnect(t *testing.T) {
	ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer cancel()

	db, err := New(nil).Connect(ctx, "127.0.0.1:3306", "user", "pass")
	if db != nil {
		_ = db.Close()
		t.Fatal("Connect(expiredCtx, \"127.0.0.1:3306\", \"user\", \"pass\") = non-nil *sql.DB, want nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Connect(expiredCtx, \"127.0.0.1:3306\", \"user\", \"pass\") error = %v, want %v", err, context.DeadlineExceeded)
	}
}

func TestConnect_ContextCanceledDuringConnect(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	addr := startFakeMySQLServer(t, func(conn net.Conn) {
		cancel()
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		var buf [1]byte
		_, _ = conn.Read(buf[:])
	})

	db, err := New(nil).Connect(ctx, addr, "user", "pass")
	if db != nil {
		_ = db.Close()
		t.Fatalf("Connect(ctx, %q, %q, %q) = non-nil *sql.DB, want nil", addr, "user", "pass")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Connect(ctx, %q, %q, %q) error = %v, want %v", addr, "user", "pass", err, context.Canceled)
	}
}

func TestClassifyError(t *testing.T) {
	unrecognizedErr := errors.New("something totally unexpected")

	testCases := []struct {
		name     string
		inputErr error
		wantErr  error
	}{
		{
			name:     "when_nil_error_returns_nil",
			inputErr: nil,
			wantErr:  nil,
		},
		{
			name:     "when_already_err_password_auth_unsupported_returns_same",
			inputErr: ErrPasswordAuthUnsupported,
			wantErr:  ErrPasswordAuthUnsupported,
		},
		{
			name:     "when_already_err_auth_failed_returns_same",
			inputErr: ErrAuthFailed,
			wantErr:  ErrAuthFailed,
		},
		{
			name:     "when_already_err_not_mysql_service_returns_same",
			inputErr: ErrNotMySQLService,
			wantErr:  ErrNotMySQLService,
		},
		{
			name:     "when_context_canceled_returns_same",
			inputErr: context.Canceled,
			wantErr:  context.Canceled,
		},
		{
			name:     "when_context_deadline_exceeded_returns_same",
			inputErr: context.DeadlineExceeded,
			wantErr:  context.DeadlineExceeded,
		},
		{
			name: "when_mysql_error_1045_returns_auth_failed",
			inputErr: &mysql.MySQLError{
				Number:   1045,
				SQLState: [5]byte{'2', '8', '0', '0', '0'},
				Message:  "Access denied for user 'root'@'localhost'",
			},
			wantErr: ErrAuthFailed,
		},
		{
			name: "when_mysql_error_1044_returns_auth_failed",
			inputErr: &mysql.MySQLError{
				Number:  1044,
				Message: "Access denied for user 'root'@'%' to database 'mysql'",
			},
			wantErr: ErrAuthFailed,
		},
		{
			name: "when_mysql_error_1698_returns_auth_failed",
			inputErr: &mysql.MySQLError{
				Number:  1698,
				Message: "Access denied for user 'root'@'localhost'",
			},
			wantErr: ErrAuthFailed,
		},
		{
			name: "when_mysql_error_sqlstate_28000_returns_auth_failed",
			inputErr: &mysql.MySQLError{
				Number:   9999,
				SQLState: [5]byte{'2', '8', '0', '0', '0'},
				Message:  "Custom auth failure",
			},
			wantErr: ErrAuthFailed,
		},
		{
			name: "when_mysql_error_1129_host_blocked_returns_password_auth_unsupported",
			inputErr: &mysql.MySQLError{
				Number:  1129,
				Message: "Host '1.2.3.4' is blocked because of many connection errors",
			},
			wantErr: ErrPasswordAuthUnsupported,
		},
		{
			name: "when_mysql_error_1130_host_not_privileged_returns_password_auth_unsupported",
			inputErr: &mysql.MySQLError{
				Number:  1130,
				Message: "Host '1.2.3.4' is not allowed to connect to this MySQL server",
			},
			wantErr: ErrPasswordAuthUnsupported,
		},
		{
			name: "when_mysql_error_1251_returns_password_auth_unsupported",
			inputErr: &mysql.MySQLError{
				Number:  1251,
				Message: "Client does not support authentication protocol requested by server",
			},
			wantErr: ErrPasswordAuthUnsupported,
		},
		{
			name: "when_mysql_error_1524_returns_password_auth_unsupported",
			inputErr: &mysql.MySQLError{
				Number:  1524,
				Message: "Plugin 'auth_socket' is not loaded",
			},
			wantErr: ErrPasswordAuthUnsupported,
		},
		{
			name:     "when_driver_err_unknown_plugin_returns_password_auth_unsupported",
			inputErr: mysql.ErrUnknownPlugin,
			wantErr:  ErrPasswordAuthUnsupported,
		},
		{
			name:     "when_driver_err_cleartext_password_returns_password_auth_unsupported",
			inputErr: mysql.ErrCleartextPassword,
			wantErr:  ErrPasswordAuthUnsupported,
		},
		{
			name:     "when_driver_err_native_password_returns_password_auth_unsupported",
			inputErr: mysql.ErrNativePassword,
			wantErr:  ErrPasswordAuthUnsupported,
		},
		{
			name:     "when_driver_err_old_password_returns_password_auth_unsupported",
			inputErr: mysql.ErrOldPassword,
			wantErr:  ErrPasswordAuthUnsupported,
		},
		{
			name:     "when_driver_err_malformed_pkt_returns_not_mysql_service",
			inputErr: mysql.ErrMalformPkt,
			wantErr:  ErrNotMySQLService,
		},
		{
			name:     "when_driver_err_old_protocol_returns_not_mysql_service",
			inputErr: mysql.ErrOldProtocol,
			wantErr:  ErrNotMySQLService,
		},
		{
			name:     "when_driver_err_invalid_conn_returns_not_mysql_service",
			inputErr: mysql.ErrInvalidConn,
			wantErr:  ErrNotMySQLService,
		},
		{
			name:     "when_driver_err_pkt_sync_returns_not_mysql_service",
			inputErr: mysql.ErrPktSync,
			wantErr:  ErrNotMySQLService,
		},
		{
			name:     "when_driver_err_pkt_sync_mul_returns_not_mysql_service",
			inputErr: mysql.ErrPktSyncMul,
			wantErr:  ErrNotMySQLService,
		},
		{
			name:     "when_driver_err_no_tls_returns_not_mysql_service",
			inputErr: mysql.ErrNoTLS,
			wantErr:  ErrNotMySQLService,
		},
		{
			name:     "when_io_eof_returns_not_mysql_service",
			inputErr: io.EOF,
			wantErr:  ErrNotMySQLService,
		},
		{
			name:     "when_io_unexpected_eof_returns_not_mysql_service",
			inputErr: io.ErrUnexpectedEOF,
			wantErr:  ErrNotMySQLService,
		},
		{
			name:     "when_access_denied_string_returns_auth_failed",
			inputErr: errors.New("Error 1045: Access denied for user 'root'"),
			wantErr:  ErrAuthFailed,
		},
		{
			name:     "when_not_allowed_to_connect_string_returns_password_auth_unsupported",
			inputErr: errors.New("Host '10.0.0.1' is not allowed to connect to this MySQL server"),
			wantErr:  ErrPasswordAuthUnsupported,
		},
		{
			name:     "when_connection_refused_string_returns_not_mysql_service",
			inputErr: errors.New("dial tcp 127.0.0.1:3306: connect: connection refused"),
			wantErr:  ErrNotMySQLService,
		},
		{
			name:     "when_unsupported_protocol_version_string_returns_not_mysql_service",
			inputErr: errors.New("unsupported protocol version 9. Version 10 or higher is required"),
			wantErr:  ErrNotMySQLService,
		},
		{
			name:     "when_unrecognized_error_returns_verbatim",
			inputErr: unrecognizedErr,
			wantErr:  unrecognizedErr,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyError(tc.inputErr)
			if !errors.Is(got, tc.wantErr) {
				t.Errorf("ClassifyError(%v) = %v, want %v", tc.inputErr, got, tc.wantErr)
			}
			if !errors.Is(got, tc.inputErr) {
				t.Errorf("ClassifyError(%v) = %v, want error wrapping %v", tc.inputErr, got, tc.inputErr)
			}
			for _, sentinel := range []error{ErrAuthFailed, ErrPasswordAuthUnsupported, ErrNotMySQLService} {
				if errors.Is(got, sentinel) != errors.Is(tc.wantErr, sentinel) {
					t.Errorf("ClassifyError(%v) sentinel %v match = %v, want %v (got = %v)", tc.inputErr, sentinel, errors.Is(got, sentinel), errors.Is(tc.wantErr, sentinel), got)
				}
			}
		})
	}
}
