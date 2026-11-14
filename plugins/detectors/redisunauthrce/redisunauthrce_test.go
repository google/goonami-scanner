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

package redisunauthrce

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/module"
	"github.com/google/goonami-scanner/core/net/netendpoint"
	"google.golang.org/protobuf/testing/protocmp"

	cpb "github.com/google/goonami-scanner/core/config/config_go_proto"
	dpb "github.com/google/tsunami-security-scanner/proto/go/detection_go_proto"
	npb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
	vpb "github.com/google/tsunami-security-scanner/proto/go/vulnerability_go_proto"
)

const validServerInfoBody = "# Server\r\nredis_version:7.4.12\r\nredis_mode:standalone\r\nos:Linux 6.6\r\narch_bits:64\r\ntcp_port:6379\r\n"

var validServerInfoBulk = fmt.Sprintf("$%d\r\n%s\r\n", len(validServerInfoBody), validServerInfoBody)

func TestNewAndRegistration(t *testing.T) {
	tests := []struct {
		name        string
		cfg         *config.Config
		wantTimeout time.Duration
	}{
		{
			name:        "when_nil_config_uses_default_timeout",
			cfg:         nil,
			wantTimeout: defaultTimeout,
		},
		{
			name:        "when_default_config_uses_configured_timeout",
			cfg:         config.Default(),
			wantTimeout: 10 * time.Second,
		},
		{
			name: "when_zero_timeout_config_uses_default_timeout",
			cfg: config.FromProto(cpb.Config_builder{
				Globalcfg: cpb.GlobalConfig_builder{
					Performance: cpb.GlobalConfig_Performance_builder{
						TimeoutPerRequestSeconds: new(int32(0)),
					}.Build(),
				}.Build(),
			}.Build()),
			wantTimeout: defaultTimeout,
		},
		{
			name: "when_custom_timeout_config_uses_custom_timeout",
			cfg: config.FromProto(cpb.Config_builder{
				Globalcfg: cpb.GlobalConfig_builder{
					Performance: cpb.GlobalConfig_Performance_builder{
						TimeoutPerRequestSeconds: new(int32(2)),
					}.Build(),
				}.Build(),
			}.Build()),
			wantTimeout: 2 * time.Second,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			det, err := New(t.Context(), tc.cfg)
			if err != nil {
				t.Fatalf("New(%v) unexpected error: %v", tc.cfg, err)
			}
			if got := det.Name(); got != moduleName {
				t.Errorf("det.Name() = %q, want %q", got, moduleName)
			}
			mod := det.(*Module)
			if mod.timeout != tc.wantTimeout {
				t.Errorf("New(%v).timeout = %v, want %v", tc.cfg, mod.timeout, tc.wantTimeout)
			}
		})
	}

	allDetectors, err := module.AllDetectors(t.Context(), config.Default())
	if err != nil {
		t.Fatalf("module.AllDetectors() unexpected error: %v", err)
	}
	registered := false
	for _, dt := range allDetectors {
		if dt.Name() == moduleName {
			registered = true
			break
		}
	}
	if !registered {
		t.Errorf("module.AllDetectors() registered %q = false, want true", moduleName)
	}
}

func TestAdvisories(t *testing.T) {
	want := []*vpb.Vulnerability{
		vpb.Vulnerability_builder{
			MainId: vpb.VulnerabilityId_builder{
				Publisher: "GOOGLE",
				Value:     "REDIS_UNAUTHENTICATED_COMMAND_EXECUTION",
			}.Build(),
			Severity:       vpb.Severity_CRITICAL,
			Title:          "Redis unauthenticated command execution",
			Description:    vulnDescription,
			Recommendation: vulnRecommendation,
		}.Build(),
	}

	det, err := New(t.Context(), config.Default())
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}
	mod := det.(*Module)

	got := mod.Advisories()
	if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
		t.Errorf("Advisories() diff (-want +got):\n%s", diff)
	}

	got[0].SetTitle("mutated")
	second := mod.Advisories()
	if gotTitle := second[0].GetTitle(); gotTitle == "mutated" {
		t.Errorf("Advisories()[0].GetTitle() after mutation = %q, want isolated copy", gotTitle)
	}
}

func readClientCommand(r *bufio.Reader) ([]string, error) {
	prefix, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	if prefix != '*' {
		return nil, fmt.Errorf("unexpected prefix %q", prefix)
	}
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	argc, err := strconv.Atoi(strings.TrimSuffix(line, "\r\n"))
	if err != nil {
		return nil, err
	}
	args := make([]string, 0, argc)
	for range argc {
		if _, err := r.ReadByte(); err != nil {
			return nil, err
		}
		lenLine, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		n, err := strconv.Atoi(strings.TrimSuffix(lenLine, "\r\n"))
		if err != nil {
			return nil, err
		}
		buf := make([]byte, n+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		args = append(args, string(buf[:n]))
	}
	return args, nil
}

func startFakeRESPServer(t *testing.T, useTLS bool, handler func(cmd []string, w io.Writer) bool) *nspb.NetworkService {
	t.Helper()
	var ln net.Listener
	var err error
	var sslVersions []string

	if useTLS {
		donor := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		donor.StartTLS()
		cert := donor.TLS.Certificates[0]
		donor.Close()
		ln, err = tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
			Certificates: []tls.Certificate{cert},
		})
		sslVersions = []string{"TLSv1.3"}
	} else {
		ln, err = net.Listen("tcp", "127.0.0.1:0")
	}
	if err != nil {
		t.Fatalf("Listen() failed: %v", err)
	}

	done := make(chan struct{})
	t.Cleanup(func() {
		_ = ln.Close()
		<-done
	})

	go func() {
		defer close(done)
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				br := bufio.NewReader(c)
				for {
					cmd, readErr := readClientCommand(br)
					if readErr != nil {
						return
					}
					if !handler(cmd, c) {
						return
					}
				}
			}(conn)
		}
	}()

	host, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort() failed: %v", err)
	}
	portNum, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("Atoi() failed: %v", err)
	}

	return nspb.NetworkService_builder{
		ServiceName:          "redis",
		TransportProtocol:    npb.TransportProtocol_TCP,
		SupportedSslVersions: sslVersions,
		NetworkEndpoint: npb.NetworkEndpoint_builder{
			Type: npb.NetworkEndpoint_IP_PORT,
			IpAddress: npb.IpAddress_builder{
				Address:       host,
				AddressFamily: npb.AddressFamily_IPV4,
			}.Build(),
			Port: npb.Port_builder{
				PortNumber: uint32(portNum),
			}.Build(),
		}.Build(),
	}.Build()
}

func TestDetect(t *testing.T) {
	tests := []struct {
		name         string
		useTLS       bool
		replies      map[string]string
		unknownReply string
		wantFindings bool
	}{
		{
			name:   "when_unauthenticated_redis_allows_eval_returns_verified_finding",
			useTLS: false,
			replies: map[string]string{
				"INFO": validServerInfoBulk,
				"EVAL": ":950521\r\n",
			},
			unknownReply: "-ERR unknown command\r\n",
			wantFindings: true,
		},
		{
			name:   "when_tls_redis_allows_unauthenticated_eval_returns_verified_finding",
			useTLS: true,
			replies: map[string]string{
				"INFO": validServerInfoBulk,
				"EVAL": ":950521\r\n",
			},
			unknownReply: "-ERR unknown command\r\n",
			wantFindings: true,
		},
		{
			name:   "when_eval_disabled_but_config_get_dir_succeeds_returns_verified_finding",
			useTLS: false,
			replies: map[string]string{
				"INFO":   validServerInfoBulk,
				"EVAL":   "-ERR unknown command 'EVAL'\r\n",
				"CONFIG": "*2\r\n$3\r\ndir\r\n$5\r\n/data\r\n",
			},
			unknownReply: "-ERR unknown command\r\n",
			wantFindings: true,
		},
		{
			name:   "when_eval_and_config_renamed_but_dbsize_and_role_succeed_returns_verified_finding",
			useTLS: false,
			replies: map[string]string{
				"INFO":   validServerInfoBulk,
				"EVAL":   "-ERR unknown command 'EVAL'\r\n",
				"CONFIG": "-ERR unknown command 'CONFIG'\r\n",
				"DBSIZE": ":12\r\n",
				"ROLE":   "*3\r\n$6\r\nmaster\r\n:0\r\n*0\r\n",
			},
			unknownReply: "-ERR unknown command\r\n",
			wantFindings: true,
		},
		{
			name:   "when_password_required_returns_noauth_and_no_findings",
			useTLS: false,
			replies: map[string]string{
				"INFO": "-NOAUTH Authentication required.\r\n",
			},
			unknownReply: "-NOAUTH Authentication required.\r\n",
			wantFindings: false,
		},
		{
			name:   "when_protected_mode_enabled_returns_denied_and_no_findings",
			useTLS: false,
			replies: map[string]string{
				"INFO": "-DENIED Redis is running in protected mode\r\n",
			},
			unknownReply: "-DENIED Redis is running in protected mode\r\n",
			wantFindings: false,
		},
		{
			name:   "when_monitoring_acl_allows_only_info_and_blocks_commands_returns_no_findings",
			useTLS: false,
			replies: map[string]string{
				"INFO":   validServerInfoBulk,
				"EVAL":   "-NOPERM no permissions to run 'eval'\r\n",
				"CONFIG": "-NOPERM no permissions to run 'config'\r\n",
				"DBSIZE": "-NOPERM no permissions to run 'dbsize'\r\n",
			},
			unknownReply: "-NOPERM unknown command\r\n",
			wantFindings: false,
		},
		{
			name:   "when_accept_all_honeypot_returns_ok_for_unknown_command_returns_no_findings",
			useTLS: false,
			replies: map[string]string{
				"INFO": validServerInfoBulk,
				"EVAL": ":950521\r\n",
			},
			unknownReply: "+OK\r\n",
			wantFindings: false,
		},
		{
			name:   "when_static_banner_server_replays_info_for_unknown_command_returns_no_findings",
			useTLS: false,
			replies: map[string]string{
				"INFO": validServerInfoBulk,
			},
			unknownReply: validServerInfoBulk,
			wantFindings: false,
		},
		{
			name:   "when_unknown_command_returns_noauth_returns_no_findings",
			useTLS: false,
			replies: map[string]string{
				"INFO": validServerInfoBulk,
			},
			unknownReply: "-NOAUTH Authentication required.\r\n",
			wantFindings: false,
		},
		{
			name:   "when_unknown_command_returns_denied_returns_no_findings",
			useTLS: false,
			replies: map[string]string{
				"INFO": validServerInfoBulk,
			},
			unknownReply: "-DENIED protected mode\r\n",
			wantFindings: false,
		},
		{
			name:   "when_eval_returns_wrong_product_returns_no_findings",
			useTLS: false,
			replies: map[string]string{
				"INFO": validServerInfoBulk,
				"EVAL": ":42\r\n",
			},
			unknownReply: "-ERR unknown command\r\n",
			wantFindings: false,
		},
		{
			name:   "when_config_get_dir_returns_empty_array_falls_back_to_dbsize_and_role",
			useTLS: false,
			replies: map[string]string{
				"INFO":   validServerInfoBulk,
				"EVAL":   "-ERR unknown command 'EVAL'\r\n",
				"CONFIG": "*0\r\n",
				"DBSIZE": ":7\r\n",
				"ROLE":   "*3\r\n$6\r\nmaster\r\n:0\r\n*0\r\n",
			},
			unknownReply: "-ERR unknown command\r\n",
			wantFindings: true,
		},
		{
			name:   "when_config_get_returns_unexpected_key_and_dbsize_denied_returns_no_findings",
			useTLS: false,
			replies: map[string]string{
				"INFO":   validServerInfoBulk,
				"EVAL":   "-ERR unknown command\r\n",
				"CONFIG": "*2\r\n$5\r\nother\r\n$5\r\n/data\r\n",
				"DBSIZE": "-NOPERM dbsize denied\r\n",
			},
			unknownReply: "-ERR unknown command\r\n",
			wantFindings: false,
		},
		{
			name:   "when_config_get_returns_single_element_array_and_dbsize_denied_returns_no_findings",
			useTLS: false,
			replies: map[string]string{
				"INFO":   validServerInfoBulk,
				"EVAL":   "-ERR unknown command\r\n",
				"CONFIG": "*1\r\n$3\r\ndir\r\n",
				"DBSIZE": "-NOPERM dbsize denied\r\n",
			},
			unknownReply: "-ERR unknown command\r\n",
			wantFindings: false,
		},
		{
			name:   "when_dbsize_returns_negative_integer_returns_no_findings",
			useTLS: false,
			replies: map[string]string{
				"INFO":   validServerInfoBulk,
				"EVAL":   "-ERR unknown command\r\n",
				"CONFIG": "-ERR unknown command\r\n",
				"DBSIZE": ":-1\r\n",
			},
			unknownReply: "-ERR unknown command\r\n",
			wantFindings: false,
		},
		{
			name:   "when_role_returns_noperm_returns_no_findings",
			useTLS: false,
			replies: map[string]string{
				"INFO":   validServerInfoBulk,
				"EVAL":   "-ERR unknown command\r\n",
				"CONFIG": "-ERR unknown command\r\n",
				"DBSIZE": ":0\r\n",
				"ROLE":   "-NOPERM role denied\r\n",
			},
			unknownReply: "-ERR unknown command\r\n",
			wantFindings: false,
		},
		{
			name:   "when_non_redis_banner_returned_returns_no_findings",
			useTLS: false,
			replies: map[string]string{
				"INFO": "HTTP/1.1 400 Bad Request\r\n\r\n",
			},
			unknownReply: "HTTP/1.1 400 Bad Request\r\n\r\n",
			wantFindings: false,
		},
		{
			name:   "when_info_bulk_string_lacks_runtime_fields_returns_no_findings",
			useTLS: false,
			replies: map[string]string{
				"INFO": "$20\r\nredis_version:7.4.0\n\r\n",
			},
			unknownReply: "-ERR unknown\r\n",
			wantFindings: false,
		},
		{
			name:   "when_eval_returns_malformed_resp_type_returns_no_findings",
			useTLS: false,
			replies: map[string]string{
				"INFO": validServerInfoBulk,
				"EVAL": "+PONG\r\n",
			},
			unknownReply: "-ERR unknown\r\n",
			wantFindings: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc := startFakeRESPServer(t, tc.useTLS, func(cmd []string, w io.Writer) bool {
				if len(cmd) == 0 {
					return false
				}
				upper := strings.ToUpper(cmd[0])
				if reply, ok := tc.replies[upper]; ok {
					_, _ = io.WriteString(w, reply)
					return true
				}
				_, _ = io.WriteString(w, tc.unknownReply)
				return true
			})

			det, err := New(t.Context(), config.Default())
			if err != nil {
				t.Fatalf("New() unexpected error: %v", err)
			}

			reports, err := det.Detect(t.Context(), svc)
			if err != nil {
				t.Fatalf("Detect(%v) unexpected error: %v", svc, err)
			}
			gotFindings := len(reports.GetDetectionReports()) > 0
			if gotFindings != tc.wantFindings {
				t.Fatalf("Detect(%v) findings = %v, want %v", svc, gotFindings, tc.wantFindings)
			}
			if tc.wantFindings {
				rep := reports.GetDetectionReports()[0]
				if got := rep.GetDetectionStatus(); got != dpb.DetectionStatus_VULNERABILITY_VERIFIED {
					t.Errorf("rep.GetDetectionStatus() = %v, want %v", got, dpb.DetectionStatus_VULNERABILITY_VERIFIED)
				}
				if got := rep.GetVulnerability().GetMainId().GetValue(); got != "REDIS_UNAUTHENTICATED_COMMAND_EXECUTION" {
					t.Errorf("MainId.GetValue() = %q, want %q", got, "REDIS_UNAUTHENTICATED_COMMAND_EXECUTION")
				}
				if len(rep.GetVulnerability().GetAdditionalDetails()) == 0 {
					t.Errorf("AdditionalDetails = empty, want non-empty")
				}
			}
		})
	}
}

func TestDetect_ServiceFilteringAndErrors(t *testing.T) {
	liveSvc := startFakeRESPServer(t, false, func(cmd []string, w io.Writer) bool {
		if len(cmd) > 0 && strings.EqualFold(cmd[0], "INFO") {
			_, _ = io.WriteString(w, validServerInfoBulk)
			return true
		}
		if len(cmd) > 0 && strings.EqualFold(cmd[0], "EVAL") {
			_, _ = io.WriteString(w, ":950521\r\n")
			return true
		}
		_, _ = io.WriteString(w, "-ERR unknown\r\n")
		return true
	})

	det, err := New(t.Context(), config.Default())
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}

	// 1. Web service with SupportedHttpMethods must be skipped even if pointing at live Redis.
	webSvc := nspb.NetworkService_builder{
		ServiceName:          "redis",
		TransportProtocol:    npb.TransportProtocol_TCP,
		SupportedHttpMethods: []string{"GET"},
		NetworkEndpoint:      liveSvc.GetNetworkEndpoint(),
	}.Build()
	if reports, err := det.Detect(t.Context(), webSvc); err != nil || reports != nil {
		t.Errorf("Detect(webSvc) = (%v, %v), want (nil, nil)", reports, err)
	}

	// 2. UDP service must be skipped even if pointing at live port.
	udpSvc := nspb.NetworkService_builder{
		ServiceName:       "redis",
		TransportProtocol: npb.TransportProtocol_UDP,
		NetworkEndpoint:   liveSvc.GetNetworkEndpoint(),
	}.Build()
	if reports, err := det.Detect(t.Context(), udpSvc); err != nil || reports != nil {
		t.Errorf("Detect(udpSvc) = (%v, %v), want (nil, nil)", reports, err)
	}

	// 3. Unspecified transport protocol with short context deadline is treated as candidate TCP.
	shortCtx, shortCancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer shortCancel()
	unspecSvc := nspb.NetworkService_builder{
		ServiceName:       "unknown",
		TransportProtocol: npb.TransportProtocol_TRANSPORT_PROTOCOL_UNSPECIFIED,
		NetworkEndpoint:   liveSvc.GetNetworkEndpoint(),
	}.Build()
	if reports, err := det.Detect(shortCtx, unspecSvc); err != nil || len(reports.GetDetectionReports()) != 1 {
		t.Errorf("Detect(unspecSvc) = (%v, %v), want 1 finding and nil error", reports, err)
	}

	// 4. Missing endpoint returns error.
	badEndpointSvc := nspb.NetworkService_builder{
		ServiceName:     "redis",
		NetworkEndpoint: &npb.NetworkEndpoint{},
	}.Build()
	if _, err := det.Detect(t.Context(), badEndpointSvc); !errors.Is(err, netendpoint.ErrEndpointMissingAddress) {
		t.Errorf("Detect(badEndpointSvc) error = %v, want %v", err, netendpoint.ErrEndpointMissingAddress)
	}

	// 5. Canceled context before Detect returns context.Canceled.
	canceledCtx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := det.Detect(canceledCtx, liveSvc); !errors.Is(err, context.Canceled) {
		t.Errorf("Detect(canceledCtx) error = %v, want %v", err, context.Canceled)
	}

	// 6. Closed TCP port returns (nil, nil) when context is active.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() failed: %v", err)
	}
	closedPort := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	closedSvc := nspb.NetworkService_builder{
		ServiceName: "redis",
		NetworkEndpoint: npb.NetworkEndpoint_builder{
			Type:      npb.NetworkEndpoint_IP_PORT,
			IpAddress: npb.IpAddress_builder{Address: "127.0.0.1", AddressFamily: npb.AddressFamily_IPV4}.Build(),
			Port:      npb.Port_builder{PortNumber: uint32(closedPort)}.Build(),
		}.Build(),
	}.Build()
	if reports, err := det.Detect(t.Context(), closedSvc); err != nil || reports != nil {
		t.Errorf("Detect(closedSvc) = (%v, %v), want (nil, nil)", reports, err)
	}

	// 7. Raw TCP byte-echo server reflecting sent bytes returns (nil, nil).
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() failed: %v", err)
	}
	echoDone := make(chan struct{})
	t.Cleanup(func() {
		_ = echoLn.Close()
		<-echoDone
	})
	go func() {
		defer close(echoDone)
		for {
			c, acceptErr := echoLn.Accept()
			if acceptErr != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()
	echoPort := echoLn.Addr().(*net.TCPAddr).Port
	echoSvc := nspb.NetworkService_builder{
		ServiceName: "redis",
		NetworkEndpoint: npb.NetworkEndpoint_builder{
			Type:      npb.NetworkEndpoint_IP_PORT,
			IpAddress: npb.IpAddress_builder{Address: "127.0.0.1", AddressFamily: npb.AddressFamily_IPV4}.Build(),
			Port:      npb.Port_builder{PortNumber: uint32(echoPort)}.Build(),
		}.Build(),
	}.Build()
	if reports, err := det.Detect(t.Context(), echoSvc); err != nil || reports != nil {
		t.Errorf("Detect(echoSvc) = (%v, %v), want (nil, nil)", reports, err)
	}
}

func TestDetect_MidSessionContextCancellation(t *testing.T) {
	tests := []struct {
		name       string
		cancelOnOp int
	}{
		{name: "when_canceled_during_info_returns_error", cancelOnOp: 1},
		{name: "when_canceled_during_unknown_cmd_returns_error", cancelOnOp: 2},
		{name: "when_canceled_during_eval_returns_error", cancelOnOp: 3},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			opCount := 0
			svc := startFakeRESPServer(t, false, func(cmd []string, w io.Writer) bool {
				opCount++
				if opCount == tc.cancelOnOp {
					cancel()
					return false
				}
				if len(cmd) > 0 && strings.EqualFold(cmd[0], "INFO") {
					_, _ = io.WriteString(w, validServerInfoBulk)
					return true
				}
				_, _ = io.WriteString(w, "-ERR unknown\r\n")
				return true
			})

			det, err := New(t.Context(), config.Default())
			if err != nil {
				t.Fatalf("New() unexpected error: %v", err)
			}
			if _, err := det.Detect(ctx, svc); !errors.Is(err, context.Canceled) {
				t.Errorf("Detect() on step %d cancellation error = %v, want %v", tc.cancelOnOp, err, context.Canceled)
			}
		})
	}
}

func TestParseRedisServerInfo(t *testing.T) {
	tests := []struct {
		name        string
		info        string
		wantVersion string
		wantOK      bool
	}{
		{
			name:        "when_redis_version_and_os_present_returns_true",
			info:        "# Server\r\nredis_version:7.4.12\r\nos:Linux\r\n",
			wantVersion: "7.4.12",
			wantOK:      true,
		},
		{
			name:        "when_valkey_version_and_server_mode_present_returns_true",
			info:        "# Server\r\nvalkey_version:8.0.1\r\nserver_mode:standalone\r\n",
			wantVersion: "8.0.1",
			wantOK:      true,
		},
		{
			name:        "when_duplicate_version_lines_preserves_first_version",
			info:        "redis_version:7.2.0\r\nvalkey_version:8.0.0\r\ntcp_port:6379\r\n",
			wantVersion: "7.2.0",
			wantOK:      true,
		},
		{
			name:        "when_process_id_present_returns_true",
			info:        "redis_version:6.2.14\nprocess_id:42\n",
			wantVersion: "6.2.14",
			wantOK:      true,
		},
		{
			name:        "when_arch_bits_present_returns_true",
			info:        "redis_version:6.2.14\r\narch_bits:64\r\n",
			wantVersion: "6.2.14",
			wantOK:      true,
		},
		{
			name:   "when_missing_version_returns_false",
			info:   "# Server\r\nos:Linux\r\ntcp_port:6379\r\n",
			wantOK: false,
		},
		{
			name:   "when_empty_version_value_returns_false",
			info:   "redis_version:\r\nos:Linux\r\n",
			wantOK: false,
		},
		{
			name:   "when_missing_runtime_field_returns_false",
			info:   "redis_version:7.4.12\r\n",
			wantOK: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotVer, gotOK := parseRedisServerInfo(tc.info)
			if gotVer != tc.wantVersion || gotOK != tc.wantOK {
				t.Errorf("parseRedisServerInfo(%q) = (%q, %v), want (%q, %v)", tc.info, gotVer, gotOK, tc.wantVersion, tc.wantOK)
			}
		})
	}
}

func TestRESPParsers(t *testing.T) {
	bulkTests := []struct {
		name    string
		raw     string
		want    string
		wantErr error
	}{
		{
			name: "when_valid_bulk_string_returns_payload",
			raw:  "$5\r\nhello\r\n",
			want: "hello",
		},
		{
			name: "when_valid_resp3_verbatim_string_strips_encoding_prefix",
			raw:  "=9\r\ntxt:hello\r\n",
			want: "hello",
		},
		{
			name:    "when_resp_error_returns_command_error",
			raw:     "-NOAUTH Authentication required.\r\n",
			wantErr: errRESPCommand,
		},
		{
			name:    "when_wrong_type_prefix_returns_invalid_resp",
			raw:     "+OK\r\n",
			wantErr: errInvalidRESP,
		},
		{
			name:    "when_negative_length_returns_invalid_resp",
			raw:     "$-1\r\n",
			wantErr: errInvalidRESP,
		},
		{
			name:    "when_oversized_length_returns_invalid_resp",
			raw:     fmt.Sprintf("$%d\r\n", maxRESPBulkBytes+1),
			wantErr: errInvalidRESP,
		},
		{
			name:    "when_missing_crlf_terminator_returns_invalid_resp",
			raw:     "$5\r\nhelloXX",
			wantErr: errInvalidRESP,
		},
		{
			name:    "when_lf_without_cr_in_header_returns_invalid_resp",
			raw:     "$5\nhello\r\n",
			wantErr: errInvalidRESP,
		},
		{
			name:    "when_line_exceeds_max_length_returns_invalid_resp",
			raw:     "$" + strings.Repeat("9", maxRESPLineBytes+5) + "\r\n",
			wantErr: errInvalidRESP,
		},
	}

	for _, tc := range bulkTests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := readRESPBulkOrVerbatimString(bufio.NewReader(strings.NewReader(tc.raw)))
			if !errors.Is(err, tc.wantErr) || got != tc.want {
				t.Errorf("readRESPBulkOrVerbatimString(%q) = (%q, %v), want (%q, %v)", tc.raw, got, err, tc.want, tc.wantErr)
			}
		})
	}

	intTests := []struct {
		name    string
		raw     string
		want    int64
		wantErr error
	}{
		{name: "when_valid_integer_returns_value", raw: ":950521\r\n", want: 950521},
		{name: "when_resp_error_returns_command_error", raw: "-ERR\r\n", wantErr: errRESPCommand},
		{name: "when_non_integer_prefix_returns_invalid_resp", raw: "+950521\r\n", wantErr: errInvalidRESP},
		{name: "when_malformed_integer_returns_invalid_resp", raw: ":notanint\r\n", wantErr: errInvalidRESP},
	}
	for _, tc := range intTests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := readRESPInteger(bufio.NewReader(strings.NewReader(tc.raw)))
			if !errors.Is(err, tc.wantErr) || got != tc.want {
				t.Errorf("readRESPInteger(%q) = (%d, %v), want (%d, %v)", tc.raw, got, err, tc.want, tc.wantErr)
			}
		})
	}

	arrTests := []struct {
		name    string
		raw     string
		want    []string
		wantErr error
	}{
		{name: "when_valid_two_element_array_returns_slice", raw: "*2\r\n$3\r\ndir\r\n$4\r\n/tmp\r\n", want: []string{"dir", "/tmp"}},
		{name: "when_resp_error_returns_command_error", raw: "-NOPERM\r\n", wantErr: errRESPCommand},
		{name: "when_wrong_prefix_returns_invalid_resp", raw: "$3\r\ndir\r\n", wantErr: errInvalidRESP},
		{name: "when_negative_count_returns_invalid_resp", raw: "*-1\r\n", wantErr: errInvalidRESP},
		{name: "when_oversized_count_returns_invalid_resp", raw: fmt.Sprintf("*%d\r\n", maxRESPArrayLen+1), wantErr: errInvalidRESP},
		{name: "when_element_invalid_returns_error", raw: "*1\r\n+notbulk\r\n", wantErr: errInvalidRESP},
	}
	for _, tc := range arrTests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := readRESPStringArray(bufio.NewReader(strings.NewReader(tc.raw)))
			if !errors.Is(err, tc.wantErr) || !cmp.Equal(got, tc.want) {
				t.Errorf("readRESPStringArray(%q) = (%v, %v), want (%v, %v)", tc.raw, got, err, tc.want, tc.wantErr)
			}
		})
	}

	roleTests := []struct {
		name    string
		raw     string
		want    string
		wantErr error
	}{
		{name: "when_master_role_returns_master", raw: "*3\r\n$6\r\nmaster\r\n:0\r\n*0\r\n", want: "master"},
		{name: "when_slave_role_returns_slave", raw: "*5\r\n$5\r\nslave\r\n", want: "slave"},
		{name: "when_sentinel_role_returns_sentinel", raw: "*2\r\n$8\r\nsentinel\r\n", want: "sentinel"},
		{name: "when_unknown_role_returns_invalid_resp", raw: "*1\r\n$8\r\nobserver\r\n", wantErr: errInvalidRESP},
		{name: "when_empty_array_returns_invalid_resp", raw: "*0\r\n", wantErr: errInvalidRESP},
		{name: "when_oversized_array_returns_invalid_resp", raw: fmt.Sprintf("*%d\r\n", maxRESPArrayLen+1), wantErr: errInvalidRESP},
		{name: "when_wrong_prefix_returns_invalid_resp", raw: "+master\r\n", wantErr: errInvalidRESP},
		{name: "when_resp_error_returns_command_error", raw: "-ERR\r\n", wantErr: errRESPCommand},
	}
	for _, tc := range roleTests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := readRESPRole(bufio.NewReader(strings.NewReader(tc.raw)))
			if !errors.Is(err, tc.wantErr) || got != tc.want {
				t.Errorf("readRESPRole(%q) = (%q, %v), want (%q, %v)", tc.raw, got, err, tc.want, tc.wantErr)
			}
		})
	}

	// Verify verifyActiveCommandExecution handles non-command protocol errors on fallbacks.
	var out bytes.Buffer
	_, ok, err := verifyActiveCommandExecution(&out, bufio.NewReader(strings.NewReader("+NOT_INT\r\n")))
	if err == nil || ok {
		t.Errorf("verifyActiveCommandExecution(non-int EVAL) = (%v, %v), want (false, error)", ok, err)
	}
	out.Reset()
	_, ok, err = verifyActiveCommandExecution(&out, bufio.NewReader(strings.NewReader("-ERR\r\n+NOT_ARRAY\r\n")))
	if err == nil || ok {
		t.Errorf("verifyActiveCommandExecution(non-array CONFIG) = (%v, %v), want (false, error)", ok, err)
	}
	out.Reset()
	_, ok, err = verifyActiveCommandExecution(&out, bufio.NewReader(strings.NewReader("-ERR\r\n-ERR\r\n+NOT_INT\r\n")))
	if err == nil || ok {
		t.Errorf("verifyActiveCommandExecution(non-int DBSIZE) = (%v, %v), want (false, error)", ok, err)
	}
	out.Reset()
	_, ok, err = verifyActiveCommandExecution(&out, bufio.NewReader(strings.NewReader("-ERR\r\n-ERR\r\n:1\r\n+NOT_ROLE\r\n")))
	if err == nil || ok {
		t.Errorf("verifyActiveCommandExecution(non-array ROLE) = (%v, %v), want (false, error)", ok, err)
	}
}
