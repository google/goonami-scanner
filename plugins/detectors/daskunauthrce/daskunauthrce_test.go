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

package daskunauthrce

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/module"
	"github.com/google/goonami-scanner/core/net/netendpoint"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"

	cpb "github.com/google/goonami-scanner/core/config/config_go_proto"
	dpb "github.com/google/tsunami-security-scanner/proto/go/detection_go_proto"
	npb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
	vpb "github.com/google/tsunami-security-scanner/proto/go/vulnerability_go_proto"
)

func TestAllDetectorsRegistration(t *testing.T) {
	tests := []struct {
		name     string
		wantName string
	}{
		{
			name:     "when_package_imported_registers_daskunauthrce_detector",
			wantName: moduleName,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			detectors, err := module.AllDetectors(t.Context(), config.Default())
			if err != nil {
				t.Fatalf("module.AllDetectors() unexpected error: %v", err)
			}

			var found module.VulnDetector
			for _, d := range detectors {
				if d.Name() == tc.wantName {
					found = d
					break
				}
			}
			if found == nil {
				t.Fatalf("module.AllDetectors() did not contain %q", tc.wantName)
			}
			if got := len(found.Advisories()); got != 1 {
				t.Errorf("len(found.Advisories()) = %d, want 1", got)
			}
		})
	}
}

func TestNew(t *testing.T) {
	tests := []struct {
		name        string
		cfg         *config.Config
		wantTimeout time.Duration
	}{
		{
			name:        "when_default_config_uses_proto_default_timeout",
			cfg:         config.Default(),
			wantTimeout: 10 * time.Second,
		},
		{
			name: "when_custom_timeout_configured_applies_timeout",
			cfg: config.FromProto(cpb.Config_builder{
				Globalcfg: cpb.GlobalConfig_builder{
					Performance: cpb.GlobalConfig_Performance_builder{
						TimeoutPerRequestSeconds: proto.Int32(15),
					}.Build(),
				}.Build(),
			}.Build()),
			wantTimeout: 15 * time.Second,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			detector, err := New(t.Context(), tc.cfg)
			if err != nil {
				t.Fatalf("New() unexpected error: %v", err)
			}
			if detector == nil {
				t.Fatal("New() = nil, want non-nil detector")
			}
			if got := detector.Name(); got != moduleName {
				t.Errorf("detector.Name() = %q, want %q", got, moduleName)
			}
			mod := detector.(*Module)
			if got := mod.config.TimeoutPerRequest(); got != tc.wantTimeout {
				t.Errorf("mod.config.TimeoutPerRequest() = %v, want %v", got, tc.wantTimeout)
			}
			a, b, err := mod.operandGenFn()
			if err != nil {
				t.Fatalf("operandGenFn() unexpected error: %v", err)
			}
			if a < minProbeOperand || a >= minProbeOperand+operandSpan {
				t.Errorf("operand a = %d, want in [%d, %d)", a, minProbeOperand, minProbeOperand+operandSpan)
			}
			if b < minProbeOperand || b >= minProbeOperand+operandSpan {
				t.Errorf("operand b = %d, want in [%d, %d)", b, minProbeOperand, minProbeOperand+operandSpan)
			}
		})
	}
}

func TestAdvisories(t *testing.T) {
	want := []*vpb.Vulnerability{
		vpb.Vulnerability_builder{
			MainId: vpb.VulnerabilityId_builder{
				Publisher: vulnPublisher,
				Value:     vulnID,
			}.Build(),
			Severity:       vpb.Severity_CRITICAL,
			Title:          vulnTitle,
			Description:    vulnDescription,
			Recommendation: vulnRecommendation,
		}.Build(),
	}

	tests := []struct {
		name string
	}{
		{
			name: "when_initialized_returns_isolated_critical_dask_advisory",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			detector, err := New(t.Context(), config.Default())
			if err != nil {
				t.Fatalf("New() unexpected error: %v", err)
			}

			got := detector.Advisories()
			if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
				t.Errorf("Advisories() mismatch (-want +got):\n%s", diff)
			}

			got[0].SetTitle("mutated")
			if second := detector.Advisories(); second[0].GetTitle() == "mutated" {
				t.Errorf("Advisories()[0].GetTitle() = %q, want isolated clone %q", second[0].GetTitle(), vulnTitle)
			}
		})
	}
}

func TestDetect_VulnerableEndpoints(t *testing.T) {
	tests := []struct {
		name               string
		behavior           fakeDaskBehavior
		useWS              bool
		useTLS             bool
		transport          npb.TransportProtocol
		serviceName        string
		httpMethods        []string
		sslVersions        []string
		fixedOperands      *[2]int32
		wantExactEvidence  bool
		wantEvidenceSubstr []string
		wantWSPath         string
	}{
		{
			name: "when_scheduler_allows_run_function_on_custom_port_returns_finding",
			behavior: fakeDaskBehavior{
				daemonType:     "Scheduler",
				daemonID:       "Scheduler-tcp-1",
				resultEncoding: "pickled_map",
			},
			transport:         npb.TransportProtocol_TCP,
			serviceName:       "unknown",
			fixedOperands:     &[2]int32{12345678, 23456789},
			wantExactEvidence: true,
		},
		{
			name: "when_transport_protocol_unspecified_and_scheduler_allows_broadcast_run_returns_finding",
			behavior: fakeDaskBehavior{
				daemonType:       "Scheduler",
				daemonID:         "Scheduler-bcast-1",
				blockRunFunction: true,
				resultEncoding:   "direct_int",
			},
			transport:          npb.TransportProtocol_TRANSPORT_PROTOCOL_UNSPECIFIED,
			wantEvidenceSubstr: []string{"Scheduler (Scheduler-bcast-1)", "via broadcast(run) RPC handler"},
		},
		{
			name: "when_worker_allows_run_with_serialized_subframe_returns_finding",
			behavior: fakeDaskBehavior{
				daemonType:     "Worker",
				daemonID:       "Worker-cuda-0",
				resultEncoding: "serialized_subframe",
			},
			transport:          npb.TransportProtocol_TCP,
			serviceName:        "custom-worker-svc",
			wantEvidenceSubstr: []string{"Worker (Worker-cuda-0)", "via run RPC handler"},
		},
		{
			name: "when_tls_comm_service_identified_by_supported_ssl_versions_allows_run_function_returns_finding",
			behavior: fakeDaskBehavior{
				daemonType:     "Scheduler",
				daemonID:       "Scheduler-tls-versions",
				resultEncoding: "raw_pickle",
			},
			useTLS:             true,
			transport:          npb.TransportProtocol_TCP,
			serviceName:        "unknown",
			sslVersions:        []string{"TLSv1.3"},
			wantEvidenceSubstr: []string{"Scheduler (Scheduler-tls-versions)", "via run_function RPC handler"},
		},
		{
			name: "when_web_service_identified_by_supported_http_methods_exposes_ws_scheduler_returns_finding",
			behavior: fakeDaskBehavior{
				daemonType:     "Scheduler",
				daemonID:       "Scheduler-ws-custom",
				resultEncoding: "pickled_map",
			},
			useWS:              true,
			transport:          npb.TransportProtocol_TCP,
			serviceName:        "custom-non-matching",
			httpMethods:        []string{"GET"},
			wantWSPath:         "/",
			wantEvidenceSubstr: []string{"Scheduler (Scheduler-ws-custom)", "via run_function RPC handler"},
		},
		{
			name: "when_tls_web_service_exposes_wss_scheduler_with_fragmented_frames_returns_finding",
			behavior: fakeDaskBehavior{
				daemonType:     "Scheduler",
				daemonID:       "Scheduler-wss-1",
				resultEncoding: "pickled_map",
				fragmentedWS:   true,
			},
			useWS:              true,
			useTLS:             true,
			transport:          npb.TransportProtocol_TCP,
			serviceName:        "unknown",
			httpMethods:        []string{"GET"},
			sslVersions:        []string{"TLSv1.3"},
			wantEvidenceSubstr: []string{"Scheduler (Scheduler-wss-1)", "via run_function RPC handler"},
		},
		{
			name: "when_cudaworker_with_custom_k8s_id_allows_run_with_pickled_offset_msgpack_subframe_returns_finding",
			behavior: fakeDaskBehavior{
				daemonType:     "CUDAWorker",
				daemonID:       "k8s-gpu-pod-0",
				resultEncoding: "pickled_offset_msgpack_subframe",
			},
			transport:          npb.TransportProtocol_TCP,
			serviceName:        "unknown",
			wantEvidenceSubstr: []string{"CUDAWorker (k8s-gpu-pod-0)", "via run RPC handler"},
		},
		{
			name: "when_nanny_service_allows_run_returns_finding",
			behavior: fakeDaskBehavior{
				daemonType:     "Nanny",
				daemonID:       "nanny-node-1",
				resultEncoding: "direct_int",
			},
			transport:          npb.TransportProtocol_TCP,
			serviceName:        "unknown",
			wantEvidenceSubstr: []string{"Nanny (nanny-node-1)", "via run RPC handler"},
		},
		{
			name: "when_scheduler_blocks_run_function_and_worker_broadcast_but_allows_nanny_broadcast_returns_finding",
			behavior: fakeDaskBehavior{
				daemonType:               "Scheduler",
				daemonID:                 "k8s-sched-0",
				blockRunFunction:         true,
				blockWorkerBroadcastOnly: true,
				resultEncoding:           "pickled_map",
			},
			transport:          npb.TransportProtocol_TCP,
			serviceName:        "unknown",
			wantEvidenceSubstr: []string{"Scheduler (k8s-sched-0)", "via broadcast(nanny_run) RPC handler"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var srv *fakeCommServer
			if tc.useWS {
				srv = startFakeWSCommServer(t, tc.useTLS, tc.behavior)
			} else {
				srv = startFakeTCPCommServer(t, tc.useTLS, tc.behavior)
			}
			svc := newService("127.0.0.1", srv.port, tc.serviceName, tc.httpMethods, tc.sslVersions)
			svc.SetTransportProtocol(tc.transport)

			detector, err := New(t.Context(), config.Default())
			if err != nil {
				t.Fatalf("New() unexpected error: %v", err)
			}
			mod := detector.(*Module)
			if tc.fixedOperands != nil {
				ops := *tc.fixedOperands
				mod.operandGenFn = func() (int32, int32, error) {
					return ops[0], ops[1], nil
				}
			}

			reports, err := mod.Detect(t.Context(), svc)
			if err != nil {
				t.Fatalf("Detect() unexpected error: %v", err)
			}
			if reports == nil || len(reports.GetDetectionReports()) != 1 {
				t.Fatalf("Detect() reports = %v, want 1 report", reports)
			}

			if tc.wantExactEvidence {
				wantEvidence := fmt.Sprintf(
					"Verified unauthenticated Dask Scheduler (Scheduler-tcp-1) code execution on 127.0.0.1:%d via run_function RPC handler: operator.add(12345678, 23456789) returned 35802467.",
					srv.port,
				)
				want := buildDetectionReport(svc, &commResult{
					commAddr:    fmt.Sprintf("127.0.0.1:%d", srv.port),
					daemonType:  "Scheduler",
					daemonID:    "Scheduler-tcp-1",
					handler:     "run_function",
					operandA:    12345678,
					operandB:    23456789,
					computedSum: 35802467,
				})
				if diff := cmp.Diff(want, reports, protocmp.Transform(), protocmp.IgnoreFields(&dpb.DetectionReport{}, "detection_timestamp")); diff != "" {
					t.Errorf("Detect() report mismatch (-want +got):\n%s", diff)
				}
				if gotText := reports.GetDetectionReports()[0].GetVulnerability().GetAdditionalDetails()[0].GetTextData().GetText(); gotText != wantEvidence {
					t.Errorf("evidence text = %q, want %q", gotText, wantEvidence)
				}
			}

			gotReport := reports.GetDetectionReports()[0]
			if got := gotReport.GetDetectionStatus(); got != dpb.DetectionStatus_VULNERABILITY_VERIFIED {
				t.Errorf("GetDetectionStatus() = %v, want %v", got, dpb.DetectionStatus_VULNERABILITY_VERIFIED)
			}
			gotEvidence := gotReport.GetVulnerability().GetAdditionalDetails()[0].GetTextData().GetText()
			for _, sub := range tc.wantEvidenceSubstr {
				if !strings.Contains(gotEvidence, sub) {
					t.Errorf("evidence = %q, want substring %q", gotEvidence, sub)
				}
			}
			if tc.wantWSPath != "" {
				if got := srv.lastPath(); got != tc.wantWSPath {
					t.Errorf("srv.lastPath() = %q, want %q", got, tc.wantWSPath)
				}
			}
		})
	}
}

func TestDetect_HardenedOrNonVulnerableDaskServers(t *testing.T) {
	tests := []struct {
		name      string
		behavior  fakeDaskBehavior
		transport npb.TransportProtocol
		wantConns int32
	}{
		{
			name: "when_scheduler_blocks_both_run_function_and_broadcast_returns_no_findings",
			behavior: fakeDaskBehavior{
				daemonType:       "Scheduler",
				daemonID:         "Scheduler-hardened",
				blockRunFunction: true,
				blockBroadcast:   true,
			},
			transport: npb.TransportProtocol_TCP,
			wantConns: 1,
		},
		{
			name: "when_worker_blocks_run_handler_returns_no_findings",
			behavior: fakeDaskBehavior{
				daemonType:     "Worker",
				daemonID:       "Worker-hardened",
				blockWorkerRun: true,
			},
			transport: npb.TransportProtocol_TCP,
			wantConns: 1,
		},
		{
			name: "when_scheduler_returns_wrong_arithmetic_sum_returns_no_findings",
			behavior: fakeDaskBehavior{
				daemonType:     "Scheduler",
				daemonID:       "Scheduler-honeypot",
				resultEncoding: "direct_int",
				wrongDelta:     1,
			},
			transport: npb.TransportProtocol_TCP,
			wantConns: 1,
		},
		{
			name: "when_udp_transport_service_points_to_live_server_skips_probe_and_returns_no_findings",
			behavior: fakeDaskBehavior{
				daemonType:     "Scheduler",
				daemonID:       "Scheduler-udp-ignored",
				resultEncoding: "direct_int",
			},
			transport: npb.TransportProtocol_UDP,
			wantConns: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := startFakeTCPCommServer(t, false, tc.behavior)
			svc := newService("127.0.0.1", srv.port, "unknown", nil, nil)
			svc.SetTransportProtocol(tc.transport)

			detector, err := New(t.Context(), config.Default())
			if err != nil {
				t.Fatalf("New() unexpected error: %v", err)
			}
			reports, err := detector.Detect(t.Context(), svc)
			if err != nil {
				t.Fatalf("Detect() unexpected error: %v", err)
			}
			if got := len(reports.GetDetectionReports()); got != 0 {
				t.Errorf("len(Detect().GetDetectionReports()) = %d, want 0", got)
			}
			if got := srv.connCount.Load(); got != tc.wantConns {
				t.Errorf("srv.connCount.Load() = %d, want %d", got, tc.wantConns)
			}
		})
	}
}

func TestDetect_EchoAndNonDaskServices(t *testing.T) {
	t.Run("when_tcp_echo_server_repeats_all_bytes_stops_at_identity_and_returns_no_findings", func(t *testing.T) {
		ln, port := listenLoopback(t)
		var stepCount atomic.Int32
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				go func(c net.Conn) {
					defer c.Close()
					rw := &tcpFrameRW{r: c, w: c}
					for {
						frames, err := rw.readFrames()
						if err != nil {
							return
						}
						stepCount.Add(1)
						if err := rw.writeFrames(frames); err != nil {
							return
						}
					}
				}(conn)
			}
		}()

		detector, err := New(t.Context(), config.Default())
		if err != nil {
			t.Fatalf("New() unexpected error: %v", err)
		}
		reports, err := detector.Detect(t.Context(), newService("127.0.0.1", port, "unknown", nil, nil))
		if err != nil {
			t.Fatalf("Detect() unexpected error: %v", err)
		}
		if got := len(reports.GetDetectionReports()); got != 0 {
			t.Errorf("len(Detect().GetDetectionReports()) = %d, want 0", got)
		}
		if got := stepCount.Load(); got != 2 {
			t.Errorf("echo server frame exchanges = %d, want 2", got)
		}
	})

	t.Run("when_plain_http_web_service_rejects_websocket_upgrade_returns_no_findings", func(t *testing.T) {
		srv := httptest.NewServer(http.NotFoundHandler())
		t.Cleanup(srv.Close)

		detector, err := New(t.Context(), config.Default())
		if err != nil {
			t.Fatalf("New() unexpected error: %v", err)
		}
		svc := newService("127.0.0.1", serverPort(t, srv.Listener.Addr().String()), "http", []string{"GET"}, nil)
		reports, err := detector.Detect(t.Context(), svc)
		if err != nil {
			t.Fatalf("Detect() unexpected error: %v", err)
		}
		if got := len(reports.GetDetectionReports()); got != 0 {
			t.Errorf("len(Detect().GetDetectionReports()) = %d, want 0", got)
		}
	})

	closedPortTests := []struct {
		name        string
		serviceName string
		httpMethods []string
	}{
		{
			name:        "when_raw_comm_service_targets_closed_port_returns_no_findings",
			serviceName: "unknown",
		},
		{
			name:        "when_web_service_targets_closed_port_returns_no_findings",
			serviceName: "http",
			httpMethods: []string{"GET"},
		},
	}
	for _, tc := range closedPortTests {
		t.Run(tc.name, func(t *testing.T) {
			ln, port := listenLoopback(t)
			_ = ln.Close()

			detector, err := New(t.Context(), config.Default())
			if err != nil {
				t.Fatalf("New() unexpected error: %v", err)
			}
			reports, err := detector.Detect(t.Context(), newService("127.0.0.1", port, tc.serviceName, tc.httpMethods, nil))
			if err != nil {
				t.Fatalf("Detect() unexpected error: %v", err)
			}
			if got := len(reports.GetDetectionReports()); got != 0 {
				t.Errorf("len(Detect().GetDetectionReports()) = %d, want 0", got)
			}
		})
	}
}

func TestDetect_ErrorsAndTimeouts(t *testing.T) {
	errEntropy := errors.New("entropy exhausted")
	errWSEntropy := errors.New("ws entropy failure")

	inputErrTests := []struct {
		name       string
		svc        *nspb.NetworkService
		operandErr error
		preCancel  bool
		wantErr    error
	}{
		{
			name: "when_endpoint_missing_address_returns_error",
			svc: nspb.NetworkService_builder{
				ServiceName:     "unknown",
				NetworkEndpoint: &npb.NetworkEndpoint{},
			}.Build(),
			wantErr: netendpoint.ErrEndpointMissingAddress,
		},
		{
			name:       "when_operand_generator_fails_returns_error",
			svc:        newService("127.0.0.1", 8786, "unknown", nil, nil),
			operandErr: errEntropy,
			wantErr:    errEntropy,
		},
		{
			name:       "when_web_service_operand_generator_fails_returns_error",
			svc:        newService("127.0.0.1", 8787, "http", []string{"GET"}, nil),
			operandErr: errWSEntropy,
			wantErr:    errWSEntropy,
		},
		{
			name:      "when_context_canceled_before_detect_returns_error",
			svc:       newService("127.0.0.1", 8786, "unknown", nil, nil),
			preCancel: true,
			wantErr:   context.Canceled,
		},
	}

	for _, tc := range inputErrTests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			if tc.preCancel {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			detector, err := New(ctx, config.Default())
			if err != nil {
				t.Fatalf("New() unexpected error: %v", err)
			}
			mod := detector.(*Module)
			if tc.operandErr != nil {
				mod.operandGenFn = func() (int32, int32, error) {
					return 0, 0, tc.operandErr
				}
			}
			reports, err := mod.Detect(ctx, tc.svc)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Detect() error = %v, want errors.Is(_, %v)", err, tc.wantErr)
			}
			if got := len(reports.GetDetectionReports()); got != 0 {
				t.Errorf("len(Detect().GetDetectionReports()) = %d, want 0", got)
			}
		})
	}

	stalledListenerTests := []struct {
		name           string
		timeoutSeconds int32
		ctxTimeout     time.Duration
		cancelOnAccept bool
		sslVersions    []string
		maxElapsed     time.Duration
		wantErr        error
	}{
		{
			name:           "when_context_canceled_during_tls_handshake_aborts_immediately_and_returns_error",
			timeoutSeconds: 5,
			cancelOnAccept: true,
			sslVersions:    []string{"TLSv1.3"},
			maxElapsed:     2 * time.Second,
			wantErr:        context.Canceled,
		},
		{
			name:           "when_raw_comm_service_with_short_ctx_deadline_hits_stalled_listener_returns_deadline_exceeded",
			timeoutSeconds: 10,
			ctxTimeout:     150 * time.Millisecond,
			maxElapsed:     2 * time.Second,
			wantErr:        context.DeadlineExceeded,
		},
		{
			name:           "when_tls_comm_server_stalls_handshake_under_background_ctx_enforces_per_request_timeout",
			timeoutSeconds: 1,
			sslVersions:    []string{"TLSv1.3"},
			maxElapsed:     2500 * time.Millisecond,
		},
	}

	for _, tc := range stalledListenerTests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			var cancel context.CancelFunc
			if tc.cancelOnAccept {
				ctx, cancel = context.WithCancel(t.Context())
				t.Cleanup(cancel)
			} else if tc.ctxTimeout > 0 {
				ctx, cancel = context.WithTimeout(t.Context(), tc.ctxTimeout)
				t.Cleanup(cancel)
			}

			ln, port := listenLoopback(t)
			done := make(chan struct{})
			t.Cleanup(func() { close(done) })
			go func() {
				for {
					conn, err := ln.Accept()
					if err != nil {
						return
					}
					go func(c net.Conn) {
						defer c.Close()
						if tc.cancelOnAccept {
							cancel()
						}
						<-done
					}(conn)
				}
			}()

			cfg := config.FromProto(cpb.Config_builder{
				Globalcfg: cpb.GlobalConfig_builder{
					Performance: cpb.GlobalConfig_Performance_builder{
						TimeoutPerRequestSeconds: proto.Int32(tc.timeoutSeconds),
					}.Build(),
				}.Build(),
			}.Build())
			detector, err := New(ctx, cfg)
			if err != nil {
				t.Fatalf("New() unexpected error: %v", err)
			}
			svc := newService("127.0.0.1", port, "unknown", nil, tc.sslVersions)

			start := time.Now()
			reports, err := detector.Detect(ctx, svc)
			elapsed := time.Since(start)
			if elapsed > tc.maxElapsed {
				t.Errorf("Detect() elapsed = %v, want <= %v", elapsed, tc.maxElapsed)
			}
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Detect() error = %v, want errors.Is(_, %v)", err, tc.wantErr)
				}
			} else if err != nil {
				t.Fatalf("Detect() unexpected error: %v", err)
			}
			if got := len(reports.GetDetectionReports()); got != 0 {
				t.Errorf("len(Detect().GetDetectionReports()) = %d, want 0", got)
			}
		})
	}

	t.Run("when_context_canceled_during_websocket_upgrade_returns_error", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cancel()
			http.NotFound(w, r)
		}))
		t.Cleanup(srv.Close)

		detector, err := New(ctx, config.Default())
		if err != nil {
			t.Fatalf("New() unexpected error: %v", err)
		}
		svc := newService("127.0.0.1", serverPort(t, srv.Listener.Addr().String()), "http", []string{"GET"}, nil)
		reports, err := detector.Detect(ctx, svc)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Detect() error = %v, want errors.Is(_, %v)", err, context.Canceled)
		}
		if got := len(reports.GetDetectionReports()); got != 0 {
			t.Errorf("len(Detect().GetDetectionReports()) = %d, want 0", got)
		}
	})
}

func TestTCPFrameRW_ReadFrames(t *testing.T) {
	tests := []struct {
		name  string
		raw   []byte
		isEOF bool
	}{
		{
			name:  "when_truncated_header_returns_eof",
			raw:   []byte{0x01, 0x02, 0x03},
			isEOF: true,
		},
		{
			name: "when_zero_frames_returns_invalid_protocol",
			raw:  appendUint64LE(nil, 8, 0),
		},
		{
			name: "when_too_many_frames_returns_invalid_protocol",
			raw:  appendUint64LE(nil, 200, maxFramesCount+1),
		},
		{
			name:  "when_truncated_lengths_buffer_returns_eof",
			raw:   []byte{24, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 2},
			isEOF: true,
		},
		{
			name: "when_frame_length_exceeds_max_returns_invalid_protocol",
			raw:  appendUint64LE(nil, 16+maxFrameBytes+1, 1, maxFrameBytes+1),
		},
		{
			name: "when_nosplit_bytes_mismatch_returns_invalid_protocol",
			raw:  appendUint64LE(nil, 999, 1, 4),
		},
		{
			name:  "when_truncated_frame_payload_returns_eof",
			raw:   append(appendUint64LE(nil, 20, 1, 4), 0xaa, 0xbb),
			isEOF: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rw := &tcpFrameRW{r: bytes.NewReader(tc.raw)}
			_, err := rw.readFrames()
			if err == nil {
				t.Fatalf("tcpFrameRW.readFrames(%x) = nil, want error", tc.raw)
			}
			if tc.isEOF {
				if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
					t.Errorf("tcpFrameRW.readFrames(%x) error = %v, want EOF/ErrUnexpectedEOF", tc.raw, err)
				}
			} else if !errors.Is(err, errInvalidDaskProtocol) {
				t.Errorf("tcpFrameRW.readFrames(%x) error = %v, want %v", tc.raw, err, errInvalidDaskProtocol)
			}
		})
	}

	t.Run("when_tcp_frame_count_equals_max_frames_count_succeeds", func(t *testing.T) {
		var frames [][]byte
		for i := 0; i < maxFramesCount; i++ {
			frames = append(frames, []byte{byte(i)})
		}
		var buf bytes.Buffer
		rw := &tcpFrameRW{r: &buf, w: &buf}
		if err := rw.writeFrames(frames); err != nil {
			t.Fatalf("tcpFrameRW.writeFrames(maxFramesCount) error: %v", err)
		}
		got, err := rw.readFrames()
		if err != nil || len(got) != maxFramesCount {
			t.Fatalf("tcpFrameRW.readFrames(maxFramesCount) = (len=%d, err=%v), want (len=%d, nil)", len(got), err, maxFramesCount)
		}
	})
}

func TestWebSocketUpgradeAndFraming(t *testing.T) {
	upgradeTests := []struct {
		name        string
		authority   string
		resp        string
		wantReqLine string
		wantNilErr  bool
	}{
		{
			name:        "when_valid_101_response_sends_root_get_and_succeeds",
			authority:   "127.0.0.1:8786",
			resp:        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: abc\r\n\r\n",
			wantReqLine: "GET / HTTP/1.1\r\nHost: 127.0.0.1:8786\r\n",
			wantNilErr:  true,
		},
		{
			name:        "when_printable_ascii_boundary_chars_present_succeeds",
			authority:   "host!~:8786",
			resp:        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: abc\r\n\r\n",
			wantReqLine: "GET / HTTP/1.1\r\nHost: host!~:8786\r\n",
			wantNilErr:  true,
		},
		{
			name:      "when_authority_is_empty_rejects_before_writing",
			authority: "",
		},
		{
			name:      "when_authority_contains_space_rejects_before_writing",
			authority: "bad host:8786",
		},
		{
			name:      "when_authority_contains_crlf_rejects_before_writing",
			authority: "127.0.0.1:8786\r\nX-Injected: 1",
		},
		{
			name:      "when_authority_contains_del_byte_rejects_before_writing",
			authority: "127.0.0.1:8786\x7f",
		},
		{
			name:        "when_upgrade_status_is_200_returns_invalid_protocol",
			authority:   "127.0.0.1:8786",
			resp:        "HTTP/1.1 200 OK\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: abc\r\nContent-Length: 0\r\n\r\n",
			wantReqLine: "GET / HTTP/1.1\r\n",
		},
		{
			name:        "when_upgrade_header_missing_returns_invalid_protocol",
			authority:   "127.0.0.1:8786",
			resp:        "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: abc\r\n\r\n",
			wantReqLine: "GET / HTTP/1.1\r\n",
		},
		{
			name:        "when_connection_header_missing_upgrade_token_returns_invalid_protocol",
			authority:   "127.0.0.1:8786",
			resp:        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: keep-alive\r\nSec-WebSocket-Accept: abc\r\n\r\n",
			wantReqLine: "GET / HTTP/1.1\r\n",
		},
		{
			name:        "when_sec_websocket_accept_empty_returns_invalid_protocol",
			authority:   "127.0.0.1:8786",
			resp:        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
			wantReqLine: "GET / HTTP/1.1\r\n",
		},
	}

	for _, tc := range upgradeTests {
		t.Run(tc.name, func(t *testing.T) {
			var reqBuf bytes.Buffer
			err := performWebSocketUpgrade(bufio.NewReader(strings.NewReader(tc.resp)), &reqBuf, tc.authority)
			if tc.wantNilErr {
				if err != nil {
					t.Fatalf("performWebSocketUpgrade(%q) unexpected error: %v", tc.authority, err)
				}
			} else if !errors.Is(err, errInvalidDaskProtocol) {
				t.Errorf("performWebSocketUpgrade(%q) error = %v, want %v", tc.authority, err, errInvalidDaskProtocol)
			}
			if tc.wantReqLine == "" {
				if reqBuf.Len() != 0 {
					t.Errorf("performWebSocketUpgrade(%q) wrote %q, want 0 bytes", tc.authority, reqBuf.String())
				}
			} else if !strings.HasPrefix(reqBuf.String(), tc.wantReqLine) {
				t.Errorf("performWebSocketUpgrade(%q) request = %q, want prefix %q", tc.authority, reqBuf.String(), tc.wantReqLine)
			}
		})
	}

	t.Run("when_websocket_upgrade_writer_or_reader_fails_returns_io_error", func(t *testing.T) {
		if err := performWebSocketUpgrade(bufio.NewReader(strings.NewReader("")), &failWriter{failOnCall: 1}, "127.0.0.1:8787"); err == nil {
			t.Errorf("performWebSocketUpgrade(failWriter) = %v, want non-nil error", err)
		}
		if err := performWebSocketUpgrade(bufio.NewReader(strings.NewReader("")), &bytes.Buffer{}, "127.0.0.1:8787"); err == nil {
			t.Errorf("performWebSocketUpgrade(EOF reader) = %v, want non-nil error", err)
		}
	})

	frameTests := []struct {
		name string
		raw  []byte
	}{
		{
			name: "when_close_frame_received_returns_invalid_protocol",
			raw:  []byte{0x88, 0x00},
		},
		{
			name: "when_text_opcode_received_returns_invalid_protocol",
			raw:  []byte{0x81, 0x02, 'h', 'i'},
		},
		{
			name: "when_unexpected_continuation_frame_returns_invalid_protocol",
			raw:  []byte{0x80, 0x01, 0x00},
		},
		{
			name: "when_nested_binary_opcode_before_fin_returns_invalid_protocol",
			raw:  []byte{0x02, 0x01, 0xaa, 0x82, 0x01, 0xbb},
		},
		{
			name: "when_64bit_length_exceeds_max_frame_bytes_returns_invalid_protocol",
			raw:  []byte{0x82, 127, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00},
		},
		{
			name: "when_fragmented_ws_chunks_cumulative_length_exceeds_max_frame_bytes_returns_invalid_protocol",
			raw: func() []byte {
				chunkLen := 300_000
				var b bytes.Buffer
				b.Write([]byte{0x02, 127, 0, 0, 0, 0, 0, 0x04, 0x93, 0xe0})
				b.Write(make([]byte, chunkLen))
				b.Write([]byte{0x80, 127, 0, 0, 0, 0, 0, 0x04, 0x93, 0xe0})
				b.Write(make([]byte, chunkLen))
				return b.Bytes()
			}(),
		},
		{
			name: "when_continuation_frame_64bit_length_wraps_uint64_returns_invalid_protocol",
			raw: []byte{
				0x02, 0x04, 'd', 'a', 's', 'k',
				0x80, 127, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			},
		},
		{
			name: "when_ws_count_message_not_8_bytes_returns_invalid_protocol",
			raw:  []byte{0x82, 0x02, 0x01, 0x02},
		},
		{
			name: "when_ws_count_is_zero_returns_invalid_protocol",
			raw:  append([]byte{0x82, 0x08}, make([]byte, 8)...),
		},
		{
			name: "when_ws_count_exceeds_max_frames_count_returns_invalid_protocol",
			raw:  append([]byte{0x82, 0x08}, appendUint64LE(nil, maxFramesCount+1)...),
		},
		{
			name: "when_excessive_ws_ping_frames_exceed_cap_returns_invalid_protocol",
			raw:  bytes.Repeat([]byte{0x89, 0x00}, maxWSFramesPerMessage+4),
		},
	}

	for _, tc := range frameTests {
		t.Run(tc.name, func(t *testing.T) {
			rw := &wsFrameRW{r: bytes.NewReader(tc.raw)}
			_, err := rw.readFrames()
			if !errors.Is(err, errInvalidDaskProtocol) {
				t.Errorf("wsFrameRW.readFrames() error = %v, want %v", err, errInvalidDaskProtocol)
			}
		})
	}

	truncatedWSTests := []struct {
		name  string
		badWS []byte
	}{
		{"when_truncated_ws_header_returns_error", []byte{0x82}},
		{"when_truncated_ws_ext16_len_returns_error", []byte{0x82, 126, 0x00}},
		{"when_truncated_ws_ext64_len_returns_error", []byte{0x82, 127, 0x00, 0x01}},
		{"when_truncated_ws_mask_key_returns_error", []byte{0x82, 0x82, 0xaa}},
		{"when_truncated_ws_masked_payload_returns_error", []byte{0x82, 0x82, 0x01, 0x02, 0x03, 0x04, 0xaa}},
		{"when_truncated_ws_second_frame_returns_error", []byte{0x82, 0x08, 1, 0, 0, 0, 0, 0, 0, 0, 0x82}},
	}
	for _, tc := range truncatedWSTests {
		t.Run(tc.name, func(t *testing.T) {
			rw := &wsFrameRW{r: bytes.NewReader(tc.badWS)}
			if _, err := rw.readFrames(); err == nil {
				t.Errorf("wsFrameRW.readFrames(%x) = nil, want EOF error", tc.badWS)
			}
		})
	}

	t.Run("when_ws_extended_16bit_payload_and_max_frames_count_round_trip_succeeds", func(t *testing.T) {
		var wsBuf bytes.Buffer
		largePayload := bytes.Repeat([]byte{0x5a}, 140)
		clientWS := &wsFrameRW{r: &wsBuf, w: &wsBuf}
		if err := clientWS.writeFrames([][]byte{largePayload}); err != nil {
			t.Fatalf("wsFrameRW.writeFrames(140B) unexpected error: %v", err)
		}
		gotFrames, err := clientWS.readFrames()
		if err != nil || len(gotFrames) != 1 || !bytes.Equal(gotFrames[0], largePayload) {
			t.Fatalf("wsFrameRW.readFrames(140B) = (%v, %v), want exact match", gotFrames, err)
		}

		var frames [][]byte
		for i := 0; i < maxFramesCount; i++ {
			frames = append(frames, []byte{byte(i)})
		}
		var maxBuf bytes.Buffer
		maxRW := &wsFrameRW{r: &maxBuf, w: &maxBuf}
		if err := maxRW.writeFrames(frames); err != nil {
			t.Fatalf("wsFrameRW.writeFrames(maxFramesCount) error: %v", err)
		}
		got, err := maxRW.readFrames()
		if err != nil || len(got) != maxFramesCount {
			t.Fatalf("wsFrameRW.readFrames(maxFramesCount) = (len=%d, err=%v), want (len=%d, nil)", len(got), err, maxFramesCount)
		}
	})

	for _, failCall := range []int{1, 2} {
		t.Run(fmt.Sprintf("when_ws_write_fails_on_call_%d_returns_error", failCall), func(t *testing.T) {
			if err := (&wsFrameRW{w: &failWriter{failOnCall: failCall}}).writeFrames([][]byte{{0x01}}); err == nil {
				t.Errorf("wsFrameRW.writeFrames(failOnCall=%d) = %v, want non-nil error", failCall, err)
			}
		})
	}
}

func TestMsgPackAndPickleDecoders(t *testing.T) {
	t.Run("when_build_args_tuple_pickle_called_encodes_exact_proto2_tuple2_bytes", func(t *testing.T) {
		got := buildArgsTuplePickle(0x01020304, 0x05060708)
		want := []byte{
			0x80, 0x02,
			'J', 0x04, 0x03, 0x02, 0x01,
			'J', 0x08, 0x07, 0x06, 0x05,
			0x86, 'q', 0x00, '.',
		}
		if !bytes.Equal(got, want) {
			t.Errorf("buildArgsTuplePickle(0x01020304, 0x05060708) = %x, want %x", got, want)
		}
	})

	pickleTests := []struct {
		name   string
		raw    []byte
		want   int64
		wantOK bool
	}{
		{
			name:   "when_proto4_frame_binint_with_memoize_returns_sum",
			raw:    []byte{0x80, 0x04, 0x95, 8, 0, 0, 0, 0, 0, 0, 0, 'J', 0x40, 0x42, 0x0f, 0x00, 0x94, 'q', 0x01, 'r', 1, 0, 0, 0, '.'},
			want:   1_000_000,
			wantOK: true,
		},
		{
			name:   "when_ascii_decimal_with_long_suffix_returns_sum",
			raw:    []byte("I9876543210L\n."),
			want:   9876543210,
			wantOK: true,
		},
		{
			name:   "when_long1_multi_byte_positive_integer_decodes_accurately",
			raw:    []byte{0x8a, 0x02, 0x01, 0x02, '.'},
			want:   0x0201,
			wantOK: true,
		},
		{
			name:   "when_empty_slice_returns_false",
			raw:    nil,
			wantOK: false,
		},
		{
			name:   "when_truncated_proto_header_returns_false",
			raw:    []byte{0x80},
			wantOK: false,
		},
		{
			name:   "when_truncated_frame_header_returns_false",
			raw:    []byte{0x80, 0x04, 0x95, 1, 2, 3},
			wantOK: false,
		},
		{
			name:   "when_proto_header_only_without_value_returns_false",
			raw:    []byte{0x80, 0x04},
			wantOK: false,
		},
		{
			name:   "when_truncated_binint_returns_false",
			raw:    []byte{'J', 1, 2},
			wantOK: false,
		},
		{
			name:   "when_ascii_int_missing_newline_returns_false",
			raw:    []byte("I12345"),
			wantOK: false,
		},
		{
			name:   "when_ascii_int_non_numeric_returns_false",
			raw:    []byte("Inot_a_number\n."),
			wantOK: false,
		},
		{
			name:   "when_truncated_long1_header_or_zero_len_returns_false",
			raw:    []byte{0x8a},
			wantOK: false,
		},
		{
			name:   "when_long1_length_exceeds_8_bytes_returns_false",
			raw:    []byte{0x8a, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, '.'},
			wantOK: false,
		},
		{
			name:   "when_trailing_bytes_after_stop_opcode_returns_false",
			raw:    []byte("I42\n.extra"),
			wantOK: false,
		},
		{
			name:   "when_unexpected_memoize_opcode_returns_false",
			raw:    []byte{'J', 1, 0, 0, 0, 'X', '.'},
			wantOK: false,
		},
		{
			name:   "when_truncated_binput_before_stop_returns_false",
			raw:    []byte{'J', 1, 0, 0, 0, 'q', '.'},
			wantOK: false,
		},
		{
			name:   "when_unsupported_opcode_returns_false",
			raw:    []byte{0x80, 0x02, 'K', 0x2a, '.'},
			wantOK: false,
		},
	}

	for _, tc := range pickleTests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parsePickleInt64(tc.raw)
			if ok != tc.wantOK {
				t.Fatalf("parsePickleInt64(%x) ok = %t, want %t", tc.raw, ok, tc.wantOK)
			}
			if tc.wantOK && got != tc.want {
				t.Errorf("parsePickleInt64(%x) = %d, want %d", tc.raw, got, tc.want)
			}
		})
	}

	msgpackTests := []struct {
		name    string
		raw     []byte
		wantErr bool
	}{
		{
			name: "when_rich_scalar_ext_and_container_tags_present_decodes_cleanly",
			raw: []byte{
				0xde, 0x00, 0x0b, // map16(11)
				0xd9, 0x02, 'k', '1', 0xe5, // str8 -> neg fixint
				0xda, 0x00, 0x02, 'k', '2', 0xc2, // str16 -> false
				0xdb, 0x00, 0x00, 0x00, 0x02, 'k', '3', 0xca, 0, 0, 0, 0, // str32 -> float32
				0xa2, 'k', '4', 0xcb, 0, 0, 0, 0, 0, 0, 0, 0, // float64
				0xa2, 'k', '5', 0xdc, 0x00, 0x09, // array16(9)
				0xc0, 0xcc, 1, 0xcd, 0, 2, 0xce, 0, 0, 0, 3, 0xcf, 0, 0, 0, 0, 0, 0, 0, 4,
				0xd0, 0xff, 0xd1, 0xff, 0xfe, 0xd2, 0xff, 0xff, 0xff, 0xfd, 0xd3, 0, 0, 0, 0, 0, 0, 0, 5,
				0xa2, 'k', '6', 0xc5, 0x00, 0x02, 0xaa, 0xbb, // bin16
				0xa2, 'k', '7', 0xd4, 0x01, 0x00, // fixext1
				0xa2, 'k', '8', 0xc7, 0x01, 0x01, 0x99, // ext8
				0xa2, 'k', '9', 0xc8, 0x00, 0x01, 0x01, 0x88, // ext16
				0xa3, 'k', '1', '0', 0xc9, 0x00, 0x00, 0x00, 0x01, 0x01, 0x77, // ext32
				0xa3, 'k', '1', '1', 0xdd, 0x00, 0x00, 0x00, 0x01, // array32(1)
				0xdf, 0x00, 0x00, 0x00, 0x01, // map32(1)
				0xa1, 'x', 0xc6, 0x00, 0x00, 0x00, 0x01, 0xfe, // bin32(1)
			},
		},
		{
			name:    "when_empty_input_returns_eof_error",
			raw:     nil,
			wantErr: true,
		},
		{
			name:    "when_array_depth_equals_max_msgpack_depth_succeeds",
			raw:     append(bytes.Repeat([]byte{0x91}, maxMsgPackDepth), 0x01),
			wantErr: false,
		},
		{
			name:    "when_array_depth_exceeds_max_msgpack_depth_by_one_returns_error",
			raw:     append(bytes.Repeat([]byte{0x91}, maxMsgPackDepth+1), 0x01),
			wantErr: true,
		},
		{
			name:    "when_map_depth_equals_max_msgpack_depth_succeeds",
			raw:     append(bytes.Repeat([]byte{0x81, 0xa1, 'k'}, maxMsgPackDepth), 0x01),
			wantErr: false,
		},
		{
			name:    "when_map_depth_exceeds_max_msgpack_depth_by_one_returns_error",
			raw:     append(bytes.Repeat([]byte{0x81, 0xa1, 'k'}, maxMsgPackDepth+1), 0x01),
			wantErr: true,
		},
		{
			name:    "when_map_key_depth_exceeds_max_msgpack_depth_by_one_returns_error",
			raw:     append(bytes.Repeat([]byte{0x81}, maxMsgPackDepth+1), 0xa1, 'k'),
			wantErr: true,
		},
		{
			name:    "when_reserved_0xc1_tag_present_returns_error",
			raw:     []byte{0xc1},
			wantErr: true,
		},
		{
			name:    "when_array16_exceeds_max_collection_size_returns_error",
			raw:     []byte{0xdc, 0x10, 0x01},
			wantErr: true,
		},
		{
			name:    "when_map16_exceeds_max_collection_size_returns_error",
			raw:     []byte{0xde, 0x10, 0x01},
			wantErr: true,
		},
		{
			name:    "when_array32_exceeds_max_collection_size_returns_error",
			raw:     []byte{0xdd, 0x00, 0x01, 0x00, 0x00},
			wantErr: true,
		},
		{
			name:    "when_map32_exceeds_max_collection_size_returns_error",
			raw:     []byte{0xdf, 0x00, 0x01, 0x00, 0x00},
			wantErr: true,
		},
		{
			name:    "when_bin32_exceeds_max_frame_bytes_returns_error",
			raw:     []byte{0xc6, 0x00, 0x10, 0x00, 0x00},
			wantErr: true,
		},
		{
			name:    "when_ext32_exceeds_max_frame_bytes_returns_error",
			raw:     []byte{0xc9, 0x00, 0x10, 0x00, 0x00},
			wantErr: true,
		},
		{
			name:    "when_truncated_multibyte_scalars_and_containers_return_eof",
			raw:     []byte{0xda, 0x00},
			wantErr: true,
		},
	}

	for _, tc := range msgpackTests {
		t.Run(tc.name, func(t *testing.T) {
			val, err := decodeMsgPack(tc.raw)
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Fatalf("decodeMsgPack(%x) error = %v, wantErr %t", tc.raw, err, tc.wantErr)
			}
			if !tc.wantErr && tc.name == "when_rich_scalar_ext_and_container_tags_present_decodes_cleanly" {
				m, ok := val.(map[string]any)
				if !ok {
					t.Fatalf("decodeMsgPack() = %T, want map[string]any", val)
				}
				if gotK1, ok := m["k1"].(int64); !ok || gotK1 != -27 {
					t.Errorf("m[\"k1\"] (str8 key) = (%T, %v), want int64(-27)", m["k1"], m["k1"])
				}
				if gotK2, ok := m["k2"].(bool); !ok || gotK2 != false {
					t.Errorf("m[\"k2\"] (str16 key) = (%T, %v), want bool(false)", m["k2"], m["k2"])
				}
				if gotK3, ok := m["k3"].(float64); !ok || gotK3 != 0.0 {
					t.Errorf("m[\"k3\"] (str32 key) = (%T, %v), want float64(0.0)", m["k3"], m["k3"])
				}
				if gotK6, ok := m["k6"].([]byte); !ok || !bytes.Equal(gotK6, []byte{0xaa, 0xbb}) {
					t.Errorf("m[\"k6\"] = (%T, %v), want []byte{0xaa, 0xbb}", m["k6"], m["k6"])
				}
				k11Arr, _ := m["k11"].([]any)
				if len(k11Arr) != 1 {
					t.Fatalf("m[\"k11\"] = %v, want 1-element slice", m["k11"])
				}
				nestedMap, _ := k11Arr[0].(map[string]any)
				if gotX, ok := nestedMap["x"].([]byte); !ok || !bytes.Equal(gotX, []byte{0xfe}) {
					t.Errorf("nestedMap[\"x\"] = (%T, %v), want []byte{0xfe}", nestedMap["x"], nestedMap["x"])
				}
			}
		})
	}

	truncatedPrefixes := []struct {
		name string
		raw  []byte
	}{
		{"when_truncated_fixstr_returns_error", []byte{0xa5, 'a', 'b'}},
		{"when_truncated_bin8_len_returns_error", []byte{0xc4}},
		{"when_truncated_bin8_body_returns_error", []byte{0xc4, 0x05, 0x01}},
		{"when_truncated_bin16_body_returns_error", []byte{0xc5, 0x00, 0x05, 0x01}},
		{"when_truncated_bin32_len_returns_error", []byte{0xc6, 0x00, 0x00}},
		{"when_truncated_bin32_body_returns_error", []byte{0xc6, 0x00, 0x00, 0x00, 0x04, 0x01}},
		{"when_truncated_uint16_returns_error", []byte{0xcd, 0x01}},
		{"when_truncated_uint32_returns_error", []byte{0xce, 0x01}},
		{"when_truncated_uint64_returns_error", []byte{0xcf, 0x01}},
		{"when_truncated_int16_returns_error", []byte{0xd1, 0x01}},
		{"when_truncated_int32_returns_error", []byte{0xd2, 0x01}},
		{"when_truncated_int64_returns_error", []byte{0xd3, 0x01}},
		{"when_truncated_array16_len_returns_error", []byte{0xdc, 0x01}},
		{"when_truncated_array32_len_returns_error", []byte{0xdd, 0x01}},
		{"when_truncated_map16_len_returns_error", []byte{0xde, 0x01}},
		{"when_truncated_map32_len_returns_error", []byte{0xdf, 0x01}},
		{"when_truncated_ext8_len_returns_error", []byte{0xc7}},
		{"when_truncated_ext16_len_returns_error", []byte{0xc8, 0x00}},
		{"when_truncated_ext32_len_returns_error", []byte{0xc9, 0x00}},
		{"when_truncated_fixarray_elem_returns_error", []byte{0x91}},
		{"when_truncated_fixmap_key_returns_error", []byte{0x81}},
		{"when_truncated_fixmap_val_returns_error", []byte{0x81, 0xa1, 'k'}},
	}
	for _, tc := range truncatedPrefixes {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := decodeMsgPack(tc.raw); err == nil {
				t.Errorf("decodeMsgPack(%x) = nil, want EOF error", tc.raw)
			}
		})
	}
}

func TestRunCommSession_Errors(t *testing.T) {
	validHS := []byte{0x81, 0xaf, 'p', 'i', 'c', 'k', 'l', 'e', '-', 'p', 'r', 'o', 't', 'o', 'c', 'o', 'l', 0x04}
	schedID := []byte{0x82, 0xa4, 't', 'y', 'p', 'e', 0xa9, 'S', 'c', 'h', 'e', 'd', 'u', 'l', 'e', 'r', 0xa2, 'i', 'd', 0xab, 'S', 'c', 'h', 'e', 'd', 'u', 'l', 'e', 'r', '-', '1'}
	workerID := []byte{0x82, 0xa4, 't', 'y', 'p', 'e', 0xa6, 'W', 'o', 'r', 'k', 'e', 'r', 0xa2, 'i', 'd', 0xa8, 'W', 'o', 'r', 'k', 'e', 'r', '-', '1'}
	emptyID := []byte{0x82, 0xa4, 't', 'y', 'p', 'e', 0xa9, 'S', 'c', 'h', 'e', 'd', 'u', 'l', 'e', 'r', 0xa2, 'i', 'd', 0xa3, ' ', ' ', ' '}
	clientID := []byte{0x82, 0xa4, 't', 'y', 'p', 'e', 0xa6, 'C', 'l', 'i', 'e', 'n', 't', 0xa2, 'i', 'd', 0xa8, 'C', 'l', 'i', 'e', 'n', 't', '-', '1'}
	validRunOK := encodeRunResultFrames(30, "direct_int", false)

	sessionCases := []struct {
		name        string
		replies     [][][]byte
		failWriteAt int
		failReadAt  int
		wantWrites  int
	}{
		{name: "when_handshake_write_fails_returns_error", failWriteAt: 1, wantWrites: 1},
		{name: "when_handshake_read_fails_returns_error", replies: [][][]byte{{validHS}, {schedID}, validRunOK}, failReadAt: 1, wantWrites: 1},
		{name: "when_handshake_reply_has_multiple_frames_stops_before_identity", replies: [][][]byte{{validHS, validHS}, {schedID}, validRunOK}, wantWrites: 1},
		{name: "when_handshake_reply_not_msgpack_map_returns_error", replies: [][][]byte{{{0x91, 0x01}}, {schedID}, validRunOK}, wantWrites: 1},
		{name: "when_handshake_reply_missing_pickle_protocol_returns_error", replies: [][][]byte{{{0x80}}, {schedID}, validRunOK}, wantWrites: 1},
		{name: "when_identity_write_fails_returns_error", replies: [][][]byte{{validHS}}, failWriteAt: 2, wantWrites: 2},
		{name: "when_identity_read_fails_with_non_empty_frames_returns_error", replies: [][][]byte{{validHS}, {schedID}, validRunOK}, failReadAt: 2, wantWrites: 2},
		{name: "when_identity_reply_has_zero_frames_returns_error", replies: [][][]byte{{validHS}, {}, validRunOK}, wantWrites: 2},
		{name: "when_identity_reply_not_map_returns_error", replies: [][][]byte{{validHS}, {{0x91, 0x01}}, validRunOK}, wantWrites: 2},
		{name: "when_identity_reply_invalid_msgpack_returns_error", replies: [][][]byte{{validHS}, {{0xc1}}, validRunOK}, wantWrites: 2},
		{name: "when_identity_reply_whitespace_daemon_id_returns_error", replies: [][][]byte{{validHS}, {emptyID}, validRunOK}, wantWrites: 2},
		{name: "when_identity_reply_unknown_daemon_type_returns_error", replies: [][][]byte{{validHS}, {clientID}, validRunOK}, wantWrites: 2},
		{name: "when_worker_run_write_fails_returns_error", replies: [][][]byte{{validHS}, {workerID}}, failWriteAt: 3, wantWrites: 3},
		{name: "when_worker_run_read_fails_returns_error", replies: [][][]byte{{validHS}, {workerID}, validRunOK}, failReadAt: 3, wantWrites: 3},
		{name: "when_scheduler_run_function_write_fails_returns_error", replies: [][][]byte{{validHS}, {schedID}}, failWriteAt: 3, wantWrites: 3},
		{name: "when_scheduler_run_function_read_fails_returns_error", replies: [][][]byte{{validHS}, {schedID}, validRunOK}, failReadAt: 3, wantWrites: 3},
		{name: "when_scheduler_broadcast_write_fails_returns_error", replies: [][][]byte{{validHS}, {schedID}, {{0x80}}}, failWriteAt: 4, wantWrites: 4},
		{name: "when_scheduler_broadcast_read_fails_returns_error", replies: [][][]byte{{validHS}, {schedID}, {{0x80}}, encodeRunResultFrames(30, "direct_int", true)}, failReadAt: 4, wantWrites: 4},
		{name: "when_scheduler_nanny_broadcast_write_fails_returns_error", replies: [][][]byte{{validHS}, {schedID}, {{0x80}}, {{0x80}}}, failWriteAt: 5, wantWrites: 5},
		{name: "when_scheduler_nanny_broadcast_read_fails_returns_error", replies: [][][]byte{{validHS}, {schedID}, {{0x80}}, {{0x80}}, encodeRunResultFrames(30, "direct_int", true)}, failReadAt: 5, wantWrites: 5},
		{
			name: "when_reply_frames_have_non_map_or_missing_result_or_bad_subframe_returns_error",
			replies: [][][]byte{
				{validHS},
				{schedID},
				{{0x82, 0xa6, 's', 't', 'a', 't', 'u', 's', 0xa2, 'O', 'K', 0xa6, 'r', 'e', 's', 'u', 'l', 't', 0xc3}},
				{{0x81, 0xa1, 'w', 0x82, 0xa6, 's', 't', 'a', 't', 'u', 's', 0xa2, 'O', 'K', 0xa6, 'r', 'e', 's', 'u', 'l', 't', 0x81, 0xae, '_', '_', 'S', 'e', 'r', 'i', 'a', 'l', 'i', 'z', 'e', 'd', '_', '_', 0xc3}, {0xc1}},
				{
					{0x81, 0xa1, 'n', 0x82, 0xa6, 's', 't', 'a', 't', 'u', 's', 0xa2, 'O', 'K', 0xa6, 'r', 'e', 's', 'u', 'l', 't', 0x81, 0xab, '_', '_', 'P', 'i', 'c', 'k', 'l', 'e', 'd', '_', '_', 0x01},
					{0x91, 0x01},
					{0x81, 0xa1, 'x', 0x01},
					{0x81, 0xab, 'p', 'i', 'c', 'k', 'l', 'e', 'd', '-', 'o', 'b', 'j', 0x01},
				},
			},
			wantWrites: 5,
		},
	}

	for _, tc := range sessionCases {
		t.Run(tc.name, func(t *testing.T) {
			seq := &seqFrameRW{replies: tc.replies, failWriteAt: tc.failWriteAt, failReadAt: tc.failReadAt}
			if res, err := runCommSession(seq, "127.0.0.1:8786", 10, 20); err == nil || res != nil {
				t.Errorf("runCommSession() = (%v, %v), want (nil, error)", res, err)
			}
			if tc.wantWrites > 0 && seq.writes != tc.wantWrites {
				t.Errorf("runCommSession() writes = %d, want %d", seq.writes, tc.wantWrites)
			}
		})
	}

	replyGuardTests := []struct {
		name   string
		frames [][]byte
	}{
		{name: "when_frames_empty_returns_false", frames: nil},
		{name: "when_frame_corrupt_msgpack_returns_false", frames: [][]byte{{0xc1}}},
		{name: "when_frame_not_msgpack_map_returns_false", frames: [][]byte{{0x91, 0x01}}},
	}
	for _, tc := range replyGuardTests {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, got := parseIdentityReply(tc.frames); got {
				t.Errorf("parseIdentityReply(%x) = %t, want false", tc.frames, got)
			}
			if len(tc.frames) > 0 {
				if got := isValidHandshakeReply(tc.frames[0]); got {
					t.Errorf("isValidHandshakeReply(%x) = %t, want false", tc.frames[0], got)
				}
			}
			if got := verifyDirectRunReply(tc.frames, 30); got {
				t.Errorf("verifyDirectRunReply(%x, 30) = %t, want false", tc.frames, got)
			}
			if got := verifyBroadcastRunReply(tc.frames, 30); got {
				t.Errorf("verifyBroadcastRunReply(%x, 30) = %t, want false", tc.frames, got)
			}
		})
	}

	statusMapMismatchTests := []struct {
		name        string
		statusMap   map[string]any
		subFrames   [][]byte
		expectedSum int64
	}{
		{
			name:        "when_worker_status_map_missing_result_key_returns_false",
			statusMap:   map[string]any{"status": "OK"},
			expectedSum: 30,
		},
		{
			name:        "when_direct_pickle_bytes_encode_wrong_sum_returns_false",
			statusMap:   map[string]any{"status": "OK", "result": []byte("I999\n.")},
			expectedSum: 30,
		},
		{
			name:        "when_direct_pickle_bytes_are_corrupt_with_zero_expected_sum_returns_false",
			statusMap:   map[string]any{"status": "OK", "result": []byte("corrupt")},
			expectedSum: 0,
		},
		{
			name:        "when_pickled_map_bytes_encode_wrong_sum_returns_false",
			statusMap:   map[string]any{"status": "OK", "result": map[string]any{"__Pickled__": []byte("I999\n.")}},
			expectedSum: 30,
		},
		{
			name:        "when_pickled_map_bytes_are_corrupt_with_zero_expected_sum_returns_false",
			statusMap:   map[string]any{"status": "OK", "result": map[string]any{"__Pickled__": []byte("corrupt")}},
			expectedSum: 0,
		},
		{
			name:        "when_serialized_subframe_encodes_wrong_sum_returns_false",
			statusMap:   map[string]any{"status": "OK", "result": map[string]any{"__Serialized__": true}},
			subFrames:   [][]byte{[]byte("I999\n.")},
			expectedSum: 30,
		},
		{
			name:        "when_serialized_subframe_is_corrupt_with_zero_expected_sum_returns_false",
			statusMap:   map[string]any{"status": "OK", "result": map[string]any{"__Serialized__": true}},
			subFrames:   [][]byte{[]byte("corrupt")},
			expectedSum: 0,
		},
	}
	for _, tc := range statusMapMismatchTests {
		t.Run(tc.name, func(t *testing.T) {
			if got := matchesWorkerStatusMap(tc.statusMap, tc.subFrames, tc.expectedSum); got {
				t.Errorf("matchesWorkerStatusMap(%v, %x, %d) = %t, want false", tc.statusMap, tc.subFrames, tc.expectedSum, got)
			}
		})
	}

	operandTests := []struct {
		name    string
		raw     []byte
		wantA   int32
		wantB   int32
		wantErr bool
	}{
		{
			name:  "when_zero_bytes_returns_min_probe_operands",
			raw:   []byte{0, 0, 0, 0, 0, 0, 0, 0},
			wantA: minProbeOperand,
			wantB: minProbeOperand,
		},
		{
			name:  "when_distinct_uint32_values_maps_modulo_operand_span",
			raw:   []byte{1, 0, 0, 0, 2, 0, 0, 0},
			wantA: minProbeOperand + 1,
			wantB: minProbeOperand + 2,
		},
		{
			name: "when_uint32_equals_or_exceeds_operand_span_wraps_accurately",
			raw: func() []byte {
				var b [8]byte
				binary.LittleEndian.PutUint32(b[0:4], uint32(operandSpan))
				binary.LittleEndian.PutUint32(b[4:8], uint32(operandSpan)+5)
				return b[:]
			}(),
			wantA: minProbeOperand,
			wantB: minProbeOperand + 5,
		},
		{
			name:    "when_reader_returns_fewer_than_8_bytes_returns_error",
			raw:     []byte{1, 2, 3},
			wantErr: true,
		},
	}
	for _, tc := range operandTests {
		t.Run(tc.name, func(t *testing.T) {
			gotA, gotB, err := randomOperandPairFrom(bytes.NewReader(tc.raw))
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Fatalf("randomOperandPairFrom(%x) error = %v, wantErr %t", tc.raw, err, tc.wantErr)
			}
			if !tc.wantErr && (gotA != tc.wantA || gotB != tc.wantB) {
				t.Errorf("randomOperandPairFrom(%x) = (%d, %d), want (%d, %d)", tc.raw, gotA, gotB, tc.wantA, tc.wantB)
			}
		})
	}
}

type fakeDaskBehavior struct {
	daemonType               string
	daemonID                 string
	blockRunFunction         bool
	blockBroadcast           bool
	blockWorkerBroadcastOnly bool
	blockWorkerRun           bool
	resultEncoding           string
	wrongDelta               int64
	fragmentedWS             bool
}

type fakeCommServer struct {
	port      int
	connCount atomic.Int32
	wsPathVal atomic.Value
}

func (s *fakeCommServer) lastPath() string {
	v, _ := s.wsPathVal.Load().(string)
	return v
}

func startFakeTCPCommServer(t *testing.T, useTLS bool, behavior fakeDaskBehavior) *fakeCommServer {
	t.Helper()
	ln, port := listenLoopback(t)
	if useTLS {
		ln = tls.NewListener(ln, testServerTLSConfig(t))
	}

	srv := &fakeCommServer{port: port}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			srv.connCount.Add(1)
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				serveFakeDaskSession(&tcpFrameRW{r: c, w: c}, behavior)
			}(conn)
		}
	}()
	return srv
}

func startFakeWSCommServer(t *testing.T, useTLS bool, behavior fakeDaskBehavior) *fakeCommServer {
	t.Helper()
	srv := &fakeCommServer{}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			http.NotFound(w, r)
			return
		}
		srv.connCount.Add(1)
		srv.wsPathVal.Store(r.URL.RequestURI())
		hj, ok := w.(http.Hijacker)
		if !ok {
			return
		}
		conn, bufrw, err := hj.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = bufrw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n")
		_ = bufrw.Flush()
		serveFakeDaskSession(&serverWSFrameRW{r: bufrw, w: conn, fragmented: behavior.fragmentedWS}, behavior)
	})

	var hs *httptest.Server
	if useTLS {
		hs = httptest.NewTLSServer(handler)
	} else {
		hs = httptest.NewServer(handler)
	}
	t.Cleanup(hs.Close)
	srv.port = serverPort(t, hs.Listener.Addr().String())
	return srv
}

func serveFakeDaskSession(rw frameReadWriter, behavior fakeDaskBehavior) {
	// Step 1: Handshake.
	hs, err := rw.readFrames()
	if err != nil || len(hs) != 1 {
		return
	}
	hsReply := []byte{0x81, 0xaf, 'p', 'i', 'c', 'k', 'l', 'e', '-', 'p', 'r', 'o', 't', 'o', 'c', 'o', 'l', 0x04}
	if err := rw.writeFrames([][]byte{hsReply}); err != nil {
		return
	}

	// Step 2: Identity.
	idReq, err := rw.readFrames()
	if err != nil || len(idReq) != 1 {
		return
	}
	var idBuf bytes.Buffer
	idBuf.WriteByte(0x82)
	writeMPFixStr(&idBuf, "type")
	writeMPFixStr(&idBuf, behavior.daemonType)
	writeMPFixStr(&idBuf, "id")
	writeMPFixStr(&idBuf, behavior.daemonID)
	if err := rw.writeFrames([][]byte{idBuf.Bytes()}); err != nil {
		return
	}

	// Step 3+: RPC commands.
	for {
		cmdFrames, err := rw.readFrames()
		if err != nil || len(cmdFrames) == 0 {
			return
		}
		decoded, err := decodeMsgPack(cmdFrames[0])
		if err != nil {
			return
		}
		cmdMap, ok := decoded.(map[string]any)
		if !ok {
			return
		}
		op, _ := cmdMap["op"].(string)
		switch op {
		case "run_function":
			if behavior.blockRunFunction {
				if err := rw.writeFrames([][]byte{encodeErrorStatusMap()}); err != nil {
					return
				}
				continue
			}
			sum, ok := evalFakeOperatorAdd(cmdMap)
			if !ok {
				return
			}
			_ = rw.writeFrames(encodeRunResultFrames(sum+behavior.wrongDelta, behavior.resultEncoding, false))
			return
		case "run":
			if behavior.blockWorkerRun {
				_ = rw.writeFrames([][]byte{encodeErrorStatusMap()})
				return
			}
			sum, ok := evalFakeOperatorAdd(cmdMap)
			if !ok {
				return
			}
			_ = rw.writeFrames(encodeRunResultFrames(sum+behavior.wrongDelta, behavior.resultEncoding, false))
			return
		case "broadcast":
			nannyFlag, _ := cmdMap["nanny"].(bool)
			if behavior.blockBroadcast || (behavior.blockWorkerBroadcastOnly && !nannyFlag) {
				if err := rw.writeFrames([][]byte{{0x80}}); err != nil {
					return
				}
				continue
			}
			inner, _ := cmdMap["msg"].(map[string]any)
			sum, ok := evalFakeOperatorAdd(inner)
			if !ok {
				return
			}
			_ = rw.writeFrames(encodeRunResultFrames(sum+behavior.wrongDelta, behavior.resultEncoding, true))
			return
		default:
			return
		}
	}
}

func evalFakeOperatorAdd(m map[string]any) (int64, bool) {
	fnBytes, _ := m["function"].([]byte)
	argsBytes, _ := m["args"].([]byte)
	kwargsBytes, _ := m["kwargs"].([]byte)
	if !bytes.Equal(fnBytes, operatorAddPickle) || !bytes.Equal(kwargsBytes, emptyKwargsPickle) {
		return 0, false
	}
	if len(argsBytes) != 16 ||
		argsBytes[0] != 0x80 ||
		argsBytes[1] != 0x02 ||
		argsBytes[2] != 'J' ||
		argsBytes[7] != 'J' ||
		argsBytes[12] != 0x86 ||
		argsBytes[13] != 'q' ||
		argsBytes[14] != 0x00 ||
		argsBytes[15] != '.' {
		return 0, false
	}
	a := int32(binary.LittleEndian.Uint32(argsBytes[3:7]))
	b := int32(binary.LittleEndian.Uint32(argsBytes[8:12]))
	return int64(a) + int64(b), true
}

func encodeErrorStatusMap() []byte {
	var buf bytes.Buffer
	buf.WriteByte(0x82)
	writeMPFixStr(&buf, "status")
	writeMPFixStr(&buf, "error")
	writeMPFixStr(&buf, "text")
	writeMPFixStr(&buf, "blocked")
	return buf.Bytes()
}

func encodeRunResultFrames(sum int64, encoding string, wrapBroadcast bool) [][]byte {
	var pklBuf [10]byte
	pklBuf[0] = 0x80
	pklBuf[1] = 0x04
	pklBuf[2] = 0x8a // LONG1
	pklBuf[3] = 0x05
	for i := 0; i < 5; i++ {
		pklBuf[4+i] = byte(uint64(sum) >> (8 * i))
	}
	pklBuf[9] = '.'
	pkl := pklBuf[:]

	var workerBuf bytes.Buffer
	workerBuf.WriteByte(0x82)
	writeMPFixStr(&workerBuf, "status")
	writeMPFixStr(&workerBuf, "OK")
	writeMPFixStr(&workerBuf, "result")

	var subFrames [][]byte
	switch encoding {
	case "direct_int":
		workerBuf.WriteByte(0xd3) // int64
		var b8 [8]byte
		binary.BigEndian.PutUint64(b8[:], uint64(sum))
		workerBuf.Write(b8[:])
	case "raw_pickle":
		writeMPBin8(&workerBuf, pkl)
	case "serialized_subframe":
		workerBuf.WriteByte(0x81)
		writeMPFixStr(&workerBuf, "__Serialized__")
		workerBuf.WriteByte(0xc3)
		subFrames = append(subFrames, pkl)
	case "pickled_offset_msgpack_subframe":
		workerBuf.WriteByte(0x81)
		writeMPFixStr(&workerBuf, "__Pickled__")
		workerBuf.WriteByte(0x01)
		var sfBuf bytes.Buffer
		sfBuf.WriteByte(0x81)
		writeMPFixStr(&sfBuf, "pickled-obj")
		writeMPBin8(&sfBuf, pkl)
		subFrames = append(subFrames, sfBuf.Bytes())
	default: // "pickled_map"
		workerBuf.WriteByte(0x81)
		writeMPFixStr(&workerBuf, "__Pickled__")
		writeMPBin8(&workerBuf, pkl)
	}

	mainFrame := workerBuf.Bytes()
	if wrapBroadcast {
		var outer bytes.Buffer
		outer.WriteByte(0x81)
		writeMPFixStr(&outer, "tcp://127.0.0.1:41001")
		outer.Write(mainFrame)
		mainFrame = outer.Bytes()
	}
	return append([][]byte{mainFrame}, subFrames...)
}

type serverWSFrameRW struct {
	r          io.Reader
	w          io.Writer
	fragmented bool
}

func (s *serverWSFrameRW) readFrames() ([][]byte, error) {
	rw := &wsFrameRW{r: s.r, w: s.w}
	return rw.readFrames()
}

func (s *serverWSFrameRW) writeFrames(frames [][]byte) error {
	var countBuf [8]byte
	binary.LittleEndian.PutUint64(countBuf[:], uint64(len(frames)))
	if err := s.writeUnmaskedWS(countBuf[:]); err != nil {
		return err
	}
	for _, f := range frames {
		if err := s.writeUnmaskedWS(f); err != nil {
			return err
		}
	}
	return nil
}

func (s *serverWSFrameRW) writeUnmaskedWS(payload []byte) error {
	if s.fragmented && len(payload) > 4 {
		// Interleave a Ping frame between two binary fragments.
		mid := len(payload) / 2
		var buf bytes.Buffer
		buf.Write([]byte{0x02, byte(mid)})
		buf.Write(payload[:mid])
		buf.Write([]byte{0x89, 0x02, 'p', 'g'})
		buf.Write([]byte{0x80, byte(len(payload) - mid)})
		buf.Write(payload[mid:])
		_, err := s.w.Write(buf.Bytes())
		return err
	}

	var buf bytes.Buffer
	buf.WriteByte(0x82)
	if len(payload) < 126 {
		buf.WriteByte(byte(len(payload)))
	} else {
		buf.WriteByte(126)
		var ext [2]byte
		binary.BigEndian.PutUint16(ext[:], uint16(len(payload)))
		buf.Write(ext[:])
	}
	buf.Write(payload)
	_, err := s.w.Write(buf.Bytes())
	return err
}

func testServerTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	probeSrv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	probeSrv.StartTLS()
	tlsCfg := probeSrv.TLS.Clone()
	probeSrv.Close()
	return tlsCfg
}

func listenLoopback(t *testing.T) (net.Listener, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() failed: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln, ln.Addr().(*net.TCPAddr).Port
}

func serverPort(t *testing.T, addr string) int {
	t.Helper()
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("net.SplitHostPort(%q) failed: %v", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("strconv.Atoi(%q) failed: %v", portStr, err)
	}
	return port
}

func newService(host string, port int, serviceName string, httpMethods []string, sslVersions []string) *nspb.NetworkService {
	ep := netendpoint.FromString(host)
	if port > 0 {
		withPort, _ := netendpoint.WithPort(ep, uint32(port))
		ep = withPort
	}
	return nspb.NetworkService_builder{
		NetworkEndpoint:      ep,
		TransportProtocol:    npb.TransportProtocol_TCP,
		ServiceName:          serviceName,
		SupportedHttpMethods: httpMethods,
		SupportedSslVersions: sslVersions,
	}.Build()
}

func appendUint64LE(dst []byte, vals ...uint64) []byte {
	var tmp [8]byte
	for _, v := range vals {
		binary.LittleEndian.PutUint64(tmp[:], v)
		dst = append(dst, tmp[:]...)
	}
	return dst
}

type seqFrameRW struct {
	replies     [][][]byte
	writes      int
	reads       int
	failWriteAt int
	failReadAt  int
}

func (s *seqFrameRW) writeFrames([][]byte) error {
	s.writes++
	if s.failWriteAt == s.writes {
		return errors.New("simulated write error")
	}
	return nil
}

func (s *seqFrameRW) readFrames() ([][]byte, error) {
	s.reads++
	if s.failReadAt == s.reads {
		var fallback [][]byte
		if s.reads-1 < len(s.replies) {
			fallback = s.replies[s.reads-1]
		}
		return fallback, errors.New("simulated read error")
	}
	if s.reads-1 >= len(s.replies) {
		return nil, io.EOF
	}
	return s.replies[s.reads-1], nil
}

type failWriter struct {
	calls      int
	failOnCall int
}

func (f *failWriter) Write(p []byte) (int, error) {
	f.calls++
	if f.calls == f.failOnCall {
		return 0, errors.New("simulated write failure")
	}
	return len(p), nil
}
