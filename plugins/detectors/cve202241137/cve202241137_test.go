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

package cve202241137

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
	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/net/netendpoint"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"

	cpb "github.com/google/goonami-scanner/core/config/config_go_proto"
	dpb "github.com/google/tsunami-security-scanner/proto/go/detection_go_proto"
	npb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
	vpb "github.com/google/tsunami-security-scanner/proto/go/vulnerability_go_proto"
)

func TestNew(t *testing.T) {
	testCases := []struct {
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
			name:        "when_default_config_uses_proto_default_timeout",
			cfg:         config.Default(),
			wantTimeout: 10 * time.Second,
		},
		{
			name: "when_custom_timeout_applies_timeout",
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

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			detector, err := New(t.Context(), tc.cfg)
			if err != nil {
				t.Fatalf("New() unexpected error: %v", err)
			}
			if detector == nil {
				t.Fatal("New() returned nil detector")
			}
			if got := detector.Name(); got != moduleName {
				t.Errorf("detector.Name() = %q, want %q", got, moduleName)
			}
			if got := detector.(*Module).timeout; got != tc.wantTimeout {
				t.Errorf("detector.timeout = %v, want %v", got, tc.wantTimeout)
			}
		})
	}
}

func TestDetect(t *testing.T) {
	hive4ControlReply := buildMetaExceptionReplyBytes(
		controlSeqID,
		thriftMethodName,
		thriftTypeStruct, 1,
		thriftTypeString, 1,
		"Buffer underflow.\nSerialization trace:\nchidren (org.apache.hadoop.hive.ql.plan.ExprNodeGenericFuncDesc)",
	)
	hive23ControlReply := buildMetaExceptionReplyBytes(
		controlSeqID,
		thriftMethodName,
		thriftTypeStruct, 1,
		thriftTypeString, 1,
		"Encountered unregistered class ID: 109\nSerialization trace:\ngenericUDF (org.apache.hadoop.hive.ql.plan.ExprNodeGenericFuncDesc)",
	)
	vulnerableTreeMapMsg := "java.lang.ClassCastException: java.util.ArrayList cannot be cast to java.lang.Comparable\nSerialization trace:\nchidren (org.apache.hadoop.hive.ql.plan.ExprNodeGenericFuncDesc)"
	vulnerableTreeMapReply := buildMetaExceptionReplyBytes(
		vulnSeqID,
		thriftMethodName,
		thriftTypeStruct, 1,
		thriftTypeString, 1,
		vulnerableTreeMapMsg,
	)
	patchedTreeMapReply := buildMetaExceptionReplyBytes(
		vulnSeqID,
		thriftMethodName,
		thriftTypeStruct, 1,
		thriftTypeString, 1,
		"java.lang.UnsupportedOperationException: Class java.util.TreeMap is not allowed for deserialization",
	)

	testCases := []struct {
		name           string
		serviceName    string
		step1Resp      []byte
		step2Resp      []byte
		wantStep2Probe []byte
		wantFindings   bool
	}{
		{
			name:           "when_vulnerable_hive4_metastore_returns_verified_finding",
			serviceName:    "unknown",
			step1Resp:      hive4ControlReply,
			step2Resp:      vulnerableTreeMapReply,
			wantStep2Probe: hive4NestedTreeMapExpr,
			wantFindings:   true,
		},
		{
			name:           "when_vulnerable_hive23_metastore_returns_verified_finding",
			serviceName:    "hive-metastore",
			step1Resp:      hive23ControlReply,
			step2Resp:      vulnerableTreeMapReply,
			wantStep2Probe: hive23NestedTreeMapExpr,
			wantFindings:   true,
		},
		{
			name:         "when_patched_hive_metastore_rejects_nested_treemap_returns_no_findings",
			serviceName:  "hive-metastore",
			step1Resp:    hive4ControlReply,
			step2Resp:    patchedTreeMapReply,
			wantFindings: false,
		},
		{
			name:        "when_second_probe_returns_unexpected_exception_returns_no_findings",
			serviceName: "thrift",
			step1Resp:   hive4ControlReply,
			step2Resp: buildMetaExceptionReplyBytes(
				vulnSeqID,
				thriftMethodName,
				thriftTypeStruct, 1,
				thriftTypeString, 1,
				"NoSuchObjectException: default.tsunami_probe table not found",
			),
			wantFindings: false,
		},
		{
			name:        "when_control_probe_returns_cast_exception_honeypot_returns_no_findings",
			serviceName: "unknown",
			step1Resp: buildMetaExceptionReplyBytes(
				controlSeqID,
				thriftMethodName,
				thriftTypeStruct, 1,
				thriftTypeString, 1,
				"org.apache.hadoop.hive.ql.plan.ExprNodeGenericFuncDesc cannot be cast to",
			),
			wantFindings: false,
		},
		{
			name:         "when_non_thrift_banner_returns_no_findings",
			serviceName:  "unknown",
			step1Resp:    []byte("HTTP/1.1 400 Bad Request\r\n\r\n"),
			wantFindings: false,
		},
		{
			name:        "when_thrift_method_name_mismatch_returns_no_findings",
			serviceName: "unknown",
			step1Resp: buildMetaExceptionReplyBytes(
				controlSeqID,
				"other_22_byte_method__",
				thriftTypeStruct, 1,
				thriftTypeString, 1,
				controlExpectedExprNode,
			),
			wantFindings: false,
		},
		{
			name:        "when_thrift_seqid_mismatch_returns_no_findings",
			serviceName: "unknown",
			step1Resp: buildMetaExceptionReplyBytes(
				99,
				thriftMethodName,
				thriftTypeStruct, 1,
				thriftTypeString, 1,
				controlExpectedExprNode,
			),
			wantFindings: false,
		},
		{
			name:        "when_thrift_outer_field_not_struct_returns_no_findings",
			serviceName: "unknown",
			step1Resp: buildMetaExceptionReplyBytes(
				controlSeqID,
				thriftMethodName,
				thriftTypeStop, 1,
				thriftTypeString, 1,
				controlExpectedExprNode,
			),
			wantFindings: false,
		},
		{
			name:        "when_thrift_inner_field_not_string_returns_no_findings",
			serviceName: "unknown",
			step1Resp: buildMetaExceptionReplyBytes(
				controlSeqID,
				thriftMethodName,
				thriftTypeStruct, 1,
				thriftTypeStop, 1,
				controlExpectedExprNode,
			),
			wantFindings: false,
		},
		{
			name:         "when_second_probe_connection_closes_early_returns_no_findings",
			serviceName:  "unknown",
			step1Resp:    hive4ControlReply,
			step2Resp:    nil,
			wantFindings: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var req1, req2 []byte
			svc := startFakeThriftServer(t, tc.serviceName, func(conn net.Conn, callNum int32) {
				req := readClientRequest(conn)
				if callNum == 1 {
					req1 = req
					_, _ = conn.Write(tc.step1Resp)
					return
				}
				req2 = req
				if tc.step2Resp != nil {
					_, _ = conn.Write(tc.step2Resp)
				}
			})

			detector, err := New(t.Context(), config.Default())
			if err != nil {
				t.Fatalf("New() unexpected error: %v", err)
			}

			reports, err := detector.Detect(t.Context(), svc)
			if err != nil {
				t.Fatalf("Detect() unexpected error: %v", err)
			}

			if !bytes.Contains(req1, []byte(thriftMethodName)) {
				t.Errorf("step 1 request missing method %q: %x", thriftMethodName, req1)
			}

			if tc.wantFindings {
				if !bytes.Contains(req2, tc.wantStep2Probe) {
					t.Errorf("step 2 request missing expected Kryo payload %x: %x", tc.wantStep2Probe, req2)
				}
				want := buildDetectionReport(svc, vulnerableTreeMapMsg)
				if diff := cmp.Diff(want, reports, protocmp.Transform(), protocmp.IgnoreFields(&dpb.DetectionReport{}, "detection_timestamp")); diff != "" {
					t.Errorf("Detect() reports diff (-want +got):\n%s", diff)
				}
				return
			}

			if reports != nil && len(reports.GetDetectionReports()) > 0 {
				t.Errorf("Detect() returned unexpected reports: %v", reports)
			}
		})
	}
}

func TestDetectHive23TableDiscoveryFallback(t *testing.T) {
	noSuchObjectReply := buildMetaExceptionReplyBytes(
		controlSeqID,
		thriftMethodName,
		thriftTypeStruct, 2,
		thriftTypeString, 1,
		"hive.default.tsunami_probe table not found",
	)
	manyTables := make([]string, 40)
	manyTables[0] = "sample_tbl"
	for i := 1; i < len(manyTables); i++ {
		manyTables[i] = "extra_tbl"
	}
	listDBsReply := buildStringListReplyBytes(listDBsSeqID, thriftGetAllDBsMethod, []string{"default"})
	listTblsReply := buildStringListReplyBytes(listTblsSeqID, thriftGetAllTblsMethod, manyTables)
	hive23ControlReply := buildMetaExceptionReplyBytes(
		controlSeqID,
		thriftMethodName,
		thriftTypeStruct, 1,
		thriftTypeString, 1,
		"Encountered unregistered class ID: 109\nSerialization trace:\ngenericUDF (org.apache.hadoop.hive.ql.plan.ExprNodeGenericFuncDesc)",
	)
	vulnerableTreeMapMsg := "java.lang.ClassCastException: java.util.ArrayList cannot be cast to java.lang.Comparable\nSerialization trace:\nchidren (org.apache.hadoop.hive.ql.plan.ExprNodeGenericFuncDesc)"
	vulnerableTreeMapReply := buildMetaExceptionReplyBytes(
		vulnSeqID,
		thriftMethodName,
		thriftTypeStruct, 1,
		thriftTypeString, 1,
		vulnerableTreeMapMsg,
	)

	var seenRequests [][]byte
	svc := startFakeThriftServer(t, "hive-metastore", func(conn net.Conn, callNum int32) {
		req := readClientRequest(conn)
		seenRequests = append(seenRequests, req)
		switch callNum {
		case 1:
			_, _ = conn.Write(noSuchObjectReply)
		case 2:
			_, _ = conn.Write(listDBsReply)
		case 3:
			_, _ = conn.Write(listTblsReply)
		case 4:
			_, _ = conn.Write(hive23ControlReply)
		case 5:
			_, _ = conn.Write(vulnerableTreeMapReply)
		}
	})

	detector, err := New(t.Context(), config.Default())
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}

	reports, err := detector.Detect(t.Context(), svc)
	if err != nil {
		t.Fatalf("Detect() unexpected error: %v", err)
	}

	want := buildDetectionReport(svc, vulnerableTreeMapMsg)
	if diff := cmp.Diff(want, reports, protocmp.Transform(), protocmp.IgnoreFields(&dpb.DetectionReport{}, "detection_timestamp")); diff != "" {
		t.Errorf("Detect() reports diff (-want +got):\n%s", diff)
	}
	if len(seenRequests) != 5 {
		t.Fatalf("len(seenRequests) = %d, want 5", len(seenRequests))
	}
	if !bytes.Contains(seenRequests[4], []byte("sample_tbl")) || !bytes.Contains(seenRequests[4], hive23NestedTreeMapExpr) {
		t.Errorf("step 5 request missing discovered table sample_tbl or hive23NestedTreeMapExpr: %x", seenRequests[4])
	}
}

func buildStringListReplyBytes(seqID uint32, method string, items []string) []byte {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.BigEndian, thriftVersion1Reply)
	writeThriftString(&buf, []byte(method))
	_ = binary.Write(&buf, binary.BigEndian, seqID)
	buf.WriteByte(thriftTypeList)
	_ = binary.Write(&buf, binary.BigEndian, uint16(0))
	buf.WriteByte(thriftTypeString)
	_ = binary.Write(&buf, binary.BigEndian, uint32(len(items)))
	for _, item := range items {
		writeThriftString(&buf, []byte(item))
	}
	buf.WriteByte(thriftTypeStop)
	return buf.Bytes()
}

func TestDetectServiceFilteringAndErrors(t *testing.T) {
	vulnerableControlReply := buildMetaExceptionReplyBytes(
		controlSeqID,
		thriftMethodName,
		thriftTypeStruct, 1,
		thriftTypeString, 1,
		"Buffer underflow.\nSerialization trace:\nchidren (org.apache.hadoop.hive.ql.plan.ExprNodeGenericFuncDesc)",
	)

	testCases := []struct {
		name              string
		svc               *nspb.NetworkService
		cancelBeforeStart bool
		cancelOnProbeStep int32
		wantErr           error
	}{
		{
			name: "when_web_service_returns_no_findings",
			svc: nspb.NetworkService_builder{
				ServiceName:          "http",
				SupportedHttpMethods: []string{"GET"},
				NetworkEndpoint: npb.NetworkEndpoint_builder{
					Type: npb.NetworkEndpoint_IP_PORT,
					IpAddress: npb.IpAddress_builder{
						Address: "127.0.0.1",
					}.Build(),
					Port: npb.Port_builder{
						PortNumber: 9083,
					}.Build(),
				}.Build(),
			}.Build(),
		},
		{
			name: "when_udp_service_returns_no_findings",
			svc: nspb.NetworkService_builder{
				ServiceName:       "thrift",
				TransportProtocol: npb.TransportProtocol_UDP,
				NetworkEndpoint: npb.NetworkEndpoint_builder{
					Type: npb.NetworkEndpoint_IP_PORT,
					IpAddress: npb.IpAddress_builder{
						Address: "127.0.0.1",
					}.Build(),
					Port: npb.Port_builder{
						PortNumber: 9083,
					}.Build(),
				}.Build(),
			}.Build(),
		},
		{
			name: "when_unrelated_service_name_returns_no_findings",
			svc: nspb.NetworkService_builder{
				ServiceName:       "ssh",
				TransportProtocol: npb.TransportProtocol_TCP,
				NetworkEndpoint: npb.NetworkEndpoint_builder{
					Type: npb.NetworkEndpoint_IP_PORT,
					IpAddress: npb.IpAddress_builder{
						Address: "127.0.0.1",
					}.Build(),
					Port: npb.Port_builder{
						PortNumber: 22,
					}.Build(),
				}.Build(),
			}.Build(),
		},
		{
			name: "when_tcpwrapped_on_non_metastore_port_returns_no_findings",
			svc: nspb.NetworkService_builder{
				ServiceName:       "tcpwrapped",
				TransportProtocol: npb.TransportProtocol_TCP,
				NetworkEndpoint: npb.NetworkEndpoint_builder{
					Type: npb.NetworkEndpoint_IP_PORT,
					IpAddress: npb.IpAddress_builder{
						Address: "127.0.0.1",
					}.Build(),
					Port: npb.Port_builder{
						PortNumber: 22,
					}.Build(),
				}.Build(),
			}.Build(),
		},
		{
			name: "when_invalid_network_endpoint_returns_error",
			svc: nspb.NetworkService_builder{
				ServiceName:     "thrift",
				NetworkEndpoint: npb.NetworkEndpoint_builder{}.Build(),
			}.Build(),
			wantErr: netendpoint.ErrEndpointMissingAddress,
		},
		{
			name: "when_context_canceled_before_start_returns_error",
			svc: nspb.NetworkService_builder{
				ServiceName: "thrift",
			}.Build(),
			cancelBeforeStart: true,
			wantErr:           context.Canceled,
		},
		{
			name:              "when_context_canceled_during_first_probe_returns_error",
			cancelOnProbeStep: 1,
			wantErr:           context.Canceled,
		},
		{
			name:              "when_context_canceled_during_second_probe_returns_error",
			cancelOnProbeStep: 2,
			wantErr:           context.Canceled,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if tc.cancelBeforeStart {
				cancel()
			}

			svc := tc.svc
			if tc.cancelOnProbeStep > 0 {
				svc = startFakeThriftServer(t, "unknown", func(conn net.Conn, callNum int32) {
					_ = readClientRequest(conn)
					if callNum < tc.cancelOnProbeStep {
						_, _ = conn.Write(vulnerableControlReply)
						return
					}
					cancel()
				})
			}

			detector, err := New(ctx, config.Default())
			if err != nil {
				t.Fatalf("New() unexpected error: %v", err)
			}

			reports, err := detector.Detect(ctx, svc)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Detect() error = %v, want %v", err, tc.wantErr)
			}
			if reports != nil && len(reports.GetDetectionReports()) > 0 {
				t.Errorf("Detect() returned unexpected reports: %v", reports)
			}
		})
	}
}

func TestReadMetaExceptionReplyTruncatedInputs(t *testing.T) {
	fullValid := buildMetaExceptionReplyBytes(
		controlSeqID,
		thriftMethodName,
		thriftTypeStruct, 1,
		thriftTypeString, 1,
		controlExpectedExprNode,
	)

	testCases := []struct {
		name  string
		input []byte
	}{
		{
			name:  "when_empty_stream_returns_error",
			input: nil,
		},
		{
			name:  "when_truncated_method_name_returns_error",
			input: fullValid[:12],
		},
		{
			name:  "when_truncated_outer_field_returns_error",
			input: fullValid[:35],
		},
		{
			name:  "when_truncated_inner_field_returns_error",
			input: fullValid[:40],
		},
		{
			name:  "when_truncated_message_body_returns_error",
			input: fullValid[:len(fullValid)-3],
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := readMetaExceptionReply(bytes.NewReader(tc.input), controlSeqID)
			if err == nil || (!errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF)) {
				t.Errorf("readMetaExceptionReply() error = %v, want EOF/ErrUnexpectedEOF", err)
			}
		})
	}
}

func TestAdvisories(t *testing.T) {
	want := []*vpb.Vulnerability{baseVulnerability()}

	testCases := []struct {
		name string
	}{
		{
			name: "when_initialized_with_default_config_returns_base_advisory",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			m, err := New(t.Context(), config.Default())
			if err != nil {
				t.Fatalf("New() failed: %v", err)
			}

			got := m.Advisories()
			if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
				t.Errorf("Advisories() mismatch (-want +got):\n%s", diff)
			}

			if len(got) > 0 {
				got[0].SetTitle("mutated title")
				second := m.Advisories()
				if second[0].GetTitle() == "mutated title" {
					t.Errorf("Advisories() returned a mutable reference, expected an isolated clone")
				}
			}
		})
	}
}

func buildMetaExceptionReplyBytes(seqID uint32, method string, outerType byte, outerID uint16, innerType byte, innerID uint16, msg string) []byte {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.BigEndian, thriftVersion1Reply)
	writeThriftString(&buf, []byte(method))
	_ = binary.Write(&buf, binary.BigEndian, seqID)
	buf.WriteByte(outerType)
	_ = binary.Write(&buf, binary.BigEndian, outerID)
	buf.WriteByte(innerType)
	_ = binary.Write(&buf, binary.BigEndian, innerID)
	writeThriftString(&buf, []byte(msg))
	buf.WriteByte(thriftTypeStop)
	buf.WriteByte(thriftTypeStop)
	return buf.Bytes()
}

func startFakeThriftServer(t *testing.T, serviceName string, handler func(conn net.Conn, callNum int32)) *nspb.NetworkService {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen failed: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	var calls atomic.Int32
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			n := calls.Add(1)
			go func(c net.Conn, num int32) {
				defer c.Close()
				handler(c, num)
			}(conn, n)
		}
	}()

	port := listener.Addr().(*net.TCPAddr).Port
	return nspb.NetworkService_builder{
		ServiceName:       serviceName,
		TransportProtocol: npb.TransportProtocol_TCP,
		NetworkEndpoint: npb.NetworkEndpoint_builder{
			Type: npb.NetworkEndpoint_IP_PORT,
			IpAddress: npb.IpAddress_builder{
				Address:       "127.0.0.1",
				AddressFamily: npb.AddressFamily_IPV4,
			}.Build(),
			Port: npb.Port_builder{
				PortNumber: uint32(port),
			}.Build(),
		}.Build(),
	}.Build()
}

func readClientRequest(conn net.Conn) []byte {
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n <= 0 {
		return nil
	}
	return buf[:n]
}
