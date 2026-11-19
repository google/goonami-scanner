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
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
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

			allDetectors, regErr := module.AllDetectors(t.Context(), tc.cfg)
			if regErr != nil {
				t.Fatalf("module.AllDetectors() unexpected error: %v", regErr)
			}
			foundSelf := false
			for _, d := range allDetectors {
				if d.Name() == moduleName {
					foundSelf = true
					break
				}
			}
			if !foundSelf {
				t.Errorf("module.AllDetectors() missing %q", moduleName)
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
	patchedMustBeExprNodeReply := buildMetaExceptionReplyBytes(
		vulnSeqID,
		thriftMethodName,
		thriftTypeStruct, 1,
		thriftTypeString, 1,
		"MetaException(message:The object to be deserialized must be an ExprNodeDesc; java.util.ArrayList cannot be cast to java.lang.Comparable org.apache.hadoop.hive.ql.plan.ExprNodeGenericFuncDesc)",
	)

	testCases := []struct {
		name           string
		serviceName    string
		transport      npb.TransportProtocol
		sslVersions    []string
		serverTLS      bool
		step1Resp      []byte
		step2Resp      []byte
		wantStep2Probe []byte
		wantFindings   bool
	}{
		{
			name:           "when_vulnerable_hive4_metastore_returns_verified_finding",
			serviceName:    "unknown",
			transport:      npb.TransportProtocol_TCP,
			step1Resp:      hive4ControlReply,
			step2Resp:      vulnerableTreeMapReply,
			wantStep2Probe: hive4NestedTreeMapExpr,
			wantFindings:   true,
		},
		{
			name:           "when_vulnerable_hive23_metastore_returns_verified_finding",
			serviceName:    "hive-metastore",
			transport:      npb.TransportProtocol_TCP,
			step1Resp:      hive23ControlReply,
			step2Resp:      vulnerableTreeMapReply,
			wantStep2Probe: hive23NestedTreeMapExpr,
			wantFindings:   true,
		},
		{
			name:           "when_non_standard_service_name_and_unspecified_transport_on_ephemeral_port_returns_verified_finding",
			serviceName:    "ssh",
			transport:      npb.TransportProtocol_TRANSPORT_PROTOCOL_UNSPECIFIED,
			step1Resp:      hive4ControlReply,
			step2Resp:      vulnerableTreeMapReply,
			wantStep2Probe: hive4NestedTreeMapExpr,
			wantFindings:   true,
		},
		{
			name:           "when_tcpwrapped_service_on_non_standard_port_returns_verified_finding",
			serviceName:    "tcpwrapped",
			transport:      npb.TransportProtocol_TCP,
			step1Resp:      hive23ControlReply,
			step2Resp:      vulnerableTreeMapReply,
			wantStep2Probe: hive23NestedTreeMapExpr,
			wantFindings:   true,
		},
		{
			name:           "when_vulnerable_tls_hive4_metastore_on_non_standard_port_returns_verified_finding",
			serviceName:    "tcpwrapped",
			transport:      npb.TransportProtocol_TCP,
			sslVersions:    []string{"TLSv1.3"},
			serverTLS:      true,
			step1Resp:      hive4ControlReply,
			step2Resp:      vulnerableTreeMapReply,
			wantStep2Probe: hive4NestedTreeMapExpr,
			wantFindings:   true,
		},
		{
			name:           "when_vulnerable_tls_hive23_metastore_with_empty_service_name_returns_verified_finding",
			serviceName:    "",
			transport:      npb.TransportProtocol_TRANSPORT_PROTOCOL_UNSPECIFIED,
			sslVersions:    []string{"TLSv1.2"},
			serverTLS:      true,
			step1Resp:      hive23ControlReply,
			step2Resp:      vulnerableTreeMapReply,
			wantStep2Probe: hive23NestedTreeMapExpr,
			wantFindings:   true,
		},
		{
			name:         "when_patched_hive_metastore_rejects_nested_treemap_returns_no_findings",
			serviceName:  "hive-metastore",
			transport:    npb.TransportProtocol_TCP,
			step1Resp:    hive4ControlReply,
			step2Resp:    patchedTreeMapReply,
			wantFindings: false,
		},
		{
			name:         "when_patched_tls_hive_metastore_enforces_expr_node_desc_returns_no_findings",
			serviceName:  "custom-thrift",
			transport:    npb.TransportProtocol_TCP,
			sslVersions:  []string{"TLSv1.3"},
			serverTLS:    true,
			step1Resp:    hive4ControlReply,
			step2Resp:    patchedMustBeExprNodeReply,
			wantFindings: false,
		},
		{
			name:        "when_tls_service_connects_to_plaintext_banner_server_returns_no_findings",
			serviceName: "ssh",
			transport:   npb.TransportProtocol_TCP,
			sslVersions: []string{"TLSv1.3"},
			serverTLS:   false,
			step1Resp:   []byte("SSH-2.0-OpenSSH_9.6\r\n"),
		},
		{
			name:        "when_plaintext_service_connects_to_tls_server_returns_no_findings",
			serviceName: "unknown",
			transport:   npb.TransportProtocol_TCP,
			sslVersions: nil,
			serverTLS:   true,
			step1Resp:   hive4ControlReply,
			step2Resp:   vulnerableTreeMapReply,
		},
		{
			name:        "when_second_probe_returns_unexpected_exception_returns_no_findings",
			serviceName: "thrift",
			transport:   npb.TransportProtocol_TCP,
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
			transport:   npb.TransportProtocol_TCP,
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
			transport:    npb.TransportProtocol_TCP,
			step1Resp:    []byte("HTTP/1.1 400 Bad Request\r\n\r\n"),
			wantFindings: false,
		},
		{
			name:        "when_thrift_method_name_mismatch_returns_no_findings",
			serviceName: "unknown",
			transport:   npb.TransportProtocol_TCP,
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
			transport:   npb.TransportProtocol_TCP,
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
			transport:   npb.TransportProtocol_TCP,
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
			transport:   npb.TransportProtocol_TCP,
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
			transport:    npb.TransportProtocol_TCP,
			step1Resp:    hive4ControlReply,
			step2Resp:    nil,
			wantFindings: false,
		},
	}

	cert := generateSelfSignedCert(t)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var (
				mu         sync.Mutex
				accepts    atomic.Int32
				req1, req2 []byte
			)
			var serverTLS *tls.Config
			if tc.serverTLS {
				serverTLS = &tls.Config{Certificates: []tls.Certificate{cert}}
			}

			svc := startFakeThriftServerWithOptions(t, fakeServerOptions{
				serviceName: tc.serviceName,
				transport:   tc.transport,
				sslVersions: tc.sslVersions,
				tlsConfig:   serverTLS,
				onAccept:    func() { accepts.Add(1) },
			}, func(conn net.Conn, callNum int32) {
				req := readClientRequest(conn)
				mu.Lock()
				if callNum == 1 {
					req1 = req
				} else if callNum == 2 {
					req2 = req
				}
				mu.Unlock()

				if callNum == 1 {
					if tc.step1Resp != nil {
						_, _ = conn.Write(tc.step1Resp)
					}
					return
				}
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

			if accepts.Load() == 0 {
				t.Fatalf("Detect() server accepts = 0, want >= 1")
			}

			mu.Lock()
			gotReq1 := req1
			gotReq2 := req2
			mu.Unlock()

			tlsModesMatch := (len(tc.sslVersions) > 0) == tc.serverTLS
			if tlsModesMatch {
				if !bytes.Contains(gotReq1, []byte(thriftMethodName)) {
					t.Errorf("step 1 request missing method %q: %x", thriftMethodName, gotReq1)
				}
			}

			if tc.wantFindings {
				if !bytes.Contains(gotReq2, tc.wantStep2Probe) {
					t.Errorf("step 2 request missing expected Kryo payload %x: %x", tc.wantStep2Probe, gotReq2)
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

	cert := generateSelfSignedCert(t)

	testCases := []struct {
		name           string
		serviceName    string
		transport      npb.TransportProtocol
		useTLS         bool
		closeAfterCall int32
		replies        [][]byte
		wantCalls      int
		wantFindings   bool
	}{
		{
			name:        "when_plaintext_hive23_requires_existing_table_discovers_table_and_returns_finding",
			serviceName: "hive-metastore",
			transport:   npb.TransportProtocol_TCP,
			useTLS:      false,
			replies: [][]byte{
				noSuchObjectReply,
				buildStringListReplyBytes(listDBsSeqID, thriftGetAllDBsMethod, []string{"default"}),
				buildStringListReplyBytes(listTblsSeqID, thriftGetAllTblsMethod, manyTables),
				hive23ControlReply,
				vulnerableTreeMapReply,
			},
			wantCalls:    5,
			wantFindings: true,
		},
		{
			name:        "when_tls_hive23_with_empty_db_list_falls_back_to_default_db_and_returns_finding",
			serviceName: "ssh",
			transport:   npb.TransportProtocol_TRANSPORT_PROTOCOL_UNSPECIFIED,
			useTLS:      true,
			replies: [][]byte{
				noSuchObjectReply,
				buildStringListReplyBytes(listDBsSeqID, thriftGetAllDBsMethod, nil),
				buildStringListReplyBytes(listTblsSeqID, thriftGetAllTblsMethod, []string{"sample_tbl"}),
				hive23ControlReply,
				vulnerableTreeMapReply,
			},
			wantCalls:    5,
			wantFindings: true,
		},
		{
			name:        "when_tls_hive23_discovers_no_tables_returns_no_findings",
			serviceName: "tcpwrapped",
			transport:   npb.TransportProtocol_TCP,
			useTLS:      true,
			replies: [][]byte{
				noSuchObjectReply,
				buildStringListReplyBytes(listDBsSeqID, thriftGetAllDBsMethod, []string{"empty_db"}),
				buildStringListReplyBytes(listTblsSeqID, thriftGetAllTblsMethod, nil),
			},
			wantCalls:    3,
			wantFindings: false,
		},
		{
			name:        "when_get_all_databases_returns_invalid_reply_returns_no_findings",
			serviceName: "unknown",
			transport:   npb.TransportProtocol_TCP,
			useTLS:      false,
			replies: [][]byte{
				noSuchObjectReply,
				[]byte("not-thrift"),
			},
			wantCalls:    2,
			wantFindings: false,
		},
		{
			name:           "when_listener_closes_before_get_all_databases_dial_returns_no_findings",
			serviceName:    "unknown",
			transport:      npb.TransportProtocol_TCP,
			useTLS:         true,
			closeAfterCall: 1,
			replies: [][]byte{
				noSuchObjectReply,
			},
			wantCalls:    1,
			wantFindings: false,
		},
		{
			name:        "when_retry_control_probe_after_table_discovery_closes_early_returns_no_findings",
			serviceName: "unknown",
			transport:   npb.TransportProtocol_TCP,
			useTLS:      true,
			replies: [][]byte{
				noSuchObjectReply,
				buildStringListReplyBytes(listDBsSeqID, thriftGetAllDBsMethod, []string{"default"}),
				buildStringListReplyBytes(listTblsSeqID, thriftGetAllTblsMethod, []string{"sample_tbl"}),
				nil,
			},
			wantCalls:    4,
			wantFindings: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var (
				mu           sync.Mutex
				seenRequests [][]byte
				sslVersions  []string
				serverTLS    *tls.Config
				listenerRef  io.Closer
			)
			if tc.useTLS {
				sslVersions = []string{"TLSv1.3"}
				serverTLS = &tls.Config{Certificates: []tls.Certificate{cert}}
			}

			svc := startFakeThriftServerWithOptions(t, fakeServerOptions{
				serviceName: tc.serviceName,
				transport:   tc.transport,
				sslVersions: sslVersions,
				tlsConfig:   serverTLS,
				onListen:    func(c io.Closer) { listenerRef = c },
			}, func(conn net.Conn, callNum int32) {
				req := readClientRequest(conn)
				mu.Lock()
				seenRequests = append(seenRequests, req)
				mu.Unlock()
				if tc.closeAfterCall > 0 && callNum == tc.closeAfterCall && listenerRef != nil {
					_ = listenerRef.Close()
				}
				if idx := int(callNum - 1); idx < len(tc.replies) && tc.replies[idx] != nil {
					_, _ = conn.Write(tc.replies[idx])
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

			mu.Lock()
			gotRequests := append([][]byte(nil), seenRequests...)
			mu.Unlock()

			if len(gotRequests) != tc.wantCalls {
				t.Fatalf("len(seenRequests) = %d, want %d", len(gotRequests), tc.wantCalls)
			}

			if tc.wantFindings {
				want := buildDetectionReport(svc, vulnerableTreeMapMsg)
				if diff := cmp.Diff(want, reports, protocmp.Transform(), protocmp.IgnoreFields(&dpb.DetectionReport{}, "detection_timestamp")); diff != "" {
					t.Errorf("Detect() reports diff (-want +got):\n%s", diff)
				}
				if !bytes.Contains(gotRequests[4], []byte("sample_tbl")) || !bytes.Contains(gotRequests[4], hive23NestedTreeMapExpr) {
					t.Errorf("step 5 request missing discovered table sample_tbl or hive23NestedTreeMapExpr: %x", gotRequests[4])
				}
				return
			}

			if reports != nil && len(reports.GetDetectionReports()) > 0 {
				t.Errorf("Detect() returned unexpected reports: %v", reports)
			}
		})
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

func TestDetectServiceFiltering(t *testing.T) {
	testCases := []struct {
		name        string
		serviceName string
		transport   npb.TransportProtocol
		httpMethods []string
		reply       []byte
		wantAccepts int32
	}{
		{
			name:        "when_web_service_skips_without_dialing_and_returns_no_findings",
			serviceName: "http",
			transport:   npb.TransportProtocol_TCP,
			httpMethods: []string{"GET"},
			wantAccepts: 0,
		},
		{
			name:        "when_udp_service_skips_without_dialing_and_returns_no_findings",
			serviceName: "thrift",
			transport:   npb.TransportProtocol_UDP,
			wantAccepts: 0,
		},
		{
			name:        "when_sctp_service_skips_without_dialing_and_returns_no_findings",
			serviceName: "thrift",
			transport:   npb.TransportProtocol_SCTP,
			wantAccepts: 0,
		},
		{
			name:        "when_ssh_service_speaks_ssh_banner_probes_and_returns_no_findings",
			serviceName: "ssh",
			transport:   npb.TransportProtocol_TCP,
			reply:       []byte("SSH-2.0-OpenSSH_9.6\r\n"),
			wantAccepts: 1,
		},
		{
			name:        "when_tcpwrapped_service_closes_immediately_probes_and_returns_no_findings",
			serviceName: "tcpwrapped",
			transport:   npb.TransportProtocol_TCP,
			wantAccepts: 1,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var accepts atomic.Int32
			svc := startFakeThriftServerWithOptions(t, fakeServerOptions{
				serviceName: tc.serviceName,
				transport:   tc.transport,
				httpMethods: tc.httpMethods,
				onAccept:    func() { accepts.Add(1) },
			}, func(conn net.Conn, _ int32) {
				_ = readClientRequest(conn)
				if tc.reply != nil {
					_, _ = conn.Write(tc.reply)
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
			if reports != nil && len(reports.GetDetectionReports()) > 0 {
				t.Errorf("Detect() returned unexpected reports: %v", reports)
			}
			if accepts.Load() != tc.wantAccepts {
				t.Errorf("server accepts = %d, want %d", accepts.Load(), tc.wantAccepts)
			}
		})
	}
}

func TestDetectInvalidInputErrors(t *testing.T) {
	testCases := []struct {
		name      string
		svc       *nspb.NetworkService
		cancelCtx bool
		wantErr   error
	}{
		{
			name:    "when_nil_service_returns_missing_address_error",
			svc:     nil,
			wantErr: netendpoint.ErrEndpointMissingAddress,
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
			cancelCtx: true,
			wantErr:   context.Canceled,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if tc.cancelCtx {
				cancel()
			}

			detector, err := New(t.Context(), config.Default())
			if err != nil {
				t.Fatalf("New() unexpected error: %v", err)
			}

			reports, err := detector.Detect(ctx, tc.svc)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Detect() error = %v, want %v", err, tc.wantErr)
			}
			if reports != nil {
				t.Errorf("Detect() = %v, want nil", reports)
			}
		})
	}
}

func TestDetectContextCancellation(t *testing.T) {
	vulnerableControlReply := buildMetaExceptionReplyBytes(
		controlSeqID,
		thriftMethodName,
		thriftTypeStruct, 1,
		thriftTypeString, 1,
		"Buffer underflow.\nSerialization trace:\nchidren (org.apache.hadoop.hive.ql.plan.ExprNodeGenericFuncDesc)",
	)
	noSuchObjectReply := buildMetaExceptionReplyBytes(
		controlSeqID,
		thriftMethodName,
		thriftTypeStruct, 2,
		thriftTypeString, 1,
		"hive.default.tsunami_probe table not found",
	)
	listDBsReply := buildStringListReplyBytes(listDBsSeqID, thriftGetAllDBsMethod, []string{"db1", "db2"})

	testCases := []struct {
		name           string
		sslVersions    []string
		stallHandshake bool
		ctxTimeout     time.Duration
		cancelOnCall   int32
		replies        [][]byte
		wantAccepts    int32
		wantErr        error
	}{
		{
			name:         "when_context_canceled_during_first_probe_returns_error",
			cancelOnCall: 1,
			wantAccepts:  1,
			wantErr:      context.Canceled,
		},
		{
			name:         "when_context_canceled_during_second_probe_returns_error",
			cancelOnCall: 2,
			replies:      [][]byte{vulnerableControlReply},
			wantAccepts:  2,
			wantErr:      context.Canceled,
		},
		{
			name:         "when_context_canceled_during_get_all_tables_aborts_and_returns_error",
			cancelOnCall: 3,
			replies:      [][]byte{noSuchObjectReply, listDBsReply},
			wantAccepts:  3,
			wantErr:      context.Canceled,
		},
		{
			name:        "when_context_deadline_exceeded_during_stalled_probe_returns_error",
			ctxTimeout:  40 * time.Millisecond,
			wantAccepts: 1,
			wantErr:     context.DeadlineExceeded,
		},
		{
			name:           "when_context_deadline_exceeded_during_stalled_tls_handshake_returns_error",
			sslVersions:    []string{"TLSv1.3"},
			stallHandshake: true,
			ctxTimeout:     40 * time.Millisecond,
			wantAccepts:    1,
			wantErr:        context.DeadlineExceeded,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if tc.ctxTimeout > 0 {
				var expCancel context.CancelFunc
				ctx, expCancel = context.WithTimeout(ctx, tc.ctxTimeout)
				defer expCancel()
			}

			var accepts atomic.Int32
			svc := startFakeThriftServerWithOptions(t, fakeServerOptions{
				serviceName: "unknown",
				transport:   npb.TransportProtocol_TCP,
				sslVersions: tc.sslVersions,
				onAccept:    func() { accepts.Add(1) },
			}, func(conn net.Conn, callNum int32) {
				if tc.stallHandshake {
					<-ctx.Done()
					return
				}
				_ = readClientRequest(conn)
				if callNum == tc.cancelOnCall {
					cancel()
					return
				}
				if idx := int(callNum - 1); idx < len(tc.replies) {
					if tc.replies[idx] != nil {
						_, _ = conn.Write(tc.replies[idx])
					}
					return
				}
				<-ctx.Done()
			})

			detector, err := New(t.Context(), config.Default())
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
			if accepts.Load() != tc.wantAccepts {
				t.Errorf("server accepts = %d, want %d", accepts.Load(), tc.wantAccepts)
			}
		})
	}
}

func TestDetectPerRequestTimeoutsReturnNil(t *testing.T) {
	noSuchObjectReply := buildMetaExceptionReplyBytes(
		controlSeqID,
		thriftMethodName,
		thriftTypeStruct, 2,
		thriftTypeString, 1,
		"hive.default.tsunami_probe table not found",
	)
	hive4ControlReply := buildMetaExceptionReplyBytes(
		controlSeqID,
		thriftMethodName,
		thriftTypeStruct, 1,
		thriftTypeString, 1,
		"Buffer underflow.\nSerialization trace:\nchidren (org.apache.hadoop.hive.ql.plan.ExprNodeGenericFuncDesc)",
	)
	vulnerableTreeMapReply := buildMetaExceptionReplyBytes(
		vulnSeqID,
		thriftMethodName,
		thriftTypeStruct, 1,
		thriftTypeString, 1,
		"java.lang.ClassCastException: java.util.ArrayList cannot be cast to java.lang.Comparable\nSerialization trace:\nchidren (org.apache.hadoop.hive.ql.plan.ExprNodeGenericFuncDesc)",
	)
	listTwoDBsReply := buildStringListReplyBytes(listDBsSeqID, thriftGetAllDBsMethod, []string{"stalled_db", "healthy_db"})
	listTblsReply := buildStringListReplyBytes(listTblsSeqID, thriftGetAllTblsMethod, []string{"sample_tbl"})

	cert := generateSelfSignedCert(t)

	testCases := []struct {
		name           string
		sslVersions    []string
		serverTLS      bool
		stallHandshake bool
		reqTimeout     time.Duration
		stallOnCall    int32
		replies        [][]byte
		wantMinAccepts int32
		wantFindings   bool
	}{
		{
			name:       "when_dial_times_out_with_active_context_returns_nil_without_error",
			reqTimeout: time.Nanosecond,
		},
		{
			name:           "when_tls_handshake_stalls_past_request_timeout_returns_nil_without_error",
			sslVersions:    []string{"TLSv1.3"},
			serverTLS:      false,
			stallHandshake: true,
			reqTimeout:     35 * time.Millisecond,
			wantMinAccepts: 1,
		},
		{
			name:           "when_tls_control_probe_stalls_after_handshake_returns_nil_without_error",
			sslVersions:    []string{"TLSv1.3"},
			serverTLS:      true,
			reqTimeout:     35 * time.Millisecond,
			stallOnCall:    1,
			wantMinAccepts: 1,
		},
		{
			name:           "when_control_probe_stalls_past_request_timeout_returns_nil_without_error",
			reqTimeout:     35 * time.Millisecond,
			stallOnCall:    1,
			wantMinAccepts: 1,
		},
		{
			name:           "when_get_all_databases_stalls_past_request_timeout_returns_nil_without_error",
			reqTimeout:     35 * time.Millisecond,
			stallOnCall:    2,
			replies:        [][]byte{noSuchObjectReply},
			wantMinAccepts: 2,
		},
		{
			name:           "when_first_db_get_all_tables_times_out_continues_to_second_db_and_returns_finding",
			reqTimeout:     35 * time.Millisecond,
			stallOnCall:    3,
			replies:        [][]byte{noSuchObjectReply, listTwoDBsReply, nil, listTblsReply, hive4ControlReply, vulnerableTreeMapReply},
			wantMinAccepts: 6,
			wantFindings:   true,
		},
		{
			name:           "when_vulnerability_probe_stalls_past_request_timeout_returns_nil_without_error",
			reqTimeout:     35 * time.Millisecond,
			stallOnCall:    2,
			replies:        [][]byte{hive4ControlReply},
			wantMinAccepts: 2,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			done := make(chan struct{})
			t.Cleanup(func() { close(done) })

			var (
				accepts   atomic.Int32
				tlsConfig *tls.Config
			)
			if tc.serverTLS {
				tlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
			}

			svc := startFakeThriftServerWithOptions(t, fakeServerOptions{
				serviceName: "hive-metastore",
				transport:   npb.TransportProtocol_TCP,
				sslVersions: tc.sslVersions,
				tlsConfig:   tlsConfig,
			}, func(conn net.Conn, callNum int32) {
				accepts.Add(1)
				if tc.stallHandshake {
					<-done
					return
				}
				_ = readClientRequest(conn)
				if callNum == tc.stallOnCall {
					<-done
					return
				}
				if idx := int(callNum - 1); idx < len(tc.replies) && tc.replies[idx] != nil {
					_, _ = conn.Write(tc.replies[idx])
				}
			})

			det, err := New(t.Context(), config.Default())
			if err != nil {
				t.Fatalf("New() unexpected error: %v", err)
			}
			det.(*Module).timeout = tc.reqTimeout

			start := time.Now()
			reports, err := det.Detect(t.Context(), svc)
			if err != nil {
				t.Fatalf("Detect() unexpected error: %v", err)
			}
			if elapsed := time.Since(start); elapsed > 2*time.Second {
				t.Errorf("Detect() took %v, expected bounded per-request timeout", elapsed)
			}
			if got := len(reports.GetDetectionReports()) > 0; got != tc.wantFindings {
				t.Errorf("Detect() findings = %v, want %v", got, tc.wantFindings)
			}
			if accepts.Load() < tc.wantMinAccepts {
				t.Errorf("server accepts = %d, want >= %d", accepts.Load(), tc.wantMinAccepts)
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

func TestReadStringListReplyInvalidInputs(t *testing.T) {
	fullValid := buildStringListReplyBytes(listDBsSeqID, thriftGetAllDBsMethod, []string{"default"})

	var oversizedItem bytes.Buffer
	_ = binary.Write(&oversizedItem, binary.BigEndian, thriftVersion1Reply)
	writeThriftString(&oversizedItem, []byte(thriftGetAllDBsMethod))
	_ = binary.Write(&oversizedItem, binary.BigEndian, listDBsSeqID)
	oversizedItem.WriteByte(thriftTypeList)
	_ = binary.Write(&oversizedItem, binary.BigEndian, uint16(0))
	oversizedItem.WriteByte(thriftTypeString)
	_ = binary.Write(&oversizedItem, binary.BigEndian, uint32(1))
	_ = binary.Write(&oversizedItem, binary.BigEndian, uint32(maxMetaExceptionLen+1))

	var badListField bytes.Buffer
	_ = binary.Write(&badListField, binary.BigEndian, thriftVersion1Reply)
	writeThriftString(&badListField, []byte(thriftGetAllDBsMethod))
	_ = binary.Write(&badListField, binary.BigEndian, listDBsSeqID)
	badListField.WriteByte(thriftTypeStruct)
	_ = binary.Write(&badListField, binary.BigEndian, uint16(0))
	badListField.WriteByte(thriftTypeString)
	_ = binary.Write(&badListField, binary.BigEndian, uint32(0))

	testCases := []struct {
		name    string
		input   []byte
		seqID   uint32
		wantErr error
	}{
		{
			name:    "when_empty_stream_returns_eof",
			input:   nil,
			seqID:   listDBsSeqID,
			wantErr: io.EOF,
		},
		{
			name:    "when_truncated_method_returns_unexpected_eof",
			input:   fullValid[:12],
			seqID:   listDBsSeqID,
			wantErr: io.ErrUnexpectedEOF,
		},
		{
			name:    "when_method_name_mismatch_returns_not_hive_metastore",
			input:   buildStringListReplyBytes(listDBsSeqID, "other_17_byte_rpc", []string{"default"}),
			seqID:   listDBsSeqID,
			wantErr: errNotHiveMetastore,
		},
		{
			name:    "when_seqid_mismatch_returns_not_hive_metastore",
			input:   fullValid,
			seqID:   99,
			wantErr: errNotHiveMetastore,
		},
		{
			name:    "when_truncated_list_header_returns_unexpected_eof",
			input:   fullValid[:31],
			seqID:   listDBsSeqID,
			wantErr: io.ErrUnexpectedEOF,
		},
		{
			name:    "when_non_list_field_header_returns_not_hive_metastore",
			input:   badListField.Bytes(),
			seqID:   listDBsSeqID,
			wantErr: errNotHiveMetastore,
		},
		{
			name:    "when_truncated_element_length_returns_unexpected_eof",
			input:   fullValid[:39],
			seqID:   listDBsSeqID,
			wantErr: io.ErrUnexpectedEOF,
		},
		{
			name:    "when_element_exceeds_max_length_returns_not_hive_metastore",
			input:   oversizedItem.Bytes(),
			seqID:   listDBsSeqID,
			wantErr: errNotHiveMetastore,
		},
		{
			name:    "when_truncated_element_body_returns_unexpected_eof",
			input:   fullValid[:len(fullValid)-3],
			seqID:   listDBsSeqID,
			wantErr: io.ErrUnexpectedEOF,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := readStringListReply(bytes.NewReader(tc.input), thriftGetAllDBsMethod, tc.seqID)
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("readStringListReply() error = %v, want %v", err, tc.wantErr)
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

type fakeServerOptions struct {
	serviceName string
	transport   npb.TransportProtocol
	httpMethods []string
	sslVersions []string
	tlsConfig   *tls.Config
	onListen    func(io.Closer)
	onAccept    func()
}

func startFakeThriftServerWithOptions(t *testing.T, opts fakeServerOptions, handler func(conn net.Conn, callNum int32)) *nspb.NetworkService {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen failed: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	if opts.onListen != nil {
		opts.onListen(listener)
	}

	var calls atomic.Int32
	go func() {
		for {
			rawConn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			if opts.onAccept != nil {
				opts.onAccept()
			}
			n := calls.Add(1)
			go func(c net.Conn, num int32) {
				if opts.tlsConfig != nil {
					tlsSrv := tls.Server(c, opts.tlsConfig)
					if hsErr := tlsSrv.Handshake(); hsErr != nil {
						_ = c.Close()
						return
					}
					defer tlsSrv.Close()
					handler(tlsSrv, num)
					return
				}
				defer c.Close()
				handler(c, num)
			}(rawConn, n)
		}
	}()

	port := listener.Addr().(*net.TCPAddr).Port
	return nspb.NetworkService_builder{
		ServiceName:          opts.serviceName,
		TransportProtocol:    opts.transport,
		SupportedHttpMethods: opts.httpMethods,
		SupportedSslVersions: opts.sslVersions,
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

func generateSelfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.StartTLS()
	cert := srv.TLS.Certificates[0]
	srv.Close()
	return cert
}

func readClientRequest(conn net.Conn) []byte {
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n <= 0 {
		return nil
	}
	return buf[:n]
}
