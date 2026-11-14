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

package cve2026119618

import (
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
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/module"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"

	cpb "github.com/google/goonami-scanner/core/config/config_go_proto"
	dpb "github.com/google/tsunami-security-scanner/proto/go/detection_go_proto"
	npb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
	rpb "github.com/google/tsunami-security-scanner/proto/go/reconnaissance_go_proto"
	vpb "github.com/google/tsunami-security-scanner/proto/go/vulnerability_go_proto"
	wcpb "github.com/google/tsunami-security-scanner/proto/go/web_crawl_go_proto"
	tspb "google.golang.org/protobuf/types/known/timestamppb"
)

var fixedTestTime = time.Date(2026, time.November, 14, 5, 0, 0, 0, time.UTC)

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
			name:        "when_default_config_uses_proto_timeout",
			cfg:         config.Default(),
			wantTimeout: 10 * time.Second,
		},
		{
			name: "when_custom_timeout_applies_configured_seconds",
			cfg: config.FromProto(cpb.Config_builder{
				Globalcfg: cpb.GlobalConfig_builder{
					Performance: cpb.GlobalConfig_Performance_builder{
						TimeoutPerRequestSeconds: proto.Int32(12),
					}.Build(),
				}.Build(),
			}.Build()),
			wantTimeout: 12 * time.Second,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			det, err := New(t.Context(), tc.cfg)
			if err != nil {
				t.Fatalf("New() unexpected error: %v", err)
			}
			if det == nil {
				t.Fatal("New() returned nil detector")
			}
			if got := det.Name(); got != moduleName {
				t.Errorf("det.Name() = %q, want %q", got, moduleName)
			}
			mod := det.(*Module)
			if mod.timeout != tc.wantTimeout {
				t.Errorf("mod.timeout = %v, want %v", mod.timeout, tc.wantTimeout)
			}
			if gotNonce := mod.nonceFn(); len(gotNonce) != 16 {
				t.Errorf("len(mod.nonceFn()) = %d, want 16 (%q)", len(gotNonce), gotNonce)
			}
			allDets, regErr := module.AllDetectors(t.Context(), tc.cfg)
			if regErr != nil {
				t.Fatalf("module.AllDetectors() unexpected error: %v", regErr)
			}
			foundSelf := false
			for _, d := range allDets {
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

func TestAdvisories(t *testing.T) {
	testCases := []struct {
		name        string
		mutateTitle string
	}{
		{
			name:        "when_called_returns_defensive_clone_of_critical_cve_advisory",
			mutateTitle: "mutated_title",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			det, err := New(t.Context(), config.Default())
			if err != nil {
				t.Fatalf("New() unexpected error: %v", err)
			}

			got := det.Advisories()
			want := []*vpb.Vulnerability{
				vpb.Vulnerability_builder{
					MainId: vpb.VulnerabilityId_builder{
						Publisher: "GOOGLE",
						Value:     "CVE-2026-119618",
					}.Build(),
					RelatedId: []*vpb.VulnerabilityId{
						vpb.VulnerabilityId_builder{
							Publisher: "CVE",
							Value:     "CVE-2026-119618",
						}.Build(),
					},
					Severity:       vpb.Severity_CRITICAL,
					Title:          vulnReportTitle,
					Description:    vulnDescription,
					Recommendation: vulnRecommendation,
				}.Build(),
			}
			if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
				t.Errorf("Advisories() mismatch (-want +got):\n%s", diff)
			}

			got[0].SetTitle(tc.mutateTitle)
			second := det.Advisories()
			if second[0].GetTitle() == tc.mutateTitle {
				t.Errorf("Advisories() returned shared mutable proto instead of defensive clone")
			}
		})
	}
}

type recordedStream struct {
	streamID  uint32
	headers   []hpack.HeaderField
	body      []byte
	endStream bool
}

type mockApacheConfig struct {
	stream1IncludeCL     bool
	stream1LowercaseCL   bool
	stream3OmitCL        bool
	http11RequestLine    bool
	lowercaseEchoHeaders bool
	omitEchoContentType  bool
	wrongResponseCT      string
	stream1Status        string
	stream3Status        string
	stream5Mode          string // "413_rst", "200_extended", "200_no_body", "200_no_cl", "500"
	routeStatuses        map[string]string
}

func defaultVulnerableApacheConfig() mockApacheConfig {
	return mockApacheConfig{
		stream5Mode: "413_rst",
	}
}

func newBufferedConnPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen failed: %v", err)
	}
	defer ln.Close()

	srvCh := make(chan net.Conn, 1)
	errCh := make(chan error, 1)
	go func() {
		sc, aErr := ln.Accept()
		if aErr != nil {
			errCh <- aErr
			return
		}
		srvCh <- sc
	}()

	cc, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("net.Dial failed: %v", err)
	}
	select {
	case sc := <-srvCh:
		return cc, sc
	case aErr := <-errCh:
		_ = cc.Close()
		t.Fatalf("Accept failed: %v", aErr)
		return nil, nil
	}
}

func serveMockApacheH2Conn(t *testing.T, conn net.Conn, cfg mockApacheConfig, recorded *[]recordedStream, mu *sync.Mutex) {
	t.Helper()
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	preface := make([]byte, len(h2ClientPreface))
	if _, err := io.ReadFull(conn, preface); err != nil {
		return
	}
	if string(preface) != h2ClientPreface {
		return
	}

	fr := http2.NewFramer(conn, conn)
	hdec := hpack.NewDecoder(4096, nil)
	fr.ReadMetaHeaders = hdec

	// Send server SETTINGS preface.
	if err := fr.WriteSettings(); err != nil {
		return
	}

	var activeStreams atomic.Int32
	indexedCT := false

	for {
		f, err := fr.ReadFrame()
		if err != nil {
			return
		}
		switch frame := f.(type) {
		case *http2.SettingsFrame:
			if !frame.IsAck() {
				_ = fr.WriteSettingsAck()
			}
		case *http2.WindowUpdateFrame:
			// Ignore client flow-control window updates.
		case *http2.PingFrame:
			if !frame.IsAck() {
				_ = fr.WritePing(true, frame.Data)
			}
		case *http2.MetaHeadersFrame:
			if activeStreams.Add(1) != 1 {
				t.Errorf("concurrent streams detected on connection; safety invariant requires single sequential stream")
			}
			hdrs := append([]hpack.HeaderField(nil), frame.Fields...)
			if len(hdrs) >= 10 {
				t.Errorf("received %d headers on stream %d; safety invariant requires <10 headers", len(hdrs), frame.StreamID)
			}
			var reqBody []byte
			endStream := frame.StreamEnded()
			for !endStream {
				nextF, readErr := fr.ReadFrame()
				if readErr != nil {
					activeStreams.Add(-1)
					return
				}
				if df, ok := nextF.(*http2.DataFrame); ok && df.StreamID == frame.StreamID {
					reqBody = append(reqBody, df.Data()...)
					endStream = df.StreamEnded()
				}
			}

			mu.Lock()
			*recorded = append(*recorded, recordedStream{
				streamID:  frame.StreamID,
				headers:   hdrs,
				body:      reqBody,
				endStream: true,
			})
			mu.Unlock()

			writeMockApacheStreamResponse(fr, frame.StreamID, &indexedCT, hdrs, reqBody, cfg)
			activeStreams.Add(-1)
		}
	}
}

func headerMap(fields []hpack.HeaderField) map[string]string {
	m := make(map[string]string, len(fields))
	for _, hf := range fields {
		m[hf.Name] = hf.Value
	}
	return m
}

// encodeApacheDynamicResponseHeaders emulates nghttp2 inserting
// "content-type: message/http; charset=UTF-8" into dynamic table index 62 on
// the first 200 response of the connection and referencing it via 1-byte
// indexed field 0xbe on subsequent streams.
func encodeApacheDynamicResponseHeaders(status, customCT string, firstResponseOnConn bool) []byte {
	var buf bytes.Buffer
	if status == "200" {
		buf.WriteByte(0x88) // Indexed :status = 200 (static index 8)
	} else {
		enc := hpack.NewEncoder(&buf)
		_ = enc.WriteField(hpack.HeaderField{Name: ":status", Value: status, Sensitive: true})
	}

	if customCT != "" {
		enc := hpack.NewEncoder(&buf)
		_ = enc.WriteField(hpack.HeaderField{Name: "content-type", Value: customCT, Sensitive: true})
		return buf.Bytes()
	}

	if firstResponseOnConn {
		// Literal Header Field with Incremental Indexing — Indexed Name 31 (content-type): 0x40 | 31 = 0x5f.
		ctVal := "message/http; charset=UTF-8"
		buf.WriteByte(0x5f)
		buf.WriteByte(byte(len(ctVal)))
		buf.WriteString(ctVal)
	} else {
		// Indexed Header Field — dynamic index 62: 0x80 | 62 = 0xbe.
		buf.WriteByte(0xbe)
	}
	return buf.Bytes()
}

func writeMockApacheStreamResponse(fr *http2.Framer, streamID uint32, indexedCT *bool, reqHeaders []hpack.HeaderField, reqBody []byte, cfg mockApacheConfig) {
	hm := headerMap(reqHeaders)
	path := hm[":path"]
	authority := hm[":authority"]
	probeVal := hm[probeHeaderWireName]
	explicitCL, hasExplicitCL := hm["content-length"]

	if cfg.routeStatuses != nil {
		if routeStatus, ok := cfg.routeStatuses[path]; ok && routeStatus != "200" {
			var hbuf bytes.Buffer
			enc := hpack.NewEncoder(&hbuf)
			_ = enc.WriteField(hpack.HeaderField{Name: ":status", Value: routeStatus, Sensitive: true})
			_ = fr.WriteHeaders(http2.HeadersFrameParam{
				StreamID:      streamID,
				BlockFragment: hbuf.Bytes(),
				EndStream:     true,
				EndHeaders:    true,
			})
			return
		}
	}

	if cfg.stream1Status != "" && !hasExplicitCL {
		var hbuf bytes.Buffer
		enc := hpack.NewEncoder(&hbuf)
		_ = enc.WriteField(hpack.HeaderField{Name: ":status", Value: cfg.stream1Status, Sensitive: true})
		_ = fr.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      streamID,
			BlockFragment: hbuf.Bytes(),
			EndStream:     true,
			EndHeaders:    true,
		})
		return
	}

	if hasExplicitCL && explicitCL == "0" && cfg.stream3Status != "" {
		var hbuf bytes.Buffer
		enc := hpack.NewEncoder(&hbuf)
		_ = enc.WriteField(hpack.HeaderField{Name: ":status", Value: cfg.stream3Status, Sensitive: true})
		_ = fr.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      streamID,
			BlockFragment: hbuf.Bytes(),
			EndStream:     true,
			EndHeaders:    true,
		})
		return
	}

	// Stream 5 (1-byte TRACE body control).
	if len(reqBody) > 0 || explicitCL == "1" {
		switch cfg.stream5Mode {
		case "413_rst", "":
			var hbuf bytes.Buffer
			enc := hpack.NewEncoder(&hbuf)
			_ = enc.WriteField(hpack.HeaderField{Name: ":status", Value: "413", Sensitive: true})
			_ = fr.WriteHeaders(http2.HeadersFrameParam{
				StreamID:      streamID,
				BlockFragment: hbuf.Bytes(),
				EndStream:     false,
				EndHeaders:    true,
			})
			_ = fr.WriteData(streamID, false, []byte("413 Request Entity Too Large"))
			_ = fr.WriteRSTStream(streamID, http2.ErrCodeNo)
			return
		case "500":
			var hbuf bytes.Buffer
			enc := hpack.NewEncoder(&hbuf)
			_ = enc.WriteField(hpack.HeaderField{Name: ":status", Value: "500", Sensitive: true})
			_ = fr.WriteHeaders(http2.HeadersFrameParam{
				StreamID:      streamID,
				BlockFragment: hbuf.Bytes(),
				EndStream:     true,
				EndHeaders:    true,
			})
			return
		}
	}

	protoVer := "HTTP/2.0"
	if cfg.http11RequestLine {
		protoVer = "HTTP/1.1"
	}
	hostKey := "Host"
	probeKey := "X-Tsunami-Probe"
	ctKey := "Content-Type"
	if cfg.lowercaseEchoHeaders {
		hostKey = "host"
		probeKey = "x-tsunami-probe"
		ctKey = "content-type"
	}

	var echo bytes.Buffer
	fmt.Fprintf(&echo, "TRACE %s %s\r\n", path, protoVer)
	fmt.Fprintf(&echo, "%s: %s\r\n", hostKey, authority)
	if ctVal, ok := hm["content-type"]; ok && !cfg.omitEchoContentType {
		fmt.Fprintf(&echo, "%s: %s\r\n", ctKey, ctVal)
	}
	if !hasExplicitCL {
		if cfg.stream1IncludeCL {
			if cfg.stream1LowercaseCL {
				echo.WriteString("content-length: 0\r\n")
			} else {
				echo.WriteString("Content-Length: 0\r\n")
			}
		}
	} else if explicitCL == "0" {
		if !cfg.stream3OmitCL {
			echo.WriteString("Content-Length: 0\r\n")
		}
	} else if explicitCL == "1" {
		if cfg.stream5Mode != "200_no_cl" {
			echo.WriteString("Content-Length: 1\r\n")
		}
	}
	fmt.Fprintf(&echo, "%s: %s\r\n\r\n", probeKey, probeVal)
	if explicitCL == "1" && cfg.stream5Mode == "200_extended" {
		echo.Write(reqBody)
	}

	firstCTOnConn := !*indexedCT
	if cfg.wrongResponseCT == "" {
		*indexedCT = true
	}
	hdrBlock := encodeApacheDynamicResponseHeaders("200", cfg.wrongResponseCT, firstCTOnConn)
	_ = fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      streamID,
		BlockFragment: hdrBlock,
		EndStream:     false,
		EndHeaders:    true,
	})
	_ = fr.WriteData(streamID, true, echo.Bytes())
}

func newTestModule(dial dialFunc) *Module {
	var nonceIdx atomic.Int32
	return &Module{
		BaseModule: module.NewBaseModule(moduleName),
		timeout:    2 * time.Second,
		dial:       dial,
		nowFn:      func() time.Time { return fixedTestTime },
		nonceFn: func() string {
			n := nonceIdx.Add(1)
			return fmt.Sprintf("000000000000000%d", n)
		},
	}
}

func generateSelfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.StartTLS()
	cert := srv.TLS.Certificates[0]
	srv.Close()
	return cert
}

func TestDetectPositive(t *testing.T) {
	testCases := []struct {
		name            string
		useTLS          bool
		stream5Mode     string
		failFirstMode   bool
		wantMode        string
		wantScheme      string
		wantStream5Note string
	}{
		{
			name:            "when_vulnerable_apache_h2c_trace_enable_on_returns_verified_finding",
			useTLS:          false,
			stream5Mode:     "413_rst",
			wantMode:        "h2c",
			wantScheme:      "http",
			wantStream5Note: "HTTP 413 (TraceEnable on)",
		},
		{
			name:            "when_vulnerable_apache_h2_tls_trace_enable_extended_returns_verified_finding",
			useTLS:          true,
			stream5Mode:     "200_extended",
			wantMode:        "h2",
			wantScheme:      "https",
			wantStream5Note: "HTTP 200 echoed 1-byte body (TraceEnable extended)",
		},
		{
			name:            "when_tls_first_transport_fails_falls_back_to_h2c_and_returns_verified_finding",
			useTLS:          true,
			failFirstMode:   true,
			stream5Mode:     "413_rst",
			wantMode:        "h2c",
			wantScheme:      "http",
			wantStream5Note: "HTTP 413 (TraceEnable on)",
		},
		{
			name:            "when_h2c_first_transport_fails_falls_back_to_h2_tls_and_returns_verified_finding",
			useTLS:          false,
			failFirstMode:   true,
			stream5Mode:     "200_extended",
			wantMode:        "h2",
			wantScheme:      "https",
			wantStream5Note: "HTTP 200 echoed 1-byte body (TraceEnable extended)",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cert := generateSelfSignedCert(t)
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("net.Listen failed: %v", err)
			}
			t.Cleanup(func() { _ = ln.Close() })

			var (
				mu       sync.Mutex
				recorded []recordedStream
			)
			apacheCfg := defaultVulnerableApacheConfig()
			apacheCfg.stream5Mode = tc.stream5Mode

			targetSpeakTLS := (tc.useTLS && !tc.failFirstMode) || (!tc.useTLS && tc.failFirstMode)
			go func() {
				for {
					rawConn, acceptErr := ln.Accept()
					if acceptErr != nil {
						return
					}
					go func(c net.Conn) {
						if targetSpeakTLS {
							tlsSrv := tls.Server(c, &tls.Config{
								Certificates: []tls.Certificate{cert},
								NextProtos:   []string{"h2"},
							})
							if hsErr := tlsSrv.Handshake(); hsErr != nil {
								_ = c.Close()
								return
							}
							serveMockApacheH2Conn(t, tlsSrv, apacheCfg, &recorded, &mu)
							return
						}
						serveMockApacheH2Conn(t, c, apacheCfg, &recorded, &mu)
					}(rawConn)
				}
			}()

			port := uint32(ln.Addr().(*net.TCPAddr).Port)
			svcName := "http"
			if tc.useTLS {
				svcName = "https"
			}
			svc := nspb.NetworkService_builder{
				ServiceName:          svcName,
				TransportProtocol:    npb.TransportProtocol_TCP,
				SupportedHttpMethods: []string{"GET"},
				NetworkEndpoint: npb.NetworkEndpoint_builder{
					Type: npb.NetworkEndpoint_IP_PORT,
					IpAddress: npb.IpAddress_builder{
						Address:       "127.0.0.1",
						AddressFamily: npb.AddressFamily_IPV4,
					}.Build(),
					Port: npb.Port_builder{PortNumber: port}.Build(),
				}.Build(),
			}.Build()

			m := newTestModule(defaultDial)
			got, err := m.Detect(t.Context(), svc)
			if err != nil {
				t.Fatalf("Detect() unexpected error: %v", err)
			}

			authority := fmt.Sprintf("127.0.0.1:%d", port)
			wantDetail := fmt.Sprintf(
				"Verified unpatched Apache mod_http2 assign_headers() over HTTP/2 (%s) at %s://%s/: "+
					"Stream 1 omitted synthesized 'Content-Length: 0' in r->headers_in, Stream 3 confirmed explicit 'Content-Length: 0' preservation, and Stream 5 confirmed ap_send_http_trace body handling (%s).",
				tc.wantMode, tc.wantScheme, authority, tc.wantStream5Note,
			)
			wantVuln := baseVulnerability()
			wantVuln.SetAdditionalDetails([]*vpb.AdditionalDetail{
				vpb.AdditionalDetail_builder{
					Description: "HTTP/2 assign_headers() causal-ablation verification evidence.",
					TextData:    vpb.TextData_builder{Text: wantDetail}.Build(),
				}.Build(),
			})
			want := dpb.DetectionReportList_builder{
				DetectionReports: []*dpb.DetectionReport{
					dpb.DetectionReport_builder{
						TargetInfo: rpb.TargetInfo_builder{
							NetworkEndpoints: []*npb.NetworkEndpoint{svc.GetNetworkEndpoint()},
						}.Build(),
						NetworkService: svc,
						DetectionTimestamp: &tspb.Timestamp{
							Seconds: fixedTestTime.Unix(),
							Nanos:   int32(fixedTestTime.Nanosecond()),
						},
						DetectionStatus: dpb.DetectionStatus_VULNERABILITY_VERIFIED,
						Vulnerability:   wantVuln,
					}.Build(),
				},
			}.Build()

			if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
				t.Errorf("Detect() report mismatch (-want +got):\n%s", diff)
			}

			mu.Lock()
			defer mu.Unlock()
			if len(recorded) != 3 {
				t.Fatalf("len(recorded) = %d, want 3 sequential streams", len(recorded))
			}
			wantIDs := []uint32{1, 3, 5}
			wantCounts := []int{6, 7, 6}
			for i, rec := range recorded {
				if rec.streamID != wantIDs[i] {
					t.Errorf("stream[%d].streamID = %d, want %d", i, rec.streamID, wantIDs[i])
				}
				if len(rec.headers) != wantCounts[i] {
					t.Errorf("len(stream[%d].headers) = %d, want %d", i, len(rec.headers), wantCounts[i])
				}
			}
			if string(recorded[2].body) != "x" {
				t.Errorf("stream[2].body = %q, want %q", string(recorded[2].body), "x")
			}
		})
	}
}

func TestDetectNegativeConfounders(t *testing.T) {
	testCases := []struct {
		name             string
		cfg              mockApacheConfig
		withCrawledPaths bool
		wantStreams      int
	}{
		{
			name:        "when_patched_apache_echoes_title_case_content_length_zero_returns_no_findings",
			cfg:         mockApacheConfig{stream1IncludeCL: true, stream5Mode: "413_rst"},
			wantStreams: 1,
		},
		{
			name:        "when_backported_apache_echoes_lowercase_content_length_zero_returns_no_findings",
			cfg:         mockApacheConfig{stream1IncludeCL: true, stream1LowercaseCL: true, stream5Mode: "413_rst"},
			wantStreams: 1,
		},
		{
			name:        "when_mod_headers_unsets_content_length_on_stream1_and_stream3_returns_no_findings",
			cfg:         mockApacheConfig{stream3OmitCL: true, stream5Mode: "413_rst"},
			wantStreams: 2,
		},
		{
			name:        "when_reverse_proxy_down_converts_trace_to_http11_returns_no_findings",
			cfg:         mockApacheConfig{http11RequestLine: true, stream5Mode: "413_rst"},
			wantStreams: 1,
		},
		{
			name:        "when_non_apache_server_echoes_lowercase_headers_returns_no_findings",
			cfg:         mockApacheConfig{lowercaseEchoHeaders: true, stream5Mode: "413_rst"},
			wantStreams: 1,
		},
		{
			name:        "when_stream1_omits_echoed_content_type_header_returns_no_findings",
			cfg:         mockApacheConfig{omitEchoContentType: true, stream5Mode: "413_rst"},
			wantStreams: 1,
		},
		{
			name:        "when_stream1_returns_non_message_http_content_type_returns_no_findings",
			cfg:         mockApacheConfig{wrongResponseCT: "text/html; charset=UTF-8", stream5Mode: "413_rst"},
			wantStreams: 1,
		},
		{
			name:        "when_stream3_returns_500_status_returns_no_findings",
			cfg:         mockApacheConfig{stream3Status: "500", stream5Mode: "413_rst"},
			wantStreams: 2,
		},
		{
			name:        "when_stream5_returns_200_without_echoed_x_body_returns_no_findings",
			cfg:         mockApacheConfig{stream5Mode: "200_no_body"},
			wantStreams: 3,
		},
		{
			name:        "when_stream5_returns_200_without_content_length_one_returns_no_findings",
			cfg:         mockApacheConfig{stream5Mode: "200_no_cl"},
			wantStreams: 3,
		},
		{
			name:        "when_stream5_returns_500_status_returns_no_findings",
			cfg:         mockApacheConfig{stream5Mode: "500"},
			wantStreams: 3,
		},
		{
			name:             "when_trace_enable_off_returns_405_on_root_aborts_without_probing_crawled_paths",
			cfg:              mockApacheConfig{stream1Status: "405", stream5Mode: "413_rst"},
			withCrawledPaths: true,
			wantStreams:      1,
		},
		{
			name:             "when_stream1_returns_501_not_implemented_aborts_without_probing_crawled_paths",
			cfg:              mockApacheConfig{stream1Status: "501", stream5Mode: "413_rst"},
			withCrawledPaths: true,
			wantStreams:      1,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var (
				mu       sync.Mutex
				recorded []recordedStream
			)
			dial := func(_ context.Context, mode transportMode, _, _ string, _ time.Duration) (net.Conn, error) {
				if mode == transportH2TLS {
					return nil, errors.New("tls disabled in h2c confounder test")
				}
				clientConn, serverConn := newBufferedConnPair(t)
				go serveMockApacheH2Conn(t, serverConn, tc.cfg, &recorded, &mu)
				return clientConn, nil
			}

			svc := nspb.NetworkService_builder{
				ServiceName:          "http",
				TransportProtocol:    npb.TransportProtocol_TCP,
				SupportedHttpMethods: []string{"GET"},
				NetworkEndpoint: npb.NetworkEndpoint_builder{
					Type: npb.NetworkEndpoint_IP_PORT,
					IpAddress: npb.IpAddress_builder{
						Address:       "127.0.0.1",
						AddressFamily: npb.AddressFamily_IPV4,
					}.Build(),
					Port: npb.Port_builder{PortNumber: 8080}.Build(),
				}.Build(),
			}.Build()
			if tc.withCrawledPaths {
				svc.SetServiceContext(nspb.ServiceContext_builder{
					WebServiceContext: nspb.WebServiceContext_builder{
						CrawlResults: []*wcpb.CrawlResult{
							wcpb.CrawlResult_builder{
								CrawlTarget: wcpb.CrawlTarget_builder{Url: "http://127.0.0.1:8080/fallback1"}.Build(),
							}.Build(),
							wcpb.CrawlResult_builder{
								CrawlTarget: wcpb.CrawlTarget_builder{Url: "http://127.0.0.1:8080/fallback2"}.Build(),
							}.Build(),
						},
					}.Build(),
				}.Build())
			}

			m := newTestModule(dial)
			got, err := m.Detect(t.Context(), svc)
			if err != nil {
				t.Fatalf("Detect() unexpected error: %v", err)
			}
			if got != nil && len(got.GetDetectionReports()) > 0 {
				t.Fatalf("Detect() returned unexpected finding: %v", got)
			}

			mu.Lock()
			defer mu.Unlock()
			if len(recorded) != tc.wantStreams {
				t.Errorf("len(recorded) = %d, want %d streams", len(recorded), tc.wantStreams)
			}
		})
	}
}

func writeRawH2Frame(w io.Writer, frameType byte, flags byte, streamIDWithMSB uint32, payload []byte) error {
	var hdr [9]byte
	hdr[0] = byte(len(payload) >> 16)
	hdr[1] = byte(len(payload) >> 8)
	hdr[2] = byte(len(payload))
	hdr[3] = frameType
	hdr[4] = flags
	binary.BigEndian.PutUint32(hdr[5:9], streamIDWithMSB)
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func TestDetectWireFramingAndAdversarialPeers(t *testing.T) {
	t.Run("when_headers_and_data_use_padded_priority_and_reserved_msb_returns_verified_finding", func(t *testing.T) {
		dial := func(_ context.Context, mode transportMode, _, _ string, _ time.Duration) (net.Conn, error) {
			if mode == transportH2TLS {
				return nil, errors.New("h2c only")
			}
			clientConn, serverConn := newBufferedConnPair(t)
			go func() {
				defer serverConn.Close()
				_ = serverConn.SetDeadline(time.Now().Add(3 * time.Second))
				preface := make([]byte, len(h2ClientPreface))
				if _, err := io.ReadFull(serverConn, preface); err != nil {
					return
				}
				fr := http2.NewFramer(serverConn, serverConn)
				fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
				_ = fr.WriteSettings()

				for streamNum := 1; streamNum <= 3; streamNum++ {
					var req *http2.MetaHeadersFrame
					for req == nil {
						f, err := fr.ReadFrame()
						if err != nil {
							return
						}
						if s, ok := f.(*http2.SettingsFrame); ok && !s.IsAck() {
							_ = fr.WriteSettingsAck()
						}
						if mh, ok := f.(*http2.MetaHeadersFrame); ok {
							req = mh
						}
					}
					if !req.StreamEnded() {
						_, _ = fr.ReadFrame() // drain 1-byte DATA on stream 5
					}
					hm := headerMap(req.Fields)
					streamIDMSB := req.StreamID | 0x80000000

					if streamNum == 3 {
						var hbuf bytes.Buffer
						enc := hpack.NewEncoder(&hbuf)
						_ = enc.WriteField(hpack.HeaderField{Name: ":status", Value: "413", Sensitive: true})
						// HEADERS with PADDED (0x08) | PRIORITY (0x20) | END_HEADERS (0x04) | END_STREAM (0x01) = 0x2d
						var paddedHdr bytes.Buffer
						paddedHdr.WriteByte(3)                              // pad length = 3
						paddedHdr.Write([]byte{0x80, 0x00, 0x00, 0x00, 16}) // exclusive dep 0, weight 16
						paddedHdr.Write(hbuf.Bytes())
						paddedHdr.Write([]byte{0, 0, 0})
						_ = writeRawH2Frame(serverConn, byte(http2.FrameHeaders), 0x2d, streamIDMSB, paddedHdr.Bytes())
						return
					}

					var echo bytes.Buffer
					fmt.Fprintf(&echo, "TRACE %s HTTP/2.0\r\nHost: %s\r\nContent-Type: text/plain\r\n", hm[":path"], hm[":authority"])
					if streamNum == 2 {
						echo.WriteString("Content-Length: 0\r\n")
					}
					fmt.Fprintf(&echo, "X-Tsunami-Probe: %s\r\n\r\n", hm[probeHeaderWireName])

					hblock := encodeApacheDynamicResponseHeaders("200", "", streamNum == 1)
					var paddedHdr bytes.Buffer
					paddedHdr.WriteByte(2)
					paddedHdr.Write([]byte{0x00, 0x00, 0x00, 0x00, 32})
					paddedHdr.Write(hblock)
					paddedHdr.Write([]byte{0, 0})
					// PADDED (0x08) | PRIORITY (0x20) | END_HEADERS (0x04) = 0x2c
					_ = writeRawH2Frame(serverConn, byte(http2.FrameHeaders), 0x2c, streamIDMSB, paddedHdr.Bytes())

					var paddedData bytes.Buffer
					paddedData.WriteByte(4)
					paddedData.Write(echo.Bytes())
					paddedData.Write([]byte{0, 0, 0, 0})
					// DATA with PADDED (0x08) | END_STREAM (0x01) = 0x09
					_ = writeRawH2Frame(serverConn, byte(http2.FrameData), 0x09, streamIDMSB, paddedData.Bytes())
				}
			}()
			return clientConn, nil
		}

		svc := nspb.NetworkService_builder{
			ServiceName:          "http",
			TransportProtocol:    npb.TransportProtocol_TCP,
			SupportedHttpMethods: []string{"GET"},
			NetworkEndpoint: npb.NetworkEndpoint_builder{
				IpAddress: npb.IpAddress_builder{Address: "127.0.0.1"}.Build(),
				Port:      npb.Port_builder{PortNumber: 8080}.Build(),
			}.Build(),
		}.Build()

		got, err := newTestModule(dial).Detect(t.Context(), svc)
		if err != nil {
			t.Fatalf("Detect() unexpected error: %v", err)
		}
		if len(got.GetDetectionReports()) != 1 {
			t.Fatalf("len(DetectionReports) = %d, want 1", len(got.GetDetectionReports()))
		}
	})

	t.Run("when_continuation_split_mid_huffman_with_ping_and_window_update_acks_ping_and_succeeds", func(t *testing.T) {
		var sawPingAck atomic.Bool
		pingPayload := [8]byte{'p', 'i', 'n', 'g', '1', '2', '3', '4'}

		dial := func(_ context.Context, mode transportMode, _, _ string, _ time.Duration) (net.Conn, error) {
			if mode == transportH2TLS {
				return nil, errors.New("h2c only")
			}
			clientConn, serverConn := newBufferedConnPair(t)
			go func() {
				defer serverConn.Close()
				_ = serverConn.SetDeadline(time.Now().Add(3 * time.Second))
				preface := make([]byte, len(h2ClientPreface))
				if _, err := io.ReadFull(serverConn, preface); err != nil {
					return
				}
				fr := http2.NewFramer(serverConn, serverConn)
				fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
				_ = fr.WriteSettings()

				for streamNum := 1; streamNum <= 3; streamNum++ {
					var req *http2.MetaHeadersFrame
					for req == nil {
						f, err := fr.ReadFrame()
						if err != nil {
							return
						}
						if pf, ok := f.(*http2.PingFrame); ok && pf.IsAck() && pf.Data == pingPayload {
							sawPingAck.Store(true)
						}
						if mh, ok := f.(*http2.MetaHeadersFrame); ok {
							req = mh
						}
					}
					if !req.StreamEnded() {
						for {
							f, err := fr.ReadFrame()
							if err != nil {
								return
							}
							if pf, ok := f.(*http2.PingFrame); ok && pf.IsAck() && pf.Data == pingPayload {
								sawPingAck.Store(true)
							}
							if df, ok := f.(*http2.DataFrame); ok && df.StreamEnded() {
								break
							}
						}
					}
					hm := headerMap(req.Fields)

					// Interleave PING (requiring PING ACK) and WINDOW_UPDATE before split HEADERS+CONTINUATION.
					_ = fr.WritePing(false, pingPayload)
					_ = fr.WriteWindowUpdate(0, 1024)

					if streamNum == 3 {
						var hbuf bytes.Buffer
						enc := hpack.NewEncoder(&hbuf) // hpack.Encoder uses Huffman encoding by default!
						_ = enc.WriteField(hpack.HeaderField{Name: ":status", Value: "413"})
						_ = fr.WriteHeaders(http2.HeadersFrameParam{
							StreamID:      req.StreamID,
							BlockFragment: hbuf.Bytes(),
							EndStream:     true,
							EndHeaders:    true,
						})
						// Read trailing PING ACK before closing pipe.
						if f, err := fr.ReadFrame(); err == nil {
							if pf, ok := f.(*http2.PingFrame); ok && pf.IsAck() && pf.Data == pingPayload {
								sawPingAck.Store(true)
							}
						}
						return
					}

					var fullBlock bytes.Buffer
					enc := hpack.NewEncoder(&fullBlock) // Huffman-encodes "message/http; charset=UTF-8"
					_ = enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
					_ = enc.WriteField(hpack.HeaderField{Name: "content-type", Value: "message/http; charset=UTF-8"})
					raw := fullBlock.Bytes()
					split1 := 3
					split2 := len(raw) - 4

					_ = fr.WriteHeaders(http2.HeadersFrameParam{
						StreamID:      req.StreamID,
						BlockFragment: raw[:split1],
						EndStream:     false,
						EndHeaders:    false,
					})
					_ = fr.WriteContinuation(req.StreamID, false, raw[split1:split2])
					_ = fr.WriteContinuation(req.StreamID, true, raw[split2:])

					var echo bytes.Buffer
					fmt.Fprintf(&echo, "TRACE %s HTTP/2.0\r\nHost: %s\r\nContent-Type: text/plain\r\n", hm[":path"], hm[":authority"])
					if streamNum == 2 {
						echo.WriteString("Content-Length: 0\r\n")
					}
					fmt.Fprintf(&echo, "X-Tsunami-Probe: %s\r\n\r\n", hm[probeHeaderWireName])
					_ = fr.WriteData(req.StreamID, true, echo.Bytes())
				}
			}()
			return clientConn, nil
		}

		svc := nspb.NetworkService_builder{
			ServiceName:          "http",
			TransportProtocol:    npb.TransportProtocol_TCP,
			SupportedHttpMethods: []string{"GET"},
			NetworkEndpoint: npb.NetworkEndpoint_builder{
				IpAddress: npb.IpAddress_builder{Address: "127.0.0.1"}.Build(),
				Port:      npb.Port_builder{PortNumber: 8080}.Build(),
			}.Build(),
		}.Build()

		got, err := newTestModule(dial).Detect(t.Context(), svc)
		if err != nil {
			t.Fatalf("Detect() unexpected error: %v", err)
		}
		if len(got.GetDetectionReports()) != 1 {
			t.Fatalf("len(DetectionReports) = %d, want 1", len(got.GetDetectionReports()))
		}
		if !sawPingAck.Load() {
			t.Errorf("sawPingAck = false, want client to respond with PING ACK matching payload")
		}
	})

	goAwayCases := []struct {
		name             string
		goAwayAfterConn1 int
	}{
		{
			name:             "when_server_sends_goaway_after_stream1_reconnects_with_stream1_and_fresh_hpack_table",
			goAwayAfterConn1: 1,
		},
		{
			name:             "when_server_sends_goaway_after_stream3_reconnects_for_stream5_and_succeeds",
			goAwayAfterConn1: 2,
		},
	}
	for _, tc := range goAwayCases {
		t.Run(tc.name, func(t *testing.T) {
			var connCount atomic.Int32
			var reconnectFirstStreamID atomic.Uint32

			dial := func(_ context.Context, mode transportMode, _, _ string, _ time.Duration) (net.Conn, error) {
				if mode == transportH2TLS {
					return nil, errors.New("h2c only")
				}
				cNum := int(connCount.Add(1))
				clientConn, serverConn := newBufferedConnPair(t)
				go func() {
					defer serverConn.Close()
					_ = serverConn.SetDeadline(time.Now().Add(3 * time.Second))
					preface := make([]byte, len(h2ClientPreface))
					if _, err := io.ReadFull(serverConn, preface); err != nil {
						return
					}
					fr := http2.NewFramer(serverConn, serverConn)
					fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
					_ = fr.WriteSettings()

					streamsOnThisConn := 0
					indexedCT := false
					for {
						f, err := fr.ReadFrame()
						if err != nil {
							return
						}
						mh, ok := f.(*http2.MetaHeadersFrame)
						if !ok {
							continue
						}
						streamsOnThisConn++
						if cNum == 2 && streamsOnThisConn == 1 {
							reconnectFirstStreamID.Store(mh.StreamID)
						}
						var reqBody []byte
						endStream := mh.StreamEnded()
						for !endStream {
							nf, rErr := fr.ReadFrame()
							if rErr != nil {
								return
							}
							if df, ok := nf.(*http2.DataFrame); ok && df.StreamID == mh.StreamID {
								reqBody = append(reqBody, df.Data()...)
								endStream = df.StreamEnded()
							}
						}
						writeMockApacheStreamResponse(fr, mh.StreamID, &indexedCT, mh.Fields, reqBody, defaultVulnerableApacheConfig())
						if cNum == 1 && streamsOnThisConn == tc.goAwayAfterConn1 {
							_ = fr.WriteGoAway(mh.StreamID, http2.ErrCodeNo, nil)
							return
						}
					}
				}()
				return clientConn, nil
			}

			svc := nspb.NetworkService_builder{
				ServiceName:          "http",
				TransportProtocol:    npb.TransportProtocol_TCP,
				SupportedHttpMethods: []string{"GET"},
				NetworkEndpoint: npb.NetworkEndpoint_builder{
					IpAddress: npb.IpAddress_builder{Address: "127.0.0.1"}.Build(),
					Port:      npb.Port_builder{PortNumber: 8080}.Build(),
				}.Build(),
			}.Build()

			got, err := newTestModule(dial).Detect(t.Context(), svc)
			if err != nil {
				t.Fatalf("Detect() unexpected error: %v", err)
			}
			if len(got.GetDetectionReports()) != 1 {
				t.Fatalf("len(DetectionReports) = %d, want 1", len(got.GetDetectionReports()))
			}
			if connCount.Load() != 2 {
				t.Errorf("connCount = %d, want 2 connections across GOAWAY reconnect", connCount.Load())
			}
			if reconnectFirstStreamID.Load() != 1 {
				t.Errorf("reconnectFirstStreamID = %d, want stream ID reset to 1 on new connection", reconnectFirstStreamID.Load())
			}
		})
	}

	malformedCases := []struct {
		name       string
		serverFunc func(conn net.Conn)
	}{
		{
			name: "when_http11_server_replies_400_bad_request_rejects_at_9byte_preface_gate",
			serverFunc: func(conn net.Conn) {
				defer conn.Close()
				buf := make([]byte, len(h2ClientPreface))
				_, _ = io.ReadFull(conn, buf)
				_, _ = conn.Write([]byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"))
				// Hold pipe open until client closes to prove detector aborts at 9-byte header gate without waiting for 4.74 MiB.
				_, _ = io.Copy(io.Discard, conn)
			},
		},
		{
			name: "when_peer_starts_with_non_settings_frame_followed_by_vulnerable_responses_rejects_at_preface_gate",
			serverFunc: func(conn net.Conn) {
				defer conn.Close()
				buf := make([]byte, len(h2ClientPreface))
				if _, err := io.ReadFull(conn, buf); err != nil {
					return
				}
				fr := http2.NewFramer(conn, conn)
				fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
				// Send PING ACK instead of mandatory server SETTINGS as the very first frame;
				// if preface validation is omitted, subsequent vulnerable responses would falsely trigger!
				_ = fr.WritePing(true, [8]byte{1, 2, 3, 4, 5, 6, 7, 8})
				indexedCT := false
				for {
					f, err := fr.ReadFrame()
					if err != nil {
						return
					}
					if mh, ok := f.(*http2.MetaHeadersFrame); ok {
						var reqBody []byte
						endStream := mh.StreamEnded()
						for !endStream {
							nf, rErr := fr.ReadFrame()
							if rErr != nil {
								return
							}
							if df, ok := nf.(*http2.DataFrame); ok && df.StreamID == mh.StreamID {
								reqBody = append(reqBody, df.Data()...)
								endStream = df.StreamEnded()
							}
						}
						writeMockApacheStreamResponse(fr, mh.StreamID, &indexedCT, mh.Fields, reqBody, defaultVulnerableApacheConfig())
					}
				}
			},
		},
		{
			name: "when_oversized_response_data_frame_after_headers_exceeds_16384_rejects_cleanly",
			serverFunc: func(conn net.Conn) {
				defer conn.Close()
				preface := make([]byte, len(h2ClientPreface))
				if _, err := io.ReadFull(conn, preface); err != nil {
					return
				}
				fr := http2.NewFramer(conn, conn)
				fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
				_ = fr.WriteSettings()
				for {
					f, err := fr.ReadFrame()
					if err != nil {
						return
					}
					mh, ok := f.(*http2.MetaHeadersFrame)
					if !ok {
						continue
					}
					hm := headerMap(mh.Fields)
					echo := fmt.Sprintf("TRACE / HTTP/2.0\r\nHost: %s\r\nContent-Type: text/plain\r\nX-Tsunami-Probe: %s\r\n\r\n", hm[":authority"], hm[probeHeaderWireName])
					hblock := encodeApacheDynamicResponseHeaders("200", "", true)
					_ = fr.WriteHeaders(http2.HeadersFrameParam{
						StreamID:      mh.StreamID,
						BlockFragment: hblock,
						EndStream:     false,
						EndHeaders:    true,
					})
					// First send valid partial DATA without END_STREAM, then an illegal >16384-byte DATA frame header!
					// If the client erroneously swallows ErrFrameTooLarge on Stream 1, continue serving Streams 3 & 5
					// on subsequent connections/streams so swallowing ErrFrameTooLarge produces a false finding!
					if mh.StreamID == 1 {
						_ = fr.WriteData(mh.StreamID, false, []byte(echo))
						var oversizedHdr [9]byte
						oversizedHdr[0] = 0x00
						oversizedHdr[1] = 0x50 // 0x005000 = 20480 > 16384
						oversizedHdr[2] = 0x00
						oversizedHdr[3] = byte(http2.FrameData)
						oversizedHdr[4] = byte(http2.FlagDataEndStream)
						binary.BigEndian.PutUint32(oversizedHdr[5:9], mh.StreamID)
						_, _ = conn.Write(oversizedHdr[:])
						_, _ = conn.Write(bytes.Repeat([]byte("A"), 20480))
						continue
					}
					indexedCT := true
					writeMockApacheStreamResponse(fr, mh.StreamID, &indexedCT, mh.Fields, nil, defaultVulnerableApacheConfig())
				}
			},
		},
		{
			name: "when_excessive_empty_continuation_frames_exceed_limit_aborts_immediately",
			serverFunc: func(conn net.Conn) {
				defer conn.Close()
				preface := make([]byte, len(h2ClientPreface))
				if _, err := io.ReadFull(conn, preface); err != nil {
					return
				}
				fr := http2.NewFramer(conn, conn)
				fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
				_ = fr.WriteSettings()
				for {
					f, err := fr.ReadFrame()
					if err != nil {
						return
					}
					mh, ok := f.(*http2.MetaHeadersFrame)
					if !ok {
						continue
					}
					_ = writeRawH2Frame(conn, byte(http2.FrameHeaders), 0x00, mh.StreamID, []byte{0x88})
					for i := 0; i < 32; i++ {
						if wErr := writeRawH2Frame(conn, byte(http2.FrameContinuation), 0x00, mh.StreamID, nil); wErr != nil {
							return
						}
					}
					// Hold pipe open until client closes; if unbounded CONTINUATION loop existed, client would stall until timeout.
					_, _ = io.Copy(io.Discard, conn)
					return
				}
			},
		},
		{
			name: "when_hpack_varint_overflow_in_headers_rejects_cleanly",
			serverFunc: func(conn net.Conn) {
				defer conn.Close()
				preface := make([]byte, len(h2ClientPreface))
				_, _ = io.ReadFull(conn, preface)
				fr := http2.NewFramer(conn, conn)
				_ = fr.WriteSettings()
				for {
					f, err := fr.ReadFrame()
					if err != nil {
						return
					}
					if hf, ok := f.(*http2.HeadersFrame); ok {
						badHpack := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f}
						_ = writeRawH2Frame(conn, byte(http2.FrameHeaders), 0x05, hf.StreamID, badHpack)
						return
					}
				}
			},
		},
		{
			name: "when_huffman_eos_or_bad_padding_in_headers_rejects_cleanly",
			serverFunc: func(conn net.Conn) {
				defer conn.Close()
				preface := make([]byte, len(h2ClientPreface))
				_, _ = io.ReadFull(conn, preface)
				fr := http2.NewFramer(conn, conn)
				_ = fr.WriteSettings()
				for {
					f, err := fr.ReadFrame()
					if err != nil {
						return
					}
					if hf, ok := f.(*http2.HeadersFrame); ok {
						// 0x88 (:status 200), followed by 0x5f (content-type) with 4-byte Huffman EOS 0x84 0xff 0xff 0xff 0xff (>7-bit padding / EOS)
						badHuffman := []byte{0x88, 0x5f, 0x84, 0xff, 0xff, 0xff, 0xff}
						_ = writeRawH2Frame(conn, byte(http2.FrameHeaders), 0x05, hf.StreamID, badHuffman)
						return
					}
				}
			},
		},
	}

	for _, tc := range malformedCases {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Now()
			dial := func(_ context.Context, mode transportMode, _, _ string, _ time.Duration) (net.Conn, error) {
				if mode == transportH2TLS {
					return nil, errors.New("h2c only")
				}
				clientConn, serverConn := newBufferedConnPair(t)
				go tc.serverFunc(serverConn)
				return clientConn, nil
			}

			svc := nspb.NetworkService_builder{
				ServiceName:          "http",
				TransportProtocol:    npb.TransportProtocol_TCP,
				SupportedHttpMethods: []string{"GET"},
				NetworkEndpoint: npb.NetworkEndpoint_builder{
					IpAddress: npb.IpAddress_builder{Address: "127.0.0.1"}.Build(),
					Port:      npb.Port_builder{PortNumber: 8080}.Build(),
				}.Build(),
			}.Build()

			m := newTestModule(dial)
			m.timeout = 1500 * time.Millisecond
			got, err := m.Detect(t.Context(), svc)
			if err != nil {
				t.Fatalf("Detect() unexpected error: %v", err)
			}
			if got != nil && len(got.GetDetectionReports()) > 0 {
				t.Fatalf("Detect() returned unexpected finding on malformed peer: %v", got)
			}
			if elapsed := time.Since(start); elapsed >= 1200*time.Millisecond {
				t.Errorf("Detect() took %v on malformed peer, expected fast rejection without socket-timeout stall", elapsed)
			}
		})
	}

	t.Run("when_tls_peer_negotiates_http11_alpn_rejects_before_sending_h2_preface", func(t *testing.T) {
		cert := generateSelfSignedCert(t)
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("net.Listen failed: %v", err)
		}
		t.Cleanup(func() { _ = ln.Close() })

		var appBytesOnTLS atomic.Int32
		var mu sync.Mutex
		var recorded []recordedStream

		go func() {
			for {
				rawConn, acceptErr := ln.Accept()
				if acceptErr != nil {
					return
				}
				go func(c net.Conn) {
					defer c.Close()
					// Negotiate http/1.1 instead of h2 on TLS; if the client ignores ALPN and
					// proceeds to speak HTTP/2 anyway, serve vulnerable Apache so ALPN mutants fail!
					tlsSrv := tls.Server(c, &tls.Config{
						Certificates: []tls.Certificate{cert},
						NextProtos:   []string{"http/1.1"},
					})
					if hsErr := tlsSrv.Handshake(); hsErr != nil {
						// When client only advertises h2 and server only advertises http/1.1, Go TLS may
						// either abort with no_application_protocol or complete with empty NegotiatedProtocol.
						return
					}
					_ = tlsSrv.SetDeadline(time.Now().Add(300 * time.Millisecond))
					var peek [1]byte
					n, _ := tlsSrv.Read(peek[:])
					if n > 0 {
						appBytesOnTLS.Add(int32(n))
						serveMockApacheH2Conn(t, &prefixedConn{Conn: tlsSrv, prefix: peek[:n]}, defaultVulnerableApacheConfig(), &recorded, &mu)
					}
				}(rawConn)
			}
		}()

		// Also test empty ALPN negotiation (server with NextProtos: nil completes handshake with NegotiatedProtocol == "").
		emptyALPNLn, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("net.Listen failed: %v", err)
		}
		t.Cleanup(func() { _ = emptyALPNLn.Close() })

		go func() {
			for {
				rawConn, acceptErr := emptyALPNLn.Accept()
				if acceptErr != nil {
					return
				}
				go func(c net.Conn) {
					// First connection is TLS (h2 attempt on port-443/https service); second connection is h2c fallback (reply HTTP/1.1 400).
					tlsSrv := tls.Server(c, &tls.Config{
						Certificates: []tls.Certificate{cert},
					})
					if hsErr := tlsSrv.Handshake(); hsErr != nil {
						_ = c.Close()
						return
					}
					_ = tlsSrv.SetDeadline(time.Now().Add(300 * time.Millisecond))
					var peek [1]byte
					n, _ := tlsSrv.Read(peek[:])
					if n > 0 {
						appBytesOnTLS.Add(int32(n))
						serveMockApacheH2Conn(t, &prefixedConn{Conn: tlsSrv, prefix: peek[:n]}, defaultVulnerableApacheConfig(), &recorded, &mu)
						return
					}
					_ = tlsSrv.Close()
				}(rawConn)
			}
		}()

		for _, port := range []uint32{
			uint32(ln.Addr().(*net.TCPAddr).Port),
			uint32(emptyALPNLn.Addr().(*net.TCPAddr).Port),
		} {
			svc := nspb.NetworkService_builder{
				ServiceName:          "https",
				TransportProtocol:    npb.TransportProtocol_TCP,
				SupportedHttpMethods: []string{"GET"},
				NetworkEndpoint: npb.NetworkEndpoint_builder{
					IpAddress: npb.IpAddress_builder{Address: "127.0.0.1"}.Build(),
					Port:      npb.Port_builder{PortNumber: port}.Build(),
				}.Build(),
			}.Build()

			got, err := newTestModule(defaultDial).Detect(t.Context(), svc)
			if err != nil {
				t.Fatalf("Detect() unexpected error: %v", err)
			}
			if got != nil && len(got.GetDetectionReports()) > 0 {
				t.Fatalf("Detect() emitted false finding when TLS ALPN was not h2: %v", got)
			}
			if appBytesOnTLS.Load() != 0 {
				t.Errorf("appBytesOnTLS = %d, want 0 HTTP/2 bytes sent over non-h2 TLS session", appBytesOnTLS.Load())
			}
		}
	})
}

type prefixedConn struct {
	net.Conn
	prefix []byte
}

func (p *prefixedConn) Read(b []byte) (int, error) {
	if len(p.prefix) > 0 {
		n := copy(b, p.prefix)
		p.prefix = p.prefix[n:]
		return n, nil
	}
	return p.Conn.Read(b)
}

func TestServiceEligibilityAndTransportParity(t *testing.T) {
	testCases := []struct {
		name           string
		svc            *nspb.NetworkService
		wantSupported  bool
		wantTransports []transportMode
	}{
		{
			name:          "when_nil_service_returns_not_supported",
			svc:           nil,
			wantSupported: false,
		},
		{
			name: "when_udp_service_returns_not_supported",
			svc: nspb.NetworkService_builder{
				ServiceName:       "http",
				TransportProtocol: npb.TransportProtocol_UDP,
				NetworkEndpoint: npb.NetworkEndpoint_builder{
					Port: npb.Port_builder{PortNumber: 80}.Build(),
				}.Build(),
			}.Build(),
			wantSupported: false,
		},
		{
			name: "when_nmap_http_service_without_supported_http_methods_on_custom_port_matches_java_parity",
			svc: nspb.NetworkService_builder{
				ServiceName:       "http",
				TransportProtocol: npb.TransportProtocol_TCP,
				NetworkEndpoint: npb.NetworkEndpoint_builder{
					Port: npb.Port_builder{PortNumber: 9080}.Build(),
				}.Build(),
			}.Build(),
			wantSupported:  true,
			wantTransports: []transportMode{transportH2C, transportH2TLS},
		},
		{
			name: "when_nmap_https_service_without_supported_http_methods_on_custom_port_matches_java_parity",
			svc: nspb.NetworkService_builder{
				ServiceName:       "https",
				TransportProtocol: npb.TransportProtocol_TCP,
				NetworkEndpoint: npb.NetworkEndpoint_builder{
					Port: npb.Port_builder{PortNumber: 9443}.Build(),
				}.Build(),
			}.Build(),
			wantSupported:  true,
			wantTransports: []transportMode{transportH2TLS, transportH2C},
		},
		{
			name: "when_nmap_ssl_http_service_without_methods_matches_java_parity",
			svc: nspb.NetworkService_builder{
				ServiceName:       "ssl/http",
				TransportProtocol: npb.TransportProtocol_TCP,
				NetworkEndpoint: npb.NetworkEndpoint_builder{
					Port: npb.Port_builder{PortNumber: 9443}.Build(),
				}.Build(),
			}.Build(),
			wantSupported:  true,
			wantTransports: []transportMode{transportH2TLS, transportH2C},
		},
		{
			name: "when_http_over_ssl_on_arbitrary_port_tries_h2_before_h2c",
			svc: nspb.NetworkService_builder{
				ServiceName:       "http over ssl",
				TransportProtocol: npb.TransportProtocol_TCP,
				NetworkEndpoint: npb.NetworkEndpoint_builder{
					Port: npb.Port_builder{PortNumber: 10443}.Build(),
				}.Build(),
			}.Build(),
			wantSupported:  true,
			wantTransports: []transportMode{transportH2TLS, transportH2C},
		},
		{
			name: "when_tcpwrapped_on_standard_web_port_8080_is_supported_h2c_first",
			svc: nspb.NetworkService_builder{
				ServiceName:       "tcpwrapped",
				TransportProtocol: npb.TransportProtocol_TCP,
				NetworkEndpoint: npb.NetworkEndpoint_builder{
					Port: npb.Port_builder{PortNumber: 8080}.Build(),
				}.Build(),
			}.Build(),
			wantSupported:  true,
			wantTransports: []transportMode{transportH2C, transportH2TLS},
		},
		{
			name: "when_empty_service_name_on_port_8443_is_supported_h2_first",
			svc: nspb.NetworkService_builder{
				ServiceName:       "",
				TransportProtocol: npb.TransportProtocol_TCP,
				NetworkEndpoint: npb.NetworkEndpoint_builder{
					Port: npb.Port_builder{PortNumber: 8443}.Build(),
				}.Build(),
			}.Build(),
			wantSupported:  true,
			wantTransports: []transportMode{transportH2TLS, transportH2C},
		},
		{
			name: "when_tcpwrapped_on_ssh_port_22_returns_not_supported",
			svc: nspb.NetworkService_builder{
				ServiceName:       "tcpwrapped",
				TransportProtocol: npb.TransportProtocol_TCP,
				NetworkEndpoint: npb.NetworkEndpoint_builder{
					Port: npb.Port_builder{PortNumber: 22}.Build(),
				}.Build(),
			}.Build(),
			wantSupported: false,
		},
		{
			name: "when_ssh_service_on_port_80_returns_not_supported",
			svc: nspb.NetworkService_builder{
				ServiceName:       "ssh",
				TransportProtocol: npb.TransportProtocol_TCP,
				NetworkEndpoint: npb.NetworkEndpoint_builder{
					Port: npb.Port_builder{PortNumber: 80}.Build(),
				}.Build(),
			}.Build(),
			wantSupported: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := isSupportedService(tc.svc)
			if got != tc.wantSupported {
				t.Fatalf("isSupportedService() = %v, want %v", got, tc.wantSupported)
			}
			if tc.wantSupported {
				gotTransports := preferredTransports(tc.svc)
				if diff := cmp.Diff(tc.wantTransports, gotTransports); diff != "" {
					t.Errorf("preferredTransports() diff (-want +got):\n%s", diff)
				}
			}
		})
	}
}

func TestEndpointSNIAndCrawledPathFallback(t *testing.T) {
	t.Run("when_ipv6_and_ipv4_literals_bracket_authority_and_suppress_sni_while_dns_sets_sni", func(t *testing.T) {
		epCases := []struct {
			name          string
			ep            *npb.NetworkEndpoint
			defaultPort   uint32
			wantOK        bool
			wantDialAddr  string
			wantAuthority string
			wantSNI       string
		}{
			{
				name:   "when_empty_endpoint_returns_not_ok",
				ep:     &npb.NetworkEndpoint{},
				wantOK: false,
			},
			{
				name: "when_ipv6_literal_brackets_authority_and_suppresses_sni",
				ep: npb.NetworkEndpoint_builder{
					IpAddress: npb.IpAddress_builder{Address: "2001:db8::1"}.Build(),
					Port:      npb.Port_builder{PortNumber: 8443}.Build(),
				}.Build(),
				defaultPort:   443,
				wantOK:        true,
				wantDialAddr:  "[2001:db8::1]:8443",
				wantAuthority: "[2001:db8::1]:8443",
				wantSNI:       "",
			},
			{
				name: "when_ipv4_literal_omits_brackets_and_suppresses_sni",
				ep: npb.NetworkEndpoint_builder{
					IpAddress: npb.IpAddress_builder{Address: "127.0.0.1"}.Build(),
				}.Build(),
				defaultPort:   443,
				wantOK:        true,
				wantDialAddr:  "127.0.0.1:443",
				wantAuthority: "127.0.0.1:443",
				wantSNI:       "",
			},
			{
				name: "when_dns_hostname_with_trailing_dot_and_uppercase_normalizes_authority_and_sni",
				ep: npb.NetworkEndpoint_builder{
					Hostname:  npb.Hostname_builder{Name: "APACHE.Example.Test."}.Build(),
					IpAddress: npb.IpAddress_builder{Address: "127.0.0.1"}.Build(),
					Port:      npb.Port_builder{PortNumber: 8443}.Build(),
				}.Build(),
				defaultPort:   443,
				wantOK:        true,
				wantDialAddr:  "127.0.0.1:8443",
				wantAuthority: "apache.example.test:8443",
				wantSNI:       "apache.example.test",
			},
			{
				name: "when_dot_only_hostname_without_ip_returns_not_ok",
				ep: npb.NetworkEndpoint_builder{
					Hostname: npb.Hostname_builder{Name: "..."}.Build(),
				}.Build(),
				defaultPort: 80,
				wantOK:      false,
			},
		}

		for _, tc := range epCases {
			t.Run(tc.name, func(t *testing.T) {
				got, ok := resolveEndpointTarget(tc.ep, tc.defaultPort)
				if ok != tc.wantOK {
					t.Fatalf("resolveEndpointTarget() ok = %v, want %v", ok, tc.wantOK)
				}
				if !tc.wantOK {
					return
				}
				if got.dialAddr != tc.wantDialAddr || got.authority != tc.wantAuthority || got.sniHost != tc.wantSNI {
					t.Errorf("resolveEndpointTarget() = %+v, want dial=%q auth=%q sni=%q", got, tc.wantDialAddr, tc.wantAuthority, tc.wantSNI)
				}
			})
		}

		// Verify authorityForMode omits default ports (:80 on h2c, :443 on h2) while keeping IPv6 brackets.
		v4Default, _ := resolveEndpointTarget(npb.NetworkEndpoint_builder{
			Hostname: npb.Hostname_builder{Name: "www.example.test"}.Build(),
			Port:     npb.Port_builder{PortNumber: 443}.Build(),
		}.Build(), 443)
		if got := v4Default.authorityForMode(transportH2TLS); got != "www.example.test" {
			t.Errorf("authorityForMode(h2, 443) = %q, want www.example.test", got)
		}
		if got := v4Default.authorityForMode(transportH2C); got != "www.example.test:443" {
			t.Errorf("authorityForMode(h2c, 443) = %q, want www.example.test:443", got)
		}
		v6Default, _ := resolveEndpointTarget(npb.NetworkEndpoint_builder{
			IpAddress: npb.IpAddress_builder{Address: "2001:db8::1"}.Build(),
			Port:      npb.Port_builder{PortNumber: 80}.Build(),
		}.Build(), 80)
		if got := v6Default.authorityForMode(transportH2C); got != "[2001:db8::1]" {
			t.Errorf("authorityForMode(h2c, 80, ipv6) = %q, want [2001:db8::1]", got)
		}

		// Verify live TLS ClientHello SNI suppression on IP literal vs DNS hostname via defaultDial.
		cert := generateSelfSignedCert(t)
		var seenSNI sync.Map
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("net.Listen failed: %v", err)
		}
		t.Cleanup(func() { _ = ln.Close() })

		var connIdx atomic.Int32
		go func() {
			for {
				raw, aErr := ln.Accept()
				if aErr != nil {
					return
				}
				idx := connIdx.Add(1)
				go func(c net.Conn, id int32) {
					defer c.Close()
					tlsSrv := tls.Server(c, &tls.Config{
						Certificates: []tls.Certificate{cert},
						NextProtos:   []string{"h2"},
						GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
							seenSNI.Store(id, chi.ServerName)
							return nil, nil
						},
					})
					_ = tlsSrv.Handshake()
				}(raw, idx)
			}
		}()

		addr := ln.Addr().String()
		c1, err := defaultDial(t.Context(), transportH2TLS, addr, "", 2*time.Second)
		if err != nil {
			t.Fatalf("defaultDial(no SNI) failed: %v", err)
		}
		_ = c1.Close()
		if gotSNI, _ := seenSNI.Load(int32(1)); gotSNI != "" {
			t.Errorf("ClientHello ServerName for IP literal = %q, want empty", gotSNI)
		}

		c2, err := defaultDial(t.Context(), transportH2TLS, addr, "apache.example.test", 2*time.Second)
		if err != nil {
			t.Fatalf("defaultDial(DNS SNI) failed: %v", err)
		}
		_ = c2.Close()
		if gotSNI, _ := seenSNI.Load(int32(2)); gotSNI != "apache.example.test" {
			t.Errorf("ClientHello ServerName for DNS hostname = %q, want %q", gotSNI, "apache.example.test")
		}
	})

	t.Run("when_root_returns_404_filters_cross_origin_and_probes_up_to_two_same_origin_crawled_paths", func(t *testing.T) {
		var mu sync.Mutex
		var recorded []recordedStream

		cfg := defaultVulnerableApacheConfig()
		cfg.routeStatuses = map[string]string{
			"/":      "404",
			"/first": "403",
			"/third": "200", // should not be reached because maxCrawledFallbacks = 2 (/first and /second)
		}

		dial := func(_ context.Context, mode transportMode, _, _ string, _ time.Duration) (net.Conn, error) {
			if mode == transportH2TLS {
				return nil, errors.New("h2c only")
			}
			clientConn, serverConn := newBufferedConnPair(t)
			go serveMockApacheH2Conn(t, serverConn, cfg, &recorded, &mu)
			return clientConn, nil
		}

		svc := nspb.NetworkService_builder{
			ServiceName:          "http",
			TransportProtocol:    npb.TransportProtocol_TCP,
			SupportedHttpMethods: []string{"GET"},
			NetworkEndpoint: npb.NetworkEndpoint_builder{
				Hostname:  npb.Hostname_builder{Name: "apache.example.test"}.Build(),
				IpAddress: npb.IpAddress_builder{Address: "127.0.0.1"}.Build(),
				Port:      npb.Port_builder{PortNumber: 8080}.Build(),
			}.Build(),
			ServiceContext: nspb.ServiceContext_builder{
				WebServiceContext: nspb.WebServiceContext_builder{
					CrawlResults: []*wcpb.CrawlResult{
						// Off-origin host -> MUST be skipped!
						wcpb.CrawlResult_builder{
							CrawlTarget: wcpb.CrawlTarget_builder{Url: "https://cdn.external.example/evil"}.Build(),
						}.Build(),
						// Protocol-relative off-origin -> MUST be skipped!
						wcpb.CrawlResult_builder{
							CrawlTarget: wcpb.CrawlTarget_builder{Url: "//evil.example/phish"}.Build(),
						}.Build(),
						// Cross-port -> MUST be skipped!
						wcpb.CrawlResult_builder{
							CrawlTarget: wcpb.CrawlTarget_builder{Url: "http://apache.example.test:9999/wrongport"}.Build(),
						}.Build(),
						// Non-HTTP scheme -> MUST be skipped!
						wcpb.CrawlResult_builder{
							CrawlTarget: wcpb.CrawlTarget_builder{Url: "javascript:alert(1)"}.Build(),
						}.Build(),
						// Control byte in path -> MUST be rejected!
						wcpb.CrawlResult_builder{
							CrawlTarget: wcpb.CrawlTarget_builder{Url: "/bad\x00path"}.Build(),
						}.Build(),
						// Same-origin #1 (returns 403)
						wcpb.CrawlResult_builder{
							CrawlTarget: wcpb.CrawlTarget_builder{Url: "http://apache.example.test:8080/first#frag"}.Build(),
						}.Build(),
						// Same-origin #2 via endpoint IP with fragment (vulnerable 200!)
						wcpb.CrawlResult_builder{
							CrawlTarget: wcpb.CrawlTarget_builder{Url: "http://127.0.0.1:8080/second?mode=1#section"}.Build(),
						}.Build(),
						// Same-origin #3 beyond maxCrawledFallbacks = 2
						wcpb.CrawlResult_builder{
							CrawlTarget: wcpb.CrawlTarget_builder{Url: "http://apache.example.test:8080/third"}.Build(),
						}.Build(),
					},
				}.Build(),
			}.Build(),
		}.Build()

		got, err := newTestModule(dial).Detect(t.Context(), svc)
		if err != nil {
			t.Fatalf("Detect() unexpected error: %v", err)
		}
		if len(got.GetDetectionReports()) != 1 {
			t.Fatalf("len(DetectionReports) = %d, want 1", len(got.GetDetectionReports()))
		}
		detail := got.GetDetectionReports()[0].GetVulnerability().GetAdditionalDetails()[0].GetTextData().GetText()
		if !strings.Contains(detail, "http://apache.example.test:8080/second?mode=1:") {
			t.Errorf("AdditionalDetail = %q, want matched fallback path /second?mode=1", detail)
		}
	})
}

func TestParseTraceEchoAndContextErrors(t *testing.T) {
	echoCases := []struct {
		name     string
		payload  string
		wantOK   bool
		wantLine string
		wantBody string
	}{
		{
			name:     "when_crlf_trace_echo_with_body_parses_exact_case_and_body",
			payload:  "TRACE / HTTP/2.0\r\nHost: 127.0.0.1:80\r\nX-Tsunami-Probe: abc\r\n\r\nx",
			wantOK:   true,
			wantLine: "TRACE / HTTP/2.0",
			wantBody: "x",
		},
		{
			name:     "when_lf_only_trace_echo_parses_cleanly",
			payload:  "TRACE /app HTTP/2.0\nHost: 127.0.0.1:80\n\n",
			wantOK:   true,
			wantLine: "TRACE /app HTTP/2.0",
			wantBody: "",
		},
		{
			name:    "when_missing_blank_line_terminator_returns_false",
			payload: "TRACE / HTTP/2.0\r\nHost: 127.0.0.1:80\r\n",
			wantOK:  false,
		},
		{
			name:    "when_empty_request_line_returns_false",
			payload: "\r\nHost: 127.0.0.1:80\r\n\r\n",
			wantOK:  false,
		},
		{
			name:    "when_malformed_header_without_colon_returns_false",
			payload: "TRACE / HTTP/2.0\r\nMalformedHeaderLine\r\n\r\n",
			wantOK:  false,
		},
	}

	for _, tc := range echoCases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseTraceEcho([]byte(tc.payload))
			if ok != tc.wantOK {
				t.Fatalf("parseTraceEcho() ok = %v, want %v", ok, tc.wantOK)
			}
			if !tc.wantOK {
				return
			}
			if got.requestLine != tc.wantLine || string(got.body) != tc.wantBody {
				t.Errorf("parseTraceEcho() = (%q, %q), want (%q, %q)", got.requestLine, string(got.body), tc.wantLine, tc.wantBody)
			}
		})
	}

	t.Run("when_context_canceled_before_detect_returns_context_canceled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		svc := nspb.NetworkService_builder{
			ServiceName:          "http",
			TransportProtocol:    npb.TransportProtocol_TCP,
			SupportedHttpMethods: []string{"GET"},
		}.Build()
		_, err := newTestModule(defaultDial).Detect(ctx, svc)
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Detect() err = %v, want context.Canceled", err)
		}
	})

	t.Run("when_outbound_header_count_exceeds_safety_ceiling_returns_err_too_many_headers", func(t *testing.T) {
		s := &h2ProbeSession{}
		many := make([]hpack.HeaderField, 10)
		if _, err := s.roundTrip(t.Context(), many, nil); !errors.Is(err, errTooManyHeaders) {
			t.Errorf("roundTrip(10 headers) err = %v, want %v", err, errTooManyHeaders)
		}
	})

	t.Run("when_endpoint_missing_address_or_context_canceled_mid_probe_handles_cleanly", func(t *testing.T) {
		emptyEpSvc := nspb.NetworkService_builder{
			ServiceName:          "http",
			TransportProtocol:    npb.TransportProtocol_TCP,
			SupportedHttpMethods: []string{"GET"},
			NetworkEndpoint:      &npb.NetworkEndpoint{},
		}.Build()
		got, err := newTestModule(defaultDial).Detect(t.Context(), emptyEpSvc)
		if err != nil || got != nil {
			t.Errorf("Detect(empty endpoint) = (%v, %v), want (nil, nil)", got, err)
		}

		ctx, cancel := context.WithCancel(t.Context())
		dialCancel := func(_ context.Context, _ transportMode, _, _ string, _ time.Duration) (net.Conn, error) {
			cancel()
			return nil, context.Canceled
		}
		validSvc := nspb.NetworkService_builder{
			ServiceName:          "https",
			TransportProtocol:    npb.TransportProtocol_TCP,
			SupportedHttpMethods: []string{"GET"},
			NetworkEndpoint: npb.NetworkEndpoint_builder{
				IpAddress: npb.IpAddress_builder{Address: "127.0.0.1"}.Build(),
			}.Build(),
		}.Build()
		if _, cErr := newTestModule(dialCancel).Detect(ctx, validSvc); !errors.Is(cErr, context.Canceled) {
			t.Errorf("Detect(mid-probe cancel) err = %v, want context.Canceled", cErr)
		}
	})

	t.Run("when_extract_candidate_paths_evaluates_relative_https_ipv6_and_invalid_urls", func(t *testing.T) {
		svc := nspb.NetworkService_builder{
			ServiceName: "https",
			ServiceContext: nspb.ServiceContext_builder{
				WebServiceContext: nspb.WebServiceContext_builder{
					ApplicationRoot: "root#frag",
					CrawlResults: []*wcpb.CrawlResult{
						wcpb.CrawlResult_builder{CrawlTarget: wcpb.CrawlTarget_builder{Url: ""}.Build()}.Build(),
						wcpb.CrawlResult_builder{CrawlTarget: wcpb.CrawlTarget_builder{Url: "http://[::1]:badport/x"}.Build()}.Build(),
						wcpb.CrawlResult_builder{CrawlTarget: wcpb.CrawlTarget_builder{Url: "ftp://[2001:db8::1]/x"}.Build()}.Build(),
						wcpb.CrawlResult_builder{CrawlTarget: wcpb.CrawlTarget_builder{Url: "https://[2001:db8::1]:0/x"}.Build()}.Build(),
						wcpb.CrawlResult_builder{CrawlTarget: wcpb.CrawlTarget_builder{Url: "#onlyfrag"}.Build()}.Build(),
						wcpb.CrawlResult_builder{CrawlTarget: wcpb.CrawlTarget_builder{Url: "relative/path#frag"}.Build()}.Build(),
						wcpb.CrawlResult_builder{CrawlTarget: wcpb.CrawlTarget_builder{Url: "https://[2001:0db8:0:0:0:0:0:1]/canonical"}.Build()}.Build(),
					},
				}.Build(),
			}.Build(),
			NetworkEndpoint: npb.NetworkEndpoint_builder{
				IpAddress: npb.IpAddress_builder{Address: "2001:db8::1"}.Build(),
			}.Build(),
		}.Build()

		gotPaths := extractCandidatePaths(svc, 3)
		wantPaths := []string{"/", "/root", "/relative/path", "/canonical"}
		if diff := cmp.Diff(wantPaths, gotPaths); diff != "" {
			t.Errorf("extractCandidatePaths() diff (-want +got):\n%s", diff)
		}
	})
}

func TestH2SessionProtocolEdgeCases(t *testing.T) {
	reqHeaders := []hpack.HeaderField{
		{Name: ":method", Value: "TRACE"},
		{Name: ":scheme", Value: "http"},
		{Name: ":authority", Value: "127.0.0.1:8080"},
		{Name: ":path", Value: "/"},
	}

	testCases := []struct {
		name       string
		serverFunc func(t *testing.T, conn net.Conn)
		wantStatus string
		wantBody   string
		wantErr    bool
	}{
		{
			name: "when_multichunk_data_midstream_settings_unrelated_streams_and_eof_after_headers_succeeds",
			serverFunc: func(t *testing.T, conn net.Conn) {
				t.Helper()
				defer conn.Close()
				preface := make([]byte, len(h2ClientPreface))
				_, _ = io.ReadFull(conn, preface)
				fr := http2.NewFramer(conn, conn)
				_ = fr.WriteSettings()
				for {
					f, err := fr.ReadFrame()
					if err != nil {
						return
					}
					hf, ok := f.(*http2.HeadersFrame)
					if !ok {
						continue
					}
					// Send mid-stream non-ACK SETTINGS, unrelated stream 99 frames, and 2 DATA chunks.
					_ = fr.WriteSettings()
					_ = fr.WriteHeaders(http2.HeadersFrameParam{
						StreamID:      99,
						BlockFragment: []byte{0x88},
						EndStream:     false,
						EndHeaders:    true,
					})
					_ = fr.WriteData(99, true, []byte("ignored"))
					_ = fr.WriteRSTStream(99, http2.ErrCodeCancel)

					var earlyHintsBuf bytes.Buffer
					ehEnc := hpack.NewEncoder(&earlyHintsBuf)
					_ = ehEnc.WriteField(hpack.HeaderField{Name: ":status", Value: "103"})
					_ = ehEnc.WriteField(hpack.HeaderField{Name: "link", Value: "</app.css>; rel=preload"})
					_ = fr.WriteHeaders(http2.HeadersFrameParam{
						StreamID:      hf.StreamID,
						BlockFragment: earlyHintsBuf.Bytes(),
						EndStream:     false,
						EndHeaders:    true,
					})
					_ = fr.WriteHeaders(http2.HeadersFrameParam{
						StreamID:      hf.StreamID,
						BlockFragment: []byte{0x88}, // :status 200
						EndStream:     false,
						EndHeaders:    true,
					})
					_ = fr.WriteData(hf.StreamID, false, []byte("part1-"))
					_ = fr.WriteData(hf.StreamID, true, []byte("part2"))
					return
				}
			},
			wantStatus: "200",
			wantBody:   "part1-part2",
			wantErr:    false,
		},
		{
			name: "when_server_closes_with_eof_after_headers_without_end_stream_returns_partial_response",
			serverFunc: func(t *testing.T, conn net.Conn) {
				t.Helper()
				defer conn.Close()
				preface := make([]byte, len(h2ClientPreface))
				_, _ = io.ReadFull(conn, preface)
				fr := http2.NewFramer(conn, conn)
				_ = fr.WriteSettings()
				for {
					f, err := fr.ReadFrame()
					if err != nil {
						return
					}
					if hf, ok := f.(*http2.HeadersFrame); ok {
						_ = fr.WriteHeaders(http2.HeadersFrameParam{
							StreamID:      hf.StreamID,
							BlockFragment: []byte{0x88},
							EndStream:     false,
							EndHeaders:    true,
						})
						return
					}
				}
			},
			wantStatus: "200",
			wantBody:   "",
			wantErr:    false,
		},
		{
			name: "when_rst_stream_before_response_headers_returns_error",
			serverFunc: func(t *testing.T, conn net.Conn) {
				t.Helper()
				defer conn.Close()
				preface := make([]byte, len(h2ClientPreface))
				_, _ = io.ReadFull(conn, preface)
				fr := http2.NewFramer(conn, conn)
				_ = fr.WriteSettings()
				for {
					f, err := fr.ReadFrame()
					if err != nil {
						return
					}
					if hf, ok := f.(*http2.HeadersFrame); ok {
						_ = fr.WriteRSTStream(hf.StreamID, http2.ErrCodeRefusedStream)
						return
					}
				}
			},
			wantErr: true,
		},
		{
			name: "when_response_body_exceeds_65536_bytes_returns_error",
			serverFunc: func(t *testing.T, conn net.Conn) {
				t.Helper()
				defer conn.Close()
				preface := make([]byte, len(h2ClientPreface))
				_, _ = io.ReadFull(conn, preface)
				fr := http2.NewFramer(conn, conn)
				_ = fr.WriteSettings()
				for {
					f, err := fr.ReadFrame()
					if err != nil {
						return
					}
					if hf, ok := f.(*http2.HeadersFrame); ok {
						_ = fr.WriteHeaders(http2.HeadersFrameParam{
							StreamID:      hf.StreamID,
							BlockFragment: []byte{0x88},
							EndStream:     false,
							EndHeaders:    true,
						})
						// Enforce RFC 9113 initial 65,535-byte stream window: send 65,535 bytes first,
						// then wait for a stream-level WINDOW_UPDATE on hf.StreamID before sending bytes >65,536.
						chunk := bytes.Repeat([]byte("B"), 16384)
						for i := 0; i < 3; i++ {
							if wErr := fr.WriteData(hf.StreamID, false, chunk); wErr != nil {
								return
							}
						}
						if wErr := fr.WriteData(hf.StreamID, false, bytes.Repeat([]byte("B"), 16383)); wErr != nil {
							return
						}
						for {
							wf, rErr := fr.ReadFrame()
							if rErr != nil {
								return
							}
							if wu, ok := wf.(*http2.WindowUpdateFrame); ok && wu.StreamID == hf.StreamID && wu.Increment > 0 {
								break
							}
						}
						_ = fr.WriteData(hf.StreamID, true, []byte("BB"))
						return
					}
				}
			},
			wantErr: true,
		},
		{
			name: "when_response_header_field_count_exceeds_limit_returns_error",
			serverFunc: func(t *testing.T, conn net.Conn) {
				t.Helper()
				defer conn.Close()
				preface := make([]byte, len(h2ClientPreface))
				_, _ = io.ReadFull(conn, preface)
				fr := http2.NewFramer(conn, conn)
				_ = fr.WriteSettings()
				for {
					f, err := fr.ReadFrame()
					if err != nil {
						return
					}
					if hf, ok := f.(*http2.HeadersFrame); ok {
						_ = fr.WriteHeaders(http2.HeadersFrameParam{
							StreamID:      hf.StreamID,
							BlockFragment: bytes.Repeat([]byte{0x88}, maxHpackFields+2),
							EndStream:     true,
							EndHeaders:    true,
						})
						return
					}
				}
			},
			wantErr: true,
		},
		{
			name: "when_peer_floods_window_updates_beyond_max_frames_per_stream_returns_error",
			serverFunc: func(t *testing.T, conn net.Conn) {
				t.Helper()
				defer conn.Close()
				preface := make([]byte, len(h2ClientPreface))
				_, _ = io.ReadFull(conn, preface)
				fr := http2.NewFramer(conn, conn)
				_ = fr.WriteSettings()
				for {
					f, err := fr.ReadFrame()
					if err != nil {
						return
					}
					if _, ok := f.(*http2.HeadersFrame); ok {
						for i := 0; i < maxFramesPerStream+2; i++ {
							if wErr := fr.WriteWindowUpdate(0, 1); wErr != nil {
								return
							}
						}
						return
					}
				}
			},
			wantErr: true,
		},
		{
			name: "when_non_continuation_frame_follows_incomplete_headers_returns_error",
			serverFunc: func(t *testing.T, conn net.Conn) {
				t.Helper()
				defer conn.Close()
				preface := make([]byte, len(h2ClientPreface))
				_, _ = io.ReadFull(conn, preface)
				fr := http2.NewFramer(conn, conn)
				_ = fr.WriteSettings()
				for {
					f, err := fr.ReadFrame()
					if err != nil {
						return
					}
					if hf, ok := f.(*http2.HeadersFrame); ok {
						_ = fr.WriteHeaders(http2.HeadersFrameParam{
							StreamID:      hf.StreamID,
							BlockFragment: []byte{0x88},
							EndStream:     true,
							EndHeaders:    false,
						})
						_ = fr.WritePing(false, [8]byte{9, 9, 9, 9, 9, 9, 9, 9})
						return
					}
				}
			},
			wantErr: true,
		},
		{
			name: "when_continuation_raw_header_block_exceeds_32768_bytes_returns_error",
			serverFunc: func(t *testing.T, conn net.Conn) {
				t.Helper()
				defer conn.Close()
				preface := make([]byte, len(h2ClientPreface))
				_, _ = io.ReadFull(conn, preface)
				fr := http2.NewFramer(conn, conn)
				_ = fr.WriteSettings()
				for {
					f, err := fr.ReadFrame()
					if err != nil {
						return
					}
					if hf, ok := f.(*http2.HeadersFrame); ok {
						_ = fr.WriteHeaders(http2.HeadersFrameParam{
							StreamID:      hf.StreamID,
							BlockFragment: bytes.Repeat([]byte{0x00, 0x01, 'a', 0x01, 'b'}, 2500), // 12500 bytes
							EndStream:     true,
							EndHeaders:    false,
						})
						_ = fr.WriteContinuation(hf.StreamID, false, bytes.Repeat([]byte{0x00, 0x01, 'a', 0x01, 'b'}, 2500))
						_ = fr.WriteContinuation(hf.StreamID, true, bytes.Repeat([]byte{0x00, 0x01, 'a', 0x01, 'b'}, 2500))
						return
					}
				}
			},
			wantErr: true,
		},
		{
			name: "when_truncated_continuation_hpack_literal_at_end_headers_returns_error",
			serverFunc: func(t *testing.T, conn net.Conn) {
				t.Helper()
				defer conn.Close()
				preface := make([]byte, len(h2ClientPreface))
				_, _ = io.ReadFull(conn, preface)
				fr := http2.NewFramer(conn, conn)
				_ = fr.WriteSettings()
				for {
					f, err := fr.ReadFrame()
					if err != nil {
						return
					}
					if hf, ok := f.(*http2.HeadersFrame); ok {
						_ = fr.WriteHeaders(http2.HeadersFrameParam{
							StreamID:      hf.StreamID,
							BlockFragment: []byte{0x88},
							EndStream:     true,
							EndHeaders:    false,
						})
						// Incomplete HPACK literal string (expects 5 bytes, provides 1) -> hpackDec.Close() fails!
						_ = fr.WriteContinuation(hf.StreamID, true, []byte{0x10, 0x05, 'x'})
						return
					}
				}
			},
			wantErr: true,
		},
		{
			name: "when_eof_occurs_during_continuation_frame_read_returns_error",
			serverFunc: func(t *testing.T, conn net.Conn) {
				t.Helper()
				defer conn.Close()
				preface := make([]byte, len(h2ClientPreface))
				_, _ = io.ReadFull(conn, preface)
				fr := http2.NewFramer(conn, conn)
				_ = fr.WriteSettings()
				for {
					f, err := fr.ReadFrame()
					if err != nil {
						return
					}
					if hf, ok := f.(*http2.HeadersFrame); ok {
						_ = fr.WriteHeaders(http2.HeadersFrameParam{
							StreamID:      hf.StreamID,
							BlockFragment: []byte{0x88},
							EndStream:     true,
							EndHeaders:    false,
						})
						return
					}
				}
			},
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dial := func(_ context.Context, _ transportMode, _, _ string, _ time.Duration) (net.Conn, error) {
				cc, sc := newBufferedConnPair(t)
				go tc.serverFunc(t, sc)
				return cc, nil
			}
			sess, err := openH2ProbeSession(t.Context(), dial, transportH2C, endpointTarget{dialAddr: "127.0.0.1:8080"}, 2*time.Second)
			if err != nil {
				t.Fatalf("openH2ProbeSession() unexpected error: %v", err)
			}
			defer sess.close()

			resp, err := sess.roundTrip(t.Context(), reqHeaders, nil)
			if (err != nil) != tc.wantErr {
				t.Fatalf("roundTrip() err = %v, wantErr = %v", err, tc.wantErr)
			}
			if !tc.wantErr {
				if resp.status != tc.wantStatus || string(resp.body) != tc.wantBody {
					t.Errorf("roundTrip() = (%q, %q), want (%q, %q)", resp.status, string(resp.body), tc.wantStatus, tc.wantBody)
				}
			}
		})
	}

	errClassificationCases := []struct {
		name      string
		err       error
		wantRetry bool
	}{
		{name: "when_frame_too_large_not_retryable", err: http2.ErrFrameTooLarge, wantRetry: false},
		{name: "when_unexpected_eof_not_retryable", err: io.ErrUnexpectedEOF, wantRetry: false},
		{name: "when_conn_error_not_retryable", err: http2.ConnectionError(http2.ErrCodeProtocol), wantRetry: false},
		{name: "when_stream_error_not_retryable", err: http2.StreamError{StreamID: 1, Code: http2.ErrCodeProtocol}, wantRetry: false},
		{name: "when_deadline_exceeded_not_retryable", err: context.DeadlineExceeded, wantRetry: false},
		{name: "when_net_closed_is_retryable", err: net.ErrClosed, wantRetry: true},
	}
	for _, tc := range errClassificationCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isRetryableReadErr(tc.err); got != tc.wantRetry {
				t.Errorf("isRetryableReadErr(%v) = %v, want %v", tc.err, got, tc.wantRetry)
			}
		})
	}
}
