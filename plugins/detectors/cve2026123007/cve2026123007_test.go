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

package cve2026123007

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/module"
	"github.com/google/goonami-scanner/core/net/netendpoint"
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

var fixedTestTime = time.Date(2026, time.November, 19, 12, 0, 0, 0, time.UTC)

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
						TimeoutPerRequestSeconds: proto.Int32(15),
					}.Build(),
				}.Build(),
			}.Build()),
			wantTimeout: 15 * time.Second,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			det, err := New(t.Context(), tc.cfg)
			if err != nil {
				t.Fatalf("New(%s) unexpected error: %v", tc.name, err)
			}
			if got := det.Name(); got != moduleName {
				t.Errorf("New(%s).Name() = %q, want %q", tc.name, got, moduleName)
			}
			if got := det.(*Module).timeout; got != tc.wantTimeout {
				t.Errorf("New(%s).timeout = %v, want %v", tc.name, got, tc.wantTimeout)
			}
		})
	}
}

func TestInitRegistration(t *testing.T) {
	t.Run("when_package_imported_registers_detector_in_module_registry", func(t *testing.T) {
		allDets, err := module.AllDetectors(t.Context(), config.Default())
		if err != nil {
			t.Fatalf("module.AllDetectors() unexpected error: %v", err)
		}
		for _, d := range allDets {
			if d.Name() == moduleName {
				return
			}
		}
		t.Errorf("module.AllDetectors() missing %q", moduleName)
	})
}

func TestAdvisories(t *testing.T) {
	t.Run("when_called_returns_defensive_clone_of_critical_cve_advisory", func(t *testing.T) {
		det, err := New(t.Context(), config.Default())
		if err != nil {
			t.Fatalf("New() unexpected error: %v", err)
		}

		got := det.Advisories()
		want := []*vpb.Vulnerability{
			vpb.Vulnerability_builder{
				MainId: vpb.VulnerabilityId_builder{
					Publisher: "GOOGLE",
					Value:     "CVE-2026-123007",
				}.Build(),
				RelatedId: []*vpb.VulnerabilityId{
					vpb.VulnerabilityId_builder{
						Publisher: "CVE",
						Value:     "CVE-2026-123007",
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

		got[0].SetTitle("mutated_advisory_title")
		if gotAfter := det.Advisories()[0].GetTitle(); gotAfter == "mutated_advisory_title" {
			t.Errorf("Advisories()[0].GetTitle() = %q, want defensive clone unaffected by mutation", gotAfter)
		}
	})
}

type fakeBurstMode int

const (
	burstVulnerable fakeBurstMode = iota
	burstPatchedFlowControlGoAway
	burstGoAwayNoErrorAfterRefused
	burstCloseWithoutPings
	burstOmitPingCAck
	burstNonContiguousRefused
)

type fakeRoute struct {
	status                  string
	headers                 []hpack.HeaderField
	trailers                []hpack.HeaderField
	body                    []byte
	bodyFn                  func(call int) []byte
	rawHeaderBlock          []byte
	continuationChunks      int
	badContinuationMismatch bool
	sendPushPromise         bool
	rstErrCode              *http2.ErrCode
}

func nginxRoute(body []byte) fakeRoute {
	return fakeRoute{
		status:  "200",
		headers: []hpack.HeaderField{{Name: "server", Value: "nginx"}},
		body:    body,
	}
}

func nginxRouteWithHeaders(headers []hpack.HeaderField, body []byte) fakeRoute {
	return fakeRoute{status: "200", headers: headers, body: body}
}

type fakeNginxServer struct {
	settings24Byte   bool
	maxStreams       uint32
	greetingOverride func(*http2.Framer)
	omitGreetPing    bool
	onReadStart      func()

	routes      map[string]fakeRoute
	defaultBody []byte

	acceptLimit        int
	acceptLimitFn      func(connNum int) int
	burstMode          fakeBurstMode
	prePingBFlushBytes int

	mu             sync.Mutex
	connCount      int
	burstConnCount int
	sawEnablePush0 atomic.Bool
	dialAddrs      []string
	sniHosts       []string
	authorities    []string
	routeCalls     map[string]int
	clientRSTCount atomic.Int32
}

func newVulnerableFakeNginx() *fakeNginxServer {
	return &fakeNginxServer{
		maxStreams:  8,
		routes:      map[string]fakeRoute{"/": nginxRoute(bytes.Repeat([]byte("A"), 12000))},
		defaultBody: bytes.Repeat([]byte("N"), 512),
		acceptLimit: 8,
		burstMode:   burstVulnerable,
		routeCalls:  make(map[string]int),
	}
}

func (s *fakeNginxServer) dialFunc(t *testing.T) dialFunc {
	t.Helper()
	port := startLoopbackListener(t, nil, s.serveConn)
	listenAddr := fmt.Sprintf("127.0.0.1:%d", port)

	return func(ctx context.Context, opts dialOptions) (net.Conn, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		s.mu.Lock()
		s.dialAddrs = append(s.dialAddrs, opts.dialAddr)
		s.sniHosts = append(s.sniHosts, opts.sniHost)
		s.mu.Unlock()

		dialer := net.Dialer{Timeout: opts.timeout}
		c, err := dialer.DialContext(ctx, "tcp", listenAddr)
		if err != nil {
			return nil, err
		}
		_ = c.SetDeadline(time.Now().Add(opts.timeout))
		return c, nil
	}
}

func (s *fakeNginxServer) writeGreeting(conn net.Conn) error {
	var buf bytes.Buffer
	f := http2.NewFramer(&buf, nil)
	if s.greetingOverride != nil {
		s.greetingOverride(f)
		_, err := conn.Write(buf.Bytes())
		return err
	}
	settings := []http2.Setting{
		{ID: http2.SettingMaxConcurrentStreams, Val: s.maxStreams},
		{ID: http2.SettingInitialWindowSize, Val: 65535},
		{ID: http2.SettingMaxFrameSize, Val: nginxMaxFrameSize},
	}
	if s.settings24Byte {
		settings = append(settings, http2.Setting{ID: http2.SettingID(settingNoPrioritiesID), Val: 1})
	}
	_ = f.WriteSettings(settings...)
	_ = f.WriteWindowUpdate(0, nginxConnWindowDelta)
	_, err := conn.Write(buf.Bytes())
	return err
}

type fakeConnState struct {
	srv                 *fakeNginxServer
	conn                net.Conn
	dec                 *hpack.Decoder
	enc                 *hpack.Encoder
	encBuf              bytes.Buffer
	isBurstConn         bool
	clientInitStreamWin uint32
	connSendWin         int64
	sendQueued          int64
	openedStreams       int
	refusedStreams      int
	pingCount           int
	connAcceptLimit     int
}

func (cs *fakeConnState) writeRaw(fn func(*http2.Framer)) error {
	var b bytes.Buffer
	fn(http2.NewFramer(&b, nil))
	_, err := cs.conn.Write(b.Bytes())
	return err
}

func (s *fakeNginxServer) serveConn(conn net.Conn) {
	defer conn.Close()

	preface := make([]byte, len(h2ClientPreface))
	if _, err := io.ReadFull(conn, preface); err != nil || string(preface) != h2ClientPreface {
		return
	}
	if s.onReadStart != nil {
		s.onReadStart()
		_, _ = io.Copy(io.Discard, conn)
		return
	}
	if err := s.writeGreeting(conn); err != nil {
		return
	}

	s.mu.Lock()
	s.connCount++
	isBurst := s.connCount > 1
	acceptLimit := s.acceptLimit
	if isBurst {
		s.burstConnCount++
		if s.acceptLimitFn != nil {
			acceptLimit = s.acceptLimitFn(s.burstConnCount)
		}
	}
	s.mu.Unlock()

	framer := http2.NewFramer(io.Discard, conn)
	framer.SetMaxReadFrameSize(1 << 20)
	cs := &fakeConnState{
		srv:                 s,
		conn:                conn,
		dec:                 hpack.NewDecoder(4096, nil),
		isBurstConn:         isBurst,
		clientInitStreamWin: 65535,
		connSendWin:         65535,
		connAcceptLimit:     acceptLimit,
	}
	cs.enc = hpack.NewEncoder(&cs.encBuf)

	for {
		f, err := framer.ReadFrame()
		if err != nil {
			return
		}
		switch fr := f.(type) {
		case *http2.RSTStreamFrame:
			s.clientRSTCount.Add(1)
		case *http2.SettingsFrame:
			if !fr.IsAck() {
				_ = fr.ForeachSetting(func(st http2.Setting) error {
					if st.ID == http2.SettingInitialWindowSize {
						cs.clientInitStreamWin = st.Val
					}
					if st.ID == http2.SettingEnablePush && st.Val == 0 {
						s.sawEnablePush0.Store(true)
					}
					return nil
				})
				_ = cs.writeRaw(func(wf *http2.Framer) { _ = wf.WriteSettingsAck() })
			}
		case *http2.HeadersFrame:
			if !cs.handleHeaders(fr) {
				return
			}
		case *http2.WindowUpdateFrame:
			if !cs.handleWindowUpdate(fr) {
				return
			}
		case *http2.PingFrame:
			if !cs.handlePing(fr) {
				return
			}
		}
	}
}

func (cs *fakeConnState) handleHeaders(fr *http2.HeadersFrame) bool {
	var reqPath, reqAuth string
	cs.dec.SetEmitFunc(func(hf hpack.HeaderField) {
		if hf.Name == ":path" {
			reqPath = hf.Value
		} else if hf.Name == ":authority" {
			reqAuth = hf.Value
		}
	})
	_, _ = cs.dec.Write(fr.HeaderBlockFragment())
	_ = cs.dec.Close()

	cs.openedStreams++
	sid := fr.Header().StreamID

	cs.srv.mu.Lock()
	if reqAuth != "" {
		cs.srv.authorities = append(cs.srv.authorities, reqAuth)
	}
	cs.srv.routeCalls[reqPath]++
	callNum := cs.srv.routeCalls[reqPath]
	route, hasRoute := cs.srv.routes[reqPath]
	cs.srv.mu.Unlock()

	if !hasRoute {
		route = fakeRoute{status: "404", headers: []hpack.HeaderField{{Name: "server", Value: "nginx"}}, body: cs.srv.defaultBody}
	}
	if route.rstErrCode != nil {
		code := *route.rstErrCode
		_ = cs.writeRaw(func(wf *http2.Framer) { _ = wf.WriteRSTStream(sid, code) })
		return true
	}
	if route.sendPushPromise {
		_ = cs.writeRaw(func(wf *http2.Framer) {
			_ = wf.WritePushPromise(http2.PushPromiseParam{StreamID: sid, PromiseID: 2, BlockFragment: []byte{0x82}, EndHeaders: true})
		})
		return true
	}
	if cs.isBurstConn && cs.srv.burstMode == burstNonContiguousRefused && cs.openedStreams == 2 {
		_ = cs.writeRaw(func(wf *http2.Framer) { _ = wf.WriteRSTStream(sid, http2.ErrCodeRefusedStream) })
		return true
	}
	if cs.isBurstConn && cs.connAcceptLimit > 0 && cs.openedStreams > cs.connAcceptLimit {
		if uint32(cs.refusedStreams) > max(cs.srv.maxStreams, 100) {
			_ = cs.writeRaw(func(wf *http2.Framer) { _ = wf.WriteGoAway(sid, http2.ErrCodeNo, nil) })
			if tc, ok := cs.conn.(*net.TCPConn); ok {
				_ = tc.CloseWrite()
			}
			_, _ = io.Copy(io.Discard, cs.conn)
			return false
		}
		cs.refusedStreams++
		_ = cs.writeRaw(func(wf *http2.Framer) { _ = wf.WriteRSTStream(sid, http2.ErrCodeRefusedStream) })
		return true
	}

	body := route.body
	if route.bodyFn != nil {
		body = route.bodyFn(callNum)
	}
	if cs.isBurstConn {
		bufferedLen := int64(min(len(body), 65536))
		cs.connSendWin -= bufferedLen
		if uint32(cs.openedStreams) > uint32(max(0, cs.connAcceptLimit-int(cs.srv.maxStreams))) {
			cs.sendQueued += bufferedLen
		}
		return true
	}

	hdrBytes := route.rawHeaderBlock
	if hdrBytes == nil {
		status := route.status
		if status == "" {
			status = "200"
		}
		cs.encBuf.Reset()
		_ = cs.enc.WriteField(hpack.HeaderField{Name: ":status", Value: status})
		for _, hf := range route.headers {
			_ = cs.enc.WriteField(hf)
		}
		hdrBytes = bytes.Clone(cs.encBuf.Bytes())
	}

	endStreamOnHeaders := len(body) == 0 && len(route.trailers) == 0
	if err := writeHeadersPossiblySplit(cs.writeRaw, sid, hdrBytes, endStreamOnHeaders, route.continuationChunks, route.badContinuationMismatch); err != nil {
		return false
	}

	maxSend := min(len(body), int(cs.clientInitStreamWin))
	streamComplete := maxSend == len(body)
	for rem := body[:maxSend]; len(rem) > 0; {
		chunkLen := min(len(rem), 16384)
		chunk := rem[:chunkLen]
		rem = rem[chunkLen:]
		isLast := len(rem) == 0 && streamComplete && len(route.trailers) == 0
		if err := cs.writeRaw(func(wf *http2.Framer) { _ = wf.WriteData(sid, isLast, chunk) }); err != nil {
			return false
		}
	}
	if streamComplete && len(route.trailers) > 0 {
		cs.encBuf.Reset()
		for _, tf := range route.trailers {
			_ = cs.enc.WriteField(tf)
		}
		trBytes := bytes.Clone(cs.encBuf.Bytes())
		if err := cs.writeRaw(func(wf *http2.Framer) {
			_ = wf.WriteHeaders(http2.HeadersFrameParam{StreamID: sid, BlockFragment: trBytes, EndStream: true, EndHeaders: true})
		}); err != nil {
			return false
		}
	}
	return true
}

func (cs *fakeConnState) handleWindowUpdate(fr *http2.WindowUpdateFrame) bool {
	if fr.Header().StreamID != 0 {
		return true
	}
	if cs.openedStreams == 0 {
		cs.connSendWin += int64(fr.Increment)
		return true
	}
	if !cs.isBurstConn {
		return true
	}
	switch cs.srv.burstMode {
	case burstVulnerable, burstPatchedFlowControlGoAway:
		accounted := cs.connSendWin
		if cs.srv.burstMode == burstPatchedFlowControlGoAway {
			accounted += cs.sendQueued
		}
		if accounted+int64(fr.Increment) > nginxMaxWindow {
			_ = cs.writeRaw(func(wf *http2.Framer) {
				_ = wf.WriteGoAway(uint32(2*cs.connAcceptLimit-1), http2.ErrCodeFlowControl, nil)
			})
			return false
		}
		cs.connSendWin += int64(fr.Increment)
	case burstGoAwayNoErrorAfterRefused:
		_ = cs.writeRaw(func(wf *http2.Framer) {
			_ = wf.WriteGoAway(uint32(2*cs.connAcceptLimit-1), http2.ErrCodeNo, nil)
		})
		return false
	case burstCloseWithoutPings:
		return false
	}
	return true
}

func (cs *fakeConnState) handlePing(fr *http2.PingFrame) bool {
	if fr.IsAck() {
		return true
	}
	cs.pingCount++
	if !cs.isBurstConn && cs.srv.omitGreetPing {
		return true
	}
	if cs.isBurstConn && (cs.srv.burstMode == burstCloseWithoutPings || (cs.srv.burstMode == burstOmitPingCAck && cs.pingCount >= 3)) {
		return false
	}
	nonce := fr.Data
	if cs.isBurstConn && cs.srv.prePingBFlushBytes > 0 && cs.pingCount == 1 {
		for rem := cs.srv.prePingBFlushBytes; rem > 0; {
			n := min(rem, 16000)
			rem -= n
			if err := cs.writeRaw(func(wf *http2.Framer) { _ = wf.WriteData(1, false, bytes.Repeat([]byte("F"), n)) }); err != nil {
				return false
			}
		}
	}
	if err := cs.writeRaw(func(wf *http2.Framer) { _ = wf.WritePing(true, nonce) }); err != nil {
		return false
	}
	if cs.isBurstConn && cs.srv.prePingBFlushBytes > 0 && cs.pingCount == 2 {
		for _, endStream := range []bool{false, true} {
			if err := cs.writeRaw(func(wf *http2.Framer) { _ = wf.WriteData(1, endStream, bytes.Repeat([]byte("P"), 10000)) }); err != nil {
				return false
			}
		}
	}
	return true
}

func writeHeadersPossiblySplit(writeRaw func(func(*http2.Framer)) error, sid uint32, hdrBytes []byte, endStream bool, contChunks int, badMismatch bool) error {
	if contChunks <= 0 {
		return writeRaw(func(wf *http2.Framer) {
			_ = wf.WriteHeaders(http2.HeadersFrameParam{StreamID: sid, BlockFragment: hdrBytes, EndStream: endStream, EndHeaders: true})
		})
	}
	firstLen := min(2, len(hdrBytes))
	if err := writeRaw(func(wf *http2.Framer) {
		_ = wf.WriteHeaders(http2.HeadersFrameParam{StreamID: sid, BlockFragment: hdrBytes[:firstLen], EndStream: endStream, EndHeaders: false})
	}); err != nil {
		return err
	}
	rest := hdrBytes[firstLen:]
	for i := range contChunks {
		isLast := i == contChunks-1
		var frag []byte
		if isLast {
			frag = rest
		} else if len(rest) > 1 {
			frag = rest[:1]
			rest = rest[1:]
		}
		targetSID := sid
		if badMismatch && i == 0 {
			targetSID = sid + 2
		}
		if err := writeRaw(func(wf *http2.Framer) {
			wf.AllowIllegalWrites = badMismatch
			_ = wf.WriteContinuation(targetSID, isLast, frag)
		}); err != nil {
			return err
		}
	}
	return nil
}

func newTestModule(t *testing.T, srv *fakeNginxServer) *Module {
	t.Helper()
	det, err := New(t.Context(), config.Default())
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}
	mod := det.(*Module)
	mod.timeout = 2 * time.Second
	mod.interBatchDelay = 0
	mod.preDrainDelay = 0
	mod.nowFn = func() time.Time { return fixedTestTime }
	if srv != nil {
		mod.dial = srv.dialFunc(t)
	}
	return mod
}

func buildWebService(host, ip string, family npb.AddressFamily, port uint32, tlsEnabled bool, crawlURLs ...string) *nspb.NetworkService {
	epBuilder := npb.NetworkEndpoint_builder{}
	switch {
	case host != "" && ip != "":
		epBuilder.Type = npb.NetworkEndpoint_IP_HOSTNAME_PORT
	case host != "":
		epBuilder.Type = npb.NetworkEndpoint_HOSTNAME_PORT
	default:
		epBuilder.Type = npb.NetworkEndpoint_IP_PORT
	}
	if host != "" {
		epBuilder.Hostname = npb.Hostname_builder{Name: host}.Build()
	}
	if ip != "" {
		if family == npb.AddressFamily_ADDRESS_FAMILY_UNSPECIFIED {
			family = npb.AddressFamily_IPV4
		}
		epBuilder.IpAddress = npb.IpAddress_builder{Address: ip, AddressFamily: family}.Build()
	}
	if port > 0 {
		epBuilder.Port = npb.Port_builder{PortNumber: port}.Build()
	}

	var sslVersions []string
	if tlsEnabled {
		sslVersions = []string{"TLSv1.3"}
	}
	svcBuilder := nspb.NetworkService_builder{
		NetworkEndpoint:      epBuilder.Build(),
		TransportProtocol:    npb.TransportProtocol_TCP,
		ServiceName:          "unknown",
		SupportedHttpMethods: []string{"GET"},
		SupportedSslVersions: sslVersions,
	}
	if len(crawlURLs) > 0 {
		var results []*wcpb.CrawlResult
		for _, u := range crawlURLs {
			results = append(results, wcpb.CrawlResult_builder{
				CrawlTarget:  wcpb.CrawlTarget_builder{Url: u, HttpMethod: "GET"}.Build(),
				ResponseCode: 200,
			}.Build())
		}
		svcBuilder.ServiceContext = nspb.ServiceContext_builder{
			WebServiceContext: nspb.WebServiceContext_builder{CrawlResults: results}.Build(),
		}.Build()
	}
	return svcBuilder.Build()
}

func TestDetect_RejectedInputsDoNotDial(t *testing.T) {
	udpSvc := buildWebService("", "127.0.0.1", npb.AddressFamily_IPV4, 443, true)
	udpSvc.SetTransportProtocol(npb.TransportProtocol_UDP)

	nonWebSvc := buildWebService("", "127.0.0.1", npb.AddressFamily_IPV4, 8080, false)
	nonWebSvc.SetSupportedHttpMethods(nil)

	testCases := []struct {
		name    string
		service *nspb.NetworkService
		wantErr error
	}{
		{name: "when_service_is_not_web_service_skips_without_dialing", service: nonWebSvc},
		{name: "when_transport_protocol_is_udp_skips_without_dialing", service: udpSvc},
		{
			name: "when_endpoint_missing_address_returns_error",
			service: nspb.NetworkService_builder{
				NetworkEndpoint:      npb.NetworkEndpoint_builder{Port: npb.Port_builder{PortNumber: 443}.Build()}.Build(),
				TransportProtocol:    npb.TransportProtocol_TCP,
				SupportedHttpMethods: []string{"GET"},
			}.Build(),
			wantErr: netendpoint.ErrEndpointMissingAddress,
		},
		{name: "when_endpoint_missing_port_skips_without_dialing", service: buildWebService("", "127.0.0.1", npb.AddressFamily_IPV4, 0, false)},
		{name: "when_port_exceeds_65535_skips_without_dialing", service: buildWebService("", "127.0.0.1", npb.AddressFamily_IPV4, 70000, false)},
		{name: "when_hostname_contains_control_bytes_skips_without_dialing", service: buildWebService("bad\r\nhost.example", "127.0.0.1", npb.AddressFamily_IPV4, 443, true)},
		{name: "when_ip_address_contains_whitespace_skips_without_dialing", service: buildWebService("app.example", "127.0.0.1 bad", npb.AddressFamily_IPV4, 443, true)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mod := newTestModule(t, nil)
			var dials atomic.Int32
			mod.dial = func(context.Context, dialOptions) (net.Conn, error) {
				dials.Add(1)
				return nil, errors.New("unexpected dial")
			}

			got, err := mod.Detect(t.Context(), tc.service)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Detect(%s) error = %v, want %v", tc.name, err, tc.wantErr)
				}
			} else if err != nil {
				t.Fatalf("Detect(%s) unexpected error: %v", tc.name, err)
			}
			if len(got.GetDetectionReports()) != 0 {
				t.Errorf("Detect(%s) reports = %v, want empty", tc.name, got)
			}
			if gotDials := dials.Load(); gotDials != 0 {
				t.Errorf("Detect(%s) dial count = %d, want 0", tc.name, gotDials)
			}
		})
	}
}

func TestDetect_EndpointTargeting(t *testing.T) {
	unspecifiedTCP := buildWebService("", "127.0.0.1", npb.AddressFamily_IPV4, 8443, true)
	unspecifiedTCP.SetTransportProtocol(npb.TransportProtocol_TRANSPORT_PROTOCOL_UNSPECIFIED)

	testCases := []struct {
		name           string
		service        *nspb.NetworkService
		wantDialAddr   string
		wantSNI        string
		wantAuthority  string
		wantDetailPart string
	}{
		{
			name:           "when_transport_protocol_is_unspecified_from_noop_portscan_detects_finding",
			service:        unspecifiedTCP,
			wantDialAddr:   "127.0.0.1:8443",
			wantAuthority:  "127.0.0.1:8443",
			wantDetailPart: "https://127.0.0.1:8443/",
		},
		{
			name:           "when_ip_hostname_endpoint_on_port_443_dials_ip_with_hostname_sni_and_authority",
			service:        buildWebService("edge.example.com", "10.0.0.5", npb.AddressFamily_IPV4, 443, true),
			wantDialAddr:   "10.0.0.5:443",
			wantSNI:        "edge.example.com",
			wantAuthority:  "edge.example.com",
			wantDetailPart: "https://edge.example.com/",
		},
		{
			name:           "when_ipv6_endpoint_on_port_80_formats_bracketed_authority",
			service:        buildWebService("", "::1", npb.AddressFamily_IPV6, 80, false),
			wantDialAddr:   "[::1]:80",
			wantAuthority:  "[::1]",
			wantDetailPart: "http://[::1]/",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newVulnerableFakeNginx()
			mod := newTestModule(t, srv)

			got, err := mod.Detect(t.Context(), tc.service)
			if err != nil {
				t.Fatalf("Detect(%s) unexpected error: %v", tc.name, err)
			}
			if len(got.GetDetectionReports()) != 1 {
				t.Fatalf("Detect(%s) report count = %d, want 1", tc.name, len(got.GetDetectionReports()))
			}

			srv.mu.Lock()
			gotDial, gotSNI, gotAuth := srv.dialAddrs[0], srv.sniHosts[0], srv.authorities[0]
			srv.mu.Unlock()
			if gotDial != tc.wantDialAddr || gotSNI != tc.wantSNI || gotAuth != tc.wantAuthority {
				t.Errorf("Detect(%s) target = (dial=%q, sni=%q, auth=%q), want (%q, %q, %q)",
					tc.name, gotDial, gotSNI, gotAuth, tc.wantDialAddr, tc.wantSNI, tc.wantAuthority)
			}
			detail := got.GetDetectionReports()[0].GetVulnerability().GetAdditionalDetails()[0].GetTextData().GetText()
			if !strings.Contains(detail, tc.wantDetailPart) {
				t.Errorf("Detect(%s) additional detail = %q, want substring %q", tc.name, detail, tc.wantDetailPart)
			}
			if !srv.sawEnablePush0.Load() {
				t.Errorf("Detect(%s) did not send SETTINGS_ENABLE_PUSH=0", tc.name)
			}
			if rst := srv.clientRSTCount.Load(); rst != 0 {
				t.Errorf("Detect(%s) sent %d RST_STREAM frames, want 0", tc.name, rst)
			}
		})
	}
}

func TestDetect_GreetingAndExclusions(t *testing.T) {
	testCases := []struct {
		name           string
		configure      func(*fakeNginxServer)
		wantFinding    bool
		wantDetailPart string
	}{
		{
			name:           "when_18_byte_nginx_settings_frame_detects_vulnerability",
			configure:      func(s *fakeNginxServer) { s.settings24Byte = false },
			wantFinding:    true,
			wantDetailPart: "settings_len=18",
		},
		{
			name:           "when_24_byte_nginx_settings_frame_detects_vulnerability",
			configure:      func(s *fakeNginxServer) { s.settings24Byte = true },
			wantFinding:    true,
			wantDetailPart: "settings_len=24",
		},
		{
			name: "when_server_header_is_openresty_detects_vulnerability",
			configure: func(s *fakeNginxServer) {
				s.routes["/"] = nginxRouteWithHeaders([]hpack.HeaderField{{Name: "server", Value: "openresty/1.25.3.1"}}, bytes.Repeat([]byte("A"), 12000))
			},
			wantFinding:    true,
			wantDetailPart: "settings_len=18",
		},
		{
			name: "when_settings_length_is_12_bytes_returns_no_finding",
			configure: func(s *fakeNginxServer) {
				s.greetingOverride = func(f *http2.Framer) {
					_ = f.WriteSettings(
						http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: 128},
						http2.Setting{ID: http2.SettingInitialWindowSize, Val: 65535},
					)
					_ = f.WriteWindowUpdate(0, nginxConnWindowDelta)
				}
			},
		},
		{
			name:      "when_settings_max_concurrent_streams_is_zero_returns_no_finding",
			configure: func(s *fakeNginxServer) { s.maxStreams = 0 },
		},
		{
			name: "when_settings_max_frame_size_differs_from_nginx_returns_no_finding",
			configure: func(s *fakeNginxServer) {
				s.greetingOverride = func(f *http2.Framer) {
					_ = f.WriteSettings(
						http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: 8},
						http2.Setting{ID: http2.SettingInitialWindowSize, Val: 65535},
						http2.Setting{ID: http2.SettingMaxFrameSize, Val: 16384},
					)
					_ = f.WriteWindowUpdate(0, nginxConnWindowDelta)
				}
			},
		},
		{
			name: "when_24_byte_settings_fourth_entry_is_not_no_priorities_returns_no_finding",
			configure: func(s *fakeNginxServer) {
				s.greetingOverride = func(f *http2.Framer) {
					_ = f.WriteSettings(
						http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: 8},
						http2.Setting{ID: http2.SettingInitialWindowSize, Val: 65535},
						http2.Setting{ID: http2.SettingMaxFrameSize, Val: nginxMaxFrameSize},
						http2.Setting{ID: http2.SettingEnablePush, Val: 0},
					)
					_ = f.WriteWindowUpdate(0, nginxConnWindowDelta)
				}
			},
		},
		{
			name: "when_second_frame_is_not_window_update_returns_no_finding",
			configure: func(s *fakeNginxServer) {
				s.greetingOverride = func(f *http2.Framer) {
					_ = f.WriteSettings(
						http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: 8},
						http2.Setting{ID: http2.SettingInitialWindowSize, Val: 65535},
						http2.Setting{ID: http2.SettingMaxFrameSize, Val: nginxMaxFrameSize},
					)
					_ = f.WriteSettingsAck()
				}
			},
		},
		{
			name: "when_stream0_window_update_increment_differs_from_nginx_returns_no_finding",
			configure: func(s *fakeNginxServer) {
				s.greetingOverride = func(f *http2.Framer) {
					_ = f.WriteSettings(
						http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: 8},
						http2.Setting{ID: http2.SettingInitialWindowSize, Val: 65535},
						http2.Setting{ID: http2.SettingMaxFrameSize, Val: nginxMaxFrameSize},
					)
					_ = f.WriteWindowUpdate(0, 983041)
				}
			},
		},
		{
			name:      "when_greeting_ping_ack_is_missing_returns_no_finding",
			configure: func(s *fakeNginxServer) { s.omitGreetPing = true },
		},
		{
			name: "when_server_sends_unexpected_push_promise_returns_no_finding",
			configure: func(s *fakeNginxServer) {
				s.routes["/"] = fakeRoute{sendPushPromise: true}
			},
		},
		{
			name: "when_server_header_is_awselb_returns_no_finding",
			configure: func(s *fakeNginxServer) {
				s.routes["/"] = nginxRouteWithHeaders([]hpack.HeaderField{{Name: "server", Value: "awselb/2.0"}}, bytes.Repeat([]byte("A"), 12000))
			},
		},
		{
			name: "when_set_cookie_has_awsalb_returns_no_finding",
			configure: func(s *fakeNginxServer) {
				s.routes["/"] = nginxRouteWithHeaders([]hpack.HeaderField{{Name: "set-cookie", Value: "AWSALB=xyz123; Path=/"}}, bytes.Repeat([]byte("A"), 12000))
			},
		},
		{
			name: "when_via_header_is_present_returns_no_finding",
			configure: func(s *fakeNginxServer) {
				s.routes["/"] = nginxRouteWithHeaders([]hpack.HeaderField{
					{Name: "server", Value: "nginx"},
					{Name: "via", Value: "2.0 varnish"},
				}, bytes.Repeat([]byte("A"), 12000))
			},
		},
		{
			name: "when_trailer_headers_include_via_header_returns_no_finding",
			configure: func(s *fakeNginxServer) {
				r := nginxRoute(bytes.Repeat([]byte("A"), 12000))
				r.trailers = []hpack.HeaderField{{Name: "via", Value: "2.0 edge-proxy"}}
				s.routes["/"] = r
			},
		},
		{
			name: "when_server_header_is_envoy_returns_no_finding",
			configure: func(s *fakeNginxServer) {
				s.routes["/"] = nginxRouteWithHeaders([]hpack.HeaderField{{Name: "server", Value: "envoy"}}, bytes.Repeat([]byte("A"), 12000))
			},
		},
		{
			name: "when_fallback_candidate_returns_awsalb_cookie_returns_no_finding",
			configure: func(s *fakeNginxServer) {
				s.routes["/"] = fakeRoute{status: "301", body: []byte(`<a href="/static/app.js">redirect</a>`)}
				s.routes["/static/app.js"] = nginxRouteWithHeaders(
					[]hpack.HeaderField{{Name: "set-cookie", Value: "AWSALB=sticky123; Path=/"}},
					bytes.Repeat([]byte("J"), 12000),
				)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newVulnerableFakeNginx()
			tc.configure(srv)
			mod := newTestModule(t, srv)

			got, err := mod.Detect(t.Context(), buildWebService("", "127.0.0.1", npb.AddressFamily_IPV4, 8443, true))
			if err != nil {
				t.Fatalf("Detect(%s) unexpected error: %v", tc.name, err)
			}
			if gotFinding := len(got.GetDetectionReports()) > 0; gotFinding != tc.wantFinding {
				t.Fatalf("Detect(%s) finding = %t, want %t", tc.name, gotFinding, tc.wantFinding)
			}
			if tc.wantFinding {
				detail := got.GetDetectionReports()[0].GetVulnerability().GetAdditionalDetails()[0].GetTextData().GetText()
				if !strings.Contains(detail, tc.wantDetailPart) {
					t.Errorf("Detect(%s) additional detail = %q, want substring %q", tc.name, detail, tc.wantDetailPart)
				}
			}
		})
	}
}

func TestDetect_PathDiscoveryAndHeaderLimits(t *testing.T) {
	rstInternal := http2.ErrCodeInternal

	// Build a valid HPACK header block of exact byte length n using RFC 7541
	// dynamic-table-size updates (0x20, 0 emitted fields) + ":status: 200" (0x88),
	// so only the raw 32,768-byte single-frame cap distinguishes 32,768 vs 32,769.
	exactSizeHeaderBlock := func(n int) []byte {
		b := bytes.Repeat([]byte{0x20}, n-1)
		return append(b, 0x88)
	}

	// Build a compact HPACK decompression bomb (wire < 32 KiB, < 128 fields, but
	// decoded field sizes exceed 32,768 bytes) by indexing a 4000-byte dynamic
	// entry once and referencing it 10 times (~40,000 decoded bytes in ~4020 wire bytes).
	hpackExpansionBomb := func() []byte {
		var buf bytes.Buffer
		enc := hpack.NewEncoder(&buf)
		_ = enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
		_ = enc.WriteField(hpack.HeaderField{Name: "x-big", Value: strings.Repeat("Z", 3800)})
		for range 10 {
			_ = enc.WriteField(hpack.HeaderField{Name: "x-big", Value: strings.Repeat("Z", 3800)})
		}
		return buf.Bytes()
	}()

	testCases := []struct {
		name           string
		crawlURLs      []string
		configure      func(*fakeNginxServer)
		wantFinding    bool
		wantDetailPart string
		wantZeroBursts bool
	}{
		{
			name: "when_crawled_static_asset_exists_uses_crawled_path",
			crawlURLs: []string{
				"https://127.0.0.1:8443/api/users",
				"https://127.0.0.1:8443//double-slash.js",
				"https://127.0.0.1:8443/static/app.js",
				"https://127.0.0.1:8443/static/app.js",
				"https://127.0.0.1:8443/static/two.css",
				"https://127.0.0.1:8443/static/three.woff2",
				"https://127.0.0.1:8443/static/four.png",
			},
			configure: func(s *fakeNginxServer) {
				s.routes["/static/app.js"] = nginxRoute(bytes.Repeat([]byte("J"), 16384))
			},
			wantFinding:    true,
			wantDetailPart: "https://127.0.0.1:8443/static/app.js (",
		},
		{
			name: "when_small_root_html_links_larger_static_asset_uses_extracted_asset",
			configure: func(s *fakeNginxServer) {
				htmlBody := `<html><head>` +
					`<link rel="stylesheet" href="https://fonts.googleapis.com/css2.css">` +
					`<script src="https://cdn.jsdelivr.net/npm/vendor.js"></script>` +
					`<link rel="stylesheet" href="https://127.0.0.1:8443/assets/main.css">` +
					`<script src='/assets/app.js'></script></head><body>ok</body></html>`
				s.routes["/"] = nginxRoute([]byte(htmlBody))
				s.routes["/assets/main.css"] = nginxRoute(bytes.Repeat([]byte("C"), 10000))
			},
			wantFinding:    true,
			wantDetailPart: "https://127.0.0.1:8443/assets/main.css (",
		},
		{
			name: "when_secondary_asset_resets_stream_retains_verified_root_candidate",
			configure: func(s *fakeNginxServer) {
				s.routes["/"] = nginxRoute([]byte(`<script src="/broken.js"></script>`))
				s.routes["/broken.js"] = fakeRoute{rstErrCode: &rstInternal}
				s.defaultBody = nil
			},
			wantFinding:    true,
			wantDetailPart: "https://127.0.0.1:8443/ (",
		},
		{
			name: "when_root_response_length_varies_falls_back_to_deterministic_404_path",
			configure: func(s *fakeNginxServer) {
				r := nginxRoute(nil)
				r.bodyFn = func(call int) []byte { return bytes.Repeat([]byte("D"), 9000+call*17) }
				s.routes["/"] = r
				s.defaultBody = bytes.Repeat([]byte("F"), 4096)
			},
			wantFinding:    true,
			wantDetailPart: "static_body_bytes=4096",
		},
		{
			name:      "when_first_candidate_exceeds_max_static_body_falls_back_without_stalling",
			crawlURLs: []string{"https://127.0.0.1:8443/huge/vendor.js"},
			configure: func(s *fakeNginxServer) {
				s.routes["/huge/vendor.js"] = nginxRoute(bytes.Repeat([]byte("X"), 98304))
				s.routes["/"] = nginxRoute(bytes.Repeat([]byte("S"), 10240))
			},
			wantFinding:    true,
			wantDetailPart: "https://127.0.0.1:8443/ (",
		},
		{
			name: "when_response_headers_span_continuation_frames_detects_vulnerability",
			configure: func(s *fakeNginxServer) {
				r := s.routes["/"]
				r.continuationChunks = 3
				s.routes["/"] = r
			},
			wantFinding:    true,
			wantDetailPart: "static_body_bytes=12000",
		},
		{
			name: "when_continuation_frame_has_mismatched_stream_id_returns_no_finding",
			configure: func(s *fakeNginxServer) {
				r := s.routes["/"]
				r.continuationChunks = 2
				r.badContinuationMismatch = true
				s.routes["/"] = r
			},
			wantZeroBursts: true,
		},
		{
			name: "when_continuation_frame_count_exceeds_limit_returns_no_finding",
			configure: func(s *fakeNginxServer) {
				r := s.routes["/"]
				r.continuationChunks = 18
				s.routes["/"] = r
			},
			wantZeroBursts: true,
		},
		{
			name: "when_single_headers_frame_is_32768_bytes_accepts_and_detects_vulnerability",
			configure: func(s *fakeNginxServer) {
				r := nginxRoute(bytes.Repeat([]byte("A"), 12000))
				r.rawHeaderBlock = exactSizeHeaderBlock(32768)
				s.routes["/"] = r
			},
			wantFinding:    true,
			wantDetailPart: "static_body_bytes=12000",
		},
		{
			name: "when_single_headers_frame_exceeds_32768_bytes_rejects_before_decoding",
			configure: func(s *fakeNginxServer) {
				r := nginxRoute(bytes.Repeat([]byte("A"), 12000))
				r.rawHeaderBlock = exactSizeHeaderBlock(32769)
				s.routes["/"] = r
			},
			wantZeroBursts: true,
		},
		{
			name: "when_hpack_decoded_bytes_exceed_budget_returns_no_finding",
			configure: func(s *fakeNginxServer) {
				r := nginxRoute(bytes.Repeat([]byte("A"), 12000))
				r.rawHeaderBlock = hpackExpansionBomb
				s.routes["/"] = r
			},
			wantZeroBursts: true,
		},
		{
			name: "when_continuation_exceeds_max_header_block_bytes_returns_no_finding",
			configure: func(s *fakeNginxServer) {
				r := nginxRouteWithHeaders([]hpack.HeaderField{
					{Name: "server", Value: "nginx"},
					{Name: "x-pad", Value: strings.Repeat("P", 65536)},
				}, bytes.Repeat([]byte("A"), 12000))
				r.continuationChunks = 2
				s.routes["/"] = r
			},
			wantZeroBursts: true,
		},
		{
			name: "when_hpack_header_field_count_exceeds_limit_returns_no_finding",
			configure: func(s *fakeNginxServer) {
				var hdrs []hpack.HeaderField
				for i := range 135 {
					hdrs = append(hdrs, hpack.HeaderField{Name: fmt.Sprintf("x-h-%d", i), Value: "1"})
				}
				s.routes["/"] = nginxRouteWithHeaders(hdrs, bytes.Repeat([]byte("A"), 12000))
			},
			wantZeroBursts: true,
		},
		{
			name: "when_first_discovery_stream_is_reset_returns_no_finding",
			configure: func(s *fakeNginxServer) {
				s.routes["/"] = fakeRoute{rstErrCode: &rstInternal}
			},
			wantZeroBursts: true,
		},
		{
			name: "when_all_candidates_return_empty_body_returns_no_finding",
			configure: func(s *fakeNginxServer) {
				s.routes["/"] = fakeRoute{status: "204", headers: []hpack.HeaderField{{Name: "server", Value: "nginx"}}}
				s.defaultBody = nil
			},
			wantZeroBursts: true,
		},
		{
			name: "when_only_small_static_body_exists_detects_vulnerability_without_inflating_burst",
			configure: func(s *fakeNginxServer) {
				s.routes["/"] = nginxRoute(bytes.Repeat([]byte("T"), 50))
				s.defaultBody = bytes.Repeat([]byte("T"), 50)
			},
			wantFinding:    true,
			wantDetailPart: "static_body_bytes=50",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newVulnerableFakeNginx()
			tc.configure(srv)
			mod := newTestModule(t, srv)

			got, err := mod.Detect(t.Context(), buildWebService("", "127.0.0.1", npb.AddressFamily_IPV4, 8443, true, tc.crawlURLs...))
			if err != nil {
				t.Fatalf("Detect(%s) unexpected error: %v", tc.name, err)
			}
			if gotFinding := len(got.GetDetectionReports()) > 0; gotFinding != tc.wantFinding {
				t.Fatalf("Detect(%s) finding = %t, want %t", tc.name, gotFinding, tc.wantFinding)
			}
			if tc.wantZeroBursts {
				srv.mu.Lock()
				bursts := srv.burstConnCount
				srv.mu.Unlock()
				if bursts != 0 {
					t.Errorf("Detect(%s) burstConnCount = %d, want 0", tc.name, bursts)
				}
			}
			if tc.wantFinding {
				detail := got.GetDetectionReports()[0].GetVulnerability().GetAdditionalDetails()[0].GetTextData().GetText()
				if !strings.Contains(detail, tc.wantDetailPart) {
					t.Errorf("Detect(%s) additional detail = %q, want substring %q", tc.name, detail, tc.wantDetailPart)
				}
			}
		})
	}
}

func TestDetect_FlowControlOracleAndRetry(t *testing.T) {
	testCases := []struct {
		name           string
		tlsService     bool
		interBatch     time.Duration
		configure      func(*fakeNginxServer)
		wantFinding    bool
		wantDetailPart string
		wantBurstConns int
	}{
		{
			name:           "when_target_is_vulnerable_over_h2c_returns_finding",
			tlsService:     false,
			configure:      func(*fakeNginxServer) {},
			wantFinding:    true,
			wantDetailPart: "HTTP/2 (h2c) at http://127.0.0.1:8080/",
		},
		{
			name:           "when_target_is_vulnerable_over_tls_h2_returns_finding",
			tlsService:     true,
			configure:      func(*fakeNginxServer) {},
			wantFinding:    true,
			wantDetailPart: "HTTP/2 (h2) at https://127.0.0.1:8080/",
		},
		{
			name:       "when_low_max_streams_sends_all_streams_in_single_batch_without_inter_batch_sleep",
			tlsService: true,
			interBatch: 200 * time.Millisecond,
			configure: func(s *fakeNginxServer) {
				s.maxStreams = 1
				s.acceptLimit = 1
			},
			wantFinding:    true,
			wantDetailPart: "burst_streams=2, tail_refused_streams=1",
		},
		{
			name:       "when_patched_server_returns_flow_control_goaway_returns_no_finding",
			tlsService: true,
			configure:  func(s *fakeNginxServer) { s.burstMode = burstPatchedFlowControlGoAway },
		},
		{
			name:       "when_server_sends_goaway_no_error_after_refused_streams_returns_no_finding",
			tlsService: true,
			configure:  func(s *fakeNginxServer) { s.burstMode = burstGoAwayNoErrorAfterRefused },
		},
		{
			name:       "when_server_closes_connection_without_ping_acks_returns_no_finding",
			tlsService: true,
			configure:  func(s *fakeNginxServer) { s.burstMode = burstCloseWithoutPings },
		},
		{
			name:       "when_server_omits_liveness_ping_c_ack_returns_no_finding",
			tlsService: true,
			configure:  func(s *fakeNginxServer) { s.burstMode = burstOmitPingCAck },
		},
		{
			name:       "when_refused_streams_are_not_contiguous_tail_returns_no_finding",
			tlsService: true,
			configure: func(s *fakeNginxServer) {
				s.maxStreams = 80
				s.acceptLimit = 80
				s.burstMode = burstNonContiguousRefused
			},
		},
		{
			name:       "when_single_stream_server_has_no_backpressure_caps_ladder_at_16_attempts",
			tlsService: true,
			configure: func(s *fakeNginxServer) {
				s.maxStreams = 1
				s.acceptLimit = 100
			},
			wantBurstConns: 16,
		},
		{
			name:       "when_refused_streams_exceed_safe_cap_succeeds_on_targeted_retry",
			tlsService: true,
			configure: func(s *fakeNginxServer) {
				s.maxStreams = 200
				s.acceptLimit = 210
				s.acceptLimitFn = func(connNum int) int {
					if connNum == 1 {
						return 250
					}
					return 210
				}
				s.routes["/"] = nginxRoute(bytes.Repeat([]byte("R"), 200))
			},
			wantFinding:    true,
			wantDetailPart: "burst_streams=258, tail_refused_streams=48",
		},
		{
			name:       "when_refused_streams_trigger_nginx_goaway_abort_guard_recovers_via_targeted_retry",
			tlsService: true,
			configure: func(s *fakeNginxServer) {
				s.maxStreams = 100
				s.acceptLimit = 100
				s.acceptLimitFn = func(connNum int) int {
					if connNum == 1 {
						return 150
					}
					return 100
				}
			},
			wantFinding:    true,
			wantDetailPart: "burst_streams=148, tail_refused_streams=48",
		},
		{
			name:       "when_pre_ping_b_flushed_data_exceeds_window_differential_returns_no_finding",
			tlsService: true,
			configure: func(s *fakeNginxServer) {
				s.routes["/"] = nginxRoute(bytes.Repeat([]byte("S"), 50))
				s.defaultBody = bytes.Repeat([]byte("S"), 50)
				s.prePingBFlushBytes = 48000
			},
		},
		{
			name:       "when_first_burst_pre_ping_b_data_equals_threshold_steps_ladder_and_ignores_post_ping_b_data",
			tlsService: true,
			configure: func(s *fakeNginxServer) {
				s.maxStreams = 120
				s.acceptLimit = 160
				s.routes["/"] = nginxRoute(bytes.Repeat([]byte("M"), 200))
				s.defaultBody = bytes.Repeat([]byte("M"), 200)
				s.prePingBFlushBytes = 9600
			},
			wantFinding:    true,
			wantDetailPart: "burst_streams=248, tail_refused_streams=88",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newVulnerableFakeNginx()
			tc.configure(srv)
			mod := newTestModule(t, srv)
			mod.interBatchDelay = tc.interBatch

			svc := buildWebService("", "127.0.0.1", npb.AddressFamily_IPV4, 8080, tc.tlsService)
			got, err := mod.Detect(t.Context(), svc)
			if err != nil {
				t.Fatalf("Detect(%s) unexpected error: %v", tc.name, err)
			}
			if gotFinding := len(got.GetDetectionReports()) > 0; gotFinding != tc.wantFinding {
				t.Fatalf("Detect(%s) finding = %t, want %t", tc.name, gotFinding, tc.wantFinding)
			}
			if rst := srv.clientRSTCount.Load(); rst != 0 {
				t.Errorf("Detect(%s) sent %d RST_STREAM frames, want 0", tc.name, rst)
			}
			if tc.wantBurstConns > 0 {
				srv.mu.Lock()
				gotBursts := srv.burstConnCount
				srv.mu.Unlock()
				if gotBursts != tc.wantBurstConns {
					t.Errorf("Detect(%s) burstConnCount = %d, want %d", tc.name, gotBursts, tc.wantBurstConns)
				}
			}
			if !tc.wantFinding {
				return
			}

			wantVuln := baseVulnerability()
			wantVuln.SetAdditionalDetails([]*vpb.AdditionalDetail{
				vpb.AdditionalDetail_builder{
					Description: "Non-destructive NGINX HTTP/2 queued-frame Stream 0 WINDOW_UPDATE verification evidence",
					TextData:    vpb.TextData_builder{Text: "placeholder"}.Build(),
				}.Build(),
			})
			wantReport := dpb.DetectionReport_builder{
				TargetInfo:         rpb.TargetInfo_builder{NetworkEndpoints: []*npb.NetworkEndpoint{svc.GetNetworkEndpoint()}}.Build(),
				NetworkService:     svc,
				DetectionTimestamp: tspb.New(fixedTestTime),
				DetectionStatus:    dpb.DetectionStatus_VULNERABILITY_VERIFIED,
				Vulnerability:      wantVuln,
			}.Build()

			report := got.GetDetectionReports()[0]
			if diff := cmp.Diff(wantReport, report, protocmp.Transform(), protocmp.IgnoreFields(&vpb.TextData{}, "text")); diff != "" {
				t.Errorf("Detect(%s) report mismatch (-want +got):\n%s", tc.name, diff)
			}
			detail := report.GetVulnerability().GetAdditionalDetails()[0].GetTextData().GetText()
			if !strings.Contains(detail, tc.wantDetailPart) {
				t.Errorf("Detect(%s) additional detail = %q, want substring %q", tc.name, detail, tc.wantDetailPart)
			}
		})
	}
}

func TestDetect_ContextCancellationAndDialErrors(t *testing.T) {
	testCases := []struct {
		name    string
		setup   func(srv *fakeNginxServer, mod *Module, cancel context.CancelFunc)
		wantErr error
	}{
		{
			name: "when_context_already_canceled_before_detect_returns_context_error",
			setup: func(_ *fakeNginxServer, _ *Module, cancel context.CancelFunc) {
				cancel()
			},
			wantErr: context.Canceled,
		},
		{
			name: "when_context_canceled_during_phase2_dial_returns_context_error",
			setup: func(_ *fakeNginxServer, mod *Module, cancel context.CancelFunc) {
				baseDial := mod.dial
				var dials atomic.Int32
				mod.dial = func(dCtx context.Context, opts dialOptions) (net.Conn, error) {
					if dials.Add(1) == 2 {
						cancel()
						return nil, context.Canceled
					}
					return baseDial(dCtx, opts)
				}
			},
			wantErr: context.Canceled,
		},
		{
			name: "when_context_canceled_during_blocking_socket_read_unblocks_and_returns_context_error",
			setup: func(srv *fakeNginxServer, mod *Module, cancel context.CancelFunc) {
				mod.timeout = 10 * time.Second
				srv.onReadStart = cancel
			},
			wantErr: context.Canceled,
		},
		{
			name: "when_dial_fails_with_active_context_returns_nil_error",
			setup: func(_ *fakeNginxServer, mod *Module, _ context.CancelFunc) {
				mod.dial = func(context.Context, dialOptions) (net.Conn, error) {
					return nil, errors.New("connection refused")
				}
			},
			wantErr: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newVulnerableFakeNginx()
			mod := newTestModule(t, srv)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			tc.setup(srv, mod, cancel)

			got, err := mod.Detect(ctx, buildWebService("", "127.0.0.1", npb.AddressFamily_IPV4, 8443, true))
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Detect(%s) error = %v, want %v", tc.name, err, tc.wantErr)
				}
			} else if err != nil {
				t.Fatalf("Detect(%s) unexpected error: %v", tc.name, err)
			}
			if got != nil {
				t.Errorf("Detect(%s) reports = %v, want nil", tc.name, got)
			}
		})
	}
}

func generateLoopbackCert(t *testing.T) tls.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey() unexpected error: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("x509.CreateCertificate() unexpected error: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
}

func startLoopbackListener(t *testing.T, tlsCfg *tls.Config, handler func(net.Conn)) uint32 {
	t.Helper()
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() unexpected error: %v", err)
	}
	port := uint32(tcpLn.Addr().(*net.TCPAddr).Port)
	ln := tcpLn
	if tlsCfg != nil {
		ln = tls.NewListener(tcpLn, tlsCfg)
	}

	var (
		mu    sync.Mutex
		conns = make(map[net.Conn]struct{})
		wg    sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns[conn] = struct{}{}
			mu.Unlock()
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				defer func() {
					mu.Lock()
					delete(conns, c)
					mu.Unlock()
				}()
				handler(c)
			}(conn)
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		for c := range conns {
			_ = c.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	return port
}

func TestLoopbackDefaultDial_NginxH2AndTLS(t *testing.T) {
	cert := generateLoopbackCert(t)

	testCases := []struct {
		name            string
		serverTLS       bool
		serverNextProto []string
		settings24Byte  bool
		serviceTLS      bool
		host            string
		wantFinding     bool
	}{
		{
			name:        "when_loopback_h2c_server_is_vulnerable_detects_over_real_tcp_socket",
			wantFinding: true,
		},
		{
			name:            "when_loopback_tls_h2_server_is_vulnerable_detects_with_sni_and_alpn",
			serverTLS:       true,
			serverNextProto: []string{"h2"},
			settings24Byte:  true,
			serviceTLS:      true,
			host:            "localhost",
			wantFinding:     true,
		},
		{
			name:            "when_loopback_tls_server_negotiates_http11_alpn_returns_no_finding",
			serverTLS:       true,
			serverNextProto: []string{"http/1.1"},
			serviceTLS:      true,
			host:            "localhost",
		},
		{
			name:       "when_loopback_tls_server_omits_alpn_negotiation_returns_no_finding",
			serverTLS:  true,
			serviceTLS: true,
			host:       "localhost",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newVulnerableFakeNginx()
			srv.settings24Byte = tc.settings24Byte
			var tlsCfg *tls.Config
			if tc.serverTLS {
				tlsCfg = &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: tc.serverNextProto}
			}
			port := startLoopbackListener(t, tlsCfg, srv.serveConn)

			mod := newTestModule(t, nil)
			mod.interBatchDelay = 2 * time.Millisecond
			mod.preDrainDelay = 2 * time.Millisecond

			got, err := mod.Detect(t.Context(), buildWebService(tc.host, "127.0.0.1", npb.AddressFamily_IPV4, port, tc.serviceTLS))
			if err != nil {
				t.Fatalf("Detect(%s) unexpected error: %v", tc.name, err)
			}
			if gotFinding := len(got.GetDetectionReports()) > 0; gotFinding != tc.wantFinding {
				t.Fatalf("Detect(%s) finding = %t, want %t", tc.name, gotFinding, tc.wantFinding)
			}
		})
	}
}

func TestLoopbackDefaultDial_NonH2AndClosedPorts(t *testing.T) {
	testCases := []struct {
		name           string
		plaintextReply []byte
		closedPort     bool
		serviceTLS     bool
		wantAccepts    int32
	}{
		{
			name:           "when_tls_flagged_service_points_to_plaintext_listener_returns_no_finding",
			plaintextReply: []byte("NOT_TLS\r\n"),
			serviceTLS:     true,
			wantAccepts:    1,
		},
		{
			name:           "when_h2c_service_points_to_http11_listener_rejects_cleanly_in_one_dial",
			plaintextReply: []byte("HTTP/1.1 400 Bad Request\r\n\r\n"),
			wantAccepts:    1,
		},
		{
			name:       "when_loopback_port_is_closed_returns_no_finding",
			closedPort: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var (
				port    uint32
				accepts atomic.Int32
			)
			if tc.closedPort {
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatalf("net.Listen() unexpected error: %v", err)
				}
				port = uint32(ln.Addr().(*net.TCPAddr).Port)
				_ = ln.Close()
			} else {
				reply := tc.plaintextReply
				port = startLoopbackListener(t, nil, func(c net.Conn) {
					defer c.Close()
					accepts.Add(1)
					_, _ = c.Write(reply)
				})
			}

			mod := newTestModule(t, nil)
			got, err := mod.Detect(t.Context(), buildWebService("", "127.0.0.1", npb.AddressFamily_IPV4, port, tc.serviceTLS))
			if err != nil {
				t.Fatalf("Detect(%s) unexpected error: %v", tc.name, err)
			}
			if len(got.GetDetectionReports()) != 0 {
				t.Errorf("Detect(%s) reports = %v, want empty", tc.name, got)
			}
			if gotAccepts := accepts.Load(); gotAccepts != tc.wantAccepts {
				t.Errorf("Detect(%s) accept count = %d, want %d", tc.name, gotAccepts, tc.wantAccepts)
			}
		})
	}
}

func TestBuildBurstHeaderBlocks(t *testing.T) {
	testCases := []struct {
		name      string
		scheme    string
		authority string
		path      string
	}{
		{
			name:      "when_standard_https_headers_encodes_idempotent_indexed_subsequent_block",
			scheme:    "https",
			authority: "example.com",
			path:      "/static/app.js",
		},
		{
			name:      "when_hpack_authority_exceeds_127_bytes_encodes_multibyte_integer_cleanly",
			scheme:    "https",
			authority: strings.Repeat("a", 250) + ".example.com:8443",
			path:      "/" + strings.Repeat("p", 300),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			firstHeaders, compactHeaders := buildBurstHeaderBlocks(tc.scheme, tc.authority, tc.path)
			if len(compactHeaders) != 6 {
				t.Errorf("buildBurstHeaderBlocks(%q, %q, %q) len(compactHeaders) = %d, want 6",
					tc.scheme, tc.authority, tc.path, len(compactHeaders))
			}

			var gotFields []hpack.HeaderField
			dec := hpack.NewDecoder(4096, func(f hpack.HeaderField) { gotFields = append(gotFields, f) })
			if _, err := dec.Write(firstHeaders); err != nil {
				t.Fatalf("dec.Write(firstHeaders) unexpected error: %v", err)
			}
			if err := dec.Close(); err != nil {
				t.Fatalf("dec.Close(firstHeaders) unexpected error: %v", err)
			}

			want := []hpack.HeaderField{
				{Name: ":method", Value: "GET"},
				{Name: ":scheme", Value: tc.scheme},
				{Name: ":authority", Value: tc.authority},
				{Name: ":path", Value: tc.path},
				{Name: "accept-encoding", Value: "identity"},
				{Name: "user-agent", Value: scannerUA},
			}
			for range 2 {
				gotFields = nil
				if _, err := dec.Write(compactHeaders); err != nil {
					t.Fatalf("dec.Write(compactHeaders) unexpected error: %v", err)
				}
				if err := dec.Close(); err != nil {
					t.Fatalf("dec.Close(compactHeaders) unexpected error: %v", err)
				}
				if diff := cmp.Diff(want, gotFields); diff != "" {
					t.Errorf("buildBurstHeaderBlocks(%q, %q, %q) decoded compact headers mismatch (-want +got):\n%s",
						tc.scheme, tc.authority, tc.path, diff)
				}
			}
		})
	}
}

func TestExtractSafeLocalPath(t *testing.T) {
	testCases := []struct {
		name      string
		raw       string
		authority string
		wantPath  string
		wantOK    bool
	}{
		{name: "when_empty_string_returns_false", raw: ""},
		{name: "when_invalid_url_escape_returns_false", raw: "http://example.com/%zz"},
		{name: "when_scheme_relative_double_slash_returns_false", raw: "//evil.com/a.js"},
		{name: "when_javascript_scheme_returns_false", raw: "javascript:alert(1)"},
		{name: "when_path_exceeds_200_bytes_returns_false", raw: "/" + strings.Repeat("x", 205)},
		{name: "when_valid_local_asset_returns_true", raw: "https://example.com/static/site.css?v=1", wantPath: "/static/site.css", wantOK: true},
		{name: "when_cross_origin_cdn_url_for_authority_returns_false", raw: "https://cdn.jsdelivr.net/npm/app.js", authority: "example.com:8443"},
		{name: "when_same_host_url_for_authority_returns_true", raw: "https://EXAMPLE.COM/static/app.js", authority: "example.com:8443", wantPath: "/static/app.js", wantOK: true},
		{name: "when_same_ipv6_host_for_bracketed_authority_returns_true", raw: "https://[::1]/static/app.js", authority: "[::1]", wantPath: "/static/app.js", wantOK: true},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if gotPath, gotOK := extractSafeLocalPath(tc.raw, tc.authority); gotOK != tc.wantOK || gotPath != tc.wantPath {
				t.Errorf("extractSafeLocalPath(%q, %q) = (%q, %t), want (%q, %t)",
					tc.raw, tc.authority, gotPath, gotOK, tc.wantPath, tc.wantOK)
			}
		})
	}
}

func TestIsSafeAuthority(t *testing.T) {
	testCases := []struct {
		name   string
		auth   string
		wantOK bool
	}{
		{name: "when_empty_authority_returns_false", auth: ""},
		{name: "when_exceeds_260_bytes_returns_false", auth: strings.Repeat("h", 265)},
		{name: "when_contains_control_bytes_returns_false", auth: "host\r\n:443"},
		{name: "when_valid_authority_returns_true", auth: "edge.example.com:8443", wantOK: true},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if gotOK := isSafeAuthority(tc.auth); gotOK != tc.wantOK {
				t.Errorf("isSafeAuthority(%q) = %t, want %t", tc.auth, gotOK, tc.wantOK)
			}
		})
	}
}
