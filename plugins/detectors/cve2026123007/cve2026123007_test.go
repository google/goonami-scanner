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
			name: "when_zero_timeout_configured_uses_default_timeout",
			cfg: config.FromProto(cpb.Config_builder{
				Globalcfg: cpb.GlobalConfig_builder{
					Performance: cpb.GlobalConfig_Performance_builder{
						TimeoutPerRequestSeconds: proto.Int32(0),
					}.Build(),
				}.Build(),
			}.Build()),
			wantTimeout: defaultTimeout,
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
	burstOmitPingAAck
	burstOmitPingCAck
	burstNonContiguousRefused
	burstFlowControlGoAwayAfterPostPing
)

type fakeRoute struct {
	status                  string
	headers                 []hpack.HeaderField
	headersFn               func(call int) []hpack.HeaderField
	trailers                []hpack.HeaderField
	body                    []byte
	bodyFn                  func(call int) []byte
	rawHeaderBlock          []byte
	continuationChunks      int
	badContinuationMismatch bool
	unchunkedOversizedData  bool
	closeConn               bool
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

	acceptLimit         int
	acceptLimitFn       func(connNum int) int
	burstMode           fakeBurstMode
	prePingBFlushBytes  int
	burstOversizedFrame bool

	mu                          sync.Mutex
	connCount                   int
	burstConnCount              int
	maxSubsequentBurstHeaderLen int
	sawEnablePush0              atomic.Bool
	dialAddrs                   []string
	sniHosts                    []string
	authorities                 []string
	routeCalls                  map[string]int
	clientRSTCount              atomic.Int32
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
	if cs.isBurstConn && sid > 1 {
		if n := len(fr.HeaderBlockFragment()); n > cs.srv.maxSubsequentBurstHeaderLen {
			cs.srv.maxSubsequentBurstHeaderLen = n
		}
	}
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
	if route.closeConn {
		return false
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
		headers := route.headers
		if route.headersFn != nil {
			headers = route.headersFn(callNum)
		}
		for _, hf := range headers {
			_ = cs.enc.WriteField(hf)
		}
		hdrBytes = bytes.Clone(cs.encBuf.Bytes())
	}

	endStreamOnHeaders := len(body) == 0 && len(route.trailers) == 0
	if err := writeHeadersPossiblySplit(cs.writeRaw, sid, hdrBytes, endStreamOnHeaders, route.continuationChunks, route.badContinuationMismatch); err != nil {
		return false
	}

	maxSend := min(len(body), int(cs.clientInitStreamWin))
	chunkCap := 16384
	if route.unchunkedOversizedData {
		maxSend = len(body)
		chunkCap = max(len(body), 1)
	}
	streamComplete := maxSend == len(body)
	for rem := body[:maxSend]; len(rem) > 0; {
		chunkLen := min(len(rem), chunkCap)
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
	if cs.isBurstConn && cs.srv.burstMode == burstOmitPingAAck && cs.pingCount == 1 {
		return true
	}
	nonce := fr.Data
	if cs.isBurstConn && cs.srv.burstOversizedFrame && cs.pingCount == 1 {
		if err := cs.writeRaw(func(wf *http2.Framer) {
			_ = wf.WriteData(1, false, bytes.Repeat([]byte("O"), maxStaticBodyBytes+1))
		}); err != nil {
			return false
		}
	}
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
	if cs.isBurstConn && cs.srv.burstMode == burstFlowControlGoAwayAfterPostPing && cs.pingCount == 2 {
		_ = cs.writeRaw(func(wf *http2.Framer) {
			_ = wf.WriteGoAway(uint32(2*cs.openedStreams-1), http2.ErrCodeFlowControl, nil)
		})
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
		{
			name: "when_endpoint_port_number_is_zero_skips_without_dialing",
			service: func() *nspb.NetworkService {
				svc := buildWebService("", "127.0.0.1", npb.AddressFamily_IPV4, 0, false)
				svc.GetNetworkEndpoint().SetPort(npb.Port_builder{PortNumber: 0}.Build())
				return svc
			}(),
		},
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
			name: "when_first_response_is_empty_with_envoy_server_header_returns_no_finding",
			configure: func(s *fakeNginxServer) {
				s.routes["/"] = fakeRoute{
					status:  "204",
					headers: []hpack.HeaderField{{Name: "server", Value: "envoy"}},
				}
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
		{
			name: "when_first_candidate_stability_check_returns_via_header_returns_no_finding",
			configure: func(s *fakeNginxServer) {
				r := nginxRoute(bytes.Repeat([]byte("A"), 12000))
				r.headersFn = func(call int) []hpack.HeaderField {
					if call >= 2 {
						return []hpack.HeaderField{
							{Name: "server", Value: "nginx"},
							{Name: "via", Value: "2.0 varnish"},
						}
					}
					return []hpack.HeaderField{{Name: "server", Value: "nginx"}}
				}
				s.routes["/"] = r
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
		wantRootCalls  int
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
			name: "when_secondary_asset_resets_stream_continues_to_next_static_candidate",
			configure: func(s *fakeNginxServer) {
				s.routes["/"] = nginxRoute([]byte(`<script src="/broken.js"></script><script src="/good.js"></script>`))
				s.routes["/broken.js"] = fakeRoute{rstErrCode: &rstInternal}
				s.routes["/good.js"] = nginxRoute(bytes.Repeat([]byte("G"), 12000))
				s.defaultBody = nil
			},
			wantFinding:    true,
			wantDetailPart: "https://127.0.0.1:8443/good.js (",
		},
		{
			name: "when_secondary_asset_closes_connection_retains_verified_root_candidate",
			configure: func(s *fakeNginxServer) {
				s.routes["/"] = nginxRoute([]byte(`<script src="/eof.js"></script>`))
				s.routes["/eof.js"] = fakeRoute{closeConn: true}
			},
			wantFinding:    true,
			wantDetailPart: "https://127.0.0.1:8443/ (",
		},
		{
			name: "when_secondary_asset_length_varies_skips_unstable_candidate_and_falls_back_to_404",
			configure: func(s *fakeNginxServer) {
				s.routes["/"] = nginxRoute([]byte(`<script src="/dynamic.js"></script>`))
				r := nginxRoute(nil)
				r.bodyFn = func(call int) []byte { return bytes.Repeat([]byte("V"), 12000+call*17) }
				s.routes["/dynamic.js"] = r
				s.defaultBody = bytes.Repeat([]byte("S"), 4096)
			},
			wantFinding:    true,
			wantDetailPart: "static_body_bytes=4096",
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
				r := nginxRoute(bytes.Repeat([]byte("A"), 12000))
				r.rawHeaderBlock = exactSizeHeaderBlock(maxHeaderBlockBytes + 1)
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
			name: "when_hpack_header_string_exceeds_max_length_returns_no_finding",
			configure: func(s *fakeNginxServer) {
				s.routes["/"] = nginxRouteWithHeaders([]hpack.HeaderField{
					{Name: "server", Value: "nginx"},
					{Name: "x-long", Value: strings.Repeat("L", maxHPACKStringLen+1)},
				}, bytes.Repeat([]byte("A"), 12000))
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
			wantRootCalls:  1,
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
		{
			name: "when_discovery_data_frame_exceeds_max_read_frame_size_returns_no_finding",
			configure: func(s *fakeNginxServer) {
				r := nginxRoute(bytes.Repeat([]byte("O"), discoveryStreamWindow+1))
				r.unchunkedOversizedData = true
				s.routes["/"] = r
			},
			wantZeroBursts: true,
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
			if tc.wantRootCalls > 0 {
				srv.mu.Lock()
				rootCalls := srv.routeCalls["/"]
				srv.mu.Unlock()
				if rootCalls != tc.wantRootCalls {
					t.Errorf("Detect(%s) root GET count = %d, want %d", tc.name, rootCalls, tc.wantRootCalls)
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
			wantDetailPart: "HTTP/2 (h2) at https://127.0.0.1:8080/ (settings_len=18, max_concurrent_streams=8, static_body_bytes=12000, burst_streams=12, tail_refused_streams=4, stream0_window_update=2147387647 ",
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
			name:       "when_server_omits_pre_update_ping_a_ack_returns_no_finding",
			tlsService: true,
			configure:  func(s *fakeNginxServer) { s.burstMode = burstOmitPingAAck },
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
		{
			name:       "when_pre_ping_b_data_is_one_byte_below_threshold_accepts_first_burst",
			tlsService: true,
			configure: func(s *fakeNginxServer) {
				s.maxStreams = 120
				s.acceptLimit = 160
				s.routes["/"] = nginxRoute(bytes.Repeat([]byte("M"), 200))
				s.defaultBody = bytes.Repeat([]byte("M"), 200)
				s.prePingBFlushBytes = 9599
			},
			wantFinding:    true,
			wantDetailPart: "burst_streams=168, tail_refused_streams=8",
			wantBurstConns: 1,
		},
		{
			name:       "when_second_overshoot_persists_stops_after_single_targeted_retry",
			tlsService: true,
			configure: func(s *fakeNginxServer) {
				s.maxStreams = 100
				s.acceptLimitFn = func(connNum int) int {
					if connNum <= 2 {
						return 1
					}
					return 140
				}
			},
			wantBurstConns: 2,
		},
		{
			name:       "when_connection_closes_without_pings_before_refusal_aborts_ladder_immediately",
			tlsService: true,
			configure: func(s *fakeNginxServer) {
				s.maxStreams = 8
				s.acceptLimit = 100
				s.burstMode = burstCloseWithoutPings
			},
			wantBurstConns: 1,
		},
		{
			name:       "when_burst_data_frame_exceeds_max_read_frame_size_returns_no_finding",
			tlsService: true,
			configure: func(s *fakeNginxServer) {
				s.maxStreams = 120
				s.acceptLimit = 120
				s.burstOversizedFrame = true
			},
		},
		{
			name:       "when_flow_control_goaway_arrives_after_post_update_ping_aborts_ladder_immediately",
			tlsService: true,
			configure: func(s *fakeNginxServer) {
				s.maxStreams = 8
				s.acceptLimit = 100
				s.burstMode = burstFlowControlGoAwayAfterPostPing
			},
			wantBurstConns: 1,
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
			srv.mu.Lock()
			gotMaxHdr := srv.maxSubsequentBurstHeaderLen
			srv.mu.Unlock()
			if gotMaxHdr != 6 {
				t.Errorf("Detect(%s) max subsequent burst HEADERS block len = %d, want 6", tc.name, gotMaxHdr)
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

type cancelOnSecondWriteConn struct {
	net.Conn
	writes     atomic.Int32
	readCalled *atomic.Bool
	cancel     context.CancelFunc
}

func (c *cancelOnSecondWriteConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if c.writes.Add(1) == 2 {
		c.cancel()
	}
	return n, err
}

func (c *cancelOnSecondWriteConn) Read(p []byte) (int, error) {
	c.readCalled.Store(true)
	return c.Conn.Read(p)
}

func TestDetect_ContextCancellationAndDialErrors(t *testing.T) {
	testCases := []struct {
		name    string
		setup   func(srv *fakeNginxServer, mod *Module, cancel context.CancelFunc, readCalled *atomic.Bool)
		wantErr error
		noRead  bool
	}{
		{
			name: "when_context_already_canceled_before_detect_returns_context_error",
			setup: func(_ *fakeNginxServer, _ *Module, cancel context.CancelFunc, _ *atomic.Bool) {
				cancel()
			},
			wantErr: context.Canceled,
		},
		{
			name: "when_context_canceled_during_phase2_dial_returns_context_error",
			setup: func(_ *fakeNginxServer, mod *Module, cancel context.CancelFunc, _ *atomic.Bool) {
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
			setup: func(srv *fakeNginxServer, mod *Module, cancel context.CancelFunc, _ *atomic.Bool) {
				mod.timeout = 10 * time.Second
				srv.onReadStart = cancel
			},
			wantErr: context.Canceled,
		},
		{
			name: "when_context_canceled_before_pre_drain_delay_skips_drain_read",
			setup: func(_ *fakeNginxServer, mod *Module, cancel context.CancelFunc, readCalled *atomic.Bool) {
				baseDial := mod.dial
				var dials atomic.Int32
				mod.dial = func(dCtx context.Context, opts dialOptions) (net.Conn, error) {
					conn, err := baseDial(dCtx, opts)
					if err != nil || dials.Add(1) != 2 {
						return conn, err
					}
					return &cancelOnSecondWriteConn{
						Conn:       conn,
						readCalled: readCalled,
						cancel:     cancel,
					}, nil
				}
			},
			wantErr: context.Canceled,
			noRead:  true,
		},
		{
			name: "when_dial_fails_with_active_context_returns_nil_error",
			setup: func(_ *fakeNginxServer, mod *Module, _ context.CancelFunc, _ *atomic.Bool) {
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
			var readCalled atomic.Bool
			tc.setup(srv, mod, cancel, &readCalled)

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
			if tc.noRead && readCalled.Load() {
				t.Errorf("Detect(%s) called Phase 2 conn.Read() after context cancellation before pre-drain delay", tc.name)
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
		{name: "when_triple_slash_path_returns_false", raw: "///evil.com/a.js"},
		{name: "when_javascript_scheme_returns_false", raw: "javascript:alert(1)"},
		{name: "when_ftp_scheme_with_root_path_returns_false", raw: "ftp://example.com/static/app.js"},
		{name: "when_path_exceeds_200_bytes_returns_false", raw: "/" + strings.Repeat("x", 205)},
		{name: "when_valid_http_asset_returns_true", raw: "http://example.com/static/site.js", wantPath: "/static/site.js", wantOK: true},
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
		{name: "when_contains_space_returns_false", auth: "host :443"},
		{name: "when_contains_del_byte_returns_false", auth: "host\x7f:443"},
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

func TestCrawledCandidatePaths(t *testing.T) {
	testCases := []struct {
		name      string
		crawlURLs []string
		limit     int
		want      []string
	}{
		{
			name:  "when_no_crawl_results_returns_nil",
			limit: maxCrawledCandidates,
		},
		{
			name: "when_crawl_results_have_duplicates_and_exceed_limit_deduplicates_and_caps",
			crawlURLs: []string{
				"https://example.com/",
				"https://example.com/api/users",
				"https://example.com//double.js",
				"https://example.com/static/a.js",
				"https://example.com/static/a.js",
				"https://example.com/static/b.css",
				"https://example.com/static/c.woff2",
				"https://example.com/static/d.png",
			},
			limit: maxCrawledCandidates,
			want:  []string{"/static/a.js", "/static/b.css", "/static/c.woff2"},
		},
		{
			name: "when_unique_static_paths_below_limit_returns_all_unique_paths",
			crawlURLs: []string{
				"https://example.com/static/a.js",
				"https://example.com/static/a.js",
				"https://example.com/static/b.css",
			},
			limit: maxCrawledCandidates,
			want:  []string{"/static/a.js", "/static/b.css"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			svc := buildWebService("", "127.0.0.1", npb.AddressFamily_IPV4, 8443, true, tc.crawlURLs...)
			got := crawledCandidatePaths(svc, tc.limit)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("crawledCandidatePaths() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestBuildProbeTarget(t *testing.T) {
	testCases := []struct {
		name        string
		mode        transportMode
		authorities []string
		endpoint    *npb.NetworkEndpoint
		port        uint32
		want        probeTarget
		wantOK      bool
	}{
		{
			name:     "when_authorities_empty_returns_false",
			mode:     transportH2TLS,
			endpoint: buildWebService("", "127.0.0.1", npb.AddressFamily_IPV4, 443, true).GetNetworkEndpoint(),
			port:     443,
		},
		{
			name:        "when_primary_authority_missing_port_returns_false",
			mode:        transportH2TLS,
			authorities: []string{"edge.example.com"},
			endpoint:    buildWebService("edge.example.com", "", npb.AddressFamily_ADDRESS_FAMILY_UNSPECIFIED, 443, true).GetNetworkEndpoint(),
			port:        443,
		},
		{
			name:        "when_ip_only_endpoint_has_ipv6_zone_omits_sni",
			mode:        transportH2TLS,
			authorities: []string{"[fe80::1%eth0]:443"},
			endpoint:    buildWebService("", "fe80::1%eth0", npb.AddressFamily_IPV6, 443, true).GetNetworkEndpoint(),
			port:        443,
			want: probeTarget{
				mode:      transportH2TLS,
				scheme:    "https",
				dialAddr:  "[fe80::1%eth0]:443",
				authority: "[fe80::1%eth0]",
				sniHost:   "",
			},
			wantOK: true,
		},
		{
			name:        "when_hostname_is_ip_literal_omits_sni",
			mode:        transportH2TLS,
			authorities: []string{"10.0.0.5:443"},
			endpoint:    buildWebService("10.0.0.5", "", npb.AddressFamily_ADDRESS_FAMILY_UNSPECIFIED, 443, true).GetNetworkEndpoint(),
			port:        443,
			want: probeTarget{
				mode:      transportH2TLS,
				scheme:    "https",
				dialAddr:  "10.0.0.5:443",
				authority: "10.0.0.5",
				sniHost:   "",
			},
			wantOK: true,
		},
		{
			name:        "when_hostname_and_ip_on_port_443_sets_sni_and_dials_ip",
			mode:        transportH2TLS,
			authorities: []string{"edge.example.com:443", "10.0.0.5:443"},
			endpoint:    buildWebService("edge.example.com", "10.0.0.5", npb.AddressFamily_IPV4, 443, true).GetNetworkEndpoint(),
			port:        443,
			want: probeTarget{
				mode:      transportH2TLS,
				scheme:    "https",
				dialAddr:  "10.0.0.5:443",
				authority: "edge.example.com",
				sniHost:   "edge.example.com",
			},
			wantOK: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, gotOK := buildProbeTarget(tc.mode, tc.authorities, tc.endpoint, tc.port)
			if gotOK != tc.wantOK {
				t.Fatalf("buildProbeTarget() ok = %t, want %t", gotOK, tc.wantOK)
			}
			if diff := cmp.Diff(tc.want, got, cmp.AllowUnexported(probeTarget{})); diff != "" {
				t.Errorf("buildProbeTarget() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestParseNginxGreetingSettings(t *testing.T) {
	makeSettingsFrame := func(t *testing.T, ack bool, settings ...http2.Setting) http2.Frame {
		t.Helper()
		var buf bytes.Buffer
		wf := http2.NewFramer(&buf, nil)
		if ack {
			if err := wf.WriteSettingsAck(); err != nil {
				t.Fatalf("WriteSettingsAck() unexpected error: %v", err)
			}
		} else {
			if err := wf.WriteSettings(settings...); err != nil {
				t.Fatalf("WriteSettings() unexpected error: %v", err)
			}
		}
		rf := http2.NewFramer(io.Discard, &buf)
		frame, err := rf.ReadFrame()
		if err != nil {
			t.Fatalf("ReadFrame() unexpected error: %v", err)
		}
		return frame
	}

	makePingFrame := func(t *testing.T) http2.Frame {
		t.Helper()
		var buf bytes.Buffer
		wf := http2.NewFramer(&buf, nil)
		if err := wf.WritePing(false, [8]byte{1, 2, 3, 4, 5, 6, 7, 8}); err != nil {
			t.Fatalf("WritePing() unexpected error: %v", err)
		}
		rf := http2.NewFramer(io.Discard, &buf)
		frame, err := rf.ReadFrame()
		if err != nil {
			t.Fatalf("ReadFrame() unexpected error: %v", err)
		}
		return frame
	}

	testCases := []struct {
		name           string
		nonSettings    bool
		ack            bool
		settings       []http2.Setting
		wantLen        int
		wantMaxStreams uint32
		wantOK         bool
	}{
		{
			name:        "when_frame_is_not_settings_returns_false",
			nonSettings: true,
		},
		{
			name: "when_frame_is_settings_ack_returns_false",
			ack:  true,
		},
		{
			name: "when_s0_id_is_not_max_concurrent_streams_returns_false",
			settings: []http2.Setting{
				{ID: http2.SettingHeaderTableSize, Val: 128},
				{ID: http2.SettingInitialWindowSize, Val: 65535},
				{ID: http2.SettingMaxFrameSize, Val: nginxMaxFrameSize},
			},
		},
		{
			name: "when_s1_id_is_not_initial_window_size_returns_false",
			settings: []http2.Setting{
				{ID: http2.SettingMaxConcurrentStreams, Val: 128},
				{ID: http2.SettingHeaderTableSize, Val: 65535},
				{ID: http2.SettingMaxFrameSize, Val: nginxMaxFrameSize},
			},
		},
		{
			name: "when_s2_id_is_not_max_frame_size_with_nginx_val_returns_false",
			settings: []http2.Setting{
				{ID: http2.SettingMaxConcurrentStreams, Val: 128},
				{ID: http2.SettingInitialWindowSize, Val: 65535},
				{ID: http2.SettingHeaderTableSize, Val: nginxMaxFrameSize},
			},
		},
		{
			name: "when_s3_id_differs_with_val_one_returns_false",
			settings: []http2.Setting{
				{ID: http2.SettingMaxConcurrentStreams, Val: 128},
				{ID: http2.SettingInitialWindowSize, Val: 65535},
				{ID: http2.SettingMaxFrameSize, Val: nginxMaxFrameSize},
				{ID: http2.SettingEnablePush, Val: 1},
			},
		},
		{
			name: "when_s3_val_is_zero_with_no_priorities_id_returns_false",
			settings: []http2.Setting{
				{ID: http2.SettingMaxConcurrentStreams, Val: 128},
				{ID: http2.SettingInitialWindowSize, Val: 65535},
				{ID: http2.SettingMaxFrameSize, Val: nginxMaxFrameSize},
				{ID: settingNoPrioritiesID, Val: 0},
			},
		},
		{
			name: "when_valid_18_byte_nginx_settings_returns_length_and_max_streams",
			settings: []http2.Setting{
				{ID: http2.SettingMaxConcurrentStreams, Val: 128},
				{ID: http2.SettingInitialWindowSize, Val: nginxMaxWindow},
				{ID: http2.SettingMaxFrameSize, Val: nginxMaxFrameSize},
			},
			wantLen:        18,
			wantMaxStreams: 128,
			wantOK:         true,
		},
		{
			name: "when_valid_24_byte_nginx_settings_returns_length_and_max_streams",
			settings: []http2.Setting{
				{ID: http2.SettingMaxConcurrentStreams, Val: 64},
				{ID: http2.SettingInitialWindowSize, Val: 65535},
				{ID: http2.SettingMaxFrameSize, Val: nginxMaxFrameSize},
				{ID: settingNoPrioritiesID, Val: 1},
			},
			wantLen:        24,
			wantMaxStreams: 64,
			wantOK:         true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var frame http2.Frame
			if tc.nonSettings {
				frame = makePingFrame(t)
			} else {
				frame = makeSettingsFrame(t, tc.ack, tc.settings...)
			}
			gotLen, gotMaxStreams, gotOK := parseNginxGreetingSettings(frame)
			if gotOK != tc.wantOK || gotLen != tc.wantLen || gotMaxStreams != tc.wantMaxStreams {
				t.Errorf("parseNginxGreetingSettings() = (%d, %d, %t), want (%d, %d, %t)",
					gotLen, gotMaxStreams, gotOK, tc.wantLen, tc.wantMaxStreams, tc.wantOK)
			}
		})
	}
}

func TestReadDiscoveryStream(t *testing.T) {
	encodeHeaders := func(fields ...hpack.HeaderField) []byte {
		var buf bytes.Buffer
		enc := hpack.NewEncoder(&buf)
		for _, f := range fields {
			_ = enc.WriteField(f)
		}
		return buf.Bytes()
	}

	testCases := []struct {
		name          string
		writeFrames   func(*http2.Framer)
		wantHeaders   []hpack.HeaderField
		wantBodyLen   int
		wantSampleLen int
	}{
		{
			name: "when_frames_arrive_for_unrelated_stream_ignores_them_and_reads_target_stream",
			writeFrames: func(wf *http2.Framer) {
				_ = wf.WriteHeaders(http2.HeadersFrameParam{
					StreamID:      99,
					BlockFragment: encodeHeaders(hpack.HeaderField{Name: ":status", Value: "200"}, hpack.HeaderField{Name: "server", Value: "envoy"}),
					EndStream:     true,
					EndHeaders:    true,
				})
				_ = wf.WriteData(99, true, []byte("unrelated"))
				_ = wf.WriteRSTStream(99, http2.ErrCodeInternal)
				_ = wf.WriteHeaders(http2.HeadersFrameParam{
					StreamID:      1,
					BlockFragment: encodeHeaders(hpack.HeaderField{Name: ":status", Value: "200"}, hpack.HeaderField{Name: "server", Value: "nginx"}),
					EndStream:     false,
					EndHeaders:    true,
				})
				_ = wf.WriteData(1, true, []byte("ok"))
			},
			wantHeaders: []hpack.HeaderField{
				{Name: ":status", Value: "200"},
				{Name: "server", Value: "nginx"},
			},
			wantBodyLen:   2,
			wantSampleLen: 2,
		},
		{
			name: "when_data_exceeds_sample_cap_captures_exact_preferred_static_body_len",
			writeFrames: func(wf *http2.Framer) {
				_ = wf.WriteHeaders(http2.HeadersFrameParam{
					StreamID:      1,
					BlockFragment: encodeHeaders(hpack.HeaderField{Name: ":status", Value: "200"}),
					EndStream:     false,
					EndHeaders:    true,
				})
				_ = wf.WriteData(1, false, bytes.Repeat([]byte("A"), 5000))
				_ = wf.WriteData(1, true, bytes.Repeat([]byte("B"), 5000))
			},
			wantHeaders:   []hpack.HeaderField{{Name: ":status", Value: "200"}},
			wantBodyLen:   10000,
			wantSampleLen: preferredStaticBodyLen,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var wire bytes.Buffer
			wf := http2.NewFramer(&wire, nil)
			tc.writeFrames(wf)

			rf := http2.NewFramer(io.Discard, &wire)
			dec := hpack.NewDecoder(4096, nil)
			got, gotPing, err := readDiscoveryStream(rf, dec, 1, nil)
			if err != nil {
				t.Fatalf("readDiscoveryStream() unexpected error: %v", err)
			}
			if !gotPing {
				t.Errorf("readDiscoveryStream() gotPing = false, want true")
			}
			if diff := cmp.Diff(tc.wantHeaders, got.headers); diff != "" {
				t.Errorf("readDiscoveryStream() headers mismatch (-want +got):\n%s", diff)
			}
			if got.bodyLen != tc.wantBodyLen {
				t.Errorf("readDiscoveryStream() bodyLen = %d, want %d", got.bodyLen, tc.wantBodyLen)
			}
			if len(got.sampleBody) != tc.wantSampleLen {
				t.Errorf("readDiscoveryStream() len(sampleBody) = %d, want %d", len(got.sampleBody), tc.wantSampleLen)
			}
		})
	}
}

func TestIsExcludedNonNginxServer(t *testing.T) {
	testCases := []struct {
		name    string
		headers []hpack.HeaderField
		want    bool
	}{
		{
			name:    "when_server_contains_nginx_and_non_nginx_token_is_not_excluded",
			headers: []hpack.HeaderField{{Name: "server", Value: "nginx/1.25 (cloudflare-origin)"}},
			want:    false,
		},
		{
			name:    "when_server_contains_openresty_and_non_nginx_token_is_not_excluded",
			headers: []hpack.HeaderField{{Name: "server", Value: "openresty/1.25 (cloudflare-origin)"}},
			want:    false,
		},
		{
			name:    "when_server_is_cloudflare_is_excluded",
			headers: []hpack.HeaderField{{Name: "server", Value: "cloudflare"}},
			want:    true,
		},
		{
			name:    "when_server_is_awselb_even_with_nginx_token_is_excluded",
			headers: []hpack.HeaderField{{Name: "server", Value: "awselb/2.0 nginx"}},
			want:    true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isExcludedNonNginxServer(tc.headers); got != tc.want {
				t.Errorf("isExcludedNonNginxServer(%v) = %t, want %t", tc.headers, got, tc.want)
			}
		})
	}
}

func TestFinalizeAttempt(t *testing.T) {
	testCases := []struct {
		name        string
		refusedSIDs []uint32
		streamCount int
		want        flowControlAttempt
	}{
		{
			name:        "when_no_refused_streams_returns_zero_flags",
			streamCount: 4,
		},
		{
			name:        "when_refused_starts_with_even_stream_id_rejects",
			refusedSIDs: []uint32{2, 4},
			streamCount: 4,
			want:        flowControlAttempt{refusedCount: 2},
		},
		{
			name:        "when_refused_contains_stream_id_above_max_rejects",
			refusedSIDs: []uint32{3, 5, 7},
			streamCount: 3,
			want:        flowControlAttempt{refusedCount: 3},
		},
		{
			name:        "when_refused_has_duplicate_stream_ids_exceeding_stream_count_rejects",
			refusedSIDs: []uint32{1, 1, 3, 5},
			streamCount: 3,
			want:        flowControlAttempt{refusedCount: 4},
		},
		{
			name:        "when_refused_is_contiguous_interior_enables_overshoot_retry_only",
			refusedSIDs: []uint32{5, 3},
			streamCount: 4,
			want: flowControlAttempt{
				refusedCount:          2,
				acceptedBeforeRefused: 1,
				canRetryOvershoot:     true,
			},
		},
		{
			name:        "when_refused_is_contiguous_tail_sets_tail_and_accepted_count",
			refusedSIDs: []uint32{7, 5},
			streamCount: 4,
			want: flowControlAttempt{
				refusedCount:          2,
				acceptedBeforeRefused: 2,
				canRetryOvershoot:     true,
				isContiguousTail:      true,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := finalizeAttempt(flowControlAttempt{}, append([]uint32(nil), tc.refusedSIDs...), tc.streamCount)
			if diff := cmp.Diff(tc.want, got, cmp.AllowUnexported(flowControlAttempt{})); diff != "" {
				t.Errorf("finalizeAttempt() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestSleepWithContext(t *testing.T) {
	t.Run("when_zero_duration_with_active_context_returns_nil", func(t *testing.T) {
		if err := sleepWithContext(t.Context(), 0); err != nil {
			t.Errorf("sleepWithContext(ctx, 0) = %v, want nil", err)
		}
	})

	t.Run("when_non_positive_duration_with_canceled_context_returns_canceled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		for _, d := range []time.Duration{0, -time.Millisecond} {
			for range 64 {
				if err := sleepWithContext(ctx, d); !errors.Is(err, context.Canceled) {
					t.Fatalf("sleepWithContext(canceled, %v) = %v, want %v", d, err, context.Canceled)
				}
			}
		}
	})

	t.Run("when_positive_duration_elapses_returns_nil", func(t *testing.T) {
		if err := sleepWithContext(t.Context(), 5*time.Millisecond); err != nil {
			t.Errorf("sleepWithContext(ctx, 5ms) = %v, want nil", err)
		}
	})

	t.Run("when_context_canceled_during_positive_sleep_returns_canceled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		done := make(chan error, 1)
		go func() {
			done <- sleepWithContext(ctx, 10*time.Second)
		}()
		select {
		case err := <-done:
			t.Fatalf("sleepWithContext(ctx, 10s) returned early before cancellation: %v", err)
		case <-time.After(20 * time.Millisecond):
		}
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Errorf("sleepWithContext(ctx, 10s) = %v, want %v", err, context.Canceled)
		}
	})
}

func TestExtractHTMLAssetPaths(t *testing.T) {
	testCases := []struct {
		name      string
		html      string
		authority string
		limit     int
		want      []string
	}{
		{
			name: "when_html_contains_mixed_tags_filters_to_unique_same_origin_static_href_and_src",
			html: `<!-- <script src="/comment.js"></script> -->` +
				`<div data-alt="/ignored.js"></div>` +
				`<a href="/">root</a>` +
				`<a href="/api/data">api</a>` +
				`<script src="https://cdn.example.com/x.js"></script>` +
				`<link rel="stylesheet" href="https://example.com/a.css">` +
				`<link rel="stylesheet" href="/a.css">` +
				`<img src="/b.png"/>` +
				`<script src="/c.js"></script>`,
			authority: "example.com:443",
			limit:     2,
			want:      []string{"/a.css", "/b.png"},
		},
		{
			name:      "when_single_tag_has_multiple_assets_stops_at_limit",
			html:      `<a href="/a.js" src="/b.js"></a>`,
			authority: "example.com",
			limit:     1,
			want:      []string{"/a.js"},
		},
		{
			name:      "when_single_tag_has_multiple_assets_within_limit_extracts_all",
			html:      `<a href="/a.js" src="/b.js"></a>`,
			authority: "example.com",
			limit:     2,
			want:      []string{"/a.js", "/b.js"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := extractHTMLAssetPaths([]byte(tc.html), tc.authority, tc.limit)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("extractHTMLAssetPaths() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
