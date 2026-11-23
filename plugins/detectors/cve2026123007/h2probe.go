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
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"net"
	"net/url"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/google/goonami-scanner/core/log"
	npb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
	"golang.org/x/net/html"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const (
	h2ClientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
	scannerUA       = "TsunamiSecurityScanner"

	nginxMaxFrameSize     = 16777215   // 0x00ffffff
	nginxConnWindowDelta  = 2147418112 // 0x7fff0000
	nginxMaxWindow        = 0x7fffffff
	settingNoPrioritiesID = 0x0009

	smallRecvBufBytes = 2304
	largeRecvBufBytes = 4 * 1024 * 1024
	// Cap static candidates at 64 KiB so every queued response fits within
	// NGINX's default output_buffers (2 * 32 KiB) when sendfile is inactive.
	maxStaticBodyBytes     = 65536
	discoveryStreamWindow  = maxStaticBodyBytes + 1
	discoveryConnWinDelta  = 4 * 1024 * 1024
	preferredStaticBodyLen = 8192
	maxHeaderBlockBytes    = 32768
	maxHPACKFields         = 128
	maxHPACKStringLen      = 8192
	maxContinuationFrames  = 16
	maxEffectiveConcurrent = 256
	maxSafeRefusedCap      = 96
	maxBatchStreams        = 64
	maxBurstStreams        = 940
	maxLadderStep          = 80
	// Cap initial ladder attempts so MAX_CONCURRENT_STREAMS=1 endpoints cannot
	// trigger hundreds of retries (at most one overshoot retry may be inserted).
	maxLadderAttempts = 16
	maxFramesPerDrain = 32768
)

var (
	errNotNginxH2   = errors.New("peer did not match NGINX HTTP/2 framing")
	errStreamReset  = errors.New("discovery stream reset by peer")
	nonNginxServers = []string{"apache", "envoy", "cloudflare", "caddy", "haproxy", "iis", "jetty", "tomcat", "gws"}
)

type transportMode string

const (
	transportH2TLS transportMode = "h2"
	transportH2C   transportMode = "h2c"
)

type dialOptions struct {
	mode         transportMode
	dialAddr     string
	sniHost      string
	timeout      time.Duration
	smallRecvBuf bool
}

type dialFunc func(ctx context.Context, opts dialOptions) (net.Conn, error)

func defaultDial(ctx context.Context, opts dialOptions) (net.Conn, error) {
	dialCtx, cancel := context.WithTimeout(ctx, opts.timeout) // NOMUTANTS -- defensive dial timeout bound
	defer cancel()                                            // NOMUTANTS -- context timer cleanup

	dialer := net.Dialer{Timeout: opts.timeout}
	if opts.smallRecvBuf {
		dialer.Control = func(_, _ string, c syscall.RawConn) error {
			_ = c.Control(func(fd uintptr) { // NOMUTANTS -- best-effort pre-SYN SO_RCVBUF clamp
				_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, smallRecvBufBytes)
			})
			return nil
		}
	}

	rawConn, err := dialer.DialContext(dialCtx, "tcp", opts.dialAddr)
	if err != nil {
		return nil, err
	}
	if tcpConn, ok := rawConn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true) // NOMUTANTS -- latency optimization
	}
	_ = rawConn.SetDeadline(time.Now().Add(opts.timeout)) // NOMUTANTS -- defensive socket deadline

	if opts.mode == transportH2C {
		return rawConn, nil
	}

	tlsCfg := &tls.Config{
		// Active network scanners probe targets that often serve self-signed or IP-bound certs.
		InsecureSkipVerify: true, // NOLINT
		NextProtos:         []string{"h2"},
		MinVersion:         tls.VersionTLS12,
		ServerName:         opts.sniHost,
	}

	tlsConn := tls.Client(rawConn, tlsCfg)
	if err := tlsConn.HandshakeContext(dialCtx); err != nil {
		_ = rawConn.Close() // NOMUTANTS -- resource cleanup on failed handshake
		return nil, err
	}
	if tlsConn.ConnectionState().NegotiatedProtocol != "h2" {
		_ = tlsConn.Close() // NOMUTANTS -- resource cleanup on ALPN mismatch
		return nil, errNotNginxH2
	}
	_ = tlsConn.SetDeadline(time.Now().Add(opts.timeout)) // NOMUTANTS -- defensive TLS socket deadline
	return tlsConn, nil
}

func expandReadBuffer(conn net.Conn, size int) {
	// NOMUTANTS -- unwraps *tls.Conn solely for the kernel SO_RCVBUF throughput hint below
	if tlsConn, ok := conn.(*tls.Conn); ok {
		conn = tlsConn.NetConn()
	}
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetReadBuffer(size) // NOMUTANTS -- socket buffer expansion is a kernel throughput hint
	}
}

func (m *Module) dialWithCancel(ctx context.Context, opts dialOptions) (net.Conn, func(), error) {
	conn, err := m.dial(ctx, opts)
	if err != nil {
		return nil, nil, err
	}
	stopCancel := context.AfterFunc(ctx, func() {
		_ = conn.SetDeadline(time.Now()) // NOMUTANTS -- immediate socket wake-up on caller context cancellation
	})
	return conn, func() {
		stopCancel()
		_ = conn.Close()
	}, nil
}

type probeTarget struct {
	mode      transportMode
	scheme    string
	dialAddr  string
	authority string
	sniHost   string
}

func buildProbeTarget(mode transportMode, authorities []string, endpoint *npb.NetworkEndpoint, port uint32) (probeTarget, bool) {
	if len(authorities) == 0 {
		return probeTarget{}, false
	}
	primary := authorities[0]
	dialAddr := authorities[len(authorities)-1]
	if !isSafeAuthority(primary) || !isSafeAuthority(dialAddr) {
		return probeTarget{}, false
	}
	hostPart, _, err := net.SplitHostPort(primary)
	if err != nil {
		return probeTarget{}, false
	}

	scheme := "http"
	if mode == transportH2TLS {
		scheme = "https"
	}
	authority := primary
	if (mode == transportH2C && port == 80) || (mode == transportH2TLS && port == 443) {
		if strings.Contains(hostPart, ":") {
			authority = "[" + hostPart + "]"
		} else {
			authority = hostPart
		}
	}
	var sni string
	if endpoint.GetHostname().GetName() != "" && net.ParseIP(hostPart) == nil {
		sni = hostPart
	}
	return probeTarget{
		mode:      mode,
		scheme:    scheme,
		dialAddr:  dialAddr,
		authority: authority,
		sniHost:   sni,
	}, true
}

func isPrintableASCII(s string, maxLen int) bool {
	if s == "" || len(s) > maxLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= 0x20 || s[i] >= 0x7f {
			return false
		}
	}
	return true
}

func isSafeAuthority(s string) bool {
	return isPrintableASCII(s, 260)
}

// extractSafeLocalPath parses raw and returns its escaped path if it is an ASCII
// root-relative HTTP(S) path within 200 bytes. When authority is non-empty,
// absolute URLs must match authority's host.
func extractSafeLocalPath(raw, authority string) (string, bool) {
	if strings.HasPrefix(raw, "//") {
		return "", false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", false
	}
	if u.Scheme != "" && u.Scheme != "http" && u.Scheme != "https" {
		return "", false
	}
	if authority != "" && u.Host != "" {
		targetHost := strings.TrimPrefix(strings.TrimSuffix(authority, "]"), "[")
		if h, _, splitErr := net.SplitHostPort(authority); splitErr == nil {
			targetHost = h
		}
		if !strings.EqualFold(u.Hostname(), targetHost) {
			return "", false
		}
	}
	p := u.EscapedPath()
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || !isPrintableASCII(p, 200) {
		return "", false
	}
	return p, true
}

type probeMatch struct {
	mode                  transportMode
	scheme                string
	authority             string
	path                  string
	settingsPayloadLen    int
	maxStreams            uint32
	bodyLen               int
	burstStreams          int
	refusedStreams        int
	windowUpdateIncrement uint32
}

type discoveryResult struct {
	settingsPayloadLen int
	maxStreams         uint32
	bodyLen            int
	path               string
}

type burstAttemptParams struct {
	target              probeTarget
	discovery           discoveryResult
	effectiveMaxStreams int
	streamCount         int
}

func (m *Module) probeTarget(ctx context.Context, target probeTarget, crawledPaths []string) (*probeMatch, error) {
	disc, err := m.discoverNginxEndpoint(ctx, target, crawledPaths)
	if err != nil {
		return nil, err
	}
	if disc.bodyLen == 0 {
		log.DebugContextf(ctx, log.DebugLevelRequest, "Phase 1 discovery on %s found no deterministic static candidate", target.dialAddr) // NOMUTANTS -- diagnostic logging
		return nil, nil
	}
	log.DebugContextf(ctx, log.DebugLevelRequest, "Phase 1 selected path=%q body_len=%d max_streams=%d settings_len=%d",
		disc.path, disc.bodyLen, disc.maxStreams, disc.settingsPayloadLen) // NOMUTANTS -- diagnostic logging

	// Keep refused tail streams within [1, min(effectiveMaxStreams, 96)] and total
	// streams <= 940: >= 1 refused proves saturation, refused <= effectiveMaxStreams
	// keeps unpatched h2c->send_window + increment <= 0x7fffffff, and 96 / 940 stay
	// below NGINX's refused_streams and keepalive_requests close thresholds.
	effectiveMaxStreams := int(min(disc.maxStreams, maxEffectiveConcurrent))
	maxSafeRefused := min(effectiveMaxStreams, maxSafeRefusedCap)
	step := max(1, min(maxLadderStep, maxSafeRefused))
	halfWindow := max(1, maxSafeRefused/2)
	startN := effectiveMaxStreams + halfWindow

	var ladder []int
	for n := startN; n <= maxBurstStreams && len(ladder) < maxLadderAttempts; n += step {
		ladder = append(ladder, n)
	}

	targetedRetryDone := false
	for idx := 0; idx < len(ladder); idx++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		streamCount := ladder[idx]
		attempt, err := m.executeFlowControlAttempt(ctx, burstAttemptParams{
			target:              target,
			discovery:           disc,
			effectiveMaxStreams: effectiveMaxStreams,
			streamCount:         streamCount,
		})
		if err != nil {
			return nil, err
		}
		log.DebugContextf(ctx, log.DebugLevelRequest, "Phase 2 attempt n=%d refused=%d contiguous=%t goaway_fc=%t pings=(%t,%t,%t) pre_post_ping_bytes=%d",
			streamCount, attempt.refusedCount, attempt.isContiguousTail, attempt.sawFlowControlGoAway,
			attempt.gotPreUpdatePing, attempt.gotPostUpdatePing, attempt.gotLivenessPing, attempt.prePostPingDataBytes) // NOMUTANTS -- diagnostic logging

		if attempt.isContiguousTail && attempt.refusedCount >= 1 && attempt.refusedCount <= maxSafeRefused {
			// Liveness PING is only sent after post-update PING ACK, so gotLivenessPing implies gotPostUpdatePing.
			if attempt.gotPreUpdatePing && attempt.gotLivenessPing {
				maxPrePostPingData := uint64(streamCount-effectiveMaxStreams) * uint64(disc.bodyLen)
				if attempt.prePostPingDataBytes < maxPrePostPingData {
					return &probeMatch{
						mode:                  target.mode,
						scheme:                target.scheme,
						authority:             target.authority,
						path:                  disc.path,
						settingsPayloadLen:    disc.settingsPayloadLen,
						maxStreams:            disc.maxStreams,
						bodyLen:               disc.bodyLen,
						burstStreams:          streamCount,
						refusedStreams:        attempt.refusedCount,
						windowUpdateIncrement: attempt.windowUpdateIncrement,
					}, nil
				}
				// Flushed DATA before post-update PING ACK consumed >= (n-M)*bodyLen
				// (e.g., limit_req errors), so patched NGINX could accept the update;
				// step to a larger burst.
				continue
			}
			return nil, nil
		}

		if attempt.canRetryOvershoot && attempt.refusedCount > maxSafeRefused && !targetedRetryDone {
			targetedRetryDone = true
			retryN := max(effectiveMaxStreams, attempt.acceptedBeforeRefused) + halfWindow
			if retryN <= maxBurstStreams {
				ladder = slices.Insert(ladder, idx+1, retryN)
				continue
			}
		}

		if attempt.sawFlowControlGoAway || !(attempt.gotPreUpdatePing && attempt.gotPostUpdatePing) {
			return nil, nil
		}
	}

	return nil, nil
}

func (m *Module) discoverNginxEndpoint(ctx context.Context, target probeTarget, crawledPaths []string) (discoveryResult, error) {
	candidates := make([]string, 0, len(crawledPaths)+4)
	candidates = append(candidates, crawledPaths...)
	candidates = append(candidates, "/")
	fallback404 := "/" + randomHex(6)

	conn, cleanup, err := m.dialWithCancel(ctx, dialOptions{
		mode:     target.mode,
		dialAddr: target.dialAddr,
		sniHost:  target.sniHost,
		timeout:  m.timeout,
	})
	if err != nil {
		return discoveryResult{}, err
	}
	defer cleanup()

	var outBuf bytes.Buffer
	outBuf.WriteString(h2ClientPreface)
	framer := http2.NewFramer(&outBuf, conn)
	framer.SetMaxReadFrameSize(discoveryStreamWindow)

	if err := framer.WriteSettings(
		http2.Setting{ID: http2.SettingHeaderTableSize, Val: 4096},
		http2.Setting{ID: http2.SettingEnablePush, Val: 0},
		http2.Setting{ID: http2.SettingInitialWindowSize, Val: discoveryStreamWindow},
	); err != nil {
		return discoveryResult{}, err
	}
	if err := framer.WriteWindowUpdate(0, discoveryConnWinDelta); err != nil {
		return discoveryResult{}, err
	}
	greetNonce := randomNonce8()
	if err := framer.WritePing(false, greetNonce); err != nil {
		return discoveryResult{}, err
	}

	firstPath := candidates[0]
	var hpackBuf bytes.Buffer
	hpackEnc := hpack.NewEncoder(&hpackBuf)
	hdrBlock1 := encodeRequestHeaders(hpackEnc, &hpackBuf, target.scheme, target.authority, firstPath)
	if err := framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      1,
		BlockFragment: hdrBlock1,
		EndStream:     true,
		EndHeaders:    true,
	}); err != nil {
		return discoveryResult{}, err
	}
	if _, err := conn.Write(outBuf.Bytes()); err != nil {
		return discoveryResult{}, err
	}

	settingsLen, maxStreams, err := readNginxGreeting(framer)
	if err != nil {
		return discoveryResult{}, err
	}

	hpackDec := hpack.NewDecoder(4096, nil)
	hpackDec.SetMaxStringLength(maxHPACKStringLen)
	resp1, gotGreetPing, err := readDiscoveryStream(framer, hpackDec, 1, &greetNonce)
	if err != nil || !gotGreetPing || isExcludedNonNginxServer(resp1.headers) {
		return discoveryResult{}, errNotNginxH2
	}

	nextStreamID := uint32(3)
	sendDiscoveryGet := func(reqPath string) (streamDiscoveryResp, error) {
		outBuf.Reset()
		hdrBlock := encodeRequestHeaders(hpackEnc, &hpackBuf, target.scheme, target.authority, reqPath)
		sid := nextStreamID
		nextStreamID += 2
		if err := framer.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      sid,
			BlockFragment: hdrBlock,
			EndStream:     true,
			EndHeaders:    true,
		}); err != nil {
			return streamDiscoveryResp{}, err
		}
		if _, err := conn.Write(outBuf.Bytes()); err != nil {
			return streamDiscoveryResp{}, err
		}
		resp, _, err := readDiscoveryStream(framer, hpackDec, sid, nil)
		if err != nil {
			return streamDiscoveryResp{}, err
		}
		if isExcludedNonNginxServer(resp.headers) {
			return streamDiscoveryResp{}, errNotNginxH2
		}
		return resp, nil
	}

	verifyStableCandidate := func(reqPath string, firstLen int) (bool, error) {
		resp2, err := sendDiscoveryGet(reqPath)
		if err != nil {
			return false, err
		}
		return resp2.bodyLen == firstLen, nil
	}

	bestPath := ""
	bestLen := 0
	if resp1.bodyLen > 0 && resp1.bodyLen <= maxStaticBodyBytes {
		stable, err := verifyStableCandidate(firstPath, resp1.bodyLen)
		if errors.Is(err, errNotNginxH2) {
			return discoveryResult{}, errNotNginxH2
		}
		if stable {
			bestPath = firstPath
			bestLen = resp1.bodyLen
		}
	}

	if bestLen < preferredStaticBodyLen {
		for _, assetPath := range extractHTMLAssetPaths(resp1.sampleBody, target.authority, 2) {
			if !slices.Contains(candidates, assetPath) {
				candidates = append(candidates, assetPath)
			}
		}
		candidates = append(candidates, fallback404)

		for _, cand := range candidates[1:] {
			if bestLen >= preferredStaticBodyLen {
				break
			}
			r1, err := sendDiscoveryGet(cand)
			if errors.Is(err, errNotNginxH2) {
				return discoveryResult{}, errNotNginxH2
			}
			if errors.Is(err, errStreamReset) {
				continue
			}
			if err != nil {
				break
			}
			if r1.bodyLen <= bestLen || r1.bodyLen > maxStaticBodyBytes {
				continue
			}
			stable, err := verifyStableCandidate(cand, r1.bodyLen)
			if errors.Is(err, errNotNginxH2) {
				return discoveryResult{}, errNotNginxH2
			}
			if stable {
				bestPath = cand
				bestLen = r1.bodyLen
			}
		}
	}

	return discoveryResult{
		settingsPayloadLen: settingsLen,
		maxStreams:         maxStreams,
		bodyLen:            bestLen,
		path:               bestPath,
	}, nil
}

func readNginxGreeting(framer *http2.Framer) (int, uint32, error) {
	frame1, err := framer.ReadFrame()
	// NOMUTANTS -- defensive err check; ReadFrame returns nil frame on error so parseNginxGreetingSettings returns the same errNotNginxH2
	if err != nil {
		return 0, 0, errNotNginxH2
	}
	settingsLen, maxStreams, ok := parseNginxGreetingSettings(frame1)
	if !ok {
		return 0, 0, errNotNginxH2
	}

	frame2, err := framer.ReadFrame()
	// NOMUTANTS -- defensive err check; ReadFrame returns nil frame on error so the WindowUpdateFrame type assertion returns the same errNotNginxH2
	if err != nil {
		return 0, 0, errNotNginxH2
	}
	wu2, ok := frame2.(*http2.WindowUpdateFrame)
	if !ok || wu2.Header().StreamID != 0 || wu2.Increment != nginxConnWindowDelta {
		return 0, 0, errNotNginxH2
	}
	return settingsLen, maxStreams, nil
}

func parseNginxGreetingSettings(frame http2.Frame) (int, uint32, bool) {
	sf, ok := frame.(*http2.SettingsFrame)
	if !ok {
		return 0, 0, false
	}
	n := sf.NumSettings()
	if n != 3 && n != 4 {
		return 0, 0, false
	}
	s0, s1, s2 := sf.Setting(0), sf.Setting(1), sf.Setting(2)
	if s0.ID != http2.SettingMaxConcurrentStreams || s0.Val == 0 {
		return 0, 0, false
	}
	if s1.ID != http2.SettingInitialWindowSize {
		return 0, 0, false
	}
	if s2.ID != http2.SettingMaxFrameSize || s2.Val != nginxMaxFrameSize {
		return 0, 0, false
	}
	if n == 4 {
		s3 := sf.Setting(3)
		if s3.ID != settingNoPrioritiesID || s3.Val != 1 {
			return 0, 0, false
		}
	}
	return int(sf.Header().Length), s0.Val, true
}

type streamDiscoveryResp struct {
	headers    []hpack.HeaderField
	bodyLen    int
	sampleBody []byte
}

func readDiscoveryStream(framer *http2.Framer, dec *hpack.Decoder, targetSID uint32, wantPing *[8]byte) (streamDiscoveryResp, bool, error) {
	var resp streamDiscoveryResp
	gotEnd := false
	gotPing := wantPing == nil

	for range 512 {
		if gotEnd && gotPing {
			return resp, true, nil
		}
		f, err := framer.ReadFrame()
		if err != nil {
			return resp, gotPing, err
		}
		switch fr := f.(type) {
		case *http2.PingFrame:
			if fr.IsAck() && wantPing != nil && fr.Data == *wantPing {
				gotPing = true
			}
		case *http2.HeadersFrame:
			hdrs, endStream, err := decodeHeadersWithContinuations(framer, dec, fr)
			if err != nil {
				return resp, gotPing, err
			}
			if fr.Header().StreamID == targetSID {
				resp.headers = append(resp.headers, hdrs...)
				if endStream {
					gotEnd = true
				}
			}
		case *http2.DataFrame:
			if fr.Header().StreamID == targetSID {
				data := fr.Data()
				resp.bodyLen += len(data)
				if len(resp.sampleBody) < preferredStaticBodyLen {
					take := min(len(data), preferredStaticBodyLen-len(resp.sampleBody))
					resp.sampleBody = append(resp.sampleBody, data[:take]...)
				}
				if resp.bodyLen > maxStaticBodyBytes || fr.StreamEnded() {
					gotEnd = true
				}
			}
		case *http2.RSTStreamFrame:
			if fr.Header().StreamID == targetSID {
				return resp, gotPing, errStreamReset
			}
		case *http2.GoAwayFrame, *http2.PushPromiseFrame:
			return resp, gotPing, errNotNginxH2
		}
	}
	return resp, gotPing, errNotNginxH2
}

func decodeHeadersWithContinuations(framer *http2.Framer, dec *hpack.Decoder, hf *http2.HeadersFrame) ([]hpack.HeaderField, bool, error) {
	firstFrag := hf.HeaderBlockFragment()
	if len(firstFrag) > maxHeaderBlockBytes {
		return nil, false, errNotNginxH2
	}
	var rawBlock bytes.Buffer
	rawBlock.Write(firstFrag)
	endStream := hf.StreamEnded()
	endHeaders := hf.HeadersEnded()

	for range maxContinuationFrames {
		if endHeaders {
			break
		}
		nextFrame, err := framer.ReadFrame()
		if err != nil {
			return nil, false, err
		}
		cf, ok := nextFrame.(*http2.ContinuationFrame)
		if !ok || cf.Header().StreamID != hf.Header().StreamID || rawBlock.Len()+len(cf.HeaderBlockFragment()) > maxHeaderBlockBytes {
			return nil, false, errNotNginxH2
		}
		rawBlock.Write(cf.HeaderBlockFragment())
		endHeaders = cf.HeadersEnded()
	}
	if !endHeaders {
		return nil, false, errNotNginxH2
	}

	var (
		fields      []hpack.HeaderField
		limitErr    error
		remainBytes = maxHeaderBlockBytes
	)
	dec.SetEmitFunc(func(f hpack.HeaderField) {
		if len(fields) >= maxHPACKFields || int(f.Size()) > remainBytes {
			limitErr = errNotNginxH2
			return
		}
		remainBytes -= int(f.Size())
		fields = append(fields, f)
	})
	defer dec.SetEmitFunc(func(hpack.HeaderField) {})
	if _, err := dec.Write(rawBlock.Bytes()); err != nil {
		return nil, false, err
	}
	if limitErr != nil {
		return nil, false, limitErr
	}
	if err := dec.Close(); err != nil {
		return nil, false, err
	}
	return fields, endStream, nil
}

func isExcludedNonNginxServer(headers []hpack.HeaderField) bool {
	for _, h := range headers {
		name := strings.ToLower(h.Name)
		val := strings.ToLower(strings.TrimSpace(h.Value))
		switch name {
		case "via":
			if val != "" {
				return true
			}
		case "server":
			if strings.Contains(val, "awselb") {
				return true
			}
			if val != "" && !strings.Contains(val, "nginx") && !strings.Contains(val, "openresty") {
				for _, nonNginx := range nonNginxServers {
					if strings.Contains(val, nonNginx) {
						return true
					}
				}
			}
		case "set-cookie":
			if strings.HasPrefix(val, "awsalb=") || strings.HasPrefix(val, "awsalbcors=") || strings.HasPrefix(val, "awsalbtg=") || strings.HasPrefix(val, "awsalbtgcors=") {
				return true
			}
		}
	}
	return false
}

func extractHTMLAssetPaths(sample []byte, authority string, limit int) []string {
	var out []string
	seen := map[string]bool{"/": true}
	z := html.NewTokenizer(bytes.NewReader(sample))
	for len(out) < limit {
		if z.Next() == html.ErrorToken {
			break
		}
		for _, attr := range z.Token().Attr {
			if attr.Key != "href" && attr.Key != "src" {
				continue
			}
			if cand, ok := extractSafeLocalPath(attr.Val, authority); ok && !seen[cand] && hasStaticAssetExtension(cand) {
				seen[cand] = true
				out = append(out, cand)
				if len(out) >= limit {
					break
				}
			}
		}
	}
	return out
}

type flowControlAttempt struct {
	refusedCount          int
	acceptedBeforeRefused int
	isContiguousTail      bool
	canRetryOvershoot     bool
	sawFlowControlGoAway  bool
	gotPreUpdatePing      bool
	gotPostUpdatePing     bool
	gotLivenessPing       bool
	prePostPingDataBytes  uint64
	windowUpdateIncrement uint32
}

func (m *Module) executeFlowControlAttempt(ctx context.Context, params burstAttemptParams) (flowControlAttempt, error) {
	var res flowControlAttempt
	conn, cleanup, err := m.dialWithCancel(ctx, dialOptions{
		mode:         params.target.mode,
		dialAddr:     params.target.dialAddr,
		sniHost:      params.target.sniHost,
		timeout:      m.timeout,
		smallRecvBuf: true,
	})
	if err != nil {
		return res, ctx.Err()
	}
	defer cleanup()

	// With pre-SYN SO_RCVBUF clamped to 2304 bytes so accepted DATA frames stay
	// queued in h2c->last_out:
	// - Unpatched NGINX deducts A = streamCount - refusedCount streams from
	//   send_window, so send_window + increment <= 0x7fffffff when refused <= M.
	// - Patched NGINX (commit e27f5fa84fe6) includes queued last_out bytes,
	//   so send_window + send_queued + increment = 0x7fffffff + refused*bodyLen
	//   exceeds 0x7fffffff for all refused >= 1 (GOAWAY FLOW_CONTROL_ERROR).
	bodyLen := params.discovery.bodyLen
	initStreamWindow := uint32(max(65535, bodyLen))
	targetConnWindow := uint64(params.streamCount) * uint64(bodyLen)
	initConnWindow := max(uint64(65535), targetConnWindow)
	windowUpdateIncrement := uint32(nginxMaxWindow - initConnWindow + uint64(params.streamCount-params.effectiveMaxStreams)*uint64(bodyLen))
	res.windowUpdateIncrement = windowUpdateIncrement

	var outBuf bytes.Buffer
	outBuf.WriteString(h2ClientPreface)
	framer := http2.NewFramer(&outBuf, conn)
	framer.SetMaxReadFrameSize(maxStaticBodyBytes)

	if err := framer.WriteSettings(
		http2.Setting{ID: http2.SettingHeaderTableSize, Val: 4096},
		http2.Setting{ID: http2.SettingEnablePush, Val: 0},
		http2.Setting{ID: http2.SettingInitialWindowSize, Val: initStreamWindow},
	); err != nil {
		return res, nil
	}
	if targetConnWindow > 65535 {
		if err := framer.WriteWindowUpdate(0, uint32(targetConnWindow-65535)); err != nil {
			return res, nil
		}
	}
	if _, err := conn.Write(outBuf.Bytes()); err != nil {
		return res, nil
	}
	if err := sleepWithContext(ctx, m.interBatchDelay/2); err != nil {
		return res, err
	}

	preUpdateNonce, postUpdateNonce, livenessNonce := randomNonce8(), randomNonce8(), randomNonce8()
	if err := m.sendBurst(ctx, conn, framer, &outBuf, params, windowUpdateIncrement, preUpdateNonce, postUpdateNonce); err != nil {
		return res, err
	}
	if err := sleepWithContext(ctx, m.preDrainDelay); err != nil {
		return res, err
	}
	expandReadBuffer(conn, largeRecvBufBytes)

	return drainAttempt(ctx, conn, framer, &outBuf, res, params.streamCount, preUpdateNonce, postUpdateNonce, livenessNonce)
}

func (m *Module) sendBurst(
	ctx context.Context,
	conn net.Conn,
	framer *http2.Framer,
	outBuf *bytes.Buffer,
	params burstAttemptParams,
	windowUpdateIncrement uint32,
	preUpdateNonce, postUpdateNonce [8]byte,
) error {
	firstHeaders, compactHeaders := buildBurstHeaderBlocks(params.target.scheme, params.target.authority, params.discovery.path)

	for sent := 0; sent < params.streamCount; {
		batch := min(maxBatchStreams, params.streamCount-sent)
		outBuf.Reset()
		for j := range batch {
			sid := uint32(1 + 2*(sent+j))
			block := compactHeaders
			if sid == 1 {
				block = firstHeaders
			}
			if err := framer.WriteHeaders(http2.HeadersFrameParam{
				StreamID:      sid,
				BlockFragment: block,
				EndStream:     true,
				EndHeaders:    true,
			}); err != nil {
				return nil
			}
		}
		sent += batch
		if sent == params.streamCount {
			if err := writeProbeVerificationFrames(framer, preUpdateNonce, postUpdateNonce, windowUpdateIncrement); err != nil {
				return nil
			}
		}
		if _, err := conn.Write(outBuf.Bytes()); err != nil {
			return nil
		}
		if sent < params.streamCount {
			if err := sleepWithContext(ctx, m.interBatchDelay); err != nil {
				return err
			}
		}
	}
	return nil
}

func writeProbeVerificationFrames(framer *http2.Framer, preUpdateNonce, postUpdateNonce [8]byte, windowUpdateIncrement uint32) error {
	if err := framer.WritePing(false, preUpdateNonce); err != nil {
		return err
	}
	if err := framer.WriteWindowUpdate(0, windowUpdateIncrement); err != nil {
		return err
	}
	return framer.WritePing(false, postUpdateNonce)
}

func drainAttempt(
	ctx context.Context,
	conn net.Conn,
	framer *http2.Framer,
	outBuf *bytes.Buffer,
	res flowControlAttempt,
	streamCount int,
	preUpdateNonce, postUpdateNonce, livenessNonce [8]byte,
) (flowControlAttempt, error) {
	var refusedSIDs []uint32
	for range maxFramesPerDrain {
		f, err := framer.ReadFrame()
		if err != nil {
			break
		}
		switch fr := f.(type) {
		case *http2.DataFrame:
			if !res.gotPostUpdatePing {
				res.prePostPingDataBytes += uint64(fr.Header().Length)
			}
		case *http2.RSTStreamFrame:
			if fr.ErrCode == http2.ErrCodeRefusedStream {
				refusedSIDs = append(refusedSIDs, fr.Header().StreamID)
			}
		case *http2.GoAwayFrame:
			if fr.ErrCode == http2.ErrCodeFlowControl {
				res.sawFlowControlGoAway = true
			}
			return finalizeAttempt(res, refusedSIDs, streamCount), nil
		case *http2.PingFrame:
			if !fr.IsAck() {
				continue
			}
			switch fr.Data {
			case preUpdateNonce:
				res.gotPreUpdatePing = true
			case postUpdateNonce:
				if !res.gotPostUpdatePing {
					res.gotPostUpdatePing = true
					outBuf.Reset()
					if err := framer.WritePing(false, livenessNonce); err != nil {
						return finalizeAttempt(res, refusedSIDs, streamCount), ctx.Err()
					}
					if _, err := conn.Write(outBuf.Bytes()); err != nil {
						return finalizeAttempt(res, refusedSIDs, streamCount), ctx.Err()
					}
				}
			case livenessNonce:
				res.gotLivenessPing = true
				return finalizeAttempt(res, refusedSIDs, streamCount), ctx.Err()
			}
		}
	}
	return finalizeAttempt(res, refusedSIDs, streamCount), ctx.Err()
}

func finalizeAttempt(res flowControlAttempt, refusedSIDs []uint32, streamCount int) flowControlAttempt {
	r := len(refusedSIDs)
	res.refusedCount = r
	if r == 0 {
		return res
	}
	slices.Sort(refusedSIDs)
	firstSID := refusedSIDs[0]
	maxSID := uint32(2*streamCount - 1)
	if firstSID%2 == 0 || refusedSIDs[r-1] > maxSID {
		return res
	}
	for k, sid := range refusedSIDs {
		if sid != firstSID+uint32(2*k) {
			return res
		}
	}
	res.acceptedBeforeRefused = int((firstSID - 1) / 2)
	res.canRetryOvershoot = true
	res.isContiguousTail = refusedSIDs[r-1] == maxSID
	return res
}

func encodeRequestHeaders(enc *hpack.Encoder, buf *bytes.Buffer, scheme, authority, reqPath string) []byte {
	buf.Reset()
	_ = enc.WriteField(hpack.HeaderField{Name: ":method", Value: "GET"})
	_ = enc.WriteField(hpack.HeaderField{Name: ":scheme", Value: scheme})
	_ = enc.WriteField(hpack.HeaderField{Name: ":authority", Value: authority})
	_ = enc.WriteField(hpack.HeaderField{Name: ":path", Value: reqPath})
	_ = enc.WriteField(hpack.HeaderField{Name: "accept-encoding", Value: "identity"})
	_ = enc.WriteField(hpack.HeaderField{Name: "user-agent", Value: scannerUA})
	return bytes.Clone(buf.Bytes())
}

// buildBurstHeaderBlocks encodes Stream 1 (populating the HPACK dynamic table)
// and a reusable purely indexed 6-byte block for all subsequent burst streams.
func buildBurstHeaderBlocks(scheme, authority, reqPath string) (first, subsequent []byte) {
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	first = encodeRequestHeaders(enc, &buf, scheme, authority, reqPath)
	subsequent = encodeRequestHeaders(enc, &buf, scheme, authority, reqPath)
	return first, subsequent
}

func sleepWithContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func randomNonce8() [8]byte {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return b
}

func randomHex(numBytes int) string {
	b := make([]byte, numBytes)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
