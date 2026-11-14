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

// Package cve2026119618 detects the Apache HTTP Server mod_http2 assign_headers
// race condition and heap memory corruption RCE vulnerability (CVE-2026-119618).
//
// Safety invariant: Every probe is executed sequentially on a single stream at
// a time with strictly fewer than 10 headers (6 pseudo+regular headers on
// Stream 1, 7 on Stream 3, and 6 on Stream 5), staying well within mod_http2's
// pre-allocated 10-element apr_table_t capacity on the c1 connection pool so
// zero unsynchronized pool reallocations or concurrent mutations can occur.
package cve2026119618

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/log"
	"github.com/google/goonami-scanner/core/module"
	"github.com/google/goonami-scanner/core/net/netservice"
	"golang.org/x/net/http2/hpack"

	dpb "github.com/google/tsunami-security-scanner/proto/go/detection_go_proto"
	npb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
	rpb "github.com/google/tsunami-security-scanner/proto/go/reconnaissance_go_proto"
	vpb "github.com/google/tsunami-security-scanner/proto/go/vulnerability_go_proto"
	tspb "google.golang.org/protobuf/types/known/timestamppb"
)

const (
	moduleName = "dt/cve2026119618"

	vulnReportPublisher = "GOOGLE"
	vulnReportID        = "CVE-2026-119618"
	vulnReportTitle     = "Apache HTTP Server mod_http2 assign_headers() Race Condition RCE (CVE-2026-119618)"
	vulnDescription     = "Apache HTTP Server versions 2.4.55 through 2.4.70 (and standalone mod_h2 versions 2.0.8 through 2.0.42) with HTTP/2 (h2 or h2c) enabled contain a race condition in mod_http2's assign_headers() function (modules/http2/h2_request.c). For body-less HTTP/2 requests carrying a Content-Type header without Content-Length, assign_headers() writes a synthesized 'Content-Length: 0' header into the shared connection-pool table (req->headers) after cloning the request-private table (r->headers_in), enabling concurrent worker threads to corrupt the heap allocator. Exploitability has been proven: Apache's crash-tolerant multi-worker architecture allows unlimited attempts to probe and align heap state and pivot RIP to ROP gadgets in libc or httpd to achieve unauthenticated Remote Code Execution."
	vulnRecommendation  = "Upgrade Apache HTTP Server to version 2.4.71 or later (or apply your Linux distribution's security update backporting commit 824beab9b9424d6cfb29595248fdbf6c3dddeab1). If immediate patching is not possible, disable HTTP/2 by removing 'h2' and 'h2c' from all Protocols directives."

	defaultTimeout      = 5 * time.Second
	defaultHTTPPort     = 80
	defaultHTTPSPort    = 443
	maxCrawledFallbacks = 2

	probeHeaderWireName  = "x-tsunami-probe"
	probeHeaderCamelName = "X-Tsunami-Probe"
	probeContentTypeVal  = "text/plain"
	traceBodyPayload     = "x"
)

var (
	// extraHTTPServiceNames covers Nmap HTTP/HTTPS service labels (matching
	// Tsunami's NetworkServiceUtils.isWebService plus HTTPS alt/SSL variants)
	// when HTTP/1.1 fingerprinting did not populate supported_http_methods.
	extraHTTPServiceNames = map[string]bool{
		"http":                true,
		"http-alt":            true,
		"http-proxy":          true,
		"https":               true,
		"https-alt":           true,
		"radan-http":          true,
		"ssl/http":            true,
		"ssl/https":           true,
		"ssl/https-alt":       true,
		"ssl/http-proxy":      true,
		"ssl/tungsten-https":  true,
		"ssl/wso2esb-console": true,
		"http over ssl":       true,
	}

	// portGatedServiceNames are probed only when listening on standardWebPorts
	// so banner-hidden HTTP/2 listeners are covered without scanning SSH/DB ports.
	portGatedServiceNames = map[string]bool{
		"":            true,
		"unknown":     true,
		"ssl/unknown": true,
		"tcpwrapped":  true,
	}

	standardWebPorts = map[uint32]bool{
		80:   true,
		443:  true,
		8008: true,
		8080: true,
		8088: true,
		8443: true,
	}
)

// Module implements the module.VulnDetector interface for CVE-2026-119618.
type Module struct {
	*module.BaseModule
	timeout time.Duration
	dial    dialFunc
	nowFn   func() time.Time
	nonceFn func() string
}

func init() {
	module.RegisterDetector(moduleName, New)
}

// New returns a new instance of the CVE-2026-119618 detector module.
func New(ctx context.Context, cfg *config.Config) (module.VulnDetector, error) {
	timeout := defaultTimeout
	if cfg != nil {
		if secs := cfg.GlobalConfig().GetPerformance().GetTimeoutPerRequestSeconds(); secs > 0 {
			timeout = time.Duration(secs) * time.Second
		}
	}
	return &Module{
		BaseModule: module.NewBaseModule(moduleName),
		timeout:    timeout,
		dial:       defaultDial,
		nowFn:      time.Now,
		nonceFn:    randomHexNonce,
	}, nil
}

// Advisories returns a fresh vulnerability advisory list reported by this module.
func (m *Module) Advisories() []*vpb.Vulnerability {
	return []*vpb.Vulnerability{baseVulnerability()}
}

func baseVulnerability() *vpb.Vulnerability {
	return vpb.Vulnerability_builder{
		MainId: vpb.VulnerabilityId_builder{
			Publisher: vulnReportPublisher,
			Value:     vulnReportID,
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
	}.Build()
}

type detectionEvidence struct {
	mode        transportMode
	authority   string
	path        string
	stream5Info string
}

// Detect probes the target network service for unpatched Apache mod_http2
// assign_headers() behavior (CVE-2026-119618) using a non-destructive 3-stream
// sequential HTTP/2 causal-ablation check.
func (m *Module) Detect(ctx context.Context, service *nspb.NetworkService) (*dpb.DetectionReportList, error) {
	ctx = log.ContextForModuleAndService(ctx, m.Name(), service) // NOMUTANTS -- diagnostic logging context
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if !isSupportedService(service) {
		return nil, nil
	}

	transports := preferredTransports(service)
	defaultPort := uint32(defaultHTTPPort)
	if transports[0] == transportH2TLS {
		defaultPort = defaultHTTPSPort
	}

	target, ok := resolveEndpointTarget(service.GetNetworkEndpoint(), defaultPort)
	if !ok {
		return nil, nil
	}

	candidatePaths := extractCandidatePaths(service, maxCrawledFallbacks)

	for _, mode := range transports {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		ev, err := m.probeTransport(ctx, mode, target, candidatePaths)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil, err
			}
			log.DebugContextf(ctx, log.DebugLevelService, "HTTP/2 %s probe on %s did not match: %v", mode, target.dialAddr, err) // NOMUTANTS -- diagnostic logging
			continue
		}
		if ev != nil {
			return m.buildDetectionReport(service, ev), nil
		}
	}

	return nil, nil
}

func isSupportedService(service *nspb.NetworkService) bool {
	if service == nil {
		return false
	}
	tp := service.GetTransportProtocol()
	if tp != npb.TransportProtocol_TRANSPORT_PROTOCOL_UNSPECIFIED && tp != npb.TransportProtocol_TCP {
		return false
	}
	if netservice.IsWebService(service) {
		return true
	}
	name := strings.ToLower(strings.TrimSpace(service.GetServiceName()))
	if extraHTTPServiceNames[name] {
		return true
	}
	if portGatedServiceNames[name] {
		return standardWebPorts[service.GetNetworkEndpoint().GetPort().GetPortNumber()]
	}
	return false
}

func preferredTransports(service *nspb.NetworkService) []transportMode {
	name := strings.ToLower(strings.TrimSpace(service.GetServiceName()))
	port := service.GetNetworkEndpoint().GetPort().GetPortNumber()
	tlsFirst := len(service.GetSupportedSslVersions()) > 0 ||
		strings.Contains(name, "https") ||
		strings.Contains(name, "ssl") ||
		port == 443 ||
		port == 8443
	if tlsFirst {
		return []transportMode{transportH2TLS, transportH2C}
	}
	return []transportMode{transportH2C, transportH2TLS}
}

func (m *Module) probeTransport(ctx context.Context, mode transportMode, target endpointTarget, candidatePaths []string) (*detectionEvidence, error) {
	session, err := openH2ProbeSession(ctx, m.dial, mode, target, m.timeout)
	if err != nil {
		return nil, err
	}
	defer session.close()

	scheme := "http"
	if mode == transportH2TLS {
		scheme = "https"
	}
	authority := target.authorityForMode(mode)

	for _, reqPath := range candidatePaths {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		ev, stopPaths, err := m.probeCandidatePath(ctx, session, mode, scheme, authority, reqPath)
		if err != nil {
			return nil, err
		}
		if ev != nil {
			return ev, nil
		}
		if stopPaths {
			return nil, nil
		}
	}

	return nil, nil
}

func (m *Module) probeCandidatePath(ctx context.Context, session *h2ProbeSession, mode transportMode, scheme, authority, reqPath string) (*detectionEvidence, bool, error) {
	// Stream 1 (Differential assign_headers() Probe):
	// Body-less (END_STREAM) TRACE with lowercase content-type and random canary
	// header, omitting content-length (6 total headers < 10 APR table slots).
	nonce1 := m.nonceFn()
	resp1, err := session.roundTrip(ctx, traceHeaders(scheme, authority, reqPath, nonce1, probeContentTypeVal, ""), nil)
	if err != nil {
		return nil, true, err
	}
	// TraceEnable Off is server-wide in Apache core; abort immediately without
	// probing fallback crawled paths.
	if resp1.status == "405" || resp1.status == "501" {
		return nil, true, nil
	}
	if resp1.status != "200" {
		return nil, false, nil
	}
	if !isMessageHTTPContentType(resp1.contentType) {
		return nil, true, nil
	}
	echo1, ok := parseTraceEcho(resp1.body)
	if !ok || !matchesApacheH2TraceBase(echo1, reqPath, authority, nonce1) ||
		!echo1.hasExactCaseHeader("Content-Type", probeContentTypeVal) ||
		echo1.hasHeaderIgnoreCase("Content-Length") {
		return nil, true, nil
	}

	// Stream 3 (Explicit Content-Length: 0 Positive Control):
	// Confirms r->headers_in echoes Content-Length: 0 when explicitly supplied,
	// ruling out mod_headers "RequestHeader unset Content-Length" on patched servers.
	nonce2 := m.nonceFn()
	resp2, err := session.roundTrip(ctx, traceHeaders(scheme, authority, reqPath, nonce2, probeContentTypeVal, "0"), nil)
	if err != nil {
		return nil, true, err
	}
	if resp2.status != "200" || !isMessageHTTPContentType(resp2.contentType) {
		return nil, true, nil
	}
	echo2, ok := parseTraceEcho(resp2.body)
	if !ok || !matchesApacheH2TraceBase(echo2, reqPath, authority, nonce2) ||
		!echo2.hasExactCaseHeader("Content-Length", "0") {
		return nil, true, nil
	}

	// Stream 5 (Apache ap_send_http_trace 1-Byte Body Control):
	// Under default TraceEnable on, Apache rejects TRACE bodies with 413; under
	// TraceEnable extended, Apache returns 200 message/http with Content-Length: 1
	// and echoes the 1-byte body after the blank header terminator.
	nonce3 := m.nonceFn()
	resp3, err := session.roundTrip(ctx, traceHeaders(scheme, authority, reqPath, nonce3, "", "1"), []byte(traceBodyPayload))
	if err != nil {
		return nil, true, err
	}
	stream5Summary, ok := verifyStream5BodyControl(resp3, reqPath, authority, nonce3)
	if !ok {
		return nil, true, nil
	}

	return &detectionEvidence{
		mode:        mode,
		authority:   authority,
		path:        reqPath,
		stream5Info: stream5Summary,
	}, true, nil
}

func traceHeaders(scheme, authority, reqPath, nonce, contentType, contentLength string) []hpack.HeaderField {
	hdrs := make([]hpack.HeaderField, 0, 7)
	hdrs = append(hdrs,
		hpack.HeaderField{Name: ":method", Value: "TRACE"},
		hpack.HeaderField{Name: ":scheme", Value: scheme},
		hpack.HeaderField{Name: ":authority", Value: authority},
		hpack.HeaderField{Name: ":path", Value: reqPath},
	)
	if contentType != "" {
		hdrs = append(hdrs, hpack.HeaderField{Name: "content-type", Value: contentType})
	}
	if contentLength != "" {
		hdrs = append(hdrs, hpack.HeaderField{Name: "content-length", Value: contentLength})
	}
	hdrs = append(hdrs, hpack.HeaderField{Name: probeHeaderWireName, Value: nonce})
	return hdrs
}

func matchesApacheH2TraceBase(echo parsedTraceEcho, reqPath, authority, nonce string) bool {
	expectedReqLine := "TRACE " + reqPath + " HTTP/2.0"
	if echo.requestLine != expectedReqLine {
		return false
	}
	if !echo.hasExactCaseHeader("Host", authority) {
		return false
	}
	return echo.hasExactCaseHeader(probeHeaderCamelName, nonce)
}

func verifyStream5BodyControl(resp h2Response, reqPath, authority, nonce string) (string, bool) {
	if resp.status == "413" {
		return "HTTP 413 (TraceEnable on)", true
	}
	if resp.status != "200" || !isMessageHTTPContentType(resp.contentType) {
		return "", false
	}
	echo, ok := parseTraceEcho(resp.body)
	if !ok || !matchesApacheH2TraceBase(echo, reqPath, authority, nonce) {
		return "", false
	}
	if !echo.hasExactCaseHeader("Content-Length", "1") {
		return "", false
	}
	if !bytes.Equal(echo.body, []byte(traceBodyPayload)) {
		return "", false
	}
	return "HTTP 200 echoed 1-byte body (TraceEnable extended)", true
}

func (m *Module) buildDetectionReport(service *nspb.NetworkService, ev *detectionEvidence) *dpb.DetectionReportList {
	scheme := "http"
	if ev.mode == transportH2TLS {
		scheme = "https"
	}
	detailText := fmt.Sprintf(
		"Verified unpatched Apache mod_http2 assign_headers() over HTTP/2 (%s) at %s://%s%s: "+
			"Stream 1 omitted synthesized 'Content-Length: 0' in r->headers_in, Stream 3 confirmed explicit 'Content-Length: 0' preservation, and Stream 5 confirmed ap_send_http_trace body handling (%s).",
		ev.mode, scheme, ev.authority, ev.path, ev.stream5Info,
	)

	vuln := baseVulnerability()
	vuln.SetAdditionalDetails([]*vpb.AdditionalDetail{
		vpb.AdditionalDetail_builder{
			Description: "HTTP/2 assign_headers() causal-ablation verification evidence.",
			TextData: vpb.TextData_builder{
				Text: detailText,
			}.Build(),
		}.Build(),
	})

	return dpb.DetectionReportList_builder{
		DetectionReports: []*dpb.DetectionReport{
			dpb.DetectionReport_builder{
				TargetInfo: rpb.TargetInfo_builder{
					NetworkEndpoints: []*npb.NetworkEndpoint{service.GetNetworkEndpoint()},
				}.Build(),
				NetworkService:     service,
				DetectionTimestamp: tspb.New(m.nowFn()),
				DetectionStatus:    dpb.DetectionStatus_VULNERABILITY_VERIFIED,
				Vulnerability:      vuln,
			}.Build(),
		},
	}.Build()
}

func randomHexNonce() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil { // NOMUTANTS -- OS CSPRNG failure fallback
		return fmt.Sprintf("%016x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}
