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
	"net"
	"net/url"
	"strconv"
	"strings"

	npb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
)

type headerPair struct {
	name  string
	value string
}

// parsedTraceEcho holds the raw request line, uncanonicalized header fields,
// and echoed request body parsed from an HTTP/2 TRACE message/http payload.
//
// Standard MIME parsers (such as net/textproto.ReadMIMEHeader) canonicalize
// header names to Title-Case, which would mask non-Apache HTTP/2 servers that
// echo lowercase HPACK header names instead of executing Apache mod_http2's
// h2_util_camel_case_header() transformation.
type parsedTraceEcho struct {
	requestLine string
	headers     []headerPair
	body        []byte
}

func parseTraceEcho(payload []byte) (parsedTraceEcho, bool) {
	sepIdx := bytes.Index(payload, []byte("\r\n\r\n"))
	sepLen := 4
	lineSep := "\r\n"
	if sepIdx < 0 {
		sepIdx = bytes.Index(payload, []byte("\n\n"))
		sepLen = 2
		lineSep = "\n"
	}
	if sepIdx < 0 {
		return parsedTraceEcho{}, false
	}

	headSection := string(payload[:sepIdx])
	bodyBytes := append([]byte(nil), payload[sepIdx+sepLen:]...)

	lines := strings.Split(headSection, lineSep)
	if len(lines) == 0 {
		return parsedTraceEcho{}, false
	}

	reqLine := strings.TrimSuffix(lines[0], "\r")
	if reqLine == "" {
		return parsedTraceEcho{}, false
	}

	headers := make([]headerPair, 0, len(lines)-1)
	for _, rawLine := range lines[1:] {
		line := strings.TrimSuffix(rawLine, "\r")
		if line == "" {
			continue
		}
		colon := strings.IndexByte(line, ':')
		if colon <= 0 {
			return parsedTraceEcho{}, false
		}
		name := line[:colon]
		val := strings.TrimSpace(line[colon+1:])
		headers = append(headers, headerPair{name: name, value: val})
	}

	return parsedTraceEcho{
		requestLine: reqLine,
		headers:     headers,
		body:        bodyBytes,
	}, true
}

func (p parsedTraceEcho) hasExactCaseHeader(exactName, expectedValue string) bool {
	for _, h := range p.headers {
		if h.name == exactName && h.value == expectedValue {
			return true
		}
	}
	return false
}

func (p parsedTraceEcho) hasHeaderIgnoreCase(name string) bool {
	for _, h := range p.headers {
		if strings.EqualFold(h.name, name) {
			return true
		}
	}
	return false
}

func isMessageHTTPContentType(raw string) bool {
	mediaType := raw
	if semi := strings.IndexByte(mediaType, ';'); semi >= 0 {
		mediaType = mediaType[:semi]
	}
	return strings.EqualFold(strings.TrimSpace(mediaType), "message/http")
}

type endpointTarget struct {
	dialAddr  string
	authHost  string
	authority string
	sniHost   string
	port      uint32
}

func (t endpointTarget) authorityForMode(mode transportMode) string {
	isDefaultPort := (mode == transportH2C && t.port == defaultHTTPPort) || (mode == transportH2TLS && t.port == defaultHTTPSPort)
	if isDefaultPort {
		if strings.Contains(t.authHost, ":") {
			return "[" + t.authHost + "]"
		}
		return t.authHost
	}
	return t.authority
}

func resolveEndpointTarget(ep *npb.NetworkEndpoint, defaultPort uint32) (endpointTarget, bool) {
	if ep == nil {
		return endpointTarget{}, false
	}
	port := ep.GetPort().GetPortNumber()
	if port == 0 {
		port = defaultPort
	}
	portStr := strconv.FormatUint(uint64(port), 10)

	hostname := normalizeEndpointHost(ep.GetHostname().GetName())
	ipAddr := stripHostBrackets(strings.TrimSpace(ep.GetIpAddress().GetAddress()))
	if hostname == "" && ipAddr == "" {
		return endpointTarget{}, false
	}

	dialHost := ipAddr
	if dialHost == "" {
		dialHost = hostname
	}

	authHost := hostname
	if authHost == "" {
		authHost = dialHost
	}

	sniHost := ""
	if net.ParseIP(authHost) == nil && !strings.Contains(authHost, ":") {
		sniHost = authHost
	}

	return endpointTarget{
		dialAddr:  net.JoinHostPort(dialHost, portStr),
		authHost:  authHost,
		authority: net.JoinHostPort(authHost, portStr),
		sniHost:   sniHost,
		port:      port,
	}, true
}

func normalizeEndpointHost(raw string) string {
	h := stripHostBrackets(strings.TrimSpace(raw))
	h = strings.TrimRight(h, ".")
	if h == "" {
		return ""
	}
	if net.ParseIP(h) == nil && !strings.Contains(h, ":") {
		return strings.ToLower(h)
	}
	return h
}

func extractCandidatePaths(service *nspb.NetworkService, maxCrawled int) []string {
	paths := []string{"/"}
	seen := map[string]bool{"/": true}

	wsc := service.GetServiceContext().GetWebServiceContext()
	if root := sanitizeRequestPath(wsc.GetApplicationRoot()); root != "" && !seen[root] {
		seen[root] = true
		paths = append(paths, root)
	}

	servicePort := resolvedServicePort(service)
	ep := service.GetNetworkEndpoint()
	epHostname := normalizeEndpointHost(ep.GetHostname().GetName())
	epIP := stripHostBrackets(strings.TrimSpace(ep.GetIpAddress().GetAddress()))

	addedCrawled := 0
	for _, cr := range wsc.GetCrawlResults() {
		if addedCrawled >= maxCrawled {
			break
		}
		rawTarget := strings.TrimSpace(cr.GetCrawlTarget().GetUrl())
		if rawTarget == "" {
			continue
		}
		parsed, err := url.Parse(rawTarget)
		if err != nil {
			continue
		}
		if !isSameOriginCrawlURL(rawTarget, parsed, epHostname, epIP, servicePort) {
			continue
		}
		candidate := parsed.EscapedPath()
		if candidate == "" {
			candidate = "/"
		}
		if parsed.RawQuery != "" {
			candidate = candidate + "?" + parsed.RawQuery
		}
		clean := sanitizeRequestPath(candidate)
		if clean == "" || seen[clean] {
			continue
		}
		seen[clean] = true
		paths = append(paths, clean)
		addedCrawled++
	}

	return paths
}

func resolvedServicePort(service *nspb.NetworkService) uint32 {
	if port := service.GetNetworkEndpoint().GetPort().GetPortNumber(); port > 0 {
		return port
	}
	name := strings.ToLower(strings.TrimSpace(service.GetServiceName()))
	if len(service.GetSupportedSslVersions()) > 0 || strings.Contains(name, "https") || strings.Contains(name, "ssl") {
		return defaultHTTPSPort
	}
	return defaultHTTPPort
}

func isSameOriginCrawlURL(rawTarget string, parsed *url.URL, epHostname, epIP string, servicePort uint32) bool {
	if parsed.Opaque != "" {
		return false
	}
	if parsed.Scheme == "" {
		return parsed.Host == "" && !strings.HasPrefix(rawTarget, "//")
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return false
	}
	urlHost := strings.TrimRight(stripHostBrackets(parsed.Hostname()), ".")
	if urlHost == "" || !matchesEndpointHost(urlHost, epHostname, epIP) {
		return false
	}
	urlPort := uint32(defaultHTTPPort)
	if scheme == "https" {
		urlPort = defaultHTTPSPort
	}
	if explicitPort := parsed.Port(); explicitPort != "" {
		p, err := strconv.ParseUint(explicitPort, 10, 32)
		if err != nil || p == 0 {
			return false
		}
		urlPort = uint32(p)
	}
	return urlPort == servicePort
}

func matchesEndpointHost(urlHost, epHostname, epIP string) bool {
	if epHostname != "" && strings.EqualFold(urlHost, epHostname) {
		return true
	}
	if epIP != "" && strings.EqualFold(urlHost, epIP) {
		return true
	}
	if parsedURLIP := net.ParseIP(urlHost); parsedURLIP != nil && epIP != "" {
		if parsedEpIP := net.ParseIP(epIP); parsedEpIP != nil && parsedURLIP.Equal(parsedEpIP) {
			return true
		}
	}
	return false
}

func stripHostBrackets(host string) string {
	return strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
}

func sanitizeRequestPath(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	if frag := strings.IndexByte(trimmed, '#'); frag >= 0 {
		trimmed = trimmed[:frag]
	}
	if trimmed == "" {
		return "/"
	}
	if !strings.HasPrefix(trimmed, "/") {
		trimmed = "/" + trimmed
	}
	for i := 0; i < len(trimmed); i++ {
		c := trimmed[i]
		if c <= 0x20 || c >= 0x7f {
			return ""
		}
	}
	return trimmed
}
