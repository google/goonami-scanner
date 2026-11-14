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

// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package cve2026111497outbound provides a Goonami vulnerability detector
// (dt/cve2026111497outbound) for CVE-2026-111497 (Google Brotli Decoder
// out-of-bounds write remote code execution) exposed via outbound HTTP fetches
// such as CMS XML-RPC pingback.ping and Next.js /_next/image.
package cve2026111497outbound

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/goonami-scanner/common/callbackserver/cbid"
	"github.com/google/goonami-scanner/common/clients/callbackserver"
	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/log"
	"github.com/google/goonami-scanner/core/module"
	goohttp "github.com/google/goonami-scanner/core/net/http"
	"github.com/google/goonami-scanner/core/net/netservice"

	dpb "github.com/google/tsunami-security-scanner/proto/go/detection_go_proto"
	npb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
	rpb "github.com/google/tsunami-security-scanner/proto/go/reconnaissance_go_proto"
	vpb "github.com/google/tsunami-security-scanner/proto/go/vulnerability_go_proto"
	tspb "google.golang.org/protobuf/types/known/timestamppb"
)

const (
	moduleName = "dt/cve2026111497outbound"

	vulnerabilityReportPublisher = "GOOGLE"
	vulnerabilityReportID        = "CVE-2026-111497-OUTBOUND"
	relatedCVEID                 = "CVE-2026-111497"
	vulnerabilityReportTitle     = "Outbound HTTP Client Google Brotli Decoder RCE (CVE-2026-111497)"
	vulnDescription              = "The target web application exposes an unauthenticated outbound HTTP fetch endpoint (such as CMS XML-RPC 'pingback.ping' in WordPress, Drupal, b2evolution, Serendipity, DokuWiki, Movable Type, or TikiWiki, or Next.js '/_next/image') backed by a Google Brotli decoder library (libbrotlidec 1.0.3 through 1.2.0) vulnerable to CVE-2026-111497. When the endpoint fetches a remote URL, its HTTP client (e.g., libcurl/Guzzle with CURLOPT_ENCODING enabled or Node.js undici fetch) advertises 'br' in Accept-Encoding and streams 'Content-Encoding: br' HTTP responses directly into BrotliDecoderDecompressStream. In unpatched Brotli decoders, a compressed metablock with NBLTYPESD == 1 and more than 16,777,216 explicit-distance commands causes BrotliDecoderDecompressStream to copy unread input bytes past the 8-byte s->buffer union into adjacent BrotliDecoderState fields, enabling unauthenticated Remote Code Execution (RCE) inside the server worker."
	recommendation               = "Upgrade the system Brotli library (libbrotli1) to version 1.2.1 or a patched distribution package (such as Debian libbrotli1 >= 1.1.0-2+deb13u1) and restart PHP-FPM/Apache, or upgrade Node.js to 22.23.4+, 24.15.0+, or 25.8.0+ for Next.js deployments. As defense-in-depth, block unauthenticated XML-RPC 'pingback.ping' endpoints at the web server or WAF, and restrict Next.js 'images.remotePatterns' / 'images.domains' to trusted origins."

	presetBrotliValid         = "brotli_valid"
	presetBrotliInvalid       = "brotli_invalid"
	presetBrotliCVE2026111497 = "brotli_cve_2026_111497"

	secretBytes = 16

	maxCrawledCMSRoots = 3
	maxXPingbackURLs   = 3
	maxCandidatePosts  = 4

	faultDefaultMasked     = 0
	faultSourceNotFound    = 16
	faultTargetLinkMissing = 17
	faultTitleMissing      = 32

	listMethodsBody = `<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>`
)

var (
	xmlrpcFaultCodePattern = regexp.MustCompile(`(?is)<name>\s*faultCode\s*</name>\s*<value>\s*<int>\s*(-?\d+)\s*</int>\s*</value>`)
	homePageLinkPattern    = regexp.MustCompile(`(?i)<homePageLink>\s*([^<\s]+)\s*</homePageLink>`)
	rssItemPattern         = regexp.MustCompile(`(?is)<item>(.*?)</item>`)
	rssLinkPattern         = regexp.MustCompile(`(?i)<link>\s*([^<\s]+)\s*</link>`)

	cmsSubpathMarkers = []string{
		"/wp-content/",
		"/wp-includes/",
		"/wp-admin/",
		"/wp-json/",
		"/wp-login.php",
		"/xmlsrv/xmlrpc.php",
		"/xmlrpc.php",
		"/sites/default/",
		"/sites/all/",
		"/core/misc/",
		"/core/modules/",
		"/core/themes/",
		"/core/assets/",
		"/modules/",
		"/services/xmlrpc",
		"/comment.php",
		"/serendipity.css",
		"/serendipity_admin.php",
		"/mt-static/",
		"/mt-xmlrpc.cgi",
		"/tiki-index.php",
		"/tiki-xmlrpc.php",
	}

	cmsRootXMLRPCPaths = []string{
		"xmlrpc.php",
		"services/xmlrpc",
		"xmlsrv/xmlrpc.php",
		"comment.php?type=pingback",
		"mt-xmlrpc.cgi",
		"tiki-xmlrpc.php",
	}

	rootOnlySubdirXMLRPCPaths = []string{
		"wordpress/xmlrpc.php",
		"wp/xmlrpc.php",
		"blog/xmlrpc.php",
		"drupal/xmlrpc.php",
		"cms/xmlrpc.php",
	}
)

type callbackClient interface {
	IsCallbackServerEnabled() bool
	GetHTTPCallbackURI(secret string) (string, error)
	HasInteraction(ctx context.Context, secret string) (bool, error)
}

type callbackProbeStep struct {
	brSecret   string
	noBrSecret string
	sourceURI  string
}

// Module implements the module.VulnDetector interface for CVE-2026-111497-OUTBOUND.
type Module struct {
	*module.BaseModule
	cfg       *config.Config
	client    goohttp.Client
	tcsClient callbackClient
}

func init() {
	module.RegisterDetector(moduleName, New)
}

// New returns a new instance of the CVE-2026-111497 outbound detector.
func New(ctx context.Context, cfg *config.Config) (module.VulnDetector, error) {
	opts := goohttp.DefaultClientOptions()
	opts.DisableFollowRedirects = true
	client, err := goohttp.NewClient(cfg, opts)
	if err != nil {
		return nil, err
	}

	return &Module{
		BaseModule: module.NewBaseModule(moduleName),
		cfg:        cfg,
		client:     client,
	}, nil
}

// Advisories returns the vulnerability metadata reported by this module.
func (m *Module) Advisories() []*vpb.Vulnerability {
	return []*vpb.Vulnerability{baseVulnerability()}
}

func baseVulnerability() *vpb.Vulnerability {
	return vpb.Vulnerability_builder{
		MainId: vpb.VulnerabilityId_builder{
			Publisher: vulnerabilityReportPublisher,
			Value:     vulnerabilityReportID,
		}.Build(),
		RelatedId: []*vpb.VulnerabilityId{
			vpb.VulnerabilityId_builder{
				Publisher: "CVE",
				Value:     relatedCVEID,
			}.Build(),
		},
		Severity:       vpb.Severity_CRITICAL,
		Title:          vulnerabilityReportTitle,
		Description:    vulnDescription,
		Recommendation: recommendation,
	}.Build()
}

func (m *Module) getCallbackClient() callbackClient {
	if m.tcsClient != nil {
		return m.tcsClient
	}
	defer func() {
		_ = recover()
	}()
	if m.cfg != nil && m.cfg.ClientsConfig().HasCallbackServer() {
		return callbackserver.DefaultClient()
	}
	return nil
}

// Detect probes the target network service for CVE-2026-111497 exposed via outbound HTTP clients.
func (m *Module) Detect(ctx context.Context, service *nspb.NetworkService) (*dpb.DetectionReportList, error) {
	ctx = log.ContextForModuleAndService(ctx, m.Name(), service)
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if !netservice.IsWebService(service) {
		return nil, nil
	}

	cbClient := m.getCallbackClient()
	if cbClient == nil || !cbClient.IsCallbackServerEnabled() {
		log.WarnContextf(ctx, "Tsunami callback server is not enabled; skipping dt/cve2026111497outbound.")
		return nil, nil
	}

	webRoots, err := netservice.BuildAllWebRoots(service)
	if err != nil || len(webRoots) == 0 {
		return nil, err
	}
	rootURL := webRoots[0]
	if !strings.HasSuffix(rootURL, "/") {
		rootURL += "/"
	}

	// 1. Multi-CMS XML-RPC pingback.ping verification.
	xmlRPCReport, err := m.checkXMLRPCTargets(ctx, service, rootURL)
	if err != nil || xmlRPCReport != nil {
		return xmlRPCReport, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// 2. Next.js Image Optimizer (/_next/image) verification.
	return m.checkNextJsImageTargets(ctx, service, rootURL)
}

func (m *Module) createProbeStep(preset string) (*callbackProbeStep, error) {
	brSecretBytes := make([]byte, secretBytes)
	if _, err := rand.Read(brSecretBytes); err != nil {
		return nil, err
	}
	noBrSecretBytes := make([]byte, secretBytes)
	if _, err := rand.Read(noBrSecretBytes); err != nil {
		return nil, err
	}
	brSecret := hex.EncodeToString(brSecretBytes)
	noBrSecret := hex.EncodeToString(noBrSecretBytes)

	cbClient := m.getCallbackClient()
	brCallbackURI, err := cbClient.GetHTTPCallbackURI(brSecret)
	if err != nil {
		return nil, err
	}
	noBrCBID, err := cbid.Generate(noBrSecret)
	if err != nil {
		return nil, err
	}

	sourceURI := fmt.Sprintf("%s?response=%s&no_br_cbid=%s", brCallbackURI, preset, noBrCBID)
	return &callbackProbeStep{
		brSecret:   brSecret,
		noBrSecret: noBrSecret,
		sourceURI:  sourceURI,
	}, nil
}

func (m *Module) hasExpectedCallbacks(ctx context.Context, step *callbackProbeStep, expectNoBrRetry bool) (bool, error) {
	cbClient := m.getCallbackClient()
	hasBr, err := cbClient.HasInteraction(ctx, step.brSecret)
	if err != nil {
		return false, err
	}
	if !hasBr {
		return false, nil
	}
	hasNoBr, err := cbClient.HasInteraction(ctx, step.noBrSecret)
	if err != nil {
		return false, err
	}
	return hasNoBr == expectNoBrRetry, nil
}

func (m *Module) checkNextJsImageTargets(ctx context.Context, service *nspb.NetworkService, rootURL string) (*dpb.DetectionReportList, error) {
	endpoints := []string{strings.TrimSuffix(rootURL, "/") + "/_next/image"}

	// Check crawl results for additional /_next/ prefixes.
	if service.GetServiceContext().HasWebServiceContext() {
		for _, crawlResult := range service.GetServiceContext().GetWebServiceContext().GetCrawlResults() {
			crawledURL := crawlResult.GetCrawlTarget().GetUrl()
			if !strings.HasPrefix(crawledURL, rootURL) {
				continue
			}
			idx := strings.Index(strings.ToLower(crawledURL), "/_next/")
			if idx >= len(rootURL)-1 {
				ep := crawledURL[:idx+1] + "_next/image"
				if !containsString(endpoints, ep) && len(endpoints) < 1+maxCrawledCMSRoots {
					endpoints = append(endpoints, ep)
				}
			}
		}
	}

	for _, endpoint := range endpoints {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		report, err := m.probeNextJsImageEndpoint(ctx, service, endpoint)
		if err != nil || report != nil {
			return report, err
		}
	}

	return nil, nil
}

func (m *Module) probeNextJsImageEndpoint(ctx context.Context, service *nspb.NetworkService, endpoint string) (*dpb.DetectionReportList, error) {
	// Step 1: Valid RFC 7932 Brotli control. Expect HTTP 400 and primary 'br' interaction.
	valid1, err := m.createProbeStep(presetBrotliValid)
	if err != nil {
		return nil, err
	}
	status1, err := m.sendNextJsImageRequest(ctx, endpoint, valid1.sourceURI)
	if err != nil || status1 != http.StatusBadRequest {
		return nil, nil
	}
	ok, err := m.hasExpectedCallbacks(ctx, valid1, false)
	if err != nil || !ok {
		return nil, nil
	}

	// Step 2: Invalid Brotli control. Expect HTTP 500 or 502 and primary 'br' interaction.
	invalid1, err := m.createProbeStep(presetBrotliInvalid)
	if err != nil {
		return nil, err
	}
	status2, err := m.sendNextJsImageRequest(ctx, endpoint, invalid1.sourceURI)
	if err != nil || (status2 != http.StatusInternalServerError && status2 != http.StatusBadGateway) {
		return nil, nil
	}
	ok, err = m.hasExpectedCallbacks(ctx, invalid1, false)
	if err != nil || !ok {
		return nil, nil
	}
	invalidStatus := status2

	// Step 3: Zero-side-effect CVE-2026-111497 probe. Expect HTTP 400 and primary 'br' interaction.
	probe, err := m.createProbeStep(presetBrotliCVE2026111497)
	if err != nil {
		return nil, err
	}
	status3, err := m.sendNextJsImageRequest(ctx, endpoint, probe.sourceURI)
	if err != nil || status3 != http.StatusBadRequest {
		return nil, nil
	}
	ok, err = m.hasExpectedCallbacks(ctx, probe, false)
	if err != nil || !ok {
		return nil, nil
	}

	// Step 4: Post-probe health and determinism verification.
	valid2, err := m.createProbeStep(presetBrotliValid)
	if err != nil {
		return nil, err
	}
	status4, err := m.sendNextJsImageRequest(ctx, endpoint, valid2.sourceURI)
	if err != nil || status4 != http.StatusBadRequest {
		return nil, nil
	}
	ok, err = m.hasExpectedCallbacks(ctx, valid2, false)
	if err != nil || !ok {
		return nil, nil
	}

	invalid2, err := m.createProbeStep(presetBrotliInvalid)
	if err != nil {
		return nil, err
	}
	status5, err := m.sendNextJsImageRequest(ctx, endpoint, invalid2.sourceURI)
	if err != nil || status5 != invalidStatus {
		return nil, nil
	}
	ok, err = m.hasExpectedCallbacks(ctx, invalid2, false)
	if err != nil || !ok {
		return nil, nil
	}

	evidence := fmt.Sprintf("Confirmed CVE-2026-111497 via Next.js Image Optimizer on %s (valid: 400, invalid: %d, probe: 400)", endpoint, invalidStatus)
	return buildDetectionReport(service, endpoint, evidence), nil
}

func (m *Module) sendNextJsImageRequest(ctx context.Context, endpoint, sourceURI string) (int, error) {
	reqURL := fmt.Sprintf("%s?url=%s&w=64&q=75", endpoint, url.QueryEscape(sourceURI))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Accept", "image/webp,*/*")

	resp, err := m.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	return resp.StatusCode, nil
}

type xmlRPCEndpointCandidate struct {
	xmlRPCURL        string
	effectiveRootURL string
}

func (m *Module) checkXMLRPCTargets(ctx context.Context, service *nspb.NetworkService, rootURL string) (*dpb.DetectionReportList, error) {
	candidates := m.discoverXMLRPCCandidates(service, rootURL)

	for _, cand := range candidates {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		homeURL, ok := m.verifyXMLRPCEndpoint(ctx, cand)
		if !ok {
			continue
		}
		postURLs := m.discoverCandidatePostURLs(ctx, service, cand.effectiveRootURL, homeURL)
		for _, postURL := range postURLs {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			report, err := m.probeXMLRPCPost(ctx, service, cand.xmlRPCURL, postURL)
			if err != nil || report != nil {
				return report, err
			}
		}
	}
	return nil, nil
}

func (m *Module) discoverXMLRPCCandidates(service *nspb.NetworkService, rootURL string) []xmlRPCEndpointCandidate {
	var candidates []xmlRPCEndpointCandidate
	seen := make(map[string]bool)

	addCandidate := func(xmlRPCURL, effectiveRoot string) {
		if !seen[xmlRPCURL] {
			seen[xmlRPCURL] = true
			candidates = append(candidates, xmlRPCEndpointCandidate{
				xmlRPCURL:        xmlRPCURL,
				effectiveRootURL: effectiveRoot,
			})
		}
	}

	// 1. Crawled X-Pingback headers
	if service.GetServiceContext().HasWebServiceContext() {
		for _, crawlResult := range service.GetServiceContext().GetWebServiceContext().GetCrawlResults() {
			for _, hdr := range crawlResult.GetResponseHeaders() {
				if strings.EqualFold(hdr.GetKey(), "X-Pingback") {
					val := strings.TrimSpace(hdr.GetValue())
					if val != "" {
						normalized := normalizePingbackURL(val, rootURL)
						if normalized != "" {
							addCandidate(normalized, rootURL)
						}
					}
				}
			}
		}
	}

	// 2. Discover CMS roots from crawl results
	cmsRoots := []string{rootURL}
	if service.GetServiceContext().HasWebServiceContext() {
		for _, crawlResult := range service.GetServiceContext().GetWebServiceContext().GetCrawlResults() {
			if len(cmsRoots) >= 1+maxCrawledCMSRoots {
				break
			}
			crawledURL := crawlResult.GetCrawlTarget().GetUrl()
			if !strings.HasPrefix(crawledURL, rootURL) {
				continue
			}
			lower := strings.ToLower(crawledURL)
			for _, marker := range cmsSubpathMarkers {
				idx := strings.Index(lower, marker)
				if idx >= len(rootURL)-1 {
					rootCandidate := crawledURL[:idx+1]
					if !containsString(cmsRoots, rootCandidate) {
						cmsRoots = append(cmsRoots, rootCandidate)
					}
					break
				}
			}
		}
	}

	// 3. Probing standard relative paths under each CMS root
	for _, cmsRoot := range cmsRoots {
		for _, p := range cmsRootXMLRPCPaths {
			addCandidate(cmsRoot+p, cmsRoot)
		}
		if cmsRoot == rootURL {
			for _, p := range rootOnlySubdirXMLRPCPaths {
				effRoot := rootURL + p[:len(p)-len("xmlrpc.php")]
				addCandidate(rootURL+p, effRoot)
			}
		}
	}

	return candidates
}

func normalizePingbackURL(val, rootURL string) string {
	parsed, err := url.Parse(val)
	if err != nil {
		return ""
	}
	if !parsed.IsAbs() {
		base, err := url.Parse(rootURL)
		if err != nil {
			return ""
		}
		parsed = base.ResolveReference(parsed)
	}
	res := parsed.String()
	if strings.HasPrefix(res, rootURL) {
		return res
	}
	return ""
}

func (m *Module) verifyXMLRPCEndpoint(ctx context.Context, cand xmlRPCEndpointCandidate) (string, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cand.xmlRPCURL, strings.NewReader(listMethodsBody))
	if err != nil {
		return "", false
	}
	req.Header.Set("Content-Type", "text/xml")

	resp, err := m.client.Do(req)
	defaultHome := strings.TrimSuffix(cand.effectiveRootURL, "/")
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))
	body := string(bodyBytes)

	if resp.StatusCode == http.StatusOK && strings.Contains(body, "<methodResponse>") {
		if strings.Contains(body, "<string>pingback.ping</string>") {
			// Extract RSD if available, or default
			rsdHome := m.checkXMLRPCRsd(ctx, cand.xmlRPCURL, cand.effectiveRootURL)
			if rsdHome != "" {
				return rsdHome, true
			}
			return defaultHome, true
		}
		if strings.Contains(body, "<fault>") && strings.Contains(cand.xmlRPCURL, "comment.php?type=pingback") {
			return defaultHome, true
		}
	}

	// If blocked or fault, try RSD
	rsdHome := m.checkXMLRPCRsd(ctx, cand.xmlRPCURL, cand.effectiveRootURL)
	if rsdHome != "" {
		return rsdHome, true
	}

	return "", false
}

func (m *Module) checkXMLRPCRsd(ctx context.Context, xmlRPCURL, effectiveRootURL string) string {
	sep := "?"
	if strings.Contains(xmlRPCURL, "?") {
		sep = "&"
	}
	rsdURL := xmlRPCURL + sep + "rsd"
	defaultHome := strings.TrimSuffix(effectiveRootURL, "/")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rsdURL, nil)
	if err != nil {
		return ""
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))
	body := string(bodyBytes)

	if resp.StatusCode == http.StatusOK && (strings.Contains(body, "<rsd") || strings.Contains(body, "<engineName>")) {
		matches := homePageLinkPattern.FindStringSubmatch(body)
		if len(matches) > 1 {
			link := strings.TrimSpace(matches[1])
			if strings.HasPrefix(link, "http://") || strings.HasPrefix(link, "https://") {
				return strings.TrimSuffix(link, "/")
			}
		}
		return defaultHome
	}
	if (resp.StatusCode == http.StatusMethodNotAllowed || resp.StatusCode == http.StatusOK) &&
		strings.Contains(body, "XML-RPC server accepts POST requests only.") {
		return defaultHome
	}
	return ""
}

func (m *Module) discoverCandidatePostURLs(ctx context.Context, service *nspb.NetworkService, cmsRootURL, homeURL string) []string {
	var postURLs []string
	addPost := func(u string) {
		if !containsString(postURLs, u) && len(postURLs) < maxCandidatePosts {
			postURLs = append(postURLs, u)
		}
	}

	// 1. WP REST API
	restURL := cmsRootURL + "wp-json/wp/v2/posts?per_page=5"
	if req, err := http.NewRequestWithContext(ctx, http.MethodGet, restURL, nil); err == nil {
		if resp, err := m.client.Do(req); err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				var items []struct {
					PingStatus string `json:"ping_status"`
					Link       string `json:"link"`
				}
				bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 32768))
				if err := json.Unmarshal(bodyBytes, &items); err == nil {
					for _, it := range items {
						if it.Link != "" && (it.PingStatus == "" || strings.EqualFold(it.PingStatus, "open")) {
							addPost(it.Link)
						}
					}
				}
			}
		}
	}

	// 2. RSS feeds
	if len(postURLs) == 0 {
		for _, rssPath := range []string{"?feed=rss2", "rss.xml"} {
			rssURL := cmsRootURL + rssPath
			if req, err := http.NewRequestWithContext(ctx, http.MethodGet, rssURL, nil); err == nil {
				if resp, err := m.client.Do(req); err == nil {
					defer resp.Body.Close()
					if resp.StatusCode == http.StatusOK {
						bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 32768))
						for _, itemMatch := range rssItemPattern.FindAllStringSubmatch(string(bodyBytes), -1) {
							if len(itemMatch) > 1 {
								linkMatch := rssLinkPattern.FindStringSubmatch(itemMatch[1])
								if len(linkMatch) > 1 {
									addPost(strings.TrimSpace(linkMatch[1]))
								}
							}
						}
					}
				}
			}
			if len(postURLs) > 0 {
				break
			}
		}
	}

	// 3. Fallbacks
	addPost(homeURL + "/?p=1")
	addPost(homeURL + "/node/1")

	return postURLs
}

func (m *Module) probeXMLRPCPost(ctx context.Context, service *nspb.NetworkService, xmlRPCURL, postURL string) (*dpb.DetectionReportList, error) {
	// Step 1: Valid Brotli control
	valid1, err := m.createProbeStep(presetBrotliValid)
	if err != nil {
		return nil, err
	}
	fault1, ok := m.sendPingbackCall(ctx, xmlRPCURL, valid1.sourceURI, postURL)
	if !ok {
		return nil, nil
	}
	sawBr, err := m.hasExpectedCallbacks(ctx, valid1, false)
	if err != nil || !sawBr {
		return nil, nil
	}

	// Step 2: Invalid Brotli control
	invalid1, err := m.createProbeStep(presetBrotliInvalid)
	if err != nil {
		return nil, err
	}
	fault2, ok := m.sendPingbackCall(ctx, xmlRPCURL, invalid1.sourceURI, postURL)
	if !ok {
		return nil, nil
	}
	cbClient := m.getCallbackClient()
	hasInvalidBr, err := cbClient.HasInteraction(ctx, invalid1.brSecret)
	if err != nil || !hasInvalidBr {
		return nil, nil
	}
	clientRetriesWithoutBr, _ := cbClient.HasInteraction(ctx, invalid1.noBrSecret)

	if !isAllowedControlFaultPair(fault1, fault2, clientRetriesWithoutBr) {
		return nil, nil
	}

	// Step 3: Zero-side-effect CVE-2026-111497 probe
	probe, err := m.createProbeStep(presetBrotliCVE2026111497)
	if err != nil {
		return nil, err
	}
	fault3, ok := m.sendPingbackCall(ctx, xmlRPCURL, probe.sourceURI, postURL)
	if !ok || fault3 != fault1 {
		return nil, nil
	}
	probeExpected, err := m.hasExpectedCallbacks(ctx, probe, false)
	if err != nil || !probeExpected {
		return nil, nil
	}

	// Step 4: Post-probe health and determinism verification
	valid2, err := m.createProbeStep(presetBrotliValid)
	if err != nil {
		return nil, err
	}
	fault4, ok := m.sendPingbackCall(ctx, xmlRPCURL, valid2.sourceURI, postURL)
	if !ok || fault4 != fault1 {
		return nil, nil
	}
	v2Expected, err := m.hasExpectedCallbacks(ctx, valid2, false)
	if err != nil || !v2Expected {
		return nil, nil
	}

	invalid2, err := m.createProbeStep(presetBrotliInvalid)
	if err != nil {
		return nil, err
	}
	fault5, ok := m.sendPingbackCall(ctx, xmlRPCURL, invalid2.sourceURI, postURL)
	if !ok || fault5 != fault2 {
		return nil, nil
	}
	i2Expected, err := m.hasExpectedCallbacks(ctx, invalid2, clientRetriesWithoutBr)
	if err != nil || !i2Expected {
		return nil, nil
	}

	evidence := fmt.Sprintf("Confirmed CVE-2026-111497 via XML-RPC pingback on %s (post: %s, validFault: %d, invalidFault: %d, probeFault: %d)", xmlRPCURL, postURL, fault1, fault2, fault3)
	return buildDetectionReport(service, xmlRPCURL, evidence), nil
}

func (m *Module) sendPingbackCall(ctx context.Context, xmlRPCURL, sourceURI, targetURI string) (int, bool) {
	var escapedSource bytes.Buffer
	xml.EscapeText(&escapedSource, []byte(sourceURI))
	var escapedTarget bytes.Buffer
	xml.EscapeText(&escapedTarget, []byte(targetURI))

	xmlPayload := fmt.Sprintf(`<?xml version="1.0"?><methodCall><methodName>pingback.ping</methodName><params><param><value><string>%s</string></value></param><param><value><string>%s</string></value></param></params></methodCall>`, escapedSource.String(), escapedTarget.String())

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, xmlRPCURL, strings.NewReader(xmlPayload))
	if err != nil {
		return 0, false
	}
	req.Header.Set("Content-Type", "text/xml")

	resp, err := m.client.Do(req)
	if err != nil {
		return 0, false
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))
	body := string(bodyBytes)

	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "<methodResponse>") {
		return 0, false
	}

	matches := xmlrpcFaultCodePattern.FindStringSubmatch(body)
	if len(matches) > 1 {
		code, err := strconv.Atoi(matches[1])
		if err == nil {
			return code, true
		}
	}
	return 0, false
}

func isAllowedControlFaultPair(validFault, invalidFault int, clientRetriesWithoutBr bool) bool {
	if clientRetriesWithoutBr && validFault == faultDefaultMasked && invalidFault == faultDefaultMasked {
		return true
	}
	return (validFault == faultTitleMissing || validFault == faultTargetLinkMissing) && invalidFault == faultSourceNotFound
}

func buildDetectionReport(service *nspb.NetworkService, endpoint, evidenceDesc string) *dpb.DetectionReportList {
	vuln := baseVulnerability()
	vuln.SetAdditionalDetails([]*vpb.AdditionalDetail{
		vpb.AdditionalDetail_builder{
			Description: "Outbound HTTP client Google Brotli decoder RCE verification",
			TextData: vpb.TextData_builder{
				Text: evidenceDesc,
			}.Build(),
		}.Build(),
	})

	return dpb.DetectionReportList_builder{
		DetectionReports: []*dpb.DetectionReport{
			dpb.DetectionReport_builder{
				TargetInfo: rpb.TargetInfo_builder{
					NetworkEndpoints: []*npb.NetworkEndpoint{
						service.GetNetworkEndpoint(),
					},
				}.Build(),
				NetworkService:     service,
				DetectionTimestamp: tspb.Now(),
				DetectionStatus:    dpb.DetectionStatus_VULNERABILITY_VERIFIED,
				Vulnerability:      vuln,
			}.Build(),
		},
	}.Build()
}

func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}
