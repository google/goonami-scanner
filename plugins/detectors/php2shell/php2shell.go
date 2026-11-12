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

// Package php2shell detects PHP core RCE vulnerabilities (CVE-2026-109618 and
// CVE-2026-109619) caused by out-of-memory error-handling bailout corruption
// and session.upload_progress stale global state.
package php2shell

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

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
	wcpb "github.com/google/tsunami-security-scanner/proto/go/web_crawl_go_proto"
	tspb "google.golang.org/protobuf/types/known/timestamppb"
)

const (
	moduleName = "dt/php2shell"

	vulnReportPublisher         = "GOOGLE"
	vulnReportID                = "CVE-2026-109618"
	vulnReportTitle             = "PHP Core RCE (PHP2Shell)"
	vulnDescription             = "PHP versions 5.4 through 8.5.11 (prior to 8.2.35, 8.3.36, 8.4.27, and 8.5.12) are vulnerable to unauthenticated Remote Code Execution caused by out-of-memory error-handling bailout corruption during input variable registration (CVE-2026-109618) combined with uncleaned cross-request global state in session.upload_progress (CVE-2026-109619). This detector non-destructively verifies that the PHP session.upload_progress RFC1867 startup handler is reachable and executes the unpatched session-flush code path when session initialization fails."
	vulnRecommendation          = "Upgrade PHP to a patched release (8.5.12+, 8.4.27+, 8.3.36+, 8.2.35+, or the corresponding OS vendor security update). As a temporary mitigation for the unauthenticated session.upload_progress exploitation vector (CVE-2026-109619), set 'session.upload_progress.enabled = 0' in php.ini; upgrading PHP is still required to fully remediate CVE-2026-109618."
	additionalDetailDescription = "Verified unpatched PHP session.upload_progress startup session flush."

	defaultPhpSessionName            = "PHPSESSID"
	maxCrawledPhpURLs                = 3
	maxCrawledExtensionlessHTMLURLs  = 1
	maxCrawledSessionRetries         = 2
	maxCustomSessionCookiesPerSource = 3
	maxEvidenceWarningLength         = 512
	maxResponseBodyBytes             = 256 * 1024

	invalidSidSubstring  = "is too long or contains illegal characters"
	failedReadSubstring  = "Failed to read session data"
	failedPathSubstring  = "Failed to create session data file path"
	failedInitSubstring  = "Failed to initialize storage module"
	failedFlushSubstring = "Failed to write session data"
)

var (
	candidatePaths    = []string{"index.php", "", "public/index.php", "web/index.php", "wp-login.php"}
	invalidSidPadding = strings.Repeat("a", 240)

	startupInvalidSidWarningPattern = regexp.MustCompile(
		`(?i)Warning(?:<[^>]*>)*:\s*(?:<[^>]*>)*(?:PHP Request Startup|Unknown)[^\r\n]{0,1000}?is too long or contains illegal characters[^\r\n]{0,1000}?in (?:<[^>]*>)*Unknown(?:<[^>]*>)* on line (?:<[^>]*>)*0(?:<[^>]*>)*`)

	startupFailedInitWarningPattern = regexp.MustCompile(
		`(?i)Warning(?:<[^>]*>)*:\s*(?:<[^>]*>)*(?:PHP Request Startup|Unknown)[^\r\n]{0,1000}?(?:Failed to read session data|Failed to create session data file path|Failed to initialize storage module)[^\r\n]{0,1000}?in (?:<[^>]*>)*Unknown(?:<[^>]*>)* on line (?:<[^>]*>)*0(?:<[^>]*>)*`)

	startupFailedFlushWarningPattern = regexp.MustCompile(
		`(?i)Warning(?:<[^>]*>)*:\s*(?:<[^>]*>)*(?:PHP Request Startup|Unknown)[^\r\n]{0,1000}?Failed to write session data[^\r\n]{0,1000}?in (?:<[^>]*>)*Unknown(?:<[^>]*>)* on line (?:<[^>]*>)*0(?:<[^>]*>)*`)

	htmlTagPattern = regexp.MustCompile(`<[^>]*>`)

	customSessionCookiePattern = regexp.MustCompile(
		`^\s*([A-Za-z_][A-Za-z0-9_-]{0,63})="?([A-Za-z0-9,_%.~-]{8,256})"?(?:\s*;|$)`)

	ignoredCookieNames = map[string]bool{
		"PHPSESSID":       true,
		"JSESSIONID":      true,
		"ASPSESSIONID":    true,
		"CFID":            true,
		"CFTOKEN":         true,
		"AWSALB":          true,
		"AWSALBCORS":      true,
		"AWSALBTG":        true,
		"AWSALBTGCORS":    true,
		"GCLB":            true,
		"__CF_BM":         true,
		"_CFUVID":         true,
		"CF_CLEARANCE":    true,
		"SERVERID":        true,
		"XSRF_TOKEN":      true,
		"CSRF_TOKEN":      true,
		"CSRFTOKEN":       true,
		"_CSRF":           true,
		"LARAVEL_SESSION": true,
	}

	knownWebServiceNames = map[string]bool{
		"http":                true,
		"http-alt":            true,
		"http-proxy":          true,
		"https":               true,
		"radan-http":          true,
		"ssl/http":            true,
		"ssl/https":           true,
		"ssl/http-proxy":      true,
		"ssl/tungsten-https":  true,
		"ssl/wso2esb-console": true,
	}
)

// Module implements the module.VulnDetector interface for PHP2Shell detection.
type Module struct {
	*module.BaseModule
	config *config.Config
	nowFn  func() time.Time
}

func init() {
	module.RegisterDetector(moduleName, New)
}

// New returns a new instance of the PHP2Shell detector module.
func New(ctx context.Context, cfg *config.Config) (module.VulnDetector, error) {
	return &Module{
		BaseModule: module.NewBaseModule(moduleName),
		config:     cfg,
		nowFn:      time.Now,
	}, nil
}

// Advisories returns the base vulnerability metadata reported by this module.
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
				Value:     "CVE-2026-109618",
			}.Build(),
			vpb.VulnerabilityId_builder{
				Publisher: "CVE",
				Value:     "CVE-2026-109619",
			}.Build(),
		},
		Severity:       vpb.Severity_CRITICAL,
		Title:          vulnReportTitle,
		Description:    vulnDescription,
		Recommendation: vulnRecommendation,
	}.Build()
}

type verificationResult struct {
	targetURL      string
	sessionName    string
	matchedWarning string
}

// Detect probes the target web service for unpatched PHP session.upload_progress
// startup session-flush behavior (CVE-2026-109618 / CVE-2026-109619).
func (m *Module) Detect(ctx context.Context, service *nspb.NetworkService) (*dpb.DetectionReportList, error) {
	ctx = log.ContextForModuleAndService(ctx, m.Name(), service)
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if !isWebService(service) {
		return nil, nil
	}

	targetURLs, err := getTargetURLs(service)
	if err != nil {
		return nil, err
	}

	opts := goohttp.DefaultClientOptions()
	opts.DisableFollowRedirects = true
	client, err := goohttp.NewClient(m.config, opts)
	if err != nil {
		return nil, err
	}

	res, err := m.probeService(ctx, client, service, targetURLs)
	if err != nil {
		return nil, err
	}
	if res == nil {
		return nil, nil
	}

	return m.buildDetectionReport(service, res), nil
}

func isWebService(service *nspb.NetworkService) bool {
	if netservice.IsWebService(service) {
		return true
	}
	return knownWebServiceNames[strings.ToLower(service.GetServiceName())]
}

func (m *Module) probeService(
	ctx context.Context,
	client goohttp.Client,
	service *nspb.NetworkService,
	targetURLs []string,
) (*verificationResult, error) {
	crawledCustomNames := extractCustomSessionNamesFromCrawl(service)
	remainingCrawledRetries := maxCrawledSessionRetries

	for _, targetURL := range targetURLs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		status, headers, body, ok, err := m.sendMultipartProbe(ctx, client, targetURL, defaultPhpSessionName, true)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}

		res, err := m.verifyStartupFlushDifferential(ctx, client, targetURL, defaultPhpSessionName, body)
		if err != nil {
			return nil, err
		}
		if res != nil {
			return res, nil
		}

		endpointCustomNames := extractCustomSessionNamesFromHeaders(headers.Values("Set-Cookie"))
		for _, customSessionName := range endpointCustomNames {
			_, _, customBody, customOK, err := m.sendMultipartProbe(ctx, client, targetURL, customSessionName, true)
			if err != nil {
				return nil, err
			}
			if !customOK {
				continue
			}
			customRes, err := m.verifyStartupFlushDifferential(ctx, client, targetURL, customSessionName, customBody)
			if err != nil {
				return nil, err
			}
			if customRes != nil {
				return customRes, nil
			}
		}

		if len(crawledCustomNames) > 0 &&
			remainingCrawledRetries > 0 &&
			status != http.StatusNotFound &&
			status != http.StatusMethodNotAllowed &&
			!isRedirectStatus(status) {
			for _, crawledSessionName := range crawledCustomNames {
				if slices.Contains(endpointCustomNames, crawledSessionName) {
					continue
				}
				if remainingCrawledRetries <= 0 {
					break
				}
				remainingCrawledRetries--
				_, _, customBody, customOK, err := m.sendMultipartProbe(ctx, client, targetURL, crawledSessionName, true)
				if err != nil {
					return nil, err
				}
				if !customOK {
					continue
				}
				customRes, err := m.verifyStartupFlushDifferential(ctx, client, targetURL, crawledSessionName, customBody)
				if err != nil {
					return nil, err
				}
				if customRes != nil {
					return customRes, nil
				}
			}
		}
	}

	return nil, nil
}

func isRedirectStatus(status int) bool {
	return status >= 300 && status < 400
}

func (m *Module) verifyStartupFlushDifferential(
	ctx context.Context,
	client goohttp.Client,
	targetURL string,
	sessionName string,
	probeBody string,
) (*verificationResult, error) {
	matchedFlushWarning, ok := extractMatchedStartupFlushWarning(probeBody)
	if !ok {
		return nil, nil
	}

	_, _, controlBody, controlOK, err := m.sendMultipartProbe(ctx, client, targetURL, sessionName, false)
	if err != nil {
		return nil, err
	}
	if !controlOK {
		return nil, nil
	}

	if _, stillPresent := extractMatchedStartupFlushWarning(controlBody); stillPresent {
		log.DebugContextf(ctx, log.DebugLevelService, "ignoring non-differential startup warning text on %q", targetURL)
		return nil, nil
	}

	log.InfoContextf(ctx, "verified unpatched PHP session.upload_progress startup session flush on %q (session parameter %q)", targetURL, sessionName)
	return &verificationResult{
		targetURL:      targetURL,
		sessionName:    sessionName,
		matchedWarning: matchedFlushWarning,
	}, nil
}

func extractMatchedStartupFlushWarning(body string) (string, bool) {
	if !strings.Contains(body, failedFlushSubstring) {
		return "", false
	}
	hasInitSubstring := strings.Contains(body, invalidSidSubstring) ||
		strings.Contains(body, failedReadSubstring) ||
		strings.Contains(body, failedPathSubstring) ||
		strings.Contains(body, failedInitSubstring)
	if !hasInitSubstring {
		return "", false
	}
	hasStartupInitWarning := startupInvalidSidWarningPattern.MatchString(body) ||
		startupFailedInitWarningPattern.MatchString(body)
	if !hasStartupInitWarning {
		return "", false
	}
	flushMatch := startupFailedFlushWarningPattern.FindString(body)
	if flushMatch == "" {
		return "", false
	}
	sanitized := htmlTagPattern.ReplaceAllString(flushMatch, "")
	sanitized = strings.ReplaceAll(sanitized, "&quot;", "\"")
	sanitized = strings.TrimSpace(sanitized)
	if len(sanitized) > maxEvidenceWarningLength {
		sanitized = sanitized[:maxEvidenceWarningLength]
	}
	return sanitized, true
}

func extractCustomSessionNamesFromCrawl(service *nspb.NetworkService) []string {
	var allHeaders []string
	for _, crawlResult := range service.GetServiceContext().GetWebServiceContext().GetCrawlResults() {
		for _, header := range crawlResult.GetResponseHeaders() {
			if strings.EqualFold(header.GetKey(), "Set-Cookie") {
				allHeaders = append(allHeaders, header.GetValue())
			}
		}
	}
	return extractCustomSessionNamesFromHeaders(allHeaders)
}

func extractCustomSessionNamesFromHeaders(setCookies []string) []string {
	seen := make(map[string]bool)
	var names []string
	for _, cookieHeader := range setCookies {
		matches := customSessionCookiePattern.FindStringSubmatch(cookieHeader)
		if len(matches) < 2 {
			continue
		}
		cookieName := matches[1]
		normalized := strings.ReplaceAll(strings.ToUpper(cookieName), "-", "_")
		if ignoredCookieNames[normalized] || seen[cookieName] {
			continue
		}
		seen[cookieName] = true
		names = append(names, cookieName)
		if len(names) >= maxCustomSessionCookiesPerSource {
			break
		}
	}
	return names
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

func getTargetURLs(service *nspb.NetworkService) ([]string, error) {
	rootURL, err := buildWebRootURL(service)
	if err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	var targetURLs []string
	addTarget := func(u string) {
		if !seen[u] {
			seen[u] = true
			targetURLs = append(targetURLs, u)
		}
	}

	crawlResults := service.GetServiceContext().GetWebServiceContext().GetCrawlResults()
	addedCrawledPhpURLs := 0
	for _, cr := range crawlResults {
		if addedCrawledPhpURLs >= maxCrawledPhpURLs {
			break
		}
		if int(cr.GetResponseCode()) == http.StatusNotFound {
			continue
		}
		crawledURL := cr.GetCrawlTarget().GetUrl()
		if isPhpURL(crawledURL) {
			addTarget(crawledURL)
			addedCrawledPhpURLs++
		}
	}
	if addedCrawledPhpURLs == 0 {
		for _, cr := range crawlResults {
			crawledURL := cr.GetCrawlTarget().GetUrl()
			if isPhpURL(crawledURL) {
				addTarget(crawledURL)
				addedCrawledPhpURLs++
				break
			}
		}
	}

	for _, subpath := range candidatePaths {
		addTarget(rootURL + subpath)
	}

	if addedCrawledPhpURLs == 0 {
		addedExtensionlessURLs := 0
		for _, cr := range crawlResults {
			if addedExtensionlessURLs >= maxCrawledExtensionlessHTMLURLs {
				break
			}
			if isExtensionlessHTMLCrawlResult(cr, rootURL) {
				addTarget(cr.GetCrawlTarget().GetUrl())
				addedExtensionlessURLs++
			}
		}
	}

	return targetURLs, nil
}

func isExtensionlessHTMLCrawlResult(cr *wcpb.CrawlResult, rootURL string) bool {
	if int(cr.GetResponseCode()) != http.StatusOK || !hasHTMLContentType(cr) {
		return false
	}
	crawledURL := cr.GetCrawlTarget().GetUrl()
	if !strings.HasPrefix(crawledURL, rootURL) {
		return false
	}
	u, err := url.Parse(crawledURL)
	if err != nil {
		return false
	}
	rootU, err := url.Parse(rootURL)
	if err != nil {
		return false
	}
	path := u.Path
	if path == "" || path == "/" || path == rootU.Path {
		return false
	}
	lastSlash := strings.LastIndex(path, "/")
	lastSegment := path[lastSlash+1:]
	return !strings.Contains(lastSegment, ".")
}

func hasHTMLContentType(cr *wcpb.CrawlResult) bool {
	contentType := cr.GetContentType()
	if contentType == "" {
		for _, h := range cr.GetResponseHeaders() {
			if strings.EqualFold(h.GetKey(), "Content-Type") {
				contentType = h.GetValue()
				break
			}
		}
	}
	normalized := strings.ToLower(strings.TrimSpace(contentType))
	return strings.HasPrefix(normalized, "text/html") || strings.HasPrefix(normalized, "application/xhtml+xml")
}

func isPhpURL(candidateURL string) bool {
	u, err := url.Parse(candidateURL)
	if err != nil || u.Path == "" {
		return false
	}
	return strings.HasSuffix(strings.ToLower(u.Path), ".php")
}

func (m *Module) sendMultipartProbe(
	ctx context.Context,
	client goohttp.Client,
	targetURL string,
	sessionName string,
	includeUploadProgress bool,
) (int, http.Header, string, bool, error) {
	tsMillis := m.nowFn().UnixMilli()
	boundary := fmt.Sprintf("----TsunamiPhp2ShellBoundary%d", tsMillis)
	invalidSid := fmt.Sprintf("tsunami/invalid_sid_%d_%s", tsMillis, invalidSidPadding)

	var body strings.Builder
	body.WriteString("--")
	body.WriteString(boundary)
	body.WriteString("\r\nContent-Disposition: form-data; name=\"")
	body.WriteString(sessionName)
	body.WriteString("\"\r\n\r\n")
	body.WriteString(invalidSid)
	body.WriteString("\r\n")
	if includeUploadProgress {
		body.WriteString("--")
		body.WriteString(boundary)
		body.WriteString("\r\nContent-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\ntsunami\r\n")
	}
	body.WriteString("--")
	body.WriteString(boundary)
	body.WriteString("\r\nContent-Disposition: form-data; name=\"file\"; filename=\"tsunami.txt\"\r\nContent-Type: text/plain\r\n\r\nX\r\n--")
	body.WriteString(boundary)
	body.WriteString("--\r\n")

	requestURL := stripSessionQueryParam(targetURL, sessionName)
	payload := body.String()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL, strings.NewReader(payload))
	if err != nil {
		return 0, nil, "", false, nil
	}
	req.ContentLength = int64(len(payload))
	req.Header.Set("Content-Type", "multipart/form-data; boundary="+boundary)
	req.Header.Set("Connection", "close")
	req.Header.Set("Cookie", sessionName+"="+invalidSid)

	resp, err := client.Do(req)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return 0, nil, "", false, ctxErr
		}
		log.DebugContextf(ctx, log.DebugLevelRequest, "HTTP probe to %q failed: %v", requestURL, err)
		return 0, nil, "", false, nil
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes))
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return 0, nil, "", false, ctxErr
		}
		return 0, nil, "", false, nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return 0, nil, "", false, ctxErr
	}
	return resp.StatusCode, resp.Header, string(respBytes), true, nil
}

func stripSessionQueryParam(targetURL string, sessionName string) string {
	u, err := url.Parse(targetURL)
	if err != nil || u.RawQuery == "" {
		return targetURL
	}
	var filtered []string
	changed := false
	for _, param := range strings.Split(u.RawQuery, "&") {
		key := param
		if eqIdx := strings.IndexByte(param, '='); eqIdx >= 0 {
			key = param[:eqIdx]
		}
		if strings.EqualFold(key, sessionName) {
			changed = true
			continue
		}
		filtered = append(filtered, param)
	}
	if !changed {
		return targetURL
	}
	u.Fragment = ""
	u.RawFragment = ""
	u.RawQuery = strings.Join(filtered, "&")
	return u.String()
}

func (m *Module) buildDetectionReport(service *nspb.NetworkService, res *verificationResult) *dpb.DetectionReportList {
	detailText := fmt.Sprintf(
		"Vulnerable endpoint: %s\nSession parameter: %s\nMatched startup warning: %s",
		res.targetURL, res.sessionName, res.matchedWarning)

	vuln := baseVulnerability()
	vuln.SetAdditionalDetails([]*vpb.AdditionalDetail{
		vpb.AdditionalDetail_builder{
			Description: additionalDetailDescription,
			TextData: vpb.TextData_builder{
				Text: detailText,
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
