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

// Package cve2026126714 detects PHP session save handler partial-overwrite RCE
// (CVE-2026-126714, phpAfterShell) on web services backed by PHP's default
// "files" session storage module.
package cve2026126714

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
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
	spb "github.com/google/tsunami-security-scanner/proto/go/software_go_proto"
	vpb "github.com/google/tsunami-security-scanner/proto/go/vulnerability_go_proto"
	wcpb "github.com/google/tsunami-security-scanner/proto/go/web_crawl_go_proto"
	tspb "google.golang.org/protobuf/types/known/timestamppb"
)

const (
	moduleName = "dt/cve2026126714"

	vulnReportPublisher         = "GOOGLE"
	vulnReportID                = "CVE-2026-126714"
	vulnReportTitle             = "PHP Session Save Handler Partial-Overwrite RCE (CVE-2026-126714)"
	vulnDescription             = "PHP versions prior to 8.2.36, 8.3.37, 8.4.28, and 8.5.13 using the default 'files' session save handler are vulnerable to Remote Code Execution (CVE-2026-126714, phpAfterShell) because ps_files_write() overwrites existing session files at offset 0 via pwrite() without first truncating the file. An interrupted write (for example via session.upload_progress) can leave a hybrid prefix of attacker-controlled session data spliced onto the tail of an existing session file, allowing PHP object injection on subsequent session deserialization. This detector non-destructively verifies that PHP's session.upload_progress RFC1867 startup handler is enabled and backed by the 'files' session save handler without writing any session files to disk."
	vulnRecommendation          = "Upgrade PHP to version 8.2.36+, 8.3.37+, 8.4.28+, 8.5.13+, or the corresponding OS distribution security update, which truncates session files before writing in ps_files_write() and disables session.upload_progress.enabled by default. As an immediate workaround when upload progress tracking is not needed, set 'session.upload_progress.enabled = 0' in php.ini."
	additionalDetailDescription = "Verified unpatched PHP session.upload_progress startup handler on 'files' session storage."

	defaultPHPSessionName            = "PHPSESSID"
	maxCrawledPHPURLs                = 3
	maxCrawledExtensionlessHTMLURLs  = 1
	maxRedirectTargets               = 2
	maxCrawledSessionRetries         = 2
	maxCustomSessionCookiesPerSource = 3
	maxEvidenceWarningLength         = 512
	maxResponseBodyBytes             = 256 * 1024

	invalidSIDSubstring      = "is too long or contains illegal characters"
	failedFilesReadSubstring = "Failed to read session data: files"
)

var (
	candidatePaths    = []string{"index.php", "", "public/index.php", "web/index.php", "wp-login.php"}
	invalidSIDPadding = strings.Repeat("a", 240)

	startupInvalidSIDWarningPattern = regexp.MustCompile(
		`(?i)Warning(?:<[^>]*>)*:\s*(?:<[^>]*>)*(?:PHP Request Startup|Unknown)[^\r\n]{0,1000}?is too long or contains illegal characters[^\r\n]{0,1000}?in (?:<[^>]*>)*Unknown(?:<[^>]*>)* on line (?:<[^>]*>)*0(?:<[^>]*>)*`)

	startupFilesReadWarningPattern = regexp.MustCompile(
		`(?i)Warning(?:<[^>]*>)*:\s*(?:<[^>]*>)*(?:PHP Request Startup|Unknown)[^\r\n]{0,1000}?Failed to read session data:\s*files\b[^\r\n]{0,1000}?in (?:<[^>]*>)*Unknown(?:<[^>]*>)* on line (?:<[^>]*>)*0(?:<[^>]*>)*`)

	htmlTagPattern = regexp.MustCompile(`<[^>]*>`)

	customSessionCookiePattern = regexp.MustCompile(
		`^\s*([A-Za-z_][A-Za-z0-9_-]{0,63})="?([A-Za-z0-9,_%.~-]{8,256})"?(?:\s*;|$)`)

	destructivePathPattern = regexp.MustCompile(
		`(?i)\b(?:abort|delete|drop|hup|kill|killall|quit|remove|logout|signout)\b`)

	phpHeaderVersionPattern = regexp.MustCompile(
		`(?i)\bPHP[/: ]+(\d+)\.(\d+)\.(\d+)(?:[-~]([0-9A-Za-z.+~-]+))?`)

	rawPHPVersionPattern = regexp.MustCompile(
		`^(\d+)\.(\d+)\.(\d+)(?:[-~]([0-9A-Za-z.+~-]+))?`)

	ubuntu2404BackportPattern = regexp.MustCompile(`(?i)^0ubuntu0\.24\.04\.(\d+)`)
	ubuntu2204BackportPattern = regexp.MustCompile(`(?i)^1ubuntu2\.(\d+)`)

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
)

// Module implements the module.VulnDetector interface for CVE-2026-126714.
type Module struct {
	*module.BaseModule
	config *config.Config
	nowFn  func() time.Time
}

func init() {
	module.RegisterDetector(moduleName, New)
}

// New returns a new instance of the CVE-2026-126714 detector module.
func New(ctx context.Context, cfg *config.Config) (module.VulnDetector, error) {
	if cfg == nil {
		cfg = config.Default()
	}
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
				Value:     vulnReportID,
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
// startup initialization on the "files" session save handler (CVE-2026-126714).
func (m *Module) Detect(ctx context.Context, service *nspb.NetworkService) (*dpb.DetectionReportList, error) {
	ctx = log.ContextForModuleAndService(ctx, m.Name(), service)
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if !netservice.IsWebService(service) || hasKnownPatchedServiceVersion(service) {
		return nil, nil
	}

	rootURL, urls, err := targetURLs(service)
	if err != nil {
		return nil, err
	}

	opts := goohttp.DefaultClientOptions()
	opts.DisableFollowRedirects = true
	client, err := goohttp.NewClient(m.config, opts)
	if err != nil {
		return nil, err
	}

	res, err := m.probeService(ctx, client, service, rootURL, urls)
	if err != nil {
		return nil, err
	}
	if res == nil {
		return nil, nil
	}

	return m.buildDetectionReport(service, res), nil
}

func (m *Module) probeService(
	ctx context.Context,
	client goohttp.Client,
	service *nspb.NetworkService,
	rootURL string,
	initialURLs []string,
) (*verificationResult, error) {
	crawledCustomNames := extractCustomSessionNamesFromCrawl(service)
	remainingCrawledRetries := maxCrawledSessionRetries
	enqueuedRedirects := 0

	queue := slices.Clone(initialURLs)
	visited := make(map[string]bool, len(queue))
	for _, u := range queue {
		visited[u] = true
	}

	for idx := 0; idx < len(queue); idx++ {
		targetURL := queue[idx]
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		status, headers, body, ok, err := m.sendMultipartProbe(ctx, client, targetURL, defaultPHPSessionName, true)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		if hasKnownPatchedHeaderVersion(headers) {
			return nil, nil
		}

		if isRedirectStatus(status) && enqueuedRedirects < maxRedirectTargets {
			if nextURL, ok := resolveSameOriginRedirect(targetURL, headers.Get("Location"), rootURL); ok && !visited[nextURL] {
				visited[nextURL] = true
				queue = append(queue, nextURL)
				enqueuedRedirects++
			}
		}

		res, err := m.verifyStartupFilesDifferential(ctx, client, targetURL, defaultPHPSessionName, body)
		if err != nil {
			return nil, err
		}
		if res != nil {
			return res, nil
		}

		endpointCustomNames := extractCustomSessionNamesFromHeaders(headers.Values("Set-Cookie"))
		for _, customSessionName := range endpointCustomNames {
			_, customHeaders, customBody, customOK, err := m.sendMultipartProbe(ctx, client, targetURL, customSessionName, true)
			if err != nil {
				return nil, err
			}
			if !customOK {
				continue
			}
			if hasKnownPatchedHeaderVersion(customHeaders) {
				return nil, nil
			}
			customRes, err := m.verifyStartupFilesDifferential(ctx, client, targetURL, customSessionName, customBody)
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
				_, customHeaders, customBody, customOK, err := m.sendMultipartProbe(ctx, client, targetURL, crawledSessionName, true)
				if err != nil {
					return nil, err
				}
				if !customOK {
					continue
				}
				if hasKnownPatchedHeaderVersion(customHeaders) {
					return nil, nil
				}
				customRes, err := m.verifyStartupFilesDifferential(ctx, client, targetURL, crawledSessionName, customBody)
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

func resolveSameOriginRedirect(baseURL string, location string, rootURL string) (string, bool) {
	trimmed := strings.TrimSpace(location)
	if trimmed == "" {
		return "", false
	}
	baseU, err := url.Parse(baseURL)
	if err != nil {
		return "", false
	}
	locU, err := url.Parse(trimmed)
	if err != nil {
		return "", false
	}
	resolved := baseU.ResolveReference(locU)
	resolved.Fragment = ""
	resolved.RawFragment = ""
	candidate := resolved.String()
	if !isSameOriginAndSafeURL(candidate, rootURL) {
		return "", false
	}
	return candidate, true
}

func hasKnownPatchedServiceVersion(service *nspb.NetworkService) bool {
	if checkSoftwareVersionSet(service.GetSoftware(), service.GetVersionSet()) {
		return true
	}
	wsc := service.GetServiceContext().GetWebServiceContext()
	return checkSoftwareVersionSet(wsc.GetSoftware(), wsc.GetVersionSet())
}

func checkSoftwareVersionSet(sw *spb.Software, vs *spb.VersionSet) bool {
	if !strings.EqualFold(sw.GetName(), "php") {
		return false
	}
	for _, v := range vs.GetVersions() {
		raw := strings.TrimSpace(v.GetFullVersionString())
		if m := rawPHPVersionPattern.FindStringSubmatch(raw); len(m) >= 4 {
			if isPatchedPHPVersionTuple(m[1], m[2], m[3], m[4]) {
				return true
			}
		}
	}
	return false
}

func hasKnownPatchedHeaderVersion(headers http.Header) bool {
	for _, headerName := range []string{"X-Powered-By", "Server"} {
		for _, val := range headers.Values(headerName) {
			for _, m := range phpHeaderVersionPattern.FindAllStringSubmatch(val, -1) {
				if len(m) >= 4 && isPatchedPHPVersionTuple(m[1], m[2], m[3], m[4]) {
					return true
				}
			}
		}
	}
	return false
}

func isPatchedPHPVersionTuple(majorStr, minorStr, patchStr, suffix string) bool {
	major, err1 := strconv.Atoi(majorStr)
	minor, err2 := strconv.Atoi(minorStr)
	patch, err3 := strconv.Atoi(patchStr)
	if err1 != nil || err2 != nil || err3 != nil {
		return false
	}
	if major > 8 || (major == 8 && minor >= 6) {
		return true
	}
	if major == 8 {
		if (minor == 5 && patch >= 13) ||
			(minor == 4 && patch >= 28) ||
			(minor == 3 && patch >= 37) ||
			(minor == 2 && patch >= 36) {
			return true
		}
		if minor == 3 && patch == 6 {
			if sub := ubuntu2404BackportPattern.FindStringSubmatch(suffix); len(sub) == 2 {
				rev, err := strconv.Atoi(sub[1])
				return err == nil && rev >= 14
			}
		}
		if minor == 1 && patch == 2 {
			if sub := ubuntu2204BackportPattern.FindStringSubmatch(suffix); len(sub) == 2 {
				rev, err := strconv.Atoi(sub[1])
				return err == nil && rev >= 29
			}
		}
	}
	return false
}

func (m *Module) verifyStartupFilesDifferential(
	ctx context.Context,
	client goohttp.Client,
	targetURL string,
	sessionName string,
	probeBody string,
) (*verificationResult, error) {
	matchedFilesWarning, ok := extractMatchedStartupFilesWarning(probeBody)
	if !ok {
		return nil, nil
	}

	_, controlHeaders, controlBody, controlOK, err := m.sendMultipartProbe(ctx, client, targetURL, sessionName, false)
	if err != nil {
		return nil, err
	}
	if !controlOK || hasKnownPatchedHeaderVersion(controlHeaders) {
		return nil, nil
	}

	if _, stillPresent := extractMatchedStartupFilesWarning(controlBody); stillPresent {
		// NOMUTANTS -- diagnostic logging does not affect detection output.
		log.DebugContextf(ctx, log.DebugLevelService, "ignoring non-differential startup warning text on %q", targetURL)
		return nil, nil
	}

	// NOMUTANTS -- diagnostic logging does not affect detection output.
	log.InfoContextf(ctx, "verified unpatched PHP session.upload_progress startup handler on 'files' session storage at %q (session parameter %q)", targetURL, sessionName)
	return &verificationResult{
		targetURL:      targetURL,
		sessionName:    sessionName,
		matchedWarning: matchedFilesWarning,
	}, nil
}

func extractMatchedStartupFilesWarning(body string) (string, bool) {
	// NOMUTANTS -- fast-path substring pre-filter; regexes below enforce the full pattern.
	if !strings.Contains(body, invalidSIDSubstring) || !strings.Contains(body, failedFilesReadSubstring) {
		return "", false
	}
	if !startupInvalidSIDWarningPattern.MatchString(body) {
		return "", false
	}
	filesMatch := startupFilesReadWarningPattern.FindString(body)
	if filesMatch == "" {
		return "", false
	}
	sanitized := htmlTagPattern.ReplaceAllString(filesMatch, "")
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

func targetURLs(service *nspb.NetworkService) (string, []string, error) {
	rootURL, err := buildWebRootURL(service)
	if err != nil {
		return "", nil, err
	}

	seen := make(map[string]bool)
	var urls []string
	addTarget := func(u string) {
		if !seen[u] {
			seen[u] = true
			urls = append(urls, u)
		}
	}

	crawlResults := service.GetServiceContext().GetWebServiceContext().GetCrawlResults()
	addedCrawledPHPURLs := 0
	for _, cr := range crawlResults {
		if addedCrawledPHPURLs >= maxCrawledPHPURLs {
			break
		}
		if int(cr.GetResponseCode()) == http.StatusNotFound {
			continue
		}
		crawledURL := cr.GetCrawlTarget().GetUrl()
		if isPHPURL(crawledURL, rootURL) {
			addTarget(crawledURL)
			addedCrawledPHPURLs++
		}
	}
	if addedCrawledPHPURLs == 0 {
		for _, cr := range crawlResults {
			crawledURL := cr.GetCrawlTarget().GetUrl()
			if isPHPURL(crawledURL, rootURL) {
				addTarget(crawledURL)
				addedCrawledPHPURLs++
				break
			}
		}
	}

	for _, subpath := range candidatePaths {
		addTarget(rootURL + subpath)
	}

	if addedCrawledPHPURLs == 0 {
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

	return rootURL, urls, nil
}

func isSameOriginAndSafeURL(candidateURL string, rootURL string) bool {
	u, err := url.Parse(candidateURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false
	}
	rootU, err := url.Parse(rootURL)
	if err != nil {
		return false
	}
	if !strings.EqualFold(u.Scheme, rootU.Scheme) || !strings.EqualFold(u.Host, rootU.Host) {
		return false
	}
	decodedPath, err := url.PathUnescape(u.Path)
	if err != nil {
		decodedPath = u.Path
	}
	decodedQuery, err := url.QueryUnescape(u.RawQuery)
	if err != nil {
		decodedQuery = u.RawQuery
	}
	return !destructivePathPattern.MatchString(decodedPath) && !destructivePathPattern.MatchString(decodedQuery)
}

func isExtensionlessHTMLCrawlResult(cr *wcpb.CrawlResult, rootURL string) bool {
	if int(cr.GetResponseCode()) != http.StatusOK || !hasHTMLOrUnsetContentType(cr) {
		return false
	}
	crawledURL := cr.GetCrawlTarget().GetUrl()
	if !strings.HasPrefix(crawledURL, rootURL) || !isSameOriginAndSafeURL(crawledURL, rootURL) {
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

func hasHTMLOrUnsetContentType(cr *wcpb.CrawlResult) bool {
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
	if normalized == "" {
		// Goonami's fp/webidentity stores CONTENT_TYPE_HASH CrawlResults without
		// populating ContentType or ResponseHeaders.
		return true
	}
	return strings.HasPrefix(normalized, "text/html") || strings.HasPrefix(normalized, "application/xhtml+xml")
}

func isPHPURL(candidateURL string, rootURL string) bool {
	if !isSameOriginAndSafeURL(candidateURL, rootURL) {
		return false
	}
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
	boundary := fmt.Sprintf("----TsunamiCve2026126714Boundary%d", tsMillis)
	invalidSID := fmt.Sprintf("tsunami/invalid_sid_%d_%s", tsMillis, invalidSIDPadding)

	var body strings.Builder
	body.WriteString("--")
	body.WriteString(boundary)
	body.WriteString("\r\nContent-Disposition: form-data; name=\"")
	body.WriteString(sessionName)
	body.WriteString("\"\r\n\r\n")
	body.WriteString(invalidSID)
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
	req.Header.Set("Cookie", sessionName+"="+invalidSID)

	resp, err := client.Do(req)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return 0, nil, "", false, ctxErr
		}
		// NOMUTANTS -- diagnostic logging does not affect detection output.
		log.DebugContextf(ctx, log.DebugLevelRequest, "HTTP probe to %q failed: %v", requestURL, err)
		return 0, nil, "", false, nil
	}
	defer resp.Body.Close()

	// NOMUTANTS -- defensive body size bound; exact cap is non-behavioral for normal responses.
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
	if err != nil {
		return targetURL
	}
	hasFragment := u.Fragment != "" || u.RawFragment != ""
	if u.RawQuery == "" && !hasFragment {
		return targetURL
	}
	var filtered []string
	changed := hasFragment
	if u.RawQuery != "" {
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
