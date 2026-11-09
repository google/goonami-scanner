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

// Package cameloauthbypass detects the Apache Camel camel-oauth fail-open
// authentication bypass vulnerability (CVE-2026-80312 / CAMEL-24411).
package cameloauthbypass

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strings"

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
	moduleName        = "dt/cameloauthbypass"
	sessionCookieName = "camel.oauth.session"
	maxBodySize       = 64 * 1024
)

var defaultPaths = []string{
	"/",
	"/protected",
	"/bearer",
	"/api",
	"/auth",
	"/callback",
	"/oauth/callback",
	"/admin",
	"/login",
}

// Module implements the module.VulnDetector interface for Apache Camel
// camel-oauth fail-open authentication bypass detection (CVE-2026-80312).
type Module struct {
	*module.BaseModule
	config *config.Config
	client goohttp.Client
}

func init() {
	module.RegisterDetector(moduleName, New)
}

// New returns a new instance of the Apache Camel camel-oauth authentication
// bypass detector.
func New(ctx context.Context, cfg *config.Config) (module.VulnDetector, error) {
	opts := goohttp.DefaultClientOptions()
	opts.DisableFollowRedirects = true
	client, err := goohttp.NewClient(cfg, opts)
	if err != nil {
		return nil, err
	}
	return &Module{
		BaseModule: module.NewBaseModule(moduleName),
		config:     cfg,
		client:     client,
	}, nil
}

// Advisories returns the base vulnerability metadata reported by this module.
func (m *Module) Advisories() []*vpb.Vulnerability {
	return []*vpb.Vulnerability{baseVulnerability()}
}

func baseVulnerability() *vpb.Vulnerability {
	return vpb.Vulnerability_builder{
		MainId: vpb.VulnerabilityId_builder{
			Publisher: "GOOGLE",
			Value:     "APACHE_CAMEL_OAUTH_AUTH_BYPASS",
		}.Build(),
		RelatedId: []*vpb.VulnerabilityId{
			vpb.VulnerabilityId_builder{
				Publisher: "CVE",
				Value:     "CVE-2026-80312",
			}.Build(),
		},
		Severity:       vpb.Severity_CRITICAL,
		Title:          "Apache Camel camel-oauth Fail-Open Authentication Bypass (CVE-2026-80312)",
		Description:    "The Apache Camel application using camel-oauth (versions 4.11.0 to 4.18.4 and 4.19.0 to 4.22.0) is vulnerable to an authentication bypass. When OAuthBearerTokenProcessor, OAuthCodeFlowProcessor, or OAuthCodeFlowCallback rejects an unauthenticated request or initiates an OIDC redirect, it returns from process(Exchange) without calling exchange.setRouteStop(true), allowing downstream protected route steps to execute and return protected response data.",
		Recommendation: "Upgrade Apache Camel (org.apache.camel:camel-oauth) to version 4.18.5, 4.22.1, or 4.23.0 or later.",
	}.Build()
}

// Detect probes the target web service for the Apache Camel camel-oauth
// fail-open authentication bypass vulnerability across OAuthCodeFlowProcessor,
// OAuthCodeFlowCallback, and OAuthBearerTokenProcessor endpoints.
func (m *Module) Detect(ctx context.Context, service *nspb.NetworkService) (*dpb.DetectionReportList, error) {
	ctx = log.ContextForModuleAndService(ctx, m.Name(), service)
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if !isSupportedService(service) {
		return nil, nil
	}

	webRoot, err := netservice.BuildWebRoot(service)
	if err != nil {
		return nil, err
	}

	for _, path := range candidatePaths(service) {
		detail, err := m.probePath(ctx, webRoot, path)
		if err != nil {
			return nil, err
		}
		if detail != "" {
			return buildDetectionReport(service, detail), nil
		}
	}

	return nil, nil
}

func isSupportedService(service *nspb.NetworkService) bool {
	proto := service.GetTransportProtocol()
	if proto != npb.TransportProtocol_TRANSPORT_PROTOCOL_UNSPECIFIED && proto != npb.TransportProtocol_TCP {
		return false
	}
	if netservice.IsWebService(service) {
		return true
	}
	name := strings.ToLower(strings.TrimSpace(service.GetServiceName()))
	return name == "" ||
		name == "unknown" ||
		name == "ssl/unknown" ||
		name == "tcpwrapped" ||
		name == "rtsp" ||
		name == "sip" ||
		strings.Contains(name, "http")
}

func candidatePaths(service *nspb.NetworkService) []string {
	seen := make(map[string]bool)
	var paths []string
	addPath := func(p string) {
		if strings.HasPrefix(p, "/") && !seen[p] {
			seen[p] = true
			paths = append(paths, p)
		}
	}

	for _, cr := range service.GetServiceContext().GetWebServiceContext().GetCrawlResults() {
		u, err := url.Parse(cr.GetCrawlTarget().GetUrl())
		if err == nil {
			addPath(u.Path)
		}
	}
	for _, p := range defaultPaths {
		addPath(p)
	}
	return paths
}

func (m *Module) probePath(ctx context.Context, webRoot, path string) (string, error) {
	nonce := newNonce()
	targetURL := webRoot + path
	resp, body, err := m.sendGet(ctx, targetURL+"?camel_probe="+nonce, "")
	if err != nil {
		return "", err
	}

	if resp.StatusCode == http.StatusFound {
		if isVulnerableCodeFlowRedirect(resp, body, nonce) {
			return fmt.Sprintf("OAuthCodeFlowProcessor on %q returned HTTP 302 with camel.oauth.session cookie, OIDC authorization redirect, and non-empty downstream route body (%d bytes).", path, len(body)), nil
		}
		return "", nil
	}

	if resp.StatusCode != http.StatusBadRequest || !isCandidateFailOpen400(resp, body, nonce) {
		return "", nil
	}

	cbOK, err := m.verifyCodeFlowCallback(ctx, targetURL, body)
	if err != nil {
		return "", err
	}
	if cbOK {
		return fmt.Sprintf("OAuthCodeFlowCallback on %q returned HTTP 400 with downstream route body (%d bytes) when the code parameter was omitted and set camel.oauth.session when code was supplied.", path, len(body)), nil
	}

	bearerOK, err := m.verifyBearerTokenProcessor(ctx, targetURL, body)
	if err != nil {
		return "", err
	}
	if bearerOK {
		return fmt.Sprintf("OAuthBearerTokenProcessor on %q returned HTTP 400 with downstream route body (%d bytes) on missing and non-Bearer Authorization headers while aborting with HTTP 500 on an invalid Bearer token.", path, len(body)), nil
	}

	return "", nil
}

func isVulnerableCodeFlowRedirect(resp *http.Response, body, nonce string) bool {
	if !hasCamelOAuthSessionCookie(resp) {
		return false
	}
	loc := resp.Header.Get("Location")
	if !strings.Contains(loc, "response_type=code") ||
		!strings.Contains(loc, "client_id=") ||
		!strings.Contains(loc, "redirect_uri=") ||
		strings.Contains(loc, nonce) {
		return false
	}
	htmlEscapedLoc := strings.ReplaceAll(loc, "&", "&amp;")
	if body == "" ||
		strings.Contains(body, nonce) ||
		strings.Contains(body, loc) ||
		strings.Contains(body, htmlEscapedLoc) {
		return false
	}
	lower := strings.ToLower(body)
	return !strings.HasPrefix(lower, "found") &&
		!strings.HasPrefix(lower, "redirecting") &&
		!strings.HasPrefix(lower, "moved") &&
		!strings.Contains(lower, "302 found") &&
		!strings.Contains(lower, "moved temporarily")
}

func isCandidateFailOpen400(resp *http.Response, body, nonce string) bool {
	if resp.Header.Get("WWW-Authenticate") != "" {
		return false
	}
	if body == "" || strings.Contains(body, nonce) {
		return false
	}
	return body != "Authorization header" &&
		body != "Invalid Authorization header" &&
		body != "Authorization code missing" &&
		body != "No authorization code flow in progress"
}

func (m *Module) verifyCodeFlowCallback(ctx context.Context, targetURL, baselineBody string) (bool, error) {
	nonce := newNonce()
	resp, body, err := m.sendGet(ctx, targetURL+"?code="+nonce, "")
	if err != nil {
		return false, err
	}
	if !hasCamelOAuthSessionCookie(resp) || body == baselineBody {
		return false, nil
	}
	return resp.StatusCode == http.StatusInternalServerError ||
		(resp.StatusCode == http.StatusBadRequest && body == "No authorization code flow in progress"), nil
}

func (m *Module) verifyBearerTokenProcessor(ctx context.Context, targetURL, baselineBody string) (bool, error) {
	nonce := newNonce()
	basicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("camel:"+nonce))
	respBasic, bodyBasic, err := m.sendGet(ctx, targetURL, basicAuth)
	if err != nil {
		return false, err
	}
	if respBasic.StatusCode != http.StatusBadRequest ||
		respBasic.Header.Get("WWW-Authenticate") != "" ||
		bodyBasic != baselineBody {
		return false, nil
	}

	respTwoSpace, bodyTwoSpace, err := m.sendGet(ctx, targetURL, "Bearer  "+nonce)
	if err != nil {
		return false, err
	}
	if respTwoSpace.StatusCode != http.StatusBadRequest ||
		respTwoSpace.Header.Get("WWW-Authenticate") != "" ||
		bodyTwoSpace != baselineBody {
		return false, nil
	}

	respBearer, bodyBearer, err := m.sendGet(ctx, targetURL, "Bearer "+nonce)
	if err != nil {
		return false, err
	}
	return respBearer.StatusCode == http.StatusInternalServerError &&
		(bodyBearer == "" ||
			strings.Contains(bodyBearer, "OAuthException") ||
			strings.Contains(bodyBearer, "org.apache.camel.oauth")), nil
}

func hasCamelOAuthSessionCookie(resp *http.Response) bool {
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookieName && c.Value != "" {
			return true
		}
	}
	return false
}

func (m *Module) sendGet(ctx context.Context, targetURL, authHeader string) (*http.Response, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, "", err
	}
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	rawBody, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	if err != nil {
		return nil, "", err
	}
	return resp, strings.TrimSpace(string(rawBody)), nil
}

func newNonce() string {
	return fmt.Sprintf("camelprobe%016x", rand.Uint64())
}

func buildDetectionReport(service *nspb.NetworkService, detail string) *dpb.DetectionReportList {
	vuln := baseVulnerability()
	vuln.SetAdditionalDetails([]*vpb.AdditionalDetail{
		vpb.AdditionalDetail_builder{
			Description: "Apache Camel camel-oauth fail-open route execution verified",
			TextData: vpb.TextData_builder{
				Text: detail,
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
