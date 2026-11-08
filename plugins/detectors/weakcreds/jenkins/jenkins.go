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

// Package jenkins provides a Goonami weak password detector ("dt/wk/jenkins")
// for Jenkins instances, testing at most 10 common weak administrator
// passwords.
package jenkins

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
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
	moduleName = "dt/wk/jenkins"

	// MaxPasswordAttempts is the hard upper bound on candidate weak passwords
	// tested against a single Jenkins service.
	MaxPasswordAttempts = 10

	defaultUsername      = "admin"
	loginPath            = "/login"
	whoAmIPath           = "/whoAmI/api/json"
	maxResponseBodyBytes = 256 * 1024
)

// ErrConfigNil is returned when New or NewWithOptions is called with a nil
// scanner configuration.
var ErrConfigNil = errors.New("jenkins weakcreds config must not be nil")

// defaultWeakPasswords contains the top 10 common weak Jenkins administrator
// passwords tested in priority order.
var defaultWeakPasswords = []string{
	"admin",
	"password",
	"jenkins",
	"123456",
	"admin123",
	"12345678",
	"password1",
	"qwerty",
	"letmein",
	"welcome",
}

// Options configures optional overrides for the Jenkins weak password detector.
type Options struct {
	// Passwords overrides the default 10 weak passwords tested for "admin". If
	// more than MaxPasswordAttempts entries are supplied, only the first
	// MaxPasswordAttempts (10) are retained.
	Passwords []string
}

// Module implements module.VulnDetector for bounded Jenkins weak administrator
// password detection.
type Module struct {
	*module.BaseModule
	client    goohttp.Client
	passwords []string
}

type whoAmIResponse struct {
	Authenticated *bool  `json:"authenticated"`
	Anonymous     *bool  `json:"anonymous"`
	Name          string `json:"name"`
}

func init() {
	module.RegisterDetector(moduleName, New)
}

// New returns a new Jenkins weak password detector configured with the default
// top-10 weak password list.
func New(ctx context.Context, cfg *config.Config) (module.VulnDetector, error) {
	return NewWithOptions(ctx, cfg, nil)
}

// NewWithOptions returns a new Jenkins weak password detector with optional
// candidate password overrides capped at MaxPasswordAttempts.
func NewWithOptions(_ context.Context, cfg *config.Config, opts *Options) (*Module, error) {
	if cfg == nil {
		return nil, ErrConfigNil
	}

	clientOpts := goohttp.DefaultClientOptions()
	clientOpts.DisableFollowRedirects = true
	client, err := goohttp.NewClient(cfg, clientOpts)
	if err != nil {
		return nil, fmt.Errorf("creating HTTP client for %s: %w", moduleName, err)
	}

	passwords := slices.Clone(defaultWeakPasswords)
	if opts != nil && len(opts.Passwords) > 0 {
		passwords = slices.Clone(opts.Passwords)
	}
	if len(passwords) > MaxPasswordAttempts {
		passwords = passwords[:MaxPasswordAttempts]
	}

	return &Module{
		BaseModule: module.NewBaseModule(moduleName),
		client:     client,
		passwords:  passwords,
	}, nil
}

// Advisories returns the vulnerability metadata reported by this detector.
func (m *Module) Advisories() []*vpb.Vulnerability {
	return []*vpb.Vulnerability{baseVulnerability()}
}

// Passwords returns a copy of the bounded weak password list configured on this
// detector instance.
func (m *Module) Passwords() []string {
	return slices.Clone(m.passwords)
}

// Detect probes candidate HTTP/HTTPS services for a Jenkins password login form
// and tests up to MaxPasswordAttempts weak passwords for the "admin" account,
// stopping on the first verified credential.
func (m *Module) Detect(ctx context.Context, service *nspb.NetworkService) (*dpb.DetectionReportList, error) {
	ctx = log.ContextForModuleAndService(ctx, m.Name(), service)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !isCandidateService(service) {
		return nil, nil
	}

	baseURL, err := buildBaseURL(service)
	if err != nil {
		return nil, err
	}

	ok, err := m.hasJenkinsPasswordLogin(ctx, baseURL)
	if err != nil || !ok {
		return nil, err
	}

	ok, err = m.passesUnauthenticatedControl(ctx, baseURL)
	if err != nil || !ok {
		return nil, err
	}

	for _, password := range m.passwords {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		matched, keepGoing, err := m.tryPassword(ctx, baseURL, defaultUsername, password)
		if err != nil {
			return nil, err
		}
		if matched {
			return buildDetectionReport(service, defaultUsername, password), nil
		}
		if !keepGoing {
			return nil, nil
		}
	}

	return nil, nil
}

func (m *Module) hasJenkinsPasswordLogin(ctx context.Context, baseURL string) (bool, error) {
	resp, body, err := m.sendGet(ctx, baseURL+loginPath, "", "")
	if err != nil || resp == nil {
		return false, err
	}
	if resp.StatusCode != http.StatusOK {
		return false, nil
	}

	hasJenkinsMarker := resp.Header.Get("X-Jenkins") != "" ||
		resp.Header.Get("X-Hudson") != "" ||
		strings.Contains(body, "[Jenkins]")
	hasPasswordForm := strings.Contains(body, "j_spring_security_check") ||
		strings.Contains(body, "j_acegi_security_check") ||
		strings.Contains(body, `name="j_password"`)
	return hasJenkinsMarker && hasPasswordForm, nil
}

func (m *Module) passesUnauthenticatedControl(ctx context.Context, baseURL string) (bool, error) {
	resp, body, err := m.sendGet(ctx, baseURL+whoAmIPath, "", "")
	if err != nil || resp == nil {
		return false, err
	}

	switch resp.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		return true, nil
	case http.StatusOK:
		var parsed whoAmIResponse
		if err := json.Unmarshal([]byte(body), &parsed); err != nil {
			return false, nil
		}
		// Jenkins /whoAmI/api/json is annotated @AlwaysReadable and returns
		// {"anonymous":true,"authenticated":true,"name":"anonymous"} when
		// unauthenticated. Abort if the server already resolves to a non-anonymous
		// session so unauthenticated instances are never misreported as weak creds.
		return parsed.Anonymous != nil && *parsed.Anonymous, nil
	default:
		return false, nil
	}
}

func (m *Module) tryPassword(ctx context.Context, baseURL, username, password string) (matched bool, keepGoing bool, err error) {
	resp, body, err := m.sendGet(ctx, baseURL+whoAmIPath, username, password)
	if err != nil || resp == nil {
		return false, false, err
	}

	switch resp.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		return false, true, nil
	case http.StatusOK:
		return isAuthenticatedUser(body, username), false, nil
	default:
		log.DebugContextf(ctx, log.DebugLevelService, "stopping Jenkins credential attempts after unexpected HTTP status %d", resp.StatusCode)
		return false, false, nil
	}
}

func (m *Module) sendGet(ctx context.Context, targetURL, username, password string) (*http.Response, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Accept", "application/json, text/html;q=0.9")
	if username != "" {
		req.SetBasicAuth(username, password)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, "", ctxErr
		}
		log.DebugContextf(ctx, log.DebugLevelRequest, "Jenkins probe to %q failed: %v", targetURL, err)
		return nil, "", nil
	}
	defer resp.Body.Close()

	bodyBytes, err := goohttp.ReadBody(resp, maxResponseBodyBytes)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, "", ctxErr
	}
	if err != nil {
		return resp, "", nil
	}
	return resp, string(bodyBytes), nil
}

func isAuthenticatedUser(body, username string) bool {
	var parsed whoAmIResponse
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		return false
	}
	return parsed.Authenticated != nil && *parsed.Authenticated &&
		parsed.Anonymous != nil && !*parsed.Anonymous &&
		strings.EqualFold(parsed.Name, username)
}

func isCandidateService(service *nspb.NetworkService) bool {
	if service == nil {
		return false
	}
	proto := service.GetTransportProtocol()
	if proto != npb.TransportProtocol_TRANSPORT_PROTOCOL_UNSPECIFIED && proto != npb.TransportProtocol_TCP {
		return false
	}
	if netservice.IsWebService(service) {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(service.GetServiceName())) {
	case "", "unknown", "tcpwrapped", "jenkins", "http", "http-alt", "http-proxy", "https", "radan-http", "ssl/http", "ssl/https", "ssl/http-proxy":
		return true
	default:
		return false
	}
}

func buildBaseURL(service *nspb.NetworkService) (string, error) {
	webRoot, err := netservice.BuildWebRoot(service)
	if err != nil {
		return "", err
	}
	appRoot := strings.Trim(strings.TrimSpace(service.GetServiceContext().GetWebServiceContext().GetApplicationRoot()), "/")
	if appRoot == "" {
		return webRoot, nil
	}
	return webRoot + "/" + appRoot, nil
}

func baseVulnerability() *vpb.Vulnerability {
	return vpb.Vulnerability_builder{
		MainId: vpb.VulnerabilityId_builder{
			Publisher: "GOOGLE",
			Value:     "WEAK_CREDENTIALS_FOR_JENKINS",
		}.Build(),
		Severity:       vpb.Severity_CRITICAL,
		Title:          "Weak 'jenkins' service credential",
		Description:    "Well known or weak credentials are detected for 'jenkins' service.",
		Recommendation: "Change the password of all affected users to a strong one, or disable local password authentication in favor of SSO/OAuth.",
	}.Build()
}

func buildDetectionReport(service *nspb.NetworkService, username, password string) *dpb.DetectionReportList {
	vuln := baseVulnerability()
	vuln.SetAdditionalDetails([]*vpb.AdditionalDetail{
		vpb.AdditionalDetail_builder{
			Description: "Weak credential found in format username:password",
			TextData: vpb.TextData_builder{
				Text: fmt.Sprintf("%s:%s", username, password),
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
				DetectionTimestamp: tspb.Now(),
				DetectionStatus:    dpb.DetectionStatus_VULNERABILITY_VERIFIED,
				Vulnerability:      vuln,
			}.Build(),
		},
	}.Build()
}
