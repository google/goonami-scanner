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

// Package cve2026110264 provides a Goonami detector for CVE-2026-110264 (CVE-2026-97229),
// an unauthenticated Remote Code Execution vulnerability in GitLab CE/EE caused by a
// 16-bit signed integer overflow in Onigmo regular expression range-repeat compilation
// reachable via org-ruby Org-mode #+TODO: keyword rendering.
package cve2026110264

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
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
	moduleName       = "dt/cve2026110264"
	rangeRepeatCount = 32768
	rangeRepeatAtom  = "a{,9}"
	verifiedSentinel = "TSUNAMI_VERIFIED"
	headingSuffix    = "HeadingEnd"
	verifiedMarker   = ">" + verifiedSentinel + " " + headingSuffix + "<"
)

var (
	csrfMetaRegex        = regexp.MustCompile(`<meta\s+name="csrf-token"\s+content="([^"]+)"`)
	exploreProjectRegex  = regexp.MustCompile(`href="/([A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+)"`)
	orgProbePayload      = buildOrgProbePayload()
	reservedPathPrefixes = map[string]bool{
		"-":       true,
		"admin":   true,
		"api":     true,
		"assets":  true,
		"explore": true,
		"groups":  true,
		"help":    true,
		"oauth":   true,
		"uploads": true,
		"users":   true,
	}
)

func init() {
	module.RegisterDetector(moduleName, New)
}

func buildOrgProbePayload() string {
	kw := ".+:|" + strings.Repeat(rangeRepeatAtom, rangeRepeatCount) + ":" + verifiedSentinel
	return "#+TODO: " + kw + "\n* " + kw + " " + headingSuffix + "\n"
}

// Module implements the module.VulnDetector interface for CVE-2026-110264.
type Module struct {
	*module.BaseModule
	cfg *config.Config
}

// New returns a new Module instance for CVE-2026-110264 detection.
func New(ctx context.Context, cfg *config.Config) (module.VulnDetector, error) {
	return &Module{
		BaseModule: module.NewBaseModule(moduleName),
		cfg:        cfg,
	}, nil
}

// Advisories returns the base vulnerability metadata reported by this detector.
func (m *Module) Advisories() []*vpb.Vulnerability {
	return []*vpb.Vulnerability{baseVulnerability()}
}

func baseVulnerability() *vpb.Vulnerability {
	return vpb.Vulnerability_builder{
		MainId: vpb.VulnerabilityId_builder{
			Publisher: "GOOGLE",
			Value:     "CVE-2026-110264",
		}.Build(),
		RelatedId: []*vpb.VulnerabilityId{
			vpb.VulnerabilityId_builder{
				Publisher: "CVE",
				Value:     "CVE-2026-110264",
			}.Build(),
			vpb.VulnerabilityId_builder{
				Publisher: "CVE",
				Value:     "CVE-2026-97229",
			}.Build(),
		},
		Severity: vpb.Severity_CRITICAL,
		Title:    "GitLab CE/EE & Onigmo Regular Expression Range Repeat 16-bit Integer Overflow RCE (CVE-2026-110264)",
		Description: "GitLab Community Edition (CE) and Enterprise Edition (EE) (< 19.3.6, >= 19.4.0 < 19.4.3, " +
			">= 19.5.0 < 19.5.1) bundle an unpatched Ruby Onigmo regular expression engine (CVE-2026-97229) " +
			"together with org-ruby (<= 0.9.12), which passes user-supplied #+TODO: keyword tokens directly " +
			"into Regexp.new without escaping inside Orgmode::Headline#parse_keywords. When an Org-mode document " +
			"contains more than 32,767 range repeat quantifiers (such as a{,9}) in a #+TODO: keyword, " +
			"Onigmo's compile_range_repeat_node increments reg->num_repeat past the signed 16-bit MemNumType " +
			"limit (32,767) without bounds checking, wraps negative into a 32-bit unsigned index during " +
			"match_at, and indexes out-of-bounds before the heap-allocated repeat_stk buffer, enabling " +
			"unauthenticated Remote Code Execution via public project blob preview endpoints " +
			"(POST /<namespace>/<project>/-/preview/<branch>/*blob_path) when at least one public project is accessible.",
		Recommendation: "Upgrade GitLab CE/EE to >= 19.3.6, >= 19.4.3, or >= 19.5.1 (which apply the Onigmo " +
			"(MemNumType)reg->num_repeat <= 0 / ONIGERR_TOO_MANY_RANGE_REPEAT bounds check in regcomp.c), and " +
			"upgrade Ruby to >= 3.3.13 / >= 3.4.10 and org-ruby to >= 0.10.0.",
	}.Build()
}

// Detect checks whether the target web service is a GitLab instance vulnerable to CVE-2026-110264.
func (m *Module) Detect(ctx context.Context, service *nspb.NetworkService) (*dpb.DetectionReportList, error) {
	ctx = log.ContextForModuleAndService(ctx, m.Name(), service) // NOMUTANTS -- attaches diagnostic log metadata to context without altering detection output.
	if !netservice.IsWebService(service) {
		return nil, nil
	}

	webRoot, err := netservice.BuildWebRoot(service)
	if err != nil {
		log.DebugContextf(ctx, log.DebugLevelService, "Failed to build web root: %v", err) // NOMUTANTS -- diagnostic debug logging only.
		return nil, nil
	}
	webRoot = strings.TrimRight(webRoot, "/")

	opts := goohttp.DefaultClientOptions()
	opts.StoreCookies = true
	client, err := goohttp.NewClient(m.cfg, opts)
	if err != nil {
		return nil, err
	}

	csrfToken, isGitLab := m.fetchGitLabCSRF(ctx, client, webRoot)
	if !isGitLab {
		return nil, nil
	}

	targets := m.discoverPublicProjects(ctx, client, webRoot, &csrfToken)
	for _, target := range targets {
		if previewURL, vulnerable := m.probeOrgPreview(ctx, client, webRoot, csrfToken, target); vulnerable {
			return buildDetectionReport(service, previewURL), nil
		}
	}
	return nil, nil
}

type projectTarget struct {
	PathWithNamespace string `json:"path_with_namespace"`
	DefaultBranch     string `json:"default_branch"`
}

func (m *Module) fetchGitLabCSRF(ctx context.Context, client goohttp.Client, webRoot string) (string, bool) {
	status, headers, body, err := doHTTPRequest(ctx, client, http.MethodGet, webRoot+"/users/sign_in", "", nil)
	if err != nil || status != http.StatusOK {
		return "", false
	}
	if !isGitLabResponse(headers, body) {
		return "", false
	}
	token := extractCSRFToken(body)
	if token == "" {
		return "", false
	}
	return token, true
}

func isGitLabResponse(headers http.Header, body string) bool {
	for _, cookie := range headers.Values("Set-Cookie") {
		if strings.Contains(cookie, "_gitlab_session=") {
			return true
		}
	}
	return strings.Contains(body, `content="GitLab"`) ||
		strings.Contains(body, "gon.gitlab_url") ||
		strings.Contains(body, "Sign in · GitLab")
}

func extractCSRFToken(body string) string {
	matches := csrfMetaRegex.FindStringSubmatch(body)
	if len(matches) < 2 {
		return ""
	}
	return matches[1]
}

func (m *Module) discoverPublicProjects(ctx context.Context, client goohttp.Client, webRoot string, csrfToken *string) []projectTarget {
	status, _, body, err := doHTTPRequest(ctx, client, http.MethodGet, webRoot+"/api/v4/projects?simple=true&per_page=5", "", map[string]string{
		"Accept": "application/json",
	})
	var targets []projectTarget
	if err == nil && status == http.StatusOK {
		var apiProjects []projectTarget
		if json.Unmarshal([]byte(body), &apiProjects) == nil {
			for _, p := range apiProjects {
				if p.PathWithNamespace == "" {
					continue
				}
				if p.DefaultBranch == "" {
					targets = append(targets,
						projectTarget{PathWithNamespace: p.PathWithNamespace, DefaultBranch: "main"},
						projectTarget{PathWithNamespace: p.PathWithNamespace, DefaultBranch: "master"},
					)
					continue
				}
				targets = append(targets, p)
			}
		}
	}
	if len(targets) > 0 {
		return targets
	}

	status, _, body, err = doHTTPRequest(ctx, client, http.MethodGet, webRoot+"/explore/projects", "", nil)
	if err != nil || status != http.StatusOK {
		return nil
	}
	if refreshed := extractCSRFToken(body); refreshed != "" {
		*csrfToken = refreshed
	}
	seen := make(map[string]bool)
	for _, match := range exploreProjectRegex.FindAllStringSubmatch(body, -1) {
		path := match[1]
		prefix, _, _ := strings.Cut(path, "/")
		if reservedPathPrefixes[strings.ToLower(prefix)] || strings.Contains(path, "/-/") || strings.HasSuffix(path, "/-") || seen[path] {
			continue
		}
		seen[path] = true
		targets = append(targets,
			projectTarget{PathWithNamespace: path, DefaultBranch: "main"},
			projectTarget{PathWithNamespace: path, DefaultBranch: "master"},
		)
	}
	return targets
}

func (m *Module) probeOrgPreview(ctx context.Context, client goohttp.Client, webRoot, csrfToken string, target projectTarget) (string, bool) {
	previewURL := fmt.Sprintf("%s/%s/-/preview/%s/README.org?file_path=README.org", webRoot, target.PathWithNamespace, target.DefaultBranch)
	form := url.Values{}
	form.Set("file_path", "README.org")
	form.Set("authenticity_token", csrfToken)
	form.Set("content", orgProbePayload)

	status, _, body, err := doHTTPRequest(ctx, client, http.MethodPost, previewURL, form.Encode(), map[string]string{
		"Content-Type":     "application/x-www-form-urlencoded",
		"X-CSRF-Token":     csrfToken,
		"X-Requested-With": "XMLHttpRequest",
	})
	if err != nil || status != http.StatusOK {
		return "", false
	}
	if strings.Contains(body, "<h1") && strings.Contains(body, verifiedMarker) {
		return previewURL, true
	}
	return "", false
}

func doHTTPRequest(ctx context.Context, client goohttp.Client, method, targetURL, formBody string, headers map[string]string) (int, http.Header, string, error) {
	var bodyReader io.Reader
	if formBody != "" {
		bodyReader = strings.NewReader(formBody)
	}
	req, err := http.NewRequestWithContext(ctx, method, targetURL, bodyReader)
	if err != nil {
		return 0, nil, "", err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, "", err
	}
	defer resp.Body.Close() // NOMUTANTS -- response body resource cleanup.

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, "", err
	}
	return resp.StatusCode, resp.Header, string(b), nil
}

func buildDetectionReport(service *nspb.NetworkService, previewURL string) *dpb.DetectionReportList {
	vuln := baseVulnerability()
	vuln.SetAdditionalDetails([]*vpb.AdditionalDetail{
		vpb.AdditionalDetail_builder{
			Description: "Non-destructive 32,768-range-repeat Onigmo/org-ruby differential probe verified on GitLab Org-mode blob preview endpoint",
			TextData: vpb.TextData_builder{
				Text: fmt.Sprintf("Vulnerable endpoint: %s compiled 32,768 Onigmo range-repeat quantifiers without ONIGERR_TOO_MANY_RANGE_REPEAT and rendered unescaped #+TODO: regex keyword output (%s %s).", previewURL, verifiedSentinel, headingSuffix),
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
