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

// Package cve20171000353 detects Jenkins CLI Deserialization Remote Code
// Execution (CVE-2017-1000353).
package cve20171000353

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
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
	tspb "google.golang.org/protobuf/types/known/timestamppb"
)

const (
	moduleName = "dt/cve20171000353"

	vulnReportPublisher = "GOOGLE"
	vulnReportID        = "CVE_2017_1000353"
	vulnReportTitle     = "Jenkins CLI Deserialization Remote Code Execution (CVE-2017-1000353)"
	vulnDescription     = "Jenkins CLI over HTTP (/cli) opens two concurrent connections (Side: download and Side: upload) with the same Session UUID. In vulnerable Jenkins (<=2.56 and LTS <=2.46.1), the server responds on the download stream with the remoting capability preamble and accepts serialized Java objects without authentication. In patched Jenkins (2.57+ and LTS 2.46.2+, SECURITY-422), remoting over HTTP CLI is disabled by default and returns 403 Forbidden. This detector safely and non-destructively verifies the unauthenticated remoting capability negotiation over /cli without executing serialized exploit gadgets or altering files."
	vulnRecommendation  = "Upgrade Jenkins to version 2.57 or LTS 2.46.2 or later where remoting over HTTP CLI is disabled. If unable to upgrade immediately, disable the CLI over HTTP endpoint or block access to /cli."

	preambleRemoting = "<===[JENKINS REMOTINGCAPACITY]===>"
	maxResponseBytes = 4096
)

var knownWebServiceNames = map[string]bool{
	"http":       true,
	"http-alt":   true,
	"http-proxy": true,
	"https":      true,
	"jenkins":    true,
	"jetty":      true,
	"unknown":    true,
}

// Module implements the module.VulnDetector interface for CVE-2017-1000353.
type Module struct {
	*module.BaseModule
	config *config.Config
	nowFn  func() time.Time
}

func init() {
	module.RegisterDetector(moduleName, New)
}

// New returns a new instance of the CVE-2017-1000353 detector module.
func New(ctx context.Context, cfg *config.Config) (module.VulnDetector, error) {
	return &Module{
		BaseModule: module.NewBaseModule(moduleName),
		config:     cfg,
		nowFn:      time.Now,
	}, nil
}

// Advisories returns the vulnerability metadata reported by this module.
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
				Value:     "CVE-2017-1000353",
			}.Build(),
		},
		Severity:       vpb.Severity_CRITICAL,
		Title:          vulnReportTitle,
		Description:    vulnDescription,
		Recommendation: vulnRecommendation,
	}.Build()
}

// Detect probes the target web service for Jenkins CLI remoting capability negotiation.
func (m *Module) Detect(ctx context.Context, service *nspb.NetworkService) (*dpb.DetectionReportList, error) {
	ctx = log.ContextForModuleAndService(ctx, m.Name(), service)
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if !isCandidateService(service) {
		return nil, nil
	}

	cliURLs, err := getCandidateCLIURLs(service)
	if err != nil {
		return nil, err
	}

	opts := goohttp.DefaultClientOptions()
	opts.DisableFollowRedirects = true
	client, err := goohttp.NewClient(m.config, opts)
	if err != nil {
		return nil, err
	}

	for _, cliURL := range cliURLs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		vulnerable, err := m.probeCLI(ctx, client, cliURL)
		if err != nil {
			log.DebugContextf(ctx, log.DebugLevelRequest, "probeCLI error for %q: %v", cliURL, err)
			continue
		}
		if vulnerable {
			log.InfoContextf(ctx, "verified Jenkins CLI remoting capability negotiation on %q (CVE-2017-1000353)", cliURL)
			return m.buildDetectionReport(service), nil
		}
	}

	return nil, nil
}

func isCandidateService(service *nspb.NetworkService) bool {
	if netservice.IsWebService(service) {
		return true
	}
	name := strings.ToLower(strings.TrimSpace(service.GetServiceName()))
	return knownWebServiceNames[name]
}

func getCandidateCLIURLs(service *nspb.NetworkService) ([]string, error) {
	webRoot, err := netservice.BuildWebRoot(service)
	if err != nil {
		return nil, err
	}
	base := strings.TrimRight(webRoot, "/") + "/"

	appRoot := strings.TrimSpace(service.GetServiceContext().GetWebServiceContext().GetApplicationRoot())
	if appRoot != "" {
		if strings.HasPrefix(appRoot, "http://") || strings.HasPrefix(appRoot, "https://") {
			base = strings.TrimRight(appRoot, "/") + "/"
		} else {
			trimmed := strings.Trim(appRoot, "/")
			if trimmed != "" {
				base = strings.TrimRight(webRoot, "/") + "/" + trimmed + "/"
			}
		}
	}

	candidates := []string{
		base + "cli",
	}
	if !strings.HasSuffix(base, "/jenkins/") {
		candidates = append(candidates, base+"jenkins/cli")
	}
	return candidates, nil
}

type downloadResult struct {
	statusCode int
	body       []byte
	err        error
}

func (m *Module) probeCLI(ctx context.Context, client goohttp.Client, cliURL string) (bool, error) {
	sessionID, err := generateSessionID()
	if err != nil {
		return false, fmt.Errorf("generateSessionID: %w", err)
	}

	ch := make(chan downloadResult, 1)

	// Goroutine to initiate download stream.
	go func() {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, cliURL, nil)
		if err != nil {
			ch <- downloadResult{err: err}
			return
		}
		req.Header.Set("Side", "download")
		req.Header.Set("Session", sessionID)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "*/*")

		resp, err := client.Do(req)
		if err != nil {
			ch <- downloadResult{err: err}
			return
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
		ch <- downloadResult{
			statusCode: resp.StatusCode,
			body:       body,
			err:        err,
		}
	}()

	// Allow 80ms for server to receive and register download stream.
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	case <-time.After(80 * time.Millisecond):
	}

	// Send upload stream exchanging remoting preamble.
	uploadPayload := []byte(preambleRemoting)
	reqUp, err := http.NewRequestWithContext(ctx, http.MethodPost, cliURL, bytes.NewReader(uploadPayload))
	if err != nil {
		return false, err
	}
	reqUp.Header.Set("Side", "upload")
	reqUp.Header.Set("Session", sessionID)
	reqUp.Header.Set("Content-Type", "application/octet-stream")
	reqUp.Header.Set("Content-Length", fmt.Sprintf("%d", len(uploadPayload)))

	respUp, err := client.Do(reqUp)
	if err != nil {
		log.DebugContextf(ctx, log.DebugLevelRequest, "upload request to %q failed: %v", cliURL, err)
	} else {
		respUp.Body.Close()
	}

	var res downloadResult
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	case res = <-ch:
	}

	if res.err != nil {
		return false, nil
	}

	// Vulnerable condition:
	// Server responds 200 OK on download stream with the remoting capability preamble.
	if res.statusCode == http.StatusOK && bytes.Contains(res.body, []byte(preambleRemoting)) {
		return true, nil
	}

	return false, nil
}

func generateSessionID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40 // Version 4
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

func (m *Module) buildDetectionReport(service *nspb.NetworkService) *dpb.DetectionReportList {
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
				Vulnerability:      baseVulnerability(),
			}.Build(),
		},
	}.Build()
}
