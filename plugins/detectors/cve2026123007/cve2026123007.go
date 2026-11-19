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

// Package cve2026123007 detects the NGINX HTTP/2 queued-frame flow-control
// validation bypass and heap buffer overflow vulnerability (CVE-2026-123007).
//
// Safety invariant: Detection is 100% non-destructive. The probe never sends
// RST_STREAM frames; after verifying whether Stream 0 WINDOW_UPDATE ignores
// queued DATA frame bytes held under socket backpressure, it drains pending
// frames and closes the connection cleanly so ngx_http_v2_finalize_connection
// clears stream->queued without triggering any window refund or worker crash.
package cve2026123007

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/log"
	"github.com/google/goonami-scanner/core/module"
	"github.com/google/goonami-scanner/core/net/netendpoint"
	"github.com/google/goonami-scanner/core/net/netservice"

	dpb "github.com/google/tsunami-security-scanner/proto/go/detection_go_proto"
	npb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
	rpb "github.com/google/tsunami-security-scanner/proto/go/reconnaissance_go_proto"
	vpb "github.com/google/tsunami-security-scanner/proto/go/vulnerability_go_proto"
	tspb "google.golang.org/protobuf/types/known/timestamppb"
)

const (
	moduleName = "dt/cve2026123007"

	vulnReportPublisher = "GOOGLE"
	vulnReportID        = "CVE-2026-123007"
	vulnReportTitle     = "NGINX HTTP/2 Queued-Frame Flow-Control Window Validation Bypass Heap Buffer Overflow (CVE-2026-123007)"
	vulnDescription     = "NGINX Open Source versions 1.9.5 through 1.30.6 and 1.31.0 through 1.31.8 (and unpatched NGINX Plus and distribution builds) with HTTP/2 enabled fail to account for unsent DATA frame bytes queued in h2c->last_out when validating connection-level Stream 0 WINDOW_UPDATE increments in ngx_http_v2_state_window_update(). Under TCP send-buffer backpressure, an unauthenticated remote attacker can replenish h2c->send_window to NGX_HTTP_V2_MAX_WINDOW while DATA frames remain queued and then cancel those streams, pushing h2c->send_window past 0x7fffffff and triggering integer wrap-around and heap buffer overflow in worker memory."
	vulnRecommendation  = "Upgrade NGINX Open Source to version 1.30.7 or later (stable) or 1.31.9 or later (mainline), upgrade NGINX Plus to a fixed release per F5 advisory K000164058, or apply your OS distribution security update containing commit e27f5fa84fe6e98505e70bc543b748747dad0a3b. If immediate patching is not possible, disable direct HTTP/2 termination ('http2 off;')."

	defaultTimeout         = 8 * time.Second
	defaultInterBatchDelay = 20 * time.Millisecond
	defaultPreDrainDelay   = 15 * time.Millisecond
	maxCrawledCandidates   = 3
)

// staticAssetExtensions filters bonus candidate URLs from crawler results and
// HTML links to read-only, deterministic static assets so Phase 2 bursts avoid
// side-effecting routes. Discovery always falls back to "/" and a random 404.
var staticAssetExtensions = []string{
	".js", ".css", ".html", ".htm", ".svg", ".png", ".ico", ".txt", ".woff2",
}

// Module implements module.VulnDetector for CVE-2026-123007.
type Module struct {
	*module.BaseModule
	timeout         time.Duration
	interBatchDelay time.Duration
	preDrainDelay   time.Duration
	dial            dialFunc
	nowFn           func() time.Time
}

func init() {
	module.RegisterDetector(moduleName, New)
}

// New constructs a CVE-2026-123007 detector module configured from cfg.
func New(ctx context.Context, cfg *config.Config) (module.VulnDetector, error) {
	timeout := defaultTimeout
	if cfg != nil && cfg.TimeoutPerRequest() > 0 {
		timeout = cfg.TimeoutPerRequest()
	}
	return &Module{
		BaseModule:      module.NewBaseModule(moduleName),
		timeout:         timeout,
		interBatchDelay: defaultInterBatchDelay,
		preDrainDelay:   defaultPreDrainDelay,
		dial:            defaultDial,
		nowFn:           time.Now,
	}, nil
}

// Advisories returns the vulnerability advisory metadata reported by this module.
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

// Detect checks whether service terminates HTTP/2 with an unpatched NGINX
// ngx_http_v2 flow-control window validator vulnerable to CVE-2026-123007.
func (m *Module) Detect(ctx context.Context, service *nspb.NetworkService) (*dpb.DetectionReportList, error) {
	ctx = log.ContextForModuleAndService(ctx, m.Name(), service) // NOMUTANTS -- diagnostic logging context
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !isSupportedService(service) {
		return nil, nil
	}

	endpoint := service.GetNetworkEndpoint()
	authorities, err := netendpoint.ToURIAuthorities(endpoint)
	if err != nil {
		return nil, err
	}
	port := endpoint.GetPort().GetPortNumber()
	if port == 0 || port > 65535 {
		return nil, nil
	}

	// Rely on fp/sslsupport (netservice.HasTLS) to pick TLS h2 vs cleartext h2c.
	mode := transportH2C
	if netservice.HasTLS(service) {
		mode = transportH2TLS
	}
	target, ok := buildProbeTarget(mode, authorities, endpoint, port)
	if !ok {
		return nil, nil
	}

	crawledPaths := crawledCandidatePaths(service, maxCrawledCandidates)
	ev, err := m.probeTarget(ctx, target, crawledPaths)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}
	// NOMUTANTS -- diagnostic logging only; probeTarget always returns nil ev on error so ev == nil below returns (nil, nil)
	if err != nil {
		log.DebugContextf(ctx, log.DebugLevelService, "HTTP/2 %s flow-control probe on %s did not match: %v", target.mode, target.dialAddr, err)
		return nil, nil
	}
	if ev == nil {
		return nil, nil
	}
	return m.buildDetectionReport(service, ev), nil
}

func isSupportedService(service *nspb.NetworkService) bool {
	// Allow UNSPECIFIED because ps/noop and ps/httpscan leave TransportProtocol unset.
	tp := service.GetTransportProtocol()
	if tp != npb.TransportProtocol_TRANSPORT_PROTOCOL_UNSPECIFIED && tp != npb.TransportProtocol_TCP {
		return false
	}
	return netservice.IsWebService(service)
}

func crawledCandidatePaths(service *nspb.NetworkService, limit int) []string {
	var paths []string
	seen := map[string]bool{"/": true}
	for _, cr := range service.GetServiceContext().GetWebServiceContext().GetCrawlResults() {
		p, ok := extractSafeLocalPath(cr.GetCrawlTarget().GetUrl(), "")
		if !ok || seen[p] || !hasStaticAssetExtension(p) {
			continue
		}
		seen[p] = true
		paths = append(paths, p)
		if len(paths) >= limit {
			break
		}
	}
	return paths
}

func hasStaticAssetExtension(p string) bool {
	lower := strings.ToLower(p)
	for _, ext := range staticAssetExtensions {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

func (m *Module) buildDetectionReport(service *nspb.NetworkService, ev *probeMatch) *dpb.DetectionReportList {
	detailText := fmt.Sprintf(
		"Verified unpatched NGINX ngx_http_v2 flow-control window validation over HTTP/2 (%s) at %s://%s%s "+
			"(settings_len=%d, max_concurrent_streams=%d, static_body_bytes=%d, burst_streams=%d, tail_refused_streams=%d, "+
			"stream0_window_update=%d accepted with queued DATA frames in h2c->last_out and verified by pre/post/liveness PING ACKs).",
		ev.mode,
		ev.scheme,
		ev.authority,
		ev.path,
		ev.settingsPayloadLen,
		ev.maxStreams,
		ev.bodyLen,
		ev.burstStreams,
		ev.refusedStreams,
		ev.windowUpdateIncrement,
	)

	vuln := baseVulnerability()
	vuln.SetAdditionalDetails([]*vpb.AdditionalDetail{
		vpb.AdditionalDetail_builder{
			Description: "Non-destructive NGINX HTTP/2 queued-frame Stream 0 WINDOW_UPDATE verification evidence",
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
