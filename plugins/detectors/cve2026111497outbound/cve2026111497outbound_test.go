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

package cve2026111497outbound

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/google/goonami-scanner/common/callbackserver/cbid"
	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/module"
	_ "github.com/google/goonami-scanner/core/net/http/simpleclient"

	dpb "github.com/google/tsunami-security-scanner/proto/go/detection_go_proto"
	npb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
	vpb "github.com/google/tsunami-security-scanner/proto/go/vulnerability_go_proto"
	wcpb "github.com/google/tsunami-security-scanner/proto/go/web_crawl_go_proto"
)

func newTestWebService(t *testing.T, s *httptest.Server) *nspb.NetworkService {
	t.Helper()
	u, err := url.Parse(s.URL)
	if err != nil {
		t.Fatalf("url.Parse(%q) failed: %v", s.URL, err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatalf("strconv.Atoi(%q) failed: %v", u.Port(), err)
	}

	return nspb.NetworkService_builder{
		NetworkEndpoint: npb.NetworkEndpoint_builder{
			Type: npb.NetworkEndpoint_IP_HOSTNAME,
			IpAddress: npb.IpAddress_builder{
				Address: u.Hostname(),
			}.Build(),
			Port: npb.Port_builder{
				PortNumber: uint32(port),
			}.Build(),
		}.Build(),
		SupportedHttpMethods: []string{"GET", "POST"},
	}.Build()
}

func TestPluginRegistration(t *testing.T) {
	ctx := t.Context()
	cfg := config.Default()

	detectors, err := module.AllDetectors(ctx, cfg)
	if err != nil {
		t.Fatalf("module.AllDetectors() failed: %v", err)
	}
	found := false
	for _, det := range detectors {
		if det.Name() == moduleName {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("moduleName %q not found in registered detectors: %v", moduleName, detectors)
	}
}

func TestAdvisories(t *testing.T) {
	det := &Module{
		BaseModule: module.NewBaseModule(moduleName),
	}
	advisories := det.Advisories()
	if len(advisories) != 1 {
		t.Fatalf("len(Advisories()) = %d, want 1", len(advisories))
	}
	adv := advisories[0]
	if adv.GetMainId().GetPublisher() != vulnerabilityReportPublisher || adv.GetMainId().GetValue() != vulnerabilityReportID {
		t.Errorf("MainId = %v, want %s/%s", adv.GetMainId(), vulnerabilityReportPublisher, vulnerabilityReportID)
	}
	if adv.GetSeverity() != vpb.Severity_CRITICAL {
		t.Errorf("Severity = %v, want CRITICAL", adv.GetSeverity())
	}
	if adv.GetTitle() != vulnerabilityReportTitle {
		t.Errorf("Title = %q, want %q", adv.GetTitle(), vulnerabilityReportTitle)
	}
}

func TestDetect_SkipsNonWebService(t *testing.T) {
	ctx := t.Context()
	cfg := config.Default()
	det, err := New(ctx, cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	nonWebService := nspb.NetworkService_builder{
		NetworkEndpoint: npb.NetworkEndpoint_builder{
			Port: npb.Port_builder{PortNumber: 80}.Build(),
		}.Build(),
	}.Build()

	reports, err := det.Detect(ctx, nonWebService)
	if err != nil {
		t.Fatalf("Detect() unexpected error: %v", err)
	}
	if reports != nil {
		t.Errorf("Detect() = %v, want nil", reports)
	}
}

func TestDetect_SkipsWhenCallbackServerDisabled(t *testing.T) {
	ctx := t.Context()
	cfg := config.Default()
	det, err := New(ctx, cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	service := newTestWebService(t, ts)
	reports, err := det.Detect(ctx, service)
	if err != nil {
		t.Fatalf("Detect() unexpected error: %v", err)
	}
	if reports != nil {
		t.Errorf("Detect() = %v, want nil", reports)
	}
}

type mockTCSClient struct {
	mu           sync.Mutex
	interactions map[string]bool // cbid -> bool
}

func newMockTCSClient() *mockTCSClient {
	return &mockTCSClient{
		interactions: make(map[string]bool),
	}
}

func (m *mockTCSClient) IsCallbackServerEnabled() bool {
	return true
}

func (m *mockTCSClient) GetHTTPCallbackURI(secret string) (string, error) {
	id, err := cbid.Generate(secret)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("http://callback.local:8080/%s", id), nil
}

func (m *mockTCSClient) HasInteraction(ctx context.Context, secret string) (bool, error) {
	id, err := cbid.Generate(secret)
	if err != nil {
		return false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.interactions[id], nil
}

func (m *mockTCSClient) RecordByCBID(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.interactions[id] = true
}

func TestDetect_NextJsImageOptimizer_Differential(t *testing.T) {
	tests := []struct {
		name          string
		isVulnerable  bool
		wantDetection bool
	}{
		{
			name:          "when_vulnerable_target_reports_vulnerability_verified",
			isVulnerable:  true,
			wantDetection: true,
		},
		{
			name:          "when_patched_target_returns_no_findings",
			isVulnerable:  false,
			wantDetection: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			tcs := newMockTCSClient()

			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/_next/image" {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				sourceURL := r.URL.Query().Get("url")
				if sourceURL == "" {
					w.WriteHeader(http.StatusBadRequest)
					return
				}

				// Simulate target fetching sourceURL from TCS:
				parsed, _ := url.Parse(sourceURL)
				pathParts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
				if len(pathParts) > 0 {
					cbidVal := pathParts[0]
					tcs.RecordByCBID(cbidVal)
				}

				respPreset := parsed.Query().Get("response")
				switch respPreset {
				case presetBrotliValid:
					w.WriteHeader(http.StatusBadRequest)
				case presetBrotliInvalid:
					w.WriteHeader(http.StatusInternalServerError)
				case presetBrotliCVE2026111497:
					if tc.isVulnerable {
						w.WriteHeader(http.StatusBadRequest)
					} else {
						w.WriteHeader(http.StatusInternalServerError)
					}
				default:
					w.WriteHeader(http.StatusBadRequest)
				}
			}))
			defer ts.Close()

			cfg := config.Default()
			detAny, err := New(ctx, cfg)
			if err != nil {
				t.Fatalf("New() failed: %v", err)
			}
			det := detAny.(*Module)
			det.tcsClient = tcs

			service := newTestWebService(t, ts)
			reports, err := det.Detect(ctx, service)
			if err != nil {
				t.Fatalf("Detect() unexpected error: %v", err)
			}

			if tc.wantDetection {
				if reports == nil || len(reports.GetDetectionReports()) != 1 {
					t.Fatalf("Detect() reports = %v, want 1 report", reports)
				}
				rep := reports.GetDetectionReports()[0]
				if rep.GetDetectionStatus() != dpb.DetectionStatus_VULNERABILITY_VERIFIED {
					t.Errorf("DetectionStatus = %v, want VULNERABILITY_VERIFIED", rep.GetDetectionStatus())
				}
			} else {
				if reports != nil && len(reports.GetDetectionReports()) > 0 {
					t.Errorf("Detect() = %v, want no reports", reports)
				}
			}
		})
	}
}

func TestDetect_XmlRpcPingback_Differential(t *testing.T) {
	tests := []struct {
		name                   string
		isVulnerable           bool
		clientRetriesWithoutBr bool
		wantDetection          bool
	}{
		{
			name:                   "when_vulnerable_wordpress_retrying_reports_verified",
			isVulnerable:           true,
			clientRetriesWithoutBr: true,
			wantDetection:          true,
		},
		{
			name:                   "when_vulnerable_drupal_unmasked_reports_verified",
			isVulnerable:           true,
			clientRetriesWithoutBr: false,
			wantDetection:          true,
		},
		{
			name:                   "when_patched_drupal_returns_no_findings",
			isVulnerable:           false,
			clientRetriesWithoutBr: false,
			wantDetection:          false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			tcs := newMockTCSClient()

			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				bodyBytes, _ := io.ReadAll(r.Body)
				body := string(bodyBytes)

				if strings.Contains(body, "system.listMethods") {
					w.Header().Set("Content-Type", "text/xml")
					w.WriteHeader(http.StatusOK)
					fmt.Fprint(w, `<?xml version="1.0"?><methodResponse><params><param><value><array><data><value><string>pingback.ping</string></value></data></array></value></param></params></methodResponse>`)
					return
				}

				if strings.Contains(body, "pingback.ping") {
					start := strings.Index(body, "<string>")
					end := strings.Index(body, "</string>")
					sourceURL := ""
					if start >= 0 && end > start {
						sourceURL = strings.ReplaceAll(body[start+8:end], "&amp;", "&")
					}

					parsed, _ := url.Parse(sourceURL)
					pathParts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
					if len(pathParts) > 0 {
						cbidVal := pathParts[0]
						tcs.RecordByCBID(cbidVal)
					}

					respPreset := parsed.Query().Get("response")
					noBrCbid := parsed.Query().Get("no_br_cbid")

					validFault := faultTargetLinkMissing // 17
					invalidFault := faultSourceNotFound  // 16
					if tc.clientRetriesWithoutBr {
						validFault = faultDefaultMasked   // 0
						invalidFault = faultDefaultMasked // 0
					}

					var faultToReturn int
					switch respPreset {
					case presetBrotliValid:
						faultToReturn = validFault
					case presetBrotliInvalid:
						faultToReturn = invalidFault
						if tc.clientRetriesWithoutBr && noBrCbid != "" {
							tcs.RecordByCBID(noBrCbid)
						}
					case presetBrotliCVE2026111497:
						if tc.isVulnerable {
							faultToReturn = validFault
						} else {
							faultToReturn = invalidFault
							if tc.clientRetriesWithoutBr && noBrCbid != "" {
								tcs.RecordByCBID(noBrCbid)
							}
						}
					default:
						faultToReturn = invalidFault
					}

					w.Header().Set("Content-Type", "text/xml")
					w.WriteHeader(http.StatusOK)
					fmt.Fprintf(w, `<?xml version="1.0"?><methodResponse><fault><value><struct><member><name>faultCode</name><value><int>%d</int></value></member></struct></value></fault></methodResponse>`, faultToReturn)
					return
				}

				w.WriteHeader(http.StatusNotFound)
			}))
			defer ts.Close()

			cfg := config.Default()
			detAny, err := New(ctx, cfg)
			if err != nil {
				t.Fatalf("New() failed: %v", err)
			}
			det := detAny.(*Module)
			det.tcsClient = tcs

			service := newTestWebService(t, ts)
			reports, err := det.Detect(ctx, service)
			if err != nil {
				t.Fatalf("Detect() unexpected error: %v", err)
			}

			if tc.wantDetection {
				if reports == nil || len(reports.GetDetectionReports()) != 1 {
					t.Fatalf("Detect() reports = %v, want 1 report", reports)
				}
				rep := reports.GetDetectionReports()[0]
				if rep.GetDetectionStatus() != dpb.DetectionStatus_VULNERABILITY_VERIFIED {
					t.Errorf("DetectionStatus = %v, want VULNERABILITY_VERIFIED", rep.GetDetectionStatus())
				}
			} else {
				if reports != nil && len(reports.GetDetectionReports()) > 0 {
					t.Errorf("Detect() = %v, want no reports", reports)
				}
			}
		})
	}
}

func TestHelperFunctions(t *testing.T) {
	t.Run("when_allowed_fault_pairs_evaluated", func(t *testing.T) {
		if !isAllowedControlFaultPair(0, 0, true) {
			t.Errorf("isAllowedControlFaultPair(0, 0, true) = false, want true")
		}
		if isAllowedControlFaultPair(0, 0, false) {
			t.Errorf("isAllowedControlFaultPair(0, 0, false) = true, want false")
		}
		if !isAllowedControlFaultPair(17, 16, false) {
			t.Errorf("isAllowedControlFaultPair(17, 16, false) = false, want true")
		}
		if !isAllowedControlFaultPair(32, 16, false) {
			t.Errorf("isAllowedControlFaultPair(32, 16, false) = false, want true")
		}
		if isAllowedControlFaultPair(16, 16, false) {
			t.Errorf("isAllowedControlFaultPair(16, 16, false) = true, want false")
		}
	})

	t.Run("when_pingback_url_normalized", func(t *testing.T) {
		root := "http://example.com:8080/"
		if got := normalizePingbackURL("/xmlrpc.php", root); got != "http://example.com:8080/xmlrpc.php" {
			t.Errorf("normalizePingbackURL(/xmlrpc.php) = %q, want http://example.com:8080/xmlrpc.php", got)
		}
		if got := normalizePingbackURL("http://evil.com/xmlrpc.php", root); got != "" {
			t.Errorf("normalizePingbackURL(evil.com) = %q, want empty string", got)
		}
	})

	t.Run("when_crawl_results_include_pingback_header", func(t *testing.T) {
		service := nspb.NetworkService_builder{
			ServiceContext: nspb.ServiceContext_builder{
				WebServiceContext: nspb.WebServiceContext_builder{
					CrawlResults: []*wcpb.CrawlResult{
						wcpb.CrawlResult_builder{
							CrawlTarget: wcpb.CrawlTarget_builder{
								Url: "http://example.com:8080/blog",
							}.Build(),
							ResponseHeaders: []*wcpb.HttpHeader{
								wcpb.HttpHeader_builder{
									Key:   "X-Pingback",
									Value: "http://example.com:8080/custom-xmlrpc.php",
								}.Build(),
							},
						}.Build(),
					},
				}.Build(),
			}.Build(),
		}.Build()

		det := &Module{}
		candidates := det.discoverXMLRPCCandidates(service, "http://example.com:8080/")
		foundCustom := false
		for _, cand := range candidates {
			if cand.xmlRPCURL == "http://example.com:8080/custom-xmlrpc.php" {
				foundCustom = true
				break
			}
		}
		if !foundCustom {
			t.Errorf("discoverXMLRPCCandidates() did not extract X-Pingback URL, got %v", candidates)
		}
	})
}
