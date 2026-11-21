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

package cve2026126714

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/goonami-scanner/common/testfakes/fakehttp"
	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/module"
	goohttp "github.com/google/goonami-scanner/core/net/http"
	_ "github.com/google/goonami-scanner/core/net/http/simpleclient"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"

	cpb "github.com/google/goonami-scanner/core/config/config_go_proto"
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
	vulnerablePlainStartupWarnings = "" +
		"Warning: PHP Request Startup: Session ID is too long or contains illegal characters, valid characters are a-z, A-Z, 0-9 and '-,' in Unknown on line 0\n" +
		"Warning: PHP Request Startup: Failed to read session data: files (path: /var/lib/php/sessions) in Unknown on line 0\n"

	vulnerableHTMLStartupWarnings = "" +
		"<br />\n<b>Warning</b>:  PHP Request Startup: Session ID is too long or contains illegal characters, valid characters are a-z, A-Z, 0-9 and '-,' in <b>Unknown</b> on line <b>0</b><br />\n" +
		"<br />\n<b>Warning</b>:  PHP Request Startup: Failed to read session data: files (path: &quot;/tmp&quot;) in <b>Unknown</b> on line <b>0</b><br />\n"
)

var fixedTestTime = time.Date(2026, time.November, 20, 12, 0, 0, 0, time.UTC)

func makeIPPortEndpoint(host string, port uint32) *npb.NetworkEndpoint {
	return npb.NetworkEndpoint_builder{
		Type: npb.NetworkEndpoint_IP_PORT,
		IpAddress: npb.IpAddress_builder{
			Address:       host,
			AddressFamily: npb.AddressFamily_IPV4,
		}.Build(),
		Port: npb.Port_builder{
			PortNumber: port,
		}.Build(),
	}.Build()
}

func webServiceForServer(t *testing.T, serverURL string) *nspb.NetworkService {
	t.Helper()
	u, err := url.Parse(serverURL)
	if err != nil {
		t.Fatalf("url.Parse(%q) failed: %v", serverURL, err)
	}
	portNum, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatalf("strconv.Atoi(%q) failed: %v", u.Port(), err)
	}
	var sslVersions []string
	if u.Scheme == "https" {
		sslVersions = []string{"TLSv1.3"}
	}
	return nspb.NetworkService_builder{
		NetworkEndpoint:      makeIPPortEndpoint(u.Hostname(), uint32(portNum)),
		TransportProtocol:    npb.TransportProtocol_TCP,
		SupportedHttpMethods: []string{"GET", "POST"},
		SupportedSslVersions: sslVersions,
	}.Build()
}

func TestNewAndRegistry(t *testing.T) {
	testCases := []struct {
		name string
		cfg  *config.Config
	}{
		{
			name: "when_nil_config_uses_default_config_and_registers_in_default_registry",
			cfg:  nil,
		},
		{
			name: "when_explicit_config_preserves_config",
			cfg:  config.Default(),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			det, err := New(t.Context(), tc.cfg)
			if err != nil {
				t.Fatalf("New() unexpected error: %v", err)
			}
			if got := det.Name(); got != moduleName {
				t.Errorf("det.Name() = %q, want %q", got, moduleName)
			}
			mod := det.(*Module)
			if mod.config == nil {
				t.Error("mod.config is nil, want non-nil")
			}
			allDets, err := module.AllDetectors(t.Context(), config.Default())
			if err != nil {
				t.Fatalf("module.AllDetectors() unexpected error: %v", err)
			}
			found := false
			for _, d := range allDets {
				if d.Name() == moduleName {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("module.AllDetectors() missing %q", moduleName)
			}
		})
	}
}

func TestAdvisories(t *testing.T) {
	testCases := []struct {
		name string
	}{
		{
			name: "when_called_returns_defensive_clone_of_critical_cve_2026_126714_advisory",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			det, err := New(t.Context(), config.Default())
			if err != nil {
				t.Fatalf("New() unexpected error: %v", err)
			}
			advs := det.Advisories()
			if len(advs) != 1 {
				t.Fatalf("len(Advisories()) = %d, want 1", len(advs))
			}
			got := advs[0]
			if got.GetMainId().GetPublisher() != "GOOGLE" || got.GetMainId().GetValue() != "CVE-2026-126714" {
				t.Errorf("MainId = %v, want GOOGLE/CVE-2026-126714", got.GetMainId())
			}
			if len(got.GetRelatedId()) != 1 || got.GetRelatedId()[0].GetPublisher() != "CVE" || got.GetRelatedId()[0].GetValue() != "CVE-2026-126714" {
				t.Errorf("RelatedId = %v, want [CVE/CVE-2026-126714]", got.GetRelatedId())
			}
			if got.GetSeverity() != vpb.Severity_CRITICAL {
				t.Errorf("Severity = %v, want CRITICAL", got.GetSeverity())
			}
			got.SetTitle("mutated")
			if det.Advisories()[0].GetTitle() == "mutated" {
				t.Error("Advisories() returned shared mutable proto instead of fresh copy")
			}
		})
	}
}

func TestDetect(t *testing.T) {
	testCases := []struct {
		name            string
		handler         http.HandlerFunc
		customizeSvc    func(svc *nspb.NetworkService, baseURL string)
		wantVulnerable  bool
		wantSessionName string
		wantEndpointSfx string
		wantWarning     string
	}{
		{
			name: "when_unpatched_php_files_handler_emits_startup_warnings_only_with_upload_progress_reports_vulnerability",
			handler: func(w http.ResponseWriter, r *http.Request) {
				bodyBytes, _ := io.ReadAll(r.Body)
				body := string(bodyBytes)
				if r.URL.Path == "/index.php" &&
					strings.Contains(body, `name="PHP_SESSION_UPLOAD_PROGRESS"`) &&
					strings.Contains(body, `name="PHPSESSID"`) &&
					strings.Contains(r.Header.Get("Cookie"), "PHPSESSID=tsunami/invalid_sid_") {
					_, _ = w.Write([]byte(vulnerablePlainStartupWarnings + "OK"))
					return
				}
				_, _ = w.Write([]byte("OK"))
			},
			wantVulnerable:  true,
			wantSessionName: "PHPSESSID",
			wantEndpointSfx: "/index.php",
			wantWarning:     "Warning: PHP Request Startup: Failed to read session data: files (path: /var/lib/php/sessions) in Unknown on line 0",
		},
		{
			name: "when_html_formatted_php_startup_warnings_sanitizes_tags_and_entities_in_evidence",
			handler: func(w http.ResponseWriter, r *http.Request) {
				bodyBytes, _ := io.ReadAll(r.Body)
				if r.URL.Path == "/index.php" && strings.Contains(string(bodyBytes), `name="PHP_SESSION_UPLOAD_PROGRESS"`) {
					_, _ = w.Write([]byte(vulnerableHTMLStartupWarnings))
					return
				}
				_, _ = w.Write([]byte("OK"))
			},
			wantVulnerable:  true,
			wantSessionName: "PHPSESSID",
			wantEndpointSfx: "/index.php",
			wantWarning:     `Warning:  PHP Request Startup: Failed to read session data: files (path: "/tmp") in Unknown on line 0`,
		},
		{
			name: "when_patched_php_8_4_28_returns_no_startup_warnings_returns_nil",
			handler: func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte("PHP CVE-2026-126714 testbed ready\n"))
			},
			wantVulnerable: false,
		},
		{
			name: "when_patched_php_8_4_28_with_legacy_ini_re_enables_upload_progress_suppresses_via_x_powered_by",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Powered-By", "PHP/8.4.28")
				bodyBytes, _ := io.ReadAll(r.Body)
				if strings.Contains(string(bodyBytes), `name="PHP_SESSION_UPLOAD_PROGRESS"`) {
					_, _ = w.Write([]byte(vulnerablePlainStartupWarnings))
					return
				}
				_, _ = w.Write([]byte("OK"))
			},
			wantVulnerable: false,
		},
		{
			name: "when_patched_ubuntu_backport_8_3_6_0ubuntu0_24_04_14_advertised_suppresses_finding",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Server", "Apache/2.4.58 (Ubuntu) PHP/8.3.6-0ubuntu0.24.04.14")
				bodyBytes, _ := io.ReadAll(r.Body)
				if strings.Contains(string(bodyBytes), `name="PHP_SESSION_UPLOAD_PROGRESS"`) {
					_, _ = w.Write([]byte(vulnerablePlainStartupWarnings))
					return
				}
				_, _ = w.Write([]byte("OK"))
			},
			wantVulnerable: false,
		},
		{
			name: "when_service_metadata_reports_patched_php_8_5_13_skips_service",
			handler: func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(vulnerablePlainStartupWarnings))
			},
			customizeSvc: func(svc *nspb.NetworkService, _ string) {
				svc.SetSoftware(spb.Software_builder{Name: "PHP"}.Build())
				svc.SetVersionSet(spb.VersionSet_builder{
					Versions: []*spb.Version{
						spb.Version_builder{FullVersionString: "8.5.13"}.Build(),
					},
				}.Build())
			},
			wantVulnerable: false,
		},
		{
			name: "when_http_echo_server_reflects_raw_multipart_request_returns_nil",
			handler: func(w http.ResponseWriter, r *http.Request) {
				dump, _ := httputil.DumpRequest(r, true)
				_, _ = w.Write(dump)
			},
			wantVulnerable: false,
		},
		{
			name: "when_redis_or_memcached_session_handler_emits_non_files_warning_returns_nil",
			handler: func(w http.ResponseWriter, r *http.Request) {
				bodyBytes, _ := io.ReadAll(r.Body)
				if strings.Contains(string(bodyBytes), `name="PHP_SESSION_UPLOAD_PROGRESS"`) {
					_, _ = w.Write([]byte(
						"Warning: PHP Request Startup: Session ID is too long or contains illegal characters in Unknown on line 0\n" +
							"Warning: PHP Request Startup: Failed to read session data: redis (path: tcp://127.0.0.1:6379) in Unknown on line 0\n"))
					return
				}
				_, _ = w.Write([]byte("OK"))
			},
			wantVulnerable: false,
		},
		{
			name: "when_session_auto_start_or_static_page_emits_same_warning_on_control_request_returns_nil",
			handler: func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(vulnerablePlainStartupWarnings))
			},
			wantVulnerable: false,
		},
		{
			name: "when_user_script_line_number_is_non_zero_returns_nil",
			handler: func(w http.ResponseWriter, r *http.Request) {
				bodyBytes, _ := io.ReadAll(r.Body)
				if strings.Contains(string(bodyBytes), `name="PHP_SESSION_UPLOAD_PROGRESS"`) {
					_, _ = w.Write([]byte(
						"Warning: session_start(): Session ID is too long or contains illegal characters in /var/www/html/index.php on line 4\n" +
							"Warning: session_start(): Failed to read session data: files (path: /tmp) in /var/www/html/index.php on line 4\n"))
					return
				}
				_, _ = w.Write([]byte("OK"))
			},
			wantVulnerable: false,
		},
		{
			name: "when_root_redirects_302_to_same_origin_non_default_php_route_follows_location_and_verifies",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/" || r.URL.Path == "/index.php" {
					w.Header().Set("Location", "/cacti/auth_login.php")
					w.WriteHeader(http.StatusFound)
					return
				}
				bodyBytes, _ := io.ReadAll(r.Body)
				if r.URL.Path == "/cacti/auth_login.php" && strings.Contains(string(bodyBytes), `name="PHP_SESSION_UPLOAD_PROGRESS"`) {
					_, _ = w.Write([]byte(vulnerablePlainStartupWarnings))
					return
				}
				_, _ = w.Write([]byte("OK"))
			},
			wantVulnerable:  true,
			wantSessionName: "PHPSESSID",
			wantEndpointSfx: "/cacti/auth_login.php",
			wantWarning:     "Warning: PHP Request Startup: Failed to read session data: files (path: /var/lib/php/sessions) in Unknown on line 0",
		},
		{
			name: "when_custom_session_cookie_set_by_endpoint_discovers_and_verifies_custom_session_name",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Add("Set-Cookie", "XSRF-TOKEN=ignoredtoken12345; Path=/")
				w.Header().Add("Set-Cookie", "MY_APP_SESS=abcdef0123456789; Path=/; HttpOnly")
				bodyBytes, _ := io.ReadAll(r.Body)
				body := string(bodyBytes)
				if r.URL.Path == "/index.php" &&
					strings.Contains(body, `name="PHP_SESSION_UPLOAD_PROGRESS"`) &&
					strings.Contains(body, `name="MY_APP_SESS"`) &&
					strings.Contains(r.Header.Get("Cookie"), "MY_APP_SESS=tsunami/invalid_sid_") {
					_, _ = w.Write([]byte(vulnerablePlainStartupWarnings))
					return
				}
				_, _ = w.Write([]byte("OK"))
			},
			wantVulnerable:  true,
			wantSessionName: "MY_APP_SESS",
			wantEndpointSfx: "/index.php",
			wantWarning:     "Warning: PHP Request Startup: Failed to read session data: files (path: /var/lib/php/sessions) in Unknown on line 0",
		},
		{
			name: "when_crawled_custom_session_cookie_and_query_param_present_strips_query_sid_and_verifies",
			handler: func(w http.ResponseWriter, r *http.Request) {
				bodyBytes, _ := io.ReadAll(r.Body)
				body := string(bodyBytes)
				if r.URL.Path == "/portal/login.php" &&
					!strings.Contains(r.URL.RawQuery, "CRAWL_SESS") &&
					r.URL.RawQuery == "keep=1" &&
					strings.Contains(body, `name="PHP_SESSION_UPLOAD_PROGRESS"`) &&
					strings.Contains(body, `name="CRAWL_SESS"`) {
					_, _ = w.Write([]byte(vulnerablePlainStartupWarnings))
					return
				}
				_, _ = w.Write([]byte("OK"))
			},
			customizeSvc: func(svc *nspb.NetworkService, baseURL string) {
				svc.SetServiceContext(nspb.ServiceContext_builder{
					WebServiceContext: nspb.WebServiceContext_builder{
						CrawlResults: []*wcpb.CrawlResult{
							wcpb.CrawlResult_builder{
								CrawlTarget: wcpb.CrawlTarget_builder{
									Url: baseURL + "/portal/login.php?CRAWL_SESS=valid12345678&keep=1#frag",
								}.Build(),
								ResponseCode: 200,
								ResponseHeaders: []*wcpb.HttpHeader{
									wcpb.HttpHeader_builder{
										Key:   "Set-Cookie",
										Value: "CRAWL_SESS=valid12345678; Path=/",
									}.Build(),
								},
							}.Build(),
						},
					}.Build(),
				}.Build())
			},
			wantVulnerable:  true,
			wantSessionName: "CRAWL_SESS",
			wantEndpointSfx: "/portal/login.php?CRAWL_SESS=valid12345678&keep=1#frag",
			wantWarning:     "Warning: PHP Request Startup: Failed to read session data: files (path: /var/lib/php/sessions) in Unknown on line 0",
		},
		{
			name: "when_front_controller_extensionless_hash_crawl_result_has_empty_content_type_probes_fallback",
			handler: func(w http.ResponseWriter, r *http.Request) {
				bodyBytes, _ := io.ReadAll(r.Body)
				if r.URL.Path == "/users/sign_in" && strings.Contains(string(bodyBytes), `name="PHP_SESSION_UPLOAD_PROGRESS"`) {
					_, _ = w.Write([]byte(vulnerablePlainStartupWarnings))
					return
				}
				if r.URL.Path == "/users/sign_in" {
					_, _ = w.Write([]byte("OK"))
					return
				}
				w.WriteHeader(http.StatusNotFound)
			},
			customizeSvc: func(svc *nspb.NetworkService, baseURL string) {
				svc.SetServiceContext(nspb.ServiceContext_builder{
					WebServiceContext: nspb.WebServiceContext_builder{
						CrawlResults: []*wcpb.CrawlResult{
							// Realistic fp/webidentity CONTENT_TYPE_HASH CrawlResult with empty ContentType & headers.
							wcpb.CrawlResult_builder{
								CrawlTarget: wcpb.CrawlTarget_builder{
									Url: baseURL + "/users/sign_in",
								}.Build(),
								ResponseCode: 200,
							}.Build(),
						},
					}.Build(),
				}.Build())
			},
			wantVulnerable:  true,
			wantSessionName: "PHPSESSID",
			wantEndpointSfx: "/users/sign_in",
			wantWarning:     "Warning: PHP Request Startup: Failed to read session data: files (path: /var/lib/php/sessions) in Unknown on line 0",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(tc.handler)
			defer srv.Close()

			svc := webServiceForServer(t, srv.URL)
			if tc.customizeSvc != nil {
				tc.customizeSvc(svc, srv.URL)
			}

			det, err := New(t.Context(), config.Default())
			if err != nil {
				t.Fatalf("New() unexpected error: %v", err)
			}
			mod := det.(*Module)
			mod.nowFn = func() time.Time { return fixedTestTime }

			got, err := mod.Detect(t.Context(), svc)
			if err != nil {
				t.Fatalf("Detect() unexpected error: %v", err)
			}

			if !tc.wantVulnerable {
				if got != nil && len(got.GetDetectionReports()) > 0 {
					t.Fatalf("Detect() = %v, want nil/empty", got)
				}
				return
			}

			wantVuln := baseVulnerability()
			wantVuln.SetAdditionalDetails([]*vpb.AdditionalDetail{
				vpb.AdditionalDetail_builder{
					Description: additionalDetailDescription,
					TextData: vpb.TextData_builder{
						Text: "Vulnerable endpoint: " + srv.URL + tc.wantEndpointSfx +
							"\nSession parameter: " + tc.wantSessionName +
							"\nMatched startup warning: " + tc.wantWarning,
					}.Build(),
				}.Build(),
			})
			want := dpb.DetectionReportList_builder{
				DetectionReports: []*dpb.DetectionReport{
					dpb.DetectionReport_builder{
						TargetInfo: rpb.TargetInfo_builder{
							NetworkEndpoints: []*npb.NetworkEndpoint{svc.GetNetworkEndpoint()},
						}.Build(),
						NetworkService:     svc,
						DetectionTimestamp: tspb.New(fixedTestTime),
						DetectionStatus:    dpb.DetectionStatus_VULNERABILITY_VERIFIED,
						Vulnerability:      wantVuln,
					}.Build(),
				},
			}.Build()

			if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
				t.Errorf("Detect() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestDetectEdgeCasesAndErrors(t *testing.T) {
	goohttp.Register("fake_transport_err_cve2026126714", func(*config.Config, *goohttp.ClientOptions) (goohttp.Client, error) {
		return fakehttp.New(0, errors.New("connection reset by peer")), nil
	})

	testCases := []struct {
		name      string
		ctxFn     func() (context.Context, context.CancelFunc)
		cfg       *config.Config
		svc       *nspb.NetworkService
		wantErr   bool
		wantNilRp bool
	}{
		{
			name: "when_context_already_canceled_returns_context_error",
			ctxFn: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx, func() {}
			},
			cfg:     config.Default(),
			svc:     nspb.NetworkService_builder{SupportedHttpMethods: []string{"GET"}}.Build(),
			wantErr: true,
		},
		{
			name: "when_non_web_service_skips_without_error",
			ctxFn: func() (context.Context, context.CancelFunc) {
				return context.WithCancel(context.Background())
			},
			cfg: config.Default(),
			svc: nspb.NetworkService_builder{
				ServiceName: "ssh",
			}.Build(),
			wantErr:   false,
			wantNilRp: true,
		},
		{
			name: "when_web_service_missing_endpoint_returns_error",
			ctxFn: func() (context.Context, context.CancelFunc) {
				return context.WithCancel(context.Background())
			},
			cfg: config.Default(),
			svc: nspb.NetworkService_builder{
				SupportedHttpMethods: []string{"GET"},
			}.Build(),
			wantErr: true,
		},
		{
			name: "when_http_transport_error_with_live_context_returns_nil_without_error",
			ctxFn: func() (context.Context, context.CancelFunc) {
				return context.WithCancel(context.Background())
			},
			cfg: config.FromProto(cpb.Config_builder{
				Globalcfg: cpb.GlobalConfig_builder{
					HttpClient: proto.String("fake_transport_err_cve2026126714"),
				}.Build(),
			}.Build()),
			svc: nspb.NetworkService_builder{
				NetworkEndpoint:      makeIPPortEndpoint("127.0.0.1", 8080),
				SupportedHttpMethods: []string{"GET"},
			}.Build(),
			wantErr:   false,
			wantNilRp: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := tc.ctxFn()
			defer cancel()

			det, err := New(t.Context(), tc.cfg)
			if err != nil {
				t.Fatalf("New() unexpected error: %v", err)
			}
			got, err := det.Detect(ctx, tc.svc)
			if (err != nil) != tc.wantErr {
				t.Fatalf("Detect() error = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantNilRp && got != nil {
				t.Errorf("Detect() = %v, want nil", got)
			}
		})
	}
}

func TestHelpersAndBoundaries(t *testing.T) {
	testCases := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "when_warning_exceeds_max_evidence_length_truncates_at_512_bytes",
			run: func(t *testing.T) {
				longPath := strings.Repeat("p", 600)
				body := "Warning: PHP Request Startup: Session ID is too long or contains illegal characters in Unknown on line 0\n" +
					"Warning: PHP Request Startup: Failed to read session data: files (path: /" + longPath + ") in Unknown on line 0"
				got, ok := extractMatchedStartupFilesWarning(body)
				if !ok {
					t.Fatal("extractMatchedStartupFilesWarning() = false, want true")
				}
				if len(got) != maxEvidenceWarningLength {
					t.Errorf("len(got) = %d, want %d", len(got), maxEvidenceWarningLength)
				}
			},
		},
		{
			name: "when_extracting_custom_cookies_enforces_cap_and_deduplicates",
			run: func(t *testing.T) {
				headers := []string{
					"invalid_header_without_equals",
					"PHPSESSID=1234567890; Path=/",
					"SESS_ONE=1234567890; Path=/",
					"SESS_ONE=abcdefghij; Path=/",
					"SESS_TWO=1234567890; Path=/",
					"SESS_THREE=1234567890; Path=/",
					"SESS_FOUR=1234567890; Path=/",
				}
				got := extractCustomSessionNamesFromHeaders(headers)
				want := []string{"SESS_ONE", "SESS_TWO", "SESS_THREE"}
				if diff := cmp.Diff(want, got); diff != "" {
					t.Errorf("extractCustomSessionNamesFromHeaders() mismatch (-want +got):\n%s", diff)
				}
			},
		},
		{
			name: "when_building_target_urls_filters_cross_origin_and_destructive_paths_and_enforces_caps",
			run: func(t *testing.T) {
				svc := nspb.NetworkService_builder{
					NetworkEndpoint:      makeIPPortEndpoint("127.0.0.1", 8080),
					SupportedHttpMethods: []string{"GET"},
					ServiceContext: nspb.ServiceContext_builder{
						WebServiceContext: nspb.WebServiceContext_builder{
							ApplicationRoot: "/app/",
							CrawlResults: []*wcpb.CrawlResult{
								wcpb.CrawlResult_builder{CrawlTarget: wcpb.CrawlTarget_builder{Url: "http://evil.example.com:8080/app/evil.php"}.Build(), ResponseCode: 200}.Build(),
								wcpb.CrawlResult_builder{CrawlTarget: wcpb.CrawlTarget_builder{Url: "http://127.0.0.1:8080/app/delete.php"}.Build(), ResponseCode: 200}.Build(),
								wcpb.CrawlResult_builder{CrawlTarget: wcpb.CrawlTarget_builder{Url: "http://127.0.0.1:8080/app/logout.php"}.Build(), ResponseCode: 200}.Build(),
								wcpb.CrawlResult_builder{CrawlTarget: wcpb.CrawlTarget_builder{Url: "http://127.0.0.1:8080/app/dead.php"}.Build(), ResponseCode: 404}.Build(),
								wcpb.CrawlResult_builder{CrawlTarget: wcpb.CrawlTarget_builder{Url: "http://127.0.0.1:8080/app/a.php"}.Build(), ResponseCode: 200}.Build(),
								wcpb.CrawlResult_builder{CrawlTarget: wcpb.CrawlTarget_builder{Url: "http://127.0.0.1:8080/app/b.php"}.Build(), ResponseCode: 200}.Build(),
								wcpb.CrawlResult_builder{CrawlTarget: wcpb.CrawlTarget_builder{Url: "http://127.0.0.1:8080/app/c.php"}.Build(), ResponseCode: 200}.Build(),
								wcpb.CrawlResult_builder{CrawlTarget: wcpb.CrawlTarget_builder{Url: "http://127.0.0.1:8080/app/d.php"}.Build(), ResponseCode: 200}.Build(),
							},
						}.Build(),
					}.Build(),
				}.Build()
				_, got, err := targetURLs(svc)
				if err != nil {
					t.Fatalf("targetURLs() unexpected error: %v", err)
				}
				for _, banned := range []string{
					"http://evil.example.com:8080/app/evil.php",
					"http://127.0.0.1:8080/app/delete.php",
					"http://127.0.0.1:8080/app/logout.php",
					"http://127.0.0.1:8080/app/d.php",
					"http://127.0.0.1:8080/app/dead.php",
				} {
					if slices.Contains(got, banned) {
						t.Errorf("targetURLs() = %v, unexpectedly contained %q", got, banned)
					}
				}
				if !slices.Contains(got, "http://127.0.0.1:8080/app/index.php") {
					t.Errorf("targetURLs() = %v, missing /app/index.php", got)
				}
			},
		},
		{
			name: "when_only_404_php_url_crawled_falls_back_to_first_crawled_php_url",
			run: func(t *testing.T) {
				svc := nspb.NetworkService_builder{
					NetworkEndpoint:      makeIPPortEndpoint("127.0.0.1", 8080),
					SupportedHttpMethods: []string{"GET"},
					ServiceContext: nspb.ServiceContext_builder{
						WebServiceContext: nspb.WebServiceContext_builder{
							ApplicationRoot: "http://127.0.0.1:8080/sub",
							CrawlResults: []*wcpb.CrawlResult{
								wcpb.CrawlResult_builder{CrawlTarget: wcpb.CrawlTarget_builder{Url: "http://127.0.0.1:8080/sub/only404.php"}.Build(), ResponseCode: 404}.Build(),
							},
						}.Build(),
					}.Build(),
				}.Build()
				_, got, err := targetURLs(svc)
				if err != nil {
					t.Fatalf("targetURLs() unexpected error: %v", err)
				}
				if len(got) == 0 || got[0] != "http://127.0.0.1:8080/sub/only404.php" {
					t.Errorf("targetURLs() = %v, want first element only404.php", got)
				}
			},
		},
		{
			name: "when_checking_patched_version_tuples_and_redirects_enforces_exact_boundaries",
			run: func(t *testing.T) {
				if isPatchedPHPVersionTuple("8", "4", "27", "") || !isPatchedPHPVersionTuple("8", "4", "28", "") {
					t.Error("8.4.27/8.4.28 boundary failed")
				}
				if isPatchedPHPVersionTuple("8", "2", "35", "1~deb12u1") || !isPatchedPHPVersionTuple("8", "2", "36", "1~deb12u1") {
					t.Error("8.2.35/8.2.36 Debian boundary failed")
				}
				if isPatchedPHPVersionTuple("8", "3", "6", "0ubuntu0.24.04.13") || !isPatchedPHPVersionTuple("8", "3", "6", "0ubuntu0.24.04.14") {
					t.Error("Ubuntu 24.04 backport boundary failed")
				}
				if isPatchedPHPVersionTuple("8", "1", "2", "1ubuntu2.28") || !isPatchedPHPVersionTuple("8", "1", "2", "1ubuntu2.29") {
					t.Error("Ubuntu 22.04 backport boundary failed")
				}
				if _, ok := resolveSameOriginRedirect("http://127.0.0.1:8080/", "http://evil.com/index.php", "http://127.0.0.1:8080/"); ok {
					t.Error("expected cross-origin redirect to be rejected")
				}
				if _, ok := resolveSameOriginRedirect("http://127.0.0.1:8080/", "/admin/delete.php", "http://127.0.0.1:8080/"); ok {
					t.Error("expected destructive redirect to be rejected")
				}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, tc.run)
	}
}
