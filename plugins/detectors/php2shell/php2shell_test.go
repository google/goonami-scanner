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

package php2shell

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/goonami-scanner/core/config"
	_ "github.com/google/goonami-scanner/core/net/http/simpleclient"
	"github.com/google/goonami-scanner/core/net/netendpoint"
	"github.com/google/goonami-scanner/core/net/netservice"
	"google.golang.org/protobuf/testing/protocmp"

	dpb "github.com/google/tsunami-security-scanner/proto/go/detection_go_proto"
	npb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
	vpb "github.com/google/tsunami-security-scanner/proto/go/vulnerability_go_proto"
	wcpb "github.com/google/tsunami-security-scanner/proto/go/web_crawl_go_proto"
)

const (
	php8UnpatchedStartupWarningsHTML = "<br />\n" +
		"<b>Warning</b>:  PHP Request Startup: Session ID is too long or contains illegal" +
		" characters. Only the A-Z, a-z, 0-9, &quot;-&quot;, and &quot;,&quot; characters are" +
		" allowed in <b>Unknown</b> on line <b>0</b><br />\n" +
		"<br />\n" +
		"<b>Warning</b>:  PHP Request Startup: Failed to write session data (files). Please" +
		" verify that the current setting of session.save_path is correct (/tmp) in" +
		" <b>Unknown</b> on line <b>0</b><br />\n" +
		"OK\n"

	sanitizedPhp8FlushWarning = "Warning:  PHP Request Startup: Failed to write session data (files). Please verify that the current setting of session.save_path is correct (/tmp) in Unknown on line 0"
)

func newTestWebService(t *testing.T, srv *httptest.Server) *nspb.NetworkService {
	t.Helper()
	host, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("net.SplitHostPort failed: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("strconv.Atoi failed: %v", err)
	}
	return nspb.NetworkService_builder{
		ServiceName:          "http",
		SupportedHttpMethods: []string{"GET", "POST"},
		NetworkEndpoint: npb.NetworkEndpoint_builder{
			Type: npb.NetworkEndpoint_IP_PORT,
			IpAddress: npb.IpAddress_builder{
				Address:       host,
				AddressFamily: npb.AddressFamily_IPV4,
			}.Build(),
			Port: npb.Port_builder{
				PortNumber: uint32(port),
			}.Build(),
		}.Build(),
	}.Build()
}

func TestNew(t *testing.T) {
	detector, err := New(t.Context(), config.Default())
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}
	if detector == nil {
		t.Fatal("New() returned nil detector")
	}
	if got := detector.Name(); got != moduleName {
		t.Errorf("detector.Name() = %q, want %q", got, moduleName)
	}
}

func TestAdvisories(t *testing.T) {
	want := []*vpb.Vulnerability{
		vpb.Vulnerability_builder{
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
		}.Build(),
	}

	tests := []struct {
		name string
	}{
		{
			name: "when_initialized_with_default_config_returns_base_advisory",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, err := New(t.Context(), config.Default())
			if err != nil {
				t.Fatalf("New() failed: %v", err)
			}
			mod := m.(*Module)

			got := mod.Advisories()
			if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
				t.Errorf("Advisories() mismatch (-want +got):\n%s", diff)
			}

			if len(got) > 0 {
				got[0].SetTitle("mutated title")
				second := mod.Advisories()
				if second[0].GetTitle() == "mutated title" {
					t.Errorf("Advisories() returned a mutable reference, expected an isolated clone")
				}
			}
		})
	}
}

func TestDetect(t *testing.T) {
	fixedTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name            string
		setup           func(t *testing.T) (context.Context, *nspb.NetworkService, string)
		wantFindings    bool
		wantSessionName string
		wantWarning     string
		wantErr         error
	}{
		{
			name: "when_php8_unpatched_startup_flush_differential_confirmed_returns_verified_finding",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService, string) {
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					bodyBytes, _ := io.ReadAll(r.Body)
					body := string(bodyBytes)
					if strings.Contains(body, "PHP_SESSION_UPLOAD_PROGRESS") &&
						strings.Contains(r.Header.Get("Cookie"), "PHPSESSID=tsunami/invalid_sid_") {
						w.WriteHeader(http.StatusOK)
						_, _ = w.Write([]byte(php8UnpatchedStartupWarningsHTML))
						return
					}
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte("OK\n"))
				}))
				t.Cleanup(srv.Close)
				svc := newTestWebService(t, srv)
				return t.Context(), svc, srv.URL + "/index.php"
			},
			wantFindings:    true,
			wantSessionName: "PHPSESSID",
			wantWarning:     sanitizedPhp8FlushWarning,
		},
		{
			name: "when_legacy_php7_plaintext_startup_flush_confirmed_returns_verified_finding",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService, string) {
				legacyWarnings := "\nWarning: Unknown: The session id is too long or contains illegal characters, valid characters are a-z, A-Z, 0-9 and '-,' in Unknown on line 0\n" +
					"\nWarning: Unknown: Failed to write session data (files). Please verify that the current setting of session.save_path is correct (/var/lib/php/sessions) in Unknown on line 0\n"
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					bodyBytes, _ := io.ReadAll(r.Body)
					if strings.Contains(string(bodyBytes), "PHP_SESSION_UPLOAD_PROGRESS") {
						_, _ = w.Write([]byte(legacyWarnings))
						return
					}
					_, _ = w.Write([]byte("OK"))
				}))
				t.Cleanup(srv.Close)
				svc := newTestWebService(t, srv)
				return t.Context(), svc, srv.URL + "/index.php"
			},
			wantFindings:    true,
			wantSessionName: "PHPSESSID",
			wantWarning:     "Warning: Unknown: Failed to write session data (files). Please verify that the current setting of session.save_path is correct (/var/lib/php/sessions) in Unknown on line 0",
		},
		{
			name: "when_redis_save_handler_emits_failed_read_and_startup_flush_warnings_returns_verified_finding",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService, string) {
				redisWarnings := "<br />\n" +
					"<b>Warning</b>:  PHP Request Startup: Failed to read session data: redis (path: tcp://127.0.0.1:6379) in <b>Unknown</b> on line <b>0</b><br />\n" +
					"<br />\n" +
					"<b>Warning</b>:  PHP Request Startup: Failed to write session data (redis). Please verify that the current setting of session.save_path is correct (tcp://127.0.0.1:6379) in <b>Unknown</b> on line <b>0</b><br />\n"
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					bodyBytes, _ := io.ReadAll(r.Body)
					if strings.Contains(string(bodyBytes), "PHP_SESSION_UPLOAD_PROGRESS") {
						_, _ = w.Write([]byte(redisWarnings))
						return
					}
					_, _ = w.Write([]byte("OK"))
				}))
				t.Cleanup(srv.Close)
				svc := newTestWebService(t, srv)
				return t.Context(), svc, srv.URL + "/index.php"
			},
			wantFindings:    true,
			wantSessionName: "PHPSESSID",
			wantWarning:     "Warning:  PHP Request Startup: Failed to write session data (redis). Please verify that the current setting of session.save_path is correct (tcp://127.0.0.1:6379) in Unknown on line 0",
		},
		{
			name: "when_static_page_returns_warning_text_without_upload_progress_returns_no_findings",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService, string) {
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					_, _ = w.Write([]byte(php8UnpatchedStartupWarningsHTML))
				}))
				t.Cleanup(srv.Close)
				svc := newTestWebService(t, srv)
				return t.Context(), svc, ""
			},
			wantFindings: false,
		},
		{
			name: "when_patched_php8427_emits_only_invalid_sid_and_failed_read_warnings_returns_no_findings",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService, string) {
				patchedBody := "<b>Warning</b>:  PHP Request Startup: Session ID is too long or contains illegal characters. Only the A-Z, a-z, 0-9, &quot;-&quot;, and &quot;,&quot; characters are allowed in <b>Unknown</b> on line <b>0</b><br />\n" +
					"<b>Warning</b>:  PHP Request Startup: Failed to read session data: files (path: /tmp) in <b>Unknown</b> on line <b>0</b><br />\nOK\n"
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("X-Powered-By", "PHP/8.4.27")
					_, _ = w.Write([]byte(patchedBody))
				}))
				t.Cleanup(srv.Close)
				svc := newTestWebService(t, srv)
				return t.Context(), svc, ""
			},
			wantFindings: false,
		},
		{
			name: "when_patched_distro_backport_discloses_old_php_version_and_set_cookie_returns_no_findings",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService, string) {
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("X-Powered-By", "PHP/8.3.6")
					w.Header().Set("Server", "Apache/2.4.58 (Ubuntu) PHP/8.3.6")
					w.Header().Add("Set-Cookie", "PHPSESSID=c8d6d79a48f07ede6d274291da7c09f8; path=/")
					_, _ = w.Write([]byte("OK"))
				}))
				t.Cleanup(srv.Close)
				svc := newTestWebService(t, srv)
				return t.Context(), svc, ""
			},
			wantFindings: false,
		},
		{
			name: "when_userland_rshutdown_fails_session_write_close_returns_no_findings",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService, string) {
				rshutdownBody := "<b>Warning</b>:  PHP Request Startup: Session ID is too long or contains illegal characters in <b>Unknown</b> on line <b>0</b><br />\n" +
					"<b>Warning</b>:  session_write_close(): Failed to write session data using user defined save handler. (session.save_path: , handler: BadHandler::write) in <b>Unknown</b> on line <b>0</b><br />\n"
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					_, _ = w.Write([]byte(rshutdownBody))
				}))
				t.Cleanup(srv.Close)
				svc := newTestWebService(t, srv)
				return t.Context(), svc, ""
			},
			wantFindings: false,
		},
		{
			name: "when_multiple_custom_set_cookies_present_iterates_to_second_cookie_and_verifies",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService, string) {
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					bodyBytes, _ := io.ReadAll(r.Body)
					body := string(bodyBytes)
					cookie := r.Header.Get("Cookie")
					if strings.HasPrefix(cookie, "transient_cookie=tsunami/invalid_sid_") {
						if hj, ok := w.(http.Hijacker); ok {
							conn, _, err := hj.Hijack()
							if err == nil {
								_ = conn.Close()
								return
							}
						}
					}
					if strings.HasPrefix(cookie, "MoodleSession=tsunami/invalid_sid_") {
						if strings.Contains(body, "PHP_SESSION_UPLOAD_PROGRESS") {
							_, _ = w.Write([]byte(php8UnpatchedStartupWarningsHTML))
							return
						}
						_, _ = w.Write([]byte("OK"))
						return
					}
					w.Header().Add("Set-Cookie", "XSRF-TOKEN=0123456789abcdef0123456789abcdef; Path=/")
					w.Header().Add("Set-Cookie", "transient_cookie=0011223344556677; Path=/")
					w.Header().Add("Set-Cookie", "theme_preference=darkmodev2abcd1234; Path=/")
					w.Header().Add("Set-Cookie", "MoodleSession=a1b2c3d4e5f6a1b2; Path=/; HttpOnly")
					_, _ = w.Write([]byte("LOGIN"))
				}))
				t.Cleanup(srv.Close)
				svc := newTestWebService(t, srv)
				return t.Context(), svc, srv.URL + "/index.php"
			},
			wantFindings:    true,
			wantSessionName: "MoodleSession",
			wantWarning:     sanitizedPhp8FlushWarning,
		},
		{
			name: "when_three_crawled_custom_cookies_present_and_first_disconnects_caps_retries_at_two",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService, string) {
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					_, _ = io.ReadAll(r.Body)
					cookie := r.Header.Get("Cookie")
					if strings.HasPrefix(cookie, "FIRSTSESSID=tsunami/invalid_sid_") {
						if hj, ok := w.(http.Hijacker); ok {
							conn, _, err := hj.Hijack()
							if err == nil {
								_ = conn.Close()
								return
							}
						}
					}
					_, _ = w.Write([]byte("OK"))
				}))
				t.Cleanup(srv.Close)
				svc := newTestWebService(t, srv)
				netservice.AddCrawlResults(svc, []*wcpb.CrawlResult{
					wcpb.CrawlResult_builder{
						CrawlTarget: wcpb.CrawlTarget_builder{
							Url:        srv.URL + "/login.php",
							HttpMethod: "GET",
						}.Build(),
						ResponseCode: http.StatusNotFound,
						ResponseHeaders: []*wcpb.HttpHeader{
							wcpb.HttpHeader_builder{
								Key:   "Set-Cookie",
								Value: "FIRSTSESSID=0123456789abcdef; Path=/",
							}.Build(),
							wcpb.HttpHeader_builder{
								Key:   "Set-Cookie",
								Value: "SECONDSESSID=fedcba9876543210; Path=/",
							}.Build(),
							wcpb.HttpHeader_builder{
								Key:   "Set-Cookie",
								Value: "THIRDSESSID=aabbccddeeff0011; Path=/",
							}.Build(),
						},
					}.Build(),
				})
				return t.Context(), svc, ""
			},
			wantFindings: false,
		},
		{
			name: "when_custom_session_name_recorded_in_crawl_headers_verifies_on_stateless_endpoint",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService, string) {
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					bodyBytes, _ := io.ReadAll(r.Body)
					body := string(bodyBytes)
					if strings.HasPrefix(r.Header.Get("Cookie"), "APP-SESS-ID=tsunami/invalid_sid_") &&
						strings.Contains(body, "PHP_SESSION_UPLOAD_PROGRESS") {
						_, _ = w.Write([]byte(php8UnpatchedStartupWarningsHTML))
						return
					}
					_, _ = w.Write([]byte("OK"))
				}))
				t.Cleanup(srv.Close)
				svc := newTestWebService(t, srv)
				netservice.AddCrawlResults(svc, []*wcpb.CrawlResult{
					wcpb.CrawlResult_builder{
						CrawlTarget: wcpb.CrawlTarget_builder{
							Url:        srv.URL + "/account",
							HttpMethod: "GET",
						}.Build(),
						ResponseCode: http.StatusOK,
						ResponseHeaders: []*wcpb.HttpHeader{
							wcpb.HttpHeader_builder{
								Key:   "Set-Cookie",
								Value: "APP-SESS-ID=0123456789abcdef0123456789; Path=/; HttpOnly",
							}.Build(),
						},
					}.Build(),
				})
				return t.Context(), svc, srv.URL + "/index.php"
			},
			wantFindings:    true,
			wantSessionName: "APP-SESS-ID",
			wantWarning:     sanitizedPhp8FlushWarning,
		},
		{
			name: "when_endpoint_emits_non_session_cookie_and_crawl_has_quoted_url_encoded_session_cookie_verifies_crawl_cookie",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService, string) {
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					bodyBytes, _ := io.ReadAll(r.Body)
					body := string(bodyBytes)
					cookie := r.Header.Get("Cookie")
					if strings.HasPrefix(cookie, "CUSTOM_SESS=tsunami/invalid_sid_") {
						if strings.Contains(body, "PHP_SESSION_UPLOAD_PROGRESS") {
							_, _ = w.Write([]byte(php8UnpatchedStartupWarningsHTML))
							return
						}
						_, _ = w.Write([]byte("OK"))
						return
					}
					w.Header().Add("Set-Cookie", "theme_cookie=darkmode1; Path=/")
					_, _ = w.Write([]byte("OK"))
				}))
				t.Cleanup(srv.Close)
				svc := newTestWebService(t, srv)
				netservice.AddCrawlResults(svc, []*wcpb.CrawlResult{
					wcpb.CrawlResult_builder{
						CrawlTarget: wcpb.CrawlTarget_builder{
							Url:        srv.URL + "/account",
							HttpMethod: "GET",
						}.Build(),
						ResponseCode: http.StatusOK,
						ResponseHeaders: []*wcpb.HttpHeader{
							wcpb.HttpHeader_builder{
								Key:   "Set-Cookie",
								Value: "theme_cookie=darkmode1; Path=/",
							}.Build(),
							wcpb.HttpHeader_builder{
								Key:   "Set-Cookie",
								Value: `CUSTOM_SESS="a1b2_c3.d4~e5%2Cf6"; Path=/; HttpOnly`,
							}.Build(),
						},
					}.Build(),
				})
				return t.Context(), svc, srv.URL + "/index.php"
			},
			wantFindings:    true,
			wantSessionName: "CUSTOM_SESS",
			wantWarning:     sanitizedPhp8FlushWarning,
		},
		{
			name: "when_crawled_php_url_contains_session_query_param_strips_query_param_and_verifies",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService, string) {
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Query().Get("PHPSESSID") != "" {
						// Simulates session.use_cookies=0 where a valid $_GET["PHPSESSID"]
						// would mask the invalid SID if not stripped.
						_, _ = w.Write([]byte("OK"))
						return
					}
					bodyBytes, _ := io.ReadAll(r.Body)
					if r.URL.Path == "/custom/upload.php" &&
						r.URL.Query().Get("id") == "42" &&
						strings.Contains(string(bodyBytes), "PHP_SESSION_UPLOAD_PROGRESS") {
						_, _ = w.Write([]byte(php8UnpatchedStartupWarningsHTML))
						return
					}
					_, _ = w.Write([]byte("OK"))
				}))
				t.Cleanup(srv.Close)
				svc := newTestWebService(t, srv)
				crawledURL := srv.URL + "/custom/upload.php?PHPSESSID=0123456789abcdef0123456789abcdef&id=42#frag"
				netservice.AddCrawlResults(svc, []*wcpb.CrawlResult{
					wcpb.CrawlResult_builder{
						CrawlTarget: wcpb.CrawlTarget_builder{
							Url:        srv.URL + "/legacy/removed.php",
							HttpMethod: "GET",
						}.Build(),
						ResponseCode: http.StatusNotFound,
					}.Build(),
					wcpb.CrawlResult_builder{
						CrawlTarget: wcpb.CrawlTarget_builder{
							Url:        crawledURL,
							HttpMethod: "GET",
						}.Build(),
						ResponseCode: http.StatusOK,
					}.Build(),
				})
				return t.Context(), svc, crawledURL
			},
			wantFindings:    true,
			wantSessionName: "PHPSESSID",
			wantWarning:     sanitizedPhp8FlushWarning,
		},
		{
			name: "when_zero_php_urls_crawled_and_candidate_paths_redirect_verifies_extensionless_html_route",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService, string) {
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path != "/users/login" {
						w.Header().Set("Location", "/users/login")
						w.WriteHeader(http.StatusFound)
						return
					}
					bodyBytes, _ := io.ReadAll(r.Body)
					if strings.Contains(string(bodyBytes), "PHP_SESSION_UPLOAD_PROGRESS") {
						_, _ = w.Write([]byte(php8UnpatchedStartupWarningsHTML))
						return
					}
					_, _ = w.Write([]byte("LOGIN"))
				}))
				t.Cleanup(srv.Close)
				svc := newTestWebService(t, srv)
				extensionlessURL := srv.URL + "/users/login"
				netservice.AddCrawlResults(svc, []*wcpb.CrawlResult{
					wcpb.CrawlResult_builder{
						CrawlTarget: wcpb.CrawlTarget_builder{
							Url:        extensionlessURL,
							HttpMethod: "GET",
						}.Build(),
						ResponseCode: http.StatusOK,
						ResponseHeaders: []*wcpb.HttpHeader{
							wcpb.HttpHeader_builder{
								Key:   "Content-Type",
								Value: "application/xhtml+xml; charset=UTF-8",
							}.Build(),
						},
					}.Build(),
				})
				return t.Context(), svc, extensionlessURL
			},
			wantFindings:    true,
			wantSessionName: "PHPSESSID",
			wantWarning:     sanitizedPhp8FlushWarning,
		},
		{
			name: "when_non_web_service_returns_no_findings",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService, string) {
				svc := nspb.NetworkService_builder{
					ServiceName: "ssh",
					NetworkEndpoint: npb.NetworkEndpoint_builder{
						Type: npb.NetworkEndpoint_IP_PORT,
						IpAddress: npb.IpAddress_builder{
							Address: "127.0.0.1",
						}.Build(),
						Port: npb.Port_builder{
							PortNumber: 22,
						}.Build(),
					}.Build(),
				}.Build()
				return t.Context(), svc, ""
			},
			wantFindings: false,
		},
		{
			name: "when_invalid_network_endpoint_returns_error",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService, string) {
				svc := nspb.NetworkService_builder{
					ServiceName:          "http",
					SupportedHttpMethods: []string{"GET"},
					NetworkEndpoint:      npb.NetworkEndpoint_builder{}.Build(),
				}.Build()
				return t.Context(), svc, ""
			},
			wantFindings: false,
			wantErr:      netendpoint.ErrEndpointMissingAddress,
		},
		{
			name: "when_context_canceled_before_start_returns_error",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService, string) {
				ctx, cancel := context.WithCancel(t.Context())
				cancel()
				svc := nspb.NetworkService_builder{
					ServiceName: "http",
				}.Build()
				return ctx, svc, ""
			},
			wantFindings: false,
			wantErr:      context.Canceled,
		},
		{
			name: "when_context_canceled_during_control_request_returns_error",
			setup: func(t *testing.T) (context.Context, *nspb.NetworkService, string) {
				ctx, cancel := context.WithCancel(t.Context())
				var reqs atomic.Int32
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if reqs.Add(1) == 1 {
						_, _ = w.Write([]byte(php8UnpatchedStartupWarningsHTML))
						return
					}
					cancel()
				}))
				t.Cleanup(srv.Close)
				svc := newTestWebService(t, srv)
				return ctx, svc, ""
			},
			wantFindings: false,
			wantErr:      context.Canceled,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx, svc, wantEndpoint := tc.setup(t)
			m, err := New(ctx, config.Default())
			if err != nil {
				t.Fatalf("New() unexpected error: %v", err)
			}
			mod := m.(*Module)
			mod.nowFn = func() time.Time { return fixedTime }

			reports, err := mod.Detect(ctx, svc)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Detect() error = %v, want %v", err, tc.wantErr)
			}

			if tc.wantFindings {
				if reports == nil || len(reports.GetDetectionReports()) != 1 {
					t.Fatalf("Detect() reports = %v, want 1 report", reports)
				}
				report := reports.GetDetectionReports()[0]
				if got := report.GetDetectionStatus(); got != dpb.DetectionStatus_VULNERABILITY_VERIFIED {
					t.Errorf("report.GetDetectionStatus() = %v, want %v", got, dpb.DetectionStatus_VULNERABILITY_VERIFIED)
				}
				vuln := report.GetVulnerability()
				if got := vuln.GetSeverity(); got != vpb.Severity_CRITICAL {
					t.Errorf("vuln.GetSeverity() = %v, want %v", got, vpb.Severity_CRITICAL)
				}
				if got := vuln.GetMainId().GetValue(); got != vulnReportID {
					t.Errorf("vuln.GetMainId().GetValue() = %q, want %q", got, vulnReportID)
				}
				wantDetail := "Vulnerable endpoint: " + wantEndpoint + "\nSession parameter: " + tc.wantSessionName + "\nMatched startup warning: " + tc.wantWarning
				details := vuln.GetAdditionalDetails()
				if len(details) != 1 || details[0].GetTextData().GetText() != wantDetail {
					t.Errorf("AdditionalDetails = %v, want text %q", details, wantDetail)
				}
				return
			}

			if reports != nil && len(reports.GetDetectionReports()) > 0 {
				t.Errorf("Detect() returned unexpected reports: %v", reports)
			}
		})
	}
}
