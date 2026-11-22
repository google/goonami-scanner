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

package cve202144228

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/goonami-scanner/common/callbackserver/cbid"
	"github.com/google/goonami-scanner/common/clients/callbackserver"
	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/module"
	_ "github.com/google/goonami-scanner/core/net/http/simpleclient"
	"github.com/google/goonami-scanner/core/net/netendpoint"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"

	cpb "github.com/google/goonami-scanner/core/config/config_go_proto"
	cbpb "github.com/google/goonami-scanner/tools/callbackserver/callbackserver_config_go_proto"
	npb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
	spb "github.com/google/tsunami-security-scanner/proto/go/software_go_proto"
	vpb "github.com/google/tsunami-security-scanner/proto/go/vulnerability_go_proto"
	wcpb "github.com/google/tsunami-security-scanner/proto/go/web_crawl_go_proto"
)

var cbidExtractPattern = regexp.MustCompile(`([0-9a-f]{56})\.cb\.example\.test`)

type fakeCallbackRegistry struct {
	mu           sync.Mutex
	recordedCBID map[string]bool
	pollCalls    atomic.Int32
	recordAfter  int32
}

func newFakeCallbackServer(t *testing.T) (*httptest.Server, *fakeCallbackRegistry) {
	t.Helper()
	reg := &fakeCallbackRegistry{
		recordedCBID: make(map[string]bool),
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := reg.pollCalls.Add(1)
		secret := r.URL.Query().Get("secret")
		id, err := cbid.Generate(secret)
		if err != nil {
			http.Error(w, "bad secret", http.StatusBadRequest)
			return
		}
		reg.mu.Lock()
		hit := reg.recordedCBID[id]
		reg.mu.Unlock()
		if hit && (reg.recordAfter == 0 || n >= reg.recordAfter) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"hasDnsInteraction":true}`))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, reg
}

func (r *fakeCallbackRegistry) recordFromText(s string) {
	decoded, err := url.QueryUnescape(s)
	if err == nil {
		s = s + " " + decoded
	}
	for _, m := range cbidExtractPattern.FindAllStringSubmatch(s, -1) {
		if len(m) >= 2 {
			r.mu.Lock()
			r.recordedCBID[m[1]] = true
			r.mu.Unlock()
		}
	}
}

func newCallbackConfig(pollURL string, localDNSMode bool, dnsPort uint32) *config.Config {
	mode := cbpb.CallbackEndpointMode_MODE_USE_REMOTE_SERVER
	if localDNSMode {
		mode = cbpb.CallbackEndpointMode_MODE_START_LOCAL_SERVER
	}
	return config.FromProto(cpb.Config_builder{
		Clients: cpb.ClientsConfig_builder{
			CallbackServer: cbpb.CallbackserverConfig_builder{
				HttpPollConfig: cbpb.EndpointConfig_builder{
					Mode:      cbpb.CallbackEndpointMode_MODE_USE_REMOTE_SERVER.Enum(),
					PublicUri: proto.String(pollURL),
				}.Build(),
				HttpRecordConfig: cbpb.EndpointConfig_builder{
					Mode:      cbpb.CallbackEndpointMode_MODE_USE_REMOTE_SERVER.Enum(),
					PublicUri: proto.String("http://172.17.0.1:18268"),
				}.Build(),
				DnsRecordConfig: cbpb.EndpointConfig_builder{
					Mode:      mode.Enum(),
					PublicUri: proto.String("cb.example.test"),
					BindPort:  proto.Uint32(dnsPort),
				}.Build(),
			}.Build(),
		}.Build(),
	}.Build())
}

func newWebServiceForServer(t *testing.T, srv *httptest.Server, serviceName string) *nspb.NetworkService {
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
		ServiceName:          serviceName,
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

func TestNewAndRegistration(t *testing.T) {
	testCases := []struct {
		name string
		cfg  *config.Config
	}{
		{
			name: "when_default_config_registers_and_constructs_detector",
			cfg:  config.Default(),
		},
		{
			name: "when_nil_config_constructs_detector",
			cfg:  nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			det, err := New(t.Context(), tc.cfg)
			if err != nil {
				t.Fatalf("New() unexpected error: %v", err)
			}
			if det == nil {
				t.Fatal("New() returned nil detector")
			}
			if got := det.Name(); got != moduleName {
				t.Errorf("det.Name() = %q, want %q", got, moduleName)
			}

			allDetectors, err := module.AllDetectors(t.Context(), config.Default())
			if err != nil {
				t.Fatalf("module.AllDetectors() unexpected error: %v", err)
			}
			found := false
			for _, d := range allDetectors {
				if d.Name() == moduleName {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("detector %q not registered in module.DefaultRegistry", moduleName)
			}
		})
	}
}

func TestAdvisories(t *testing.T) {
	want := []*vpb.Vulnerability{baseVulnerability()}
	testCases := []struct {
		name string
	}{
		{
			name: "when_called_returns_isolated_advisory_clone",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			det, err := New(t.Context(), config.Default())
			if err != nil {
				t.Fatalf("New() failed: %v", err)
			}
			got := det.Advisories()
			if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
				t.Errorf("Advisories() diff (-want +got):\n%s", diff)
			}
			got[0].SetTitle("mutated")
			if det.Advisories()[0].GetTitle() == "mutated" {
				t.Error("Advisories() returned mutable shared proto")
			}
		})
	}
}

func TestIsWebService(t *testing.T) {
	testCases := []struct {
		name string
		svc  *nspb.NetworkService
		want bool
	}{
		{
			name: "when_supported_http_methods_present_on_custom_service_returns_true",
			svc: nspb.NetworkService_builder{
				ServiceName:          "custom-daemon",
				SupportedHttpMethods: []string{"GET"},
			}.Build(),
			want: true,
		},
		{
			name: "when_known_web_service_name_without_methods_returns_true",
			svc: nspb.NetworkService_builder{
				ServiceName: "ssl/http",
			}.Build(),
			want: true,
		},
		{
			name: "when_non_web_service_returns_false",
			svc: nspb.NetworkService_builder{
				ServiceName: "ssh",
			}.Build(),
			want: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isWebService(tc.svc); got != tc.want {
				t.Errorf("isWebService() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDetect(t *testing.T) {
	fixedNow := time.Date(2026, 11, 14, 2, 0, 0, 0, time.UTC)

	testCases := []struct {
		name           string
		localDNSMode   bool
		dnsPort        uint32
		delayedPollHit int32
		setupTarget    func(t *testing.T, reg *fakeCallbackRegistry) (*httptest.Server, *nspb.NetworkService)
		wantFinding    bool
	}{
		{
			name: "when_header_jndi_ldap_triggers_callback_returns_verified_finding",
			setupTarget: func(t *testing.T, reg *fakeCallbackRegistry) (*httptest.Server, *nspb.NetworkService) {
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if ua := r.Header.Get("User-Agent"); strings.Contains(ua, "${jndi:ldap://") {
						reg.recordFromText(ua)
					}
					w.WriteHeader(http.StatusOK)
				}))
				t.Cleanup(srv.Close)
				return srv, newWebServiceForServer(t, srv, "http")
			},
			wantFinding: true,
		},
		{
			name: "when_2_15_0_localhost_fragment_bypass_triggers_callback_returns_verified_finding",
			setupTarget: func(t *testing.T, reg *fakeCallbackRegistry) (*httptest.Server, *nspb.NetworkService) {
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					q := r.URL.Query().Get("q")
					if strings.Contains(q, "${jndi:ldap://127.0.0.1#.") {
						reg.recordFromText(q)
					}
					w.WriteHeader(http.StatusOK)
				}))
				t.Cleanup(srv.Close)
				return srv, newWebServiceForServer(t, srv, "http")
			},
			wantFinding: true,
		},
		{
			name:         "when_local_dns_callback_server_and_solr_redirect_triggers_callback_returns_verified_finding",
			localDNSMode: true,
			dnsPort:      18269,
			setupTarget: func(t *testing.T, reg *fakeCallbackRegistry) (*httptest.Server, *nspb.NetworkService) {
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/" {
						http.Redirect(w, r, "/solr/", http.StatusFound)
						return
					}
					if r.URL.Path == "/solr/admin/info/system" {
						wt := r.URL.Query().Get("wt")
						if strings.Contains(wt, "${jndi:dns://172.17.0.1:18269/") {
							reg.recordFromText(wt)
						}
					}
					w.WriteHeader(http.StatusOK)
				}))
				t.Cleanup(srv.Close)
				return srv, newWebServiceForServer(t, srv, "http")
			},
			wantFinding: true,
		},
		{
			name:           "when_crawled_post_form_triggers_delayed_async_callback_returns_verified_finding",
			delayedPollHit: 4,
			setupTarget: func(t *testing.T, reg *fakeCallbackRegistry) (*httptest.Server, *nspb.NetworkService) {
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method == http.MethodPost && r.URL.Path == "/login" {
						body, _ := io.ReadAll(r.Body)
						if strings.Contains(string(body), "username=%24%7Bjndi%3Adns%3A%2F%2F") {
							reg.recordFromText(string(body))
						}
					}
					w.WriteHeader(http.StatusOK)
				}))
				t.Cleanup(srv.Close)
				svc := newWebServiceForServer(t, srv, "http")
				svc.SetServiceContext(nspb.ServiceContext_builder{
					WebServiceContext: nspb.WebServiceContext_builder{
						ApplicationRoot: "/app",
						Software: spb.Software_builder{
							Name: "CustomJavaApp",
						}.Build(),
						CrawlResults: []*wcpb.CrawlResult{
							wcpb.CrawlResult_builder{
								CrawlTarget: wcpb.CrawlTarget_builder{
									Url:             srv.URL + "/login",
									HttpMethod:      "POST",
									HttpRequestBody: []byte("username=guest&domain=corp"),
								}.Build(),
							}.Build(),
							wcpb.CrawlResult_builder{
								CrawlTarget: wcpb.CrawlTarget_builder{
									Url: "",
								}.Build(),
							}.Build(),
						},
					}.Build(),
				}.Build())
				return srv, svc
			},
			wantFinding: true,
		},
		{
			name: "when_echo_server_reflects_all_headers_query_and_body_without_oob_callback_returns_no_findings",
			setupTarget: func(t *testing.T, reg *fakeCallbackRegistry) (*httptest.Server, *nspb.NetworkService) {
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					body, _ := io.ReadAll(r.Body)
					for k, vals := range r.Header {
						for _, v := range vals {
							w.Header().Add("X-Echo-"+k, v)
						}
					}
					w.WriteHeader(http.StatusOK)
					_, _ = fmt.Fprintf(w, "URI=%s\nHEADERS=%v\nBODY=%s\n", r.URL.String(), r.Header, string(body))
				}))
				t.Cleanup(srv.Close)
				return srv, newWebServiceForServer(t, srv, "http")
			},
			wantFinding: false,
		},
		{
			name: "when_patched_server_ignores_jndi_strings_returns_no_findings",
			setupTarget: func(t *testing.T, reg *fakeCallbackRegistry) (*httptest.Server, *nspb.NetworkService) {
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte("Apache Solr 8.11.2 OK"))
				}))
				t.Cleanup(srv.Close)
				return srv, newWebServiceForServer(t, srv, "http")
			},
			wantFinding: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pollSrv, reg := newFakeCallbackServer(t)
			reg.recordAfter = tc.delayedPollHit
			cfg := newCallbackConfig(pollSrv.URL, tc.localDNSMode, tc.dnsPort)
			if err := callbackserver.Initialize(t.Context(), cfg); err != nil {
				t.Fatalf("callbackserver.Initialize() failed: %v", err)
			}

			_, svc := tc.setupTarget(t, reg)
			det, err := New(t.Context(), cfg)
			if err != nil {
				t.Fatalf("New() failed: %v", err)
			}
			mod := det.(*Module)
			mod.pollAttempts = 2
			mod.pollInterval = time.Millisecond
			mod.nowFn = func() time.Time { return fixedNow }
			mod.randRead = func(b []byte) (int, error) {
				copy(b, bytes.Repeat([]byte{0x42}, len(b)))
				return len(b), nil
			}

			reports, err := mod.Detect(t.Context(), svc)
			if err != nil {
				t.Fatalf("Detect() unexpected error: %v", err)
			}

			if tc.wantFinding {
				if reports == nil || len(reports.GetDetectionReports()) != 1 {
					t.Fatalf("Detect() reports = %v, want 1 report", reports)
				}
				secret, _ := mod.generateSecret()
				dnsDomain, _ := callbackserver.DefaultClient().GetDNSCallbackDomain(secret)
				want := mod.buildDetectionReport(svc, dnsDomain)
				if diff := cmp.Diff(want, reports, protocmp.Transform()); diff != "" {
					t.Errorf("Detect() report diff (-want +got):\n%s", diff)
				}
				return
			}

			if reports != nil && len(reports.GetDetectionReports()) > 0 {
				t.Errorf("Detect() returned unexpected findings: %v", reports)
			}
		})
	}
}

func TestDetectSkipAndErrorCases(t *testing.T) {
	pollSrv, _ := newFakeCallbackServer(t)
	enabledCfg := newCallbackConfig(pollSrv.URL, false, 0)
	disabledCfg := config.Default()

	closedSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	unreachableSvc := newWebServiceForServer(t, closedSrv, "http")
	closedSrv.Close()

	testCases := []struct {
		name          string
		cfg           *config.Config
		detectorCfg   *config.Config
		svc           *nspb.NetworkService
		cancelBefore  bool
		randErr       error
		wantErrSubstr string
	}{
		{
			name:        "when_non_web_service_skips_without_error",
			cfg:         enabledCfg,
			detectorCfg: enabledCfg,
			svc: nspb.NetworkService_builder{
				ServiceName: "ssh",
			}.Build(),
		},
		{
			name:        "when_callback_server_disabled_skips_without_error",
			cfg:         disabledCfg,
			detectorCfg: disabledCfg,
			svc: nspb.NetworkService_builder{
				ServiceName:          "http",
				SupportedHttpMethods: []string{"GET"},
			}.Build(),
		},
		{
			name:        "when_missing_network_endpoint_returns_error",
			cfg:         enabledCfg,
			detectorCfg: enabledCfg,
			svc: nspb.NetworkService_builder{
				ServiceName:          "http",
				SupportedHttpMethods: []string{"GET"},
				NetworkEndpoint:      npb.NetworkEndpoint_builder{}.Build(),
			}.Build(),
			wantErrSubstr: netendpoint.ErrEndpointMissingAddress.Error(),
		},
		{
			name:          "when_nil_detector_config_returns_http_client_error",
			cfg:           enabledCfg,
			detectorCfg:   nil,
			svc:           unreachableSvc,
			wantErrSubstr: "config is nil",
		},
		{
			name:          "when_rng_fails_returns_error",
			cfg:           enabledCfg,
			detectorCfg:   enabledCfg,
			svc:           unreachableSvc,
			randErr:       errors.New("rng failure"),
			wantErrSubstr: "rng failure",
		},
		{
			name:          "when_context_canceled_before_detect_returns_canceled",
			cfg:           enabledCfg,
			detectorCfg:   enabledCfg,
			svc:           unreachableSvc,
			cancelBefore:  true,
			wantErrSubstr: context.Canceled.Error(),
		},
		{
			name:        "when_target_unreachable_short_circuits_cleanly",
			cfg:         enabledCfg,
			detectorCfg: enabledCfg,
			svc:         unreachableSvc,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if err := callbackserver.Initialize(t.Context(), tc.cfg); err != nil {
				t.Fatalf("callbackserver.Initialize() failed: %v", err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if tc.cancelBefore {
				cancel()
			}

			det, err := New(ctx, tc.detectorCfg)
			if err != nil {
				t.Fatalf("New() failed: %v", err)
			}
			mod := det.(*Module)
			mod.pollInterval = time.Millisecond
			if tc.randErr != nil {
				mod.randRead = func([]byte) (int, error) { return 0, tc.randErr }
			}

			reports, err := mod.Detect(ctx, tc.svc)
			if tc.wantErrSubstr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErrSubstr) {
					t.Fatalf("Detect() error = %v, want substring %q", err, tc.wantErrSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Detect() unexpected error: %v", err)
			}
			if reports != nil && len(reports.GetDetectionReports()) > 0 {
				t.Errorf("Detect() returned unexpected reports: %v", reports)
			}
		})
	}
}

func TestDetectContextCanceledDuringPolling(t *testing.T) {
	testCases := []struct {
		name string
	}{
		{
			name: "when_context_canceled_during_post_send_poll_returns_canceled",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			var pollCount atomic.Int32
			pollSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if pollCount.Add(1) >= 3 {
					cancel()
				}
				http.Error(w, "server error", http.StatusInternalServerError)
			}))
			t.Cleanup(pollSrv.Close)

			targetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			t.Cleanup(targetSrv.Close)

			cfg := newCallbackConfig(pollSrv.URL, false, 0)
			if err := callbackserver.Initialize(t.Context(), cfg); err != nil {
				t.Fatalf("callbackserver.Initialize() failed: %v", err)
			}

			det, err := New(ctx, cfg)
			if err != nil {
				t.Fatalf("New() failed: %v", err)
			}
			mod := det.(*Module)
			mod.pollAttempts = 5
			mod.pollInterval = 5 * time.Millisecond

			svc := newWebServiceForServer(t, targetSrv, "http")
			_, err = mod.Detect(ctx, svc)
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("Detect() error = %v, want %v", err, context.Canceled)
			}
		})
	}
}

func TestURLAndPayloadHelpers(t *testing.T) {
	testCases := []struct {
		name     string
		baseURL  string
		location string
		want     string
	}{
		{
			name:     "when_relative_redirect_resolves_same_host",
			baseURL:  "http://127.0.0.1:8983/",
			location: "/solr/#/",
			want:     "http://127.0.0.1:8983/solr/",
		},
		{
			name:     "when_external_host_redirect_returns_empty",
			baseURL:  "http://127.0.0.1:8983/",
			location: "http://example.com/solr/",
			want:     "",
		},
		{
			name:     "when_non_http_scheme_redirect_returns_empty",
			baseURL:  "http://127.0.0.1:8983/",
			location: "javascript:alert(1)",
			want:     "",
		},
		{
			name:     "when_redirect_equals_base_returns_empty",
			baseURL:  "http://127.0.0.1:8983/",
			location: "/",
			want:     "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveSameHostURL(tc.baseURL, tc.location); got != tc.want {
				t.Errorf("resolveSameHostURL(%q, %q) = %q, want %q", tc.baseURL, tc.location, got, tc.want)
			}
		})
	}

	t.Run("when_full_url_application_root_preserves_full_url", func(t *testing.T) {
		svc := nspb.NetworkService_builder{
			ServiceName: "http",
			NetworkEndpoint: npb.NetworkEndpoint_builder{
				Type: npb.NetworkEndpoint_IP_PORT,
				IpAddress: npb.IpAddress_builder{
					Address:       "127.0.0.1",
					AddressFamily: npb.AddressFamily_IPV4,
				}.Build(),
				Port: npb.Port_builder{
					PortNumber: 8080,
				}.Build(),
			}.Build(),
			ServiceContext: nspb.ServiceContext_builder{
				WebServiceContext: nspb.WebServiceContext_builder{
					ApplicationRoot: "http://127.0.0.1:8080/custom",
				}.Build(),
			}.Build(),
		}.Build()
		got, err := buildWebRootURL(svc)
		if err != nil {
			t.Fatalf("buildWebRootURL() unexpected error: %v", err)
		}
		if got != "http://127.0.0.1:8080/custom/" {
			t.Errorf("buildWebRootURL() = %q, want %q", got, "http://127.0.0.1:8080/custom/")
		}
	})

	t.Run("when_fuzz_url_query_receives_invalid_or_multi_param_urls", func(t *testing.T) {
		if got := fuzzURLQuery("mailto:user@example.com", "P"); got != nil {
			t.Errorf("fuzzURLQuery(mailto) = %v, want nil", got)
		}
		got := fuzzURLQuery("http://127.0.0.1:8080/search?a=1&=empty&b", "ENC")
		want := []string{
			"http://127.0.0.1:8080/search?a=ENC&=empty&b",
			"http://127.0.0.1:8080/search?a=1&=empty&b=ENC",
		}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("fuzzURLQuery() diff (-want +got):\n%s", diff)
		}
	})

	t.Run("when_local_callback_dns_authority_checks_invalid_configs", func(t *testing.T) {
		if got := localCallbackDNSAuthority(nil); got != "" {
			t.Errorf("localCallbackDNSAuthority(nil) = %q, want empty", got)
		}
		zeroPortCfg := newCallbackConfig("http://127.0.0.1:18267", true, 0)
		if got := localCallbackDNSAuthority(zeroPortCfg); got != "" {
			t.Errorf("localCallbackDNSAuthority(port=0) = %q, want empty", got)
		}
	})
}
