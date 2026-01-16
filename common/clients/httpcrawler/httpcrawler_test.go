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

package httpcrawler

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/goonami-scanner/core/config"
	"google.golang.org/protobuf/testing/protocmp"

	cpb "github.com/google/goonami-scanner/common/clients/httpcrawler/httpcrawler_client_config_go_proto"
	cfgpb "github.com/google/goonami-scanner/core/config/config_go_proto"
	goohttp "github.com/google/goonami-scanner/core/net/http"
)

type testPage struct {
	links []string
}

func newTestServer(pages map[string]*testPage) *httptest.Server {
	handler := func(w http.ResponseWriter, r *http.Request) {
		p, ok := pages[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}

		if len(p.links) == 0 {
			return
		}

		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintln(w, "<html><body>")
		for _, link := range p.links {
			fmt.Fprintf(w, `<a href="%s">link</a>`, link)
		}
		fmt.Fprintln(w, "</body></html>")
	}
	return httptest.NewServer(http.HandlerFunc(handler))
}

func TestDefaultClientConfig(t *testing.T) {
	want := cpb.HttpCrawlerClientConfig_builder{
		MaxConcurrency:   3,
		MaxPageSizeBytes: 1 * 1024 * 1024,
		MaxDepth:         1,
		MaxRequests:      100,
		Exclusions: []string{
			".*abort.*", ".*delete.*", ".*drop.*", ".*huphuphup.*",
			".*kill.*", ".*quit.*", ".*remove.*",
		},
		ScopePolicy: cpb.HttpCrawlerClientConfig_SCOPE_POLICY_EXPAND,
	}.Build()
	got := DefaultClientConfig()
	if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
		t.Errorf("DefaultClientConfig() returned diff (-want +got):\n%s", diff)
	}
}

func TestCrawl(t *testing.T) {
	errTest := errors.New("test error")
	errAny := errors.New("any error")
	pages := map[string]*testPage{
		"/":              {links: []string{"/d1", "/d2", "/excluded/page", "/d3"}},
		"/d1":            {links: []string{"/d1/1"}},
		"/d1/1":          {links: []string{"/d1/1/2"}},
		"/d1/1/2":        {links: []string{"/", "/d1/"}},
		"/d2":            {links: []string{"http://outofscopedomain.lan/"}},
		"/d3":            {links: []string{"://localhost"}},
		"/empty":         {},
		"/excluded/page": {links: []string{"/d1"}},
	}
	srv := newTestServer(pages)
	defer srv.Close()

	// note: we reset the state at the beginning of each test, but we need it to be globally available
	// for the callback function.
	var crawled []string
	cb := func(i *PageInfo, _ *http.Response, _ []byte) error {
		crawled = append(crawled, i.URL)
		return nil
	}
	errCb := func(i *PageInfo, _ *http.Response, _ []byte) error {
		crawled = append(crawled, i.URL)
		return errTest
	}

	rootURL := srv.URL + "/"
	tests := []struct {
		name        string
		config      *config.Config
		startURLs   []string
		callback    PageCallback
		wantErr     error
		wantStats   *CrawlStats
		wantCrawled []string
	}{
		{
			name: "nil_callback_returns_error",
			config: config.FromProto(
				cfgpb.Config_builder{
					Globalcfg: cfgpb.GlobalConfig_builder{
						Performance: cfgpb.GlobalConfig_Performance_builder{
							MaxConcurrency:           1,
							TimeoutPerRequestSeconds: 2,
						}.Build(),
					}.Build(),
					Clients: cfgpb.ClientsConfig_builder{
						HttpCrawler: cpb.HttpCrawlerClientConfig_builder{
							MaxConcurrency:   1,
							MaxPageSizeBytes: 1024,
							MaxDepth:         1,
							MaxRequests:      10,
						}.Build(),
					}.Build(),
				}.Build(),
			),
			startURLs: []string{srv.URL},
			callback:  nil,
			wantErr:   ErrNoCallback,
		},
		{
			name: "malformed_start_url_returns_error",
			config: config.FromProto(
				cfgpb.Config_builder{
					Globalcfg: cfgpb.GlobalConfig_builder{
						Performance: cfgpb.GlobalConfig_Performance_builder{
							MaxConcurrency:           1,
							TimeoutPerRequestSeconds: 2,
						}.Build(),
					}.Build(),
					Clients: cfgpb.ClientsConfig_builder{
						HttpCrawler: cpb.HttpCrawlerClientConfig_builder{
							MaxConcurrency:   1,
							MaxPageSizeBytes: 1024,
							MaxDepth:         1,
							MaxRequests:      10,
						}.Build(),
					}.Build(),
				}.Build(),
			),
			startURLs: []string{"://localhost"},
			callback:  cb,
			wantErr:   errAny,
		},
		{
			name: "callback_error_propagates",
			config: config.FromProto(
				cfgpb.Config_builder{
					Globalcfg: cfgpb.GlobalConfig_builder{
						Performance: cfgpb.GlobalConfig_Performance_builder{
							MaxConcurrency:           1,
							TimeoutPerRequestSeconds: 2,
						}.Build(),
					}.Build(),
					Clients: cfgpb.ClientsConfig_builder{
						HttpCrawler: cpb.HttpCrawlerClientConfig_builder{
							MaxConcurrency:   1,
							MaxPageSizeBytes: 1024,
							MaxDepth:         1,
							MaxRequests:      10,
							ScopePolicy:      cpb.HttpCrawlerClientConfig_SCOPE_POLICY_EXPAND,
						}.Build(),
					}.Build(),
				}.Build(),
			),
			startURLs:   []string{rootURL},
			callback:    errCb,
			wantErr:     errTest,
			wantCrawled: []string{rootURL},
		},
		{
			name: "success_no_recursion",
			config: config.FromProto(
				cfgpb.Config_builder{
					Globalcfg: cfgpb.GlobalConfig_builder{
						Performance: cfgpb.GlobalConfig_Performance_builder{
							MaxConcurrency:           1,
							TimeoutPerRequestSeconds: 2,
						}.Build(),
					}.Build(),
					Clients: cfgpb.ClientsConfig_builder{
						HttpCrawler: cpb.HttpCrawlerClientConfig_builder{
							MaxConcurrency:   1,
							MaxPageSizeBytes: 1024,
							MaxDepth:         0,
							MaxRequests:      10,
							ScopePolicy:      cpb.HttpCrawlerClientConfig_SCOPE_POLICY_EXPAND,
						}.Build(),
					}.Build(),
				}.Build(),
			),
			startURLs:   []string{rootURL},
			callback:    cb,
			wantStats:   &CrawlStats{TotalPagesCrawled: 1},
			wantCrawled: []string{rootURL},
		},
		{
			name: "respect_max_page_size",
			config: config.FromProto(
				cfgpb.Config_builder{
					Globalcfg: cfgpb.GlobalConfig_builder{
						Performance: cfgpb.GlobalConfig_Performance_builder{
							MaxConcurrency:           1,
							TimeoutPerRequestSeconds: 2,
						}.Build(),
					}.Build(),
					Clients: cfgpb.ClientsConfig_builder{
						HttpCrawler: cpb.HttpCrawlerClientConfig_builder{
							MaxConcurrency:   1,
							MaxPageSizeBytes: 10,
							MaxDepth:         1,
							MaxRequests:      10,
						}.Build(),
					}.Build(),
				}.Build(),
			),
			// d2 is larger than 10 bytes, so the crawl count will be incremented but the callback will
			// not be called because the page will be dropped.
			startURLs:   []string{rootURL + "/d2"},
			callback:    cb,
			wantStats:   &CrawlStats{TotalPagesCrawled: 1},
			wantCrawled: nil,
		},
		{
			name: "respect_max_depth",
			config: config.FromProto(
				cfgpb.Config_builder{
					Globalcfg: cfgpb.GlobalConfig_builder{
						Performance: cfgpb.GlobalConfig_Performance_builder{
							MaxConcurrency:           1,
							TimeoutPerRequestSeconds: 2,
						}.Build(),
					}.Build(),
					Clients: cfgpb.ClientsConfig_builder{
						HttpCrawler: cpb.HttpCrawlerClientConfig_builder{
							MaxConcurrency:   1,
							MaxPageSizeBytes: 1024,
							MaxDepth:         1,
							MaxRequests:      10,
						}.Build(),
					}.Build(),
				}.Build(),
			),
			startURLs: []string{srv.URL},
			callback:  cb,
			wantStats: &CrawlStats{TotalPagesCrawled: 5},
			wantCrawled: []string{
				srv.URL,
				srv.URL + "/excluded/page",
				srv.URL + "/d1",
				srv.URL + "/d2",
				srv.URL + "/d3",
			},
		},
		{
			name: "respect_max_requests",
			config: config.FromProto(
				cfgpb.Config_builder{
					Globalcfg: cfgpb.GlobalConfig_builder{
						Performance: cfgpb.GlobalConfig_Performance_builder{
							MaxConcurrency:           1,
							TimeoutPerRequestSeconds: 2,
						}.Build(),
					}.Build(),
					Clients: cfgpb.ClientsConfig_builder{
						HttpCrawler: cpb.HttpCrawlerClientConfig_builder{
							MaxConcurrency:   1,
							MaxPageSizeBytes: 1024,
							MaxDepth:         10,
							MaxRequests:      2,
						}.Build(),
					}.Build(),
				}.Build(),
			),
			startURLs: []string{srv.URL + "/d1"},
			callback:  cb,
			// note: in the case of max requests, the page will be considered visited before the request
			// limit is hit.
			wantStats: &CrawlStats{TotalPagesCrawled: 3},
			wantCrawled: []string{
				srv.URL + "/d1",
				srv.URL + "/d1/1",
			},
		},
		{
			name: "respect_exclusions",
			config: config.FromProto(
				cfgpb.Config_builder{
					Globalcfg: cfgpb.GlobalConfig_builder{
						Performance: cfgpb.GlobalConfig_Performance_builder{
							MaxConcurrency:           1,
							TimeoutPerRequestSeconds: 2,
						}.Build(),
					}.Build(),
					Clients: cfgpb.ClientsConfig_builder{
						HttpCrawler: cpb.HttpCrawlerClientConfig_builder{
							MaxConcurrency:   1,
							MaxPageSizeBytes: 1024,
							MaxDepth:         1,
							MaxRequests:      10,
							Exclusions:       []string{".*excluded.*"},
						}.Build(),
					}.Build(),
				}.Build(),
			),
			startURLs:   []string{srv.URL},
			callback:    cb,
			wantStats:   &CrawlStats{TotalPagesCrawled: 4},
			wantCrawled: []string{srv.URL, srv.URL + "/d1", srv.URL + "/d2", srv.URL + "/d3"},
		},
		{
			name: "visit_pages_only_once",
			config: config.FromProto(
				cfgpb.Config_builder{
					Globalcfg: cfgpb.GlobalConfig_builder{
						Performance: cfgpb.GlobalConfig_Performance_builder{
							MaxConcurrency:           1,
							TimeoutPerRequestSeconds: 2,
						}.Build(),
					}.Build(),
					Clients: cfgpb.ClientsConfig_builder{
						HttpCrawler: cpb.HttpCrawlerClientConfig_builder{
							MaxConcurrency:   1,
							MaxPageSizeBytes: 1024,
							MaxDepth:         10,
							MaxRequests:      10,
						}.Build(),
					}.Build(),
				}.Build(),
			),
			startURLs: []string{srv.URL},
			callback:  cb,
			wantStats: &CrawlStats{TotalPagesCrawled: 7},
			wantCrawled: []string{
				srv.URL,
				srv.URL + "/d1",
				srv.URL + "/d1/1",
				srv.URL + "/d1/1/2",
				srv.URL + "/d2",
				srv.URL + "/d3",
				srv.URL + "/excluded/page",
			},
		},
		{
			name: "invalid_url_in_links_error_is_ignored",
			config: config.FromProto(
				cfgpb.Config_builder{
					Globalcfg: cfgpb.GlobalConfig_builder{
						Performance: cfgpb.GlobalConfig_Performance_builder{
							MaxConcurrency:           1,
							TimeoutPerRequestSeconds: 2,
						}.Build(),
					}.Build(),
					Clients: cfgpb.ClientsConfig_builder{
						HttpCrawler: cpb.HttpCrawlerClientConfig_builder{
							MaxConcurrency:   1,
							MaxPageSizeBytes: 1024,
							MaxDepth:         10,
							MaxRequests:      10,
						}.Build(),
					}.Build(),
				}.Build(),
			),
			startURLs: []string{srv.URL + "/d3"},
			callback:  cb,
			wantStats: &CrawlStats{TotalPagesCrawled: 1},
			wantCrawled: []string{
				srv.URL + "/d3",
			},
		},
		{
			name: "respect_scope",
			config: config.FromProto(
				cfgpb.Config_builder{
					Globalcfg: cfgpb.GlobalConfig_builder{
						Performance: cfgpb.GlobalConfig_Performance_builder{
							MaxConcurrency:           1,
							TimeoutPerRequestSeconds: 2,
						}.Build(),
					}.Build(),
					Clients: cfgpb.ClientsConfig_builder{
						HttpCrawler: cpb.HttpCrawlerClientConfig_builder{
							MaxConcurrency:   1,
							MaxPageSizeBytes: 1024,
							MaxDepth:         1,
							MaxRequests:      10,
						}.Build(),
					}.Build(),
				}.Build(),
			),
			startURLs:   []string{srv.URL + "/d2"},
			callback:    cb,
			wantStats:   &CrawlStats{TotalPagesCrawled: 1},
			wantCrawled: []string{srv.URL + "/d2"},
		},
		{
			name: "empty_response_is_ignored",
			config: config.FromProto(
				cfgpb.Config_builder{
					Globalcfg: cfgpb.GlobalConfig_builder{
						Performance: cfgpb.GlobalConfig_Performance_builder{
							MaxConcurrency:           1,
							TimeoutPerRequestSeconds: 2,
						}.Build(),
					}.Build(),
					Clients: cfgpb.ClientsConfig_builder{
						HttpCrawler: cpb.HttpCrawlerClientConfig_builder{
							MaxConcurrency:   1,
							MaxPageSizeBytes: 1024,
							MaxDepth:         1,
							MaxRequests:      10,
						}.Build(),
					}.Build(),
				}.Build(),
			),
			startURLs:   []string{srv.URL + "/empty"},
			callback:    cb,
			wantStats:   &CrawlStats{TotalPagesCrawled: 1},
			wantCrawled: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			crawled = nil
			if err := goohttp.InitializeDefaults(tc.config); err != nil {
				t.Fatalf("failed to initialize http library defaults: %v", err)
			}
			sc := NewSimpleCrawler(tc.config)

			ctx := context.Background()
			stats, err := sc.Crawl(ctx, tc.callback, tc.startURLs)
			if tc.wantErr != nil {
				if err == nil {
					t.Fatalf("Crawl() returned nil error, want non-nil")
				}
				if tc.wantErr != errAny && !errors.Is(err, tc.wantErr) {
					t.Fatalf("Crawl() returned error %v, want %v", err, tc.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("Crawl() returned error %v, want nil", err)
			}

			if tc.wantStats != nil {
				if diff := cmp.Diff(tc.wantStats, stats); diff != "" {
					t.Errorf("Crawl() returned unexpected stats (-want +got):\n%s", diff)
				}
			}

			sort.Strings(crawled)
			sort.Strings(tc.wantCrawled)
			if diff := cmp.Diff(tc.wantCrawled, crawled); diff != "" {
				t.Errorf("Crawl() crawled unexpected pages (-want +got):\n%s", diff)
			}
		})
	}
}
