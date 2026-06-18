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
	"github.com/google/goonami-scanner/common/clients/httpcrawler/scope"
	"github.com/google/goonami-scanner/core/config"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"

	cpb "github.com/google/goonami-scanner/common/clients/httpcrawler/httpcrawler_client_config_go_proto"
	cfgpb "github.com/google/goonami-scanner/core/config/config_go_proto"
	_ "github.com/google/goonami-scanner/core/net/http/simpleclient"
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
		MaxConcurrency:   proto.Int32(1),
		MaxPageSizeBytes: proto.Int32(1 * 1024 * 1024),
		MaxDepth:         proto.Int32(1),
		MaxRequests:      proto.Int32(100),
		Exclusions: []string{
			".*abort.*", ".*delete.*", ".*drop.*", ".*huphuphup.*",
			".*kill.*", ".*quit.*", ".*remove.*",
		},
		ScopePolicy: cpb.HttpCrawlerClientConfig_SCOPE_POLICY_EXPAND.Enum(),
	}.Build()
	got := DefaultClientConfig()
	if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
		t.Errorf("DefaultClientConfig() returned diff (-want +got):\n%s", diff)
	}
}

func testConfig() *config.Config {
	return config.FromProto(
		cfgpb.Config_builder{
			Globalcfg: cfgpb.GlobalConfig_builder{
				Performance: cfgpb.GlobalConfig_Performance_builder{
					TimeoutPerRequestSeconds: proto.Int32(2),
				}.Build(),
			}.Build(),
			Clients: cfgpb.ClientsConfig_builder{
				HttpCrawler: cpb.HttpCrawlerClientConfig_builder{
					MaxConcurrency: proto.Int32(1),
					MaxDepth:       proto.Int32(10),
					MaxRequests:    proto.Int32(10),
				}.Build(),
			}.Build(),
		}.Build(),
	)
}

func TestCrawl(t *testing.T) {
	errTest := errors.New("test error")
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
	cb := func(_ context.Context, i *PageInfo, _ *http.Response, _ []byte) error {
		crawled = append(crawled, i.URL)
		return nil
	}
	errCb := func(_ context.Context, i *PageInfo, _ *http.Response, _ []byte) error {
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
			name:      "when_callback_is_nil_returns_error",
			config:    testConfig(),
			startURLs: []string{srv.URL},
			callback:  nil,
			wantErr:   ErrNoCallback,
		},
		{
			name:      "when_start_url_is_malformed_returns_error",
			config:    testConfig(),
			startURLs: []string{"://localhost"},
			callback:  cb,
			wantErr:   scope.ErrParseURL,
		},
		{
			name: "when_callback_errors_it_propagates_error",
			config: config.FromProto(
				cfgpb.Config_builder{
					Clients: cfgpb.ClientsConfig_builder{
						HttpCrawler: cpb.HttpCrawlerClientConfig_builder{
							ScopePolicy: cpb.HttpCrawlerClientConfig_SCOPE_POLICY_EXPAND.Enum(),
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
			name: "when_recursion_is_disabled_it_crawls_only_start_urls",
			config: config.FromProto(
				cfgpb.Config_builder{
					Clients: cfgpb.ClientsConfig_builder{
						HttpCrawler: cpb.HttpCrawlerClientConfig_builder{
							MaxDepth:    proto.Int32(0),
							ScopePolicy: cpb.HttpCrawlerClientConfig_SCOPE_POLICY_EXPAND.Enum(),
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
			name: "when_page_size_exceeds_max_it_is_dropped",
			config: config.FromProto(
				cfgpb.Config_builder{
					Clients: cfgpb.ClientsConfig_builder{
						HttpCrawler: cpb.HttpCrawlerClientConfig_builder{
							MaxPageSizeBytes: proto.Int32(10),
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
			name: "when_max_depth_is_reached_it_stops_crawling",
			config: config.FromProto(
				cfgpb.Config_builder{
					Clients: cfgpb.ClientsConfig_builder{
						HttpCrawler: cpb.HttpCrawlerClientConfig_builder{
							MaxDepth: proto.Int32(1),
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
			name: "when_max_requests_is_reached_it_stops_crawling",
			config: config.FromProto(
				cfgpb.Config_builder{
					Clients: cfgpb.ClientsConfig_builder{
						HttpCrawler: cpb.HttpCrawlerClientConfig_builder{
							MaxConcurrency: proto.Int32(1),
							MaxRequests:    proto.Int32(2),
							MaxDepth:       proto.Int32(10),
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
			name: "when_url_matches_exclusion_it_is_not_crawled",
			config: config.FromProto(
				cfgpb.Config_builder{
					Clients: cfgpb.ClientsConfig_builder{
						HttpCrawler: cpb.HttpCrawlerClientConfig_builder{
							Exclusions: []string{".*excluded.*"},
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
			name: "when_pages_are_linked_multiple_times_they_are_visited_only_once",
			config: config.FromProto(
				cfgpb.Config_builder{
					Clients: cfgpb.ClientsConfig_builder{
						HttpCrawler: cpb.HttpCrawlerClientConfig_builder{
							MaxDepth: proto.Int32(10),
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
			name: "when_links_contain_invalid_urls_errors_are_ignored",
			config: config.FromProto(
				cfgpb.Config_builder{
					Clients: cfgpb.ClientsConfig_builder{
						HttpCrawler: cpb.HttpCrawlerClientConfig_builder{
							MaxDepth: proto.Int32(10),
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
			name:        "when_links_are_out_of_scope_they_are_not_crawled",
			config:      testConfig(),
			startURLs:   []string{srv.URL + "/d2"},
			callback:    cb,
			wantStats:   &CrawlStats{TotalPagesCrawled: 1},
			wantCrawled: []string{srv.URL + "/d2"},
		},
		{
			name:        "when_response_is_empty_it_is_ignored",
			config:      testConfig(),
			startURLs:   []string{srv.URL + "/empty"},
			callback:    cb,
			wantStats:   &CrawlStats{TotalPagesCrawled: 1},
			wantCrawled: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			crawled = nil

			ctx := t.Context()
			sc := NewSimpleCrawler(ctx, tc.config)
			stats, err := sc.Crawl(ctx, tc.callback, tc.startURLs)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Crawl() returned error %v, want %v", err, tc.wantErr)
			}

			if tc.wantErr != nil {
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
