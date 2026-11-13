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

package webidentity

import (
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/goonami-scanner/common/clients/httpcrawler"
	"google.golang.org/protobuf/testing/protocmp"

	wcpb "github.com/google/tsunami-security-scanner/proto/go/web_crawl_go_proto"
)

func createRunInfo() *runInfo {
	return &runInfo{
		crawlResults: make(map[string]*wcpb.CrawlResult),
	}
}

func TestRunInfoAddVisitedAndCrawlResults(t *testing.T) {
	type visitedPage struct {
		info    *httpcrawler.PageInfo
		resp    *http.Response
		content []byte
	}
	tests := []struct {
		name  string
		pages []visitedPage
		want  []*wcpb.CrawlResult
	}{
		{
			name: "when_multiple_pages_visited_returns_all_crawl_results",
			pages: []visitedPage{
				{
					info:    &httpcrawler.PageInfo{URL: "http://localhost/1", Depth: 1},
					resp:    &http.Response{StatusCode: 200},
					content: []byte("content1"),
				},
				{
					info:    &httpcrawler.PageInfo{URL: "http://localhost/2", Depth: 1},
					resp:    &http.Response{StatusCode: 404},
					content: []byte("content2"),
				},
			},
			want: []*wcpb.CrawlResult{
				wcpb.CrawlResult_builder{
					CrawlTarget:      wcpb.CrawlTarget_builder{Url: "http://localhost/1"}.Build(),
					CrawlDepth:       1,
					ResponseCode:     200,
					Content:          []byte("content1"),
					CrawlContentType: wcpb.CrawlContentType_CONTENT_TYPE_HASH,
				}.Build(),
				wcpb.CrawlResult_builder{
					CrawlTarget:      wcpb.CrawlTarget_builder{Url: "http://localhost/2"}.Build(),
					CrawlDepth:       1,
					ResponseCode:     404,
					Content:          []byte("content2"),
					CrawlContentType: wcpb.CrawlContentType_CONTENT_TYPE_HASH,
				}.Build(),
			},
		},
	}

	sortProtos := cmpopts.SortSlices(func(m1, m2 *wcpb.CrawlResult) bool { return m1.String() < m2.String() })
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ri := createRunInfo()
			for _, p := range tc.pages {
				ri.AddVisited(p.info, p.resp, p.content)
			}

			got := ri.CrawlResults()
			if diff := cmp.Diff(tc.want, got, protocmp.Transform(), sortProtos); diff != "" {
				t.Errorf("CrawlResults() returned diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestRunInfoHasCrawlResult(t *testing.T) {
	tests := []struct {
		name string
		urls []string
		url  string
		want bool
	}{
		{
			name: "when_url_exists_returns_true",
			urls: []string{"http://localhost/1", "http://localhost/2"},
			url:  "http://localhost/1",
			want: true,
		},
		{
			name: "when_url_does_not_exist_returns_false",
			urls: []string{"http://localhost/1"},
			url:  "http://localhost/not_found",
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ri := createRunInfo()
			for _, u := range tc.urls {
				ri.AddVisited(&httpcrawler.PageInfo{URL: u}, &http.Response{StatusCode: 200}, []byte("test"))
			}
			if got := ri.HasCrawlResult(tc.url); got != tc.want {
				t.Errorf("HasCrawlResult(%q) = %v, want %v", tc.url, got, tc.want)
			}
		})
	}
}
