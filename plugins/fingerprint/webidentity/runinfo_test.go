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
	"context"
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/goonami-scanner/common/clients/httpcrawler"
	"github.com/google/goonami-scanner/plugins/fingerprint/webidentity/hash"
	wcpb "github.com/google/tsunami-security-scanner/proto/go/web_crawl_go_proto"
	"google.golang.org/protobuf/testing/protocmp"
)

func createRunInfo() *runInfo {
	return &runInfo{
		matches:      make(map[string][]*hash.Identity),
		crawlResults: make(map[string]*wcpb.CrawlResult),
	}
}

func TestRunInfo_AddMatch(t *testing.T) {
	tests := []struct {
		name     string
		existing func() map[string][]*hash.Identity
		new      *hash.Identity
		want     map[string][]*hash.Identity
	}{
		{
			name: "when_adding_first_identity_it_creates_a_new_entry",
			existing: func() map[string][]*hash.Identity {
				return make(map[string][]*hash.Identity)
			},
			new: &hash.Identity{
				Software:       "test",
				PotentialRoots: []string{"/"},
				Versions:       []string{"1.0"},
			},
			want: map[string][]*hash.Identity{
				"test": []*hash.Identity{
					{
						Software:       "test",
						PotentialRoots: []string{"/"},
						Versions:       []string{"1.0"},
					},
				},
			},
		},
		{
			name: "when_adding_identity_with_different_root_it_creates_a_new_entry",
			existing: func() map[string][]*hash.Identity {
				return map[string][]*hash.Identity{
					"test": []*hash.Identity{{
						Software:       "test",
						PotentialRoots: []string{"/forum"},
						Versions:       []string{"1.0", "1.1"},
					}},
				}
			},
			new: &hash.Identity{
				Software:       "test",
				PotentialRoots: []string{"/blog"},
				Versions:       []string{"1.1", "1.2"},
			},
			want: map[string][]*hash.Identity{
				"test": []*hash.Identity{
					{
						Software:       "test",
						PotentialRoots: []string{"/forum"},
						Versions:       []string{"1.0", "1.1"},
					},
					{
						Software:       "test",
						PotentialRoots: []string{"/blog"},
						Versions:       []string{"1.1", "1.2"},
					},
				},
			},
		},
		{
			name: "when_adding_identity_with_more_specific_path_it_updates_existing_entry",
			existing: func() map[string][]*hash.Identity {
				return map[string][]*hash.Identity{
					"test": []*hash.Identity{{
						Software:       "test",
						PotentialRoots: []string{"/forum"},
						Versions:       []string{"1.0", "1.1"},
					}},
				}
			},
			new: &hash.Identity{
				Software:       "test",
				PotentialRoots: []string{"/forum/images"},
				Versions:       []string{"1.1"},
			},
			want: map[string][]*hash.Identity{
				"test": []*hash.Identity{
					{
						Software:       "test",
						PotentialRoots: []string{"/forum"},
						Versions:       []string{"1.1"},
					},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ri := runInfo{matches: tc.existing(), crawlResults: make(map[string]*wcpb.CrawlResult)}
			ri.AddMatch(context.Background(), tc.new)
			if diff := cmp.Diff(tc.want, ri.matches, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("AddMatch(...) resulted in unexpected matches diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestRunInfo_AddVisited_and_CrawlResults(t *testing.T) {
	ri := createRunInfo()
	info1 := &httpcrawler.PageInfo{URL: "http://localhost/1", Depth: 1}
	resp1 := &http.Response{StatusCode: 200}
	content1 := []byte("content1")
	info2 := &httpcrawler.PageInfo{URL: "http://localhost/2", Depth: 1}
	resp2 := &http.Response{StatusCode: 404}
	content2 := []byte("content2")

	ri.AddVisited(info1, resp1, content1)
	ri.AddVisited(info2, resp2, content2)

	want := []*wcpb.CrawlResult{
		wcpb.CrawlResult_builder{
			CrawlTarget:      wcpb.CrawlTarget_builder{Url: "http://localhost/1"}.Build(),
			CrawlDepth:       1,
			ResponseCode:     200,
			Content:          content1,
			CrawlContentType: wcpb.CrawlContentType_CONTENT_TYPE_HASH,
		}.Build(),
		wcpb.CrawlResult_builder{
			CrawlTarget:      wcpb.CrawlTarget_builder{Url: "http://localhost/2"}.Build(),
			CrawlDepth:       1,
			ResponseCode:     404,
			Content:          content2,
			CrawlContentType: wcpb.CrawlContentType_CONTENT_TYPE_HASH,
		}.Build(),
	}

	got := ri.CrawlResults()
	sortProtos := cmpopts.SortSlices(func(m1, m2 *wcpb.CrawlResult) bool { return m1.String() < m2.String() })
	if diff := cmp.Diff(want, got, protocmp.Transform(), sortProtos); diff != "" {
		t.Errorf("CrawlResults() returned diff (-want +got):\n%s", diff)
	}
}

func TestRunInfo_Matches(t *testing.T) {
	ri := createRunInfo()
	id1 := &hash.Identity{Software: "foo", PotentialRoots: []string{"/"}, Versions: []string{"1.0"}}
	id2 := &hash.Identity{Software: "bar", PotentialRoots: []string{"/bar"}, Versions: []string{"2.0"}}
	ri.AddMatch(context.Background(), id1)
	ri.AddMatch(context.Background(), id2)

	want := map[string][]*hash.Identity{
		"foo": []*hash.Identity{id1},
		"bar": []*hash.Identity{id2},
	}
	got := ri.Matches()
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Matches() returned diff (-want +got):\n%s", diff)
	}
}
