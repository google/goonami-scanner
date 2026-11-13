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
	"sync"

	"github.com/google/goonami-scanner/common/clients/httpcrawler"

	wcpb "github.com/google/tsunami-security-scanner/proto/go/web_crawl_go_proto"
)

// runInfo contains internal state for a single run of the fingerprinting module.
type runInfo struct {
	mut          sync.Mutex
	crawlResults map[string]*wcpb.CrawlResult
}

// AddVisited records a visited page and its content hash in the crawl results.
func (r *runInfo) AddVisited(info *httpcrawler.PageInfo, resp *http.Response, content []byte) {
	r.mut.Lock()
	defer r.mut.Unlock()

	r.crawlResults[info.URL] = wcpb.CrawlResult_builder{
		CrawlTarget: wcpb.CrawlTarget_builder{
			Url: info.URL,
		}.Build(),
		CrawlDepth:       info.Depth,
		ResponseCode:     int32(resp.StatusCode),
		Content:          content,
		CrawlContentType: wcpb.CrawlContentType_CONTENT_TYPE_HASH,
	}.Build()
}

// HasCrawlResult reports whether a crawl result exists for the given URL.
func (r *runInfo) HasCrawlResult(url string) bool {
	r.mut.Lock()
	defer r.mut.Unlock()

	_, ok := r.crawlResults[url]
	return ok
}

// CrawlResults returns all recorded crawl results.
func (r *runInfo) CrawlResults() []*wcpb.CrawlResult {
	r.mut.Lock()
	defer r.mut.Unlock()

	var crawlResults []*wcpb.CrawlResult
	for _, result := range r.crawlResults {
		crawlResults = append(crawlResults, result)
	}

	return crawlResults
}
