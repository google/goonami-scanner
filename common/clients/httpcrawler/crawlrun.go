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
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/goonami-scanner/common/clients/httpcrawler/scope"
)

// maxDecodeIterations is the maximum number of times we attempt to URL-decode a string.
const maxDecodeIterations = 10

// crawlRun tracks the current run of the crawler.
type crawlRun struct {
	queue     chan *PageInfo
	scopes    []*scope.Scope
	callback  PageCallback
	mut       sync.Mutex
	workCount int
	visited   map[string]bool
}

// Callback simply calls the callback function that was registered for this run.
func (r *crawlRun) Callback(ctx context.Context, info *PageInfo, resp *http.Response, content []byte) error {
	return r.callback(ctx, info, resp, content)
}

// QueuePage adds a new page to the queue for crawling.
// Note: The caller is likely using one of the goroutine slots. If we try to queue directly, we risk
// starving as we will have to wait for the queue (that we are blocking). Hence, we need to queue
// new work in a separate goroutine.
func (r *crawlRun) QueuePage(url string, depth int32) {
	r.mut.Lock()
	r.workCount++
	r.mut.Unlock()
	go func() { r.queue <- &PageInfo{URL: url, Depth: depth} }()
}

// Pages returns the channel of pages to be crawled so it can be iterated over.
func (r *crawlRun) Pages() chan *PageInfo {
	return r.queue
}

// PageDone is called when a page is done being crawled.
func (r *crawlRun) PageDone() {
	r.mut.Lock()
	defer r.mut.Unlock()
	r.workCount--
}

// normalizeURL normalizes a URL for visited-tracking by:
//  1. Iteratively URL-decoding the URL until it stabilizes (handles multi-encoded parameters like
//     %253F which decodes to %3F, then to ?).
//  2. Stripping query parameters and fragments from the decoded URL.
//  3. Removing trailing slashes.
func normalizeURL(rawurl string) string {
	decoded := fullyDecode(rawurl)

	if i := strings.IndexAny(decoded, "?#"); i != -1 {
		decoded = decoded[:i]
	}

	return strings.TrimRight(decoded, "/")
}

// fullyDecode iteratively URL-decodes a string until it no longer changes.
func fullyDecode(s string) string {
	for i := 0; i < maxDecodeIterations; i++ {
		decoded, err := url.PathUnescape(s)
		if err != nil || decoded == s {
			return s
		}
		s = decoded
	}

	return s
}

// AlreadyVisited returns true if the given URL has already been visited.
func (r *crawlRun) AlreadyVisited(rawurl string) bool {
	normalized := normalizeURL(rawurl)

	r.mut.Lock()
	defer r.mut.Unlock()
	return r.visited[normalized]
}

// AddToVisited adds a new URL to the visited set.
func (r *crawlRun) AddToVisited(rawurl string) {
	normalized := normalizeURL(rawurl)

	r.mut.Lock()
	defer r.mut.Unlock()
	r.visited[normalized] = true
}

// CountVisited returns the number of visited URLs (i.e. requests sent for this run).
func (r *crawlRun) CountVisited() int32 {
	r.mut.Lock()
	defer r.mut.Unlock()
	return int32(len(r.visited))
}

// CountPending returns the number of pending crawls.
func (r *crawlRun) CountPending() int {
	r.mut.Lock()
	defer r.mut.Unlock()
	return r.workCount
}

func (r *crawlRun) Close() {
	close(r.queue)
}

// Note: Our concurrency is feeding itself. Thus, it is very difficult to detect when the work
// is actually done. This is not a very elegant approach, but as a workaround we keep track of the
// work count (in progress or to be done) until there is no more work to be done.
func (r *crawlRun) StartWatcher() {
	go func() {
		defer close(r.queue)
		for {
			if r.CountPending() == 0 {
				return
			}

			time.Sleep(time.Millisecond * 100)
		}
	}()
}
