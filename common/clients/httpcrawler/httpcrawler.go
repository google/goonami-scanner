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

// Package httpcrawler provides a simple web crawler.
package httpcrawler

import (
	"context"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"

	"github.com/google/goonami-scanner/common/clients/httpcrawler/parser"
	"github.com/google/goonami-scanner/common/clients/httpcrawler/scope"
	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/log"
	goohttp "github.com/google/goonami-scanner/core/net/http"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/proto"

	cpb "github.com/google/goonami-scanner/common/clients/httpcrawler/httpcrawler_client_config_go_proto"
)

var (
	// ErrNoCallback is returned when the crawler is called without a callback function.
	ErrNoCallback = errors.New("a valid callback function is required")
)

// PageCallback is a function that is called on every page crawled. The response's body MUST NOT be
// used at all. Use the content parameter instead.
type PageCallback func(ctx context.Context, info *PageInfo, resp *http.Response, content []byte) error

// Crawler is the interface for a web crawler.
type Crawler interface {
	Crawl(context.Context, PageCallback, []string) (*CrawlStats, error)
}

// DefaultClientConfig returns the default configuration for the HTTP crawler client.
func DefaultClientConfig() *cpb.HttpCrawlerClientConfig {
	return cpb.HttpCrawlerClientConfig_builder{
		MaxConcurrency:   proto.Int32(1),
		MaxPageSizeBytes: proto.Int32(1 * 1024 * 1024), // 1 MB
		MaxDepth:         proto.Int32(1),
		MaxRequests:      proto.Int32(100),
		Exclusions: []string{
			".*abort.*", ".*delete.*", ".*drop.*", ".*huphuphup.*",
			".*kill.*", ".*quit.*", ".*remove.*",
		},
		ScopePolicy: cpb.HttpCrawlerClientConfig_SCOPE_POLICY_EXPAND.Enum(),
	}.Build()
}

// SimpleCrawler is a simple implementation of the Crawler interface.
type SimpleCrawler struct {
	config          *cpb.HttpCrawlerClientConfig
	coreConfig      *config.Config
	exclusionRegexp []*regexp.Regexp
	mut             sync.Mutex
	sentRequests    int32
}

// PageInfo contains information about the currently crawled page.
type PageInfo struct {
	URL   string
	Depth int32
}

// CrawlStats contains statistics about the crawl.
type CrawlStats struct {
	TotalPagesCrawled int32
}

// NewSimpleCrawler creates a new SimpleCrawler.
func NewSimpleCrawler(ctx context.Context, config *config.Config) *SimpleCrawler {
	ctx = log.ContextForModule(ctx, "client/httpcrawler")
	clientConfig := DefaultClientConfig()
	if config.ClientsConfig().HasHttpCrawler() {
		proto.Merge(clientConfig, config.ClientsConfig().GetHttpCrawler())
	}

	if clientConfig.GetMaxPageSizeBytes() == 0 {
		log.WarnContextf(ctx, "max page size is 0, everything will be dropped")
	}

	var pathExclusionsRegexp []*regexp.Regexp
	for _, pathExclusion := range clientConfig.GetExclusions() {
		pathExclusionsRegexp = append(pathExclusionsRegexp, regexp.MustCompile(pathExclusion))
	}

	return &SimpleCrawler{
		config:          clientConfig,
		coreConfig:      config,
		exclusionRegexp: pathExclusionsRegexp,
	}
}

// Crawl starts the crawling process.
func (c *SimpleCrawler) Crawl(ctx context.Context, callback PageCallback, urls []string) (*CrawlStats, error) {
	if callback == nil {
		return nil, ErrNoCallback
	}

	run := &crawlRun{
		queue:    make(chan *PageInfo, 500),
		visited:  make(map[string]bool),
		callback: callback,
	}

	scopes, err := scope.Load(c.config, urls)
	if err != nil {
		return nil, err
	}

	ctx = log.ContextForModule(ctx, "client/httpcrawler")
	run.scopes = scopes
	for _, url := range urls {
		if err := c.queueForCrawl(ctx, url, 0, run); err != nil {
			return nil, err
		}
	}

	run.StartWatcher()
	group, grpctx := errgroup.WithContext(ctx)
	group.SetLimit(int(c.config.GetMaxConcurrency()))

	for page := range run.Pages() {
		group.Go(func() error {
			return c.crawlPage(grpctx, run, page)
		})
	}

	if err := group.Wait(); err != nil {
		return nil, err
	}

	return &CrawlStats{
		TotalPagesCrawled: run.CountVisited(),
	}, nil
}

func (c *SimpleCrawler) crawlPage(ctx context.Context, run *crawlRun, page *PageInfo) error {
	defer func() { run.PageDone() }()

	if ctx.Err() != nil {
		return ctx.Err()
	}

	ctx, cancel := context.WithTimeout(ctx, c.coreConfig.TimeoutPerRequest())
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", page.URL, nil)
	if err != nil {
		return err
	}

	if !c.checkAndIncreaseRequestCount() {
		log.DebugContextf(ctx, log.DebugLevelRequest, "skipping (max requests): %s", page.URL)
		return nil
	}

	log.DebugContextf(ctx, log.DebugLevelRequest, "visiting: %q", page.URL)
	resp, err := goohttp.DefaultClient().Do(req)
	if err != nil {
		// Do not consider deadline errors as fatal.
		if strings.Contains(err.Error(), "context deadline exceeded") {
			log.DebugContextf(ctx, log.DebugLevelRequest, "skipping (deadline exceeded): %q", page.URL)
			return nil
		}

		return err
	}

	maxsize := int(c.config.GetMaxPageSizeBytes())
	content, err := goohttp.ReadBody(resp, maxsize)
	if err != nil {
		if err == goohttp.ErrPageTooBig {
			log.DebugContextf(ctx, log.DebugLevelRequest, "skipping (page too big): %q", page.URL)
			return nil
		}

		if strings.Contains(err.Error(), "context deadline exceeded") {
			log.DebugContextf(ctx, log.DebugLevelRequest, "skipping (deadline exceeded): %q", page.URL)
			return nil
		}

		if err == io.EOF {
			log.DebugContextf(ctx, log.DebugLevelRequest, "skipping (empty page): %q", page.URL)
			return nil
		}

		return err
	}
	resp.Body.Close()

	if content == nil {
		return nil
	}

	return c.processResponse(ctx, run, page, resp, content)
}

func (c *SimpleCrawler) processResponse(ctx context.Context, run *crawlRun, page *PageInfo, resp *http.Response, content []byte) error {
	if err := run.Callback(ctx, page, resp, content); err != nil {
		return err
	}

	links, err := parser.ExtractLinksFromHTML(page.URL, content)
	if err != nil {
		log.WarnContextf(ctx, "failed to parse links from %q: %v", page.URL, err)
		return nil
	}

	newdepth := page.Depth + 1
	for _, link := range links {
		if err := c.queueForCrawl(ctx, link, newdepth, run); err != nil {
			return err
		}
	}

	return nil
}

// queueForCrawl performs the necessary checks and queue a page for later crawling.
func (c *SimpleCrawler) queueForCrawl(ctx context.Context, url string, depth int32, run *crawlRun) error {
	if depth > c.config.GetMaxDepth() {
		log.DebugContextf(ctx, log.DebugLevelRequest, "skipping (max depth): %q", url)
		return nil
	}

	if c.isExcluded(url) {
		log.DebugContextf(ctx, log.DebugLevelRequest, "skipping (excluded): %q", url)
		return nil
	}

	inScope, err := scope.MatchAnyScope(url, run.scopes)
	if err != nil {
		return err
	}

	if !inScope {
		log.DebugContextf(ctx, log.DebugLevelRequest, "skipping (scope): %q", url)
		return nil
	}

	if run.AlreadyVisited(url) {
		log.DebugContextf(ctx, log.DebugLevelRequest, "skipping (already visited): %q", url)
		return nil
	}
	run.AddToVisited(url)

	run.QueuePage(url, depth)
	return nil
}

func (c *SimpleCrawler) isExcluded(path string) bool {
	for _, regexp := range c.exclusionRegexp {
		if regexp.MatchString(path) {
			return true
		}
	}

	return false
}

func (c *SimpleCrawler) checkAndIncreaseRequestCount() bool {
	c.mut.Lock()
	defer c.mut.Unlock()
	newcount := c.sentRequests + 1

	if newcount > c.config.GetMaxRequests() {
		return false
	}

	c.sentRequests++
	return true
}
