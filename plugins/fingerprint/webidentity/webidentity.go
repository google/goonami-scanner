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

// Package webidentity provides a fingerprinter to identify specifically a web service.
package webidentity

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"

	"github.com/google/goonami-scanner/common/clients/httpcrawler"
	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/log"
	"github.com/google/goonami-scanner/core/metrics"
	"github.com/google/goonami-scanner/core/module"
	goohttp "github.com/google/goonami-scanner/core/net/http"
	"github.com/google/goonami-scanner/core/net/netservice"
	"github.com/google/goonami-scanner/plugins/fingerprint/webidentity/cache"
	"github.com/google/goonami-scanner/plugins/fingerprint/webidentity/engine"
	"github.com/google/goonami-scanner/plugins/fingerprint/webidentity/hash"
	"github.com/google/goonami-scanner/plugins/fingerprint/webidentity/storage"

	wfpb "github.com/google/goonami-scanner/plugins/fingerprint/webidentity/webidentity_fp_config_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
	wcpb "github.com/google/tsunami-security-scanner/proto/go/web_crawl_go_proto"
)

const (
	moduleName = "fp/webidentity"
)

var (
	// ErrArtifactsWrite is returned when writing an artifact file fails.
	ErrArtifactsWrite = errors.New("writing artifact file")
)

// Module is the fingerprinter to detect what product is running on a web server. It is the module
// most people refer to as "web fingerprinting".
type Module struct {
	*module.BaseModule
	config     *wfpb.WebIdentityFpConfig
	coreConfig *config.Config
	storage    *storage.Storage
	engine     *engine.Engine
}

func init() {
	module.RegisterFingerprinter(moduleName, New)
}

// New returns a new instance of the module.
func New(ctx context.Context, config *config.Config) (module.Fingerprinter, error) {
	modConfig := config.PluginsConfig().GetWebidentity()
	ctx = log.ContextForModule(ctx, moduleName)

	compiledFps, err := loadAllFingerprints(ctx, modConfig)
	if err != nil {
		return nil, err
	}
	log.DebugContextf(ctx, log.DebugLevelSession, "Loaded %d signatures", len(compiledFps))

	return newWithEngine(ctx, modConfig, config, engine.New(compiledFps))
}

// newWithEngine performs the initialization of the module once the checks have been performed
// and the engine loaded. This function is used in tests to load custom engines or fingerprints.
func newWithEngine(ctx context.Context, modConfig *wfpb.WebIdentityFpConfig, config *config.Config, eng *engine.Engine) (module.Fingerprinter, error) {
	return &Module{
		BaseModule: module.NewBaseModule(moduleName),
		coreConfig: config,
		config:     modConfig,
		storage:    storage.New(modConfig.GetWriteHtmlToFile(), modConfig.GetMaximumStorageSpaceBytes()),
		engine:     eng,
	}, nil
}

// Fingerprint identifies the web application running on a web server. Note that this fingerprinter
// can potentially return **several** network services if it hosts several web applications.
func (m *Module) Fingerprint(ctx context.Context, service *nspb.NetworkService) ([]*nspb.NetworkService, error) {
	if !netservice.IsWebService(service) {
		return []*nspb.NetworkService{service}, nil
	}

	ctx = log.ContextForModuleAndService(ctx, moduleName, service)
	crawler := httpcrawler.NewSimpleCrawler(ctx, m.coreConfig)
	var allServices []*nspb.NetworkService
	var allIdentifications []*identifiedApp
	for _, epService := range splitServiceByEndpoint(service) {
		services, apps, err := m.fingerprintEndpoint(ctx, crawler, epService)
		if err != nil {
			return nil, err
		}
		allServices = append(allServices, services...)
		allIdentifications = append(allIdentifications, apps...)
	}

	reconciled := reconcileServices(service, allServices)
	for _, app := range reconcileIdentifiedApps(allIdentifications) {
		for _, step := range app.steps {
			metrics.FingerprintIdentifications.Add(ctx, 1, metrics.Fingerprint(app.software), metrics.FingerprintRule(step))
		}
	}
	return reconciled, nil
}

func (m *Module) fingerprintEndpoint(ctx context.Context, crawler *httpcrawler.SimpleCrawler, service *nspb.NetworkService) ([]*nspb.NetworkService, []*identifiedApp, error) {
	webroot, err := netservice.BuildWebRoot(service)
	if err != nil {
		return nil, nil, err
	}

	run := &runInfo{
		crawlResults: make(map[string]*wcpb.CrawlResult),
	}
	httpCache := cache.New(goohttp.SharedClient(m.coreConfig))

	if err := m.crawl(ctx, crawler, run, webroot, httpCache); err != nil {
		return nil, nil, err
	}

	return m.matching(ctx, run, service, httpCache, webroot)
}

func (m *Module) crawl(ctx context.Context, crawler *httpcrawler.SimpleCrawler, run *runInfo, webroot string, httpCache *cache.Cache) error {
	seeds := []string{webroot + "/"}

	var bytesWritten int64
	callback := func(ctx context.Context, info *httpcrawler.PageInfo, resp *http.Response, content []byte) error {
		if httpCache != nil {
			httpCache.Put(http.MethodGet, info.URL, resp, content)
		}
		bytes, err := m.processPage(ctx, run, info, resp, content)
		if err == nil { // success
			bytesWritten += bytes
		}

		return err
	}

	log.DebugContextf(ctx, log.DebugLevelService, "starting crawling")
	stats, err := crawler.Crawl(ctx, callback, seeds)
	if err != nil {
		return err
	}

	log.DebugContextf(ctx, log.DebugLevelService, "crawled %d pages (%d bytes written)", stats.TotalPagesCrawled, bytesWritten)
	return nil
}

// processPage processes a single page. This function is called on every page during the crawl.
func (m *Module) processPage(ctx context.Context, run *runInfo, info *httpcrawler.PageInfo, resp *http.Response, content []byte) (int64, error) {
	h, err := hash.FromResponse(resp, content)
	if err != nil {
		return 0, err
	}
	hexHash := h.Hex()

	run.AddVisited(info, resp, []byte(hexHash))

	if !m.config.GetWriteHtmlToFile() {
		return 0, nil
	}

	return m.writeToArtifacts(ctx, info, hexHash, content)
}

func (m *Module) writeToArtifacts(ctx context.Context, info *httpcrawler.PageInfo, hexHash string, content []byte) (int64, error) {
	artifactsDir, err := m.coreConfig.ArtifactsForModule(moduleName)
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrArtifactsWrite, err)
	}

	// Given that the filename is the hash of the content, we know that an existing file necessarily
	// has the same content: so we can skip the write.
	path := filepath.Join(artifactsDir, hexHash)
	if _, err := os.Stat(path); err == nil {
		log.DebugContextf(ctx, log.DebugLevelRequest, "not writing (already exists) for: %q (%s)", info.URL, hexHash)
		return 0, nil
	}

	contentSize := int64(len(content))
	if contentSize > m.config.GetMaximumFileSizeBytes() {
		log.DebugContextf(ctx, log.DebugLevelRequest, "not writing (file too big) for: %q (%s)", info.URL, hexHash)
		return 0, nil
	}

	if !m.storage.Reserve(contentSize) {
		log.DebugContextf(ctx, log.DebugLevelRequest, "not writing (storage full) for: %q (%s)", info.URL, hexHash)
		return 0, nil
	}

	if err := os.WriteFile(path, content, 0644); err != nil {
		m.storage.Release(contentSize)
		return 0, fmt.Errorf("%w: %v", ErrArtifactsWrite, err)
	}

	return contentSize, nil
}

func (m *Module) matching(ctx context.Context, run *runInfo, service *nspb.NetworkService, httpCache *cache.Cache, webroot string) ([]*nspb.NetworkService, []*identifiedApp, error) {
	identifications, err := m.runEngineOnWebRoots(ctx, httpCache, []string{webroot})
	if err != nil {
		return nil, nil, err
	}

	apps := make([]*identifiedApp, 0, len(identifications))
	for _, ir := range identifications {
		apps = append(apps, &identifiedApp{
			software: ir.result.Software,
			appRoot:  applicationRootPath(ir.fullRoots[0]),
			versions: ir.result.Versions,
			steps:    ir.result.MatchedSteps,
		})
	}

	m.recordActiveCachePages(ctx, run, httpCache)
	return buildIdentifiedServices(ctx, service, identifications, run.CrawlResults()), apps, nil
}

func (m *Module) runEngineOnWebRoots(ctx context.Context, httpCache *cache.Cache, webroots []string) ([]*rootResult, error) {
	var allIdentifications []*rootResult
	for _, root := range webroots {
		results, err := m.engine.Run(ctx, httpCache, root)
		if err != nil {
			return nil, err
		}
		for _, r := range results {
			fullRoot := root + r.ApplicationRoot
			idx := slices.IndexFunc(allIdentifications, func(existing *rootResult) bool {
				return sameIdentification(existing.result, r)
			})
			if idx >= 0 {
				allIdentifications[idx].fullRoots = append(allIdentifications[idx].fullRoots, fullRoot)
				allIdentifications[idx].result.MatchedSteps = mergeUniqueSorted(allIdentifications[idx].result.MatchedSteps, r.MatchedSteps)
				continue
			}
			allIdentifications = append(allIdentifications, &rootResult{
				fullRoots: []string{fullRoot},
				result:    r,
			})
		}
	}
	return allIdentifications, nil
}

func (m *Module) recordActiveCachePages(ctx context.Context, run *runInfo, httpCache *cache.Cache) {
	if httpCache == nil {
		return
	}
	for _, entry := range httpCache.All() {
		if entry.URL == nil || entry.StatusCode != http.StatusOK {
			continue
		}
		rawURL := entry.URL.String()
		if !run.HasCrawlResult(rawURL) {
			_, _ = m.processPage(ctx, run, &httpcrawler.PageInfo{URL: rawURL}, entry.Response(), entry.Body)
		}
	}
}
