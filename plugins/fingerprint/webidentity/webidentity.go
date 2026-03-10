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
	"strings"

	"github.com/google/goonami-scanner/common/clients/httpcrawler"
	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/log"
	"github.com/google/goonami-scanner/core/module"
	"github.com/google/goonami-scanner/core/net/netservice"
	"github.com/google/goonami-scanner/plugins/fingerprint/webidentity/hash"
	"github.com/google/goonami-scanner/plugins/fingerprint/webidentity/storage"
	"google.golang.org/protobuf/proto"

	fpb "github.com/google/goonami-scanner/plugins/fingerprint/webidentity/fingerprints_go_proto"
	wfpb "github.com/google/goonami-scanner/plugins/fingerprint/webidentity/webidentity_fp_config_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
	spb "github.com/google/tsunami-security-scanner/proto/go/software_go_proto"
	wcpb "github.com/google/tsunami-security-scanner/proto/go/web_crawl_go_proto"
)

const (
	moduleName = "fp/webidentity"
)

var (
	// ErrNoFingerprintsDirectory indicates that the configuration does not specify the path to the
	// directory containing the signatures.
	ErrNoFingerprintsDirectory = errors.New("invalid configuration: the webidentity plugin REQUIRES the path to the directory containing the signatures, none found")

	// ErrSignaturesRead is returned when there is an error while reading a signature file.
	ErrSignaturesRead = errors.New("error while reading signature file")

	// ErrSignaturesUnmarshal is returned when there is an error while unmarshaling a signature.
	ErrSignaturesUnmarshal = errors.New("error while unmarshaling signature")

	// ErrArtifactsWrite is returned when there is an error while writing an artifact file.
	ErrArtifactsWrite = errors.New("error while writing artifact file")
)

// DefaultConfig returns the default configuration for the webidentity plugin.
func DefaultConfig() *wfpb.WebIdentityFpConfig {
	return wfpb.WebIdentityFpConfig_builder{
		WriteHtmlToFile:          proto.Bool(false),
		MaximumFileSizeBytes:     proto.Int64(1 * 1024 * 1024),   // 1 MB
		MaximumStorageSpaceBytes: proto.Int64(100 * 1024 * 1024), // 100 MB
	}.Build()
}

// Module is the fingerprinter to detect what product is running on a web server. It is the module
// most people refer to as "web fingerprinting".
type Module struct {
	*module.BaseModule
	config     *wfpb.WebIdentityFpConfig
	coreConfig *config.Config
	crawler    *httpcrawler.SimpleCrawler
	storage    *storage.Storage
	registry   *hash.Registry
}

// New returns a new instance of the module.
func New(ctx context.Context, config *config.Config) (module.Fingerprinter, error) {
	modConfig := DefaultConfig()

	if config.PluginsConfig().HasWebidentity() {
		proto.Merge(modConfig, config.PluginsConfig().GetWebidentity())
	}

	if modConfig.GetSignaturesDirectory() == "" {
		return nil, ErrNoFingerprintsDirectory
	}

	ctx = log.ContextForModule(ctx, moduleName)

	registry := hash.NewRegistry()
	if err := loadAllFingerprints(ctx, modConfig, registry); err != nil {
		return nil, err
	}
	log.DebugContextf(ctx, log.DebugLevelSession, "Loaded %d signatures", registry.Count())

	return newWithRegistry(ctx, modConfig, config, registry)
}

// newWithRegistry performs the initialization of the module once the checks have been performed
// and the registry loaded. This function is used in tests to load custom registries.
func newWithRegistry(ctx context.Context, modConfig *wfpb.WebIdentityFpConfig, config *config.Config, registry *hash.Registry) (module.Fingerprinter, error) {
	return &Module{
		BaseModule: module.NewBaseModule(moduleName),
		coreConfig: config,
		config:     modConfig,
		crawler:    httpcrawler.NewSimpleCrawler(ctx, config),
		storage:    storage.New(modConfig.GetWriteHtmlToFile(), modConfig.GetMaximumStorageSpaceBytes()),
		registry:   registry,
	}, nil
}

// Fingerprint identifies the web application running on a web server. Note that this fingerprinter
// can potentially return **several** network services if it hosts several web applications.
func (m *Module) Fingerprint(ctx context.Context, service *nspb.NetworkService) ([]*nspb.NetworkService, error) {
	if !netservice.IsWebService(service) {
		return []*nspb.NetworkService{service}, nil
	}

	run := &runInfo{
		matches:      make(map[string][]*hash.Identity),
		crawlResults: make(map[string]*wcpb.CrawlResult),
	}

	if err := m.crawl(ctx, run, service); err != nil {
		return nil, err
	}

	return m.matching(ctx, run, service)
}

func (m *Module) crawl(ctx context.Context, run *runInfo, service *nspb.NetworkService) error {
	webroot, err := netservice.BuildWebRoot(service)
	if err != nil {
		return fmt.Errorf("%w: %w", module.ErrFatal, err)
	}
	webroot = webroot + "/"

	var bytesWritten int64
	callback := func(ctx context.Context, info *httpcrawler.PageInfo, resp *http.Response, content []byte) error {
		bytes, err := m.processPage(ctx, run, info, resp, content)
		if err == nil { // success
			bytesWritten += bytes
		}

		return err
	}

	log.DebugContextf(ctx, log.DebugLevelService, "starting crawling")
	stats, err := m.crawler.Crawl(ctx, callback, []string{webroot})
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return fmt.Errorf("%w: %w", module.ErrFatal, err)
		}

		return fmt.Errorf("%w: %w", module.ErrRecoverable, err)
	}

	log.DebugContextf(ctx, log.DebugLevelService, "crawled %d pages (%d bytes written)", stats.TotalPagesCrawled, bytesWritten)
	return nil
}

// processPage processes a single page. This function is called on every page during the crawl.
func (m *Module) processPage(ctx context.Context, run *runInfo, info *httpcrawler.PageInfo, resp *http.Response, content []byte) (int64, error) {
	hash, err := hash.FromResponse(resp, content)
	if err != nil {
		return 0, err
	}
	hexHash := hash.Hex()

	run.AddVisited(info, resp, []byte(hexHash))
	if identity := m.registry.Find(hexHash, info.URL); identity != nil {
		run.AddMatch(ctx, identity)
	}

	if !m.config.GetWriteHtmlToFile() {
		return 0, nil
	}

	return m.writeToArtifacts(ctx, info, hexHash, content)
}

func (m *Module) writeToArtifacts(ctx context.Context, info *httpcrawler.PageInfo, hexHash string, content []byte) (int64, error) {
	// Given that the filename is the hash of the content, we know that an existing file necessarily
	// has the same content: so we can skip the write.
	path := filepath.Join(m.coreConfig.ArtifactsDirectory(), hexHash)
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

func (m *Module) matching(ctx context.Context, run *runInfo, service *nspb.NetworkService) ([]*nspb.NetworkService, error) {
	crawlResults := run.CrawlResults()
	matches := run.Matches()
	if len(matches) == 0 {
		netservice.AddCrawlResults(service, crawlResults)
		return []*nspb.NetworkService{service}, nil
	}

	var networkServices []*nspb.NetworkService
	for _, identities := range matches {
		for _, identity := range identities {
			networkServices = append(networkServices, identityToNewService(ctx, service, crawlResults, identity))
		}
	}

	var knownRoots []string
	for _, identities := range matches {
		for _, identity := range identities {
			knownRoots = append(knownRoots, identity.PotentialRoots...)
		}
	}

	svc := serviceFromUnidentifiedCrawls(service, knownRoots, crawlResults)
	if svc != nil {
		networkServices = append(networkServices, svc)
	}

	return networkServices, nil
}

func serviceFromUnidentifiedCrawls(service *nspb.NetworkService, knownRoots []string, crawls []*wcpb.CrawlResult) *nspb.NetworkService {
	var unidentifiedCrawls []*wcpb.CrawlResult
	newService := proto.Clone(service).(*nspb.NetworkService)

	for _, result := range crawls {
		foundRoot := false

		for _, root := range knownRoots {
			if strings.HasPrefix(result.GetCrawlTarget().GetUrl(), root) {
				foundRoot = true
				break
			}
		}

		if foundRoot {
			continue
		}

		unidentifiedCrawls = append(unidentifiedCrawls, result)
	}

	if len(unidentifiedCrawls) == 0 {
		return nil
	}

	netservice.AddCrawlResults(newService, unidentifiedCrawls)
	return newService
}

// Make a copy of the provided service with information obtained from the identity. It also adds the
// relevant crawl results to the service.
func identityToNewService(ctx context.Context, service *nspb.NetworkService, crawls []*wcpb.CrawlResult, identity *hash.Identity) *nspb.NetworkService {
	newService := proto.Clone(service).(*nspb.NetworkService)
	software := identity.Software

	// first, we add the relevant crawl results to the service.
	var results []*wcpb.CrawlResult
	for _, root := range identity.PotentialRoots {
		for _, r := range crawls {
			url := r.GetCrawlTarget().GetUrl()
			if strings.HasPrefix(url, root) {
				results = append(results, r)
			}
		}
	}

	netservice.AddCrawlResults(newService, results)

	// then all the identification information
	var versions []*spb.Version
	for _, v := range identity.Versions {
		versions = append(versions, spb.Version_builder{FullVersionString: v}.Build())
	}

	wsc := newService.GetServiceContext().GetWebServiceContext()
	wsc.SetSoftware(spb.Software_builder{Name: software}.Build())
	wsc.SetVersionSet(spb.VersionSet_builder{Versions: versions}.Build())

	if len(identity.PotentialRoots) != 1 {
		log.WarnContextf(ctx, "software:%q has %d roots. This is likely an issue. Please report to Goonami developpers.", software, len(identity.PotentialRoots))
	} else {
		wsc.SetApplicationRoot(identity.PotentialRoots[0])
	}

	return newService
}

// Retrieves the directory containing the signatures.
func getSignaturesDirectory(config *wfpb.WebIdentityFpConfig) (string, error) {
	root := ""
	return filepath.Join(root, config.GetSignaturesDirectory()), nil
}

// Load all signatures from the directory defined in the configuration.
func loadAllFingerprints(ctx context.Context, config *wfpb.WebIdentityFpConfig, registry *hash.Registry) error {
	sigDirectory, err := getSignaturesDirectory(config)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrSignaturesRead, err)
	}

	log.DebugContextf(ctx, log.DebugLevelRequest, "signatures directory is: %q", sigDirectory)
	dirs, err := os.ReadDir(sigDirectory)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrSignaturesRead, err)
	}

	for _, dir := range dirs {
		if dir.IsDir() {
			continue
		}

		if !strings.HasSuffix(dir.Name(), ".binproto") {
			continue
		}

		filePath := filepath.Join(sigDirectory, dir.Name())
		fingerprints, err := os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("%w %q: %w", ErrSignaturesRead, filePath, err)
		}

		log.DebugContextf(ctx, log.DebugLevelRequest, "loading signatures: %q", dir.Name())
		fingerprintsProto := &fpb.Fingerprints{}
		if err := proto.Unmarshal(fingerprints, fingerprintsProto); err != nil {
			return fmt.Errorf("%w %q: %w", ErrSignaturesUnmarshal, filePath, err)
		}

		if err := registry.Load(fingerprintsProto); err != nil {
			return err
		}
	}

	return nil
}
