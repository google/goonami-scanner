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

// Package cache provides functions for caching and retrieving authentication strategies.
package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/log"
	goohttp "github.com/google/goonami-scanner/core/net/http"
	"github.com/google/goonami-scanner/core/net/netservice"
	"github.com/google/goonami-scanner/plugins/fingerprint/webidentity/hash"

	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
	wcpb "github.com/google/tsunami-security-scanner/proto/go/web_crawl_go_proto"
)

const (
	indexFileName  = "index.json"
	cacheDirName   = "cache"
	strategySuffix = ".strategy.json"
)

// Index of cached strategies.
type Index struct {
	indexpath string
	directory string

	mut        sync.RWMutex
	HashToPath map[string]string `json:"hash_to_path"`
}

// Load the index from disk.
func Load(ctx context.Context, path string) *Index {
	if path == "" {
		return nil
	}

	fullpath := filepath.Join(path, indexFileName)
	emptyIndex := &Index{
		indexpath:  fullpath,
		directory:  path,
		HashToPath: make(map[string]string),
	}

	data, err := os.ReadFile(fullpath)
	if err != nil {
		log.WarnContextf(ctx, "failed to load cache index, continuing with empty cache: %v", err)
		return emptyIndex
	}

	var idx Index
	idx.indexpath = fullpath
	idx.directory = path

	if err := json.Unmarshal(data, &idx); err != nil {
		log.WarnContextf(ctx, "failed to unmarshal cache index, continuing with empty cache: %v", err)
		return emptyIndex
	}

	if idx.HashToPath == nil {
		idx.HashToPath = make(map[string]string)
	}

	return &idx
}

// Add a new entry to the index and immediately saves it and its strategy to disk.
func (idx *Index) Add(ctx context.Context, cfg *config.Config, service *nspb.NetworkService, path string, strategy []byte) error {
	if idx == nil || idx.indexpath == "" {
		return nil
	}

	client, err := goohttp.NewClient(cfg, nil)
	if err != nil {
		return fmt.Errorf("creating http client: %w", err)
	}

	hash, err := fetchAndHashPage(ctx, cfg, client, service, path)
	if err != nil {
		return fmt.Errorf("can't hash page: %w", err)
	}

	idx.mut.Lock()
	defer idx.mut.Unlock()

	idx.HashToPath[hash] = path

	if err := idx.saveStrategy(hash, strategy); err != nil {
		return fmt.Errorf("can't save strategy: %w", err)
	}

	if err := idx.save(); err != nil {
		return fmt.Errorf("can't save index: %w", err)
	}

	return nil
}

// FindForService attempts to find a cached strategy for the service.
func (idx *Index) FindForService(ctx context.Context, cfg *config.Config, service *nspb.NetworkService) ([]byte, bool) {
	log.DebugContextf(ctx, log.DebugLevelRequest, "checking cache for service")
	if idx == nil || idx.indexpath == "" {
		return nil, false
	}

	idx.mut.RLock()
	pathToHashes := make(map[string][]string, len(idx.HashToPath))
	for expectedHash, path := range idx.HashToPath {
		pathToHashes[path] = append(pathToHashes[path], expectedHash)
	}
	idx.mut.RUnlock()

	client, err := goohttp.NewClient(cfg, nil)
	if err != nil {
		log.DebugContextf(ctx, log.DebugLevelRequest, "failed to create http client for cache check: %v", err)
		return nil, false
	}

	for path, expectedHashes := range pathToHashes {
		// First, we try to reuse the crawl results as much as possible.
		// There are two possible cases here: either the result exists and has the same hash (this is
		// cache hit) or it exists but has a different hash (then we do not want to process it further).
		if netservice.WasCrawled(service, path) {
			content, contentType, ok := netservice.GetCrawlContent(service, path)

			if !ok || contentType != wcpb.CrawlContentType_CONTENT_TYPE_HASH {
				continue
			}

			crawledHash := string(content)
			for _, expectedHash := range expectedHashes {
				if crawledHash == expectedHash {
					return idx.find(expectedHash)
				}
			}
			continue
		}

		// Otherwise we have to resort to fetching and hashing the path.
		gotHash, err := fetchAndHashPage(ctx, cfg, client, service, path)
		if err != nil {
			log.DebugContextf(ctx, log.DebugLevelRequest, "failed to fetch %s for cache check: %v", path, err)
			continue
		}

		for _, expectedHash := range expectedHashes {
			if gotHash == expectedHash {
				return idx.find(expectedHash)
			}
		}
		log.DebugContextf(ctx, log.DebugLevelRequest, "hash mismatch for %s: got %s", path, gotHash)
	}

	return nil, false
}

func (idx *Index) save() error {
	data, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling index: %w", err)
	}

	return os.WriteFile(idx.indexpath, data, 0644)
}

func (idx *Index) find(hash string) ([]byte, bool) {
	filename := hash + strategySuffix
	path := filepath.Join(idx.directory, cacheDirName, filename)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}

	return data, true
}

func (idx *Index) saveStrategy(hash string, strategy []byte) error {
	dir := filepath.Join(idx.directory, cacheDirName)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("creating cache directory: %w", err)
	}

	filename := hash + strategySuffix
	path := filepath.Join(dir, filename)
	return os.WriteFile(path, strategy, 0644)
}

func fetchAndHashPage(ctx context.Context, cfg *config.Config, client goohttp.Client, service *nspb.NetworkService, path string) (string, error) {
	if ctx.Err() != nil {
		return "", ctx.Err()
	}

	ctx, cancel := context.WithTimeout(ctx, cfg.TimeoutPerRequest())
	defer cancel()

	webroot, err := netservice.BuildWebRoot(service)
	if err != nil {
		return "", err
	}

	url := webroot + path
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		return "", fmt.Errorf("rate limited by server")
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	h, err := hash.FromResponse(resp, body)
	if err != nil {
		return "", err
	}

	return h.Hex(), nil
}
