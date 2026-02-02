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
	"strings"
	"sync"

	"github.com/google/goonami-scanner/common/clients/httpcrawler"
	"github.com/google/goonami-scanner/core/log"
	"github.com/google/goonami-scanner/plugins/fingerprint/webidentity/hash"
	wcpb "github.com/google/tsunami-security-scanner/proto/go/web_crawl_go_proto"
)

// runInfo contains internal state for a single run of the fingerprinting module.
type runInfo struct {
	mut          sync.Mutex
	matches      map[string][]*hash.Identity
	crawlResults map[string]*wcpb.CrawlResult
}

func (m *runInfo) AddMatch(identity *hash.Identity) {
	m.mut.Lock()
	defer m.mut.Unlock()

	software := identity.Software
	if _, ok := m.matches[software]; !ok {
		log.Debugf(log.DebugLevelService, "[fp/webidentity] found a known web application: %q", software)
		m.matches[software] = []*hash.Identity{identity}
		return
	}

	for _, knownID := range m.matches[software] {
		for _, newPath := range identity.PotentialRoots {
			for _, knownPath := range knownID.PotentialRoots {
				if strings.HasPrefix(newPath, knownPath) {
					knownID.IntersectVersions(identity)
					return
				}
			}
		}
	}

	// We did not find a match, so we add a new identity.
	m.matches[software] = append(m.matches[software], identity)
	return
}

func (m *runInfo) AddVisited(info *httpcrawler.PageInfo, resp *http.Response, content []byte) {
	m.mut.Lock()
	defer m.mut.Unlock()

	m.crawlResults[info.URL] = wcpb.CrawlResult_builder{
		CrawlTarget: wcpb.CrawlTarget_builder{
			Url: info.URL,
		}.Build(),
		CrawlDepth:   info.Depth,
		ResponseCode: int32(resp.StatusCode),
		Content:      content,
	}.Build()
}

func (m *runInfo) CrawlResults() []*wcpb.CrawlResult {
	m.mut.Lock()
	defer m.mut.Unlock()

	var crawlResults []*wcpb.CrawlResult
	for _, result := range m.crawlResults {
		crawlResults = append(crawlResults, result)
	}

	return crawlResults
}

func (m *runInfo) Matches() map[string][]*hash.Identity {
	m.mut.Lock()
	defer m.mut.Unlock()

	return m.matches
}
