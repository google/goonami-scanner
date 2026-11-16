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
	"maps"
	"net/url"
	"slices"
	"strings"

	"github.com/google/goonami-scanner/core/log"
	"github.com/google/goonami-scanner/core/net/netservice"
	"github.com/google/goonami-scanner/plugins/fingerprint/webidentity/engine"
	"google.golang.org/protobuf/proto"

	npb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
	spb "github.com/google/tsunami-security-scanner/proto/go/software_go_proto"
	wcpb "github.com/google/tsunami-security-scanner/proto/go/web_crawl_go_proto"
)

type rootResult struct {
	fullRoots []string
	result    *engine.IdentificationResult
}

type identifiedApp struct {
	software string
	appRoot  string
	versions []string
	steps    []string
}

func mergeUniqueSorted(a, b []string) []string {
	merged := make([]string, 0, len(a)+len(b))
	merged = append(merged, a...)
	merged = append(merged, b...)
	slices.Sort(merged)
	return slices.Compact(merged)
}

func reconcileIdentifiedApps(apps []*identifiedApp) []*identifiedApp {
	var reconciled []*identifiedApp
	for _, app := range apps {
		idx := slices.IndexFunc(reconciled, func(existing *identifiedApp) bool {
			return existing.software == app.software &&
				existing.appRoot == app.appRoot &&
				slices.Equal(existing.versions, app.versions)
		})
		if idx >= 0 {
			reconciled[idx].steps = mergeUniqueSorted(reconciled[idx].steps, app.steps)
			continue
		}
		reconciled = append(reconciled, &identifiedApp{
			software: app.software,
			appRoot:  app.appRoot,
			versions: slices.Clone(app.versions),
			steps:    mergeUniqueSorted(app.steps, nil),
		})
	}
	return reconciled
}

func sameIdentification(a, b *engine.IdentificationResult) bool {
	return a.Software == b.Software &&
		a.ApplicationRoot == b.ApplicationRoot &&
		slices.Equal(a.Versions, b.Versions)
}

func buildIdentifiedServices(ctx context.Context, service *nspb.NetworkService, identifications []*rootResult, crawlResults []*wcpb.CrawlResult) []*nspb.NetworkService {
	if len(identifications) == 0 {
		log.DebugContextf(ctx, log.DebugLevelService, "no matches found for service")
		netservice.AddCrawlResults(service, crawlResults)
		return []*nspb.NetworkService{service}
	}

	var networkServices []*nspb.NetworkService
	var knownRoots []string
	for _, ir := range identifications {
		primaryRoot := ir.fullRoots[0]
		knownRoots = append(knownRoots, ir.fullRoots...)
		log.DebugContextf(ctx, log.DebugLevelService, "identified service: %s at %s (versions: %v)", ir.result.Software, primaryRoot, ir.result.Versions)
		networkServices = append(networkServices, identityToNewService(service, crawlResults, ir.result, ir.fullRoots))
	}

	if svc := serviceFromUnidentifiedCrawls(service, knownRoots, crawlResults); svc != nil {
		networkServices = append(networkServices, svc)
	}

	return networkServices
}

func serviceFromUnidentifiedCrawls(service *nspb.NetworkService, knownRoots []string, crawls []*wcpb.CrawlResult) *nspb.NetworkService {
	var unidentifiedCrawls []*wcpb.CrawlResult
	for _, result := range crawls {
		targetURL := result.GetCrawlTarget().GetUrl()
		if slices.ContainsFunc(knownRoots, func(root string) bool { return strings.HasPrefix(targetURL, root) }) {
			continue
		}
		unidentifiedCrawls = append(unidentifiedCrawls, result)
	}

	if len(unidentifiedCrawls) == 0 {
		return nil
	}

	newService := proto.CloneOf(service)
	netservice.AddCrawlResults(newService, unidentifiedCrawls)
	return newService
}

// identityToNewService returns a copy of service populated with identification and crawl results.
func identityToNewService(service *nspb.NetworkService, crawls []*wcpb.CrawlResult, idResult *engine.IdentificationResult, fullRoots []string) *nspb.NetworkService {
	newService := proto.CloneOf(service)

	var results []*wcpb.CrawlResult
	for _, r := range crawls {
		targetURL := r.GetCrawlTarget().GetUrl()
		if slices.ContainsFunc(fullRoots, func(root string) bool { return strings.HasPrefix(targetURL, root) }) {
			results = append(results, r)
		}
	}
	netservice.AddCrawlResults(newService, results)

	var versions []*spb.Version
	for _, v := range idResult.Versions {
		versions = append(versions, spb.Version_builder{
			Type:              spb.Version_NORMAL,
			FullVersionString: v,
		}.Build())
	}

	wsc := newService.GetServiceContext().GetWebServiceContext()
	wsc.SetSoftware(spb.Software_builder{Name: idResult.Software}.Build())
	if len(versions) > 0 {
		wsc.SetVersionSet(spb.VersionSet_builder{Versions: versions}.Build())
	} else {
		wsc.SetVersionSet(&spb.VersionSet{})
	}
	wsc.SetApplicationRoot(applicationRootPath(fullRoots[0]))

	return newService
}

// If a network service is identified by both a hostname and an IP address, split it into two
// services, one for each endpoint, then reconcile results afterwards.
func splitServiceByEndpoint(service *nspb.NetworkService) []*nspb.NetworkService {
	endpoint := service.GetNetworkEndpoint()
	if !endpoint.HasHostname() || !endpoint.HasIpAddress() {
		return []*nspb.NetworkService{service}
	}

	hostEpType := npb.NetworkEndpoint_HOSTNAME
	ipEpType := npb.NetworkEndpoint_IP
	if endpoint.HasPort() {
		hostEpType = npb.NetworkEndpoint_HOSTNAME_PORT
		ipEpType = npb.NetworkEndpoint_IP_PORT
	}

	hostService := proto.CloneOf(service)
	hostService.SetNetworkEndpoint(npb.NetworkEndpoint_builder{
		Type:     hostEpType,
		Hostname: endpoint.GetHostname(),
		Port:     endpoint.GetPort(),
	}.Build())

	ipService := proto.CloneOf(service)
	ipService.SetNetworkEndpoint(npb.NetworkEndpoint_builder{
		Type:      ipEpType,
		IpAddress: endpoint.GetIpAddress(),
		Port:      endpoint.GetPort(),
	}.Build())

	return []*nspb.NetworkService{hostService, ipService}
}

func reconcileServices(baseService *nspb.NetworkService, services []*nspb.NetworkService) []*nspb.NetworkService {
	var reconciled []*nspb.NetworkService
	for _, s := range services {
		i := slices.IndexFunc(reconciled, func(r *nspb.NetworkService) bool {
			return areServicesIdentical(r, s)
		})
		if i == -1 {
			reconciled = append(reconciled, s)
			continue
		}
		reconciled[i].SetNetworkEndpoint(baseService.GetNetworkEndpoint())
		netservice.AddCrawlResults(reconciled[i], s.GetServiceContext().GetWebServiceContext().GetCrawlResults())
	}
	return reconciled
}

func areServicesIdentical(s1, s2 *nspb.NetworkService) bool {
	wsc1 := s1.GetServiceContext().GetWebServiceContext()
	wsc2 := s2.GetServiceContext().GetWebServiceContext()

	if wsc1.HasSoftware() && wsc2.HasSoftware() {
		return wsc1.GetSoftware().GetName() == wsc2.GetSoftware().GetName() &&
			extractPath(wsc1.GetApplicationRoot()) == extractPath(wsc2.GetApplicationRoot()) &&
			proto.Equal(wsc1.GetVersionSet(), wsc2.GetVersionSet())
	}

	if wsc1.HasSoftware() != wsc2.HasSoftware() {
		return false
	}

	return maps.Equal(crawlHashes(wsc1), crawlHashes(wsc2))
}

func crawlHashes(wsc *nspb.WebServiceContext) map[string]string {
	hashes := make(map[string]string, len(wsc.GetCrawlResults()))
	for _, r := range wsc.GetCrawlResults() {
		hashes[extractPath(r.GetCrawlTarget().GetUrl())] = string(r.GetContent())
	}
	return hashes
}

func extractPath(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return u.Path
}

func applicationRootPath(rawURL string) string {
	path := strings.TrimRight(extractPath(rawURL), "/")
	if path == "" {
		return "/"
	}
	if !strings.HasPrefix(path, "/") {
		return "/" + path
	}
	return path
}
