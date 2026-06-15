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

// Package netservice provides utility functions to work with the NetworkService proto.
package netservice

import (
	"fmt"
	"net/url"

	"github.com/google/goonami-scanner/core/net/netendpoint"

	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
	wcpb "github.com/google/tsunami-security-scanner/proto/go/web_crawl_go_proto"
)

// HasTLS returns whether the network service supports SSL/TLS.
func HasTLS(service *nspb.NetworkService) bool {
	return len(service.GetSupportedSslVersions()) > 0
}

// IsWebService returns whether the network service is a web service.
func IsWebService(service *nspb.NetworkService) bool {
	return len(service.GetSupportedHttpMethods()) > 0
}

// BuildWebRoot returns the HTTP(S) URL used to query the web root of the given endpoint.
func BuildWebRoot(service *nspb.NetworkService) (string, error) {
	authority, err := netendpoint.ToURIAuthority(service.GetNetworkEndpoint())
	if err != nil {
		return "", err
	}

	protocol := "http"
	if HasTLS(service) {
		protocol = "https"
	}

	return fmt.Sprintf("%s://%s", protocol, authority), nil
}

// AddCrawlResults adds the given set of crawl results to the service context.
func AddCrawlResults(service *nspb.NetworkService, crawlResults []*wcpb.CrawlResult) {
	if !service.HasServiceContext() {
		service.SetServiceContext(&nspb.ServiceContext{})
	}

	if !service.GetServiceContext().HasWebServiceContext() {
		service.SetServiceContext(nspb.ServiceContext_builder{
			WebServiceContext: &nspb.WebServiceContext{},
		}.Build())
	}

	results := service.GetServiceContext().GetWebServiceContext().GetCrawlResults()
	results = append(results, crawlResults...)
	service.GetServiceContext().GetWebServiceContext().SetCrawlResults(results)
}

// WasCrawled returns whether the given URI was crawled on the given service.
// Note that crawl results store the absolute URI, so we need to perform the resolution first.
func WasCrawled(service *nspb.NetworkService, uri string) bool {
	webRoot, err := BuildWebRoot(service)
	if err != nil {
		return false
	}

	base, err := url.Parse(webRoot)
	if err != nil {
		return false
	}

	ref, err := url.Parse(uri)
	if err != nil {
		return false
	}

	targetURL := base.ResolveReference(ref).String()
	for _, result := range service.GetServiceContext().GetWebServiceContext().GetCrawlResults() {
		if result.GetCrawlTarget().GetUrl() == targetURL {
			return true
		}
	}

	return false
}
