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

package netservice

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	npb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
	wcpb "github.com/google/tsunami-security-scanner/proto/go/web_crawl_go_proto"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestHasTLS(t *testing.T) {
	tests := []struct {
		name    string
		service *nspb.NetworkService
		want    bool
	}{
		{
			name:    "when_no_ssl_versions_are_present_returns_false",
			service: nspb.NetworkService_builder{}.Build(),
			want:    false,
		},
		{
			name: "when_ssl_versions_are_present_returns_true",
			service: nspb.NetworkService_builder{
				SupportedSslVersions: []string{"TLSv1.2"},
			}.Build(),
			want: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := HasTLS(tc.service); got != tc.want {
				t.Errorf("HasTLS(%v) = %v, want: %v", tc.service, got, tc.want)
			}
		})
	}
}

func TestIsWebService(t *testing.T) {
	tests := []struct {
		name    string
		service *nspb.NetworkService
		want    bool
	}{
		{
			name:    "when_no_http_methods_are_present_returns_false",
			service: nspb.NetworkService_builder{}.Build(),
			want:    false,
		},
		{
			name: "when_http_methods_are_present_returns_true",
			service: nspb.NetworkService_builder{
				SupportedHttpMethods: []string{"GET"},
			}.Build(),
			want: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsWebService(tc.service); got != tc.want {
				t.Errorf("IsWebService(%v) = %v, want: %v", tc.service, got, tc.want)
			}
		})
	}
}

func TestBuildWebRoot(t *testing.T) {
	tests := []struct {
		name    string
		service *nspb.NetworkService
		want    string
		wantErr bool
	}{
		{
			name: "when_no_tls_is_supported_returns_http_uri",
			service: nspb.NetworkService_builder{
				NetworkEndpoint: npb.NetworkEndpoint_builder{
					Hostname: npb.Hostname_builder{Name: "localhost.lan"}.Build(),
					Port:     npb.Port_builder{PortNumber: 80}.Build(),
				}.Build(),
			}.Build(),
			want:    "http://localhost.lan:80",
			wantErr: false,
		},
		{
			name: "when_tls_is_supported_returns_https_uri",
			service: nspb.NetworkService_builder{
				NetworkEndpoint: npb.NetworkEndpoint_builder{
					Hostname: npb.Hostname_builder{Name: "localhost.lan"}.Build(),
					Port:     npb.Port_builder{PortNumber: 443}.Build(),
				}.Build(),
				SupportedSslVersions: []string{"TLSv1.2"},
			}.Build(),
			want:    "https://localhost.lan:443",
			wantErr: false,
		},
		{
			name: "when_endpoint_is_missing_address_returns_error",
			service: nspb.NetworkService_builder{
				NetworkEndpoint: npb.NetworkEndpoint_builder{
					Port: npb.Port_builder{PortNumber: 80}.Build(),
				}.Build(),
			}.Build(),
			want:    "",
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := BuildWebRoot(tc.service)
			if tc.wantErr != (err != nil) {
				t.Fatalf("BuildWebRoot(%v) got err %v, wantErr: %v", tc.service, err, tc.wantErr)
			}
			if got != tc.want {
				t.Errorf("BuildWebRoot(%v) = %v, want: %v", tc.service, got, tc.want)
			}
		})
	}
}

func TestAddCrawlResults(t *testing.T) {
	tests := []struct {
		name         string
		service      *nspb.NetworkService
		crawlResults []*wcpb.CrawlResult
		want         *nspb.NetworkService
	}{
		{
			name:    "when_service_context_is_missing_it_is_created",
			service: nspb.NetworkService_builder{}.Build(),
			crawlResults: []*wcpb.CrawlResult{
				wcpb.CrawlResult_builder{
					CrawlTarget: wcpb.CrawlTarget_builder{Url: "http://local.lan/1"}.Build(),
				}.Build(),
			},
			want: nspb.NetworkService_builder{
				ServiceContext: nspb.ServiceContext_builder{
					WebServiceContext: nspb.WebServiceContext_builder{
						CrawlResults: []*wcpb.CrawlResult{
							wcpb.CrawlResult_builder{
								CrawlTarget: wcpb.CrawlTarget_builder{Url: "http://local.lan/1"}.Build(),
							}.Build(),
						},
					}.Build(),
				}.Build(),
			}.Build(),
		},
		{
			name: "when_web_service_context_is_missing_it_is_created",
			service: nspb.NetworkService_builder{
				ServiceContext: nspb.ServiceContext_builder{}.Build(),
			}.Build(),
			crawlResults: []*wcpb.CrawlResult{
				wcpb.CrawlResult_builder{
					CrawlTarget: wcpb.CrawlTarget_builder{Url: "http://local.lan/1"}.Build(),
				}.Build(),
			},
			want: nspb.NetworkService_builder{
				ServiceContext: nspb.ServiceContext_builder{
					WebServiceContext: nspb.WebServiceContext_builder{
						CrawlResults: []*wcpb.CrawlResult{
							wcpb.CrawlResult_builder{
								CrawlTarget: wcpb.CrawlTarget_builder{Url: "http://local.lan/1"}.Build(),
							}.Build(),
						},
					}.Build(),
				}.Build(),
			}.Build(),
		},
		{
			name: "when_crawl_results_are_missing_they_are_initialized_with_new_results",
			service: nspb.NetworkService_builder{
				ServiceContext: nspb.ServiceContext_builder{
					WebServiceContext: nspb.WebServiceContext_builder{}.Build(),
				}.Build(),
			}.Build(),
			crawlResults: []*wcpb.CrawlResult{
				wcpb.CrawlResult_builder{
					CrawlTarget: wcpb.CrawlTarget_builder{Url: "http://local.lan/1"}.Build(),
				}.Build(),
			},
			want: nspb.NetworkService_builder{
				ServiceContext: nspb.ServiceContext_builder{
					WebServiceContext: nspb.WebServiceContext_builder{
						CrawlResults: []*wcpb.CrawlResult{
							wcpb.CrawlResult_builder{
								CrawlTarget: wcpb.CrawlTarget_builder{Url: "http://local.lan/1"}.Build(),
							}.Build(),
						},
					}.Build(),
				}.Build(),
			}.Build(),
		},
		{
			name: "when_crawl_results_already_exist_new_results_are_appended",
			service: nspb.NetworkService_builder{
				ServiceContext: nspb.ServiceContext_builder{
					WebServiceContext: nspb.WebServiceContext_builder{
						CrawlResults: []*wcpb.CrawlResult{
							wcpb.CrawlResult_builder{
								CrawlTarget: wcpb.CrawlTarget_builder{Url: "http://local.lan/1"}.Build(),
							}.Build(),
						},
					}.Build(),
				}.Build(),
			}.Build(),
			crawlResults: []*wcpb.CrawlResult{
				wcpb.CrawlResult_builder{
					CrawlTarget: wcpb.CrawlTarget_builder{Url: "http://local.lan/2"}.Build(),
				}.Build(),
			},
			want: nspb.NetworkService_builder{
				ServiceContext: nspb.ServiceContext_builder{
					WebServiceContext: nspb.WebServiceContext_builder{
						CrawlResults: []*wcpb.CrawlResult{
							wcpb.CrawlResult_builder{
								CrawlTarget: wcpb.CrawlTarget_builder{Url: "http://local.lan/1"}.Build(),
							}.Build(),
							wcpb.CrawlResult_builder{
								CrawlTarget: wcpb.CrawlTarget_builder{Url: "http://local.lan/2"}.Build(),
							}.Build(),
						},
					}.Build(),
				}.Build(),
			}.Build(),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			AddCrawlResults(tc.service, tc.crawlResults)
			if diff := cmp.Diff(tc.want, tc.service, protocmp.Transform()); diff != "" {
				t.Errorf("AddCrawlResults(%v, %v) returned diff (-want +got):\n%s", tc.service, tc.crawlResults, diff)
			}
		})
	}
}
