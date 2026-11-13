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
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/metrics"
	_ "github.com/google/goonami-scanner/core/net/http/simpleclient"
	"github.com/google/goonami-scanner/plugins/fingerprint/webidentity/engine"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"

	hcpb "github.com/google/goonami-scanner/common/clients/httpcrawler/httpcrawler_client_config_go_proto"
	cpb "github.com/google/goonami-scanner/core/config/config_go_proto"
	fpb "github.com/google/goonami-scanner/plugins/fingerprint/webidentity/fingerprint_go_proto"
	wfpb "github.com/google/goonami-scanner/plugins/fingerprint/webidentity/webidentity_fp_config_go_proto"
	npb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
	spb "github.com/google/tsunami-security-scanner/proto/go/software_go_proto"
	wcpb "github.com/google/tsunami-security-scanner/proto/go/web_crawl_go_proto"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name              string
		configFunc        func() *config.Config
		wantErr           error
		wantMinSignatures int
	}{
		{
			name: "when_config_has_no_signatures_directory_loads_embedded_signatures",
			configFunc: func() *config.Config {
				return config.FromProto(&cpb.Config{})
			},
			wantErr:           nil,
			wantMinSignatures: 30,
		},
		{
			name: "when_config_has_valid_signatures_directory_loads_signatures",
			configFunc: func() *config.Config {
				return config.FromProto(cpb.Config_builder{
					Plugins: cpb.PluginsConfig_builder{
						Webidentity: wfpb.WebIdentityFpConfig_builder{
							SignaturesDirectory:      proto.String("testdata/valid/"),
							WriteHtmlToFile:          proto.Bool(true),
							MaximumFileSizeBytes:     proto.Int64(100),
							MaximumStorageSpaceBytes: proto.Int64(100),
						}.Build(),
					}.Build(),
				}.Build())
			},
			wantErr:           nil,
			wantMinSignatures: 1,
		},
		{
			name: "when_signatures_directory_does_not_exist_returns_error",
			configFunc: func() *config.Config {
				return config.FromProto(cpb.Config_builder{
					Plugins: cpb.PluginsConfig_builder{
						Webidentity: wfpb.WebIdentityFpConfig_builder{
							SignaturesDirectory:      proto.String("/non/existent/directory/"),
							WriteHtmlToFile:          proto.Bool(true),
							MaximumFileSizeBytes:     proto.Int64(100),
							MaximumStorageSpaceBytes: proto.Int64(100),
						}.Build(),
					}.Build(),
				}.Build())
			},
			wantErr: ErrSignaturesRead,
		},
		{
			name: "when_signatures_are_invalid_returns_error",
			configFunc: func() *config.Config {
				return config.FromProto(cpb.Config_builder{
					Plugins: cpb.PluginsConfig_builder{
						Webidentity: wfpb.WebIdentityFpConfig_builder{
							SignaturesDirectory:      proto.String("testdata/invalid/"),
							WriteHtmlToFile:          proto.Bool(true),
							MaximumFileSizeBytes:     proto.Int64(100),
							MaximumStorageSpaceBytes: proto.Int64(100),
						}.Build(),
					}.Build(),
				}.Build())
			},
			wantErr: ErrSignaturesUnmarshal,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mod, err := New(t.Context(), tc.configFunc())
			if err != nil {
				if tc.wantErr == nil || !errors.Is(err, tc.wantErr) {
					t.Fatalf("New() returned unexpected error: got: %v, want: %v", err, tc.wantErr)
				}

				return
			}

			if tc.wantErr != nil {
				t.Fatalf("New() did not return any error, want: %v", tc.wantErr)
			}

			if mod == nil {
				t.Fatalf("New() returned nil module")
			}

			m := mod.(*Module)
			if len(m.engine.Fingerprints()) < tc.wantMinSignatures {
				t.Errorf("len(engine.Fingerprints()) = %d, want at least %d", len(m.engine.Fingerprints()), tc.wantMinSignatures)
			}
		})
	}
}

func TestFingerprint(t *testing.T) {
	tests := []struct {
		name         string
		pages        map[string]string
		fingerprints []*fpb.WebFingerprint
		want         []*nspb.ServiceContext
		wantErr      error
	}{
		{
			name: "when_no_fingerprint_matches_returns_no_identification",
			fingerprints: []*fpb.WebFingerprint{
				fpb.WebFingerprint_builder{
					Info: fpb.FingerprintInfo_builder{
						Name:     "irrelevant",
						Software: "irrelevant",
					}.Build(),
					Steps: []*fpb.Step{
						fpb.Step_builder{
							Name: "step1",
							Path: proto.String("/unknown"),
							Response: fpb.HttpResponse_builder{
								StatusCodes: []int32{200},
							}.Build(),
						}.Build(),
					},
					Workflows: []*fpb.Workflow{
						fpb.Workflow_builder{
							Steps: []string{"step1"},
						}.Build(),
					},
				}.Build(),
			},
			pages: map[string]string{
				"/": "<html><body>Hello</body></html>",
			},
			want: []*nspb.ServiceContext{
				nspb.ServiceContext_builder{
					WebServiceContext: nspb.WebServiceContext_builder{
						CrawlResults: []*wcpb.CrawlResult{
							wcpb.CrawlResult_builder{
								CrawlTarget:      wcpb.CrawlTarget_builder{Url: "{uri}/"}.Build(),
								ResponseCode:     200,
								Content:          []byte("994ada221335e522d21c6051ee8c5231"),
								CrawlContentType: wcpb.CrawlContentType_CONTENT_TYPE_HASH,
							}.Build(),
						},
					}.Build(),
				}.Build(),
			},
		},
		{
			name: "when_known_fingerprint_has_no_version_it_is_identified_without_version",
			fingerprints: []*fpb.WebFingerprint{
				fpb.WebFingerprint_builder{
					Info: fpb.FingerprintInfo_builder{
						Name:     "nginx",
						Software: "nginx",
					}.Build(),
					Steps: []*fpb.Step{
						fpb.Step_builder{
							Name: "nginx_step",
							Path: proto.String("/"),
							Response: fpb.HttpResponse_builder{
								StatusCodes: []int32{200},
								ExpectAll: fpb.HttpResponse_ExpectAll_builder{
									Conditions: []*fpb.HttpResponse_Expectation{
										fpb.HttpResponse_Expectation_builder{
											Body:     &fpb.HttpResponse_Body{},
											Contains: "I am supposed to be an NGINX",
										}.Build(),
									},
								}.Build(),
							}.Build(),
						}.Build(),
					},
					Workflows: []*fpb.Workflow{
						fpb.Workflow_builder{
							Steps: []string{"nginx_step"},
						}.Build(),
					},
				}.Build(),
			},
			pages: map[string]string{
				"/": "I am supposed to be an NGINX",
			},
			want: []*nspb.ServiceContext{
				nspb.ServiceContext_builder{
					WebServiceContext: nspb.WebServiceContext_builder{
						ApplicationRoot: "/",
						Software:        spb.Software_builder{Name: "nginx"}.Build(),
						VersionSet:      &spb.VersionSet{},
						CrawlResults: []*wcpb.CrawlResult{
							wcpb.CrawlResult_builder{
								CrawlTarget:      wcpb.CrawlTarget_builder{Url: "{uri}/"}.Build(),
								ResponseCode:     200,
								Content:          []byte("cd30f2d1a6ba78af7430b2105716051b"),
								CrawlContentType: wcpb.CrawlContentType_CONTENT_TYPE_HASH,
							}.Build(),
						},
					}.Build(),
				}.Build(),
			},
		},
		{
			name: "when_known_fingerprint_extracts_version_it_is_identified_with_versions",
			fingerprints: []*fpb.WebFingerprint{
				fpb.WebFingerprint_builder{
					Info: fpb.FingerprintInfo_builder{
						Name:     "nginx",
						Software: "nginx",
					}.Build(),
					Steps: []*fpb.Step{
						fpb.Step_builder{
							Name: "nginx_step",
							Path: proto.String("/"),
							Response: fpb.HttpResponse_builder{
								StatusCodes: []int32{200},
								ExpectAll: fpb.HttpResponse_ExpectAll_builder{
									Conditions: []*fpb.HttpResponse_Expectation{
										fpb.HttpResponse_Expectation_builder{
											Body:     &fpb.HttpResponse_Body{},
											Contains: "I am supposed to be an NGINX",
										}.Build(),
									},
								}.Build(),
								VersionExtractors: []*fpb.VersionExtractor{
									fpb.VersionExtractor_builder{
										FromBody: &fpb.HttpResponse_Body{},
										Regexp:   "NGINX\\s+(v[0-9.]+)",
									}.Build(),
								},
							}.Build(),
						}.Build(),
					},
					Workflows: []*fpb.Workflow{
						fpb.Workflow_builder{
							Steps: []string{"nginx_step"},
						}.Build(),
					},
				}.Build(),
			},
			pages: map[string]string{
				"/": "I am supposed to be an NGINX v2.0",
			},
			want: []*nspb.ServiceContext{
				nspb.ServiceContext_builder{
					WebServiceContext: nspb.WebServiceContext_builder{
						ApplicationRoot: "/",
						Software:        spb.Software_builder{Name: "nginx"}.Build(),
						VersionSet: spb.VersionSet_builder{
							Versions: []*spb.Version{
								spb.Version_builder{Type: spb.Version_NORMAL, FullVersionString: "v2.0"}.Build(),
							},
						}.Build(),
						CrawlResults: []*wcpb.CrawlResult{
							wcpb.CrawlResult_builder{
								CrawlTarget:      wcpb.CrawlTarget_builder{Url: "{uri}/"}.Build(),
								ResponseCode:     200,
								Content:          []byte("88fab31f9e3a692ada238dc5c404cbf5"),
								CrawlContentType: wcpb.CrawlContentType_CONTENT_TYPE_HASH,
							}.Build(),
						},
					}.Build(),
				}.Build(),
			},
		},
		{
			name: "when_multiple_roots_match_returns_all_identified_roots",
			fingerprints: []*fpb.WebFingerprint{
				fpb.WebFingerprint_builder{
					Info: fpb.FingerprintInfo_builder{
						Name:     "nginx",
						Software: "nginx",
					}.Build(),
					Steps: []*fpb.Step{
						fpb.Step_builder{
							Name:       "nginx_version_step",
							PathSuffix: proto.String("/version"),
							Response: fpb.HttpResponse_builder{
								StatusCodes: []int32{200},
								ExpectAll: fpb.HttpResponse_ExpectAll_builder{
									Conditions: []*fpb.HttpResponse_Expectation{
										fpb.HttpResponse_Expectation_builder{
											Body:     &fpb.HttpResponse_Body{},
											Contains: "I am actually version",
										}.Build(),
									},
								}.Build(),
								VersionExtractors: []*fpb.VersionExtractor{
									fpb.VersionExtractor_builder{
										FromBody: &fpb.HttpResponse_Body{},
										Regexp:   "version\\s+([0-9.]+)",
									}.Build(),
								},
							}.Build(),
						}.Build(),
					},
					Workflows: []*fpb.Workflow{
						fpb.Workflow_builder{
							Steps: []string{"nginx_version_step"},
						}.Build(),
					},
				}.Build(),
			},
			pages: map[string]string{
				"/":           "<a href=\"/v1/version\">v1</a><a href=\"/v2/version\">v2</a>",
				"/v1/version": "I am actually version 1.0",
				"/v2/version": "I am actually version 2.0",
			},
			want: []*nspb.ServiceContext{
				nspb.ServiceContext_builder{
					WebServiceContext: nspb.WebServiceContext_builder{
						CrawlResults: []*wcpb.CrawlResult{
							wcpb.CrawlResult_builder{
								CrawlTarget:      wcpb.CrawlTarget_builder{Url: "{uri}/"}.Build(),
								ResponseCode:     200,
								Content:          []byte("758be908ac4fb77a41268ef57aac71d4"),
								CrawlContentType: wcpb.CrawlContentType_CONTENT_TYPE_HASH,
							}.Build(),
						},
					}.Build(),
				}.Build(),
				nspb.ServiceContext_builder{
					WebServiceContext: nspb.WebServiceContext_builder{
						ApplicationRoot: "/v1",
						Software:        spb.Software_builder{Name: "nginx"}.Build(),
						VersionSet: spb.VersionSet_builder{
							Versions: []*spb.Version{
								spb.Version_builder{Type: spb.Version_NORMAL, FullVersionString: "1.0"}.Build(),
							},
						}.Build(),
						CrawlResults: []*wcpb.CrawlResult{
							wcpb.CrawlResult_builder{
								CrawlTarget:      wcpb.CrawlTarget_builder{Url: "{uri}/v1/version"}.Build(),
								ResponseCode:     200,
								CrawlDepth:       1,
								Content:          []byte("2d12331d1c80f5bfa00f6712ea547aca"),
								CrawlContentType: wcpb.CrawlContentType_CONTENT_TYPE_HASH,
							}.Build(),
						},
					}.Build(),
				}.Build(),
				nspb.ServiceContext_builder{
					WebServiceContext: nspb.WebServiceContext_builder{
						ApplicationRoot: "/v2",
						Software:        spb.Software_builder{Name: "nginx"}.Build(),
						VersionSet: spb.VersionSet_builder{
							Versions: []*spb.Version{
								spb.Version_builder{Type: spb.Version_NORMAL, FullVersionString: "2.0"}.Build(),
							},
						}.Build(),
						CrawlResults: []*wcpb.CrawlResult{
							wcpb.CrawlResult_builder{
								CrawlTarget:      wcpb.CrawlTarget_builder{Url: "{uri}/v2/version"}.Build(),
								ResponseCode:     200,
								CrawlDepth:       1,
								Content:          []byte("5eadef45e713f861e6d6b32b998dde07"),
								CrawlContentType: wcpb.CrawlContentType_CONTENT_TYPE_HASH,
							}.Build(),
						},
					}.Build(),
				}.Build(),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := newTestServer(tc.pages)
			defer server.Close()

			hostname, port, service := serverInfo(t, server)
			mod := newTestModuleWithFingerprints(t, tc.fingerprints, nil, "")

			gotServices, err := mod.Fingerprint(t.Context(), service)
			if err != nil {
				if tc.wantErr == nil || !errors.Is(err, tc.wantErr) {
					t.Fatalf("Fingerprint() returned unexpected error: got: %v, want: %v", err, tc.wantErr)
				}

				return
			}

			uri := fmt.Sprintf("http://%s:%d", hostname, port)

			var gotContexts []*nspb.ServiceContext
			for _, s := range gotServices {
				gotContexts = append(gotContexts, s.GetServiceContext())
			}

			wantContexts := replaceURIPlaceholders(tc.want, uri)

			sortPerRoot := cmpopts.SortSlices(func(a, b *nspb.ServiceContext) bool {
				return a.GetWebServiceContext().GetApplicationRoot() < b.GetWebServiceContext().GetApplicationRoot()
			})
			sortCrawlResults := protocmp.SortRepeatedFields((*nspb.WebServiceContext)(nil), "crawl_results")
			sortVersions := protocmp.SortRepeatedFields((*spb.VersionSet)(nil), "versions")

			if diff := cmp.Diff(wantContexts, gotContexts, sortPerRoot, protocmp.Transform(), sortCrawlResults, sortVersions); diff != "" {
				t.Errorf("Fingerprint() returned unexpected diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestFingerprintWithWrites(t *testing.T) {
	const pageContent = "<html><body>Hello</body></html>"
	const pageHash = "994ada221335e522d21c6051ee8c5231"
	pages := map[string]string{
		"/": pageContent,
	}

	tests := []struct {
		name                 string
		config               *wfpb.WebIdentityFpConfig
		wantFileWritten      bool
		wantFileContentBytes []byte
	}{
		{
			name: "when_artifacts_are_disabled_no_file_is_written",
			config: wfpb.WebIdentityFpConfig_builder{
				WriteHtmlToFile:          proto.Bool(false),
				MaximumFileSizeBytes:     proto.Int64(1000),
				MaximumStorageSpaceBytes: proto.Int64(1000),
			}.Build(),
			wantFileWritten: false,
		},
		{
			name: "when_artifacts_are_enabled_file_is_written",
			config: wfpb.WebIdentityFpConfig_builder{
				WriteHtmlToFile:          proto.Bool(true),
				MaximumFileSizeBytes:     proto.Int64(1000),
				MaximumStorageSpaceBytes: proto.Int64(1000),
			}.Build(),
			wantFileWritten:      true,
			wantFileContentBytes: []byte(pageContent + "\n"),
		},
		{
			name: "when_file_is_too_big_no_file_is_written",
			config: wfpb.WebIdentityFpConfig_builder{
				WriteHtmlToFile:          proto.Bool(true),
				MaximumFileSizeBytes:     proto.Int64(10),
				MaximumStorageSpaceBytes: proto.Int64(1000),
			}.Build(),
			wantFileWritten: false,
		},
		{
			name: "when_storage_is_full_no_file_is_written",
			config: wfpb.WebIdentityFpConfig_builder{
				WriteHtmlToFile:          proto.Bool(true),
				MaximumFileSizeBytes:     proto.Int64(1000),
				MaximumStorageSpaceBytes: proto.Int64(10),
			}.Build(),
			wantFileWritten: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			workdir := t.TempDir()

			server := newTestServer(pages)
			defer server.Close()

			_, _, service := serverInfo(t, server)
			artifactsDir := filepath.Join(workdir, "artifacts", moduleName)

			mod := newTestModuleWithFingerprints(t, nil, tc.config, workdir)
			if _, err := mod.Fingerprint(t.Context(), service); err != nil {
				t.Fatalf("Fingerprint() returned unexpected error: %v", err)
			}

			artifactPath := filepath.Join(artifactsDir, pageHash)
			gotFile, err := os.ReadFile(artifactPath)
			if err != nil {
				if tc.wantFileWritten {
					t.Fatalf("os.ReadFile(%q) returned error %v, want artifact file written", artifactPath, err)
				}
				return
			}

			if !tc.wantFileWritten {
				t.Fatalf("os.ReadFile(%q) succeeded, want artifact file not written", artifactPath)
			}

			if !bytes.Equal(gotFile, tc.wantFileContentBytes) {
				t.Errorf("os.ReadFile(%q) = %q, want %q", artifactPath, string(gotFile), string(tc.wantFileContentBytes))
			}
		})
	}
}

func TestFingerprintReconciliation(t *testing.T) {
	const (
		grafanaPage       = "I am Grafana"
		nginxPage         = "I am NGINX"
		unidentifiedPage1 = "<html><body>Hello</body></html>"
		unidentifiedPage2 = "<html><body>Other</body></html>"
		linkToV1Page      = "<a href=\"/v1/app\">v1</a>"
		linkToV2Page      = "<a href=\"/v2/app\">v2</a>"
	)

	grafanaHash := pageHash(t, grafanaPage)
	nginxHash := pageHash(t, nginxPage)
	unidentifiedHash1 := pageHash(t, unidentifiedPage1)
	unidentifiedHash2 := pageHash(t, unidentifiedPage2)
	linkToV1Hash := pageHash(t, linkToV1Page)
	linkToV2Hash := pageHash(t, linkToV2Page)

	fingerprints := []*fpb.WebFingerprint{
		fpb.WebFingerprint_builder{
			Info: fpb.FingerprintInfo_builder{
				Name:     "grafana",
				Software: "grafana",
			}.Build(),
			Steps: []*fpb.Step{
				fpb.Step_builder{
					Name: "grafana_root",
					Path: proto.String("/"),
					Response: fpb.HttpResponse_builder{
						StatusCodes: []int32{200},
						ExpectAll: fpb.HttpResponse_ExpectAll_builder{
							Conditions: []*fpb.HttpResponse_Expectation{
								fpb.HttpResponse_Expectation_builder{
									Body:     &fpb.HttpResponse_Body{},
									Contains: grafanaPage,
								}.Build(),
							},
						}.Build(),
					}.Build(),
				}.Build(),
				fpb.Step_builder{
					Name:       "grafana_subpath",
					PathSuffix: proto.String("/app"),
					Response: fpb.HttpResponse_builder{
						StatusCodes: []int32{200},
						ExpectAll: fpb.HttpResponse_ExpectAll_builder{
							Conditions: []*fpb.HttpResponse_Expectation{
								fpb.HttpResponse_Expectation_builder{
									Body:     &fpb.HttpResponse_Body{},
									Contains: grafanaPage,
								}.Build(),
							},
						}.Build(),
					}.Build(),
				}.Build(),
			},
			Workflows: []*fpb.Workflow{
				fpb.Workflow_builder{Steps: []string{"grafana_root"}}.Build(),
				fpb.Workflow_builder{Steps: []string{"grafana_subpath"}}.Build(),
			},
		}.Build(),
		fpb.WebFingerprint_builder{
			Info: fpb.FingerprintInfo_builder{
				Name:     "nginx",
				Software: "nginx",
			}.Build(),
			Steps: []*fpb.Step{
				fpb.Step_builder{
					Name: "nginx_root",
					Path: proto.String("/"),
					Response: fpb.HttpResponse_builder{
						StatusCodes: []int32{200},
						ExpectAll: fpb.HttpResponse_ExpectAll_builder{
							Conditions: []*fpb.HttpResponse_Expectation{
								fpb.HttpResponse_Expectation_builder{
									Body:     &fpb.HttpResponse_Body{},
									Contains: nginxPage,
								}.Build(),
							},
						}.Build(),
					}.Build(),
				}.Build(),
			},
			Workflows: []*fpb.Workflow{
				fpb.Workflow_builder{Steps: []string{"nginx_root"}}.Build(),
			},
		}.Build(),
	}

	tests := []struct {
		name      string
		hostPages map[string]string
		ipPages   map[string]string
		want      []*nspb.NetworkService
	}{
		{
			name:      "when_ip_and_hostname_serve_same_identity_returns_single_reconciled_service",
			hostPages: map[string]string{"/": grafanaPage},
			ipPages:   map[string]string{"/": grafanaPage},
			want: []*nspb.NetworkService{
				buildTestService(npb.NetworkEndpoint_IP_HOSTNAME_PORT, "/", "grafana",
					buildTestCrawl("{host_uri}/", 0, grafanaHash),
					buildTestCrawl("{ip_uri}/", 0, grafanaHash),
				),
			},
		},
		{
			name:      "when_ip_is_identified_and_hostname_is_unidentified_returns_narrowed_services",
			hostPages: map[string]string{"/": unidentifiedPage1},
			ipPages:   map[string]string{"/": grafanaPage},
			want: []*nspb.NetworkService{
				buildTestService(npb.NetworkEndpoint_IP_PORT, "/", "grafana",
					buildTestCrawl("{ip_uri}/", 0, grafanaHash),
				),
				buildTestService(npb.NetworkEndpoint_HOSTNAME_PORT, "", "",
					buildTestCrawl("{host_uri}/", 0, unidentifiedHash1),
				),
			},
		},
		{
			name:      "when_hostname_is_identified_and_ip_is_unidentified_returns_narrowed_services",
			hostPages: map[string]string{"/": grafanaPage},
			ipPages:   map[string]string{"/": unidentifiedPage1},
			want: []*nspb.NetworkService{
				buildTestService(npb.NetworkEndpoint_HOSTNAME_PORT, "/", "grafana",
					buildTestCrawl("{host_uri}/", 0, grafanaHash),
				),
				buildTestService(npb.NetworkEndpoint_IP_PORT, "", "",
					buildTestCrawl("{ip_uri}/", 0, unidentifiedHash1),
				),
			},
		},
		{
			name:      "when_ip_and_hostname_serve_different_software_returns_narrowed_services",
			hostPages: map[string]string{"/": nginxPage},
			ipPages:   map[string]string{"/": grafanaPage},
			want: []*nspb.NetworkService{
				buildTestService(npb.NetworkEndpoint_HOSTNAME_PORT, "/", "nginx",
					buildTestCrawl("{host_uri}/", 0, nginxHash),
				),
				buildTestService(npb.NetworkEndpoint_IP_PORT, "/", "grafana",
					buildTestCrawl("{ip_uri}/", 0, grafanaHash),
				),
			},
		},
		{
			name:      "when_ip_and_hostname_serve_same_unidentified_pages_returns_single_reconciled_service",
			hostPages: map[string]string{"/": unidentifiedPage1},
			ipPages:   map[string]string{"/": unidentifiedPage1},
			want: []*nspb.NetworkService{
				buildTestService(npb.NetworkEndpoint_IP_HOSTNAME_PORT, "", "",
					buildTestCrawl("{host_uri}/", 0, unidentifiedHash1),
					buildTestCrawl("{ip_uri}/", 0, unidentifiedHash1),
				),
			},
		},
		{
			name:      "when_ip_and_hostname_serve_different_unidentified_pages_returns_narrowed_services",
			hostPages: map[string]string{"/": unidentifiedPage1},
			ipPages:   map[string]string{"/": unidentifiedPage2},
			want: []*nspb.NetworkService{
				buildTestService(npb.NetworkEndpoint_HOSTNAME_PORT, "", "",
					buildTestCrawl("{host_uri}/", 0, unidentifiedHash1),
				),
				buildTestService(npb.NetworkEndpoint_IP_PORT, "", "",
					buildTestCrawl("{ip_uri}/", 0, unidentifiedHash2),
				),
			},
		},
		{
			name: "when_ip_and_hostname_serve_same_identity_at_different_roots_returns_narrowed_services",
			hostPages: map[string]string{
				"/":       linkToV1Page,
				"/v1/app": grafanaPage,
			},
			ipPages: map[string]string{
				"/":       linkToV2Page,
				"/v2/app": grafanaPage,
			},
			want: []*nspb.NetworkService{
				buildTestService(npb.NetworkEndpoint_HOSTNAME_PORT, "/v1", "grafana",
					buildTestCrawl("{host_uri}/v1/app", 1, grafanaHash),
				),
				buildTestService(npb.NetworkEndpoint_IP_PORT, "/v2", "grafana",
					buildTestCrawl("{ip_uri}/v2/app", 1, grafanaHash),
				),
				buildTestService(npb.NetworkEndpoint_HOSTNAME_PORT, "", "",
					buildTestCrawl("{host_uri}/", 0, linkToV1Hash),
				),
				buildTestService(npb.NetworkEndpoint_IP_PORT, "", "",
					buildTestCrawl("{ip_uri}/", 0, linkToV2Hash),
				),
			},
		},
		{
			name: "when_ip_and_hostname_serve_same_identity_at_subpath_returns_reconciled_service",
			hostPages: map[string]string{
				"/":       linkToV1Page,
				"/v1/app": grafanaPage,
			},
			ipPages: map[string]string{
				"/":       linkToV1Page,
				"/v1/app": grafanaPage,
			},
			want: []*nspb.NetworkService{
				buildTestService(npb.NetworkEndpoint_IP_HOSTNAME_PORT, "/v1", "grafana",
					buildTestCrawl("{host_uri}/v1/app", 1, grafanaHash),
					buildTestCrawl("{ip_uri}/v1/app", 1, grafanaHash),
				),
				buildTestService(npb.NetworkEndpoint_IP_HOSTNAME_PORT, "", "",
					buildTestCrawl("{host_uri}/", 0, linkToV1Hash),
					buildTestCrawl("{ip_uri}/", 0, linkToV1Hash),
				),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			server := newHostAwareTestServer(tc.hostPages, tc.ipPages)
			defer server.Close()

			ip, port, _ := serverInfo(t, server)
			service := nspb.NetworkService_builder{
				NetworkEndpoint:      buildTestEndpoint(npb.NetworkEndpoint_IP_HOSTNAME_PORT, ip, port),
				SupportedHttpMethods: []string{"GET"},
			}.Build()

			mod := newTestModuleWithFingerprints(t, fingerprints, nil, "")

			gotServices, err := mod.Fingerprint(ctx, service)
			if err != nil {
				t.Fatalf("Fingerprint() returned unexpected error: %v", err)
			}

			hostURI := fmt.Sprintf("http://localhost:%d", port)
			ipURI := fmt.Sprintf("http://%s:%d", ip, port)
			replacePlaceholders := func(s string) string {
				s = strings.ReplaceAll(s, "{host_uri}", hostURI)
				return strings.ReplaceAll(s, "{ip_uri}", ipURI)
			}

			for _, svc := range tc.want {
				svc.SetNetworkEndpoint(buildTestEndpoint(svc.GetNetworkEndpoint().GetType(), ip, port))
				wsc := svc.GetServiceContext().GetWebServiceContext()
				if wsc.GetApplicationRoot() != "" {
					wsc.SetApplicationRoot(replacePlaceholders(wsc.GetApplicationRoot()))
				}
				for _, cr := range wsc.GetCrawlResults() {
					cr.GetCrawlTarget().SetUrl(replacePlaceholders(cr.GetCrawlTarget().GetUrl()))
				}
			}

			sortServices := cmpopts.SortSlices(func(a, b *nspb.NetworkService) bool {
				aRoot := a.GetServiceContext().GetWebServiceContext().GetApplicationRoot()
				bRoot := b.GetServiceContext().GetWebServiceContext().GetApplicationRoot()
				if aRoot != bRoot {
					return aRoot < bRoot
				}
				return a.GetNetworkEndpoint().GetType() < b.GetNetworkEndpoint().GetType()
			})
			sortCrawlResults := protocmp.SortRepeatedFields((*nspb.WebServiceContext)(nil), "crawl_results")

			if diff := cmp.Diff(tc.want, gotServices, sortServices, protocmp.Transform(), sortCrawlResults); diff != "" {
				t.Errorf("Fingerprint() returned unexpected diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestSplitServiceByEndpoint(t *testing.T) {
	tests := []struct {
		name    string
		service *nspb.NetworkService
		want    []*nspb.NetworkService
	}{
		{
			name: "when_endpoint_is_ip_hostname_splits_into_hostname_and_ip",
			service: nspb.NetworkService_builder{
				NetworkEndpoint: npb.NetworkEndpoint_builder{
					Type: npb.NetworkEndpoint_IP_HOSTNAME,
					IpAddress: npb.IpAddress_builder{
						AddressFamily: npb.AddressFamily_IPV4,
						Address:       "127.0.0.1",
					}.Build(),
					Hostname: npb.Hostname_builder{
						Name: "localhost",
					}.Build(),
				}.Build(),
				SupportedHttpMethods: []string{"GET"},
			}.Build(),
			want: []*nspb.NetworkService{
				nspb.NetworkService_builder{
					NetworkEndpoint: npb.NetworkEndpoint_builder{
						Type: npb.NetworkEndpoint_HOSTNAME,
						Hostname: npb.Hostname_builder{
							Name: "localhost",
						}.Build(),
					}.Build(),
					SupportedHttpMethods: []string{"GET"},
				}.Build(),
				nspb.NetworkService_builder{
					NetworkEndpoint: npb.NetworkEndpoint_builder{
						Type: npb.NetworkEndpoint_IP,
						IpAddress: npb.IpAddress_builder{
							AddressFamily: npb.AddressFamily_IPV4,
							Address:       "127.0.0.1",
						}.Build(),
					}.Build(),
					SupportedHttpMethods: []string{"GET"},
				}.Build(),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := splitServiceByEndpoint(tc.service)
			if diff := cmp.Diff(tc.want, got, protocmp.Transform()); diff != "" {
				t.Errorf("splitServiceByEndpoint() returned unexpected diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestFingerprintPerServiceRequestBudget(t *testing.T) {
	const versionPage = "nginx version page"
	pages := map[string]string{
		"/":        `<a href="/version">version</a>`,
		"/version": versionPage,
	}

	fp, err := engine.CompileFingerprint(fpb.WebFingerprint_builder{
		Info: fpb.FingerprintInfo_builder{
			Name:     "nginx",
			Software: "nginx",
		}.Build(),
		Steps: []*fpb.Step{
			fpb.Step_builder{
				Name:       "nginx_version_step",
				PathSuffix: proto.String("/version"),
				Response: fpb.HttpResponse_builder{
					StatusCodes: []int32{200},
					ExpectAll: fpb.HttpResponse_ExpectAll_builder{
						Conditions: []*fpb.HttpResponse_Expectation{
							fpb.HttpResponse_Expectation_builder{
								Body:     &fpb.HttpResponse_Body{},
								Contains: versionPage,
							}.Build(),
						},
					}.Build(),
				}.Build(),
			}.Build(),
		},
		Workflows: []*fpb.Workflow{
			fpb.Workflow_builder{Steps: []string{"nginx_version_step"}}.Build(),
		},
	}.Build())
	if err != nil {
		t.Fatalf("engine.CompileFingerprint() failed: %v", err)
	}

	tests := []struct {
		name string
	}{
		{
			name: "when_multiple_services_fingerprinted_each_gets_full_request_budget",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv1 := newTestServer(pages)
			defer srv1.Close()
			srv2 := newTestServer(pages)
			defer srv2.Close()

			_, _, svc1 := serverInfo(t, srv1)
			_, _, svc2 := serverInfo(t, srv2)

			modConfig := wfpb.WebIdentityFpConfig_builder{WriteHtmlToFile: proto.Bool(false)}.Build()
			cfg := config.FromProto(cpb.Config_builder{
				Clients: cpb.ClientsConfig_builder{
					HttpCrawler: hcpb.HttpCrawlerClientConfig_builder{
						MaxConcurrency: proto.Int32(1),
						MaxDepth:       proto.Int32(1),
						MaxRequests:    proto.Int32(2),
					}.Build(),
				}.Build(),
				Plugins: cpb.PluginsConfig_builder{
					Webidentity: modConfig,
				}.Build(),
			}.Build())

			mod, err := newWithEngine(t.Context(), modConfig, cfg, engine.New([]*engine.CompiledFingerprint{fp}))
			if err != nil {
				t.Fatalf("newWithEngine() failed: %v", err)
			}

			for idx, svc := range []*nspb.NetworkService{svc1, svc2} {
				got, err := mod.Fingerprint(t.Context(), svc)
				if err != nil {
					t.Fatalf("Fingerprint(service %d) returned unexpected error: %v", idx, err)
				}

				var identified []string
				for _, s := range got {
					if sw := s.GetServiceContext().GetWebServiceContext().GetSoftware().GetName(); sw != "" {
						identified = append(identified, sw)
					}
				}
				if diff := cmp.Diff([]string{"nginx"}, identified); diff != "" {
					t.Errorf("Fingerprint(service %d) identified software diff (-want +got):\n%s", idx, diff)
				}
			}
		})
	}
}

func TestFingerprintRelativeApplicationRoot(t *testing.T) {
	const assetContent = "console.log('grafana')"

	fp, err := engine.CompileFingerprint(fpb.WebFingerprint_builder{
		Info: fpb.FingerprintInfo_builder{
			Name:     "grafana",
			Software: "grafana",
		}.Build(),
		Steps: []*fpb.Step{
			fpb.Step_builder{
				Name:       "grafana_asset",
				PathSuffix: proto.String("public/app.js"),
				Response: fpb.HttpResponse_builder{
					StatusCodes: []int32{200},
					ExpectAll: fpb.HttpResponse_ExpectAll_builder{
						Conditions: []*fpb.HttpResponse_Expectation{
							fpb.HttpResponse_Expectation_builder{
								Body:     &fpb.HttpResponse_Body{},
								Contains: assetContent,
							}.Build(),
						},
					}.Build(),
				}.Build(),
			}.Build(),
		},
		Workflows: []*fpb.Workflow{
			fpb.Workflow_builder{Steps: []string{"grafana_asset"}}.Build(),
		},
	}.Build())
	if err != nil {
		t.Fatalf("engine.CompileFingerprint() failed: %v", err)
	}

	tests := []struct {
		name     string
		pages    map[string]string
		wantRoot string
	}{
		{
			name: "when_path_suffix_without_leading_slash_matches_at_root_returns_slash",
			pages: map[string]string{
				"/":              `<a href="/public/app.js">app</a>`,
				"/public/app.js": assetContent,
			},
			wantRoot: "/",
		},
		{
			name: "when_path_suffix_without_leading_slash_matches_at_subpath_returns_subpath",
			pages: map[string]string{
				"/":                      `<a href="/grafana/public/app.js">app</a>`,
				"/grafana/public/app.js": assetContent,
			},
			wantRoot: "/grafana",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := newTestServer(tc.pages)
			defer server.Close()

			_, _, service := serverInfo(t, server)
			modConfig := wfpb.WebIdentityFpConfig_builder{WriteHtmlToFile: proto.Bool(false)}.Build()
			cfg := buildConfig(t, modConfig, "")
			mod, err := newWithEngine(t.Context(), modConfig, cfg, engine.New([]*engine.CompiledFingerprint{fp}))
			if err != nil {
				t.Fatalf("newWithEngine() failed: %v", err)
			}

			gotServices, err := mod.Fingerprint(t.Context(), service)
			if err != nil {
				t.Fatalf("Fingerprint() returned unexpected error: %v", err)
			}

			var identifiedRoots []string
			for _, svc := range gotServices {
				wsc := svc.GetServiceContext().GetWebServiceContext()
				if wsc.GetSoftware().GetName() == "grafana" {
					identifiedRoots = append(identifiedRoots, wsc.GetApplicationRoot())
				}
			}

			if diff := cmp.Diff([]string{tc.wantRoot}, identifiedRoots); diff != "" {
				t.Errorf("Fingerprint() returned unexpected application_root diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestFingerprintRecordsIdentificationMetrics(t *testing.T) {
	fingerprints := []*fpb.WebFingerprint{
		fpb.WebFingerprint_builder{
			Info: fpb.FingerprintInfo_builder{
				Name:     "Grafana",
				Software: "grafana",
			}.Build(),
			Steps: []*fpb.Step{
				fpb.Step_builder{
					Name:       "grafana_login",
					PathSuffix: proto.String("/login"),
					Response: fpb.HttpResponse_builder{
						StatusCodes: []int32{200},
						ExpectAll: fpb.HttpResponse_ExpectAll_builder{
							Conditions: []*fpb.HttpResponse_Expectation{
								fpb.HttpResponse_Expectation_builder{
									Body:     &fpb.HttpResponse_Body{},
									Contains: "grafana-app",
								}.Build(),
							},
						}.Build(),
					}.Build(),
				}.Build(),
				fpb.Step_builder{
					Name: "grafana_health",
					Path: proto.String("/api/health"),
					Response: fpb.HttpResponse_builder{
						StatusCodes: []int32{200},
						ExpectAll: fpb.HttpResponse_ExpectAll_builder{
							Conditions: []*fpb.HttpResponse_Expectation{
								fpb.HttpResponse_Expectation_builder{
									Body:     &fpb.HttpResponse_Body{},
									Contains: "grafana-ok",
								}.Build(),
							},
						}.Build(),
						VersionExtractors: []*fpb.VersionExtractor{
							fpb.VersionExtractor_builder{
								FromBody: &fpb.HttpResponse_Body{},
								Regexp:   `v([0-9.]+)`,
							}.Build(),
						},
					}.Build(),
				}.Build(),
			},
			Workflows: []*fpb.Workflow{
				fpb.Workflow_builder{Steps: []string{"grafana_login", "grafana_health"}}.Build(),
				fpb.Workflow_builder{Steps: []string{"grafana_login"}}.Build(),
			},
		}.Build(),
		fpb.WebFingerprint_builder{
			Info: fpb.FingerprintInfo_builder{
				Name:     "NGINX",
				Software: "nginx",
			}.Build(),
			Steps: []*fpb.Step{
				fpb.Step_builder{
					Name: "nginx_root",
					Path: proto.String("/"),
					Response: fpb.HttpResponse_builder{
						StatusCodes: []int32{200},
						ExpectAll: fpb.HttpResponse_ExpectAll_builder{
							Conditions: []*fpb.HttpResponse_Expectation{
								fpb.HttpResponse_Expectation_builder{
									Body:     &fpb.HttpResponse_Body{},
									Contains: "nginx-welcome",
								}.Build(),
							},
						}.Build(),
					}.Build(),
				}.Build(),
			},
			Workflows: []*fpb.Workflow{
				fpb.Workflow_builder{Steps: []string{"nginx_root"}}.Build(),
			},
		}.Build(),
	}

	type wantCount struct {
		fingerprint string
		rule        string
		count       int64
	}

	tests := []struct {
		name      string
		epType    npb.NetworkEndpoint_Type
		hostPages map[string]string
		ipPages   map[string]string
		want      []wantCount
	}{
		{
			name:   "when_no_fingerprint_matches_records_no_series",
			epType: npb.NetworkEndpoint_IP_PORT,
			ipPages: map[string]string{
				"/": "<html><body>unknown</body></html>",
			},
		},
		{
			name:   "when_multi_step_workflow_matches_records_each_matched_step",
			epType: npb.NetworkEndpoint_IP_PORT,
			ipPages: map[string]string{
				"/":           `<a href="/login">login</a>`,
				"/login":      "grafana-app",
				"/api/health": "grafana-ok v10.1.0",
			},
			want: []wantCount{
				{fingerprint: "grafana", rule: "grafana_health", count: 1},
				{fingerprint: "grafana", rule: "grafana_login", count: 1},
			},
		},
		{
			name:   "when_ip_and_hostname_identify_same_app_counts_each_rule_once",
			epType: npb.NetworkEndpoint_IP_HOSTNAME_PORT,
			hostPages: map[string]string{
				"/":           `<a href="/login">login</a>`,
				"/login":      "grafana-app",
				"/api/health": "grafana-ok v10.1.0",
			},
			ipPages: map[string]string{
				"/":           `<a href="/login">login</a>`,
				"/login":      "grafana-app",
				"/api/health": "grafana-ok v10.1.0",
			},
			want: []wantCount{
				{fingerprint: "grafana", rule: "grafana_health", count: 1},
				{fingerprint: "grafana", rule: "grafana_login", count: 1},
			},
		},
		{
			name:   "when_ip_and_hostname_identify_different_apps_counts_rules_for_each",
			epType: npb.NetworkEndpoint_IP_HOSTNAME_PORT,
			hostPages: map[string]string{
				"/": "nginx-welcome",
			},
			ipPages: map[string]string{
				"/":           `<a href="/login">login</a>`,
				"/login":      "grafana-app",
				"/api/health": "grafana-ok v10.1.0",
			},
			want: []wantCount{
				{fingerprint: "grafana", rule: "grafana_health", count: 1},
				{fingerprint: "grafana", rule: "grafana_login", count: 1},
				{fingerprint: "nginx", rule: "nginx_root", count: 1},
			},
		},
		{
			name:   "when_multiple_subpaths_identified_sums_rule_counts",
			epType: npb.NetworkEndpoint_IP_PORT,
			ipPages: map[string]string{
				"/":        `<a href="/a/login">a</a><a href="/b/login">b</a>`,
				"/a/login": "grafana-app",
				"/b/login": "grafana-app",
			},
			want: []wantCount{
				{fingerprint: "grafana", rule: "grafana_login", count: 2},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			collector := metrics.NewCollector()
			metrics.SetRecorder(collector)
			t.Cleanup(func() { metrics.SetRecorder(nil) })

			server := newHostAwareTestServer(tc.hostPages, tc.ipPages)
			defer server.Close()

			ip, port, _ := serverInfo(t, server)
			service := nspb.NetworkService_builder{
				NetworkEndpoint:      buildTestEndpoint(tc.epType, ip, port),
				SupportedHttpMethods: []string{"GET"},
			}.Build()

			mod := newTestModuleWithFingerprints(t, fingerprints, nil, "")
			if _, err := mod.Fingerprint(t.Context(), service); err != nil {
				t.Fatalf("Fingerprint() returned unexpected error: %v", err)
			}

			type seriesKey struct {
				fingerprint string
				rule        string
			}
			got := make(map[seriesKey]int64)
			for _, s := range collector.Series() {
				if s.Metric != metrics.FingerprintIdentifications {
					continue
				}
				var fp, rule string
				for _, l := range s.Labels {
					switch l.Key {
					case metrics.LabelFingerprint:
						fp = l.Value
					case metrics.LabelRule:
						rule = l.Value
					}
				}
				got[seriesKey{fingerprint: fp, rule: rule}] = s.Value()
			}

			want := make(map[seriesKey]int64, len(tc.want))
			for _, w := range tc.want {
				want[seriesKey{fingerprint: w.fingerprint, rule: w.rule}] = w.count
			}
			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("FingerprintIdentifications metrics diff (-want +got):\n%s", diff)
			}
		})
	}
}
