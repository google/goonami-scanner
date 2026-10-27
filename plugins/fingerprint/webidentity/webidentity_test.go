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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/goonami-scanner/core/config"
	_ "github.com/google/goonami-scanner/core/net/http/simpleclient"
	"github.com/google/goonami-scanner/plugins/fingerprint/webidentity/hash"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"

	cpb "github.com/google/goonami-scanner/core/config/config_go_proto"
	fpb "github.com/google/goonami-scanner/plugins/fingerprint/webidentity/fingerprints_go_proto"
	wfpb "github.com/google/goonami-scanner/plugins/fingerprint/webidentity/webidentity_fp_config_go_proto"
	npb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
	spb "github.com/google/tsunami-security-scanner/proto/go/software_go_proto"
	wcpb "github.com/google/tsunami-security-scanner/proto/go/web_crawl_go_proto"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name       string
		configFunc func() *config.Config
		wantErr    error
	}{
		{
			name: "when_config_has_webidentity_returns_no_error",
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
			wantErr: nil,
		},
		{
			name: "when_config_does_not_have_webidentity_returns_error",
			configFunc: func() *config.Config {
				return config.FromProto(&cpb.Config{})
			},
			wantErr: ErrNoFingerprintsDirectory,
		},
		{
			name: "when_config_is_missing_signatures_directory_returns_error",
			configFunc: func() *config.Config {
				return config.FromProto(cpb.Config_builder{
					Plugins: cpb.PluginsConfig_builder{
						Webidentity: wfpb.WebIdentityFpConfig_builder{
							SignaturesDirectory:      proto.String(""),
							WriteHtmlToFile:          proto.Bool(true),
							MaximumFileSizeBytes:     proto.Int64(100),
							MaximumStorageSpaceBytes: proto.Int64(100),
						}.Build(),
					}.Build(),
				}.Build())
			},
			wantErr: ErrNoFingerprintsDirectory,
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
			if m.registry.Count() == 0 {
				t.Errorf("New() did not load any signatures")
			}
		})
	}
}

func TestFingerprint(t *testing.T) {
	tests := []struct {
		name        string
		pages       map[string]string
		knownHashes *fpb.Fingerprints
		want        []*nspb.ServiceContext
		wantErr     error
	}{
		{
			name: "when_no_known_hash_matches_returns_no_identification",
			knownHashes: fpb.Fingerprints_builder{
				SoftwareIdentity: fpb.SoftwareIdentity_builder{Software: "irrelevant"}.Build(),
				ContentHashes: []*fpb.ContentHash{
					fpb.ContentHash_builder{
						ContentPath: "/",
						Hashes: []*fpb.Hash{
							fpb.Hash_builder{HexString: "unknown"}.Build(),
						},
					}.Build(),
				},
			}.Build(),
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
			name: "when_known_hash_has_no_version_it_is_identified_without_version",
			knownHashes: fpb.Fingerprints_builder{
				SoftwareIdentity: fpb.SoftwareIdentity_builder{Software: "nginx"}.Build(),
				ContentHashes: []*fpb.ContentHash{
					fpb.ContentHash_builder{
						ContentPath: "/",
						Hashes: []*fpb.Hash{
							fpb.Hash_builder{HexString: "cd30f2d1a6ba78af7430b2105716051b"}.Build(),
						},
					}.Build(),
				},
			}.Build(),
			pages: map[string]string{
				"/": "I am supposed to be an NGINX",
			},
			want: []*nspb.ServiceContext{
				nspb.ServiceContext_builder{
					WebServiceContext: nspb.WebServiceContext_builder{
						ApplicationRoot: "{uri}",
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
			name: "when_known_hash_has_version_range_it_is_identified_with_versions",
			knownHashes: fpb.Fingerprints_builder{
				SoftwareIdentity: fpb.SoftwareIdentity_builder{Software: "nginx"}.Build(),
				ContentHashes: []*fpb.ContentHash{
					fpb.ContentHash_builder{
						ContentPath: "/",
						Hashes: []*fpb.Hash{
							fpb.Hash_builder{HexString: "3786b9d769425320f43d7c7d8b559d63"}.Build(),
						},
					}.Build(),
				},
				HashVersions: []*fpb.HashVersion{
					fpb.HashVersion_builder{
						Hash: fpb.Hash_builder{HexString: "3786b9d769425320f43d7c7d8b559d63"}.Build(),
						Versions: []*fpb.Version{
							fpb.Version_builder{FullName: "v1.0"}.Build(),
							fpb.Version_builder{FullName: "v2.0"}.Build(),
							fpb.Version_builder{FullName: "v3.0"}.Build(),
						},
					}.Build(),
				},
			}.Build(),
			pages: map[string]string{
				"/": "I am supposed to be an NGINX v1.0 or v2.0 or v3.0",
			},
			want: []*nspb.ServiceContext{
				nspb.ServiceContext_builder{
					WebServiceContext: nspb.WebServiceContext_builder{
						ApplicationRoot: "{uri}",
						Software:        spb.Software_builder{Name: "nginx"}.Build(),
						VersionSet: spb.VersionSet_builder{
							Versions: []*spb.Version{
								spb.Version_builder{FullVersionString: "v1.0"}.Build(),
								spb.Version_builder{FullVersionString: "v2.0"}.Build(),
								spb.Version_builder{FullVersionString: "v3.0"}.Build(),
							},
						}.Build(),
						CrawlResults: []*wcpb.CrawlResult{
							wcpb.CrawlResult_builder{
								CrawlTarget:      wcpb.CrawlTarget_builder{Url: "{uri}/"}.Build(),
								ResponseCode:     200,
								Content:          []byte("3786b9d769425320f43d7c7d8b559d63"),
								CrawlContentType: wcpb.CrawlContentType_CONTENT_TYPE_HASH,
							}.Build(),
						},
					}.Build(),
				}.Build(),
			},
		},
		{
			name: "when_multiple_known_hashes_match_returns_the_most_specific_versions",
			knownHashes: fpb.Fingerprints_builder{
				SoftwareIdentity: fpb.SoftwareIdentity_builder{Software: "nginx"}.Build(),
				ContentHashes: []*fpb.ContentHash{
					fpb.ContentHash_builder{
						ContentPath: "/",
						Hashes: []*fpb.Hash{
							fpb.Hash_builder{HexString: "6acc630ba438d3c47709f3e4a03d0433"}.Build(),
						},
					}.Build(),
					fpb.ContentHash_builder{
						ContentPath: "/version",
						Hashes: []*fpb.Hash{
							fpb.Hash_builder{HexString: "5eadef45e713f861e6d6b32b998dde07"}.Build(),
						},
					}.Build(),
				},
				HashVersions: []*fpb.HashVersion{
					fpb.HashVersion_builder{
						Hash: fpb.Hash_builder{HexString: "6acc630ba438d3c47709f3e4a03d0433"}.Build(),
						Versions: []*fpb.Version{
							fpb.Version_builder{FullName: "v1.0"}.Build(),
							fpb.Version_builder{FullName: "v2.0"}.Build(),
							fpb.Version_builder{FullName: "v3.0"}.Build(),
						},
					}.Build(),
					fpb.HashVersion_builder{
						Hash: fpb.Hash_builder{HexString: "5eadef45e713f861e6d6b32b998dde07"}.Build(),
						Versions: []*fpb.Version{
							fpb.Version_builder{FullName: "v2.0"}.Build(),
						},
					}.Build(),
				},
			}.Build(),
			pages: map[string]string{
				"/":        "I can be many versions but... <a href=\"/version\">/version</a>",
				"/version": "I am actually version 2.0",
			},
			want: []*nspb.ServiceContext{
				nspb.ServiceContext_builder{
					WebServiceContext: nspb.WebServiceContext_builder{
						ApplicationRoot: "{uri}",
						Software:        spb.Software_builder{Name: "nginx"}.Build(),
						VersionSet: spb.VersionSet_builder{
							Versions: []*spb.Version{
								spb.Version_builder{FullVersionString: "v2.0"}.Build(),
							},
						}.Build(),
						CrawlResults: []*wcpb.CrawlResult{
							wcpb.CrawlResult_builder{
								CrawlTarget:      wcpb.CrawlTarget_builder{Url: "{uri}/"}.Build(),
								ResponseCode:     200,
								Content:          []byte("6acc630ba438d3c47709f3e4a03d0433"),
								CrawlContentType: wcpb.CrawlContentType_CONTENT_TYPE_HASH,
							}.Build(),
							wcpb.CrawlResult_builder{
								CrawlTarget:      wcpb.CrawlTarget_builder{Url: "{uri}/version"}.Build(),
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
		{
			name: "when_multiple_roots_match_returns_all_identified_roots",
			knownHashes: fpb.Fingerprints_builder{
				SoftwareIdentity: fpb.SoftwareIdentity_builder{Software: "nginx"}.Build(),
				ContentHashes: []*fpb.ContentHash{
					fpb.ContentHash_builder{
						ContentPath: "/version",
						Hashes: []*fpb.Hash{
							fpb.Hash_builder{HexString: "2d12331d1c80f5bfa00f6712ea547aca"}.Build(),
							fpb.Hash_builder{HexString: "5eadef45e713f861e6d6b32b998dde07"}.Build(),
						},
					}.Build(),
				},
				HashVersions: []*fpb.HashVersion{
					fpb.HashVersion_builder{
						Hash: fpb.Hash_builder{HexString: "2d12331d1c80f5bfa00f6712ea547aca"}.Build(),
						Versions: []*fpb.Version{
							fpb.Version_builder{FullName: "v1.0"}.Build(),
						},
					}.Build(),
					fpb.HashVersion_builder{
						Hash: fpb.Hash_builder{HexString: "5eadef45e713f861e6d6b32b998dde07"}.Build(),
						Versions: []*fpb.Version{
							fpb.Version_builder{FullName: "v2.0"}.Build(),
						},
					}.Build(),
				},
			}.Build(),
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
						ApplicationRoot: "{uri}/v1",
						Software:        spb.Software_builder{Name: "nginx"}.Build(),
						VersionSet: spb.VersionSet_builder{
							Versions: []*spb.Version{
								spb.Version_builder{FullVersionString: "v1.0"}.Build(),
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
						ApplicationRoot: "{uri}/v2",
						Software:        spb.Software_builder{Name: "nginx"}.Build(),
						VersionSet: spb.VersionSet_builder{
							Versions: []*spb.Version{
								spb.Version_builder{FullVersionString: "v2.0"}.Build(),
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
			registry := hash.NewRegistry()
			if err := registry.Load(tc.knownHashes); err != nil {
				t.Fatalf("Failed to load known hashes: %v", err)
			}

			modConfig := wfpb.WebIdentityFpConfig_builder{WriteHtmlToFile: proto.Bool(false)}.Build()
			cfg := buildConfig(t, modConfig, "")

			mod, err := newWithRegistry(t.Context(), modConfig, cfg, registry)
			if err != nil {
				t.Fatalf("Failed to create module: %v", err)
			}

			ctx := t.Context()
			gotServices, err := mod.Fingerprint(ctx, service)
			if err != nil {
				if tc.wantErr == nil || err != tc.wantErr {
					t.Fatalf("Fingerprint() returned unexpected error: got: %v, want: %v", err, tc.wantErr)
				}

				return
			}

			uri := fmt.Sprintf("http://%s:%d", hostname, port)

			var gotContexts []*nspb.ServiceContext
			for _, s := range gotServices {
				gotContexts = append(gotContexts, s.GetServiceContext())
			}

			var wantContexts []*nspb.ServiceContext
			for _, sc := range tc.want {
				wsc := sc.GetWebServiceContext()

				if wsc.GetApplicationRoot() != "" {
					wsc.SetApplicationRoot(strings.ReplaceAll(wsc.GetApplicationRoot(), "{uri}", uri))
				}

				for _, crawlResult := range wsc.GetCrawlResults() {
					newurl := strings.ReplaceAll(crawlResult.GetCrawlTarget().GetUrl(), "{uri}", uri)
					crawlResult.GetCrawlTarget().SetUrl(newurl)
				}

				wantContexts = append(wantContexts, sc)
			}

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
		hashes               *fpb.Fingerprints
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
			hashes:          &fpb.Fingerprints{},
			wantFileWritten: false,
		},
		{
			name: "when_artifacts_are_enabled_file_is_written",
			config: wfpb.WebIdentityFpConfig_builder{
				WriteHtmlToFile:          proto.Bool(true),
				MaximumFileSizeBytes:     proto.Int64(1000),
				MaximumStorageSpaceBytes: proto.Int64(1000),
			}.Build(),
			hashes:               &fpb.Fingerprints{},
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
			hashes:          &fpb.Fingerprints{},
			wantFileWritten: false,
		},
		{
			name: "when_storage_is_full_no_file_is_written",
			config: wfpb.WebIdentityFpConfig_builder{
				WriteHtmlToFile:          proto.Bool(true),
				MaximumFileSizeBytes:     proto.Int64(1000),
				MaximumStorageSpaceBytes: proto.Int64(10),
			}.Build(),
			hashes:          &fpb.Fingerprints{},
			wantFileWritten: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			workdir := t.TempDir()
			defer os.RemoveAll(workdir)

			server := newTestServer(pages)
			defer server.Close()

			_, _, service := serverInfo(t, server)
			registry := hash.NewRegistry()
			cfg := buildConfig(t, tc.config, workdir)
			artifactsDir := filepath.Join(workdir, "artifacts", moduleName)

			mod, err := newWithRegistry(t.Context(), tc.config, cfg, registry)
			if err != nil {
				t.Fatalf("Failed to create module: %v", err)
			}

			ctx := t.Context()
			_, err = mod.Fingerprint(ctx, service)
			if err != nil {
				t.Fatalf("Fingerprint() returned unexpected error: got: %v", err)
			}

			artifactPath := filepath.Join(artifactsDir, pageHash)
			gotFile, err := os.ReadFile(artifactPath)
			if err != nil {
				if tc.wantFileWritten {
					t.Fatalf("Expected artifact file %q to be written, but it was not found.", artifactPath)
				}

				// File not found, and we don't expect it to be written.
				return
			}

			if !tc.wantFileWritten {
				t.Fatalf("Expected artifact file %q not to be written, but it was found.", artifactPath)
			}

			if !bytes.Equal(gotFile, tc.wantFileContentBytes) {
				t.Errorf("Artifact file %q content mismatch: got %q, want %q", artifactPath, string(gotFile), string(tc.wantFileContentBytes))
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

	knownHashes := []*fpb.Fingerprints{
		fpb.Fingerprints_builder{
			SoftwareIdentity: fpb.SoftwareIdentity_builder{Software: "grafana"}.Build(),
			ContentHashes: []*fpb.ContentHash{
				fpb.ContentHash_builder{
					ContentPath: "/",
					Hashes:      []*fpb.Hash{fpb.Hash_builder{HexString: grafanaHash}.Build()},
				}.Build(),
				fpb.ContentHash_builder{
					ContentPath: "/app",
					Hashes:      []*fpb.Hash{fpb.Hash_builder{HexString: grafanaHash}.Build()},
				}.Build(),
			},
		}.Build(),
		fpb.Fingerprints_builder{
			SoftwareIdentity: fpb.SoftwareIdentity_builder{Software: "nginx"}.Build(),
			ContentHashes: []*fpb.ContentHash{
				fpb.ContentHash_builder{
					ContentPath: "/",
					Hashes:      []*fpb.Hash{fpb.Hash_builder{HexString: nginxHash}.Build()},
				}.Build(),
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
				buildTestService(npb.NetworkEndpoint_IP_HOSTNAME_PORT, "{host_uri}", "grafana",
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
				buildTestService(npb.NetworkEndpoint_IP_PORT, "{ip_uri}", "grafana",
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
				buildTestService(npb.NetworkEndpoint_HOSTNAME_PORT, "{host_uri}", "grafana",
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
				buildTestService(npb.NetworkEndpoint_HOSTNAME_PORT, "{host_uri}", "nginx",
					buildTestCrawl("{host_uri}/", 0, nginxHash),
				),
				buildTestService(npb.NetworkEndpoint_IP_PORT, "{ip_uri}", "grafana",
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
				buildTestService(npb.NetworkEndpoint_HOSTNAME_PORT, "{host_uri}/v1", "grafana",
					buildTestCrawl("{host_uri}/v1/app", 1, grafanaHash),
				),
				buildTestService(npb.NetworkEndpoint_IP_PORT, "{ip_uri}/v2", "grafana",
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
				buildTestService(npb.NetworkEndpoint_IP_HOSTNAME_PORT, "{host_uri}/v1", "grafana",
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

			registry := hash.NewRegistry()
			for _, fp := range knownHashes {
				if err := registry.Load(fp); err != nil {
					t.Fatalf("Failed to load known hashes: %v", err)
				}
			}

			modConfig := wfpb.WebIdentityFpConfig_builder{WriteHtmlToFile: proto.Bool(false)}.Build()
			cfg := buildConfig(t, modConfig, "")

			mod, err := newWithRegistry(ctx, modConfig, cfg, registry)
			if err != nil {
				t.Fatalf("Failed to create module: %v", err)
			}

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

func pageHash(t *testing.T, page string) string {
	t.Helper()
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
	}
	h, err := hash.FromResponse(resp, []byte(page+"\n"))
	if err != nil {
		t.Fatalf("hash.FromResponse(%q) failed: %v", page, err)
	}
	return h.Hex()
}

func buildTestEndpoint(epType npb.NetworkEndpoint_Type, ip string, port uint32) *npb.NetworkEndpoint {
	b := npb.NetworkEndpoint_builder{
		Type: epType,
		Port: npb.Port_builder{PortNumber: port}.Build(),
	}
	if epType == npb.NetworkEndpoint_HOSTNAME_PORT || epType == npb.NetworkEndpoint_IP_HOSTNAME_PORT {
		b.Hostname = npb.Hostname_builder{Name: "localhost"}.Build()
	}
	if epType == npb.NetworkEndpoint_IP_PORT || epType == npb.NetworkEndpoint_IP_HOSTNAME_PORT {
		b.IpAddress = npb.IpAddress_builder{AddressFamily: npb.AddressFamily_IPV4, Address: ip}.Build()
	}
	return b.Build()
}

func buildTestService(epType npb.NetworkEndpoint_Type, appRoot, software string, crawls ...*wcpb.CrawlResult) *nspb.NetworkService {
	wsc := nspb.WebServiceContext_builder{
		ApplicationRoot: appRoot,
		CrawlResults:    crawls,
	}
	if software != "" {
		wsc.Software = spb.Software_builder{Name: software}.Build()
		wsc.VersionSet = &spb.VersionSet{}
	}
	return nspb.NetworkService_builder{
		NetworkEndpoint:      npb.NetworkEndpoint_builder{Type: epType}.Build(),
		SupportedHttpMethods: []string{"GET"},
		ServiceContext: nspb.ServiceContext_builder{
			WebServiceContext: wsc.Build(),
		}.Build(),
	}.Build()
}

func buildTestCrawl(url string, depth int32, hexHash string) *wcpb.CrawlResult {
	return wcpb.CrawlResult_builder{
		CrawlTarget:      wcpb.CrawlTarget_builder{Url: url}.Build(),
		CrawlDepth:       depth,
		ResponseCode:     http.StatusOK,
		Content:          []byte(hexHash),
		CrawlContentType: wcpb.CrawlContentType_CONTENT_TYPE_HASH,
	}.Build()
}

func newHostAwareTestServer(hostPages, ipPages map[string]string) *httptest.Server {
	handler := func(w http.ResponseWriter, r *http.Request) {
		pages := ipPages
		if strings.HasPrefix(r.Host, "localhost") {
			pages = hostPages
		}

		p, ok := pages[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}

		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintln(w, p)
	}

	return httptest.NewServer(http.HandlerFunc(handler))
}

func newTestServer(pages map[string]string) *httptest.Server {
	return newHostAwareTestServer(pages, pages)
}

func serverInfo(t *testing.T, server *httptest.Server) (string, uint32, *nspb.NetworkService) {
	t.Helper()

	addr := strings.Split(server.Listener.Addr().String(), ":")
	if len(addr) != 2 {
		t.Fatalf("Failed to parse ip/port from test server: %s", addr)
	}

	p, err := strconv.Atoi(addr[1])
	if err != nil {
		t.Fatalf("Failed to parse port: %v", err)
	}

	hostname := addr[0]
	port := uint32(p)
	service := nspb.NetworkService_builder{
		NetworkEndpoint:      buildTestEndpoint(npb.NetworkEndpoint_IP_PORT, hostname, port),
		SupportedHttpMethods: []string{"GET"},
	}.Build()

	return hostname, port, service
}

func buildConfig(t *testing.T, modConfig *wfpb.WebIdentityFpConfig, workdir string) *config.Config {
	t.Helper()

	cfg := config.FromProto(cpb.Config_builder{
		Plugins: cpb.PluginsConfig_builder{
			Webidentity: modConfig,
		}.Build(),
	}.Build())

	if workdir != "" {
		cfg.CreateDirectories(workdir)
	}

	return cfg
}
