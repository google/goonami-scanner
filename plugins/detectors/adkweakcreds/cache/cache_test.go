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

package cache

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/google/goonami-scanner/core/config"
	_ "github.com/google/goonami-scanner/core/net/http/simpleclient"
	"github.com/google/goonami-scanner/core/net/netservice"
	"github.com/google/goonami-scanner/plugins/fingerprint/webidentity/hash"
	"google.golang.org/protobuf/proto"

	cpb "github.com/google/goonami-scanner/core/config/config_go_proto"
	npb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
	wcpb "github.com/google/tsunami-security-scanner/proto/go/web_crawl_go_proto"
)

func createNetworkService(host string, port int, tls bool) *nspb.NetworkService {
	endpointBuilder := npb.NetworkEndpoint_builder{
		Type: npb.NetworkEndpoint_IP_PORT,
		IpAddress: npb.IpAddress_builder{
			Address: host,
		}.Build(),
		Port: npb.Port_builder{
			PortNumber: uint32(port),
		}.Build(),
	}

	svcBuilder := nspb.NetworkService_builder{
		ServiceName:          "http",
		SupportedHttpMethods: []string{"GET", "POST"},
		NetworkEndpoint:      endpointBuilder.Build(),
	}

	if tls {
		svcBuilder.SupportedSslVersions = []string{"TLSv1_3"}
	}

	return svcBuilder.Build()
}

func createTestConfig() *config.Config {
	return config.FromProto(cpb.Config_builder{
		Globalcfg: cpb.GlobalConfig_builder{
			Performance: cpb.GlobalConfig_Performance_builder{
				TimeoutPerRequestSeconds: proto.Int32(5),
			}.Build(),
		}.Build(),
	}.Build())
}

func computeExpectedHash(statusCode int, contentType string, body []byte) (string, error) {
	resp := &http.Response{
		StatusCode: statusCode,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", contentType)
	h, err := hash.FromResponse(resp, body)
	if err != nil {
		return "", err
	}
	return h.Hex(), nil
}

func TestLoad(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(t *testing.T) string
		wantNil   bool
		wantEmpty bool
		wantMap   map[string]string
	}{
		{
			name: "when_path_is_empty_returns_nil",
			setup: func(t *testing.T) string {
				return ""
			},
			wantNil: true,
		},
		{
			name: "when_index_file_does_not_exist_returns_empty_index",
			setup: func(t *testing.T) string {
				return t.TempDir()
			},
			wantEmpty: true,
		},
		{
			name: "when_index_file_corrupt_returns_empty_index",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				if err := os.WriteFile(filepath.Join(dir, indexFileName), []byte("corrupt"), 0644); err != nil {
					t.Fatalf("failed to write corrupt index: %v", err)
				}
				return dir
			},
			wantEmpty: true,
		},
		{
			name: "when_hash_to_path_is_nil_initializes_empty_map",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				if err := os.WriteFile(filepath.Join(dir, indexFileName), []byte(`{"hash_to_path": null}`), 0644); err != nil {
					t.Fatalf("failed to write index: %v", err)
				}
				return dir
			},
			wantMap: map[string]string{},
		},
		{
			name: "when_index_file_is_valid_loads_index",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				if err := os.WriteFile(filepath.Join(dir, indexFileName), []byte(`{"hash_to_path":{"abc":"/path"}}`), 0644); err != nil {
					t.Fatalf("failed to write index: %v", err)
				}
				return dir
			},
			wantMap: map[string]string{"abc": "/path"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := tc.setup(t)
			got := Load(t.Context(), path)
			if tc.wantNil {
				if got != nil {
					t.Errorf("Load() = %v, want nil", got)
				}
				return
			}
			if got == nil {
				t.Fatal("Load() returned nil")
			}
			if tc.wantEmpty {
				if got.HashToPath == nil || len(got.HashToPath) != 0 {
					t.Errorf("Load() HashToPath = %v, want empty map", got.HashToPath)
				}
				return
			}
			if len(got.HashToPath) != len(tc.wantMap) {
				t.Errorf("Load() HashToPath = %v, want %v", got.HashToPath, tc.wantMap)
			}
			for k, v := range tc.wantMap {
				if got.HashToPath[k] != v {
					t.Errorf("Load() HashToPath[%q] = %q, want %q", k, got.HashToPath[k], v)
				}
			}
		})
	}
}

func TestAdd(t *testing.T) {
	cfg := createTestConfig()

	tests := []struct {
		name     string
		setupIdx func(t *testing.T, dir string) *Index
		setupSvc func(t *testing.T) (*nspb.NetworkService, string, func())
		wantErr  bool
	}{
		{
			name: "when_indexpath_is_empty_add_does_nothing",
			setupIdx: func(t *testing.T, dir string) *Index {
				return Load(t.Context(), "")
			},
			setupSvc: func(t *testing.T) (*nspb.NetworkService, string, func()) {
				return nspb.NetworkService_builder{}.Build(), "/uri", func() {}
			},
			wantErr: false,
		},
		{
			name: "when_hash_page_fails_add_returns_error",
			setupIdx: func(t *testing.T, dir string) *Index {
				return Load(t.Context(), dir)
			},
			setupSvc: func(t *testing.T) (*nspb.NetworkService, string, func()) {
				return nspb.NetworkService_builder{}.Build(), "/uri", func() {}
			},
			wantErr: true,
		},
		{
			name: "when_context_is_canceled_returns_error",
			setupIdx: func(t *testing.T, dir string) *Index {
				return Load(t.Context(), dir)
			},
			setupSvc: func(t *testing.T) (*nspb.NetworkService, string, func()) {
				return createNetworkService("localhost", 8080, false), "/auth", func() {}
			},
			wantErr: true,
		},
		{
			name: "when_valid_inputs_saves_strategy_and_index",
			setupIdx: func(t *testing.T, dir string) *Index {
				return Load(t.Context(), dir)
			},
			setupSvc: func(t *testing.T) (*nspb.NetworkService, string, func()) {
				ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "text/html")
					w.WriteHeader(http.StatusOK)
					w.Write([]byte("response_body"))
				}))
				host, portStr, _ := net.SplitHostPort(ts.Listener.Addr().String())
				port, _ := strconv.Atoi(portStr)
				svc := createNetworkService(host, port, false)
				return svc, "/auth", ts.Close
			},
			wantErr: false,
		},
		{
			name: "when_server_returns_429_add_returns_error",
			setupIdx: func(t *testing.T, dir string) *Index {
				return Load(t.Context(), dir)
			},
			setupSvc: func(t *testing.T) (*nspb.NetworkService, string, func()) {
				ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusTooManyRequests)
				}))
				host, portStr, _ := net.SplitHostPort(ts.Listener.Addr().String())
				port, _ := strconv.Atoi(portStr)
				svc := createNetworkService(host, port, false)
				return svc, "/auth", ts.Close
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			idx := tc.setupIdx(t, dir)
			svc, path, cleanup := tc.setupSvc(t)
			defer cleanup()

			ctx := t.Context()
			if tc.name == "when_context_is_canceled_returns_error" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}

			strategyBytes := []byte("my_strategy_bytes")
			err := idx.Add(ctx, cfg, svc, path, strategyBytes)
			if (err != nil) != tc.wantErr {
				t.Fatalf("Add() error = %v, wantErr = %v", err, tc.wantErr)
			}
			if tc.wantErr || idx == nil || idx.directory == "" {
				return
			}

			expectedHash, err := computeExpectedHash(http.StatusOK, "text/html", []byte("response_body"))
			if err != nil {
				t.Fatalf("failed to compute expected hash: %v", err)
			}

			if idx.HashToPath[expectedHash] != path {
				t.Errorf("idx.HashToPath[%q] = %q, want %q", expectedHash, idx.HashToPath[expectedHash], path)
			}

			loadedIdx := Load(t.Context(), dir)
			if loadedIdx.HashToPath[expectedHash] != path {
				t.Errorf("loaded Index HashToPath[%q] = %q, want %q", expectedHash, loadedIdx.HashToPath[expectedHash], path)
			}

			strategyPath := filepath.Join(dir, cacheDirName, expectedHash+strategySuffix)
			gotStrategy, err := os.ReadFile(strategyPath)
			if err != nil {
				t.Fatalf("failed to read strategy file: %v", err)
			}
			if string(gotStrategy) != string(strategyBytes) {
				t.Errorf("strategy file content = %q, want %q", gotStrategy, strategyBytes)
			}
		})
	}
}

func TestFindForService(t *testing.T) {
	cfg := createTestConfig()

	tests := []struct {
		name         string
		setupCache   func(t *testing.T, dir string) (*Index, string)
		setupSvc     func(t *testing.T, expectedHash string) (*nspb.NetworkService, func())
		wantStrategy []byte
		wantFound    bool
	}{
		{
			name: "when_indexpath_is_empty_returns_nil_false",
			setupCache: func(t *testing.T, dir string) (*Index, string) {
				return Load(t.Context(), ""), "anyhash"
			},
			setupSvc: func(t *testing.T, expectedHash string) (*nspb.NetworkService, func()) {
				return nspb.NetworkService_builder{}.Build(), func() {}
			},
			wantStrategy: nil,
			wantFound:    false,
		},
		{
			name: "when_crawled_and_hash_matches_returns_strategy_and_true",
			setupCache: func(t *testing.T, dir string) (*Index, string) {
				idx := Load(t.Context(), dir)
				h := "hash123"
				idx.mut.Lock()
				idx.HashToPath[h] = "/login"
				idx.mut.Unlock()

				strategyBytes := []byte("strategy_crawled")
				if err := idx.saveStrategy(h, strategyBytes); err != nil {
					t.Fatalf("failed to save strategy: %v", err)
				}
				return idx, h
			},
			setupSvc: func(t *testing.T, expectedHash string) (*nspb.NetworkService, func()) {
				svc := createNetworkService("localhost", 8080, false)
				crawlResult := wcpb.CrawlResult_builder{
					CrawlTarget:      wcpb.CrawlTarget_builder{Url: "http://localhost:8080/login"}.Build(),
					Content:          []byte(expectedHash),
					CrawlContentType: wcpb.CrawlContentType_CONTENT_TYPE_HASH,
				}.Build()
				netservice.AddCrawlResults(svc, []*wcpb.CrawlResult{crawlResult})
				return svc, func() {}
			},
			wantStrategy: []byte("strategy_crawled"),
			wantFound:    true,
		},
		{
			name: "when_crawled_but_content_type_not_hash_skips_fetch",
			setupCache: func(t *testing.T, dir string) (*Index, string) {
				idx := Load(t.Context(), dir)
				h := "hash123"
				idx.mut.Lock()
				idx.HashToPath[h] = "/login"
				idx.mut.Unlock()
				if err := idx.saveStrategy(h, []byte("strategy_crawled")); err != nil {
					t.Fatalf("failed to save strategy: %v", err)
				}
				return idx, h
			},
			setupSvc: func(t *testing.T, expectedHash string) (*nspb.NetworkService, func()) {
				serverHit := false
				ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					serverHit = true
					w.WriteHeader(http.StatusOK)
				}))
				host, portStr, _ := net.SplitHostPort(ts.Listener.Addr().String())
				port, _ := strconv.Atoi(portStr)
				svc := createNetworkService(host, port, false)
				crawlResult := wcpb.CrawlResult_builder{
					CrawlTarget:      wcpb.CrawlTarget_builder{Url: ts.URL + "/login"}.Build(),
					Content:          []byte(expectedHash),
					CrawlContentType: wcpb.CrawlContentType_CONTENT_TYPE_UNSPECIFIED,
				}.Build()
				netservice.AddCrawlResults(svc, []*wcpb.CrawlResult{crawlResult})
				return svc, func() {
					ts.Close()
					if serverHit {
						t.Errorf("server was hit for already-crawled path")
					}
				}
			},
			wantStrategy: nil,
			wantFound:    false,
		},
		{
			name: "when_crawled_and_hash_mismatches_skips_network_fetch",
			setupCache: func(t *testing.T, dir string) (*Index, string) {
				idx := Load(t.Context(), dir)
				h := "hash123"
				idx.mut.Lock()
				idx.HashToPath[h] = "/login"
				idx.mut.Unlock()
				if err := idx.saveStrategy(h, []byte("strategy_crawled")); err != nil {
					t.Fatalf("failed to save strategy: %v", err)
				}
				return idx, h
			},
			setupSvc: func(t *testing.T, expectedHash string) (*nspb.NetworkService, func()) {
				serverHit := false
				ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					serverHit = true
					w.WriteHeader(http.StatusOK)
				}))
				host, portStr, _ := net.SplitHostPort(ts.Listener.Addr().String())
				port, _ := strconv.Atoi(portStr)
				svc := createNetworkService(host, port, false)
				crawlResult := wcpb.CrawlResult_builder{
					CrawlTarget:      wcpb.CrawlTarget_builder{Url: ts.URL + "/login"}.Build(),
					Content:          []byte("mismatch_hash"),
					CrawlContentType: wcpb.CrawlContentType_CONTENT_TYPE_HASH,
				}.Build()
				netservice.AddCrawlResults(svc, []*wcpb.CrawlResult{crawlResult})
				return svc, func() {
					ts.Close()
					if serverHit {
						t.Errorf("server was hit for already-crawled path with mismatched hash")
					}
				}
			},
			wantStrategy: nil,
			wantFound:    false,
		},
		{
			name: "when_not_crawled_but_fetched_hash_matches_returns_strategy_and_true",
			setupCache: func(t *testing.T, dir string) (*Index, string) {
				idx := Load(t.Context(), dir)
				h, _ := computeExpectedHash(http.StatusOK, "text/html", []byte("page_body"))
				idx.mut.Lock()
				idx.HashToPath[h] = "/login"
				idx.mut.Unlock()
				if err := idx.saveStrategy(h, []byte("strategy_fetched")); err != nil {
					t.Fatalf("failed to save strategy: %v", err)
				}
				return idx, h
			},
			setupSvc: func(t *testing.T, expectedHash string) (*nspb.NetworkService, func()) {
				ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "text/html")
					w.WriteHeader(http.StatusOK)
					w.Write([]byte("page_body"))
				}))
				host, portStr, _ := net.SplitHostPort(ts.Listener.Addr().String())
				port, _ := strconv.Atoi(portStr)
				svc := createNetworkService(host, port, false)
				return svc, ts.Close
			},
			wantStrategy: []byte("strategy_fetched"),
			wantFound:    true,
		},
		{
			name: "when_not_crawled_but_fetched_hash_mismatch_returns_nil_false",
			setupCache: func(t *testing.T, dir string) (*Index, string) {
				idx := Load(t.Context(), dir)
				idx.mut.Lock()
				idx.HashToPath["expected_hash"] = "/login"
				idx.mut.Unlock()
				if err := idx.saveStrategy("expected_hash", []byte("strategy_fetched")); err != nil {
					t.Fatalf("failed to save strategy: %v", err)
				}
				return idx, "expected_hash"
			},
			setupSvc: func(t *testing.T, expectedHash string) (*nspb.NetworkService, func()) {
				ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "text/html")
					w.WriteHeader(http.StatusOK)
					w.Write([]byte("different_page_body"))
				}))
				host, portStr, _ := net.SplitHostPort(ts.Listener.Addr().String())
				port, _ := strconv.Atoi(portStr)
				svc := createNetworkService(host, port, false)
				return svc, ts.Close
			},
			wantStrategy: nil,
			wantFound:    false,
		},
		{
			name: "when_not_crawled_and_fetch_fails_returns_nil_false",
			setupCache: func(t *testing.T, dir string) (*Index, string) {
				idx := Load(t.Context(), dir)
				idx.mut.Lock()
				idx.HashToPath["expected_hash"] = "/login"
				idx.mut.Unlock()
				if err := idx.saveStrategy("expected_hash", []byte("strategy_fetched")); err != nil {
					t.Fatalf("failed to save strategy: %v", err)
				}
				return idx, "expected_hash"
			},
			setupSvc: func(t *testing.T, expectedHash string) (*nspb.NetworkService, func()) {
				svc := createNetworkService("127.0.0.1", 1, false)
				return svc, func() {}
			},
			wantStrategy: nil,
			wantFound:    false,
		},
		{
			name: "when_context_is_canceled_returns_nil_false",
			setupCache: func(t *testing.T, dir string) (*Index, string) {
				idx := Load(t.Context(), dir)
				idx.mut.Lock()
				idx.HashToPath["expected_hash"] = "/login"
				idx.mut.Unlock()
				if err := idx.saveStrategy("expected_hash", []byte("strategy_fetched")); err != nil {
					t.Fatalf("failed to save strategy: %v", err)
				}
				return idx, "expected_hash"
			},
			setupSvc: func(t *testing.T, expectedHash string) (*nspb.NetworkService, func()) {
				ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "text/html")
					w.WriteHeader(http.StatusOK)
					w.Write([]byte("page_body"))
				}))
				host, portStr, _ := net.SplitHostPort(ts.Listener.Addr().String())
				port, _ := strconv.Atoi(portStr)
				svc := createNetworkService(host, port, false)
				return svc, ts.Close
			},
			wantStrategy: nil,
			wantFound:    false,
		},
		{
			name: "when_not_crawled_and_server_returns_429_returns_nil_false",
			setupCache: func(t *testing.T, dir string) (*Index, string) {
				idx := Load(t.Context(), dir)
				idx.mut.Lock()
				idx.HashToPath["expected_hash"] = "/login"
				idx.mut.Unlock()
				if err := idx.saveStrategy("expected_hash", []byte("strategy_fetched")); err != nil {
					t.Fatalf("failed to save strategy: %v", err)
				}
				return idx, "expected_hash"
			},
			setupSvc: func(t *testing.T, expectedHash string) (*nspb.NetworkService, func()) {
				ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusTooManyRequests)
				}))
				host, portStr, _ := net.SplitHostPort(ts.Listener.Addr().String())
				port, _ := strconv.Atoi(portStr)
				svc := createNetworkService(host, port, false)
				return svc, ts.Close
			},
			wantStrategy: nil,
			wantFound:    false,
		},
		{
			name: "when_multiple_hashes_share_path_probes_only_once_and_matches",
			setupCache: func(t *testing.T, dir string) (*Index, string) {
				idx := Load(t.Context(), dir)
				hMatch, _ := computeExpectedHash(http.StatusOK, "text/html", []byte("shared_page"))
				idx.mut.Lock()
				idx.HashToPath["other_hash_1"] = "/login"
				idx.HashToPath[hMatch] = "/login"
				idx.HashToPath["other_hash_2"] = "/login"
				idx.mut.Unlock()
				if err := idx.saveStrategy(hMatch, []byte("strategy_matched")); err != nil {
					t.Fatalf("failed to save strategy: %v", err)
				}
				return idx, hMatch
			},
			setupSvc: func(t *testing.T, expectedHash string) (*nspb.NetworkService, func()) {
				reqCount := 0
				ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					reqCount++
					w.Header().Set("Content-Type", "text/html")
					w.WriteHeader(http.StatusOK)
					w.Write([]byte("shared_page"))
				}))
				host, portStr, _ := net.SplitHostPort(ts.Listener.Addr().String())
				port, _ := strconv.Atoi(portStr)
				svc := createNetworkService(host, port, false)
				return svc, func() {
					ts.Close()
					if reqCount != 1 {
						t.Errorf("expected exactly 1 request to /login, got %d", reqCount)
					}
				}
			},
			wantStrategy: []byte("strategy_matched"),
			wantFound:    true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			idx, expectedHash := tc.setupCache(t, dir)
			svc, cleanup := tc.setupSvc(t, expectedHash)
			defer cleanup()

			ctx := t.Context()
			if tc.name == "when_context_is_canceled_returns_nil_false" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}

			gotStrategy, ok := idx.FindForService(ctx, cfg, svc)
			if ok != tc.wantFound {
				t.Fatalf("FindForService() ok = %v, want %v", ok, tc.wantFound)
			}
			if string(gotStrategy) != string(tc.wantStrategy) {
				t.Errorf("FindForService() strategy = %q, want %q", gotStrategy, tc.wantStrategy)
			}
		})
	}
}
