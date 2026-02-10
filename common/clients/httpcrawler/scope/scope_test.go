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

package scope

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	hcpb "github.com/google/goonami-scanner/common/clients/httpcrawler/httpcrawler_client_config_go_proto"
)

func TestFromProto(t *testing.T) {
	tests := []struct {
		name  string
		proto *hcpb.HttpCrawlerClientConfig_Scope
		want  *Scope
	}{
		{
			name: "when_scope_has_domain_only_returns_normalized_scope",
			proto: hcpb.HttpCrawlerClientConfig_Scope_builder{
				Domain: "foo.com",
			}.Build(),
			want: &Scope{Domain: "foo.com", Path: "/"},
		},
		{
			name: "when_scope_has_domain_and_path_returns_normalized_scope",
			proto: hcpb.HttpCrawlerClientConfig_Scope_builder{
				Domain: "foo.com",
				Path:   "/path",
			}.Build(),
			want: &Scope{Domain: "foo.com", Path: "/path/"},
		},
		{
			name: "when_scope_has_domain_and_file_path_returns_normalized_scope_with_parent_dir",
			proto: hcpb.HttpCrawlerClientConfig_Scope_builder{
				Domain: "foo.com",
				Path:   "/path/foo.html",
			}.Build(),
			want: &Scope{Domain: "foo.com", Path: "/path/"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := FromProto(tc.proto)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("FromProto(%v) returned diff (-want +got):\n%s", tc.proto, diff)
			}
		})
	}
}

func TestFromURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		want    *Scope
		wantErr bool
	}{
		{
			name: "when_url_is_valid_returns_scope",
			url:  "http://foo.com/path",
			want: &Scope{Domain: "foo.com", Path: "/path/"},
		},
		{
			name: "when_url_has_port_returns_scope_with_port",
			url:  "http://foo.com:8080/path",
			want: &Scope{Domain: "foo.com:8080", Path: "/path/"},
		},
		{
			name: "when_url_has_file_returns_scope_with_parent_dir",
			url:  "http://foo.com/path/index.html",
			want: &Scope{Domain: "foo.com", Path: "/path/"},
		},
		{
			name:    "when_url_is_invalid_returns_error",
			url:     "://foo.com",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := FromURL(tc.url)
			if tc.wantErr {
				if err == nil {
					t.Errorf("FromURL(%q) got nil error, want error", tc.url)
				}
				return
			}
			if err != nil {
				t.Fatalf("FromURL(%q) got error %v, want nil", tc.url, err)
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("FromURL(%q) returned diff (-want +got):\n%s", tc.url, diff)
			}
		})
	}
}

func TestLoad(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *hcpb.HttpCrawlerClientConfig
		urls    []string
		want    []*Scope
		wantErr bool
	}{
		{
			name: "when_policy_is_config_only_it_ignores_seed_urls",
			cfg: hcpb.HttpCrawlerClientConfig_builder{
				ScopePolicy: hcpb.HttpCrawlerClientConfig_SCOPE_POLICY_CONFIG_ONLY,
				Scopes: []*hcpb.HttpCrawlerClientConfig_Scope{
					hcpb.HttpCrawlerClientConfig_Scope_builder{Domain: "foo.com", Path: ""}.Build(),
					hcpb.HttpCrawlerClientConfig_Scope_builder{Domain: "foo.com", Path: "/path"}.Build(),
					hcpb.HttpCrawlerClientConfig_Scope_builder{Domain: "foo.com", Path: "/some/test.html"}.Build(),
					hcpb.HttpCrawlerClientConfig_Scope_builder{Domain: "foo.com", Path: "/test/"}.Build(),
				},
			}.Build(),
			urls: []string{"http://bar.com"},
			want: []*Scope{
				&Scope{Domain: "foo.com", Path: "/"},
				&Scope{Domain: "foo.com", Path: "/path/"},
				&Scope{Domain: "foo.com", Path: "/some/"},
				&Scope{Domain: "foo.com", Path: "/test/"},
			},
		},
		{
			name: "when_policy_is_expand_it_uses_seed_urls",
			cfg: hcpb.HttpCrawlerClientConfig_builder{
				ScopePolicy: hcpb.HttpCrawlerClientConfig_SCOPE_POLICY_EXPAND,
			}.Build(),
			urls: []string{
				"http://bar.com/path/",
				"http://bar.com/test",
				"http://bar.com/some/index.html",
				"http://bar.com:8080/path2/",
			},
			want: []*Scope{
				&Scope{Domain: "bar.com", Path: "/path/"},
				&Scope{Domain: "bar.com", Path: "/test/"},
				&Scope{Domain: "bar.com", Path: "/some/"},
				&Scope{Domain: "bar.com:8080", Path: "/path2/"},
			},
		},
		{
			name: "when_policy_is_expand_it_uses_both_config_and_seed_urls",
			cfg: hcpb.HttpCrawlerClientConfig_builder{
				ScopePolicy: hcpb.HttpCrawlerClientConfig_SCOPE_POLICY_EXPAND,
				Scopes: []*hcpb.HttpCrawlerClientConfig_Scope{
					hcpb.HttpCrawlerClientConfig_Scope_builder{Domain: "foo.com", Path: "/"}.Build(),
				},
			}.Build(),
			urls: []string{"http://bar.com/path"},
			want: []*Scope{
				&Scope{Domain: "foo.com", Path: "/"},
				&Scope{Domain: "bar.com", Path: "/path/"},
			},
		},
		{
			name: "when_seed_url_is_invalid_returns_error",
			cfg: hcpb.HttpCrawlerClientConfig_builder{
				ScopePolicy: hcpb.HttpCrawlerClientConfig_SCOPE_POLICY_EXPAND,
			}.Build(),
			urls:    []string{"://bar.com"},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			scopes, err := Load(tc.cfg, tc.urls)
			if tc.wantErr {
				if err == nil {
					t.Errorf("Load() got nil error, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("Load() got error %v, want nil", err)
			}
			if diff := cmp.Diff(tc.want, scopes); diff != "" {
				t.Errorf("Load() scopes diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestScope_Decision(t *testing.T) {
	tests := []struct {
		name      string
		scope     *Scope
		targetURL string
		want      Decision
		wantErr   bool
	}{
		{
			name:      "when_target_matches_domain_it_is_in_scope",
			scope:     &Scope{Domain: "foo.com"},
			targetURL: "http://foo.com/path",
			want:      DecisionInScope,
		},
		{
			name:      "when_target_matches_domain_and_path_it_is_in_scope",
			scope:     &Scope{Domain: "foo.com", Path: "/path"},
			targetURL: "http://foo.com/path/sub",
			want:      DecisionInScope,
		},
		{
			name:      "when_target_matches_domain_with_port_it_is_in_scope",
			scope:     &Scope{Domain: "foo.com:8080", Path: "/"},
			targetURL: "http://foo.com:8080/",
			want:      DecisionInScope,
		},

		{
			name:      "when_target_domain_mismatches_it_is_not_in_scope",
			scope:     &Scope{Domain: "foo.com"},
			targetURL: "http://bar.com/path",
			want:      DecisionDomainMismatch,
		},
		{
			name:      "when_target_path_mismatches_it_is_not_in_scope",
			scope:     &Scope{Domain: "foo.com", Path: "/path"},
			targetURL: "http://foo.com/other",
			want:      DecisionPathMismatch,
		},
		{
			name:      "when_target_url_is_invalid_returns_error",
			targetURL: "://foo.com",
			wantErr:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.scope.Decision(tc.targetURL)
			if tc.wantErr {
				if err == nil {
					t.Errorf("Decision(%q) got nil error, want error", tc.targetURL)
				}
				return
			}
			if err != nil {
				t.Fatalf("Decision(%q) got error %v, want nil", tc.targetURL, err)
			}
			if got != tc.want {
				t.Errorf("Decision(%q) = %d, want %d", tc.targetURL, got, tc.want)
			}
		})
	}
}

func TestScope_Matches(t *testing.T) {
	tests := []struct {
		name      string
		scope     *Scope
		targetURL string
		want      bool
		wantErr   bool
	}{
		{
			name:      "when_target_is_in_scope_returns_true",
			scope:     &Scope{Domain: "foo.com", Path: "/"},
			targetURL: "http://foo.com/",
			want:      true,
		},
		{
			name:      "when_target_is_not_in_scope_returns_false",
			scope:     &Scope{Domain: "foo.com", Path: "/"},
			targetURL: "http://bar.com/",
			want:      false,
		},
		{
			name:      "when_target_url_is_invalid_returns_error",
			targetURL: "://foo.com",
			wantErr:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.scope.Matches(tc.targetURL)
			if tc.wantErr {
				if err == nil {
					t.Errorf("Matches(%q) got nil error, want error", tc.targetURL)
				}
				return
			}
			if err != nil {
				t.Fatalf("Matches(%q) got error %v, want nil", tc.targetURL, err)
			}
			if got != tc.want {
				t.Errorf("Matches(%q) = %v, want %v", tc.targetURL, got, tc.want)
			}
		})
	}
}

func TestNormalizePath(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{
			path: "/",
			want: "/",
		},
		{
			path: "/test",
			want: "/test/",
		},
		{
			path: "/test/",
			want: "/test/",
		},
		{
			path: "/test/foo",
			want: "/test/foo/",
		},
		{
			path: "/test/foo.html",
			want: "/test/",
		},
	}

	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			got := NormalizePath(tc.path)
			if got != tc.want {
				t.Errorf("NormalizePath(%q) = %q, want %q", tc.path, got, tc.want)
			}
		})
	}
}

func TestMatchAnyScope(t *testing.T) {
	tests := []struct {
		name    string
		scopes  []*Scope
		url     string
		want    bool
		wantErr bool
	}{
		{
			name: "when_url_matches_first_scope_returns_true",
			scopes: []*Scope{
				&Scope{Domain: "foo.com", Path: "/"},
				&Scope{Domain: "bar.com", Path: "/path/"},
			},
			url:  "http://foo.com/test",
			want: true,
		},
		{
			name: "when_url_matches_second_scope_returns_true",
			scopes: []*Scope{
				&Scope{Domain: "foo.com", Path: "/"},
				&Scope{Domain: "bar.com", Path: "/path/"},
			},
			url:  "http://bar.com/path/test",
			want: true,
		},
		{
			name: "when_url_matches_no_scope_returns_false",
			scopes: []*Scope{
				&Scope{Domain: "foo.com", Path: "/"},
				&Scope{Domain: "bar.com", Path: "/path/"},
			},
			url:  "http://bar.com/other",
			want: false,
		},
		{
			name: "when_url_is_invalid_returns_error",
			scopes: []*Scope{
				&Scope{Domain: "foo.com", Path: "/"},
			},
			url:     "://foo.com",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := MatchAnyScope(tc.url, tc.scopes)
			if tc.wantErr {
				if err == nil {
					t.Errorf("MatchAnyScope(%q) got nil error, want error", tc.url)
				}
				return
			}
			if err != nil {
				t.Fatalf("MatchAnyScope(%q) got error %v, want nil", tc.url, err)
			}
			if got != tc.want {
				t.Errorf("MatchAnyScope(%q) = %v, want %v", tc.url, got, tc.want)
			}
		})
	}
}
