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

package parser

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestExtractFromHTML(t *testing.T) {
	tests := []struct {
		name     string
		rootURL  string
		body     []byte
		testFile string
		want     []string
		wantErr  error
	}{
		{
			name:     "when_all_link_attributes_are_present_returns_all_links",
			rootURL:  "http://a.com/d/index.html",
			testFile: "all_link_attrs.html",
			want: []string{
				"http://a.com/d/manifest.json",
				"http://a.com/d/background.jpg",
				"http://a.com/d/links/1",
				"http://a.com/links/2",
				"http://other.com/links/3",
				"http://a.com/d/images/1.png",
				"http://a.com/d/descriptions/1.txt",
				"http://a.com/d/profile.png",
				"http://a.com/d/quotes/1",
				"http://a.com/d/data/1",
				"http://a.com/d/code/base/",
				"http://a.com/d/archives/1.zip",
				"http://a.com/d/forms/1",
				"http://a.com/d/forms/2",
				"http://a.com/d/media/poster.png",
				"http://a.com/d/media/subtitles.vtt",
				"http://a.com/d/srcdoc.html",
				"http://a.com/d/ping/1",
			},
			wantErr: nil,
		},
		{
			name:     "when_page_contains_malformed_url_returns_error",
			rootURL:  "http://a.com/d/index.html",
			testFile: "page_with_malformed_url.html",
			wantErr:  ErrParseURL,
		},
		{
			name:    "when_content_is_empty_returns_no_links",
			rootURL: "http://a.com/d/index.html",
			body:    nil,
			wantErr: nil,
		},
		{
			name:     "when_root_url_is_invalid_returns_error",
			rootURL:  "http://%40invalid.com/",
			testFile: "all_link_attrs.html",
			wantErr:  ErrParseURL,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body := tc.body

			if tc.testFile != "" {
				b, err := os.ReadFile(filepath.Join("testdata", tc.testFile))
				if err != nil {
					t.Fatalf("os.ReadFile() returned an unexpected error: %v", err)
				}
				body = b
			}

			got, err := ExtractLinksFromHTML(tc.rootURL, body)
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("ExtractLinksFromHTML(%q) error = %v, want %v", tc.rootURL, err, tc.wantErr)
			}

			if tc.wantErr != nil {
				return
			}

			sort.Strings(got)
			sort.Strings(tc.want)

			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("extractFromHTML() returned diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestParseURL(t *testing.T) {
	tests := []struct {
		name    string
		rootURL string
		nodeURL string
		want    string
		wantErr error
	}{
		{
			name:    "when_node_is_relative_path_from_root_returns_absolute_url",
			rootURL: "http://something.lan:8080",
			nodeURL: "/google",
			want:    "http://something.lan:8080/google",
		},
		{
			name:    "when_node_is_relative_path_from_file_returns_absolute_url",
			rootURL: "http://something.lan:8080/test.html",
			nodeURL: "/google",
			want:    "http://something.lan:8080/google",
		},
		{
			name:    "when_node_is_relative_path_from_dir_returns_absolute_url",
			rootURL: "http://something.lan:8080/test/",
			nodeURL: "google/",
			want:    "http://something.lan:8080/test/google/",
		},
		{
			name:    "when_node_is_relative_path_from_html_file_returns_absolute_url",
			rootURL: "http://something.lan:8080/test.html",
			nodeURL: "google/",
			want:    "http://something.lan:8080/google/",
		},
		{
			name:    "when_node_is_absolute_path_returns_absolute_url",
			rootURL: "http://something.lan:8080/test/",
			nodeURL: "/google",
			want:    "http://something.lan:8080/google",
		},
		{
			name:    "when_node_is_different_domain_returns_other_domain_url",
			rootURL: "http://something.lan:8080/test.html",
			nodeURL: "http://somethingelse.lan:8080/othertest.html",
			want:    "http://somethingelse.lan:8080/othertest.html",
		},
		{
			name:    "when_root_is_ipv4_returns_ipv4_url",
			rootURL: "http://1.2.3.4/",
			nodeURL: "a",
			want:    "http://1.2.3.4/a",
		},
		{
			name:    "when_root_is_ipv4_with_port_returns_ipv4_url_with_port",
			rootURL: "http://1.2.3.4:8080/",
			nodeURL: "a",
			want:    "http://1.2.3.4:8080/a",
		},
		{
			name:    "when_root_is_domain_returns_domain_url",
			rootURL: "http://domain.com/",
			nodeURL: "a",
			want:    "http://domain.com/a",
		},
		{
			name:    "when_root_is_domain_with_port_returns_domain_url_with_port",
			rootURL: "http://domain.com:1234/",
			nodeURL: "a",
			want:    "http://domain.com:1234/a",
		},
		{
			name:    "when_root_is_ipv6_returns_ipv6_url",
			rootURL: "http://[::1]/",
			nodeURL: "a",
			want:    "http://[::1]/a",
		},
		{
			name:    "when_root_is_ipv6_with_port_returns_ipv6_url_with_port",
			rootURL: "http://[::1]:8080/",
			nodeURL: "a",
			want:    "http://[::1]:8080/a",
		},
		{
			name:    "when_node_is_empty_returns_root_url",
			rootURL: "http://domain.com/test",
			nodeURL: "",
			want:    "http://domain.com/test",
		},
		{
			name:    "when_node_is_fragment_only_returns_root_url_without_fragment",
			rootURL: "http://domain.com/test",
			nodeURL: "#frag",
			want:    "http://domain.com/test",
		},
		{
			name:    "when_node_is_query_only_returns_root_url_without_query",
			rootURL: "http://domain.com/test",
			nodeURL: "?q=1",
			want:    "http://domain.com/test",
		},
		{
			name:    "when_node_is_protocol_relative_http_returns_http_url",
			rootURL: "http://domain.com/",
			nodeURL: "//domain.com/something",
			want:    "http://domain.com/something",
		},
		{
			name:    "when_node_is_protocol_relative_https_returns_https_url",
			rootURL: "https://domain.com/",
			nodeURL: "//domain.com/something",
			want:    "https://domain.com/something",
		},
		{
			name:    "when_node_has_different_protocol_returns_error",
			rootURL: "http://domain.com/",
			nodeURL: "ftp://domain.com/a",
			wantErr: ErrUnsupportedScheme,
		},
		{
			name:    "when_node_is_javascript_returns_error",
			rootURL: "http://domain.com/",
			nodeURL: "javascript:alert('Evil XSS')",
			wantErr: ErrUnsupportedURLType,
		},
		{
			name:    "when_node_is_mailto_returns_error",
			rootURL: "http://domain.com/",
			nodeURL: "mailto:someone@domain.com",
			wantErr: ErrUnsupportedURLType,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseURL(tc.rootURL, tc.nodeURL)
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("parseURL(%q, %q) returned error %v, want %v", tc.rootURL, tc.nodeURL, err, tc.wantErr)
			}

			if tc.wantErr != nil {
				return
			}

			if got != tc.want {
				t.Errorf("parseURL(%q, %q) = %q, want: %q", tc.rootURL, tc.nodeURL, got, tc.want)
			}
		})
	}
}
