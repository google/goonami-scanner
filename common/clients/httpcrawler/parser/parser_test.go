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
		{
			name:    "when_page_contains_meta_refresh_extracts_url",
			rootURL: "http://a.com/d/index.html",
			body:    []byte(`<html><head><meta http-equiv="refresh" content="0;URL=index.jsp"></head></html>`),
			want: []string{
				"http://a.com/d/index.jsp",
			},
			wantErr: nil,
		},
		{
			name:    "when_page_contains_meta_refresh_with_absolute_url_extracts_url",
			rootURL: "http://a.com/d/index.html",
			body:    []byte(`<html><head><meta http-equiv="refresh" content="0;URL=http://other.com/index.jsp"></head></html>`),
			want: []string{
				"http://other.com/index.jsp",
			},
			wantErr: nil,
		},
		{
			name:    "when_page_contains_meta_refresh_case_insensitive_extracts_url",
			rootURL: "http://a.com/d/index.html",
			body:    []byte(`<html><head><META HTTP-EQUIV="Refresh" CONTENT="0;url=index.jsp"></head></html>`),
			want: []string{
				"http://a.com/d/index.jsp",
			},
			wantErr: nil,
		},
		{
			name:    "when_page_contains_meta_refresh_with_spaces_extracts_url",
			rootURL: "http://a.com/d/index.html",
			body:    []byte(`<html><head><meta http-equiv="refresh" content=" 0 ; URL = index.jsp "></head></html>`),
			want: []string{
				"http://a.com/d/index.jsp",
			},
			wantErr: nil,
		},
		{
			name:    "when_page_contains_meta_refresh_no_url_returns_nothing",
			rootURL: "http://a.com/d/index.html",
			body:    []byte(`<html><head><meta http-equiv="refresh" content="5"></head></html>`),
			want:    nil,
			wantErr: nil,
		},
		{
			name:    "when_page_contains_mixed_case_unsupported_prefixes_and_tel_skips_them_and_keeps_valid_links",
			rootURL: "http://a.com/d/index.html",
			body:    []byte(`<html><body><a href="tel:+1-555-0100">Call</a><a href="JAVASCRIPT:alert('#%zz')">Click</a><a href="Mailto:ops@a.com">Email</a><img src="DATA:image/gif;base64,R0lGODlhAQABAAAAACw="><a href="valid.html">Valid</a></body></html>`),
			want: []string{
				"http://a.com/d/valid.html",
			},
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
			name:    "when_node_is_empty_query_delimiter_returns_root_url_without_query",
			rootURL: "http://domain.com/test",
			nodeURL: "?",
			want:    "http://domain.com/test",
		},
		{
			name:    "when_node_is_relative_path_with_query_strips_query",
			rootURL: "http://domain.com/sub/",
			nodeURL: "red/red.min.js?v=2.2.3",
			want:    "http://domain.com/sub/red/red.min.js",
		},
		{
			name:    "when_node_is_absolute_path_with_query_strips_query",
			rootURL: "http://domain.com/sub/",
			nodeURL: "/assets/index.js?v=1.2.3",
			want:    "http://domain.com/assets/index.js",
		},
		{
			name:    "when_root_has_query_and_node_is_empty_drops_root_query",
			rootURL: "http://domain.com/sub/page.html?old=1",
			nodeURL: "",
			want:    "http://domain.com/sub/page.html",
		},
		{
			name:    "when_root_has_query_and_node_is_relative_path_drops_root_query",
			rootURL: "http://domain.com/sub/page.html?old=1",
			nodeURL: "next.html",
			want:    "http://domain.com/sub/next.html",
		},
		{
			name:    "when_node_is_relative_path_with_percent_encoding_avoids_double_encoding",
			rootURL: "http://domain.com/dir/",
			nodeURL: "my%20file.js",
			want:    "http://domain.com/dir/my%20file.js",
		},
		{
			name:    "when_node_is_relative_path_with_query_and_fragment_strips_both",
			rootURL: "http://domain.com/dir/",
			nodeURL: "page.html?v=1#section",
			want:    "http://domain.com/dir/page.html",
		},
		{
			name:    "when_node_is_absolute_url_with_query_and_fragment_strips_both",
			rootURL: "http://domain.com/",
			nodeURL: "https://other.com/page?q=1#section",
			want:    "https://other.com/page",
		},
		{
			name:    "when_node_has_dot_segments_resolves_parent_dir",
			rootURL: "http://domain.com/a/b/index.html",
			nodeURL: "../c.js?v=1",
			want:    "http://domain.com/a/c.js",
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
			name:    "when_node_is_protocol_relative_other_domain_returns_other_domain_url",
			rootURL: "https://domain.com/dir/",
			nodeURL: "//cdn.other.com/app.js?v=1",
			want:    "https://cdn.other.com/app.js",
		},
		{
			name:    "when_node_has_different_protocol_returns_error",
			rootURL: "http://domain.com/",
			nodeURL: "ftp://domain.com/a",
			wantErr: ErrUnsupportedScheme,
		},
		{
			name:    "when_node_is_javascript_returns_nothing",
			rootURL: "http://domain.com/",
			nodeURL: "javascript:alert('hello')",
			wantErr: nil,
			want:    "",
		},
		{
			name:    "when_node_is_mailto_returns_nothing",
			rootURL: "http://domain.com/",
			nodeURL: "mailto:someone@domain.com",
			wantErr: nil,
			want:    "",
		},
		{
			name:    "when_node_is_data_url_returns_nothing",
			rootURL: "http://domain.com/",
			nodeURL: "data:text/plain;base64,SGVsbG8sIFdvcmxkIQ==",
			wantErr: nil,
			want:    "",
		},
		{
			name:    "when_node_has_whitespace_returns_trimmed_url",
			rootURL: "http://domain.com/",
			nodeURL: "  http://domain.com/a \n",
			want:    "http://domain.com/a",
		},
		{
			name:    "when_node_is_javascript_with_leading_whitespace_returns_nothing",
			rootURL: "http://domain.com/",
			nodeURL: "  javascript:alert('hello')",
			wantErr: nil,
			want:    "",
		},
		{
			name:    "when_node_is_tel_returns_nothing",
			rootURL: "http://domain.com/",
			nodeURL: "tel:+1-555-0100",
		},
		{
			name:    "when_node_is_bare_uppercase_tel_prefix_returns_nothing",
			rootURL: "http://domain.com/",
			nodeURL: "TEL:",
		},
		{
			name:    "when_node_is_uppercase_javascript_with_invalid_escape_returns_nothing",
			rootURL: "http://domain.com/",
			nodeURL: "JAVASCRIPT:alert('#%zz')",
		},
		{
			name:    "when_node_is_shorter_than_unsupported_prefix_resolves_relative_url",
			rootURL: "http://domain.com/",
			nodeURL: "tel",
			want:    "http://domain.com/tel",
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
