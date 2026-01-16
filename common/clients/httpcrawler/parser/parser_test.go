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
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestExtractFromHTML(t *testing.T) {
	tests := []struct {
		name      string
		rootURL   string
		body      []byte
		testFile  string
		want      []string
		wantError bool
	}{
		{
			name:     "all_link_attrs",
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
			wantError: false,
		},
		{
			name:      "page_with_malformed_url",
			rootURL:   "http://a.com/d/index.html",
			testFile:  "page_with_malformed_url.html",
			wantError: true,
		},
		{
			name:      "empty_content_does_nothing",
			rootURL:   "http://a.com/d/index.html",
			body:      nil,
			wantError: false,
		},
		{
			name:      "invalid_root_url",
			rootURL:   "http://%40invalid.com/",
			testFile:  "all_link_attrs.html",
			wantError: true,
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
			if tc.wantError {
				if err == nil {
					t.Errorf("extractFromHTML() returned no error, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("extractFromHTML() returned an unexpected error: %v", err)
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
		name      string
		rootURL   string
		nodeURL   string
		want      string
		wantError bool
	}{
		{
			name:    "relative_path_from_root",
			rootURL: "http://something.lan:8080",
			nodeURL: "/google",
			want:    "http://something.lan:8080/google",
		},
		{
			name:    "relative_path_from_file",
			rootURL: "http://something.lan:8080/test.html",
			nodeURL: "/google",
			want:    "http://something.lan:8080/google",
		},
		{
			name:    "relative_path_from_dir",
			rootURL: "http://something.lan:8080/test/",
			nodeURL: "google/",
			want:    "http://something.lan:8080/test/google/",
		},
		{
			name:    "relative_path_from_html_file_path",
			rootURL: "http://something.lan:8080/test.html",
			nodeURL: "google/",
			want:    "http://something.lan:8080/google/",
		},
		{
			name:    "absolute_path",
			rootURL: "http://something.lan:8080/test/",
			nodeURL: "/google",
			want:    "http://something.lan:8080/google",
		},
		{
			name:    "other_domain",
			rootURL: "http://something.lan:8080/test.html",
			nodeURL: "http://somethingelse.lan:8080/othertest.html",
			want:    "http://somethingelse.lan:8080/othertest.html",
		},
		{
			name:    "ipv4",
			rootURL: "http://1.2.3.4/",
			nodeURL: "a",
			want:    "http://1.2.3.4/a",
		},
		{
			name:    "ipv4_with_port",
			rootURL: "http://1.2.3.4:8080/",
			nodeURL: "a",
			want:    "http://1.2.3.4:8080/a",
		},
		{
			name:    "domain",
			rootURL: "http://domain.com/",
			nodeURL: "a",
			want:    "http://domain.com/a",
		},
		{
			name:    "domain_with_port",
			rootURL: "http://domain.com:1234/",
			nodeURL: "a",
			want:    "http://domain.com:1234/a",
		},
		{
			name:    "ipv6",
			rootURL: "http://[::1]/",
			nodeURL: "a",
			want:    "http://[::1]/a",
		},
		{
			name:    "ipv6_with_port",
			rootURL: "http://[::1]:8080/",
			nodeURL: "a",
			want:    "http://[::1]:8080/a",
		},
		{
			name:    "empty_node",
			rootURL: "http://domain.com/test",
			nodeURL: "",
			want:    "http://domain.com/test",
		},
		{
			name:    "fragment_only_node",
			rootURL: "http://domain.com/test",
			nodeURL: "#frag",
			want:    "http://domain.com/test",
		},
		{
			name:    "query_only_node",
			rootURL: "http://domain.com/test",
			nodeURL: "?q=1",
			want:    "http://domain.com/test",
		},
		{
			name:    "protocol_relative_url_http",
			rootURL: "http://domain.com/",
			nodeURL: "//domain.com/something",
			want:    "http://domain.com/something",
		},
		{
			name:    "protocol_relative_url_https",
			rootURL: "https://domain.com/",
			nodeURL: "//domain.com/something",
			want:    "https://domain.com/something",
		},
		{
			name:      "different_protocol",
			rootURL:   "http://domain.com/",
			nodeURL:   "ftp://domain.com/a",
			wantError: true,
		},
		{
			name:      "javascript_content",
			rootURL:   "http://domain.com/",
			nodeURL:   "javascript:alert('Evil XSS')",
			wantError: true,
		},
		{
			name:      "mailto_protocol",
			rootURL:   "http://domain.com/",
			nodeURL:   "mailto:someone@domain.com",
			wantError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseURL(tc.rootURL, tc.nodeURL)
			if tc.wantError {
				if err == nil {
					t.Errorf("parseURL(%q, %q) returned no error, want error", tc.rootURL, tc.nodeURL)
				}
				return
			}

			if got != tc.want {
				t.Errorf("parseURL(%q, %q) = %q, want: %q", tc.rootURL, tc.nodeURL, got, tc.want)
			}
		})
	}
}
