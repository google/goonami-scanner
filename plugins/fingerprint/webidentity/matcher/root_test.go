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

package matcher

import (
	"regexp"
	"testing"
)

func TestInferRootFromSuffix(t *testing.T) {
	tests := []struct {
		name        string
		crawledPath string
		suffix      string
		wantRoot    string
		wantOK      bool
	}{
		{
			name:        "when_exact_match_at_root_returns_empty_root",
			crawledPath: "/login",
			suffix:      "/login",
			wantRoot:    "",
			wantOK:      true,
		},
		{
			name:        "when_subpath_matches_returns_subpath_root",
			crawledPath: "/grafana/login",
			suffix:      "/login",
			wantRoot:    "/grafana",
			wantOK:      true,
		},
		{
			name:        "when_nested_subpath_matches_returns_trimmed_root",
			crawledPath: "/apps/mon/grafana/login",
			suffix:      "/login",
			wantRoot:    "/apps/mon/grafana",
			wantOK:      true,
		},
		{
			name:        "when_suffix_does_not_match_returns_false",
			crawledPath: "/dashboard",
			suffix:      "/login",
			wantRoot:    "",
			wantOK:      false,
		},
		{
			name:        "when_suffix_is_empty_returns_false",
			crawledPath: "/login",
			suffix:      "",
			wantRoot:    "",
			wantOK:      false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotRoot, gotOK := InferRootFromSuffix(tc.crawledPath, tc.suffix)
			if gotOK != tc.wantOK {
				t.Fatalf("InferRootFromSuffix(%q, %q) ok = %v, want %v", tc.crawledPath, tc.suffix, gotOK, tc.wantOK)
			}
			if gotRoot != tc.wantRoot {
				t.Errorf("InferRootFromSuffix(%q, %q) root = %q, want %q", tc.crawledPath, tc.suffix, gotRoot, tc.wantRoot)
			}
		})
	}
}

func TestInferRootFromRegexp(t *testing.T) {
	tests := []struct {
		name        string
		crawledPath string
		re          *regexp.Regexp
		wantRoot    string
		wantOK      bool
	}{
		{
			name:        "when_named_root_group_present_extracts_named_root",
			crawledPath: "/grafana/public/build/app.1234.js",
			re:          regexp.MustCompile(`^(?P<root>.*?)/public/build/app\..*\.js$`),
			wantRoot:    "/grafana",
			wantOK:      true,
		},
		{
			name:        "when_no_named_group_uses_prefix_before_match",
			crawledPath: "/grafana/static/main.js",
			re:          regexp.MustCompile(`/static/.*\.js`),
			wantRoot:    "/grafana",
			wantOK:      true,
		},
		{
			name:        "when_regexp_does_not_match_returns_false",
			crawledPath: "/other/page",
			re:          regexp.MustCompile(`/static/.*\.js`),
			wantRoot:    "",
			wantOK:      false,
		},
		{
			name:        "when_regexp_is_nil_returns_false",
			crawledPath: "/page",
			re:          nil,
			wantRoot:    "",
			wantOK:      false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotRoot, gotOK := InferRootFromRegexp(tc.crawledPath, tc.re)
			if gotOK != tc.wantOK {
				t.Fatalf("InferRootFromRegexp(%q, %v) ok = %v, want %v", tc.crawledPath, tc.re, gotOK, tc.wantOK)
			}
			if gotRoot != tc.wantRoot {
				t.Errorf("InferRootFromRegexp(%q, %v) root = %q, want %q", tc.crawledPath, tc.re, gotRoot, tc.wantRoot)
			}
		})
	}
}
