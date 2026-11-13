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
	"net/http"
	"regexp"
	"testing"
)

func TestCompiledVariableExtractionExtract(t *testing.T) {
	resp := &http.Response{
		Header: http.Header{
			"Location": []string{"/app/dashboard/v2"},
		},
	}
	body := []byte(`<html><script src="/static/js/main.abc1234.chunk.js"></script></html>`)

	tests := []struct {
		name       string
		extraction *compiledVariableExtraction
		wantVal    string
		wantOK     bool
	}{
		{
			name: "when_header_matches_subgroup_returns_value",
			extraction: &compiledVariableExtraction{
				variableName: "app_id",
				fromHeader:   "Location",
				re:           regexp.MustCompile(`/app/(.*?)/`),
			},
			wantVal: "dashboard",
			wantOK:  true,
		},
		{
			name: "when_body_matches_subgroup_returns_value",
			extraction: &compiledVariableExtraction{
				variableName: "bundle_path",
				re:           regexp.MustCompile(`src="/?(static/js/main\.[a-z0-9]+\.chunk\.js)"`),
			},
			wantVal: "static/js/main.abc1234.chunk.js",
			wantOK:  true,
		},
		{
			name: "when_regex_does_not_match_returns_false",
			extraction: &compiledVariableExtraction{
				variableName: "missing",
				re:           regexp.MustCompile(`not-found-pattern`),
			},
			wantVal: "",
			wantOK:  false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotVal, gotOK := tc.extraction.extract(resp, body)
			if gotOK != tc.wantOK {
				t.Fatalf("extract() ok = %v, want %v", gotOK, tc.wantOK)
			}
			if gotVal != tc.wantVal {
				t.Errorf("extract() val = %q, want %q", gotVal, tc.wantVal)
			}
		})
	}
}
