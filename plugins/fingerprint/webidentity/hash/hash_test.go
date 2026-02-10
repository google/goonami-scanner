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

package hash

import (
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestFromResponse(t *testing.T) {
	tests := []struct {
		name        string
		statusCode  int
		contentType string
		content     []byte
		want        string
	}{
		{
			name:        "when_response_is_a_sample_react_app_returns_correct_hash",
			statusCode:  200,
			contentType: "application/json",
			content: []byte(`{
  "short_name": "React App",
  "name": "Create React App Sample",
  "icons": [
    {
      "src": "favicon.ico",
      "sizes": "64x64 32x32 24x24 16x16",
      "type": "image/x-icon"
    }
  ],
  "start_url": "./index.html",
  "display": "standalone",
  "theme_color": "#000000",
  "background_color": "#ffffff"
}
`),
			want: "62086d24223bfd1b6f9ee96e2fe508bc",
		},
		{
			name:        "when_response_is_empty_returns_correct_hash",
			statusCode:  404,
			contentType: "text/html",
			content:     []byte{},
			want:        "edff0a01352073577a892743b8b74411",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := &http.Response{
				StatusCode: tc.statusCode,
				Header:     http.Header{"Content-Type": []string{tc.contentType}},
			}

			hash, err := FromResponse(resp, tc.content)
			if err != nil {
				t.Fatalf("FromResponse(...) returned an unexpected error: %v", err)
			}

			if got := hash.Hex(); got != tc.want {
				t.Errorf("FromResponse(...) = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestNew(t *testing.T) {
	resp := &http.Response{
		StatusCode: 404,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
	}
	h := New(resp)

	want := "edff0a01352073577a892743b8b74411"
	if got := h.Hex(); got != want {
		t.Errorf("New(resp).Update([]byte{}) returned %q, want %q", got, want)
	}
}

func TestUpdate(t *testing.T) {
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
	}
	content := []byte(`{
  "short_name": "React App",
  "name": "Create React App Sample",
  "icons": [
    {
      "src": "favicon.ico",
      "sizes": "64x64 32x32 24x24 16x16",
      "type": "image/x-icon"
    }
  ],
  "start_url": "./index.html",
  "display": "standalone",
  "theme_color": "#000000",
  "background_color": "#ffffff"
}
`)
	h := New(resp)
	if err := h.Update(content); err != nil {
		t.Fatalf("Update returned unexpected error: %v", err)
	}

	want := "62086d24223bfd1b6f9ee96e2fe508bc"
	if got := h.Hex(); got != want {
		t.Errorf("New(resp).Update(content) returned %q, want %q", got, want)
	}
}

func TestIntersectVersions(t *testing.T) {
	tests := []struct {
		name         string
		id           *Identity
		newMatch     *Identity
		wantVersions []string
	}{
		{
			name: "when_new_match_is_nil_it_returns_no_change",
			id: &Identity{
				Software: "sw",
				Versions: []string{"1", "2"},
			},
			newMatch:     nil,
			wantVersions: []string{"1", "2"},
		},
		{
			name: "when_software_names_differ_it_returns_no_change",
			id: &Identity{
				Software: "sw",
				Versions: []string{"1", "2"},
			},
			newMatch: &Identity{
				Software: "othersw",
				Versions: []string{"1"},
			},
			wantVersions: []string{"1", "2"},
		},
		{
			name: "when_versions_do_not_intersect_it_returns_no_change",
			id: &Identity{
				Software: "sw",
				Versions: []string{"1", "2"},
			},
			newMatch: &Identity{
				Software: "sw",
				Versions: []string{"3", "4"},
			},
			wantVersions: []string{"1", "2"},
		},
		{
			name: "when_versions_intersect_it_returns_the_intersection",
			id: &Identity{
				Software: "sw",
				Versions: []string{"1", "2", "3"},
			},
			newMatch: &Identity{
				Software: "sw",
				Versions: []string{"2", "3", "4"},
			},
			wantVersions: []string{"2", "3"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.id.IntersectVersions(tc.newMatch)
			if diff := cmp.Diff(tc.wantVersions, tc.id.Versions, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("IntersectVersions(%v) resulted in unexpected Versions (-want +got):\n%s", tc.newMatch, diff)
			}
		})
	}
}
