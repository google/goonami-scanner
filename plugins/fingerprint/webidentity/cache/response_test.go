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
	"io"
	"net/http"
	"net/url"
	"testing"
)

func TestCachedResponse(t *testing.T) {
	tests := []struct {
		name       string
		cached     *CachedResponse
		wantStatus int
		wantBody   string
	}{
		{
			name: "when_body_is_present_returns_independent_readable_responses",
			cached: &CachedResponse{
				StatusCode: 200,
				Status:     "200 OK",
				Header:     http.Header{"X-Custom": []string{"hello"}},
				Body:       []byte("cached data"),
				URL:        &url.URL{Path: "/test"},
				Method:     "GET",
			},
			wantStatus: 200,
			wantBody:   "cached data",
		},
		{
			name: "when_body_is_nil_returns_empty_readable_body",
			cached: &CachedResponse{
				StatusCode: 204,
				Status:     "204 No Content",
			},
			wantStatus: 204,
			wantBody:   "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for readIdx := range 2 {
				resp := tc.cached.Response()
				if resp.StatusCode != tc.wantStatus {
					t.Errorf("Response() read %d StatusCode = %d, want %d", readIdx, resp.StatusCode, tc.wantStatus)
				}
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatalf("Response() read %d ReadAll failed: %v", readIdx, err)
				}
				if got := string(body); got != tc.wantBody {
					t.Errorf("Response() read %d body = %q, want %q", readIdx, got, tc.wantBody)
				}
			}
		})
	}
}
