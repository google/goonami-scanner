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
	"testing"
)

func TestResponseHashesCaching(t *testing.T) {
	tests := []struct {
		name string
		body []byte
	}{
		{
			name: "when_called_twice_returns_cached_hashes",
			body: []byte("test body"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := &http.Response{StatusCode: 200, Header: http.Header{}}
			rh := &responseHashes{}

			m3First, err := rh.murmur3Hash(resp, tc.body)
			if err != nil {
				t.Fatalf("murmur3Hash() unexpected error: %v", err)
			}
			m3Second, err := rh.murmur3Hash(resp, tc.body)
			if err != nil {
				t.Fatalf("murmur3Hash() unexpected error: %v", err)
			}
			if m3First != m3Second || !rh.murmur3Computed {
				t.Errorf("murmur3Hash() = (%q, %q), murmer3Computed = %v; want identical cached values", m3First, m3Second, rh.murmur3Computed)
			}

			sha1 := rh.sha256Hash(tc.body)
			sha2 := rh.sha256Hash(tc.body)
			if sha1 != sha2 || !rh.sha256Computed {
				t.Errorf("sha256Hash() = (%q, %q), sha256Computed = %v; want identical cached values", sha1, sha2, rh.sha256Computed)
			}
		})
	}
}
