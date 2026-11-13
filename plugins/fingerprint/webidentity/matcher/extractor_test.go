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
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"regexp"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/goonami-scanner/plugins/fingerprint/webidentity/hash"
)

func TestCompiledVersionExtractorExtract(t *testing.T) {
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Server":       []string{"nginx/1.25.1"},
			"Content-Type": []string{"text/html"},
		},
	}
	body := []byte("<html><body>Grafana v10.4.1 (commit: abc1234)</body></html>")

	m3Hash, err := hash.FromResponse(resp, body)
	if err != nil {
		t.Fatalf("hash.FromResponse() unexpected error: %v", err)
	}
	shaSum := sha256.Sum256(body)
	shaHash := hex.EncodeToString(shaSum[:])

	tests := []struct {
		name      string
		extractor *compiledVersionExtractor
		want      []string
	}{
		{
			name: "when_header_regex_matches_with_subgroup_returns_version",
			extractor: &compiledVersionExtractor{
				fromHeader: "Server",
				re:         regexp.MustCompile(`nginx/([0-9.]+)`),
			},
			want: []string{"1.25.1"},
		},
		{
			name: "when_header_regex_matches_without_subgroup_returns_full_match",
			extractor: &compiledVersionExtractor{
				fromHeader: "Server",
				re:         regexp.MustCompile(`1\.[0-9.]+`),
			},
			want: []string{"1.25.1"},
		},
		{
			name: "when_body_regex_matches_returns_captured_version",
			extractor: &compiledVersionExtractor{
				re: regexp.MustCompile(`Grafana v([0-9.]+)`),
			},
			want: []string{"10.4.1"},
		},
		{
			name: "when_regex_does_not_match_returns_nil",
			extractor: &compiledVersionExtractor{
				re: regexp.MustCompile(`Apache/([0-9.]+)`),
			},
			want: nil,
		},
		{
			name: "when_murmur3_matches_returns_static_versions",
			extractor: &compiledVersionExtractor{
				murmur3Hash:    m3Hash.Hex(),
				staticVersions: []string{"10.4.1", "10.4.2"},
			},
			want: []string{"10.4.1", "10.4.2"},
		},
		{
			name: "when_murmur3_differs_returns_nil",
			extractor: &compiledVersionExtractor{
				murmur3Hash:    "deadbeef",
				staticVersions: []string{"1.0"},
			},
			want: nil,
		},
		{
			name: "when_sha256_matches_returns_static_versions",
			extractor: &compiledVersionExtractor{
				bodySHA256Hash: shaHash,
				staticVersions: []string{"10.4.1"},
			},
			want: []string{"10.4.1"},
		},
		{
			name: "when_sha256_differs_returns_nil",
			extractor: &compiledVersionExtractor{
				bodySHA256Hash: "abcdef",
				staticVersions: []string{"1.0"},
			},
			want: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.extractor.extract(resp, body, &responseHashes{})
			if err != nil {
				t.Fatalf("extract() unexpected error: %v", err)
			}
			if diff := cmp.Diff(tc.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("extract() diff (-want +got):\n%s", diff)
			}
		})
	}
}
