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
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	fpb "github.com/google/goonami-scanner/plugins/fingerprint/webidentity/fingerprint_go_proto"
	"github.com/google/goonami-scanner/plugins/fingerprint/webidentity/hash"
)

func headerCondition(name, contains, re string) *fpb.HttpResponse_Expectation {
	return fpb.HttpResponse_Expectation_builder{
		Header:   fpb.HttpResponse_Header_builder{Name: name}.Build(),
		Contains: contains,
		Regexp:   re,
	}.Build()
}

func bodyCondition(contains, re string) *fpb.HttpResponse_Expectation {
	return fpb.HttpResponse_Expectation_builder{
		Body:     &fpb.HttpResponse_Body{},
		Contains: contains,
		Regexp:   re,
	}.Build()
}

func hashCondition(m3, sha []string) *fpb.HttpResponse_Expectation {
	return fpb.HttpResponse_Expectation_builder{
		Hash: fpb.HttpResponse_Hash_builder{
			Murmur3Hashes:    m3,
			BodySha256Hashes: sha,
		}.Build(),
	}.Build()
}

func TestCompiledHeaderConditionMatches(t *testing.T) {
	tests := []struct {
		name      string
		condition *fpb.HttpResponse_Expectation
		header    http.Header
		wantMatch bool
	}{
		{
			name:      "when_header_exists_matches",
			condition: headerCondition("Server", "", ""),
			header:    http.Header{"Server": []string{"nginx/1.2.3"}},
			wantMatch: true,
		},
		{
			name:      "when_header_case_insensitive_matches",
			condition: headerCondition("server", "", ""),
			header:    http.Header{"Server": []string{"nginx"}},
			wantMatch: true,
		},
		{
			name:      "when_header_missing_does_not_match",
			condition: headerCondition("X-Custom", "", ""),
			header:    http.Header{"Server": []string{"nginx"}},
			wantMatch: false,
		},
		{
			name:      "when_header_contains_substring_matches",
			condition: headerCondition("Content-Type", "application/json", ""),
			header:    http.Header{"Content-Type": []string{"application/json; charset=utf-8"}},
			wantMatch: true,
		},
		{
			name:      "when_header_does_not_contain_substring_does_not_match",
			condition: headerCondition("Content-Type", "application/xml", ""),
			header:    http.Header{"Content-Type": []string{"text/html"}},
			wantMatch: false,
		},
		{
			name:      "when_header_matches_regexp_matches",
			condition: headerCondition("Server", "", "^nginx/[0-9.]+$"),
			header:    http.Header{"Server": []string{"nginx/1.25.1"}},
			wantMatch: true,
		},
		{
			name:      "when_header_does_not_match_regexp_does_not_match",
			condition: headerCondition("Server", "", "^Apache/.*"),
			header:    http.Header{"Server": []string{"nginx/1.25.1"}},
			wantMatch: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cc, err := compileCondition(tc.condition)
			if err != nil {
				t.Fatalf("compileCondition() unexpected error: %v", err)
			}
			resp := &http.Response{Header: tc.header}
			matched, err := cc.matches(resp, nil, &responseHashes{})
			if err != nil {
				t.Fatalf("cc.matches() unexpected error: %v", err)
			}
			if matched != tc.wantMatch {
				t.Errorf("cc.matches() = %v, want %v", matched, tc.wantMatch)
			}
		})
	}
}

func TestCompiledBodyConditionMatches(t *testing.T) {
	body := []byte("<html><head><title>Grafana</title></head><body>window.grafanaBootData = {}</body></html>")

	tests := []struct {
		name      string
		condition *fpb.HttpResponse_Expectation
		wantMatch bool
	}{
		{
			name:      "when_body_contains_string_matches",
			condition: bodyCondition("grafanaBootData", ""),
			wantMatch: true,
		},
		{
			name:      "when_body_does_not_contain_string_does_not_match",
			condition: bodyCondition("WordPress", ""),
			wantMatch: false,
		},
		{
			name:      "when_body_matches_regexp_matches",
			condition: bodyCondition("", "<title>\\s*Grafana\\s*</title>"),
			wantMatch: true,
		},
		{
			name:      "when_body_does_not_match_regexp_does_not_match",
			condition: bodyCondition("", "PHP/[0-9.]+"),
			wantMatch: false,
		},
		{
			name:      "when_both_contains_and_regexp_match_matches",
			condition: bodyCondition("Grafana", "<title>Grafana</title>"),
			wantMatch: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cc, err := compileCondition(tc.condition)
			if err != nil {
				t.Fatalf("compileCondition() unexpected error: %v", err)
			}
			resp := &http.Response{}
			matched, err := cc.matches(resp, body, &responseHashes{})
			if err != nil {
				t.Fatalf("cc.matches() unexpected error: %v", err)
			}
			if matched != tc.wantMatch {
				t.Errorf("cc.matches() = %v, want %v", matched, tc.wantMatch)
			}
		})
	}
}

func TestCompiledHashConditionMatches(t *testing.T) {
	body := []byte("favicon-content")
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"image/x-icon"}},
	}
	m3Hash, err := hash.FromResponse(resp, body)
	if err != nil {
		t.Fatalf("hash.FromResponse() unexpected error: %v", err)
	}
	shaSum := sha256.Sum256(body)
	shaHash := hex.EncodeToString(shaSum[:])

	tests := []struct {
		name      string
		condition *fpb.HttpResponse_Expectation
		wantMatch bool
	}{
		{
			name:      "when_murmur3_matches_returns_true",
			condition: hashCondition([]string{m3Hash.Hex()}, nil),
			wantMatch: true,
		},
		{
			name:      "when_murmur3_differs_returns_false",
			condition: hashCondition([]string{"deadbeef"}, nil),
			wantMatch: false,
		},
		{
			name:      "when_sha256_matches_returns_true",
			condition: hashCondition(nil, []string{shaHash}),
			wantMatch: true,
		},
		{
			name:      "when_sha256_differs_returns_false",
			condition: hashCondition(nil, []string{"abcdef123456"}),
			wantMatch: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cc, err := compileCondition(tc.condition)
			if err != nil {
				t.Fatalf("compileCondition() unexpected error: %v", err)
			}
			matched, err := cc.matches(resp, body, &responseHashes{})
			if err != nil {
				t.Fatalf("cc.matches() unexpected error: %v", err)
			}
			if matched != tc.wantMatch {
				t.Errorf("cc.matches() = %v, want %v", matched, tc.wantMatch)
			}
		})
	}
}

func TestCompileConditionsErrors(t *testing.T) {
	tests := []struct {
		name      string
		condition *fpb.HttpResponse_Expectation
		wantErr   bool
	}{
		{
			name:      "when_header_regexp_invalid_returns_error",
			condition: headerCondition("Server", "", "[invalid"),
			wantErr:   true,
		},
		{
			name:      "when_body_regexp_invalid_returns_error",
			condition: bodyCondition("", "(unclosed"),
			wantErr:   true,
		},
		{
			name:      "when_condition_is_valid_succeeds",
			condition: bodyCondition("ok", ""),
			wantErr:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := compileConditions([]*fpb.HttpResponse_Expectation{tc.condition})
			if (err != nil) != tc.wantErr {
				t.Errorf("compileConditions() error = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}

func TestHeaderValues(t *testing.T) {
	h := http.Header{
		"Content-Type": []string{"application/json"},
		"X-Custom-Hdr": []string{"val1", "val2"},
	}

	tests := []struct {
		name   string
		header http.Header
		key    string
		want   []string
	}{
		{
			name:   "when_lowercase_key_matches_canonical_header_returns_values",
			header: h,
			key:    "content-type",
			want:   []string{"application/json"},
		},
		{
			name:   "when_uppercase_key_matches_header_returns_values",
			header: h,
			key:    "X-CUSTOM-HDR",
			want:   []string{"val1", "val2"},
		},
		{
			name:   "when_header_does_not_exist_returns_nil",
			header: h,
			key:    "Non-Existent",
			want:   nil,
		},
		{
			name:   "when_header_map_is_nil_returns_nil",
			header: nil,
			key:    "Content-Type",
			want:   nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := headerValues(tc.header, tc.key)
			if diff := cmp.Diff(tc.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("headerValues(%q) diff (-want +got):\n%s", tc.key, diff)
			}
		})
	}
}
