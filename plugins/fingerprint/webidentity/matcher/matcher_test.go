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
	"errors"
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	fpb "github.com/google/goonami-scanner/plugins/fingerprint/webidentity/fingerprint_go_proto"
)

func TestCompileResponseMatcher(t *testing.T) {
	tests := []struct {
		name     string
		response *fpb.HttpResponse
		wantErr  bool
	}{
		{
			name:     "when_response_is_nil_succeeds",
			response: nil,
			wantErr:  false,
		},
		{
			name: "when_expect_all_regexp_invalid_returns_error",
			response: fpb.HttpResponse_builder{
				ExpectAll: fpb.HttpResponse_ExpectAll_builder{
					Conditions: []*fpb.HttpResponse_Expectation{
						bodyCondition("", "["),
					},
				}.Build(),
			}.Build(),
			wantErr: true,
		},
		{
			name: "when_header_regexp_invalid_returns_error",
			response: fpb.HttpResponse_builder{
				ExpectAll: fpb.HttpResponse_ExpectAll_builder{
					Conditions: []*fpb.HttpResponse_Expectation{
						headerCondition("Server", "", "("),
					},
				}.Build(),
			}.Build(),
			wantErr: true,
		},
		{
			name: "when_expect_any_regexp_invalid_returns_error",
			response: fpb.HttpResponse_builder{
				ExpectAny: fpb.HttpResponse_ExpectAny_builder{
					Conditions: []*fpb.HttpResponse_Expectation{
						bodyCondition("", "+"),
					},
				}.Build(),
			}.Build(),
			wantErr: true,
		},
		{
			name: "when_expect_none_regexp_invalid_returns_error",
			response: fpb.HttpResponse_builder{
				ExpectNone: fpb.HttpResponse_ExpectNone_builder{
					Conditions: []*fpb.HttpResponse_Expectation{
						bodyCondition("", "*"),
					},
				}.Build(),
			}.Build(),
			wantErr: true,
		},
		{
			name: "when_version_extractor_regexp_invalid_returns_error",
			response: fpb.HttpResponse_builder{
				VersionExtractors: []*fpb.VersionExtractor{
					fpb.VersionExtractor_builder{
						FromBody: &fpb.HttpResponse_Body{},
						Regexp:   "[0-9",
					}.Build(),
				},
			}.Build(),
			wantErr: true,
		},
		{
			name: "when_all_conditions_valid_succeeds",
			response: fpb.HttpResponse_builder{
				StatusCodes: []int32{200, 302},
				ExpectAll: fpb.HttpResponse_ExpectAll_builder{
					Conditions: []*fpb.HttpResponse_Expectation{
						headerCondition("Content-Type", "application/json", ""),
					},
				}.Build(),
			}.Build(),
			wantErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			crm, err := CompileResponseMatcher(tc.response)
			if (err != nil) != tc.wantErr {
				t.Errorf("CompileResponseMatcher() error = %v, wantErr = %v", err, tc.wantErr)
			}
			if err == nil && crm == nil {
				t.Errorf("CompileResponseMatcher() = nil, want non-nil")
			}
		})
	}
}

func TestCompiledResponseMatcherMatch(t *testing.T) {
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
			"Server":       []string{"nginx/1.25.1"},
		},
	}
	body := []byte(`{"version": "1.25.1", "status": "ok"}`)

	tests := []struct {
		name         string
		response     *fpb.HttpResponse
		resp         *http.Response
		body         []byte
		wantMatched  bool
		wantVersions []string
		wantErr      error
	}{
		{
			name:        "when_resp_is_nil_returns_error",
			response:    &fpb.HttpResponse{},
			resp:        nil,
			body:        nil,
			wantMatched: false,
			wantErr:     ErrNilResponse,
		},
		{
			name: "when_status_code_matches_returns_matched",
			response: fpb.HttpResponse_builder{
				StatusCodes: []int32{200, 201},
				ExpectAll: fpb.HttpResponse_ExpectAll_builder{
					Conditions: []*fpb.HttpResponse_Expectation{
						bodyCondition("ok", ""),
					},
				}.Build(),
			}.Build(),
			resp:        resp,
			body:        body,
			wantMatched: true,
		},
		{
			name: "when_status_code_does_not_match_returns_not_matched",
			response: fpb.HttpResponse_builder{
				StatusCodes: []int32{404, 500},
				ExpectAll: fpb.HttpResponse_ExpectAll_builder{
					Conditions: []*fpb.HttpResponse_Expectation{
						bodyCondition("ok", ""),
					},
				}.Build(),
			}.Build(),
			resp:        resp,
			body:        body,
			wantMatched: false,
		},
		{
			name: "when_expect_all_conditions_match_returns_matched",
			response: fpb.HttpResponse_builder{
				StatusCodes: []int32{200},
				ExpectAll: fpb.HttpResponse_ExpectAll_builder{
					Conditions: []*fpb.HttpResponse_Expectation{
						headerCondition("Content-Type", "application/json", ""),
						bodyCondition("status", ""),
					},
				}.Build(),
			}.Build(),
			resp:        resp,
			body:        body,
			wantMatched: true,
		},
		{
			name: "when_one_expect_all_condition_fails_returns_not_matched",
			response: fpb.HttpResponse_builder{
				StatusCodes: []int32{200},
				ExpectAll: fpb.HttpResponse_ExpectAll_builder{
					Conditions: []*fpb.HttpResponse_Expectation{
						headerCondition("Content-Type", "application/json", ""),
						bodyCondition("WordPress", ""),
					},
				}.Build(),
			}.Build(),
			resp:        resp,
			body:        body,
			wantMatched: false,
		},
		{
			name: "when_expect_any_condition_matches_returns_matched",
			response: fpb.HttpResponse_builder{
				StatusCodes: []int32{200},
				ExpectAny: fpb.HttpResponse_ExpectAny_builder{
					Conditions: []*fpb.HttpResponse_Expectation{
						headerCondition("Server", "Apache", ""),
						headerCondition("Server", "nginx", ""),
					},
				}.Build(),
			}.Build(),
			resp:        resp,
			body:        body,
			wantMatched: true,
		},
		{
			name: "when_all_expect_any_conditions_fail_returns_not_matched",
			response: fpb.HttpResponse_builder{
				StatusCodes: []int32{200},
				ExpectAny: fpb.HttpResponse_ExpectAny_builder{
					Conditions: []*fpb.HttpResponse_Expectation{
						headerCondition("Server", "Apache", ""),
						headerCondition("Server", "Caddy", ""),
					},
				}.Build(),
			}.Build(),
			resp:        resp,
			body:        body,
			wantMatched: false,
		},
		{
			name: "when_expect_none_condition_matches_returns_not_matched",
			response: fpb.HttpResponse_builder{
				StatusCodes: []int32{200},
				ExpectNone: fpb.HttpResponse_ExpectNone_builder{
					Conditions: []*fpb.HttpResponse_Expectation{
						headerCondition("Server", "nginx", ""),
					},
				}.Build(),
			}.Build(),
			resp:        resp,
			body:        body,
			wantMatched: false,
		},
		{
			name: "when_version_extractor_matches_populates_versions",
			response: fpb.HttpResponse_builder{
				StatusCodes: []int32{200},
				ExpectAll: fpb.HttpResponse_ExpectAll_builder{
					Conditions: []*fpb.HttpResponse_Expectation{
						bodyCondition("version", ""),
					},
				}.Build(),
				VersionExtractors: []*fpb.VersionExtractor{
					fpb.VersionExtractor_builder{
						FromBody: &fpb.HttpResponse_Body{},
						Regexp:   `"version":\s*"([0-9.]+)"`,
					}.Build(),
				},
			}.Build(),
			resp:         resp,
			body:         body,
			wantMatched:  true,
			wantVersions: []string{"1.25.1"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			crm, err := CompileResponseMatcher(tc.response)
			if err != nil {
				t.Fatalf("CompileResponseMatcher() unexpected error: %v", err)
			}
			res, err := crm.Match(tc.resp, tc.body)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Match() error = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Match() unexpected error: %v", err)
			}
			if res.Matched != tc.wantMatched {
				t.Errorf("Match() matched = %v, want %v", res.Matched, tc.wantMatched)
			}
			if diff := cmp.Diff(tc.wantVersions, res.Versions, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Match() versions diff (-want +got):\n%s", diff)
			}
		})
	}
}
