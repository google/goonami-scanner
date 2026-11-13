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

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	fpb "github.com/google/goonami-scanner/plugins/fingerprint/webidentity/fingerprint_go_proto"
	"google.golang.org/protobuf/proto"
)

func TestCompileStep(t *testing.T) {
	tests := []struct {
		name    string
		step    *fpb.Step
		wantErr bool
	}{
		{
			name:    "when_step_is_nil_returns_error",
			step:    nil,
			wantErr: true,
		},
		{
			name: "when_step_missing_name_returns_error",
			step: fpb.Step_builder{
				Path: proto.String("/api/health"),
			}.Build(),
			wantErr: true,
		},
		{
			name: "when_path_regexp_invalid_returns_error",
			step: fpb.Step_builder{
				Name:       "step1",
				PathRegexp: proto.String("[invalid"),
			}.Build(),
			wantErr: true,
		},
		{
			name: "when_extraction_missing_variable_name_returns_error",
			step: fpb.Step_builder{
				Name: "step1",
				Response: fpb.HttpResponse_builder{
					ExtractAll: fpb.HttpResponse_ExtractAll_builder{
						Patterns: []*fpb.HttpResponse_Extract{
							fpb.HttpResponse_Extract_builder{
								Regexp: ".*",
							}.Build(),
						},
					}.Build(),
				}.Build(),
			}.Build(),
			wantErr: true,
		},
		{
			name: "when_extraction_missing_regexp_returns_error",
			step: fpb.Step_builder{
				Name: "step1",
				Response: fpb.HttpResponse_builder{
					ExtractAll: fpb.HttpResponse_ExtractAll_builder{
						Patterns: []*fpb.HttpResponse_Extract{
							fpb.HttpResponse_Extract_builder{
								VariableName: "var",
							}.Build(),
						},
					}.Build(),
				}.Build(),
			}.Build(),
			wantErr: true,
		},
		{
			name: "when_step_is_valid_succeeds",
			step: fpb.Step_builder{
				Name: "step1",
				Path: proto.String("/api/health"),
				Response: fpb.HttpResponse_builder{
					ExtractAll: fpb.HttpResponse_ExtractAll_builder{
						Patterns: []*fpb.HttpResponse_Extract{
							fpb.HttpResponse_Extract_builder{
								VariableName: "id",
								Regexp:       "([0-9]+)",
							}.Build(),
						},
					}.Build(),
				}.Build(),
			}.Build(),
			wantErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cs, err := CompileStep(tc.step)
			if (err != nil) != tc.wantErr {
				t.Errorf("CompileStep() error = %v, wantErr = %v", err, tc.wantErr)
			}
			if err == nil && cs == nil {
				t.Errorf("CompileStep() = nil, want non-nil")
			}
			if err == nil && cs.Name() != tc.step.GetName() {
				t.Errorf("cs.Name() = %q, want %q", cs.Name(), tc.step.GetName())
			}
		})
	}
}

func TestCompiledStepMatch(t *testing.T) {
	step := fpb.Step_builder{
		Name: "login_step",
		Path: proto.String("/login"),
		Response: fpb.HttpResponse_builder{
			StatusCodes: []int32{200},
			ExpectAll: fpb.HttpResponse_ExpectAll_builder{
				Conditions: []*fpb.HttpResponse_Expectation{
					fpb.HttpResponse_Expectation_builder{
						Body:     &fpb.HttpResponse_Body{},
						Contains: "login-form",
					}.Build(),
				},
			}.Build(),
			ExtractAll: fpb.HttpResponse_ExtractAll_builder{
				Patterns: []*fpb.HttpResponse_Extract{
					fpb.HttpResponse_Extract_builder{
						VariableName: "token",
						FromBody:     &fpb.HttpResponse_Body{},
						Regexp:       `csrf_token="([a-zA-Z0-9]+)"`,
					}.Build(),
				},
			}.Build(),
		}.Build(),
	}.Build()

	cs, err := CompileStep(step)
	if err != nil {
		t.Fatalf("CompileStep() unexpected error: %v", err)
	}

	resp := &http.Response{StatusCode: 200, Header: http.Header{}}

	tests := []struct {
		name        string
		body        []byte
		wantMatched bool
		wantVars    map[string]string
	}{
		{
			name:        "when_extract_all_matches_returns_matched_with_vars",
			body:        []byte(`<html><div class="login-form"><input csrf_token="abc123xyz" /></div></html>`),
			wantMatched: true,
			wantVars:    map[string]string{"token": "abc123xyz"},
		},
		{
			name:        "when_extract_all_fails_returns_not_matched",
			body:        []byte(`<html><div class="login-form">no token</div></html>`),
			wantMatched: false,
			wantVars:    nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, err := cs.Match(resp, tc.body)
			if err != nil {
				t.Fatalf("Match() unexpected error: %v", err)
			}
			if res.Matched != tc.wantMatched {
				t.Errorf("Match() matched = %v, want %v", res.Matched, tc.wantMatched)
			}
			if diff := cmp.Diff(tc.wantVars, res.ExtractedVars, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Match() ExtractedVars diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestCompiledStepMatchExtractAny(t *testing.T) {
	step := fpb.Step_builder{
		Name: "app_step",
		Path: proto.String("/app"),
		Response: fpb.HttpResponse_builder{
			StatusCodes: []int32{200},
			ExtractAny: fpb.HttpResponse_ExtractAny_builder{
				Patterns: []*fpb.HttpResponse_Extract{
					fpb.HttpResponse_Extract_builder{
						VariableName: "header_var",
						FromHeader:   fpb.HttpResponse_Header_builder{Name: "X-Missing"}.Build(),
						Regexp:       "(.*)",
					}.Build(),
					fpb.HttpResponse_Extract_builder{
						VariableName: "body_var",
						FromBody:     &fpb.HttpResponse_Body{},
						Regexp:       `session="([a-z]+)"`,
					}.Build(),
				},
			}.Build(),
		}.Build(),
	}.Build()

	cs, err := CompileStep(step)
	if err != nil {
		t.Fatalf("CompileStep() unexpected error: %v", err)
	}

	resp := &http.Response{StatusCode: 200, Header: http.Header{}}

	tests := []struct {
		name        string
		body        []byte
		wantMatched bool
		wantVars    map[string]string
	}{
		{
			name:        "when_one_extract_any_pattern_matches_returns_matched",
			body:        []byte(`<html><div session="abc"></div></html>`),
			wantMatched: true,
			wantVars:    map[string]string{"body_var": "abc"},
		},
		{
			name:        "when_all_extract_any_patterns_fail_returns_not_matched",
			body:        []byte(`<html><div>no session</div></html>`),
			wantMatched: false,
			wantVars:    nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, err := cs.Match(resp, tc.body)
			if err != nil {
				t.Fatalf("Match() unexpected error: %v", err)
			}
			if res.Matched != tc.wantMatched {
				t.Errorf("Match() matched = %v, want %v", res.Matched, tc.wantMatched)
			}
			if diff := cmp.Diff(tc.wantVars, res.ExtractedVars, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Match() ExtractedVars diff (-want +got):\n%s", diff)
			}
		})
	}
}
