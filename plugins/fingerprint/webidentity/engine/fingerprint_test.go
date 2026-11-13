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

package engine

import (
	"testing"

	fpb "github.com/google/goonami-scanner/plugins/fingerprint/webidentity/fingerprint_go_proto"
	"google.golang.org/protobuf/proto"
)

func TestCompileFingerprint(t *testing.T) {
	tests := []struct {
		name    string
		fp      *fpb.WebFingerprint
		wantErr bool
	}{
		{
			name:    "when_fingerprint_is_nil_returns_error",
			fp:      nil,
			wantErr: true,
		},
		{
			name:    "when_fingerprint_missing_info_returns_error",
			fp:      &fpb.WebFingerprint{},
			wantErr: true,
		},
		{
			name: "when_fingerprint_missing_software_returns_error",
			fp: fpb.WebFingerprint_builder{
				Info: fpb.FingerprintInfo_builder{Name: "Grafana"}.Build(),
			}.Build(),
			wantErr: true,
		},
		{
			name: "when_fingerprint_has_invalid_step_returns_error",
			fp: fpb.WebFingerprint_builder{
				Info: fpb.FingerprintInfo_builder{Name: "Bad", Software: "bad"}.Build(),
				Steps: []*fpb.Step{
					fpb.Step_builder{
						Name:       "bad_step",
						PathRegexp: proto.String("["),
					}.Build(),
				},
				Workflows: []*fpb.Workflow{
					fpb.Workflow_builder{Steps: []string{"bad_step"}}.Build(),
				},
			}.Build(),
			wantErr: true,
		},
		{
			name: "when_fingerprint_has_duplicate_step_name_returns_error",
			fp: fpb.WebFingerprint_builder{
				Info: fpb.FingerprintInfo_builder{Name: "Bad", Software: "bad"}.Build(),
				Steps: []*fpb.Step{
					fpb.Step_builder{
						Name: "dup_step",
						Path: proto.String("/a"),
						Response: fpb.HttpResponse_builder{
							StatusCodes: []int32{200},
						}.Build(),
					}.Build(),
					fpb.Step_builder{
						Name: "dup_step",
						Path: proto.String("/b"),
						Response: fpb.HttpResponse_builder{
							StatusCodes: []int32{200},
						}.Build(),
					}.Build(),
				},
				Workflows: []*fpb.Workflow{
					fpb.Workflow_builder{Steps: []string{"dup_step"}}.Build(),
				},
			}.Build(),
			wantErr: true,
		},
		{
			name: "when_fingerprint_workflow_references_unknown_step_returns_error",
			fp: fpb.WebFingerprint_builder{
				Info: fpb.FingerprintInfo_builder{Name: "Bad", Software: "bad"}.Build(),
				Steps: []*fpb.Step{
					fpb.Step_builder{
						Name: "step1",
						Path: proto.String("/a"),
						Response: fpb.HttpResponse_builder{
							StatusCodes: []int32{200},
						}.Build(),
					}.Build(),
				},
				Workflows: []*fpb.Workflow{
					fpb.Workflow_builder{Steps: []string{"step1", "missing_step"}}.Build(),
				},
			}.Build(),
			wantErr: true,
		},
		{
			name: "when_fingerprint_is_valid_compiles_successfully",
			fp: fpb.WebFingerprint_builder{
				Info: fpb.FingerprintInfo_builder{Name: "Grafana", Software: "grafana"}.Build(),
				Steps: []*fpb.Step{
					fpb.Step_builder{
						Name: "health",
						Path: proto.String("/api/health"),
						Response: fpb.HttpResponse_builder{
							StatusCodes: []int32{200},
							ExpectAll: fpb.HttpResponse_ExpectAll_builder{
								Conditions: []*fpb.HttpResponse_Expectation{
									fpb.HttpResponse_Expectation_builder{
										Body:     &fpb.HttpResponse_Body{},
										Contains: "ok",
									}.Build(),
								},
							}.Build(),
							VersionExtractors: []*fpb.VersionExtractor{
								fpb.VersionExtractor_builder{
									FromBody: &fpb.HttpResponse_Body{},
									Regexp:   `v([0-9.]+)`,
								}.Build(),
							},
						}.Build(),
					}.Build(),
				},
				Workflows: []*fpb.Workflow{
					fpb.Workflow_builder{Steps: []string{"health"}}.Build(),
				},
			}.Build(),
			wantErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cf, err := CompileFingerprint(tc.fp)
			if (err != nil) != tc.wantErr {
				t.Fatalf("CompileFingerprint() error = %v, wantErr %v", err, tc.wantErr)
			}
			if !tc.wantErr && cf == nil {
				t.Fatal("CompileFingerprint() = nil, want non-nil *CompiledFingerprint")
			}
		})
	}
}

func TestCompiledFingerprintGetters(t *testing.T) {
	fpProto := fpb.WebFingerprint_builder{
		Info: fpb.FingerprintInfo_builder{Name: "Grafana", Software: "grafana"}.Build(),
		Steps: []*fpb.Step{
			fpb.Step_builder{
				Name: "health",
				Path: proto.String("/api/health"),
				Response: fpb.HttpResponse_builder{
					StatusCodes: []int32{200},
				}.Build(),
			}.Build(),
		},
		Workflows: []*fpb.Workflow{
			fpb.Workflow_builder{Steps: []string{"health"}}.Build(),
		},
	}.Build()

	cf, err := CompileFingerprint(fpProto)
	if err != nil {
		t.Fatalf("CompileFingerprint() unexpected error: %v", err)
	}

	if got, want := cf.Name(), "Grafana"; got != want {
		t.Errorf("cf.Name() = %q, want %q", got, want)
	}
	if got, want := cf.Software(), "grafana"; got != want {
		t.Errorf("cf.Software() = %q, want %q", got, want)
	}
	if got, want := cf.Raw(), fpProto; got != want {
		t.Errorf("cf.Raw() = %v, want %v", got, want)
	}
}
