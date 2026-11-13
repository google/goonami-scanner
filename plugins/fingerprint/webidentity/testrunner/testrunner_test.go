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

package testrunner

import (
	"testing"

	"github.com/google/goonami-scanner/plugins/fingerprint/webidentity/engine"
	fpb "github.com/google/goonami-scanner/plugins/fingerprint/webidentity/fingerprint_go_proto"
	ftpb "github.com/google/goonami-scanner/plugins/fingerprint/webidentity/fingerprint_test_go_proto"
	"google.golang.org/protobuf/proto"
)

func TestRunTestCase(t *testing.T) {
	fpProto := fpb.WebFingerprint_builder{
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
								Contains: "database",
							}.Build(),
						},
					}.Build(),
					VersionExtractors: []*fpb.VersionExtractor{
						fpb.VersionExtractor_builder{
							FromBody: &fpb.HttpResponse_Body{},
							Regexp:   `version:"([0-9.]+)"`,
						}.Build(),
					},
				}.Build(),
			}.Build(),
			fpb.Step_builder{
				Name:       "login",
				PathSuffix: proto.String("/login"),
				Response: fpb.HttpResponse_builder{
					StatusCodes: []int32{200},
					ExpectAll: fpb.HttpResponse_ExpectAll_builder{
						Conditions: []*fpb.HttpResponse_Expectation{
							fpb.HttpResponse_Expectation_builder{
								Body:     &fpb.HttpResponse_Body{},
								Contains: "grafana-app",
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
			fpb.Workflow_builder{Steps: []string{"login"}}.Build(),
		},
	}.Build()

	fp, err := engine.CompileFingerprint(fpProto)
	if err != nil {
		t.Fatalf("engine.CompileFingerprint() unexpected error: %v", err)
	}

	tests := []struct {
		name     string
		testFp   *engine.CompiledFingerprint
		testCase *ftpb.WebFingerprintTests_TestCase
		wantErr  bool
	}{
		{
			name:     "when_fingerprint_is_nil_returns_error",
			testCase: ftpb.WebFingerprintTests_TestCase_builder{Name: "dummy"}.Build(),
			wantErr:  true,
		},
		{
			name:    "when_test_case_is_nil_returns_error",
			testFp:  fp,
			wantErr: true,
		},
		{
			name:   "when_expected_detection_matches_succeeds",
			testFp: fp,
			testCase: ftpb.WebFingerprintTests_TestCase_builder{
				Name: "grafana_root",
				MockResponses: []*ftpb.WebFingerprintTests_MockResponse{
					ftpb.WebFingerprintTests_MockResponse_builder{
						Uri:        "/api/health",
						StatusCode: 200,
						Body:       `{"database":"ok", version:"9.2.1"}`,
					}.Build(),
				},
				ExpectedMatches: []*ftpb.WebFingerprintTests_ExpectedMatch{
					ftpb.WebFingerprintTests_ExpectedMatch_builder{
						ExpectedVersions: []string{"9.2.1"},
					}.Build(),
				},
			}.Build(),
		},
		{
			name:   "when_expected_subpath_matches_succeeds",
			testFp: fp,
			testCase: ftpb.WebFingerprintTests_TestCase_builder{
				Name: "grafana_subpath",
				MockResponses: []*ftpb.WebFingerprintTests_MockResponse{
					ftpb.WebFingerprintTests_MockResponse_builder{
						Uri:        "/grafana/login",
						StatusCode: 200,
						Body:       `<html>grafana-app v8.3.4</html>`,
					}.Build(),
				},
				ExpectedMatches: []*ftpb.WebFingerprintTests_ExpectedMatch{
					ftpb.WebFingerprintTests_ExpectedMatch_builder{
						ApplicationRootPath: "/grafana",
						ExpectedVersions:    []string{"8.3.4"},
					}.Build(),
				},
			}.Build(),
		},
		{
			name:   "when_expected_no_detection_and_none_found_succeeds",
			testFp: fp,
			testCase: ftpb.WebFingerprintTests_TestCase_builder{
				Name: "no_match",
				MockResponses: []*ftpb.WebFingerprintTests_MockResponse{
					ftpb.WebFingerprintTests_MockResponse_builder{
						Uri:        "/other",
						StatusCode: 200,
						Body:       "plain content",
					}.Build(),
				},
			}.Build(),
		},
		{
			name:   "when_expected_detection_missing_returns_error",
			testFp: fp,
			testCase: ftpb.WebFingerprintTests_TestCase_builder{
				Name: "missing_detection",
				MockResponses: []*ftpb.WebFingerprintTests_MockResponse{
					ftpb.WebFingerprintTests_MockResponse_builder{
						Uri:        "/other",
						StatusCode: 200,
						Body:       "plain content",
					}.Build(),
				},
				ExpectedMatches: []*ftpb.WebFingerprintTests_ExpectedMatch{
					ftpb.WebFingerprintTests_ExpectedMatch_builder{
						ExpectedVersions: []string{"9.2.1"},
					}.Build(),
				},
			}.Build(),
			wantErr: true,
		},
		{
			name:   "when_root_path_mismatch_returns_error",
			testFp: fp,
			testCase: ftpb.WebFingerprintTests_TestCase_builder{
				Name: "root_mismatch",
				MockResponses: []*ftpb.WebFingerprintTests_MockResponse{
					ftpb.WebFingerprintTests_MockResponse_builder{
						Uri:        "/grafana/login",
						StatusCode: 200,
						Body:       `<html>grafana-app v8.3.4</html>`,
					}.Build(),
				},
				ExpectedMatches: []*ftpb.WebFingerprintTests_ExpectedMatch{
					ftpb.WebFingerprintTests_ExpectedMatch_builder{
						ApplicationRootPath: "/wrong_subpath",
						ExpectedVersions:    []string{"8.3.4"},
					}.Build(),
				},
			}.Build(),
			wantErr: true,
		},
		{
			name:   "when_expected_version_missing_returns_error",
			testFp: fp,
			testCase: ftpb.WebFingerprintTests_TestCase_builder{
				Name: "version_mismatch",
				MockResponses: []*ftpb.WebFingerprintTests_MockResponse{
					ftpb.WebFingerprintTests_MockResponse_builder{
						Uri:        "/api/health",
						StatusCode: 200,
						Body:       `{"database":"ok", version:"9.2.1"}`,
					}.Build(),
				},
				ExpectedMatches: []*ftpb.WebFingerprintTests_ExpectedMatch{
					ftpb.WebFingerprintTests_ExpectedMatch_builder{
						ExpectedVersions: []string{"10.0.0"},
					}.Build(),
				},
			}.Build(),
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := RunTestCase(t.Context(), tc.testFp, tc.testCase)
			if (err != nil) != tc.wantErr {
				t.Fatalf("RunTestCase() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestRunSuite(t *testing.T) {
	fp := fpb.WebFingerprint_builder{
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
								Contains: "database",
							}.Build(),
						},
					}.Build(),
					VersionExtractors: []*fpb.VersionExtractor{
						fpb.VersionExtractor_builder{
							FromBody: &fpb.HttpResponse_Body{},
							Regexp:   `version:"([0-9.]+)"`,
						}.Build(),
					},
				}.Build(),
			}.Build(),
		},
		Workflows: []*fpb.Workflow{
			fpb.Workflow_builder{Steps: []string{"health"}}.Build(),
		},
	}.Build()

	tests := []struct {
		name  string
		suite *ftpb.WebFingerprintTests
	}{
		{
			name: "when_suite_has_valid_cases_passes",
			suite: ftpb.WebFingerprintTests_builder{
				TestedFingerprint: "grafana",
				Tests: []*ftpb.WebFingerprintTests_TestCase{
					ftpb.WebFingerprintTests_TestCase_builder{
						Name: "valid_health",
						MockResponses: []*ftpb.WebFingerprintTests_MockResponse{
							ftpb.WebFingerprintTests_MockResponse_builder{
								Uri:        "/api/health",
								StatusCode: 200,
								Body:       `{"database":"ok", version:"9.2.1"}`,
							}.Build(),
						},
						ExpectedMatches: []*ftpb.WebFingerprintTests_ExpectedMatch{
							ftpb.WebFingerprintTests_ExpectedMatch_builder{
								ExpectedVersions: []string{"9.2.1"},
							}.Build(),
						},
					}.Build(),
				},
			}.Build(),
		},
		{
			name: "when_suite_is_disabled_skips_suite",
			suite: ftpb.WebFingerprintTests_builder{
				TestedFingerprint: "disabled_test",
				Disabled:          true,
			}.Build(),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			RunSuite(t, fp, tc.suite)
		})
	}
}
