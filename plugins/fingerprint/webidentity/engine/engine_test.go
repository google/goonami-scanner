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
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/goonami-scanner/core/log"
	"github.com/google/goonami-scanner/plugins/fingerprint/webidentity/cache"
	fpb "github.com/google/goonami-scanner/plugins/fingerprint/webidentity/fingerprint_go_proto"
	"google.golang.org/protobuf/proto"
)

func TestEnginePass1PassiveEvaluation(t *testing.T) {
	fpProto := fpb.WebFingerprint_builder{
		Info: fpb.FingerprintInfo_builder{Name: "Grafana", Software: "grafana"}.Build(),
		Steps: []*fpb.Step{
			fpb.Step_builder{
				Name:       "grafana_login",
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
			fpb.Step_builder{
				Name:       "grafana_bundle",
				PathRegexp: proto.String(`^(?P<root>.*?)/public/build/grafana\..*\.js$`),
				Response: fpb.HttpResponse_builder{
					StatusCodes: []int32{200},
					ExpectAll: fpb.HttpResponse_ExpectAll_builder{
						Conditions: []*fpb.HttpResponse_Expectation{
							fpb.HttpResponse_Expectation_builder{
								Body:     &fpb.HttpResponse_Body{},
								Contains: "Grafana",
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
				Name:       "grafana_icon",
				PathSuffix: proto.String("/public/img/icon.svg"),
				Response: fpb.HttpResponse_builder{
					StatusCodes: []int32{200},
					ExpectAll: fpb.HttpResponse_ExpectAll_builder{
						Conditions: []*fpb.HttpResponse_Expectation{
							fpb.HttpResponse_Expectation_builder{
								Body:     &fpb.HttpResponse_Body{},
								Contains: "<svg",
							}.Build(),
						},
					}.Build(),
				}.Build(),
			}.Build(),
			fpb.Step_builder{
				Name: "grafana_health",
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
				}.Build(),
			}.Build(),
		},
		Workflows: []*fpb.Workflow{
			fpb.Workflow_builder{Steps: []string{"grafana_login"}}.Build(),
			fpb.Workflow_builder{Steps: []string{"grafana_bundle"}}.Build(),
			fpb.Workflow_builder{Steps: []string{"grafana_icon", "grafana_health"}}.Build(),
		},
	}.Build()

	cf, err := CompileFingerprint(fpProto)
	if err != nil {
		t.Fatalf("CompileFingerprint() unexpected error: %v", err)
	}

	tests := []struct {
		name         string
		populate     func(c *cache.Cache)
		wantIdent    bool
		wantSoftware string
		wantRoot     string
		wantVersions []string
	}{
		{
			name: "when_cache_contains_matching_login_suffix_identifies_software_and_infers_root",
			populate: func(c *cache.Cache) {
				c.Put("GET", "http://host:8080/grafana/login", &http.Response{StatusCode: 200}, []byte("<html>grafana-app v8.3.4</html>"))
			},
			wantIdent:    true,
			wantSoftware: "grafana",
			wantRoot:     "/grafana",
			wantVersions: []string{"8.3.4"},
		},
		{
			name: "when_cache_contains_matching_regexp_infers_root",
			populate: func(c *cache.Cache) {
				c.Put("GET", "http://host:8080/sub/public/build/grafana.app.123.js", &http.Response{StatusCode: 200}, []byte("/* Grafana version:\"9.0.0\" */"))
			},
			wantIdent:    true,
			wantSoftware: "grafana",
			wantRoot:     "/sub",
			wantVersions: []string{"9.0.0"},
		},
		{
			name: "when_multi_step_workflow_has_only_first_step_in_cache_does_not_identify_in_pass1",
			populate: func(c *cache.Cache) {
				c.Put("GET", "http://host:8080/public/img/icon.svg", &http.Response{StatusCode: 200}, []byte("<svg></svg>"))
			},
			wantIdent: false,
		},
		{
			name: "when_multi_step_workflow_has_all_steps_in_cache_identifies_in_pass1",
			populate: func(c *cache.Cache) {
				c.Put("GET", "http://host:8080/public/img/icon.svg", &http.Response{StatusCode: 200}, []byte("<svg></svg>"))
				c.Put("GET", "http://host:8080/api/health", &http.Response{StatusCode: 200}, []byte("ok"))
			},
			wantIdent:    true,
			wantSoftware: "grafana",
			wantRoot:     "",
			wantVersions: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := cache.New(nil)
			tc.populate(c)
			eng := New([]*CompiledFingerprint{cf})
			states := eng.evaluatePass1(t.Context(), c, "http://host:8080")

			var foundState *matchState
			for _, s := range states {
				if s.software == tc.wantSoftware {
					foundState = s
					break
				}
			}

			if !tc.wantIdent {
				if foundState != nil && foundState.isIdentified() {
					t.Fatalf("evaluatePass1() state = %+v, want no identification", foundState)
				}
				return
			}

			if foundState == nil {
				t.Fatalf("evaluatePass1() state for software %q = nil, want non-nil", tc.wantSoftware)
			}
			if foundState.isIdentified() != tc.wantIdent {
				t.Errorf("foundState.isIdentified() = %v, want %v", foundState.isIdentified(), tc.wantIdent)
			}
			if foundState.rootPath != tc.wantRoot {
				t.Errorf("foundState.rootPath = %q, want %q", foundState.rootPath, tc.wantRoot)
			}
			if diff := cmp.Diff(tc.wantVersions, foundState.versions, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("foundState.versions diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestEnginePass2ActiveQueries(t *testing.T) {
	fpProto := fpb.WebFingerprint_builder{
		Info: fpb.FingerprintInfo_builder{Name: "Grafana", Software: "grafana"}.Build(),
		Steps: []*fpb.Step{
			fpb.Step_builder{
				Name:       "grafana_icon",
				PathSuffix: proto.String("/public/img/icon.svg"),
				Response: fpb.HttpResponse_builder{
					StatusCodes: []int32{200},
					ExpectAll: fpb.HttpResponse_ExpectAll_builder{
						Conditions: []*fpb.HttpResponse_Expectation{
							fpb.HttpResponse_Expectation_builder{
								Body:     &fpb.HttpResponse_Body{},
								Contains: "<svg",
							}.Build(),
						},
					}.Build(),
				}.Build(),
			}.Build(),
			fpb.Step_builder{
				Name: "grafana_health",
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
				Name: "grafana_unused",
				Path: proto.String("/unused"),
				Response: fpb.HttpResponse_builder{
					StatusCodes: []int32{200},
					ExpectAll: fpb.HttpResponse_ExpectAll_builder{
						Conditions: []*fpb.HttpResponse_Expectation{
							fpb.HttpResponse_Expectation_builder{
								Body:     &fpb.HttpResponse_Body{},
								Contains: "unused",
							}.Build(),
						},
					}.Build(),
				}.Build(),
			}.Build(),
		},
		Workflows: []*fpb.Workflow{
			fpb.Workflow_builder{Steps: []string{"grafana_icon"}}.Build(),
			fpb.Workflow_builder{Steps: []string{"grafana_icon", "grafana_health"}}.Build(),
			fpb.Workflow_builder{Steps: []string{"grafana_unused"}}.Build(),
		},
	}.Build()

	cf, err := CompileFingerprint(fpProto)
	if err != nil {
		t.Fatalf("CompileFingerprint() unexpected error: %v", err)
	}

	client := &mockClient{
		responses: map[string]*http.Response{
			"GET http://host:8080/public/img/icon.svg": {StatusCode: 200},
			"GET http://host:8080/api/health":          {StatusCode: 200},
		},
		bodies: map[string][]byte{
			"GET http://host:8080/public/img/icon.svg": []byte(`<svg></svg>`),
			"GET http://host:8080/api/health":          []byte(`{"database":"ok", version:"9.2.1"}`),
		},
	}

	tests := []struct {
		name              string
		initialPass1Setup func(c *cache.Cache)
		wantVersion       string
		wantMaxCalls      int32
	}{
		{
			name: "when_already_identified_with_version_in_pass1_does_not_issue_active_queries",
			initialPass1Setup: func(c *cache.Cache) {
				c.Put("GET", "http://host:8080/public/img/icon.svg", &http.Response{StatusCode: 200}, []byte(`<svg></svg>`))
				c.Put("GET", "http://host:8080/api/health", &http.Response{StatusCode: 200}, []byte(`{"database":"ok", version:"9.2.1"}`))
			},
			wantVersion:  "9.2.1",
			wantMaxCalls: 0,
		},
		{
			name: "when_identified_without_version_in_pass1_runs_version_extracting_workflow_and_exits_early",
			initialPass1Setup: func(c *cache.Cache) {
				c.Put("GET", "http://host:8080/public/img/icon.svg", &http.Response{StatusCode: 200}, []byte(`<svg></svg>`))
			},
			wantVersion:  "9.2.1",
			wantMaxCalls: 1, // Only /api/health is fetched; /unused is skipped after version is found!
		},
		{
			name: "when_shared_step_across_workflows_fetches_each_step_once_and_exits_early",
			initialPass1Setup: func(c *cache.Cache) {
				// Empty cache: workflow 1 ("grafana_icon") identifies without version, workflow 2 ("grafana_icon", "grafana_health") reuses grafana_icon and fetches /api/health for version.
			},
			wantVersion:  "9.2.1",
			wantMaxCalls: 2, // /public/img/icon.svg and /api/health; /unused is never queried!
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			atomic.StoreInt32(&client.callCount, 0)
			c := cache.New(client)
			tc.initialPass1Setup(c)

			eng := New([]*CompiledFingerprint{cf})
			results, err := eng.Run(t.Context(), c, "http://host:8080")
			if err != nil {
				t.Fatalf("eng.Run() unexpected error: %v", err)
			}

			want := []*IdentificationResult{
				{
					Software: "grafana",
					Versions: []string{tc.wantVersion},
				},
			}
			if diff := cmp.Diff(want, results); diff != "" {
				t.Errorf("eng.Run() diff (-want +got):\n%s", diff)
			}

			if calls := atomic.LoadInt32(&client.callCount); calls > tc.wantMaxCalls {
				t.Errorf("active query calls = %d, want at most %d", calls, tc.wantMaxCalls)
			}
		})
	}
}

func TestEngineRunContextCanceled(t *testing.T) {
	fpProto := fpb.WebFingerprint_builder{
		Info: fpb.FingerprintInfo_builder{Name: "Test", Software: "test"}.Build(),
		Steps: []*fpb.Step{
			fpb.Step_builder{
				Name: "s1",
				Path: proto.String("/active"),
				Response: fpb.HttpResponse_builder{
					StatusCodes: []int32{200},
				}.Build(),
			}.Build(),
		},
		Workflows: []*fpb.Workflow{
			fpb.Workflow_builder{Steps: []string{"s1"}}.Build(),
		},
	}.Build()
	cf, err := CompileFingerprint(fpProto)
	if err != nil {
		t.Fatalf("CompileFingerprint() unexpected error: %v", err)
	}

	tests := []struct {
		name           string
		cancelBefore   bool
		cancelDuringDo bool
	}{
		{
			name:         "when_context_already_canceled_returns_canceled",
			cancelBefore: true,
		},
		{
			name:           "when_context_canceled_during_active_probe_returns_canceled",
			cancelDuringDo: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if tc.cancelBefore {
				cancel()
			}

			client := &mockClient{}
			if tc.cancelDuringDo {
				client.doFunc = func(req *http.Request) (*http.Response, error) {
					cancel()
					return nil, req.Context().Err()
				}
			}

			c := cache.New(client)
			eng := New([]*CompiledFingerprint{cf})
			_, err := eng.Run(ctx, c, "http://host:8080")
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("eng.Run() error = %v, want %v", err, context.Canceled)
			}
		})
	}
}

func TestEngineDebugLogging(t *testing.T) {
	fpProto := fpb.WebFingerprint_builder{
		Info: fpb.FingerprintInfo_builder{Name: "Grafana", Software: "grafana"}.Build(),
		Steps: []*fpb.Step{
			fpb.Step_builder{
				Name: "grafana_login",
				Path: proto.String("/login"),
				Response: fpb.HttpResponse_builder{
					StatusCodes: []int32{200},
					ExpectAll: fpb.HttpResponse_ExpectAll_builder{
						Conditions: []*fpb.HttpResponse_Expectation{
							fpb.HttpResponse_Expectation_builder{
								Body:     &fpb.HttpResponse_Body{},
								Contains: "login",
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
			fpb.Step_builder{
				Name: "grafana_health",
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
			fpb.Workflow_builder{Steps: []string{"grafana_login"}}.Build(),
			fpb.Workflow_builder{Steps: []string{"grafana_health"}}.Build(),
		},
	}.Build()
	cf, err := CompileFingerprint(fpProto)
	if err != nil {
		t.Fatalf("CompileFingerprint() unexpected error: %v", err)
	}

	tests := []struct {
		name         string
		verboseLevel log.DebugLevel
		responses    map[string]*http.Response
		bodies       map[string][]byte
		wantLogs     []string
	}{
		{
			name:         "when_steps_evaluated_at_debug_level_request_logs_each_step_match_and_failure",
			verboseLevel: log.DebugLevelRequest,
			responses: map[string]*http.Response{
				"GET http://host:8080/login":      {StatusCode: 404},
				"GET http://host:8080/api/health": {StatusCode: 200},
			},
			bodies: map[string][]byte{
				"GET http://host:8080/login":      []byte("not found"),
				"GET http://host:8080/api/health": []byte("ok v9.5.1"),
			},
			wantLogs: []string{
				`definition "grafana" step "grafana_login" did not match on http://host:8080/login`,
				`definition "grafana" step "grafana_health" matched on http://host:8080/api/health`,
			},
		},
		{
			name:         "when_debug_level_is_lower_than_request_suppresses_log",
			verboseLevel: log.DebugLevelService,
			responses: map[string]*http.Response{
				"GET http://host:8080/login": {StatusCode: 200},
			},
			bodies: map[string][]byte{
				"GET http://host:8080/login": []byte("login v9.5.1"),
			},
			wantLogs: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			logger := &testDebugLogger{
				DefaultLogger: log.DefaultLogger{VerboseLevel: tc.verboseLevel},
			}
			log.SetLogger(logger)
			defer log.SetLogger(&log.DefaultLogger{})

			client := &mockClient{
				responses: tc.responses,
				bodies:    tc.bodies,
			}
			c := cache.New(client)
			eng := New([]*CompiledFingerprint{cf})

			_, err := eng.Run(t.Context(), c, "http://host:8080")
			if err != nil {
				t.Fatalf("eng.Run() unexpected error: %v", err)
			}

			if diff := cmp.Diff(tc.wantLogs, logger.entries, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("debug logs diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestMethodToString(t *testing.T) {
	tests := []struct {
		name   string
		method fpb.HttpMethod
		want   string
	}{
		{
			name:   "when_unspecified_returns_get",
			method: fpb.HttpMethod_METHOD_UNSPECIFIED,
			want:   http.MethodGet,
		},
		{
			name:   "when_get_returns_get",
			method: fpb.HttpMethod_GET,
			want:   http.MethodGet,
		},
		{
			name:   "when_post_returns_post",
			method: fpb.HttpMethod_POST,
			want:   http.MethodPost,
		},
		{
			name:   "when_head_returns_head",
			method: fpb.HttpMethod_HEAD,
			want:   http.MethodHead,
		},
		{
			name:   "when_options_returns_options",
			method: fpb.HttpMethod_OPTIONS,
			want:   http.MethodOptions,
		},
		{
			name:   "when_put_returns_put",
			method: fpb.HttpMethod_PUT,
			want:   http.MethodPut,
		},
		{
			name:   "when_delete_returns_delete",
			method: fpb.HttpMethod_DELETE,
			want:   http.MethodDelete,
		},
		{
			name:   "when_unknown_value_returns_get",
			method: fpb.HttpMethod(999),
			want:   http.MethodGet,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := methodToString(tc.method)
			if got != tc.want {
				t.Errorf("methodToString(%v) = %q, want %q", tc.method, got, tc.want)
			}
		})
	}
}

func TestEngineRunSubpathAndBaseURLDeduplication(t *testing.T) {
	fpProto := fpb.WebFingerprint_builder{
		Info: fpb.FingerprintInfo_builder{Name: "Grafana", Software: "grafana"}.Build(),
		Steps: []*fpb.Step{
			fpb.Step_builder{
				Name:       "grafana_login",
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
			fpb.Workflow_builder{Steps: []string{"grafana_login"}}.Build(),
		},
	}.Build()
	cf, err := CompileFingerprint(fpProto)
	if err != nil {
		t.Fatalf("CompileFingerprint() unexpected error: %v", err)
	}

	tests := []struct {
		name      string
		populate  func(c *cache.Cache)
		responses map[string]*http.Response
		bodies    map[string][]byte
		want      []*IdentificationResult
	}{
		{
			name: "when_parent_root_and_subpath_both_match_keeps_only_parent_root",
			populate: func(c *cache.Cache) {
				c.Put("GET", "http://127.0.0.1:3000/user/login", &http.Response{StatusCode: 200}, []byte("grafana-app v13.2.4"))
			},
			responses: map[string]*http.Response{
				"GET http://127.0.0.1:3000/login": {StatusCode: 200},
			},
			bodies: map[string][]byte{
				"GET http://127.0.0.1:3000/login": []byte("grafana-app v13.2.4"),
			},
			want: []*IdentificationResult{
				{
					Software:        "grafana",
					ApplicationRoot: "",
					Versions:        []string{"13.2.4"},
				},
			},
		},
		{
			name: "when_cache_has_entry_for_different_base_url_ignores_it_in_pass1",
			populate: func(c *cache.Cache) {
				c.Put("GET", "http://localhost:3000/user/login", &http.Response{StatusCode: 200}, []byte("grafana-app v13.2.4"))
			},
			responses: map[string]*http.Response{
				"GET http://127.0.0.1:3000/login": {StatusCode: 200},
			},
			bodies: map[string][]byte{
				"GET http://127.0.0.1:3000/login": []byte("grafana-app v13.2.4"),
			},
			want: []*IdentificationResult{
				{
					Software:        "grafana",
					ApplicationRoot: "",
					Versions:        []string{"13.2.4"},
				},
			},
		},
		{
			name: "when_sibling_roots_match_keeps_both_roots",
			populate: func(c *cache.Cache) {
				c.Put("GET", "http://127.0.0.1:3000/app/login", &http.Response{StatusCode: 200}, []byte("grafana-app v13.2.4"))
				c.Put("GET", "http://127.0.0.1:3000/app2/login", &http.Response{StatusCode: 200}, []byte("grafana-app v13.2.4"))
			},
			want: []*IdentificationResult{
				{
					Software:        "grafana",
					ApplicationRoot: "/app",
					Versions:        []string{"13.2.4"},
				},
				{
					Software:        "grafana",
					ApplicationRoot: "/app2",
					Versions:        []string{"13.2.4"},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client := &mockClient{
				responses: tc.responses,
				bodies:    tc.bodies,
			}
			c := cache.New(client)
			if tc.populate != nil {
				tc.populate(c)
			}
			eng := New([]*CompiledFingerprint{cf})
			got, err := eng.Run(t.Context(), c, "http://127.0.0.1:3000")
			if err != nil {
				t.Fatalf("eng.Run() unexpected error: %v", err)
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("eng.Run() diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestEngineSubpathCandidateRootPromotion(t *testing.T) {
	fpProto := fpb.WebFingerprint_builder{
		Info: fpb.FingerprintInfo_builder{Name: "Grafana", Software: "grafana"}.Build(),
		Steps: []*fpb.Step{
			fpb.Step_builder{
				Name:       "grafana_icon",
				PathSuffix: proto.String("/public/img/icon.svg"),
				Response: fpb.HttpResponse_builder{
					StatusCodes: []int32{200},
					ExpectAll: fpb.HttpResponse_ExpectAll_builder{
						Conditions: []*fpb.HttpResponse_Expectation{
							fpb.HttpResponse_Expectation_builder{
								Body:     &fpb.HttpResponse_Body{},
								Contains: "<svg",
							}.Build(),
						},
					}.Build(),
				}.Build(),
			}.Build(),
			fpb.Step_builder{
				Name: "grafana_health",
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
							Regexp:   `"version":"([0-9.]+)"`,
						}.Build(),
					},
				}.Build(),
			}.Build(),
		},
		Workflows: []*fpb.Workflow{
			fpb.Workflow_builder{Steps: []string{"grafana_icon", "grafana_health"}}.Build(),
		},
	}.Build()

	cf, err := CompileFingerprint(fpProto)
	if err != nil {
		t.Fatalf("CompileFingerprint() unexpected error: %v", err)
	}

	tests := []struct {
		name      string
		populate  func(c *cache.Cache)
		responses map[string]*http.Response
		bodies    map[string][]byte
		want      []*IdentificationResult
	}{
		{
			name: "subpath_step0_in_pass1_promotes_root_and_completes_workflow_in_pass2",
			populate: func(c *cache.Cache) {
				c.Put("GET", "http://127.0.0.1:3000/sub/public/img/icon.svg", &http.Response{StatusCode: 200}, []byte("<svg></svg>"))
			},
			responses: map[string]*http.Response{
				"GET http://127.0.0.1:3000/sub/api/health":      {StatusCode: 200},
				"GET http://127.0.0.1:3000/public/img/icon.svg": {StatusCode: 404},
			},
			bodies: map[string][]byte{
				"GET http://127.0.0.1:3000/sub/api/health": []byte(`{"database":"ok","version":"9.2.1"}`),
			},
			want: []*IdentificationResult{
				{
					Software:        "grafana",
					ApplicationRoot: "/sub",
					Versions:        []string{"9.2.1"},
				},
			},
		},
		{
			name: "subpath_step0_in_pass1_without_pass2_confirmation_does_not_identify",
			populate: func(c *cache.Cache) {
				c.Put("GET", "http://127.0.0.1:3000/sub/public/img/icon.svg", &http.Response{StatusCode: 200}, []byte("<svg></svg>"))
			},
			responses: map[string]*http.Response{
				"GET http://127.0.0.1:3000/sub/api/health":      {StatusCode: 404},
				"GET http://127.0.0.1:3000/public/img/icon.svg": {StatusCode: 404},
			},
			bodies: map[string][]byte{
				"GET http://127.0.0.1:3000/sub/api/health": []byte("404 Not Found"),
			},
			want: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client := &mockClient{
				responses: tc.responses,
				bodies:    tc.bodies,
			}
			c := cache.New(client)
			if tc.populate != nil {
				tc.populate(c)
			}
			eng := New([]*CompiledFingerprint{cf})
			got, err := eng.Run(t.Context(), c, "http://127.0.0.1:3000")
			if err != nil {
				t.Fatalf("eng.Run() unexpected error: %v", err)
			}
			if diff := cmp.Diff(tc.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("eng.Run() diff (-want +got):\n%s", diff)
			}
		})
	}
}
