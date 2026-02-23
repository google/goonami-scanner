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

package actions

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"testing"

	"github.com/google/goonami-scanner/common/templatedengine/environment"
	"github.com/google/goonami-scanner/core/config"
	goohttp "github.com/google/goonami-scanner/core/net/http"

	tpb "github.com/google/tsunami-security-scanner-plugins/templated/templateddetector/proto/templated_plugin_go_proto"
	npb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
	"google.golang.org/protobuf/encoding/prototext"
)

func TestHTTPActionRunner_Run(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/OK" {
			w.Header().Set("X-Test", "Value")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("body content"))
		} else if r.URL.Path == "/POST" {
			if r.Method != "POST" {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			body, _ := io.ReadAll(r.Body)
			if string(body) == "expected body" && r.Header.Get("X-Custom") == "custom value" {
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, "post success")
			} else {
				w.WriteHeader(http.StatusBadRequest)
			}
		} else if r.URL.Path == "/MULTI_KO" {
			w.WriteHeader(http.StatusNotFound)
		} else if r.URL.Path == "/MULTI_OK" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "multi success")
		} else if r.URL.Path == "/EXPECT_ANY" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "found second")
		} else if r.URL.Path == "/EXTRACT_ANY" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "key=value")
		} else if r.URL.Path == "/HEADER_EXPECT" {
			w.Header().Set("X-Status", "Ready")
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	port, _ := strconv.Atoi(u.Port())

	cfg := config.Default()
	goohttp.InitializeDefaults(cfg)

	service := nspb.NetworkService_builder{
		NetworkEndpoint: npb.NetworkEndpoint_builder{
			Hostname: npb.Hostname_builder{Name: u.Hostname()}.Build(),
			Port:     npb.Port_builder{PortNumber: uint32(port)}.Build(),
		}.Build(),
		SupportedHttpMethods: []string{"GET", "POST"},
	}.Build()

	tests := []struct {
		name       string
		actionFile string
		env        func() *environment.Environment
		wantOk     bool
		wantVars   map[string]string
	}{
		{
			name:       "when_request_succeeds_returns_true",
			actionFile: "testdata/request_succeeds.textproto",
			wantOk:     true,
		},
		{
			name:       "when_status_code_mismatch_returns_false",
			actionFile: "testdata/status_code_mismatch.textproto",
			wantOk:     false,
		},
		{
			name:       "when_expectation_all_fails_returns_false",
			actionFile: "testdata/expectation_all_fails.textproto",
			wantOk:     false,
		},
		{
			name:       "when_expectation_missing_header_or_body_fails_returns_false",
			actionFile: "testdata/expect_missing_body_header.textproto",
			wantOk:     false,
		},
		{
			name:       "when_expectation_any_fails_returns_false",
			actionFile: "testdata/expectation_any_fails.textproto",
			wantOk:     false,
		},
		{
			name:       "when_extraction_succeeds_stores_variable",
			actionFile: "testdata/extract_all_succeeds.textproto",
			wantOk:     true,
			wantVars: map[string]string{
				"extracted": "content",
			},
		},
		{
			name:       "when_extraction_all_fails_returns_false",
			actionFile: "testdata/extract_all_fails.textproto",
			wantOk:     false,
		},
		{
			name:       "when_extraction_missing_header_or_body_fails_returns_false",
			actionFile: "testdata/extract_missing_header_body.textproto",
			wantOk:     false,
		},
		{
			name:       "when_header_extraction_succeeds_stores_variable",
			actionFile: "testdata/header_extraction_succeeds.textproto",
			wantOk:     true,
			wantVars: map[string]string{
				"header_var": "alue",
			},
		},
		{
			name:       "when_method_is_unspecified_returns_false",
			actionFile: "testdata/method_unspecified.textproto",
			wantOk:     false,
		},
		{
			name:       "when_post_with_substitution_works",
			actionFile: "testdata/post_with_substitution.textproto",
			env: func() *environment.Environment {
				e := environment.New(cfg)
				e.Set("path", "POST")
				e.Set("header_val", "custom value")
				e.Set("target", "body")
				return e
			},
			wantOk: true,
		},
		{
			name:       "when_multiple_uris_first_fails_second_succeeds_returns_true",
			actionFile: "testdata/multiple_uris.textproto",
			wantOk:     true,
		},
		{
			name:       "when_expect_any_works",
			actionFile: "testdata/expect_any_works.textproto",
			wantOk:     true,
		},
		{
			name:       "when_expect_all_works",
			actionFile: "testdata/expect_all_works.textproto",
			wantOk:     true,
		},
		{
			name:       "when_extract_any_works",
			actionFile: "testdata/extract_any_works.textproto",
			wantOk:     true,
			wantVars:   map[string]string{"v2": "value"},
		},
		{
			name:       "when_header_expectation_works",
			actionFile: "testdata/header_expectation_works.textproto",
			wantOk:     true,
		},
		{
			name:       "when_extraction_does_not_compile_returns_false",
			actionFile: "testdata/extraction_does_not_compile.textproto",
			wantOk:     false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			action := loadAction(t, tc.actionFile)
			env := environment.New(cfg)
			if tc.env != nil {
				env = tc.env()
			}

			runner := NewHTTPActionRunner(goohttp.DefaultClient())
			gotOk := runner.Run(t.Context(), service, action, env)
			if gotOk != tc.wantOk {
				t.Errorf("Run() = %v, want %v", gotOk, tc.wantOk)
			}

			for k, v := range tc.wantVars {
				val, ok := env.Get(k)
				if !ok || val != v {
					t.Errorf("env.Get(%q) = %q, %v, want %q, true", k, val, ok, v)
				}
			}
		})
	}
}

func loadAction(t *testing.T, filename string) *tpb.PluginAction {
	t.Helper()
	content, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("Failed to read action file %s: %v", filename, err)
	}
	action := &tpb.PluginAction{}
	if err := prototext.Unmarshal(content, action); err != nil {
		t.Fatalf("Failed to unmarshal action from %s: %v", filename, err)
	}
	return action
}

func TestHTTPActionRunner_Run_Errors(t *testing.T) {
	service := nspb.NetworkService_builder{
		NetworkEndpoint: npb.NetworkEndpoint_builder{
			Hostname: npb.Hostname_builder{Name: "localhost"}.Build(),
			Port:     npb.Port_builder{PortNumber: 80}.Build(),
		}.Build(),
		SupportedHttpMethods: []string{"GET"},
	}.Build()
	cfg := config.Default()

	tests := []struct {
		name       string
		actionFile string
	}{
		{
			name:       "when_client_do_fails_returns_false",
			actionFile: "testdata/simple_get.textproto",
		},
		{
			name:       "when_client_do_fails_but_ignored_returns_true",
			actionFile: "testdata/get_with_ignore_errors.textproto",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runner := NewHTTPActionRunner(&errorClient{})
			action := loadAction(t, tc.actionFile)
			if runner.Run(t.Context(), service, action, environment.New(cfg)) {
				t.Error("Run() = true, want false on client error")
			}
		})
	}
}

type errorClient struct{}

func (c *errorClient) Do(req *http.Request) (*http.Response, error) {
	return nil, fmt.Errorf("simulated error")
}
func (c *errorClient) Initialize(cfg *config.Config) error { return nil }
