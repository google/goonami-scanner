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

package templatedengine

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"testing"

	"github.com/google/goonami-scanner/core/config"
	cpb "github.com/google/goonami-scanner/core/config/config_go_proto"
	goohttp "github.com/google/goonami-scanner/core/net/http"

	tpb "github.com/google/tsunami-security-scanner-plugins/templated/templateddetector/proto/templated_plugin_go_proto"
	npb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
	"google.golang.org/protobuf/encoding/prototext"
)

func TestTemplatedDetector_Detect(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/OK" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "enabled:true")
		} else if r.URL.Path == "/CLEANUP" {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	port, _ := strconv.Atoi(u.Port())

	cfg := config.FromProto(&cpb.Config{})
	if err := goohttp.InitializeDefaults(cfg); err != nil {
		t.Fatalf("Failed to initialize HTTP client: %v", err)
	}

	service := nspb.NetworkService_builder{
		NetworkEndpoint: npb.NetworkEndpoint_builder{
			Hostname: npb.Hostname_builder{Name: u.Hostname()}.Build(),
			Port:     npb.Port_builder{PortNumber: uint32(port)}.Build(),
		}.Build(),
		SupportedHttpMethods: []string{"GET"},
	}.Build()

	tests := []struct {
		name          string
		protoFile     string
		wantDetection bool
	}{
		{
			name:          "when_workflow_succeeds_returns_findings",
			protoFile:     "testdata/workflow_succeeds.textproto",
			wantDetection: true,
		},
		{
			name:          "when_workflow_fails_returns_no_findings",
			protoFile:     "testdata/workflow_fails.textproto",
			wantDetection: false,
		},
		{
			name:          "when_variable_substitution_works",
			protoFile:     "testdata/variable_substitution.textproto",
			wantDetection: true,
		},
		{
			name:          "when_action_not_found_returns_no_findings",
			protoFile:     "testdata/action_not_found.textproto",
			wantDetection: false,
		},
		{
			name:          "when_unsupported_action_type_returns_no_findings",
			protoFile:     "testdata/unsupported_action_type.textproto",
			wantDetection: false,
		},
		{
			name:          "when_workflow_condition_not_met_skips_it",
			protoFile:     "testdata/workflow_condition_not_met.textproto",
			wantDetection: false,
		},
		{
			name:          "when_multiple_workflows_returns_status_of_first_compatible",
			protoFile:     "testdata/multiple_workflows.textproto",
			wantDetection: false,
		},
		{
			name:          "when_cleanup_action_is_executed",
			protoFile:     "testdata/cleanup_action.textproto",
			wantDetection: true,
		},
		{
			name:          "when_utility_sleep_action_works",
			protoFile:     "testdata/utility_sleep_action.textproto",
			wantDetection: true,
		},
		{
			name:          "when_callback_server_action_fails_currently",
			protoFile:     "testdata/callback_server_action.textproto",
			wantDetection: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			proto := loadProto(t, tc.protoFile)
			detector, err := New(context.Background(), proto, goohttp.DefaultClient())
			if err != nil {
				t.Fatalf("Failed to create detector: %v", err)
			}

			reports, err := detector.Detect(context.Background(), service)
			if err != nil {
				t.Fatalf("Detect failed: %v", err)
			}

			hasReports := len(reports.GetDetectionReports()) > 0
			if hasReports != tc.wantDetection {
				t.Errorf("Detect() hasReports = %v, want %v", hasReports, tc.wantDetection)
			}
		})
	}
}

func loadProto(t *testing.T, filename string) *tpb.TemplatedPlugin {
	t.Helper()
	content, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("Failed to read proto file %s: %v", filename, err)
	}
	proto := &tpb.TemplatedPlugin{}
	if err := prototext.Unmarshal(content, proto); err != nil {
		t.Fatalf("Failed to unmarshal proto from %s: %v", filename, err)
	}
	return proto
}

func TestLoadPlugins(t *testing.T) {
	plugins := []*tpb.TemplatedPlugin{
		loadProto(t, "testdata/empty_plugin.textproto"),
	}

	initFns := LoadPlugins(plugins)
	if len(initFns) != len(plugins) {
		t.Errorf("LoadPlugins() returned %d functions, want %d", len(initFns), len(plugins))
	}

	for i, fn := range initFns {
		_, err := fn(context.Background(), &config.Config{})
		if err != nil {
			t.Errorf("initFns[%d]() failed: %v", i, err)
			continue
		}
	}
}

func TestTemplatedDetector_Detect_NonWebService(t *testing.T) {
	service := nspb.NetworkService_builder{
		NetworkEndpoint: npb.NetworkEndpoint_builder{
			Hostname: npb.Hostname_builder{Name: "localhost"}.Build(),
			Port:     npb.Port_builder{PortNumber: 1234}.Build(),
		}.Build(),
		// No SupportedHttpMethods makes it a non-web service
	}.Build()

	proto := loadProto(t, "testdata/non_web_service.textproto")

	detector, _ := New(context.Background(), proto, goohttp.DefaultClient())
	reports, err := detector.Detect(context.Background(), service)
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if len(reports.GetDetectionReports()) > 0 {
		t.Errorf("Detect() returned reports for non-web service, want none")
	}
}
