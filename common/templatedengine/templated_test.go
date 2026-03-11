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
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"testing"

	"github.com/google/goonami-scanner/common/clients/callbackserver"
	"github.com/google/goonami-scanner/common/templatedengine/actions"
	"github.com/google/goonami-scanner/core/config"
	goohttp "github.com/google/goonami-scanner/core/net/http"
	"google.golang.org/protobuf/encoding/prototext"

	cpb "github.com/google/goonami-scanner/core/config/config_go_proto"
	cbpb "github.com/google/goonami-scanner/tools/callbackserver/callbackserver_config_go_proto"
	tpb "github.com/google/tsunami-security-scanner-plugins/templated/templateddetector/proto/templated_plugin_go_proto"
	npb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
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

	cbs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"hasHttpInteraction": true}`)
	}))
	defer cbs.Close()
	cbsURL, _ := url.Parse(cbs.URL)

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
		enableCBS     bool
		wantErr       error
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
			name:          "when_action_not_found_returns_error",
			protoFile:     "testdata/action_not_found.textproto",
			wantDetection: false,
			wantErr:       actions.ErrActionNotFound,
		},
		{
			name:          "when_unsupported_action_type_returns_fatal_error",
			protoFile:     "testdata/unsupported_action_type.textproto",
			wantDetection: false,
			wantErr:       actions.ErrInvalidAction,
		},
		{
			name:          "when_workflow_condition_not_met_skips_it",
			protoFile:     "testdata/workflow_condition_not_met.textproto",
			wantDetection: false,
			enableCBS:     false,
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
			name:          "when_callback_server_action_succeeds",
			protoFile:     "testdata/callback_server_action.textproto",
			wantDetection: true,
			enableCBS:     true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfgProto := config.DefaultProto()
			if tc.enableCBS {
				clicfg := cpb.ClientsConfig_builder{
					CallbackServer: cbpb.CallbackserverConfig_builder{
						HttpPollConfig: cbpb.EndpointConfig_builder{
							PublicUri: cbsURL.String(),
						}.Build(),
						HttpRecordConfig: cbpb.EndpointConfig_builder{
							PublicUri: cbsURL.String(),
						}.Build(),
						DnsRecordConfig: cbpb.EndpointConfig_builder{
							PublicUri: "cb.localhost.lan",
						}.Build(),
					}.Build(),
				}.Build()
				cfgProto.SetClients(clicfg)
			}
			cfg := config.FromProto(cfgProto)

			if err := callbackserver.Initialize(t.Context(), cfg); err != nil {
				t.Fatalf("Failed to initialize HTTP client: %v", err)
			}

			if err := goohttp.InitializeDefaults(cfg); err != nil {
				t.Fatalf("Failed to initialize HTTP client: %v", err)
			}

			proto := loadProto(t, tc.protoFile)
			detector, err := New(t.Context(), cfg, proto, goohttp.DefaultClient())
			if err != nil {
				t.Fatalf("Failed to create detector: %v", err)
			}

			reports, err := detector.Detect(t.Context(), service)
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("Detect() returned unexpected error: %v, want: %v", err, tc.wantErr)
			}

			if tc.wantErr != nil {
				return
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

	cfg := config.Default()
	initFns := LoadPlugins(cfg, plugins)
	if len(initFns) != len(plugins) {
		t.Errorf("LoadPlugins() returned %d functions, want %d", len(initFns), len(plugins))
	}

	for i, fn := range initFns {
		_, err := fn(t.Context(), cfg)
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

	cfg := config.Default()
	detector, _ := New(t.Context(), cfg, proto, goohttp.DefaultClient())
	reports, err := detector.Detect(t.Context(), service)
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if len(reports.GetDetectionReports()) > 0 {
		t.Errorf("Detect() returned reports for non-web service, want none")
	}
}
