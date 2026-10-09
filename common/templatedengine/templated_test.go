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
	"testing/fstest"

	"github.com/google/goonami-scanner/common/clients/callbackserver"
	"github.com/google/goonami-scanner/common/templatedengine/actions"
	"github.com/google/goonami-scanner/core/config"
	_ "github.com/google/goonami-scanner/core/net/http/simpleclient"
	"google.golang.org/protobuf/encoding/prototext"

	cpb "github.com/google/goonami-scanner/core/config/config_go_proto"
	cbpb "github.com/google/goonami-scanner/tools/callbackserver/callbackserver_config_go_proto"
	tpb "github.com/google/tsunami-security-scanner-plugins/templated/templateddetector/proto/templated_plugin_go_proto"
	npb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
)

func TestTNew(t *testing.T) {
	tests := []struct {
		name    string
		proto   *tpb.TemplatedPlugin
		wantErr error
	}{
		{
			name:    "action_not_found_returns_error",
			proto:   loadProto(t, "testdata/action_not_found.textproto"),
			wantErr: actions.ErrActionNotFound,
		},
		{
			name:    "when_unsupported_action_type_returns_fatal_error",
			proto:   loadProto(t, "testdata/unsupported_action_type.textproto"),
			wantErr: actions.ErrInvalidAction,
		},
		{
			name:    "cleanup_action_not_found_returns_error",
			proto:   loadProto(t, "testdata/cleanup_not_found.textproto"),
			wantErr: actions.ErrActionNotFound,
		},
		{
			name: "when_fingerprint_action_follows_detection_action_returns_error",
			proto: tpb.TemplatedPlugin_builder{
				Actions: []*tpb.PluginAction{
					tpb.PluginAction_builder{
						Name:        "detect_action",
						ActionPhase: tpb.PluginAction_ACTION_PHASE_DETECTION,
						Utility:     &tpb.UtilityAction{},
					}.Build(),
					tpb.PluginAction_builder{
						Name:        "fingerprint_action",
						ActionPhase: tpb.PluginAction_ACTION_PHASE_FINGERPRINT,
						Utility:     &tpb.UtilityAction{},
					}.Build(),
				},
				Workflows: []*tpb.PluginWorkflow{
					tpb.PluginWorkflow_builder{
						Actions: []string{"detect_action", "fingerprint_action"},
					}.Build(),
				},
			}.Build(),
			wantErr: actions.ErrInvalidAction,
		},
		{
			name: "when_fingerprint_action_follows_undefined_phase_action_returns_error",
			proto: tpb.TemplatedPlugin_builder{
				Actions: []*tpb.PluginAction{
					tpb.PluginAction_builder{
						Name:    "default_phase_action",
						Utility: &tpb.UtilityAction{},
					}.Build(),
					tpb.PluginAction_builder{
						Name:        "fingerprint_action",
						ActionPhase: tpb.PluginAction_ACTION_PHASE_FINGERPRINT,
						Utility:     &tpb.UtilityAction{},
					}.Build(),
				},
				Workflows: []*tpb.PluginWorkflow{
					tpb.PluginWorkflow_builder{
						Actions: []string{"default_phase_action", "fingerprint_action"},
					}.Build(),
				},
			}.Build(),
			wantErr: actions.ErrInvalidAction,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Default()

			_, err := New(t.Context(), cfg, tc.proto)
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("New() returned unexpected error: %v, want: %v", err, tc.wantErr)
			}
		})
	}
}

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

	t.Cleanup(func() {
		if err := callbackserver.Initialize(t.Context(), config.Default()); err != nil {
			t.Errorf("Failed to reset callback server client: %v", err)
		}
	})

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
			t.Cleanup(func() {
				if err := callbackserver.Initialize(t.Context(), config.Default()); err != nil {
					t.Errorf("Failed to reset callback server client: %v", err)
				}
			})

			proto := loadProto(t, tc.protoFile)
			detector, err := New(t.Context(), cfg, proto)
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

func TestLoadPluginsFromFS(t *testing.T) {
	fsys := fstest.MapFS{
		"valid.textproto": &fstest.MapFile{
			Data: []byte(`
				info { name: "ValidPlugin" }
				config { disabled: false }
			`),
		},
		"disabled.textproto": &fstest.MapFile{
			Data: []byte(`
				info { name: "DisabledPlugin" }
				config { disabled: true }
			`),
		},
		"ignored.txt": &fstest.MapFile{
			Data: []byte(`not a proto`),
		},
		"invalid_test.textproto": &fstest.MapFile{
			Data: []byte(`test file should be skipped`),
		},
		"subdir/valid_nested.textproto": &fstest.MapFile{
			Data: []byte(`
				info { name: "NestedPlugin" }
				config { disabled: false }
			`),
		},
	}

	plugins, err := LoadPluginsFromFS(t.Context(), fsys)
	if err != nil {
		t.Fatalf("LoadPluginsFromFS() failed: %v", err)
	}

	if len(plugins) != 2 {
		t.Errorf("LoadPluginsFromFS() returned %d plugins, want 2", len(plugins))
	}

	var names []string
	for _, p := range plugins {
		names = append(names, p.GetInfo().GetName())
	}

	wantNames := []string{"ValidPlugin", "NestedPlugin"}
	for _, want := range wantNames {
		found := false
		for _, name := range names {
			if name == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("LoadPluginsFromFS() missed expected plugin: %s", want)
		}
	}
}

func TestLoadPluginsFromFS_InvalidPluginReturnsError(t *testing.T) {
	fsys := fstest.MapFS{
		"invalid.textproto": &fstest.MapFile{
			Data: []byte(`not a proto`),
		},
	}

	_, err := LoadPluginsFromFS(t.Context(), fsys)
	if err == nil {
		t.Fatalf("LoadPluginsFromFS() succeeded, want error")
	}
}

func TestTemplatedDetector_Detect_NonWebService(t *testing.T) {
	tests := []struct {
		name    string
		service *nspb.NetworkService
		proto   *tpb.TemplatedPlugin
	}{
		{
			name: "when_non_web_service_returns_no_findings",
			service: nspb.NetworkService_builder{
				NetworkEndpoint: npb.NetworkEndpoint_builder{
					Hostname: npb.Hostname_builder{Name: "localhost"}.Build(),
					Port:     npb.Port_builder{PortNumber: 1234}.Build(),
				}.Build(),
				// No SupportedHttpMethods makes it a non-web service
			}.Build(),
			proto: loadProto(t, "testdata/non_web_service.textproto"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Default()
			if err := callbackserver.Initialize(t.Context(), cfg); err != nil {
				t.Fatalf("Failed to initialize callback server client: %v", err)
			}
			t.Cleanup(func() {
				if err := callbackserver.Initialize(t.Context(), config.Default()); err != nil {
					t.Errorf("Failed to reset callback server client: %v", err)
				}
			})

			detector, err := New(t.Context(), cfg, tc.proto)
			if err != nil {
				t.Fatalf("Failed to create detector: %v", err)
			}
			reports, err := detector.Detect(t.Context(), tc.service)
			if err != nil {
				t.Fatalf("Detect failed: %v", err)
			}

			if len(reports.GetDetectionReports()) > 0 {
				t.Errorf("Detect() returned reports for non-web service, want none")
			}
		})
	}
}

func TestTemplatedDetector_DetectForPhase(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/OK" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("url.Parse(%q) failed: %v", ts.URL, err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatalf("strconv.Atoi(%q) failed: %v", u.Port(), err)
	}

	service := nspb.NetworkService_builder{
		NetworkEndpoint: npb.NetworkEndpoint_builder{
			Hostname: npb.Hostname_builder{Name: u.Hostname()}.Build(),
			Port:     npb.Port_builder{PortNumber: uint32(port)}.Build(),
		}.Build(),
		SupportedHttpMethods: []string{"GET"},
	}.Build()

	tests := []struct {
		name            string
		pluginProtoText string
		targetPhase     tpb.PluginAction_ActionPhase
		wantDetection   bool
		wantErr         error
	}{
		{
			name:        "when_target_phase_is_fingerprint_runs_only_fingerprint_actions_and_stops_before_detection",
			targetPhase: tpb.PluginAction_ACTION_PHASE_FINGERPRINT,
			pluginProtoText: `
				actions {
					name: "fingerprint_action"
					action_phase: ACTION_PHASE_FINGERPRINT
					http_request {
						method: GET
						uri: "/OK"
						response { http_status: 200 }
					}
				}
				actions {
					name: "detect_action"
					action_phase: ACTION_PHASE_DETECTION
					http_request {
						method: GET
						uri: "/NOTFOUND"
						response { http_status: 200 }
					}
				}
				workflows {
					actions: "fingerprint_action"
					actions: "detect_action"
				}
			`,
			wantDetection: false,
		},
		{
			name:        "when_target_phase_is_fingerprint_and_fingerprint_action_fails_returns_action_failed_error",
			targetPhase: tpb.PluginAction_ACTION_PHASE_FINGERPRINT,
			pluginProtoText: `
				actions {
					name: "fingerprint_action"
					action_phase: ACTION_PHASE_FINGERPRINT
					http_request {
						method: GET
						uri: "/NOTFOUND"
						response { http_status: 200 }
					}
				}
				actions {
					name: "detect_action"
					action_phase: ACTION_PHASE_DETECTION
					http_request {
						method: GET
						uri: "/OK"
						response { http_status: 200 }
					}
				}
				workflows {
					actions: "fingerprint_action"
					actions: "detect_action"
				}
			`,
			wantErr: actions.ErrActionFailed,
		},
		{
			name:        "when_target_phase_is_detection_skips_fingerprint_actions_and_runs_detection_actions",
			targetPhase: tpb.PluginAction_ACTION_PHASE_DETECTION,
			pluginProtoText: `
				actions {
					name: "fingerprint_action"
					action_phase: ACTION_PHASE_FINGERPRINT
					http_request {
						method: GET
						uri: "/NOTFOUND"
						response { http_status: 200 }
					}
				}
				actions {
					name: "detect_action"
					action_phase: ACTION_PHASE_DETECTION
					http_request {
						method: GET
						uri: "/OK"
						response { http_status: 200 }
					}
				}
				actions {
					name: "default_phase_action"
					http_request {
						method: GET
						uri: "/OK"
						response { http_status: 200 }
					}
				}
				workflows {
					actions: "fingerprint_action"
					actions: "detect_action"
					actions: "default_phase_action"
				}
			`,
			wantDetection: true,
		},
		{
			name:        "when_target_phase_is_detection_and_detection_action_fails_returns_action_failed_error",
			targetPhase: tpb.PluginAction_ACTION_PHASE_DETECTION,
			pluginProtoText: `
				actions {
					name: "fingerprint_action"
					action_phase: ACTION_PHASE_FINGERPRINT
					http_request {
						method: GET
						uri: "/OK"
						response { http_status: 200 }
					}
				}
				actions {
					name: "detect_action"
					action_phase: ACTION_PHASE_DETECTION
					http_request {
						method: GET
						uri: "/NOTFOUND"
						response { http_status: 200 }
					}
				}
				workflows {
					actions: "fingerprint_action"
					actions: "detect_action"
				}
			`,
			wantErr: actions.ErrActionFailed,
		},
		{
			name:        "when_target_phase_is_undefined_runs_all_actions_and_returns_findings",
			targetPhase: tpb.PluginAction_ACTION_PHASE_UNDEFINED,
			pluginProtoText: `
				actions {
					name: "fingerprint_action"
					action_phase: ACTION_PHASE_FINGERPRINT
					http_request {
						method: GET
						uri: "/OK"
						response { http_status: 200 }
					}
				}
				actions {
					name: "detect_action"
					http_request {
						method: GET
						uri: "/OK"
						response { http_status: 200 }
					}
				}
				workflows {
					actions: "fingerprint_action"
					actions: "detect_action"
				}
			`,
			wantDetection: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Default()
			if err := callbackserver.Initialize(t.Context(), cfg); err != nil {
				t.Fatalf("callbackserver.Initialize() failed: %v", err)
			}

			proto := &tpb.TemplatedPlugin{}
			if err := prototext.Unmarshal([]byte(tc.pluginProtoText), proto); err != nil {
				t.Fatalf("prototext.Unmarshal() failed: %v", err)
			}

			detector, err := New(t.Context(), cfg, proto)
			if err != nil {
				t.Fatalf("New() failed: %v", err)
			}

			reports, err := detector.DetectForPhase(t.Context(), service, tc.targetPhase, nil)
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("DetectForPhase() error = %v, want %v", err, tc.wantErr)
			}
			if tc.wantErr != nil {
				return
			}

			hasReports := len(reports.GetDetectionReports()) > 0
			if hasReports != tc.wantDetection {
				t.Errorf("DetectForPhase() hasReports = %v, want %v", hasReports, tc.wantDetection)
			}
		})
	}
}
