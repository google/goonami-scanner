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

package templatedweakcredentials

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/goonami-scanner/common/clients/callbackserver"
	"github.com/google/goonami-scanner/common/credentialstore"
	"github.com/google/goonami-scanner/common/templatedengine"
	"github.com/google/goonami-scanner/common/templatedengine/environment"
	"github.com/google/goonami-scanner/common/testfakes/fakecallbackserver"
	"github.com/google/goonami-scanner/common/testfakes/faketemplated"
	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/log"
	"github.com/google/goonami-scanner/core/metrics"
	"github.com/google/goonami-scanner/core/module"
	_ "github.com/google/goonami-scanner/core/net/http/simpleclient"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"

	bfpb "github.com/google/goonami-scanner/common/bruteforce/bruteforce_config_go_proto"
	cpb "github.com/google/goonami-scanner/core/config/config_go_proto"
	tpb "github.com/google/tsunami-security-scanner-plugins/templated/templateddetector/proto/templated_plugin_go_proto"
	ttpb "github.com/google/tsunami-security-scanner-plugins/templated/templateddetector/proto/templated_plugin_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
)

const mockPluginTextproto = `
info {
	name: "MockWeakCreds"
}
finding {
	title: "Mock Weak Credentials"
}
config {
	disabled: false
}
service_information {
	default_credentials {
		login: "admin"
		password: "password"
	}
	default_credentials {
		login: "root"
		password: "123"
	}
}
workflows {
	actions: "attempt_login"
}
actions {
	name: "attempt_login"
	http_request {
		method: POST
		uri: "/login"
		data: "user={{ T_USERNAME }}&pass={{ T_PASSWORD }}"
		response {
			http_status: 200
			expect_all {
				conditions {
					contains: "Welcome {{ T_USERNAME }}"
					body {}
				}
			}
		}
	}
}
`

const mockPasswordOnlyPluginTextproto = `
info {
	name: "MockPasswordOnlyCreds"
}
finding {
	title: "Mock Password Only Credentials"
}
config {
	disabled: false
}
service_information {
	authentication_type: AUTHENTICATION_TYPE_PASSWORD_ONLY
	default_credentials {
		password: "secret_password"
	}
}
workflows {
	actions: "attempt_login"
}
actions {
	name: "attempt_login"
	http_request {
		method: POST
		uri: "/login"
		data: "pass={{ T_PASSWORD }}"
		response {
			http_status: 200
			expect_all {
				conditions {
					contains: "Welcome User"
					body {}
				}
			}
		}
	}
}
`

const mockCallbackRequiredPluginTextproto = `
info {
	name: "MockCallbackRequiredCreds"
}
finding {
	title: "Mock Callback Required Credentials"
}
config {
	disabled: false
}
service_information {
	default_credentials {
		login: "root"
		password: "123"
	}
}
workflows {
	condition: REQUIRES_CALLBACK_SERVER
	actions: "attempt_login"
}
actions {
	name: "attempt_login"
	http_request {
		method: POST
		uri: "/login"
		data: "user={{ T_USERNAME }}&pass={{ T_PASSWORD }}"
		response {
			http_status: 200
			expect_all {
				conditions {
					contains: "Welcome {{ T_USERNAME }}"
					body {}
				}
			}
		}
	}
}
`

const mockFingerprintedPluginTextproto = `
info {
	name: "MockFingerprintedWeakCreds"
}
finding {
	title: "Mock Fingerprinted Weak Credentials"
}
config {
	disabled: false
}
service_information {
	default_credentials {
		login: "root"
		password: "123"
	}
	default_credentials {
		login: "admin"
		password: "password"
	}
}
workflows {
	actions: "check_health"
	actions: "check_version"
	actions: "attempt_login"
}
actions {
	name: "check_health"
	action_phase: ACTION_PHASE_FINGERPRINT
	http_request {
		method: GET
		uri: "/health"
		response {
			http_status: 200
		}
	}
}
actions {
	name: "check_version"
	action_phase: ACTION_PHASE_FINGERPRINT
	http_request {
		method: GET
		uri: "/version"
		response {
			http_status: 200
		}
	}
}
actions {
	name: "attempt_login"
	http_request {
		method: POST
		uri: "/login"
		data: "user={{ T_USERNAME }}&pass={{ T_PASSWORD }}"
		response {
			http_status: 200
			expect_all {
				conditions {
					contains: "Welcome {{ T_USERNAME }}"
					body {}
				}
			}
		}
	}
}
`

func TestTemplatedWeakCredentialsDetector(t *testing.T) {
	l := &log.DefaultLogger{VerboseLevel: log.DebugLevelRequest}
	log.SetLogger(l)

	tests := []struct {
		name                string
		pluginProtoText     string
		responseFunc        func(w http.ResponseWriter, r *http.Request)
		bfCfg               *bfpb.BruteForceConfig
		customServiceSetup  func(ts *httptest.Server) *nspb.NetworkService
		expectVulnerability bool
		expectError         bool
		wantBudgetExhausted int64
		wantDetails         []string
	}{
		{
			name:            "when_valid_credentials_exist_detection_reports_are_generated",
			pluginProtoText: mockPluginTextproto,
			responseFunc: requireBodyLoginHandler(map[string]string{
				"user=root&pass=123": "Welcome root",
			}),
			expectVulnerability: true,
			wantDetails:         []string{"root:123"},
		},
		{
			name:            "when_multiple_valid_credentials_exist_stops_at_first_by_default",
			pluginProtoText: mockPluginTextproto,
			responseFunc: requireBodyLoginHandler(map[string]string{
				"user=admin&pass=password": "Welcome admin",
				"user=root&pass=123":       "Welcome root",
			}),
			expectVulnerability: true,
			wantDetails:         []string{"admin:password"},
		},
		{
			name:            "when_stop_at_first_valid_credentials_is_false_collects_all_valid_credentials",
			pluginProtoText: mockPluginTextproto,
			responseFunc: requireBodyLoginHandler(map[string]string{
				"user=admin&pass=password": "Welcome admin",
				"user=root&pass=123":       "Welcome root",
			}),
			bfCfg: bfpb.BruteForceConfig_builder{
				StopAtFirstValidCredentials: proto.Bool(false),
			}.Build(),
			expectVulnerability: true,
			wantDetails:         []string{"admin:password", "root:123"},
		},
		{
			name:                "when_no_valid_credentials_exist_no_detector_reports",
			pluginProtoText:     mockPluginTextproto,
			responseFunc:        requireBodyLoginHandler(nil),
			expectVulnerability: false,
		},
		{
			name:            "when_embedded_credentials_match_successfully_scans",
			pluginProtoText: mockPluginTextproto,
			responseFunc: requireBodyLoginHandler(map[string]string{
				"user=admin&pass=password": "Welcome admin",
			}),
			expectVulnerability: true,
		},
		{
			name:            "when_password_only_authentication_configured_successfully_scans",
			pluginProtoText: mockPasswordOnlyPluginTextproto,
			responseFunc: requireBodyLoginHandler(map[string]string{
				"pass=secret_password": "Welcome User",
			}),
			expectVulnerability: true,
		},
		{
			name:            "when_service_is_invalid_returns_fatal_error",
			pluginProtoText: mockPluginTextproto,
			responseFunc: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			},
			customServiceSetup: func(ts *httptest.Server) *nspb.NetworkService {
				return &nspb.NetworkService{}
			},
			expectError: true,
		},
		{
			name:                "when_workflow_condition_not_met_skips_and_produces_no_reports",
			pluginProtoText:     mockCallbackRequiredPluginTextproto,
			responseFunc:        acceptAnyLogin,
			expectVulnerability: false,
		},
		{
			name:            "when_max_attempts_reached_aborts_detection",
			pluginProtoText: mockPluginTextproto,
			responseFunc:    succeedOnAttemptLoginHandler(2, "Welcome admin"),
			bfCfg: bfpb.BruteForceConfig_builder{
				MaxAttemptsPerService: proto.Int32(1),
			}.Build(),
			expectVulnerability: false,
			wantBudgetExhausted: 1,
		},
		{
			name:            "when_fingerprinting_fails_returns_no_reports_without_login_attempt",
			pluginProtoText: mockFingerprintedPluginTextproto,
			responseFunc: func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/health":
					w.WriteHeader(http.StatusOK)
				case "/version":
					w.WriteHeader(http.StatusNotFound)
				default:
					acceptAnyLogin(w, r)
				}
			},
			bfCfg: bfpb.BruteForceConfig_builder{
				MaxAttemptsPerService: proto.Int32(1),
			}.Build(),
			expectVulnerability: false,
			wantBudgetExhausted: 0,
		},
		{
			name:                "when_fingerprinting_succeeds_runs_fingerprint_once_and_detects_weak_credentials",
			pluginProtoText:     mockFingerprintedPluginTextproto,
			responseFunc:        fingerprintOnceLoginHandler("user=root&pass=123", "Welcome root"),
			expectVulnerability: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()

			collector := metrics.NewCollector()
			metrics.SetRecorder(collector)
			t.Cleanup(func() { metrics.SetRecorder(nil) })

			var pluginProto tpb.TemplatedPlugin
			if err := prototext.Unmarshal([]byte(tc.pluginProtoText), &pluginProto); err != nil {
				t.Fatalf("Failed to parse mock plugin: %v", err)
			}

			bfCfg := bfpb.BruteForceConfig_builder{
				MaxRequestsPerSecond: proto.Int32(0),
			}.Build()
			if tc.bfCfg != nil {
				proto.Merge(bfCfg, tc.bfCfg)
			}
			cfg := config.FromProto(cpb.Config_builder{
				Plugins: cpb.PluginsConfig_builder{
					Bruteforce: bfCfg,
				}.Build(),
			}.Build())
			if err := callbackserver.Initialize(ctx, cfg); err != nil {
				t.Fatalf("Failed to initialize callback server client: %v", err)
			}

			ts := httptest.NewServer(http.HandlerFunc(tc.responseFunc))
			defer ts.Close()

			var service *nspb.NetworkService
			if tc.customServiceSetup != nil {
				service = tc.customServiceSetup(ts)
			} else {
				var err error
				service, err = faketemplated.ServiceForServer(ts)
				if err != nil {
					t.Fatalf("ServiceForServer() failed: %v", err)
				}
			}

			env := environment.New(cfg)
			env.InitializeFor(ctx, service)

			store, err := credentialstore.NewWithDefaults()
			if err != nil {
				if tc.expectError {
					return
				}
				t.Fatalf("credentialstore.NewWithDefaults() failed: %v", err)
			}

			detector, err := NewFromProto(ctx, cfg, &pluginProto, store)
			if tc.expectError {
				if err != nil {
					return
				}
				_, err = detector.Detect(ctx, service)
				if err == nil {
					t.Fatalf("Expected detection or detector creation to error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("Failed to create detector: %v", err)
			}

			expectedName := fmt.Sprintf("dt/wktpl/%s", pluginProto.GetInfo().GetName())
			if detector.Name() != expectedName {
				t.Errorf("Expected detector name %q, got %q", expectedName, detector.Name())
			}

			reports, err := detector.Detect(ctx, service)
			if err != nil {
				t.Fatalf("Detect failed: %v", err)
			}

			hasVob := reports != nil && len(reports.GetDetectionReports()) > 0
			if hasVob != tc.expectVulnerability {
				t.Errorf("Detect() hasVulnerability = %v, want %v", hasVob, tc.expectVulnerability)
			}

			if tc.wantDetails != nil {
				var gotDetails []string
				for _, r := range reports.GetDetectionReports() {
					for _, ad := range r.GetVulnerability().GetAdditionalDetails() {
						gotDetails = append(gotDetails, ad.GetTextData().GetText())
					}
				}
				if diff := cmp.Diff(tc.wantDetails, gotDetails); diff != "" {
					t.Errorf("Detect() AdditionalDetails mismatch (-want +got):\n%s", diff)
				}
			}

			budget := collector.Value(ctx, metrics.BudgetExhausted,
				metrics.Module(detector.Name()),
				metrics.LimitName(metrics.LimitMaxAttemptsPerService))
			if budget != tc.wantBudgetExhausted {
				t.Errorf("budget/exhausted = %d, want %d", budget, tc.wantBudgetExhausted)
			}
		})
	}
}

func requireBodyLoginHandler(validBodies map[string]string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		if welcomeMsg, ok := validBodies[string(bodyBytes)]; ok {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, welcomeMsg)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "Unauthorized")
	}
}

func succeedOnAttemptLoginHandler(succeedAttempt int, welcomeMsg string) http.HandlerFunc {
	var attempts int
	return func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts >= succeedAttempt {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, welcomeMsg)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "Unauthorized")
	}
}

func fingerprintOnceLoginHandler(validBody, welcomeMsg string) http.HandlerFunc {
	var healthChecks, versionChecks int
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			healthChecks++
			if healthChecks > 1 {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
		case "/version":
			versionChecks++
			if versionChecks > 1 {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
		case "/login":
			if healthChecks != 1 || versionChecks != 1 {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			bodyBytes, _ := io.ReadAll(r.Body)
			if strings.Contains(string(bodyBytes), validBody) {
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, welcomeMsg)
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

// acceptAnyLogin answers every request with the welcome message that the mock plugins expect for
// the submitted user (form data "user=<user>&pass=<password>"), so any login attempt is a success.
func acceptAnyLogin(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	userField, _, _ := strings.Cut(string(body), "&")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Welcome %s", strings.TrimPrefix(userField, "user="))
}

func TestDetectors(t *testing.T) {
	l := &log.DefaultLogger{VerboseLevel: log.DebugLevelRequest}
	log.SetLogger(l)

	plugins, tests, err := faketemplated.LoadPluginsAndTests(pluginFilesFS)
	if err != nil {
		t.Fatalf("Failed to load unit tests: %v", err)
	}

	if len(tests) == 0 {
		t.Log("No templated weak credential plugin tests found")
		return
	}

	for testPath, testProto := range tests {
		pluginName := testProto.GetConfig().GetTestedPlugin()
		plugin, ok := plugins[pluginName]
		if !ok {
			t.Errorf("Test %s references unknown plugin %s", testPath, pluginName)
			continue
		}

		t.Run(pluginName, func(t *testing.T) {
			for _, tc := range testProto.GetTests() {
				t.Run(tc.GetName(), func(t *testing.T) {
					runTestCase(t, plugin, tc)
				})
			}
		})
	}
}

func runTestCase(t *testing.T, plugin *tpb.TemplatedPlugin, tc *ttpb.TemplatedPluginTests_Test) {
	ctx := t.Context()
	cfgProto := cpb.Config_builder{
		Plugins: cpb.PluginsConfig_builder{
			Bruteforce: bfpb.BruteForceConfig_builder{
				MaxRequestsPerSecond: proto.Int32(0),
			}.Build(),
		}.Build(),
	}.Build()
	mockCBS := tc.GetMockCallbackServer()
	tcsmock := fakecallbackserver.NewServer(mockCBS.GetEnabled(), mockCBS.GetHasInteraction(), false)
	defer tcsmock.Close()

	if mockCBS.GetEnabled() {
		cfgProto.SetClients(tcsmock.ClientsConfig())
	}

	cfg := config.FromProto(cfgProto)
	if err := callbackserver.Initialize(ctx, cfg); err != nil {
		t.Fatalf("Failed to initialize callback server client: %v", err)
	}

	env := environment.New(cfg)
	env.Set(environment.VarTestingDisableSleep, "true")
	httpmock := faketemplated.NewHTTPServer(ctx, tc.GetMockHttpServer(), env)
	defer httpmock.Close()

	service, err := faketemplated.ServiceForServer(httpmock)
	if err != nil {
		t.Fatalf("ServiceForServer() failed: %v", err)
	}
	env.InitializeFor(ctx, service)

	detector, err := newDetectorForTesting(ctx, cfg, plugin, env)
	if err != nil {
		t.Fatalf("Failed to create detector: %v", err)
	}

	reports, err := detector.Detect(ctx, service)
	if err != nil {
		t.Fatalf("%s Detect() failed: %v", plugin.GetInfo().GetName(), err)
	}

	hasVulnerability := len(reports.GetDetectionReports()) > 0
	if hasVulnerability != tc.GetExpectVulnerability() {
		t.Errorf("Detect() hasVulnerability = %v, want %v", hasVulnerability, tc.GetExpectVulnerability())
	}
}

func newDetectorForTesting(ctx context.Context, cfg *config.Config, pluginProto *tpb.TemplatedPlugin, env *environment.Environment) (module.VulnDetector, error) {
	baseDetector, err := templatedengine.NewForTesting(ctx, cfg, pluginProto, env)
	if err != nil {
		return nil, err
	}

	store, err := credentialstore.NewWithDefaults()
	if err != nil {
		return nil, err
	}

	return newDetector(ctx, cfg, pluginProto, baseDetector, store)
}
