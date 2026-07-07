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

// Package templatedweakcredentials provides tests for the templatedweakcredentials detector.
package templatedweakcredentials

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/goonami-scanner/common/clients/callbackserver"
	"github.com/google/goonami-scanner/common/templatedengine"
	"github.com/google/goonami-scanner/common/templatedengine/environment"
	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/log"
	"github.com/google/goonami-scanner/core/module"
	_ "github.com/google/goonami-scanner/core/net/http/simpleclient"
	"google.golang.org/protobuf/encoding/prototext"

	cpb "github.com/google/goonami-scanner/core/config/config_go_proto"
	twcpb "github.com/google/goonami-scanner/plugins/detectors/templatedweakcredentials/templatedweakcredentials_config_go_proto"
	cbpb "github.com/google/goonami-scanner/tools/callbackserver/callbackserver_config_go_proto"
	tpb "github.com/google/tsunami-security-scanner-plugins/templated/templateddetector/proto/templated_plugin_go_proto"
	ttpb "github.com/google/tsunami-security-scanner-plugins/templated/templateddetector/proto/templated_plugin_go_proto"
	npb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
)

const mockPluginTextproto = `
info {
	name: "MockWeakCreds"
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

func serviceForMockHTTPServer(t *testing.T, httpmock *httptest.Server) *nspb.NetworkService {
	t.Helper()

	url := strings.TrimPrefix(httpmock.URL, "http://")
	hostPort := strings.Split(url, ":")

	if len(hostPort) != 2 {
		t.Fatalf("Failed to parse host and port from URL of mock HTTP server: %s", url)
	}

	host := hostPort[0]
	port := 80
	if len(hostPort) > 1 {
		fmt.Sscanf(hostPort[1], "%d", &port)
	}

	return nspb.NetworkService_builder{
		NetworkEndpoint: npb.NetworkEndpoint_builder{
			Type: npb.NetworkEndpoint_IP_PORT,
			IpAddress: npb.IpAddress_builder{
				AddressFamily: npb.AddressFamily_IPV4,
				Address:       host,
			}.Build(),
			Port: npb.Port_builder{
				PortNumber: uint32(port),
			}.Build(),
		}.Build(),
		ServiceName:          "http",
		SupportedHttpMethods: []string{"GET", "POST", "PUT", "DELETE", "HEAD"},
	}.Build()
}

func TestTemplatedWeakCredentialsDetector(t *testing.T) {
	l := &log.DefaultLogger{VerboseLevel: log.DebugLevelRequest}
	log.SetLogger(l)

	ctx := context.Background()

	tests := []struct {
		name                string
		pluginProtoText     string
		responseFunc        func(w http.ResponseWriter, r *http.Request)
		configSetup         func() *config.Config
		customServiceSetup  func(ts *httptest.Server) *nspb.NetworkService
		expectVulnerability bool
		expectError         bool
	}{
		{
			name:            "when_valid_credentials_exist_detection_reports_are_generated",
			pluginProtoText: mockPluginTextproto,
			responseFunc: func(w http.ResponseWriter, r *http.Request) {
				bodyBytes, _ := io.ReadAll(r.Body)
				bodyString := string(bodyBytes)
				if strings.Contains(bodyString, "user=root&pass=123") {
					w.WriteHeader(http.StatusOK)
					fmt.Fprint(w, "Welcome root")
					return
				}
				w.WriteHeader(http.StatusUnauthorized)
				fmt.Fprint(w, "Unauthorized")
			},
			configSetup: func() *config.Config {
				return config.Default()
			},
			expectVulnerability: true,
		},
		{
			name:            "when_no_valid_credentials_exist_no_detector_reports",
			pluginProtoText: mockPluginTextproto,
			responseFunc: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
				fmt.Fprint(w, "Unauthorized")
			},
			configSetup: func() *config.Config {
				return config.Default()
			},
			expectVulnerability: false,
		},
		{
			name:            "when_external_username_and_password_files_configured_successfully_scans",
			pluginProtoText: mockPluginTextproto,
			responseFunc: func(w http.ResponseWriter, r *http.Request) {
				bodyBytes, _ := io.ReadAll(r.Body)
				bodyString := string(bodyBytes)
				if strings.Contains(bodyString, "user=admin&pass=password") {
					w.WriteHeader(http.StatusOK)
					fmt.Fprint(w, "Welcome admin")
					return
				}
				w.WriteHeader(http.StatusUnauthorized)
				fmt.Fprint(w, "Unauthorized")
			},
			configSetup: func() *config.Config {
				twcCfg := twcpb.TemplatedWeakCredentialsConfig_builder{
					UsernameFile:  stringPtr("data/usernames.txt"),
					PasswordsFile: stringPtr("data/passwords.txt"),
				}.Build()
				pluginsCfg := cpb.PluginsConfig_builder{
					Templatedweakcredentials: twcCfg,
				}.Build()
				cfgProto := cpb.Config_builder{
					Plugins: pluginsCfg,
				}.Build()
				return config.FromProto(cfgProto)
			},
			expectVulnerability: true,
		},
		{
			name:            "when_nonexistent_files_configured_new_from_proto_fails",
			pluginProtoText: mockPluginTextproto,
			responseFunc: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			},
			configSetup: func() *config.Config {
				twcCfg := twcpb.TemplatedWeakCredentialsConfig_builder{
					UsernameFile: stringPtr("nonexistent_user_file.txt"),
				}.Build()
				pluginsCfg := cpb.PluginsConfig_builder{
					Templatedweakcredentials: twcCfg,
				}.Build()
				cfgProto := cpb.Config_builder{
					Plugins: pluginsCfg,
				}.Build()
				return config.FromProto(cfgProto)
			},
			expectError: true,
		},
		{
			name:            "when_password_only_authentication_configured_successfully_scans",
			pluginProtoText: mockPasswordOnlyPluginTextproto,
			responseFunc: func(w http.ResponseWriter, r *http.Request) {
				bodyBytes, _ := io.ReadAll(r.Body)
				bodyString := string(bodyBytes)
				if bodyString == "pass=secret_password" {
					w.WriteHeader(http.StatusOK)
					fmt.Fprint(w, "Welcome User")
					return
				}
				w.WriteHeader(http.StatusUnauthorized)
			},
			configSetup: func() *config.Config {
				return config.Default()
			},
			expectVulnerability: true,
		},
		{
			name:            "when_service_is_invalid_returns_fatal_error",
			pluginProtoText: mockPluginTextproto,
			responseFunc: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			},
			configSetup: func() *config.Config {
				return config.Default()
			},
			customServiceSetup: func(ts *httptest.Server) *nspb.NetworkService {
				return &nspb.NetworkService{}
			},
			expectError: true,
		},
		{
			name:            "when_workflow_condition_not_met_skips_and_produces_no_reports",
			pluginProtoText: mockCallbackRequiredPluginTextproto,
			responseFunc: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			},
			configSetup: func() *config.Config {
				return config.Default()
			},
			expectVulnerability: false,
		},
		{
			name:            "when_max_attempts_reached_aborts_detection",
			pluginProtoText: mockPluginTextproto,
			responseFunc: func() func(w http.ResponseWriter, r *http.Request) {
				var attempts int
				return func(w http.ResponseWriter, r *http.Request) {
					attempts++
					if attempts >= 2 {
						w.WriteHeader(http.StatusOK)
						fmt.Fprint(w, "Welcome admin")
						return
					}
					w.WriteHeader(http.StatusUnauthorized)
					fmt.Fprint(w, "Unauthorized")
				}
			}(),
			configSetup: func() *config.Config {
				twcCfg := twcpb.TemplatedWeakCredentialsConfig_builder{
					MaxAttemptsPerService: int32Ptr(1),
				}.Build()
				pluginsCfg := cpb.PluginsConfig_builder{
					Templatedweakcredentials: twcCfg,
				}.Build()
				cfgProto := cpb.Config_builder{
					Plugins: pluginsCfg,
				}.Build()
				return config.FromProto(cfgProto)
			},
			expectVulnerability: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var pluginProto tpb.TemplatedPlugin
			if err := prototext.Unmarshal([]byte(tc.pluginProtoText), &pluginProto); err != nil {
				t.Fatalf("Failed to parse mock plugin: %v", err)
			}

			cfg := tc.configSetup()
			if err := callbackserver.Initialize(ctx, cfg); err != nil {
				t.Fatalf("Failed to initialize callback server client: %v", err)
			}

			ts := httptest.NewServer(http.HandlerFunc(tc.responseFunc))
			defer ts.Close()

			var service *nspb.NetworkService
			if tc.customServiceSetup != nil {
				service = tc.customServiceSetup(ts)
			} else {
				service = serviceForMockHTTPServer(t, ts)
			}

			env := environment.New(cfg)
			env.InitializeFor(ctx, service)

			store := NewCredentialStore()
			err := store.LoadFromConfigOnce(ctx, cfg)
			if err != nil {
				if tc.expectError {
					return
				}
				t.Fatalf("LoadCredentialsFromConfig failed: %v", err)
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
		})
	}
}

func stringPtr(s string) *string {
	return &s
}

func int32Ptr(i int32) *int32 {
	return &i
}

func TestDetectors(t *testing.T) {
	l := &log.DefaultLogger{VerboseLevel: log.DebugLevelRequest}
	log.SetLogger(l)

	plugins, tests, err := loadPluginsAndTests(t)
	if err != nil {
		return
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

func loadPluginsAndTests(t *testing.T) (map[string]*tpb.TemplatedPlugin, map[string]*ttpb.TemplatedPluginTests, error) {
	t.Helper()

	plugins := make(map[string]*tpb.TemplatedPlugin)
	tests := make(map[string]*ttpb.TemplatedPluginTests)

	err := fs.WalkDir(pluginFilesFS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() || filepath.Ext(path) != ".textproto" {
			return nil
		}

		content, err := pluginFilesFS.ReadFile(path)
		if err != nil {
			return nil
		}

		if strings.HasSuffix(path, "_test.textproto") {
			test := &ttpb.TemplatedPluginTests{}
			if err := prototext.Unmarshal(content, test); err != nil {
				return err
			}

			tests[path] = test
			return nil
		}

		plugin := &tpb.TemplatedPlugin{}
		if err := prototext.Unmarshal(content, plugin); err != nil {
			return err
		}

		plugins[plugin.GetInfo().GetName()] = plugin
		return nil
	})

	if err != nil {
		t.Fatalf("Failed to load unit tests: %v", err)
		return nil, nil, err
	}

	return plugins, tests, nil
}

func runTestCase(t *testing.T, plugin *tpb.TemplatedPlugin, tc *ttpb.TemplatedPluginTests_Test) {
	ctx := t.Context()
	cfgProto := config.DefaultProto()
	tcsmock := callbackServerMock(t, tc)
	defer tcsmock.Close()

	if tc.GetMockCallbackServer().GetEnabled() {
		clicfg := cpb.ClientsConfig_builder{
			CallbackServer: cbpb.CallbackserverConfig_builder{
				HttpPollConfig: cbpb.EndpointConfig_builder{
					PublicUri: tcsmock.URL,
				}.Build(),
				HttpRecordConfig: cbpb.EndpointConfig_builder{
					PublicUri: tcsmock.URL,
				}.Build(),
				DnsRecordConfig: cbpb.EndpointConfig_builder{
					PublicUri: "cb.localhost.lan",
				}.Build(),
			}.Build(),
		}.Build()
		cfgProto.SetClients(clicfg)
	}

	cfg := config.FromProto(cfgProto)
	if err := callbackserver.Initialize(ctx, cfg); err != nil {
		t.Fatalf("Failed to initialize callback server client: %v", err)
	}

	env := environment.New(cfg)
	env.Set(environment.VarTestingDisableSleep, "true")
	httpmock := httpMockServer(t, tc, env)
	defer httpmock.Close()

	service := serviceForMockHTTPServer(t, httpmock)
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

func callbackServerMock(t *testing.T, tc *ttpb.TemplatedPluginTests_Test) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !tc.GetMockCallbackServer().GetEnabled() {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		if !tc.GetMockCallbackServer().GetHasInteraction() {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "{\"hasHttpInteraction\": true}")
	}))
}

func httpMockServer(t *testing.T, tc *ttpb.TemplatedPluginTests_Test, env *environment.Environment) *httptest.Server {
	t.Helper()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := t.Context()
		for _, mockResp := range tc.GetMockHttpServer().GetMockResponses() {
			mockURL := env.Substitute(ctx, mockResp.GetUri())
			// mockURL is the path, i.e. /index.php?foo=bar, so it should start with a "/". But if it is
			// one of the magic strings, it should not have a leading "/".
			if mockURL[0] != '/' && !strings.HasPrefix(mockURL, environment.VarTestingMagicPrefix) {
				mockURL = "/" + mockURL
			}

			if mockURL != environment.VarTestingMagicAnyURI && r.URL.String() != mockURL && r.URL.Path != mockURL {
				continue
			}

			if !matchesConditions(t, r, mockResp.GetCondition(), env) {
				continue
			}

			for _, header := range mockResp.GetHeaders() {
				w.Header().Add(header.GetName(), env.Substitute(ctx, header.GetValue()))
			}

			w.WriteHeader(int(mockResp.GetStatus()))
			fmt.Fprint(w, env.Substitute(ctx, mockResp.GetBodyContent()))
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))

	return ts
}

func matchesConditions(t *testing.T, r *http.Request, cond *ttpb.MockHttpServer_HttpCondition, env *environment.Environment) bool {
	t.Helper()

	if cond == nil {
		return true
	}

	ctx := t.Context()
	for _, header := range cond.GetHeaders() {
		if r.Header.Get(header.GetName()) != env.Substitute(ctx, header.GetValue()) {
			return false
		}
	}

	for _, param := range cond.GetGetParameter() {
		if r.URL.Query().Get(param.GetName()) != env.Substitute(ctx, param.GetValue()) {
			return false
		}
	}

	if cond.GetRequestType() != ttpb.MockHttpServer_UNKNOWN {
		if r.Method != cond.GetRequestType().String() {
			return false
		}
	}

	var bodyStr string
	if len(cond.GetBodyContent()) > 0 {
		body, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(strings.NewReader(string(body)))
		bodyStr = string(body)
	}

	for _, content := range cond.GetBodyContent() {
		if !strings.Contains(bodyStr, env.Substitute(ctx, content)) {
			return false
		}
	}

	return true
}

func newDetectorForTesting(ctx context.Context, cfg *config.Config, pluginProto *tpb.TemplatedPlugin, env *environment.Environment) (module.VulnDetector, error) {
	baseDetector, err := templatedengine.NewForTesting(ctx, cfg, pluginProto, env)
	if err != nil {
		return nil, err
	}

	store := NewCredentialStore()
	if err := store.LoadFromConfigOnce(ctx, cfg); err != nil {
		return nil, err
	}

	d := &Detector{
		cfg:          cfg,
		baseDetector: baseDetector,
		proto:        pluginProto,
		store:        store,
	}

	d.loadCredentials(ctx)

	return d, nil
}
