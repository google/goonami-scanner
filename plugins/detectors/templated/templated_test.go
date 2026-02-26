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

package templated

import (
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
	goohttp "github.com/google/goonami-scanner/core/net/http"
	"google.golang.org/protobuf/encoding/prototext"

	cpb "github.com/google/goonami-scanner/core/config/config_go_proto"
	cbpb "github.com/google/goonami-scanner/tools/callbackserver/callbackserver_config_go_proto"
	tpb "github.com/google/tsunami-security-scanner-plugins/templated/templateddetector/proto/templated_plugin_go_proto"
	ttpb "github.com/google/tsunami-security-scanner-plugins/templated/templateddetector/proto/templated_plugin_go_proto"
	npb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
)

func TestDetectors(t *testing.T) {
	// Note: this set of tests can be tricky to debug, because there is no obvious feedback apart from
	// a generic failure message. As such, we allow ourselves to enforce the core engine of Goonami
	// to perform maximum level logging for this test.
	l := &log.DefaultLogger{VerboseLevel: log.DebugLevelRequest}
	log.SetLogger(l)

	cfg := config.Default()
	if err := goohttp.InitializeDefaults(cfg); err != nil {
		t.Fatalf("Failed to initialize HTTP client: %v", err)
	}

	plugins, tests, err := loadPluginsAndTests(t)
	if err != nil {
		return
	}

	if len(tests) == 0 {
		t.Log("No templated plugin tests found")
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

	httpClient := goohttp.DefaultClient()
	service := serviceForMockHTTPServer(t, httpmock)
	env.InitializeFor(ctx, service)

	detector, err := templatedengine.NewForTesting(ctx, cfg, plugin, httpClient, env)
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

	if len(cond.GetBodyContent()) == 0 {
		return true
	}

	body, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(strings.NewReader(string(body)))
	bodyStr := string(body)

	for _, content := range cond.GetBodyContent() {
		if !strings.Contains(bodyStr, env.Substitute(ctx, content)) {
			return false
		}
	}

	return true
}

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
			Hostname: npb.Hostname_builder{Name: host}.Build(),
			Port:     npb.Port_builder{PortNumber: uint32(port)}.Build(),
		}.Build(),
		ServiceName:          "http",
		SupportedHttpMethods: []string{"GET", "POST", "PUT", "DELETE", "HEAD"},
	}.Build()
}
