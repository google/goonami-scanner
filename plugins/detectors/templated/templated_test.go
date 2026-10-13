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
	"errors"
	"testing"

	"github.com/google/goonami-scanner/common/clients/callbackserver"
	"github.com/google/goonami-scanner/common/templatedengine"
	"github.com/google/goonami-scanner/common/templatedengine/actions"
	"github.com/google/goonami-scanner/common/templatedengine/environment"
	"github.com/google/goonami-scanner/common/testfakes/fakecallbackserver"
	"github.com/google/goonami-scanner/common/testfakes/faketemplated"
	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/log"
	_ "github.com/google/goonami-scanner/core/net/http/simpleclient"

	tpb "github.com/google/tsunami-security-scanner-plugins/templated/templateddetector/proto/templated_plugin_go_proto"
	ttpb "github.com/google/tsunami-security-scanner-plugins/templated/templateddetector/proto/templated_plugin_go_proto"
)

func TestDetectors(t *testing.T) {
	// Note: this set of tests can be tricky to debug, because there is no obvious feedback apart from
	// a generic failure message. As such, we allow ourselves to enforce the core engine of Goonami
	// to perform maximum level logging for this test.
	l := &log.DefaultLogger{VerboseLevel: log.DebugLevelRequest}
	log.SetLogger(l)

	plugins, tests, err := faketemplated.LoadPluginsAndTests(pluginFilesFS)
	if err != nil {
		t.Fatalf("Failed to load unit tests: %v", err)
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

func runTestCase(t *testing.T, plugin *tpb.TemplatedPlugin, tc *ttpb.TemplatedPluginTests_Test) {
	ctx := t.Context()
	cfgProto := config.DefaultProto()
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

	detector, err := templatedengine.NewForTesting(ctx, cfg, plugin, env)
	if err != nil {
		t.Fatalf("Failed to create detector: %v", err)
	}

	// Note: we use DetectWithVariables to explicitly surface errors hidden by the engine.
	reports, err := detector.DetectWithVariables(ctx, service, nil)
	if err != nil {
		if errors.Is(err, actions.ErrActionFailed) {
			if tc.GetExpectVulnerability() {
				t.Fatalf("Detect() action failed, expected a vulnerability: %v", err)
			}

			return
		}

		t.Fatalf("Detect() returned unexpected error: %v", err)
	}

	hasVulnerability := len(reports.GetDetectionReports()) > 0
	if hasVulnerability != tc.GetExpectVulnerability() {
		t.Errorf("Detect() hasVulnerability = %v, want %v", hasVulnerability, tc.GetExpectVulnerability())
	}
}
