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

package entrypoint

import (
	"context"
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/goonami-scanner/common/testfakes/fakemodule"
	"github.com/google/goonami-scanner/common/testfakes/fakerunner"
	"github.com/google/goonami-scanner/core/config"
	cpb "github.com/google/goonami-scanner/core/config/config_go_proto"
	"github.com/google/goonami-scanner/core/module"
	_ "github.com/google/goonami-scanner/core/net/http/simpleclient"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"

	srpb "github.com/google/tsunami-security-scanner/proto/go/scan_results_go_proto"
)

type fakeHTTPClient struct{}

func (m *fakeHTTPClient) Get(url string) (*http.Response, error)  { return nil, nil }
func (m *fakeHTTPClient) Head(url string) (*http.Response, error) { return nil, nil }
func (m *fakeHTTPClient) Post(url string, contentType string, body io.Reader) (*http.Response, error) {
	return nil, nil
}
func (m *fakeHTTPClient) Do(req *http.Request) (*http.Response, error) { return nil, nil }

func TestNewWhenDefaultRunner(t *testing.T) {
	module.ClearRegistry()
	module.RegisterPortScanner("ps1", fakemodule.InitFakePortScanner("ps1", nil, fakemodule.FakePortScanFnDoNothing))

	cfg := config.FromProto(cpb.Config_builder{
		Workflowcfg: cpb.WorkflowConfiguration_builder{
			Portscan: proto.String("ps1"),
		}.Build(),
	}.Build())
	cfg.CreateDirectories(t.TempDir())
	defer cfg.Close(t.Context())

	opts := &Options{
		Config: cfg,
	}

	e, err := New(t.Context(), opts)
	if err != nil {
		t.Fatalf("New(%v) returned unexpected error: %v", opts, err)
	}

	if e.runner == nil {
		t.Errorf("New(%v) did not create a default runner", opts)
	}
}

func TestNewWhenPluginRegistration(t *testing.T) {
	cfgProto := cpb.Config_builder{
		Workflowcfg: cpb.WorkflowConfiguration_builder{
			Portscan: proto.String("ps1"),
			Fingerprinters: cpb.WorkflowConfiguration_ModuleFilter_builder{
				Require: []string{"fp1"},
			}.Build(),
			Detectors: cpb.WorkflowConfiguration_ModuleFilter_builder{
				Require: []string{"d1"},
			}.Build(),
		}.Build(),
	}.Build()

	genericErr := errors.New("generic error")

	tests := []struct {
		name     string
		setupReg func()
		wantErr  error
	}{
		{
			name: "when_modules_are_successfully_initialized_they_are_registered",
			setupReg: func() {
				module.RegisterPortScanner("ps1", fakemodule.InitFakePortScanner("ps1", nil, fakemodule.FakePortScanFnDoNothing))
				module.RegisterFingerprinter("fp1", fakemodule.InitFakeFingerprinter("fp1", nil, fakemodule.FakeFingerprintFnDoNothing))
				module.RegisterDetector("d1", fakemodule.InitFakeVulnDetector("d1", nil, fakemodule.FakeDetectFnNoFindings))
			},
			wantErr: nil,
		},
		{
			name: "when_port_scanner_init_fails_returns_error",
			setupReg: func() {
				module.RegisterPortScanner("ps1", fakemodule.InitFakePortScanner("ps1", genericErr, fakemodule.FakePortScanFnDoNothing))
				module.RegisterFingerprinter("fp1", fakemodule.InitFakeFingerprinter("fp1", nil, fakemodule.FakeFingerprintFnDoNothing))
				module.RegisterDetector("d1", fakemodule.InitFakeVulnDetector("d1", nil, fakemodule.FakeDetectFnNoFindings))
			},
			wantErr: genericErr,
		},
		{
			name: "when_fingerprinter_init_fails_returns_error",
			setupReg: func() {
				module.RegisterPortScanner("ps1", fakemodule.InitFakePortScanner("ps1", nil, fakemodule.FakePortScanFnDoNothing))
				module.RegisterFingerprinter("fp1", fakemodule.InitFakeFingerprinter("fp1", genericErr, fakemodule.FakeFingerprintFnDoNothing))
				module.RegisterDetector("d1", fakemodule.InitFakeVulnDetector("d1", nil, fakemodule.FakeDetectFnNoFindings))
			},
			wantErr: genericErr,
		},
		{
			name: "when_detector_init_fails_returns_error",
			setupReg: func() {
				module.RegisterPortScanner("ps1", fakemodule.InitFakePortScanner("ps1", nil, fakemodule.FakePortScanFnDoNothing))
				module.RegisterFingerprinter("fp1", fakemodule.InitFakeFingerprinter("fp1", nil, fakemodule.FakeFingerprintFnDoNothing))
				module.RegisterDetector("d1", fakemodule.InitFakeVulnDetector("d1", genericErr, fakemodule.FakeDetectFnNoFindings))
			},
			wantErr: genericErr,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			module.ClearRegistry()
			tc.setupReg()

			cfg := config.FromProto(cfgProto)
			cfg.CreateDirectories(t.TempDir())
			defer cfg.Close(t.Context())

			runner := fakerunner.New()
			opts := &Options{
				Config: cfg,
				Runner: runner,
			}
			_, err := New(t.Context(), opts)

			if !errors.Is(err, tc.wantErr) {
				t.Errorf("New(%v) error = %v, wantErr %v", opts, err, tc.wantErr)
			}
			if tc.wantErr != nil {
				return
			}

			if err != nil {
				t.Fatalf("New(%v) returned unexpected error: %v", opts, err)
			}

			if runner.PortScanner() == nil || runner.PortScanner().Name() != "ps1" {
				t.Errorf("New(%v) did not register port scanner correctly, got %+v", opts, runner.PortScanner())
			}

			if len(runner.Fingerprinters()) != 1 || runner.Fingerprinters()[0].Name() != "fp1" {
				t.Errorf("New(%v) did not register fingerprinters correctly, got %+v", opts, runner.Fingerprinters())
			}

			if len(runner.Detectors()) != 1 || runner.Detectors()[0].Name() != "d1" {
				t.Errorf("New(%v) did not register detectors correctly, got %+v", opts, runner.Detectors())
			}
		})
	}
}

func TestNew_ErrorCases(t *testing.T) {
	tests := []struct {
		name    string
		options *Options
	}{
		{
			name: "when_config_is_nil_simplerunner_init_fails_returns_error",
			options: &Options{
				Config: nil,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(t.Context(), tc.options); err == nil {
				t.Errorf("New(%v) returned no error, want error", tc.options)
			}
		})
	}
}

func TestRun(t *testing.T) {
	tests := []struct {
		name      string
		runnerErr error
		report    *srpb.ScanResults
	}{
		{
			name: "when_runner_succeeds_returns_report",
			report: srpb.ScanResults_builder{
				ScanStatus: srpb.ScanStatus_SUCCEEDED,
			}.Build(),
			runnerErr: nil,
		},
		{
			name:      "when_runner_fails_returns_error",
			report:    nil,
			runnerErr: errors.New("runner failure"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			module.ClearRegistry()
			module.RegisterPortScanner("ps1", fakemodule.InitFakePortScanner("ps1", nil, fakemodule.FakePortScanFnDoNothing))

			cfg := config.FromProto(cpb.Config_builder{
				Workflowcfg: cpb.WorkflowConfiguration_builder{
					Portscan: proto.String("ps1"),
				}.Build(),
			}.Build())
			cfg.CreateDirectories(t.TempDir())
			defer cfg.Close(t.Context())

			runner := fakerunner.New()
			runner.OverrideRun(func(ctx context.Context, target string) (s *srpb.ScanResults, err error) {
				return tc.report, tc.runnerErr
			})

			opts := &Options{
				Config: cfg,
				Runner: runner,
			}
			e, err := New(t.Context(), opts)
			if err != nil {
				t.Fatalf("New(%v) returned unexpected error: %v", opts, err)
			}

			report, err := e.Run(t.Context(), "fake-target")
			if !errors.Is(err, tc.runnerErr) {
				t.Errorf("Run() returned unexpected error: %v, want %v", err, tc.runnerErr)
			}

			if tc.runnerErr != nil {
				return
			}

			if diff := cmp.Diff(tc.report, report, protocmp.Transform()); diff != "" {
				t.Errorf("Run() returned unexpected diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestArtifacts(t *testing.T) {
	module.ClearRegistry()
	module.RegisterPortScanner("ps1", fakemodule.InitFakePortScanner("ps1", nil, fakemodule.FakePortScanFnDoNothing))

	cfg := config.FromProto(cpb.Config_builder{
		Workflowcfg: cpb.WorkflowConfiguration_builder{
			Portscan: proto.String("ps1"),
		}.Build(),
	}.Build())
	cfg.CreateDirectories(t.TempDir())
	defer cfg.Close(t.Context())

	artifactsDir := cfg.ArtifactsDirectory()
	opts := &Options{
		Config: cfg,
	}

	e, err := New(t.Context(), opts)
	if err != nil {
		t.Fatalf("New(%v) returned unexpected error: %v", opts, err)
	}

	if e.Artifacts() != artifactsDir {
		t.Errorf("Artifacts() = %s, want %s", e.Artifacts(), artifactsDir)
	}
}

func TestNewWithWorkflowConfiguration(t *testing.T) {
	tests := []struct {
		name        string
		setupReg    func()
		workflowcfg *cpb.WorkflowConfiguration
		wantErr     bool
	}{
		{
			name: "when_workflow_config_is_used_modules_are_loaded_from_registry",
			setupReg: func() {
				module.RegisterPortScanner("ps1", fakemodule.InitFakePortScanner("ps1", nil, fakemodule.FakePortScanFnDoNothing))
				module.RegisterFingerprinter("fp1", fakemodule.InitFakeFingerprinter("fp1", nil, fakemodule.FakeFingerprintFnDoNothing))
				module.RegisterDetector("d1", fakemodule.InitFakeVulnDetector("d1", nil, fakemodule.FakeDetectFnNoFindings))
			},
			workflowcfg: cpb.WorkflowConfiguration_builder{
				Portscan: proto.String("ps1"),
				Fingerprinters: cpb.WorkflowConfiguration_ModuleFilter_builder{
					Require: []string{"fp1"},
				}.Build(),
				Detectors: cpb.WorkflowConfiguration_ModuleFilter_builder{
					Require: []string{"d1"},
				}.Build(),
			}.Build(),
			wantErr: false,
		},
		{
			name: "when_workflow_config_has_non_existent_module_it_fails",
			setupReg: func() {
				module.RegisterPortScanner("ps1", fakemodule.InitFakePortScanner("ps1", nil, fakemodule.FakePortScanFnDoNothing))
			},
			workflowcfg: cpb.WorkflowConfiguration_builder{
				Portscan: proto.String("ps1"),
				Fingerprinters: cpb.WorkflowConfiguration_ModuleFilter_builder{
					Require: []string{"non-existent"},
				}.Build(),
			}.Build(),
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			module.ClearRegistry()
			tc.setupReg()

			cfg := config.FromProto(cpb.Config_builder{
				Workflowcfg: tc.workflowcfg,
			}.Build())
			cfg.CreateDirectories(t.TempDir())
			defer cfg.Close(t.Context())

			runner := fakerunner.New()
			opts := &Options{
				Config: cfg,
				Runner: runner,
			}

			_, err := New(t.Context(), opts)
			if (err != nil) != tc.wantErr {
				t.Fatalf("New() error = %v, wantErr %v", err, tc.wantErr)
			}

			if tc.wantErr {
				return
			}

			if runner.PortScanner() == nil || runner.PortScanner().Name() != "ps1" {
				t.Errorf("expected ps1 port scanner, got %+v", runner.PortScanner())
			}
			if len(runner.Fingerprinters()) != 1 || runner.Fingerprinters()[0].Name() != "fp1" {
				t.Errorf("expected fp1 fingerprinter, got %+v", runner.Fingerprinters())
			}
			if len(runner.Detectors()) != 1 || runner.Detectors()[0].Name() != "d1" {
				t.Errorf("expected d1 detector, got %+v", runner.Detectors())
			}
		})
	}
}
