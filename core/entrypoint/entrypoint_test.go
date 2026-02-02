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
	goohttp "github.com/google/goonami-scanner/core/net/http"
	srpb "github.com/google/tsunami-security-scanner/proto/go/scan_results_go_proto"
	"google.golang.org/protobuf/testing/protocmp"
)

type fakeHTTPClient struct{}

func (m *fakeHTTPClient) Get(url string) (*http.Response, error)  { return nil, nil }
func (m *fakeHTTPClient) Head(url string) (*http.Response, error) { return nil, nil }
func (m *fakeHTTPClient) Post(url string, contentType string, body io.Reader) (*http.Response, error) {
	return nil, nil
}
func (m *fakeHTTPClient) Do(req *http.Request) (*http.Response, error) { return nil, nil }

var defaultConfig = cpb.Config_builder{
	Globalcfg: cpb.GlobalConfig_builder{
		Performance: cpb.GlobalConfig_Performance_builder{
			MaxConcurrency: 1,
		}.Build(),
	}.Build(),
}.Build()

func TestNewWhenSideEffects(t *testing.T) {
	cfg := config.FromProto(defaultConfig)
	cfg.CreateDirectories(t.TempDir())
	defer cfg.Close()

	client := &fakeHTTPClient{}
	opts := &Options{
		Config:      cfg,
		HTTPClient:  client,
		PortScanner: fakemodule.InitFakePortScanner("ps1", nil, fakemodule.FakePortScanFnDoNothing),
	}

	_, err := New(opts)
	if err != nil {
		t.Fatalf("New(%v) returned unexpected error: %v", opts, err)
	}

	if goohttp.DefaultClient() != client {
		t.Errorf("New(%v) did not set HTTP client", opts)
	}
}

func TestNewWhenDefaultRunner(t *testing.T) {
	cfg := config.FromProto(defaultConfig)
	cfg.CreateDirectories(t.TempDir())
	defer cfg.Close()

	opts := &Options{
		Config:      cfg,
		PortScanner: fakemodule.InitFakePortScanner("ps1", nil, fakemodule.FakePortScanFnDoNothing),
	}

	e, err := New(opts)
	if err != nil {
		t.Fatalf("New(%v) returned unexpected error: %v", opts, err)
	}

	if e.runner == nil {
		t.Errorf("New(%v) did not create a default runner", opts)
	}
}

func TestNewWhenPluginRegistration(t *testing.T) {
	cfg := config.FromProto(defaultConfig)
	cfg.CreateDirectories(t.TempDir())
	defer cfg.Close()
	genericErr := errors.New("generic error")

	tests := []struct {
		name    string
		options *Options
		wantErr bool
	}{
		{
			name: "modules_successfully_initialized_modules_are_registered",
			options: &Options{
				Config:      cfg,
				Runner:      fakerunner.New(),
				PortScanner: fakemodule.InitFakePortScanner("ps1", nil, fakemodule.FakePortScanFnDoNothing),
				Fingerprinters: []module.InitFingerprinterFn{
					fakemodule.InitFakeFingerprinter("fp1", nil, fakemodule.FakeFingerprintFnDoNothing),
				},
				Detectors: []module.InitVulnDetectorFn{
					fakemodule.InitFakeVulnDetector("d1", nil, fakemodule.FakeDetectFnNoFindings),
				},
			},
			wantErr: false,
		},
		{
			name: "port_scanner_init_fails_returns_err",
			options: &Options{
				Config:      cfg,
				PortScanner: fakemodule.InitFakePortScanner("ps1", genericErr, fakemodule.FakePortScanFnDoNothing),
			},
			wantErr: true,
		},
		{
			name: "fingerprinter_init_fails_returns_err",
			options: &Options{
				Config:      cfg,
				PortScanner: fakemodule.InitFakePortScanner("ps1", nil, fakemodule.FakePortScanFnDoNothing),
				Fingerprinters: []module.InitFingerprinterFn{
					fakemodule.InitFakeFingerprinter("fp1", genericErr, fakemodule.FakeFingerprintFnDoNothing),
					fakemodule.InitFakeFingerprinter("fp2", nil, fakemodule.FakeFingerprintFnDoNothing),
				},
			},
			wantErr: true,
		},
		{
			name: "detector_init_fails_returns_err",
			options: &Options{
				Config:      cfg,
				PortScanner: fakemodule.InitFakePortScanner("ps1", nil, fakemodule.FakePortScanFnDoNothing),
				Fingerprinters: []module.InitFingerprinterFn{
					fakemodule.InitFakeFingerprinter("fp1", nil, nil),
				},
				Detectors: []module.InitVulnDetectorFn{
					fakemodule.InitFakeVulnDetector("d1", genericErr, fakemodule.FakeDetectFnNoFindings),
					fakemodule.InitFakeVulnDetector("d2", nil, fakemodule.FakeDetectFnNoFindings),
				},
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts := tc.options
			_, err := New(opts)

			if tc.wantErr {
				if err == nil {
					t.Errorf("New(%v) returned no error, want error", opts)
				}

				return
			}

			if err != nil {
				t.Fatalf("New(%v) returned unexpected error: %v", opts, err)
			}

			runner := opts.Runner.(*fakerunner.FakeRunner)
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

func TestRun(t *testing.T) {
	tests := []struct {
		name      string
		runnerErr error
		report    *srpb.ScanResults
	}{
		{
			name: "runner_succeeds",
			report: srpb.ScanResults_builder{
				ScanStatus: srpb.ScanStatus_SUCCEEDED,
			}.Build(),
			runnerErr: nil,
		},
		{
			name:      "runner_fails",
			report:    nil,
			runnerErr: errors.New("runner failure"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.FromProto(defaultConfig)
			cfg.CreateDirectories(t.TempDir())
			defer cfg.Close()

			runner := fakerunner.New()
			runner.OverrideRun(func(ctx context.Context, target string) (s *srpb.ScanResults, err error) {
				return tc.report, tc.runnerErr
			})

			opts := &Options{
				Config:      cfg,
				Runner:      runner,
				PortScanner: fakemodule.InitFakePortScanner("ps1", nil, fakemodule.FakePortScanFnDoNothing),
			}
			e, err := New(opts)
			if err != nil {
				t.Fatalf("New(%v) returned unexpected error: %v", opts, err)
			}

			report, err := e.Run(context.Background(), "fake-target")
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
	cfg := config.FromProto(defaultConfig)
	cfg.CreateDirectories(t.TempDir())
	defer cfg.Close()

	artifactsDir := cfg.ArtifactsDirectory()
	opts := &Options{
		Config:      cfg,
		PortScanner: fakemodule.InitFakePortScanner("ps1", nil, fakemodule.FakePortScanFnDoNothing),
	}

	e, err := New(opts)
	if err != nil {
		t.Fatalf("New(%v) returned unexpected error: %v", opts, err)
	}

	if e.Artifacts() != artifactsDir {
		t.Errorf("Artifacts() = %s, want %s", e.Artifacts(), artifactsDir)
	}
}
