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

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/google/goonami-scanner/common/testfakes/fakemodule"
	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/module"
	rpb "github.com/google/tsunami-security-scanner/proto/go/reconnaissance_go_proto"
	srpb "github.com/google/tsunami-security-scanner/proto/go/scan_results_go_proto"
)

var (
	fakeConfig = `
workflowcfg: {
  portscan: "ps1"
  fingerprinters: {
    require: ["fp1"]
  }
}
clients: {
  callback_server: {
		interaction_ttl_seconds: 300
    cleanup_interval_seconds: 10

    http_poll_config: {
      mode: MODE_USE_REMOTE_SERVER
      public_uri: "http://127.0.0.1:32189"
    }
  }
}
`
)

func TestRun(t *testing.T) {
	module.ClearRegistry()
	module.RegisterPortScanner("ps1", fakemodule.InitFakePortScanner("ps1", nil, fakemodule.FakePortScanFnDoNothing))
	module.RegisterFingerprinter("fp1", fakemodule.InitFakeFingerprinter("fp1", nil, fakemodule.FakeFingerprintFnDoNothing))

	tempDir := t.TempDir()
	configPath := path.Join(tempDir, "config.textproto")
	if err := os.WriteFile(configPath, []byte(fakeConfig), 0644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	*ConfigFlag = configPath
	*OutputDirFlag = tempDir
	*TargetFlag = "1.1.1.1"
	*DebugLevelFlag = 0

	if err := run(t.Context()); err != nil {
		t.Errorf("run() returned error: %v", err)
	}

	// Verify results file exists
	if _, err := os.Stat(path.Join(tempDir, "results.textproto")); err != nil {
		t.Errorf("results.textproto was not created: %v", err)
	}
}

func TestRun_ErrorCases(t *testing.T) {
	tempDir := t.TempDir()
	configPath := path.Join(tempDir, "config.textproto")
	os.WriteFile(configPath, []byte(fakeConfig), 0644)

	// Create a file where OutputDir should be to make CreateDirectories fail
	blockedOutputDir := path.Join(tempDir, "blocked")
	os.WriteFile(blockedOutputDir, []byte(""), 0644)

	tests := []struct {
		name      string
		target    string
		outputDir string
		config    string
		setup     func()
		wantErr   error
	}{
		{
			name:    "when_flags_are_invalid_returns_error",
			target:  "", // invalid
			wantErr: ErrTargetRequired,
		},
		{
			name:      "when_config_file_not_found_returns_error",
			target:    "1.1.1.1",
			outputDir: tempDir,
			config:    "non/existent/config",
			wantErr:   config.ErrConfigRead,
		},
		{
			name:      "when_create_directories_fails_returns_error",
			target:    "1.1.1.1",
			outputDir: blockedOutputDir,
			config:    configPath,
			wantErr:   config.ErrCreateDir,
		},
		{
			name:      "when_entrypoint_new_fails_returns_error",
			target:    "1.1.1.1",
			outputDir: t.TempDir(),
			config:    configPath,
			setup: func() {
				module.ClearRegistry()
				module.RegisterPortScanner("ps1", func(ctx context.Context, config *config.Config) (module.PortScanner, error) {
					return nil, fmt.Errorf("init error")
				})
			},
			wantErr: errors.New("init error"),
		},
		{
			name:      "when_entrypoint_run_fails_returns_error",
			target:    "1.1.1.1",
			outputDir: t.TempDir(),
			config:    configPath,
			setup: func() {
				module.ClearRegistry()
				module.RegisterPortScanner("ps1", func(ctx context.Context, config *config.Config) (module.PortScanner, error) {
					return fakemodule.NewFakePortScanner("ps1", func(ctx context.Context, target string) (*rpb.PortScanningReport, error) {
						return nil, fmt.Errorf("run error")
					}), nil
				})
				module.RegisterFingerprinter("fp1", fakemodule.InitFakeFingerprinter("fp1", nil, fakemodule.FakeFingerprintFnDoNothing))
			},
			wantErr: errors.New("run error"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			module.ClearRegistry()
			module.RegisterPortScanner("ps1", fakemodule.InitFakePortScanner("ps1", nil, fakemodule.FakePortScanFnDoNothing))
			module.RegisterFingerprinter("fp1", fakemodule.InitFakeFingerprinter("fp1", nil, fakemodule.FakeFingerprintFnDoNothing))

			*TargetFlag = tc.target
			*OutputDirFlag = tc.outputDir
			*ConfigFlag = tc.config
			*DebugLevelFlag = 0

			if tc.setup != nil {
				tc.setup()
			}

			err := run(t.Context())
			if err == nil {
				t.Errorf("run() for %s returned no error, want error", tc.name)
				return
			}

			if tc.wantErr != nil {
				// For generic errors in main_test.go, we might need string matching if they are not structured
				if !errors.Is(err, tc.wantErr) && !strings.Contains(err.Error(), tc.wantErr.Error()) {
					t.Errorf("run() error = %v, wantErr %v", err, tc.wantErr)
				}
			}
		})
	}
}

func TestValidateFlags(t *testing.T) {
	tests := []struct {
		name       string
		target     string
		outputDir  string
		config     string
		debugLevel int
		wantErr    error
	}{
		{
			name:       "when_all_flags_are_valid_returns_no_error",
			target:     "1.1.1.1",
			outputDir:  "/tmp",
			config:     "config.textproto",
			debugLevel: 1,
			wantErr:    nil,
		},
		{
			name:       "when_target_is_missing_returns_error",
			target:     "",
			outputDir:  "/tmp",
			config:     "config.textproto",
			debugLevel: 1,
			wantErr:    ErrTargetRequired,
		},
		{
			name:       "when_output_dir_is_missing_returns_error",
			target:     "1.1.1.1",
			outputDir:  "",
			config:     "config.textproto",
			debugLevel: 1,
			wantErr:    ErrOutputDirRequired,
		},
		{
			name:       "when_config_is_missing_returns_error",
			target:     "1.1.1.1",
			outputDir:  "/tmp",
			config:     "",
			debugLevel: 1,
			wantErr:    ErrConfigRequired,
		},
		{
			name:       "when_debug_level_is_negative_returns_error",
			target:     "1.1.1.1",
			outputDir:  "/tmp",
			config:     "config.textproto",
			debugLevel: -1,
			wantErr:    ErrInvalidDebugLevel,
		},
		{
			name:       "when_debug_level_is_too_high_returns_error",
			target:     "1.1.1.1",
			outputDir:  "/tmp",
			config:     "config.textproto",
			debugLevel: 4,
			wantErr:    ErrInvalidDebugLevel,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Set flags
			*TargetFlag = tc.target
			*OutputDirFlag = tc.outputDir
			*ConfigFlag = tc.config
			*DebugLevelFlag = tc.debugLevel

			err := validateFlags()
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("validateFlags() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestWriteResults(t *testing.T) {
	tempDir := t.TempDir()
	resultsPath := path.Join(tempDir, "results.textproto")
	results := srpb.ScanResults_builder{
		ScanStatus: srpb.ScanStatus_SUCCEEDED,
	}.Build()

	if err := writeResults(resultsPath, results); err != nil {
		t.Fatalf("writeResults() returned unexpected error: %v", err)
	}

	// Verify file content
	data, err := os.ReadFile(resultsPath)
	if err != nil {
		t.Fatalf("failed to read written results file: %v", err)
	}

	if len(data) == 0 {
		t.Errorf("written results file is empty")
	}
}
