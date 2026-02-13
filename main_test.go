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
	"fmt"
	"os"
	"path"
	"testing"

	"github.com/google/goonami-scanner/common/testfakes/fakemodule"
	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/module"
	rpb "github.com/google/tsunami-security-scanner/proto/go/reconnaissance_go_proto"
	srpb "github.com/google/tsunami-security-scanner/proto/go/scan_results_go_proto"
)

func TestRun(t *testing.T) {
	// Backup and restore
	oldPS := portScanner
	oldFPs := fingerprinters
	defer func() {
		portScanner = oldPS
		fingerprinters = oldFPs
	}()

	// Override with fakes
	portScanner = fakemodule.InitFakePortScanner("ps1", nil, fakemodule.FakePortScanFnDoNothing)
	fingerprinters = []module.InitFingerprinterFn{
		fakemodule.InitFakeFingerprinter("fp1", nil, fakemodule.FakeFingerprintFnDoNothing),
	}

	tempDir := t.TempDir()
	configPath := path.Join(tempDir, "config.textproto")
	if err := os.WriteFile(configPath, []byte(""), 0644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	*ConfigFlag = configPath
	*OutputDirFlag = tempDir
	*TargetFlag = "1.1.1.1"
	*DebugLevelFlag = 0

	if err := run(context.Background()); err != nil {
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
	os.WriteFile(configPath, []byte(""), 0644)

	// Create a file where OutputDir should be to make CreateDirectories fail
	blockedOutputDir := path.Join(tempDir, "blocked")
	os.WriteFile(blockedOutputDir, []byte(""), 0644)

	tests := []struct {
		name      string
		target    string
		outputDir string
		config    string
		setup     func()
		teardown  func()
	}{
		{
			name:   "when_flags_are_invalid_returns_error",
			target: "", // invalid
		},
		{
			name:      "when_config_file_not_found_returns_error",
			target:    "1.1.1.1",
			outputDir: tempDir,
			config:    "non/existent/config",
		},
		{
			name:      "when_create_directories_fails_returns_error",
			target:    "1.1.1.1",
			outputDir: blockedOutputDir,
			config:    configPath,
		},
		{
			name:      "when_entrypoint_new_fails_returns_error",
			target:    "1.1.1.1",
			outputDir: t.TempDir(),
			config:    configPath,
			setup: func() {
				oldPS := portScanner
				portScanner = func(ctx context.Context, config *config.Config) (module.PortScanner, error) {
					return nil, fmt.Errorf("init error")
				}
				_oldPS = oldPS
			},
			teardown: func() {
				portScanner = _oldPS
			},
		},
		{
			name:      "when_entrypoint_run_fails_returns_error",
			target:    "1.1.1.1",
			outputDir: t.TempDir(),
			config:    configPath,
			setup: func() {
				oldPS := portScanner
				portScanner = func(ctx context.Context, config *config.Config) (module.PortScanner, error) {
					return fakemodule.NewFakePortScanner("ps1", func(ctx context.Context, target string) (*rpb.PortScanningReport, error) {
						return nil, fmt.Errorf("run error")
					}), nil
				}
				_oldPS = oldPS
			},
			teardown: func() {
				portScanner = _oldPS
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			*TargetFlag = tc.target
			*OutputDirFlag = tc.outputDir
			*ConfigFlag = tc.config
			*DebugLevelFlag = 0

			if tc.setup != nil {
				tc.setup()
			}
			if tc.teardown != nil {
				defer tc.teardown()
			}

			if err := run(context.Background()); err == nil {
				t.Errorf("run() for %s returned no error, want error", tc.name)
			}
		})
	}
}

var _oldPS module.InitPortScannerFn

func TestValidateFlags(t *testing.T) {
	tests := []struct {
		name       string
		target     string
		outputDir  string
		config     string
		debugLevel int
		wantErr    bool
	}{
		{
			name:       "when_all_flags_are_valid_returns_no_error",
			target:     "1.1.1.1",
			outputDir:  "/tmp",
			config:     "config.textproto",
			debugLevel: 1,
			wantErr:    false,
		},
		{
			name:       "when_target_is_missing_returns_error",
			target:     "",
			outputDir:  "/tmp",
			config:     "config.textproto",
			debugLevel: 1,
			wantErr:    true,
		},
		{
			name:       "when_output_dir_is_missing_returns_error",
			target:     "1.1.1.1",
			outputDir:  "",
			config:     "config.textproto",
			debugLevel: 1,
			wantErr:    true,
		},
		{
			name:       "when_config_is_missing_returns_error",
			target:     "1.1.1.1",
			outputDir:  "/tmp",
			config:     "",
			debugLevel: 1,
			wantErr:    true,
		},
		{
			name:       "when_debug_level_is_negative_returns_error",
			target:     "1.1.1.1",
			outputDir:  "/tmp",
			config:     "config.textproto",
			debugLevel: -1,
			wantErr:    true,
		},
		{
			name:       "when_debug_level_is_too_high_returns_error",
			target:     "1.1.1.1",
			outputDir:  "/tmp",
			config:     "config.textproto",
			debugLevel: 4,
			wantErr:    true,
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
			if (err != nil) != tc.wantErr {
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

	// Optional: we could unmarshal and compare, but checking if file is written and non-empty is already good.
}
