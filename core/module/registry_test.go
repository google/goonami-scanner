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

package module

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/goonami-scanner/core/config"
	"google.golang.org/protobuf/proto"

	cpb "github.com/google/goonami-scanner/core/config/config_go_proto"
	dpb "github.com/google/tsunami-security-scanner/proto/go/detection_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
	rpb "github.com/google/tsunami-security-scanner/proto/go/reconnaissance_go_proto"
)

// Define dummy types for testing
type dummyPortScanner struct {
	BaseModule
}

func (d *dummyPortScanner) Scan(ctx context.Context, target string) (*rpb.PortScanningReport, error) {
	return nil, nil
}

type dummyFingerprinter struct {
	BaseModule
}

func (d *dummyFingerprinter) Fingerprint(ctx context.Context, service *nspb.NetworkService) ([]*nspb.NetworkService, error) {
	return nil, nil
}

type dummyDetector struct {
	BaseModule
}

func (d *dummyDetector) Detect(ctx context.Context, service *nspb.NetworkService) (*dpb.DetectionReportList, error) {
	return nil, nil
}

func TestGetPortScanner(t *testing.T) {
	tests := []struct {
		name       string
		setupReg   func()
		config     *cpb.Config
		wantErrMsg string
	}{
		{
			name: "when_no_port_scanner_registered_returns_error",
			setupReg: func() {
				// empty registry
			},
			config: cpb.Config_builder{
				Workflowcfg: cpb.WorkflowConfiguration_builder{
					Portscan: proto.String("nmap"),
				}.Build(),
			}.Build(),
			wantErrMsg: `port scanner "nmap" is not registered`,
		},
		{
			name: "when_config_has_no_portscan_returns_error",
			setupReg: func() {
				RegisterPortScanner("nmap", func(context.Context, *config.Config) (PortScanner, error) {
					return &dummyPortScanner{*NewBaseModule("nmap")}, nil
				})
			},
			config:     cpb.Config_builder{}.Build(),
			wantErrMsg: "no port scanner specified in workflow configuration",
		},
		{
			name: "when_registered_returns_scanner",
			setupReg: func() {
				RegisterPortScanner("nmap", func(context.Context, *config.Config) (PortScanner, error) {
					return &dummyPortScanner{*NewBaseModule("nmap")}, nil
				})
			},
			config: cpb.Config_builder{
				Workflowcfg: cpb.WorkflowConfiguration_builder{
					Portscan: proto.String("nmap"),
				}.Build(),
			}.Build(),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ClearRegistry()
			tc.setupReg()

			cfg := config.FromProto(tc.config)
			got, err := GetPortScanner(t.Context(), cfg)

			if tc.wantErrMsg != "" {
				if err == nil {
					t.Fatalf("GetPortScanner() got nil error, want error containing %q", tc.wantErrMsg)
				}
				if !strings.Contains(err.Error(), tc.wantErrMsg) {
					t.Errorf("GetPortScanner() got error %q, want it to contain %q", err.Error(), tc.wantErrMsg)
				}
				return
			}

			if err != nil {
				t.Fatalf("GetPortScanner() returned unexpected error: %v", err)
			}
			if got == nil {
				t.Fatal("GetPortScanner() returned nil, want a PortScanner")
			}
			if got.Name() != "nmap" {
				t.Errorf("GetPortScanner().Name() = %q, want %q", got.Name(), "nmap")
			}
		})
	}
}

func TestGetFingerprinters(t *testing.T) {
	tests := []struct {
		name       string
		setupReg   func()
		config     *cpb.Config
		wantNames  []string
		wantErrMsg string
	}{
		{
			name:     "when_no_fingerprinter_config_returns_nil",
			setupReg: func() {},
			config:   cpb.Config_builder{}.Build(),
		},
		{
			name: "when_registered_and_requested_returns_fingerprinter",
			setupReg: func() {
				RegisterFingerprinter("fp1", func(context.Context, *config.Config) (Fingerprinter, error) {
					return &dummyFingerprinter{*NewBaseModule("fp1")}, nil
				})
				RegisterFingerprinter("fp2", func(context.Context, *config.Config) (Fingerprinter, error) {
					return &dummyFingerprinter{*NewBaseModule("fp2")}, nil
				})
			},
			config: cpb.Config_builder{
				Workflowcfg: cpb.WorkflowConfiguration_builder{
					Fingerprinters: cpb.WorkflowConfiguration_ModuleFilter_builder{
						Require: []string{"fp1", "fp2"},
					}.Build(),
				}.Build(),
			}.Build(),
			wantNames: []string{"fp1", "fp2"},
		},
		{
			name: "when_requested_not_registered_returns_error",
			setupReg: func() {
				RegisterFingerprinter("fp1", func(context.Context, *config.Config) (Fingerprinter, error) {
					return &dummyFingerprinter{*NewBaseModule("fp1")}, nil
				})
			},
			config: cpb.Config_builder{
				Workflowcfg: cpb.WorkflowConfiguration_builder{
					Fingerprinters: cpb.WorkflowConfiguration_ModuleFilter_builder{
						Require: []string{"fp1", "fp2"},
					}.Build(),
				}.Build(),
			}.Build(),
			wantErrMsg: `requested pattern "fp2" for fingerprinters did not expand to any module`,
		},
		{
			name: "when_some_ignored_filters_out_and_logs",
			setupReg: func() {
				RegisterFingerprinter("fp/iswebservice", func(context.Context, *config.Config) (Fingerprinter, error) {
					return &dummyFingerprinter{*NewBaseModule("fp/iswebservice")}, nil
				})
				RegisterFingerprinter("fp/hasssl", func(context.Context, *config.Config) (Fingerprinter, error) {
					return &dummyFingerprinter{*NewBaseModule("fp/hasssl")}, nil
				})
				RegisterFingerprinter("fp/private", func(context.Context, *config.Config) (Fingerprinter, error) {
					return &dummyFingerprinter{*NewBaseModule("fp/private")}, nil
				})
			},
			config: cpb.Config_builder{
				Workflowcfg: cpb.WorkflowConfiguration_builder{
					Fingerprinters: cpb.WorkflowConfiguration_ModuleFilter_builder{
						Require: []string{"fp/iswebservice", "fp/hasssl", ".*"},
						Ignore:  []string{"fp/private"},
					}.Build(),
				}.Build(),
			}.Build(),
			wantNames: []string{"fp/iswebservice", "fp/hasssl"},
		},
		{
			name: "when_pattern_contains_substring_name_it_does_not_match_unless_exact",
			setupReg: func() {
				RegisterFingerprinter("fp/detector", func(context.Context, *config.Config) (Fingerprinter, error) {
					return &dummyFingerprinter{*NewBaseModule("fp/detector")}, nil
				})
				RegisterFingerprinter("fp/detectorSuper", func(context.Context, *config.Config) (Fingerprinter, error) {
					return &dummyFingerprinter{*NewBaseModule("fp/detectorSuper")}, nil
				})
			},
			config: cpb.Config_builder{
				Workflowcfg: cpb.WorkflowConfiguration_builder{
					Fingerprinters: cpb.WorkflowConfiguration_ModuleFilter_builder{
						Require: []string{"fp/detector"},
					}.Build(),
				}.Build(),
			}.Build(),
			wantNames: []string{"fp/detector"},
		},
		{
			name: "when_invalid_require_pattern_returns_error",
			setupReg: func() {
				RegisterFingerprinter("fp1", func(context.Context, *config.Config) (Fingerprinter, error) {
					return &dummyFingerprinter{*NewBaseModule("fp1")}, nil
				})
			},
			config: cpb.Config_builder{
				Workflowcfg: cpb.WorkflowConfiguration_builder{
					Fingerprinters: cpb.WorkflowConfiguration_ModuleFilter_builder{
						Require: []string{"["},
					}.Build(),
				}.Build(),
			}.Build(),
			wantErrMsg: `invalid require pattern "[": error parsing regexp: missing closing ]`,
		},
		{
			name: "when_invalid_ignore_pattern_returns_error",
			setupReg: func() {
				RegisterFingerprinter("fp1", func(context.Context, *config.Config) (Fingerprinter, error) {
					return &dummyFingerprinter{*NewBaseModule("fp1")}, nil
				})
			},
			config: cpb.Config_builder{
				Workflowcfg: cpb.WorkflowConfiguration_builder{
					Fingerprinters: cpb.WorkflowConfiguration_ModuleFilter_builder{
						Require: []string{"fp1"},
						Ignore:  []string{"["},
					}.Build(),
				}.Build(),
			}.Build(),
			wantErrMsg: `invalid ignore pattern "[": error parsing regexp: missing closing ]`,
		},
		{
			name: "when_initialization_fails_returns_error",
			setupReg: func() {
				RegisterFingerprinter("fp1", func(context.Context, *config.Config) (Fingerprinter, error) {
					return nil, errors.New("init error")
				})
			},
			config: cpb.Config_builder{
				Workflowcfg: cpb.WorkflowConfiguration_builder{
					Fingerprinters: cpb.WorkflowConfiguration_ModuleFilter_builder{
						Require: []string{"fp1"},
					}.Build(),
				}.Build(),
			}.Build(),
			wantErrMsg: `failed to initialize fingerprinter "fp1": init error`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ClearRegistry()
			tc.setupReg()

			cfg := config.FromProto(tc.config)
			got, err := GetFingerprinters(t.Context(), cfg)

			if tc.wantErrMsg != "" {
				if err == nil {
					t.Fatalf("GetFingerprinters() got nil error, want error containing %q", tc.wantErrMsg)
				}
				if !strings.Contains(err.Error(), tc.wantErrMsg) {
					t.Errorf("GetFingerprinters() got error %q, want it to contain %q", err.Error(), tc.wantErrMsg)
				}
				return
			}

			if err != nil {
				t.Fatalf("GetFingerprinters() returned unexpected error: %v", err)
			}
			if len(got) != len(tc.wantNames) {
				t.Fatalf("GetFingerprinters() returned %d fingerprinters, want %d", len(got), len(tc.wantNames))
			}
			for i, name := range tc.wantNames {
				if got[i].Name() != name {
					t.Errorf("GetFingerprinters()[%d].Name() = %q, want %q", i, got[i].Name(), name)
				}
			}
		})
	}
}

func TestGetDetectors(t *testing.T) {
	tests := []struct {
		name       string
		setupReg   func()
		config     *cpb.Config
		wantNames  []string
		wantErrMsg string
	}{
		{
			name:     "when_no_detector_config_returns_nil",
			setupReg: func() {},
			config:   cpb.Config_builder{}.Build(),
		},
		{
			name: "when_registered_and_requested_returns_detector",
			setupReg: func() {
				RegisterDetector("dt1", func(context.Context, *config.Config) (VulnDetector, error) {
					return &dummyDetector{*NewBaseModule("dt1")}, nil
				})
				RegisterDetector("dt2", func(context.Context, *config.Config) (VulnDetector, error) {
					return &dummyDetector{*NewBaseModule("dt2")}, nil
				})
			},
			config: cpb.Config_builder{
				Workflowcfg: cpb.WorkflowConfiguration_builder{
					Detectors: cpb.WorkflowConfiguration_ModuleFilter_builder{
						Require: []string{"dt1", "dt2"},
					}.Build(),
				}.Build(),
			}.Build(),
			wantNames: []string{"dt1", "dt2"},
		},
		{
			name: "when_requested_not_registered_returns_error",
			setupReg: func() {
				RegisterDetector("dt1", func(context.Context, *config.Config) (VulnDetector, error) {
					return &dummyDetector{*NewBaseModule("dt1")}, nil
				})
			},
			config: cpb.Config_builder{
				Workflowcfg: cpb.WorkflowConfiguration_builder{
					Detectors: cpb.WorkflowConfiguration_ModuleFilter_builder{
						Require: []string{"dt1", "dt2"},
					}.Build(),
				}.Build(),
			}.Build(),
			wantErrMsg: `requested pattern "dt2" for detectors did not expand to any module`,
		},
		{
			name: "when_some_ignored_filters_out_and_logs",
			setupReg: func() {
				RegisterDetector("dt/cve-1", func(context.Context, *config.Config) (VulnDetector, error) {
					return &dummyDetector{*NewBaseModule("dt/cve-1")}, nil
				})
				RegisterDetector("dt/cve-2", func(context.Context, *config.Config) (VulnDetector, error) {
					return &dummyDetector{*NewBaseModule("dt/cve-2")}, nil
				})
				RegisterDetector("dt/private", func(context.Context, *config.Config) (VulnDetector, error) {
					return &dummyDetector{*NewBaseModule("dt/private")}, nil
				})
			},
			config: cpb.Config_builder{
				Workflowcfg: cpb.WorkflowConfiguration_builder{
					Detectors: cpb.WorkflowConfiguration_ModuleFilter_builder{
						Require: []string{"dt/cve-1", "dt/cve-2", ".*"},
						Ignore:  []string{"dt/private"},
					}.Build(),
				}.Build(),
			}.Build(),
			wantNames: []string{"dt/cve-1", "dt/cve-2"},
		},
		{
			name: "when_invalid_require_pattern_returns_error",
			setupReg: func() {
				RegisterDetector("dt1", func(context.Context, *config.Config) (VulnDetector, error) {
					return &dummyDetector{*NewBaseModule("dt1")}, nil
				})
			},
			config: cpb.Config_builder{
				Workflowcfg: cpb.WorkflowConfiguration_builder{
					Detectors: cpb.WorkflowConfiguration_ModuleFilter_builder{
						Require: []string{"["},
					}.Build(),
				}.Build(),
			}.Build(),
			wantErrMsg: `invalid require pattern "[": error parsing regexp: missing closing ]`,
		},
		{
			name: "when_invalid_ignore_pattern_returns_error",
			setupReg: func() {
				RegisterDetector("dt1", func(context.Context, *config.Config) (VulnDetector, error) {
					return &dummyDetector{*NewBaseModule("dt1")}, nil
				})
			},
			config: cpb.Config_builder{
				Workflowcfg: cpb.WorkflowConfiguration_builder{
					Detectors: cpb.WorkflowConfiguration_ModuleFilter_builder{
						Require: []string{"dt1"},
						Ignore:  []string{"["},
					}.Build(),
				}.Build(),
			}.Build(),
			wantErrMsg: `invalid ignore pattern "[": error parsing regexp: missing closing ]`,
		},
		{
			name: "when_initialization_fails_returns_error",
			setupReg: func() {
				RegisterDetector("dt1", func(context.Context, *config.Config) (VulnDetector, error) {
					return nil, errors.New("init error")
				})
			},
			config: cpb.Config_builder{
				Workflowcfg: cpb.WorkflowConfiguration_builder{
					Detectors: cpb.WorkflowConfiguration_ModuleFilter_builder{
						Require: []string{"dt1"},
					}.Build(),
				}.Build(),
			}.Build(),
			wantErrMsg: `failed to initialize detector "dt1": init error`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ClearRegistry()
			tc.setupReg()

			cfg := config.FromProto(tc.config)
			got, err := GetDetectors(t.Context(), cfg)

			if tc.wantErrMsg != "" {
				if err == nil {
					t.Fatalf("GetDetectors() got nil error, want error containing %q", tc.wantErrMsg)
				}
				if !strings.Contains(err.Error(), tc.wantErrMsg) {
					t.Errorf("GetDetectors() got error %q, want it to contain %q", err.Error(), tc.wantErrMsg)
				}
				return
			}

			if err != nil {
				t.Fatalf("GetDetectors() returned unexpected error: %v", err)
			}
			if len(got) != len(tc.wantNames) {
				t.Fatalf("GetDetectors() returned %d detectors, want %d", len(got), len(tc.wantNames))
			}
			for i, name := range tc.wantNames {
				if got[i].Name() != name {
					t.Errorf("GetDetectors()[%d].Name() = %q, want %q", i, got[i].Name(), name)
				}
			}
		})
	}
}

func TestDuplicateRegistrationsPanic(t *testing.T) {
	tests := []struct {
		name     string
		register func()
	}{
		{
			name: "when_registering_port_scanner_twice_it_panics",
			register: func() {
				RegisterPortScanner("ps1", func(context.Context, *config.Config) (PortScanner, error) { return nil, nil })
				RegisterPortScanner("ps1", func(context.Context, *config.Config) (PortScanner, error) { return nil, nil })
			},
		},
		{
			name: "when_registering_fingerprinter_twice_it_panics",
			register: func() {
				RegisterFingerprinter("fp1", func(context.Context, *config.Config) (Fingerprinter, error) { return nil, nil })
				RegisterFingerprinter("fp1", func(context.Context, *config.Config) (Fingerprinter, error) { return nil, nil })
			},
		},
		{
			name: "when_registering_detector_twice_it_panics",
			register: func() {
				RegisterDetector("d1", func(context.Context, *config.Config) (VulnDetector, error) { return nil, nil })
				RegisterDetector("d1", func(context.Context, *config.Config) (VulnDetector, error) { return nil, nil })
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r == nil {
					t.Errorf("expected duplicate registration to panic, but it did not")
				}
			}()

			ClearRegistry()
			tc.register()
		})
	}
}
