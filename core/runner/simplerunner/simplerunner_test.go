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

package simplerunner

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/goonami-scanner/common/testfakes/fakemodule"
	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/module"
	"google.golang.org/protobuf/testing/protocmp"

	cpb "github.com/google/goonami-scanner/core/config/config_go_proto"
	dpb "github.com/google/tsunami-security-scanner/proto/go/detection_go_proto"
	npb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
	rpb "github.com/google/tsunami-security-scanner/proto/go/reconnaissance_go_proto"
	srpb "github.com/google/tsunami-security-scanner/proto/go/scan_results_go_proto"
)

var defaultConfig = config.FromProto(cpb.Config_builder{
	Globalcfg: cpb.GlobalConfig_builder{
		Performance: cpb.GlobalConfig_Performance_builder{
			MaxConcurrency: 1,
		}.Build(),
	}.Build(),
}.Build())

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		config  *config.Config
		wantErr error
	}{
		{
			name:    "when_config_is_valid_returns_no_error",
			config:  config.FromProto(cpb.Config_builder{}.Build()),
			wantErr: nil,
		},
		{
			name:    "when_config_is_nil_returns_error",
			config:  nil,
			wantErr: ErrConfigNil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(tc.config)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("New() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestRegisterPortScanner(t *testing.T) {
	tests := []struct {
		name            string
		module          module.PortScanner
		existingScanner module.PortScanner
		wantErr         error
	}{
		{
			name:            "when_module_is_valid_returns_no_error",
			module:          fakemodule.NewFakePortScanner("ps1", nil),
			existingScanner: nil,
			wantErr:         nil,
		},
		{
			name:            "when_scanner_is_already_registered_returns_error",
			module:          fakemodule.NewFakePortScanner("ps1", nil),
			existingScanner: fakemodule.NewFakePortScanner("ps2", nil),
			wantErr:         ErrPortScannerAlreadyRegistered,
		},
		{
			name:            "when_module_is_nil_returns_error",
			module:          nil,
			existingScanner: nil,
			wantErr:         ErrRegistrationNil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, err := New(defaultConfig)
			if err != nil {
				t.Fatalf("New() returned error %v, want nil", err)
			}

			r.portScanner = tc.existingScanner

			if err := r.RegisterPortScanner(tc.module); !errors.Is(err, tc.wantErr) {
				t.Fatalf("RegisterPortScanner() returned error %v, want error %v", err, tc.wantErr)
			}

			if tc.wantErr != nil {
				return
			}

			if tc.module != nil && r.portScanner != tc.module {
				t.Errorf("RegisterPortScanner() did not register the port scanner")
			}
		})
	}
}

func TestRegisterFingerprinter(t *testing.T) {
	tests := []struct {
		name    string
		modules []module.Fingerprinter
		wantErr error
	}{
		{
			name: "when_modules_are_valid_returns_no_error",
			modules: []module.Fingerprinter{
				fakemodule.NewFakeFingerprinter("fp1", nil),
				fakemodule.NewFakeFingerprinter("fp2", nil),
			},
			wantErr: nil,
		},
		{
			name:    "when_module_is_nil_returns_error",
			modules: []module.Fingerprinter{nil},
			wantErr: ErrRegistrationNil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, err := New(defaultConfig)
			if err != nil {
				t.Fatalf("New() returned error %v, want nil", err)
			}

			for _, m := range tc.modules {
				err = r.RegisterFingerprinter(m)
				if err != nil {
					break
				}
			}

			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("RegisterFingerprinter() returned error %v, want error %v", err, tc.wantErr)
			}

			if tc.wantErr != nil {
				return
			}

			if len(r.fingerprinters) != len(tc.modules) {
				t.Fatalf("RegisterFingerprinter() registered %d modules, want %d", len(r.fingerprinters), len(tc.modules))
			}

			for i, m := range tc.modules {
				if r.fingerprinters[i] != m {
					t.Errorf("RegisterFingerprinter() wrong module at index %d: got %s, want %s", i, r.fingerprinters[i].Name(), m.Name())
				}
			}
		})
	}
}

func TestRegisterDetector(t *testing.T) {
	tests := []struct {
		name    string
		modules []module.VulnDetector
		wantErr error
	}{
		{
			name: "when_modules_are_valid_returns_no_error",
			modules: []module.VulnDetector{
				fakemodule.NewFakeVulnDetector("det1", fakemodule.FakeDetectFnNoFindings),
				fakemodule.NewFakeVulnDetector("det2", fakemodule.FakeDetectFnNoFindings),
			},
			wantErr: nil,
		},
		{
			name:    "when_module_is_nil_returns_error",
			modules: []module.VulnDetector{nil},
			wantErr: ErrRegistrationNil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, err := New(defaultConfig)
			if err != nil {
				t.Fatalf("New() returned error %v, want nil", err)
			}

			for _, m := range tc.modules {
				err = r.RegisterDetector(m)
				if err != nil {
					break
				}
			}

			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("RegisterDetector() returned error %v, want error %v", err, tc.wantErr)
			}

			if tc.wantErr != nil {
				return
			}

			if len(r.detectors) != len(tc.modules) {
				t.Fatalf("RegisterDetector() registered %d modules, want %d", len(r.detectors), len(tc.modules))
			}

			for i, m := range tc.modules {
				if r.detectors[i] != m {
					t.Errorf("RegisterDetector() wrong module at index %d: got %s, want %s", i, r.detectors[i].Name(), m.Name())
				}
			}
		})
	}
}

func TestPortScanStep(t *testing.T) {
	testReport := rpb.PortScanningReport_builder{
		NetworkServices: []*nspb.NetworkService{
			nspb.NetworkService_builder{ServiceName: "svc1"}.Build(),
		},
	}.Build()
	testReportFn := func(ctx context.Context, target string) (*rpb.PortScanningReport, error) {
		return testReport, nil
	}

	tests := []struct {
		name          string
		portScanner   module.PortScanner
		target        string
		wantErr       error
		wantReport    *rpb.PortScanningReport
		wantScanCalls int
	}{
		{
			name:          "when_port_scanner_is_nil_returns_error",
			portScanner:   nil,
			target:        "1.1.1.1",
			wantErr:       ErrNoPortScanner,
			wantReport:    nil,
			wantScanCalls: 0,
		},
		{
			name:          "when_port_scanner_succeeds_returns_report",
			portScanner:   fakemodule.NewFakePortScanner("ps1", testReportFn),
			target:        "1.1.1.1",
			wantErr:       nil,
			wantReport:    testReport,
			wantScanCalls: 1,
		},
		{
			name:          "when_port_scanner_errors_returns_error",
			portScanner:   fakemodule.NewFakePortScanner("ps1", fakemodule.FakePortScanFnErrors),
			target:        "1.1.1.1",
			wantErr:       fakemodule.ErrFakePortScanGeneric,
			wantReport:    nil,
			wantScanCalls: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, err := New(defaultConfig)
			if err != nil {
				t.Fatalf("New() returned error %v, want nil", err)
			}

			r.portScanner = tc.portScanner
			got, err := r.PortScanStep(context.Background(), tc.target)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("PortScanStep() error = %v, wantErr %v", err, tc.wantErr)
			}

			if tc.wantErr != nil {
				return
			}

			if diff := cmp.Diff(tc.wantReport, got, protocmp.Transform()); diff != "" {
				t.Errorf("PortScanStep() returned diff (-want +got):\n%s", diff)
			}

			if ps, ok := tc.portScanner.(*fakemodule.FakePortScanner); ok {
				if ps.CountCalls() != tc.wantScanCalls {
					t.Errorf("PortScanStep() called %d times, want %d", ps.CountCalls(), tc.wantScanCalls)
				}
			}
		})
	}
}

func TestFingerprintStep(t *testing.T) {
	portScanReport := rpb.PortScanningReport_builder{
		NetworkServices: []*nspb.NetworkService{
			nspb.NetworkService_builder{ServiceName: "svc1"}.Build(),
			nspb.NetworkService_builder{ServiceName: "svc2"}.Build(),
		},
	}.Build()
	fpAppendNameFn := func(val string) fakemodule.FakeFingerprintFn {
		return func(ctx context.Context, svc *nspb.NetworkService) ([]*nspb.NetworkService, error) {
			name := svc.GetServiceName() + val
			svc.SetServiceName(name)
			return []*nspb.NetworkService{svc}, nil
		}
	}

	tests := []struct {
		name           string
		fingerprinters []module.Fingerprinter
		want           *rpb.FingerprintingReport
		wantErr        error
	}{
		{
			name:           "when_no_fingerprinter_is_registered_returns_no_service_change",
			fingerprinters: []module.Fingerprinter{},
			want: rpb.FingerprintingReport_builder{
				NetworkServices: []*nspb.NetworkService{
					nspb.NetworkService_builder{ServiceName: "svc1"}.Build(),
					nspb.NetworkService_builder{ServiceName: "svc2"}.Build(),
				},
			}.Build(),
		},
		{
			name: "when_fingerprinters_are_called_they_execute_in_order",
			fingerprinters: []module.Fingerprinter{
				fakemodule.NewFakeFingerprinter("fp1", fpAppendNameFn("_fp1")),
				fakemodule.NewFakeFingerprinter("fp2", fpAppendNameFn("_fp2")),
			},
			want: rpb.FingerprintingReport_builder{
				NetworkServices: []*nspb.NetworkService{
					nspb.NetworkService_builder{ServiceName: "svc1_fp1_fp2"}.Build(),
					nspb.NetworkService_builder{ServiceName: "svc2_fp1_fp2"}.Build(),
				},
			}.Build(),
		},
		{
			name: "when_fingerprinter_errors_it_propagates_error",
			fingerprinters: []module.Fingerprinter{
				fakemodule.NewFakeFingerprinter("fp1", fakemodule.FakeFingerprintFnErrors),
				fakemodule.NewFakeFingerprinter("fp2", fpAppendNameFn("_fp2")),
			},
			want:    nil,
			wantErr: fakemodule.ErrFakeFingerprintGeneric,
		},
		{
			name: "when_fingerprinter_returns_multiple_services_they_are_accumulated",
			fingerprinters: []module.Fingerprinter{
				fakemodule.NewFakeFingerprinter("fp1", func(ctx context.Context, svc *nspb.NetworkService) ([]*nspb.NetworkService, error) {
					return []*nspb.NetworkService{
						nspb.NetworkService_builder{ServiceName: fmt.Sprintf("%s_fp1_1", svc.GetServiceName())}.Build(),
						nspb.NetworkService_builder{ServiceName: fmt.Sprintf("%s_fp1_2", svc.GetServiceName())}.Build(),
					}, nil
				}),
				fakemodule.NewFakeFingerprinter("fp2", fpAppendNameFn("_fp2")),
			},
			want: rpb.FingerprintingReport_builder{
				NetworkServices: []*nspb.NetworkService{
					nspb.NetworkService_builder{ServiceName: "svc1_fp1_1_fp2"}.Build(),
					nspb.NetworkService_builder{ServiceName: "svc1_fp1_2_fp2"}.Build(),
					nspb.NetworkService_builder{ServiceName: "svc2_fp1_1_fp2"}.Build(),
					nspb.NetworkService_builder{ServiceName: "svc2_fp1_2_fp2"}.Build(),
				},
			}.Build(),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, err := New(defaultConfig)
			if err != nil {
				t.Fatalf("New() returned error %v, want nil", err)
			}

			r.fingerprinters = tc.fingerprinters
			got, err := r.FingerprintStep(context.Background(), portScanReport)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("FingerprintStep() error = %v, wantErr %v", err, tc.wantErr)
			}

			if tc.wantErr != nil {
				return
			}

			if diff := cmp.Diff(tc.want, got, protocmp.Transform(), protocmp.SortRepeatedFields(&rpb.FingerprintingReport{}, "network_services")); diff != "" {
				t.Errorf("FingerprintStep() returned diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestDetectStep(t *testing.T) {
	fingerprintReport := rpb.FingerprintingReport_builder{
		NetworkServices: []*nspb.NetworkService{
			nspb.NetworkService_builder{ServiceName: "svc1"}.Build(),
			nspb.NetworkService_builder{ServiceName: "svc2"}.Build(),
		},
	}.Build()
	fakeDetectFnWithFinding := func(ctx context.Context, svc *nspb.NetworkService) (*dpb.DetectionReportList, error) {
		return dpb.DetectionReportList_builder{
			DetectionReports: []*dpb.DetectionReport{
				dpb.DetectionReport_builder{
					NetworkService: svc,
				}.Build(),
			},
		}.Build(), nil
	}

	tests := []struct {
		name      string
		detectors []module.VulnDetector
		want      []*dpb.DetectionReport
		wantErr   error
	}{
		{
			name:      "when_no_detector_is_registered_returns_nil",
			detectors: []module.VulnDetector{},
			want:      nil,
			wantErr:   nil,
		},
		{
			name: "when_detector_has_no_findings_returns_nil",
			detectors: []module.VulnDetector{
				fakemodule.NewFakeVulnDetector("d1", fakemodule.FakeDetectFnNoFindings),
			},
			want:    nil,
			wantErr: nil,
		},
		{
			name: "when_detector_has_findings_returns_reports",
			detectors: []module.VulnDetector{
				fakemodule.NewFakeVulnDetector("d1", fakeDetectFnWithFinding),
			},
			want: []*dpb.DetectionReport{
				dpb.DetectionReport_builder{
					NetworkService: nspb.NetworkService_builder{ServiceName: "svc1"}.Build(),
				}.Build(),
				dpb.DetectionReport_builder{
					NetworkService: nspb.NetworkService_builder{ServiceName: "svc2"}.Build(),
				}.Build(),
			},
			wantErr: nil,
		},
		{
			name: "when_multiple_detectors_have_findings_reports_are_accumulated",
			detectors: []module.VulnDetector{
				fakemodule.NewFakeVulnDetector("d1", fakeDetectFnWithFinding),
				fakemodule.NewFakeVulnDetector("d2", fakeDetectFnWithFinding),
			},
			want: []*dpb.DetectionReport{
				dpb.DetectionReport_builder{
					NetworkService: nspb.NetworkService_builder{ServiceName: "svc1"}.Build(),
				}.Build(),
				dpb.DetectionReport_builder{
					NetworkService: nspb.NetworkService_builder{ServiceName: "svc1"}.Build(),
				}.Build(),
				dpb.DetectionReport_builder{
					NetworkService: nspb.NetworkService_builder{ServiceName: "svc2"}.Build(),
				}.Build(),
				dpb.DetectionReport_builder{
					NetworkService: nspb.NetworkService_builder{ServiceName: "svc2"}.Build(),
				}.Build(),
			},
			wantErr: nil,
		},
		{
			name: "when_detector_errors_it_propagates_error",
			detectors: []module.VulnDetector{
				fakemodule.NewFakeVulnDetector("d1", fakemodule.FakeDetectFnErrors),
				fakemodule.NewFakeVulnDetector("d2", fakeDetectFnWithFinding),
			},
			want:    nil,
			wantErr: fakemodule.ErrFakeDetectGeneric,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, err := New(defaultConfig)
			if err != nil {
				t.Fatalf("New() returned error %v, want nil", err)
			}

			r.detectors = tc.detectors
			got, err := r.DetectStep(context.Background(), fingerprintReport)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("DetectStep() error = %v, wantErr %v", err, tc.wantErr)
			}

			if tc.wantErr != nil {
				return
			}

			sortFn := func(a, b *dpb.DetectionReport) bool { return a.String() < b.String() }
			if diff := cmp.Diff(tc.want, got, protocmp.Transform(), cmpopts.SortSlices(sortFn)); diff != "" {
				t.Errorf("DetectStep() returned diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestRun(t *testing.T) {
	testReport := rpb.PortScanningReport_builder{
		TargetInfo: rpb.TargetInfo_builder{
			NetworkEndpoints: []*npb.NetworkEndpoint{
				npb.NetworkEndpoint_builder{
					Type: npb.NetworkEndpoint_IP,
					IpAddress: npb.IpAddress_builder{
						AddressFamily: npb.AddressFamily_IPV4,
						Address:       "1.1.1.1",
					}.Build(),
				}.Build(),
			},
		}.Build(),
		NetworkServices: []*nspb.NetworkService{
			nspb.NetworkService_builder{ServiceName: "svc1"}.Build(),
			nspb.NetworkService_builder{ServiceName: "svc2"}.Build(),
		},
	}.Build()
	testReportFn := func(ctx context.Context, target string) (*rpb.PortScanningReport, error) {
		return testReport, nil
	}

	tests := []struct {
		name           string
		portScanner    module.PortScanner
		fingerprinters []module.Fingerprinter
		detectors      []module.VulnDetector
		target         string
		wantErr        error
		want           *srpb.ScanResults
	}{
		{
			name:        "when_no_port_scanner_is_registered_returns_error",
			portScanner: nil,
			wantErr:     ErrNoPortScanner,
		},
		{
			name:        "when_port_scan_fails_returns_error",
			portScanner: fakemodule.NewFakePortScanner("ps1", fakemodule.FakePortScanFnErrors),
			wantErr:     fakemodule.ErrFakePortScanGeneric,
		},
		{
			name:        "when_fingerprinting_fails_returns_error",
			portScanner: fakemodule.NewFakePortScanner("ps1", testReportFn),
			fingerprinters: []module.Fingerprinter{
				fakemodule.NewFakeFingerprinter("fp1", fakemodule.FakeFingerprintFnErrors),
			},
			wantErr: fakemodule.ErrFakeFingerprintGeneric,
		},
		{
			name:        "when_detector_fails_returns_error",
			portScanner: fakemodule.NewFakePortScanner("ps1", testReportFn),
			fingerprinters: []module.Fingerprinter{
				fakemodule.NewFakeFingerprinter("fp1", fakemodule.FakeFingerprintFnDoNothing),
			},
			detectors: []module.VulnDetector{
				fakemodule.NewFakeVulnDetector("d1", fakemodule.FakeDetectFnErrors),
			},
			wantErr: fakemodule.ErrFakeDetectGeneric,
		},
		{
			name:        "when_scan_succeeds_returns_report",
			portScanner: fakemodule.NewFakePortScanner("ps1", testReportFn),
			fingerprinters: []module.Fingerprinter{
				fakemodule.NewFakeFingerprinter("fp1", fakemodule.FakeFingerprintFnDoNothing),
			},
			detectors: []module.VulnDetector{
				fakemodule.NewFakeVulnDetector("d1", fakemodule.FakeDetectFnNoFindings),
			},
			wantErr: nil,
			want: srpb.ScanResults_builder{
				FullDetectionReports: &srpb.FullDetectionReports{},
				ReconnaissanceReport: rpb.ReconnaissanceReport_builder{
					TargetInfo: rpb.TargetInfo_builder{
						NetworkEndpoints: []*npb.NetworkEndpoint{
							npb.NetworkEndpoint_builder{
								Type: npb.NetworkEndpoint_IP,
								IpAddress: npb.IpAddress_builder{
									AddressFamily: npb.AddressFamily_IPV4,
									Address:       "1.1.1.1",
								}.Build(),
							}.Build(),
						},
					}.Build(),
					NetworkServices: []*nspb.NetworkService{
						nspb.NetworkService_builder{ServiceName: "svc1"}.Build(),
						nspb.NetworkService_builder{ServiceName: "svc2"}.Build(),
					},
				}.Build(),
			}.Build(),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, err := New(defaultConfig)
			if err != nil {
				t.Fatalf("New() returned error %v, want nil", err)
			}

			r.portScanner = tc.portScanner
			r.fingerprinters = tc.fingerprinters
			r.detectors = tc.detectors
			got, err := r.Run(context.Background(), "irrelevant")
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Run() error = %v, wantErr %v", err, tc.wantErr)
			}

			if tc.wantErr != nil {
				return
			}

			opts := []cmp.Option{
				protocmp.Transform(),
				protocmp.SortRepeatedFields(&rpb.ReconnaissanceReport{}, "network_services"),
			}
			if diff := cmp.Diff(tc.want, got, opts...); diff != "" {
				t.Errorf("Run() returned diff (-want +got):\n%s", diff)
			}
		})
	}
}
