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

package fakerunner

import (
	"context"
	"errors"
	"testing"

	"github.com/google/goonami-scanner/common/testfakes/fakemodule"
	"github.com/google/goonami-scanner/core/module"
	srpb "github.com/google/tsunami-security-scanner/proto/go/scan_results_go_proto"
)

func TestNew(t *testing.T) {
	if New() == nil {
		t.Errorf("New() returned nil")
	}
}

func TestFakeRunner_RegisterPortScanner(t *testing.T) {
	errOverride := errors.New("override error")
	tests := []struct {
		name       string
		overrideFn OverrideRegisterPortScannerFn
		ps         module.PortScanner
		wantErr    error
		wantPs     bool
	}{
		{
			name:   "when_no_override_is_provided_it_registers_successfully",
			ps:     fakemodule.NewFakePortScanner("ps1", nil),
			wantPs: true,
		},
		{
			name: "when_override_returns_success_it_uses_override_logic",
			overrideFn: func(ctx context.Context, ps module.PortScanner) error {
				return nil
			},
			ps:     fakemodule.NewFakePortScanner("ps1", nil),
			wantPs: false,
		},
		{
			name: "when_override_returns_error_it_propagates_error",
			overrideFn: func(ctx context.Context, ps module.PortScanner) error {
				return errOverride
			},
			ps:      fakemodule.NewFakePortScanner("ps1", nil),
			wantErr: errOverride,
			wantPs:  false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := New()
			r.OverrideRegisterPortScanner(tc.overrideFn)

			err := r.RegisterPortScanner(context.Background(), tc.ps)
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("RegisterPortScanner(%v) returned error %v, wantErr=%v", tc.ps, err, tc.wantErr)
			}

			if tc.wantErr != nil {
				return
			}

			if tc.wantPs && r.PortScanner() != tc.ps {
				t.Errorf("PortScanner() returned %v, want %v", r.PortScanner(), tc.ps)
			}

			if !tc.wantPs && r.PortScanner() != nil {
				t.Errorf("PortScanner() returned %v, want nil", r.PortScanner())
			}
		})
	}
}

func TestFakeRunner_RegisterFingerprinter(t *testing.T) {
	errOverride := errors.New("override error")
	tests := []struct {
		name       string
		overrideFn OverrideRegisterFingerprinterFn
		fp         module.Fingerprinter
		wantErr    error
		wantFp     bool
	}{
		{
			name:   "when_no_override_is_provided_it_registers_successfully",
			fp:     fakemodule.NewFakeFingerprinter("fp1", nil),
			wantFp: true,
		},
		{
			name: "when_override_returns_success_it_uses_override_logic",
			overrideFn: func(ctx context.Context, fp module.Fingerprinter) error {
				return nil
			},
			fp:     fakemodule.NewFakeFingerprinter("fp1", nil),
			wantFp: false,
		},
		{
			name: "when_override_returns_error_it_propagates_error",
			overrideFn: func(ctx context.Context, fp module.Fingerprinter) error {
				return errOverride
			},
			fp:      fakemodule.NewFakeFingerprinter("fp1", nil),
			wantErr: errOverride,
			wantFp:  false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := New()
			r.OverrideRegisterFingerprinter(tc.overrideFn)

			err := r.RegisterFingerprinter(context.Background(), tc.fp)
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("RegisterFingerprinter(%v) returned error %v, wantErr=%v", tc.fp, err, tc.wantErr)
			}

			if tc.wantErr != nil {
				return
			}

			if tc.wantFp && len(r.Fingerprinters()) != 1 {
				t.Errorf("Fingerprinters() returned %d fingerprinters, want 1", len(r.Fingerprinters()))
			}

			if !tc.wantFp && len(r.Fingerprinters()) != 0 {
				t.Errorf("Fingerprinters() returned %d fingerprinters, want 0", len(r.Fingerprinters()))
			}
		})
	}
}

func TestFakeRunner_RegisterDetector(t *testing.T) {
	errOverride := errors.New("override error")
	tests := []struct {
		name       string
		overrideFn OverrideRegisterDetectorFn
		d          module.VulnDetector
		wantErr    error
		wantD      bool
	}{
		{
			name:  "when_no_override_is_provided_it_registers_successfully",
			d:     fakemodule.NewFakeVulnDetector("d1", fakemodule.FakeDetectFnNoFindings),
			wantD: true,
		},
		{
			name: "when_override_returns_success_it_uses_override_logic",
			overrideFn: func(ctx context.Context, d module.VulnDetector) error {
				return nil
			},
			d:     fakemodule.NewFakeVulnDetector("d1", fakemodule.FakeDetectFnNoFindings),
			wantD: false,
		},
		{
			name: "when_override_returns_error_it_propagates_error",
			overrideFn: func(ctx context.Context, d module.VulnDetector) error {
				return errOverride
			},
			d:       fakemodule.NewFakeVulnDetector("d1", fakemodule.FakeDetectFnNoFindings),
			wantErr: errOverride,
			wantD:   false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := New()
			r.OverrideRegisterDetector(tc.overrideFn)

			err := r.RegisterDetector(context.Background(), tc.d)
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("RegisterDetector(%v) returned error %v, wantErr=%v", tc.d, err, tc.wantErr)
			}

			if tc.wantErr != nil {
				return
			}

			if tc.wantD && len(r.Detectors()) != 1 {
				t.Errorf("Detectors() returned %d detectors, want 1", len(r.Detectors()))
			}

			if !tc.wantD && len(r.Detectors()) != 0 {
				t.Errorf("Detectors() returned %d detectors, want 0", len(r.Detectors()))
			}
		})
	}
}

func TestFakeRunner_Run(t *testing.T) {
	errOverride := errors.New("override error")
	tests := []struct {
		name       string
		overrideFn OverrideRunFn
		wantRes    bool
		wantErr    error
	}{
		{
			name: "when_no_override_is_provided_it_returns_nil",
		},
		{
			name: "when_override_returns_success_it_returns_results",
			overrideFn: func(ctx context.Context, target string) (*srpb.ScanResults, error) {
				return &srpb.ScanResults{}, nil
			},
			wantRes: true,
		},
		{
			name: "when_override_returns_error_it_propagates_error",
			overrideFn: func(ctx context.Context, target string) (*srpb.ScanResults, error) {
				return nil, errOverride
			},
			wantErr: errOverride,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := New()
			r.OverrideRun(tc.overrideFn)

			res, err := r.Run(context.Background(), "target")
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("Run() returned error %v, wantErr=%v", err, tc.wantErr)
			}

			if tc.wantErr != nil {
				return
			}

			if tc.wantRes && res == nil {
				t.Errorf("Run() returned nil results, want non-nil")
			}

			if !tc.wantRes && res != nil {
				t.Errorf("Run() returned non-nil results %v, want nil", res)
			}
		})
	}
}
