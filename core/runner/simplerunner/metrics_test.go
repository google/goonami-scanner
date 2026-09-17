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
	"testing"

	"github.com/google/goonami-scanner/common/testfakes/fakemodule"
	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/metrics"
	"github.com/google/goonami-scanner/core/module"

	cpb "github.com/google/goonami-scanner/core/config/config_go_proto"
	dpb "github.com/google/tsunami-security-scanner/proto/go/detection_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
	rpb "github.com/google/tsunami-security-scanner/proto/go/reconnaissance_go_proto"
	vpb "github.com/google/tsunami-security-scanner/proto/go/vulnerability_go_proto"
)

// installCollector installs a metrics collector for the duration of the test and
// restores the default recorder afterwards.
func installCollector(t *testing.T) *metrics.Collector {
	t.Helper()
	collector := metrics.NewCollector()
	metrics.SetRecorder(collector)
	t.Cleanup(func() { metrics.SetRecorder(nil) })
	return collector
}

// newRunnerForMetrics builds a runner with the given modules registered.
func newRunnerForMetrics(t *testing.T, portScanner module.PortScanner, fingerprinters []module.Fingerprinter, detectors []module.VulnDetector) *SimpleRunner {
	t.Helper()
	ctx := t.Context()

	runner, err := New(config.FromProto(cpb.Config_builder{}.Build()))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if portScanner != nil {
		if err := runner.RegisterPortScanner(ctx, portScanner); err != nil {
			t.Fatalf("RegisterPortScanner() error = %v", err)
		}
	}
	for _, fp := range fingerprinters {
		if err := runner.RegisterFingerprinter(ctx, fp); err != nil {
			t.Fatalf("RegisterFingerprinter() error = %v", err)
		}
	}
	for _, dt := range detectors {
		if err := runner.RegisterDetector(ctx, dt); err != nil {
			t.Fatalf("RegisterDetector() error = %v", err)
		}
	}
	return runner
}

// scanReport returns a port scanning report exposing one service per name.
func scanReport(names ...string) func(ctx context.Context, target string) (*rpb.PortScanningReport, error) {
	services := make([]*nspb.NetworkService, 0, len(names))
	for _, name := range names {
		services = append(services, nspb.NetworkService_builder{ServiceName: name}.Build())
	}

	report := rpb.PortScanningReport_builder{NetworkServices: services}.Build()
	return func(ctx context.Context, target string) (*rpb.PortScanningReport, error) {
		return report, nil
	}
}

// detectOneFinding returns a detect function reporting one finding for every
// service it is given.
func detectOneFinding() fakemodule.FakeDetectFn {
	return func(ctx context.Context, svc *nspb.NetworkService) (*dpb.DetectionReportList, error) {
		return dpb.DetectionReportList_builder{
			DetectionReports: []*dpb.DetectionReport{
				dpb.DetectionReport_builder{
					DetectionStatus: dpb.DetectionStatus_VULNERABILITY_VERIFIED,
					NetworkService:  svc,
					Vulnerability: vpb.Vulnerability_builder{
						MainId:   vpb.VulnerabilityId_builder{Publisher: "FAKE", Value: "Vuln"}.Build(),
						Title:    "Fake Vulnerability",
						Severity: vpb.Severity_HIGH,
					}.Build(),
				}.Build(),
			},
		}.Build(), nil
	}
}

func TestRunRecordsPhaseMetrics(t *testing.T) {
	testCases := []struct {
		name                   string
		portScanner            module.PortScanner
		fingerprinters         []module.Fingerprinter
		detectors              []module.VulnDetector
		wantErr                error
		wantServicesDiscovered int64
		wantTimed              []*metrics.Distribution
		wantNotTimed           []*metrics.Distribution
		wantTotal              bool
	}{
		{
			name:                   "when_scan_succeeds_every_phase_is_timed",
			portScanner:            fakemodule.NewFakePortScanner("ps1", scanReport("svc1", "svc2")),
			fingerprinters:         []module.Fingerprinter{fakemodule.NewFakeFingerprinter("fp1", fakemodule.FakeFingerprintFnDoNothing)},
			detectors:              []module.VulnDetector{fakemodule.NewFakeVulnDetector("d1", fakemodule.FakeDetectFnNoFindings)},
			wantServicesDiscovered: 2,
			wantTimed: []*metrics.Distribution{
				metrics.PortScanDuration, metrics.FingerprintDuration, metrics.DetectDuration,
			},
			wantTotal: true,
		},
		{
			name:                   "when_no_service_is_found_services_discovered_is_not_recorded",
			portScanner:            fakemodule.NewFakePortScanner("ps1", scanReport()),
			fingerprinters:         []module.Fingerprinter{fakemodule.NewFakeFingerprinter("fp1", fakemodule.FakeFingerprintFnDoNothing)},
			detectors:              []module.VulnDetector{fakemodule.NewFakeVulnDetector("d1", fakemodule.FakeDetectFnNoFindings)},
			wantServicesDiscovered: 0,
			wantTimed: []*metrics.Distribution{
				metrics.PortScanDuration, metrics.FingerprintDuration, metrics.DetectDuration,
			},
			wantTotal: true,
		},
		{
			name:        "when_port_scan_fails_later_phases_are_not_timed",
			portScanner: fakemodule.NewFakePortScanner("ps1", fakemodule.FakePortScanFnErrors),
			wantErr:     fakemodule.ErrFakePortScanGeneric,
			wantNotTimed: []*metrics.Distribution{
				metrics.PortScanDuration, metrics.FingerprintDuration, metrics.DetectDuration,
			},
		},
		{
			name:           "when_fingerprinting_fails_only_the_port_scan_phase_is_timed",
			portScanner:    fakemodule.NewFakePortScanner("ps1", scanReport("svc1")),
			fingerprinters: []module.Fingerprinter{fakemodule.NewFakeFingerprinter("fp1", fakemodule.FakeFingerprintFnErrors)},
			wantErr:        fakemodule.ErrFakeFingerprintGeneric,
			wantTimed:      []*metrics.Distribution{metrics.PortScanDuration},
			wantNotTimed: []*metrics.Distribution{
				metrics.FingerprintDuration, metrics.DetectDuration,
			},
			wantServicesDiscovered: 1,
		},
		{
			name:           "when_detection_fails_the_whole_scan_is_not_timed",
			portScanner:    fakemodule.NewFakePortScanner("ps1", scanReport("svc1")),
			fingerprinters: []module.Fingerprinter{fakemodule.NewFakeFingerprinter("fp1", fakemodule.FakeFingerprintFnDoNothing)},
			detectors:      []module.VulnDetector{fakemodule.NewFakeVulnDetector("d1", fakemodule.FakeDetectFnErrors)},
			wantErr:        fakemodule.ErrFakeDetectGeneric,
			wantTimed:      []*metrics.Distribution{metrics.PortScanDuration, metrics.FingerprintDuration},
			wantNotTimed: []*metrics.Distribution{
				metrics.DetectDuration,
			},
			wantServicesDiscovered: 1,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			collector := installCollector(t)
			runner := newRunnerForMetrics(t, tc.portScanner, tc.fingerprinters, tc.detectors)

			if _, err := runner.Run(t.Context(), "1.1.1.1"); !errors.Is(err, tc.wantErr) {
				t.Fatalf("Run() error = %v, wantErr %v", err, tc.wantErr)
			}

			for _, phase := range tc.wantTimed {
				if stats, ok := collector.Stats(t.Context(), phase); !ok || stats.Count != 1 {
					t.Errorf("%s = (%+v, %t), want a single sample", phase.Name(), stats, ok)
				}
			}
			for _, phase := range tc.wantNotTimed {
				if _, ok := collector.Stats(t.Context(), phase); ok {
					t.Errorf("%s was recorded, want no sample", phase.Name())
				}
			}

			// The whole-scan duration is the parent of the phase metrics rather
			// than one of them, so that globbing "scan/duration/*" and summing
			// cannot accidentally include it.
			if _, ok := collector.Stats(t.Context(), metrics.ScanDuration); ok != tc.wantTotal {
				t.Errorf("scan/duration recorded = %t, want %t", ok, tc.wantTotal)
			}

			if got := collector.Value(t.Context(), metrics.ServicesDiscovered); got != tc.wantServicesDiscovered {
				t.Errorf("services/discovered = %d, want %d", got, tc.wantServicesDiscovered)
			}
		})
	}
}

func TestRunRecordsModuleMetrics(t *testing.T) {
	testCases := []struct {
		name           string
		portScanner    module.PortScanner
		fingerprinters []module.Fingerprinter
		detectors      []module.VulnDetector
		wantErr        error
		// wantRuns is keyed by module name and holds the expected invocation
		// count and the expected error count. Successes are the difference of
		// the two, and the invocation count is read from module/duration.
		wantRuns map[string]moduleExpectation
	}{
		{
			name:           "when_modules_succeed_runs_are_counted_once_per_service",
			portScanner:    fakemodule.NewFakePortScanner("ps1", scanReport("svc1", "svc2")),
			fingerprinters: []module.Fingerprinter{fakemodule.NewFakeFingerprinter("fp1", fakemodule.FakeFingerprintFnDoNothing)},
			detectors:      []module.VulnDetector{fakemodule.NewFakeVulnDetector("d1", fakemodule.FakeDetectFnNoFindings)},
			wantRuns: map[string]moduleExpectation{
				"ps1": {runs: 1},
				"fp1": {runs: 2},
				"d1":  {runs: 2},
			},
		},
		{
			name:        "when_the_port_scanner_fails_the_error_is_counted",
			portScanner: fakemodule.NewFakePortScanner("ps1", fakemodule.FakePortScanFnErrors),
			wantErr:     fakemodule.ErrFakePortScanGeneric,
			wantRuns: map[string]moduleExpectation{
				"ps1": {runs: 1, errs: 1},
			},
		},
		{
			name:           "when_a_detector_fails_the_error_is_counted",
			portScanner:    fakemodule.NewFakePortScanner("ps1", scanReport("svc1")),
			fingerprinters: []module.Fingerprinter{fakemodule.NewFakeFingerprinter("fp1", fakemodule.FakeFingerprintFnDoNothing)},
			detectors:      []module.VulnDetector{fakemodule.NewFakeVulnDetector("d1", fakemodule.FakeDetectFnErrors)},
			wantErr:        fakemodule.ErrFakeDetectGeneric,
			wantRuns: map[string]moduleExpectation{
				"ps1": {runs: 1},
				"fp1": {runs: 1},
				"d1":  {runs: 1, errs: 1},
			},
		},
		{
			name:        "when_several_modules_of_a_kind_run_each_is_attributed_separately",
			portScanner: fakemodule.NewFakePortScanner("ps1", scanReport("svc1")),
			fingerprinters: []module.Fingerprinter{
				fakemodule.NewFakeFingerprinter("fp1", fakemodule.FakeFingerprintFnDoNothing),
				fakemodule.NewFakeFingerprinter("fp2", fakemodule.FakeFingerprintFnDoNothing),
			},
			detectors: []module.VulnDetector{
				fakemodule.NewFakeVulnDetector("d1", fakemodule.FakeDetectFnNoFindings),
				fakemodule.NewFakeVulnDetector("d2", fakemodule.FakeDetectFnNoFindings),
			},
			wantRuns: map[string]moduleExpectation{
				"ps1": {runs: 1},
				"fp1": {runs: 1},
				"fp2": {runs: 1},
				"d1":  {runs: 1},
				"d2":  {runs: 1},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			collector := installCollector(t)
			runner := newRunnerForMetrics(t, tc.portScanner, tc.fingerprinters, tc.detectors)

			if _, err := runner.Run(t.Context(), "1.1.1.1"); !errors.Is(err, tc.wantErr) {
				t.Fatalf("Run() error = %v, wantErr %v", err, tc.wantErr)
			}

			for name, want := range tc.wantRuns {
				moduleLabel := metrics.Module(name)

				// The duration is observed for failures too, so its sample count
				// is the invocation count. Nothing else records that number.
				stats, ok := collector.Stats(t.Context(), metrics.ModuleDuration, moduleLabel)
				if !ok || stats.Count != want.runs {
					t.Errorf("module/duration[%s] = (%+v, %t), want %d samples", name, stats, ok, want.runs)
				}

				// Errors are only recorded for the runs that failed, and always
				// with a bounded class rather than the error message.
				got := collector.Value(t.Context(), metrics.ModuleErrors, moduleLabel, metrics.ErrorClass(tc.wantErr))
				if want.errs == 0 {
					got = totalModuleErrors(collector, name)
				}
				if got != want.errs {
					t.Errorf("module/errors[%s] = %d, want %d", name, got, want.errs)
				}

				// Successful runs are not recorded on their own: they are the
				// difference, and that arithmetic has to hold.
				if gotSuccesses := stats.Count - got; gotSuccesses != want.runs-want.errs {
					t.Errorf("successful runs of %s = %d, want %d", name, gotSuccesses, want.runs-want.errs)
				}
			}
		})
	}
}

type moduleExpectation struct {
	runs int64
	errs int64
}

// totalModuleErrors sums every module/errors series belonging to a module,
// whatever its error class. It is used to assert that a module recorded no error
// at all, which a single lookup cannot prove.
func totalModuleErrors(collector *metrics.Collector, name string) int64 {
	var total int64
	for _, series := range collector.Series() {
		if series.Metric != metrics.ModuleErrors {
			continue
		}
		for _, label := range series.Labels {
			if label.Key == metrics.LabelModule && label.Value == name {
				total += series.Value()
			}
		}
	}
	return total
}

func TestRunRecordsFindings(t *testing.T) {
	testCases := []struct {
		name         string
		detectors    []module.VulnDetector
		services     []string
		wantFindings map[string]int64
	}{
		{
			name:         "when_no_finding_is_reported_nothing_is_counted",
			detectors:    []module.VulnDetector{fakemodule.NewFakeVulnDetector("d1", fakemodule.FakeDetectFnNoFindings)},
			services:     []string{"svc1"},
			wantFindings: map[string]int64{},
		},
		{
			name:         "when_findings_are_reported_they_are_counted_once_per_service",
			detectors:    []module.VulnDetector{fakemodule.NewFakeVulnDetector("d1", detectOneFinding())},
			services:     []string{"svc1", "svc2"},
			wantFindings: map[string]int64{"d1": 2},
		},
		{
			name: "when_several_detectors_report_each_is_attributed_separately",
			detectors: []module.VulnDetector{
				fakemodule.NewFakeVulnDetector("d1", detectOneFinding()),
				fakemodule.NewFakeVulnDetector("d2", fakemodule.FakeDetectFnNoFindings),
			},
			services:     []string{"svc1"},
			wantFindings: map[string]int64{"d1": 1, "d2": 0},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			collector := installCollector(t)
			runner := newRunnerForMetrics(t,
				fakemodule.NewFakePortScanner("ps1", scanReport(tc.services...)),
				[]module.Fingerprinter{fakemodule.NewFakeFingerprinter("fp1", fakemodule.FakeFingerprintFnDoNothing)},
				tc.detectors)

			if _, err := runner.Run(t.Context(), "1.1.1.1"); err != nil {
				t.Fatalf("Run() error = %v", err)
			}

			if len(tc.wantFindings) == 0 {
				for _, series := range collector.Series() {
					if series.Metric == metrics.Findings {
						t.Errorf("findings series %v was recorded, want none", series.Labels)
					}
				}
				return
			}

			for name, want := range tc.wantFindings {
				if got := collector.Value(t.Context(), metrics.Findings, metrics.Module(name)); got != want {
					t.Errorf("findings[%s] = %d, want %d", name, got, want)
				}
			}
		})
	}
}
