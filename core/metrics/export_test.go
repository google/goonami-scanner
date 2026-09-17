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

package metrics

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"

	smpb "github.com/google/goonami-scanner/core/metrics/scan_metrics_go_proto"
)

func TestExportCounterSeries(t *testing.T) {
	counter := NewCounter("export/counter", "Exported counter.", LabelModule)
	collector := NewCollector()
	SetRecorder(collector)
	defer SetRecorder(nil)

	counter.Add(t.Context(), 4, Module("webidentity"))

	got := collector.Export()

	want := smpb.ScanMetrics_builder{
		Series: []*smpb.Series{
			smpb.Series_builder{
				Name: "export/counter",
				Labels: []*smpb.Label{
					smpb.Label_builder{Key: "module", Value: "webidentity"}.Build(),
				},
				Counter: proto.Int64(4),
			}.Build(),
		},
	}.Build()

	if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
		t.Errorf("Export() returned an unexpected diff (-want +got):\n%s", diff)
	}
}

func TestExportDistributionSeries(t *testing.T) {
	distribution := NewDistribution("export/distribution", "Exported distribution.", UnitSeconds)
	collector := NewCollector()
	SetRecorder(collector)
	defer SetRecorder(nil)

	// Observed out of order on purpose: the minimum and the maximum must not
	// depend on which sample arrived first.
	for _, sample := range []float64{3, 1, 4, 2} {
		distribution.Observe(t.Context(), sample)
	}

	got := collector.Export()

	want := smpb.ScanMetrics_builder{
		Series: []*smpb.Series{
			smpb.Series_builder{
				Name: "export/distribution",
				Distribution: smpb.Distribution_builder{
					Count: 4,
					Sum:   10,
					Min:   1,
					Max:   4,
				}.Build(),
			}.Build(),
		},
	}.Build()

	if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
		t.Errorf("Export() returned an unexpected diff (-want +got):\n%s", diff)
	}
}

func TestExportWhenNothingWasRecordedIsEmpty(t *testing.T) {
	collector := NewCollector()

	got := collector.Export()

	if len(got.GetSeries()) != 0 {
		t.Errorf("Export() returned %d series, want 0", len(got.GetSeries()))
	}
	if len(got.GetDropped()) != 0 {
		t.Errorf("Export() returned %d dropped metrics, want 0", len(got.GetDropped()))
	}
}

func TestExportReportsDroppedSeries(t *testing.T) {
	counter := NewCounter("export/dropped", "Exported counter.", LabelModule)
	collector := NewCollector(WithMaxSeriesPerMetric(1))
	SetRecorder(collector)
	defer SetRecorder(nil)

	counter.Add(t.Context(), 1, Module("kept"))
	counter.Add(t.Context(), 1, Module("first_dropped"))
	counter.Add(t.Context(), 1, Module("second_dropped"))

	dropped := collector.Export().GetDropped()

	if len(dropped) != 1 {
		t.Fatalf("Export() returned %d dropped metrics, want 1", len(dropped))
	}
	if got := dropped[0].GetMetric(); got != "export/dropped" {
		t.Errorf("dropped metric = %q, want %q", got, "export/dropped")
	}
	if got := dropped[0].GetObservations(); got != 2 {
		t.Errorf("dropped observations = %d, want 2", got)
	}
}

func TestExportOrdersSeriesDeterministically(t *testing.T) {
	counter := NewCounter("export/ordered", "Exported counter.", LabelModule)
	collector := NewCollector()
	SetRecorder(collector)
	defer SetRecorder(nil)

	for _, module := range []string{"zeta", "alpha", "mu"} {
		counter.Add(t.Context(), 1, Module(module))
	}

	series := collector.Export().GetSeries()

	want := []string{"alpha", "mu", "zeta"}
	if len(series) != len(want) {
		t.Fatalf("Export() returned %d series, want %d", len(series), len(want))
	}
	for i, wantValue := range want {
		if got := series[i].GetLabels()[0].GetValue(); got != wantValue {
			t.Errorf("series[%d] label = %q, want %q", i, got, wantValue)
		}
	}
}

func TestWriteFileRoundTrips(t *testing.T) {
	counter := NewCounter("export/write_counter", "Exported counter.", LabelModule)
	distribution := NewDistribution("export/write_duration", "Exported distribution.", UnitSeconds)
	collector := NewCollector()
	SetRecorder(collector)
	defer SetRecorder(nil)

	counter.Add(t.Context(), 2, Module("nmap"))
	distribution.Observe(t.Context(), 1.5)

	path := filepath.Join(t.TempDir(), "metrics.textproto")
	if err := collector.WriteFile(path); err != nil {
		t.Fatalf("WriteFile() returned an unexpected error: %v", err)
	}

	written, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading back the metrics file failed: %v", err)
	}

	parsed := &smpb.ScanMetrics{}
	if err := prototext.Unmarshal(written, parsed); err != nil {
		t.Fatalf("the written file is not a valid textproto: %v", err)
	}

	if diff := cmp.Diff(collector.Export(), parsed, protocmp.Transform()); diff != "" {
		t.Errorf("the written file does not match what was collected (-want +got):\n%s", diff)
	}
}

func TestWriteFileWhenThePathIsNotWritableReturnsError(t *testing.T) {
	collector := NewCollector()

	err := collector.WriteFile(filepath.Join(t.TempDir(), "missing_directory", "metrics.textproto"))

	if err == nil {
		t.Fatalf("WriteFile() returned no error, want one")
	}
	if !errors.Is(err, ErrWriteMetrics) {
		t.Errorf("WriteFile() returned %v, want it to wrap ErrWriteMetrics", err)
	}
}
