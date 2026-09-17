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
	"fmt"
	"sync"
	"testing"
)

func TestCollectorAddAccumulates(t *testing.T) {
	counter := testCounter(t)
	collector := NewCollector()
	SetRecorder(collector)
	defer SetRecorder(nil)

	counter.Add(t.Context(), 2)
	counter.Add(t.Context(), 3)

	if got := collector.Value(t.Context(), counter); got != 5 {
		t.Errorf("Value() = %d, want 5", got)
	}
}

func TestCollectorSeparatesSeriesByLabels(t *testing.T) {
	counter := testCounter(t, LabelModule)
	collector := NewCollector()
	SetRecorder(collector)
	defer SetRecorder(nil)

	counter.Add(t.Context(), 1, Module("webidentity"))
	counter.Add(t.Context(), 2, Module("nmap"))
	counter.Add(t.Context(), 4, Module("webidentity"))

	if got := collector.Value(t.Context(), counter, Module("webidentity")); got != 5 {
		t.Errorf("Value(webidentity) = %d, want 5", got)
	}
	if got := collector.Value(t.Context(), counter, Module("nmap")); got != 2 {
		t.Errorf("Value(nmap) = %d, want 2", got)
	}
}

func TestCollectorValueIsOrderIndependent(t *testing.T) {
	counter := testCounter(t, LabelModule, labelTestKind)
	collector := NewCollector()
	SetRecorder(collector)
	defer SetRecorder(nil)

	counter.Add(t.Context(), 1, Module("nmap"), Label{Key: labelTestKind, Value: "portscan"})

	// Looking the series up with the labels in the other order must find it.
	if got := collector.Value(t.Context(), counter, Label{Key: labelTestKind, Value: "portscan"}, Module("nmap")); got != 1 {
		t.Errorf("Value() with reordered labels = %d, want 1", got)
	}
}

func TestCollectorValueWhenSeriesIsMissingReturnsZero(t *testing.T) {
	counter := testCounter(t, LabelModule)
	collector := NewCollector()

	if got := collector.Value(t.Context(), counter, Module("never_recorded")); got != 0 {
		t.Errorf("Value() = %d, want 0", got)
	}
}

func TestCollectorStats(t *testing.T) {
	testCases := []struct {
		name    string
		samples []float64
		want    Stats
	}{
		{
			name:    "when_there_is_one_sample_every_statistic_is_that_sample",
			samples: []float64{2},
			want:    Stats{Count: 1, Sum: 2, Min: 2, Max: 2},
		},
		{
			name:    "when_there_are_several_samples_it_summarizes_them",
			samples: []float64{1, 2, 3, 4},
			want:    Stats{Count: 4, Sum: 10, Min: 1, Max: 4},
		},
		{
			name:    "when_samples_are_unordered_it_still_summarizes_them",
			samples: []float64{4, 1, 3, 2},
			want:    Stats{Count: 4, Sum: 10, Min: 1, Max: 4},
		},
		{
			name:    "when_samples_are_negative_it_still_summarizes_them",
			samples: []float64{-3, 1, -5},
			want:    Stats{Count: 3, Sum: -7, Min: -5, Max: 1},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			distribution := testDistribution(t)
			collector := NewCollector()
			SetRecorder(collector)
			defer SetRecorder(nil)

			for _, sample := range tc.samples {
				distribution.Observe(t.Context(), sample)
			}

			got, ok := collector.Stats(t.Context(), distribution)
			if !ok {
				t.Fatalf("Stats() reported no series, want one")
			}
			if got != tc.want {
				t.Errorf("Stats() = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestCollectorStatsWhenSeriesIsMissingReportsIt(t *testing.T) {
	distribution := testDistribution(t)
	collector := NewCollector()

	got, ok := collector.Stats(t.Context(), distribution)

	if ok {
		t.Errorf("Stats() reported a series, want none")
	}
	if (got != Stats{}) {
		t.Errorf("Stats() = %+v, want the zero value", got)
	}
}

func TestCollectorStatsFoldsManySamples(t *testing.T) {
	// Samples are folded as they arrive rather than retained, so the summary has
	// to stay exact over a long run.
	distribution := testDistribution(t)
	collector := NewCollector()
	SetRecorder(collector)
	defer SetRecorder(nil)

	const samples = 10000
	for i := 1; i <= samples; i++ {
		distribution.Observe(t.Context(), float64(i))
	}

	got, ok := collector.Stats(t.Context(), distribution)
	if !ok {
		t.Fatalf("Stats() reported no series, want one")
	}
	want := Stats{Count: samples, Sum: samples * (samples + 1) / 2, Min: 1, Max: samples}
	if got != want {
		t.Errorf("Stats() = %+v, want %+v", got, want)
	}
}

func TestCollectorStatsSeparatesSeriesByLabels(t *testing.T) {
	distribution := testDistribution(t, LabelModule)
	collector := NewCollector()
	SetRecorder(collector)
	defer SetRecorder(nil)

	distribution.Observe(t.Context(), 1, Module("nmap"))
	distribution.Observe(t.Context(), 2, Module("webidentity"))
	distribution.Observe(t.Context(), 3, Module("nmap"))

	got, ok := collector.Stats(t.Context(), distribution, Module("nmap"))
	if !ok {
		t.Fatalf("Stats(nmap) reported no series, want one")
	}
	if want := (Stats{Count: 2, Sum: 4, Min: 1, Max: 3}); got != want {
		t.Errorf("Stats(nmap) = %+v, want %+v", got, want)
	}
}

func TestCollectorCardinalityCap(t *testing.T) {
	testCases := []struct {
		name          string
		max           int
		distinct      int
		wantSeries    int
		wantDropped   int64
		wantCollected int64
	}{
		{
			name:          "when_below_the_cap_every_series_is_kept",
			max:           5,
			distinct:      3,
			wantSeries:    3,
			wantDropped:   0,
			wantCollected: 1,
		},
		{
			name:          "when_at_the_cap_every_series_is_kept",
			max:           3,
			distinct:      3,
			wantSeries:    3,
			wantDropped:   0,
			wantCollected: 1,
		},
		{
			name:          "when_above_the_cap_the_extra_series_are_dropped",
			max:           3,
			distinct:      10,
			wantSeries:    3,
			wantDropped:   7,
			wantCollected: 1,
		},
		{
			name:          "when_the_cap_is_disabled_every_series_is_kept",
			max:           0,
			distinct:      50,
			wantSeries:    50,
			wantDropped:   0,
			wantCollected: 1,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			counter := testCounter(t, LabelModule)
			collector := NewCollector(WithMaxSeriesPerMetric(tc.max))
			SetRecorder(collector)
			defer SetRecorder(nil)

			for i := 0; i < tc.distinct; i++ {
				counter.Add(t.Context(), 1, Module(fmt.Sprintf("module_%d", i)))
			}

			if got := len(collector.Series()); got != tc.wantSeries {
				t.Errorf("len(Series()) = %d, want %d", got, tc.wantSeries)
			}
			if got := collector.DroppedObservations(counter); got != tc.wantDropped {
				t.Errorf("DroppedObservations() = %d, want %d", got, tc.wantDropped)
			}
			// The series created before the cap was reached keep accumulating.
			if got := collector.Value(t.Context(), counter, Module("module_0")); got != tc.wantCollected {
				t.Errorf("Value(module_0) = %d, want %d", got, tc.wantCollected)
			}
		})
	}
}

func TestCollectorCapDoesNotBlockExistingSeries(t *testing.T) {
	counter := testCounter(t, LabelModule)
	collector := NewCollector(WithMaxSeriesPerMetric(1))
	SetRecorder(collector)
	defer SetRecorder(nil)

	counter.Add(t.Context(), 1, Module("kept"))
	counter.Add(t.Context(), 1, Module("dropped"))
	counter.Add(t.Context(), 5, Module("kept"))

	if got := collector.Value(t.Context(), counter, Module("kept")); got != 6 {
		t.Errorf("Value(kept) = %d, want 6", got)
	}
	if got := collector.Value(t.Context(), counter, Module("dropped")); got != 0 {
		t.Errorf("Value(dropped) = %d, want 0", got)
	}
	if got := collector.DroppedObservations(counter); got != 1 {
		t.Errorf("DroppedObservations() = %d, want 1", got)
	}
}

func TestCollectorCapAppliesPerMetric(t *testing.T) {
	first := NewCounter("collector/cap_first", "A description.", LabelModule)
	second := NewCounter("collector/cap_second", "A description.", LabelModule)
	collector := NewCollector(WithMaxSeriesPerMetric(1))
	SetRecorder(collector)
	defer SetRecorder(nil)

	first.Add(t.Context(), 1, Module("a"))
	second.Add(t.Context(), 1, Module("b"))

	if got := collector.Value(t.Context(), second, Module("b")); got != 1 {
		t.Errorf("Value() on the second metric = %d, want 1: the cap must be per metric", got)
	}
}

func TestCollectorObserveRespectsTheCap(t *testing.T) {
	distribution := testDistribution(t, LabelModule)
	collector := NewCollector(WithMaxSeriesPerMetric(1))
	SetRecorder(collector)
	defer SetRecorder(nil)

	distribution.Observe(t.Context(), 1, Module("kept"))
	distribution.Observe(t.Context(), 2, Module("dropped"))

	if _, ok := collector.Stats(t.Context(), distribution, Module("dropped")); ok {
		t.Errorf("Stats(dropped) reported a series, want none")
	}
	if got := collector.DroppedObservations(distribution); got != 1 {
		t.Errorf("DroppedObservations() = %d, want 1", got)
	}
}

func TestCollectorSeriesIsOrderedDeterministically(t *testing.T) {
	counter := NewCounter("collector/ordered", "A description.", LabelModule)
	collector := NewCollector()
	SetRecorder(collector)
	defer SetRecorder(nil)

	for _, module := range []string{"zeta", "alpha", "mu"} {
		counter.Add(t.Context(), 1, Module(module))
	}

	var got []string
	for _, series := range collector.Series() {
		got = append(got, series.Labels[0].Value)
	}

	want := []string{"alpha", "mu", "zeta"}
	if len(got) != len(want) {
		t.Fatalf("Series() = %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("Series()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestCollectorIsSafeForConcurrentUse(t *testing.T) {
	// The runner fingerprints and detects services in parallel, so the collector
	// is written from several goroutines at once. Run with --race.
	counter := NewCounter("collector/concurrent_counter", "A description.", LabelModule)
	distribution := NewDistribution("collector/concurrent_duration", "A description.", UnitSeconds, LabelModule)
	collector := NewCollector()
	SetRecorder(collector)
	defer SetRecorder(nil)

	const goroutines = 8
	const perGoroutine = 100

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				counter.Add(t.Context(), 1, Module("shared"))
				counter.Add(t.Context(), 1, Module(fmt.Sprintf("goroutine_%d", g)))
				distribution.Observe(t.Context(), float64(i), Module("shared"))
			}
		}(g)
	}
	wg.Wait()

	if got := collector.Value(t.Context(), counter, Module("shared")); got != goroutines*perGoroutine {
		t.Errorf("Value(shared) = %d, want %d", got, goroutines*perGoroutine)
	}

	stats, ok := collector.Stats(t.Context(), distribution, Module("shared"))
	if !ok {
		t.Fatalf("Stats(shared) reported no series, want one")
	}
	if stats.Count != goroutines*perGoroutine {
		t.Errorf("Stats(shared).Count = %d, want %d", stats.Count, goroutines*perGoroutine)
	}
}
