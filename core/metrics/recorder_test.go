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
	"math"
	"testing"
)

func TestDefaultRecorderIsNoop(t *testing.T) {
	// Recording without a recorder installed must not panic and must not retain
	// anything: this is the path every open source library user takes.
	counter := testCounter(t)
	SetRecorder(nil)

	counter.Add(t.Context(), 1)
}

func TestSetRecorderRoutesObservations(t *testing.T) {
	counter := testCounter(t)
	collector := NewCollector()

	SetRecorder(collector)
	defer SetRecorder(nil)

	counter.Add(t.Context(), 3)

	if got := collector.Value(t.Context(), counter); got != 3 {
		t.Errorf("Value() = %d, want 3", got)
	}
}

func TestSetRecorderWithNilRestoresNoop(t *testing.T) {
	SetRecorder(NewCollector())
	SetRecorder(nil)

	if _, ok := CurrentRecorder().(NoopRecorder); !ok {
		t.Errorf("CurrentRecorder() = %T, want NoopRecorder", CurrentRecorder())
	}
}

func TestNoopRecorderDiscardsEverything(t *testing.T) {
	counter := NewCounter("collector/noop_counter", "A description.")
	distribution := NewDistribution("collector/noop_duration", "A description.", UnitSeconds)

	var rec Recorder = NoopRecorder{}

	// Must not panic and must not retain anything.
	rec.Add(t.Context(), counter, 1, nil)
	rec.Observe(t.Context(), distribution, math.Pi, nil)
}

func TestCollectorRecordsThroughTheRecorderInterface(t *testing.T) {
	// The Collector is installed as a Recorder, so it must satisfy the interface
	// without the metric handles in between.
	counter := NewCounter("collector/interface_counter", "A description.")
	distribution := NewDistribution("collector/interface_duration", "A description.", UnitSeconds)

	var rec Recorder = NewCollector()
	rec.Add(t.Context(), counter, 2, nil)
	rec.Observe(t.Context(), distribution, 1, nil)

	collector, ok := rec.(*Collector)
	if !ok {
		t.Fatalf("recorder is %T, want *Collector", rec)
	}
	if got := collector.Value(t.Context(), counter); got != 2 {
		t.Errorf("Value() = %d, want 2", got)
	}
	if _, ok := collector.Stats(t.Context(), distribution); !ok {
		t.Errorf("Stats() reported no series, want one")
	}
}
