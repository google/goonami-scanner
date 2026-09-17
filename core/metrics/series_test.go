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
	"testing"
)

func TestSeriesValueForCounter(t *testing.T) {
	counter := testCounter(t)
	collector := NewCollector()
	SetRecorder(collector)
	defer SetRecorder(nil)

	counter.Add(t.Context(), 7)

	all := collector.Series()
	if len(all) != 1 {
		t.Fatalf("Series() returned %d series, want 1", len(all))
	}
	if got := all[0].Value(); got != 7 {
		t.Errorf("Value() = %d, want 7", got)
	}
}

func TestSeriesStatsWhenThereAreNoSamplesIsZero(t *testing.T) {
	series := &Series{Metric: testDistribution(t)}

	if got := series.Stats(); (got != Stats{}) {
		t.Errorf("Stats() = %+v, want the zero value", got)
	}
}

func TestSeriesKeyDistinguishesLabelCombinations(t *testing.T) {
	m := testCounter(t, LabelModule, labelTestKind)

	base := seriesKey(m, []Label{{Key: LabelModule, Value: "a"}})
	other := seriesKey(m, []Label{{Key: LabelModule, Value: "b"}})
	if base == other {
		t.Errorf("seriesKey() returned %q for two different label values, want different keys", base)
	}

	// A value containing the separator must not be able to impersonate another
	// series by shifting the encoding.
	spoofed := seriesKey(m, []Label{{Key: LabelModule, Value: "a|kind=detector"}})
	real := seriesKey(m, []Label{
		{Key: LabelModule, Value: "a"},
		{Key: labelTestKind, Value: "detector"},
	})
	if spoofed == real {
		t.Errorf("seriesKey() collided between a spoofed label value and a real label combination")
	}
}
