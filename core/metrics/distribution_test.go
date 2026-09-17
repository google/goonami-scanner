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

func TestObserveAcceptsAnyValue(t *testing.T) {
	cases := []struct {
		name  string
		value float64
	}{
		{name: "negative_value_is_recorded", value: -1.5},
		{name: "zero_is_recorded", value: 0},
		{name: "positive_value_is_recorded", value: 2.5},
		{name: "very_large_value_is_recorded", value: math.MaxFloat64},
		{name: "very_small_value_is_recorded", value: -math.MaxFloat64},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			distribution := testDistribution(t)
			collector := NewCollector()
			SetRecorder(collector)
			defer SetRecorder(nil)

			distribution.Observe(t.Context(), tc.value)

			stats, ok := collector.Stats(t.Context(), distribution)
			if !ok {
				t.Fatalf("Stats() reported no series, want the sample to be recorded")
			}
			if stats.Count != 1 {
				t.Errorf("Stats().Count = %d, want 1", stats.Count)
			}
			if stats.Sum != tc.value {
				t.Errorf("Stats().Sum = %v, want %v", stats.Sum, tc.value)
			}
			if stats.Min != tc.value {
				t.Errorf("Stats().Min = %v, want %v", stats.Min, tc.value)
			}
			if stats.Max != tc.value {
				t.Errorf("Stats().Max = %v, want %v", stats.Max, tc.value)
			}
		})
	}
}
