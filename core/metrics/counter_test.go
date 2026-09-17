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

func TestAddRejectsInvalidObservations(t *testing.T) {
	testCases := []struct {
		name  string
		delta int64
		want  int64
	}{
		{
			name:  "when_delta_is_positive_it_records",
			delta: 5,
			want:  5,
		},
		{
			name:  "when_delta_is_zero_it_records",
			delta: 0,
			want:  0,
		},
		{
			name:  "when_delta_is_negative_it_drops_the_observation",
			delta: -5,
			want:  0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			m := testCounter(t)
			collector := NewCollector()
			SetRecorder(collector)
			defer SetRecorder(nil)

			m.Add(t.Context(), tc.delta)

			if got := collector.Value(t.Context(), m); got != tc.want {
				t.Errorf("Value() = %d, want %d", got, tc.want)
			}
		})
	}
}
