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

func TestMetricAccessors(t *testing.T) {
	m := NewDistribution("accessors/duration", "A description.", UnitSeconds, LabelModule)

	if got := m.Name(); got != "accessors/duration" {
		t.Errorf("Name() = %q, want %q", got, "accessors/duration")
	}
	if got := m.Description(); got != "A description." {
		t.Errorf("Description() = %q, want %q", got, "A description.")
	}
	if got := m.Unit(); got != UnitSeconds {
		t.Errorf("Unit() = %q, want %q", got, UnitSeconds)
	}

	keys := m.LabelKeys()
	if len(keys) != 1 || keys[0] != LabelModule {
		t.Errorf("LabelKeys() = %v, want [%v]", keys, LabelModule)
	}

	// The returned slice must be a copy: mutating it must not corrupt the metric.
	keys[0] = LabelErrorClass
	if m.LabelKeys()[0] != LabelModule {
		t.Errorf("LabelKeys() returned the underlying slice, want a copy")
	}
}

func TestResolveLabels(t *testing.T) {
	testCases := []struct {
		name   string
		keys   []LabelKey
		labels []Label
		want   []Label
	}{
		{
			name:   "when_labels_are_declared_it_keeps_them",
			keys:   []LabelKey{LabelModule, labelTestKind},
			labels: []Label{Module("webidentity"), Label{Key: labelTestKind, Value: "fingerprinter"}},
			want: []Label{
				{Key: labelTestKind, Value: "fingerprinter"},
				{Key: LabelModule, Value: "webidentity"},
			},
		},
		{
			name:   "when_labels_are_out_of_order_it_sorts_them_by_key",
			keys:   []LabelKey{LabelModule, labelTestKind},
			labels: []Label{Label{Key: labelTestKind, Value: "detector"}, Module("nmap")},
			want: []Label{
				{Key: labelTestKind, Value: "detector"},
				{Key: LabelModule, Value: "nmap"},
			},
		},
		{
			name:   "when_a_label_is_not_declared_it_drops_the_label",
			keys:   []LabelKey{LabelModule},
			labels: []Label{Module("nmap"), LimitName(LimitMaxAttempts)},
			want:   []Label{{Key: LabelModule, Value: "nmap"}},
		},
		{
			name:   "when_a_label_is_repeated_it_keeps_the_first_value",
			keys:   []LabelKey{LabelModule},
			labels: []Label{Module("first"), Module("second")},
			want:   []Label{{Key: LabelModule, Value: "first"}},
		},
		{
			name:   "when_a_label_value_is_empty_it_becomes_unknown",
			keys:   []LabelKey{LabelModule},
			labels: []Label{Module("")},
			want:   []Label{{Key: LabelModule, Value: "unknown"}},
		},
		{
			name:   "when_there_are_no_labels_it_returns_none",
			keys:   nil,
			labels: nil,
			want:   []Label{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			m := testCounter(t, tc.keys...)

			got := m.resolve(t.Context(), tc.labels)

			if len(got) != len(tc.want) {
				t.Fatalf("resolve() = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("resolve()[%d] = %v, want %v", i, got[i], tc.want[i])
				}
			}

			// The read path must produce the same labels as the write path: the
			// series key is built from them on both sides, so any disagreement
			// would make every lookup miss and report a zero that looks real.
			lookup := m.lookupLabels(t.Context(), tc.labels)
			if len(lookup) != len(got) {
				t.Fatalf("lookupLabels() = %v, want %v (same as resolve())", lookup, got)
			}
			for i := range lookup {
				if lookup[i] != got[i] {
					t.Errorf("lookupLabels()[%d] = %v, want %v (same as resolve())", i, lookup[i], got[i])
				}
			}
		})
	}
}

func TestEveryDeclaredMetricIsACounterOrADistribution(t *testing.T) {
	// The Metric interface is sealed, and exportSeries relies on that: its type
	// switch has no default, so a third implementation would export a series
	// with neither oneof set. This keeps the switch exhaustive.
	for _, m := range Declared() {
		switch m.(type) {
		case *Counter, *Distribution:
		default:
			t.Errorf("metric %q has type %T, want *Counter or *Distribution", m.Name(), m)
		}
	}
}
