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
	"strings"
	"testing"
)

// labelTestKind is a label key used only by the tests in this package, for
// metrics that are not part of the catalog.
const labelTestKind LabelKey = "kind"

// testMetricName returns a metric name unique to the calling test, so that the
// package level registry does not leak state between tests.
func testMetricName(t *testing.T) string {
	t.Helper()

	name := "test/" + strings.ToLower(strings.ReplaceAll(t.Name(), "/", "_"))
	return strings.ReplaceAll(name, "-", "_")
}

// testCounter declares a counter named after the calling test.
func testCounter(t *testing.T, labelKeys ...LabelKey) *Counter {
	t.Helper()
	return NewCounter(testMetricName(t), "Test counter.", labelKeys...)
}

// testDistribution declares a distribution named after the calling test.
func testDistribution(t *testing.T, labelKeys ...LabelKey) *Distribution {
	t.Helper()
	return NewDistribution(testMetricName(t), "Test distribution.", UnitSeconds, labelKeys...)
}

func TestNewCounterPanics(t *testing.T) {
	testCases := []struct {
		name      string
		declare   func()
		wantPanic bool
	}{
		{
			name:      "when_name_is_valid_it_does_not_panic",
			declare:   func() { NewCounter("panics/valid_name", "A description.") },
			wantPanic: false,
		},
		{
			name:      "when_name_is_uppercase_it_panics",
			declare:   func() { NewCounter("panics/Invalid", "A description.") },
			wantPanic: true,
		},
		{
			name:      "when_name_is_empty_it_panics",
			declare:   func() { NewCounter("", "A description.") },
			wantPanic: true,
		},
		{
			name:      "when_name_has_a_trailing_slash_it_panics",
			declare:   func() { NewCounter("panics/trailing/", "A description.") },
			wantPanic: true,
		},
		{
			name:      "when_description_is_empty_it_panics",
			declare:   func() { NewCounter("panics/no_description", "") },
			wantPanic: true,
		},
		{
			name:      "when_a_label_key_is_empty_it_panics",
			declare:   func() { NewCounter("panics/empty_label", "A description.", LabelKey("")) },
			wantPanic: true,
		},
		{
			name:      "when_a_label_key_is_declared_twice_it_panics",
			declare:   func() { NewCounter("panics/duplicate_label", "A description.", LabelModule, LabelModule) },
			wantPanic: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				recovered := recover()
				if tc.wantPanic && recovered == nil {
					t.Errorf("declaring the metric did not panic, want panic")
				}
				if !tc.wantPanic && recovered != nil {
					t.Errorf("declaring the metric panicked with %v, want no panic", recovered)
				}
			}()

			tc.declare()
		})
	}
}

func TestNewCounterWhenNameIsDeclaredTwicePanics(t *testing.T) {
	NewCounter("panics/declared_twice", "A description.")

	defer func() {
		if recovered := recover(); recovered == nil {
			t.Errorf("declaring the same metric twice did not panic, want panic")
		}
	}()

	NewCounter("panics/declared_twice", "A description.")
}

func TestNewDistributionWhenNameIsAlreadyACounterPanics(t *testing.T) {
	// Counters and distributions are different types but share one registry, so
	// a name taken by one must not be reusable by the other: the two would
	// otherwise export as a single, incoherent series.
	NewCounter("panics/declared_as_both", "A description.")

	defer func() {
		if recovered := recover(); recovered == nil {
			t.Errorf("declaring a distribution with a counter's name did not panic, want panic")
		}
	}()

	NewDistribution("panics/declared_as_both", "A description.", UnitSeconds)
}

func TestDeclaredIncludesCatalogMetricsSorted(t *testing.T) {
	declared := Declared()

	if len(declared) == 0 {
		t.Fatalf("Declared() returned no metrics, want the catalog")
	}

	for i := 1; i < len(declared); i++ {
		if declared[i-1].Name() >= declared[i].Name() {
			t.Errorf("Declared() is not sorted: %q came before %q", declared[i-1].Name(), declared[i].Name())
		}
	}

	found := false
	for _, m := range declared {
		if m == ModuleDuration {
			found = true
		}
	}
	if !found {
		t.Errorf("Declared() does not contain ModuleDuration, want it to contain every catalog metric")
	}
}
