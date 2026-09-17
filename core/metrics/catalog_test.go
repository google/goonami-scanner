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
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
)

func TestClassifyError(t *testing.T) {
	testCases := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "when_there_is_no_error_it_is_none",
			err:  nil,
			want: errorClassNone,
		},
		{
			name: "when_the_deadline_was_exceeded_it_is_deadline_exceeded",
			err:  context.DeadlineExceeded,
			want: errorClassDeadlineExceeded,
		},
		{
			name: "when_the_deadline_error_is_wrapped_it_is_still_deadline_exceeded",
			err:  fmt.Errorf("running detector: %w", context.DeadlineExceeded),
			want: errorClassDeadlineExceeded,
		},
		{
			name: "when_the_context_was_canceled_it_is_canceled",
			err:  context.Canceled,
			want: errorClassCanceled,
		},
		{
			name: "when_the_stream_ended_early_it_is_eof",
			err:  io.ErrUnexpectedEOF,
			want: errorClassEOF,
		},
		{
			name: "when_the_network_timed_out_it_is_timeout",
			err:  &net.DNSError{IsTimeout: true},
			want: errorClassTimeout,
		},
		{
			name: "when_the_network_failed_it_is_network",
			err:  &net.DNSError{Err: "no such host"},
			want: errorClassNetwork,
		},
		{
			name: "when_the_error_is_unrecognized_it_is_other",
			err:  errors.New("something specific to the target that must not become a label"),
			want: errorClassOther,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyError(tc.err); got != tc.want {
				t.Errorf("classifyError(%v) = %q, want %q", tc.err, got, tc.want)
			}
		})
	}
}

func TestErrorClassLabel(t *testing.T) {
	got := ErrorClass(context.Canceled)
	want := Label{Key: LabelErrorClass, Value: errorClassCanceled}

	if got != want {
		t.Errorf("ErrorClass() = %v, want %v", got, want)
	}
}

func TestSimpleLabelConstructors(t *testing.T) {
	testCases := []struct {
		name  string
		label Label
		want  Label
	}{
		{
			name:  "module",
			label: Module("webidentity"),
			want:  Label{Key: LabelModule, Value: "webidentity"},
		},
		{
			name:  "limit_name",
			label: LimitName(LimitMaxAttemptsPerService),
			want:  Label{Key: LabelLimitName, Value: "max_attempts_per_service"},
		},
		{
			name:  "model",
			label: LLMModel("gemini-3.6-flash"),
			want:  Label{Key: LabelModel, Value: "gemini-3.6-flash"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.label != tc.want {
				t.Errorf("label = %v, want %v", tc.label, tc.want)
			}
		})
	}
}

// catalogMetrics returns the declared metrics that belong to the Goonami
// catalog, skipping the throwaway metrics the tests in this package register.
func catalogMetrics() []Metric {
	testPrefixes := []string{"test/", "panics/", "accessors/", "collector/", "export/"}

	var catalog []Metric
	for _, m := range Declared() {
		isTestMetric := false
		for _, prefix := range testPrefixes {
			if strings.HasPrefix(m.Name(), prefix) {
				isTestMetric = true
				break
			}
		}
		if !isTestMetric {
			catalog = append(catalog, m)
		}
	}
	return catalog
}

// aggregateWords are the names a measurement covering other measurements tends
// to be given. None of them may appear as a label value or as a name segment.
var aggregateWords = map[string]bool{"total": true, "all": true, "any": true, "sum": true}

func TestCatalogMetricsOnlyUseDeclaredLabelKeys(t *testing.T) {
	// Guards the cardinality contract: every catalog metric must declare the keys
	// it is recorded with, and no metric may declare a key that is not a known
	// label. A new key must be added to this list deliberately.
	known := map[LabelKey]bool{
		LabelModule:     true,
		LabelErrorClass: true,
		LabelLimitName:  true,
		LabelModel:      true,
	}

	for _, m := range catalogMetrics() {
		for _, key := range m.LabelKeys() {
			if !known[key] {
				t.Errorf("metric %q declares unknown label key %q", m.Name(), key)
			}
		}
	}
}

func TestCatalogHasNoAggregateLabelValues(t *testing.T) {
	// Guards the labels-versus-names rule. A label value that names an aggregate
	// sits in the same series family as the parts it is made of, so the obvious
	// query (sum across the label) double counts. Such a measurement belongs in
	// its own metric.
	//
	// The catalog declares keys, not values, so this checks the constructors
	// that produce closed value sets.
	closedSetLabels := []Label{
		LimitName(LimitMaxAttemptsPerService), LimitName(LimitMaxRequestsPerService),
		LimitName(LimitMaxHTTPRedirects), LimitName(LimitMaxAttempts),
	}

	for _, label := range closedSetLabels {
		if aggregateWords[label.Value] {
			t.Errorf("label %s=%q names an aggregate: it overlaps the other values of the key, so it must be its own metric", label.Key, label.Value)
		}
	}
}

func TestCatalogHasNoAggregateNameSegments(t *testing.T) {
	// Guards the same rule on the other side. A dimension folded into the name
	// must put the parts under the whole, never beside it: "scan/duration/total"
	// would be summed together with "scan/duration/portscan" by anything that
	// globs the family, which is the double counting trap moved from the label
	// to the name.
	for _, m := range catalogMetrics() {
		segments := strings.Split(m.Name(), "/")
		leaf := segments[len(segments)-1]
		if aggregateWords[leaf] {
			t.Errorf("metric %q ends in %q: an aggregate must be the parent of its parts, not a sibling of them", m.Name(), leaf)
		}
	}
}

func TestCatalogChildMetricsHaveADeclaredParent(t *testing.T) {
	// A name like "a/b/c" claims to be a part of "a/b", so "a/b" has to be a
	// metric someone can actually read. The first segment of a two segment name
	// is only a namespace ("module", "budget"), but a deeper prefix is a promise.
	//
	// This is what turns deleting an aggregate into a test failure instead of an
	// orphan: dropping "module/runs" while keeping "module/runs/error" would
	// leave a child pointing at a whole that no longer exists.
	declared := make(map[string]bool)
	for _, m := range catalogMetrics() {
		declared[m.Name()] = true
	}

	for _, m := range catalogMetrics() {
		segments := strings.Split(m.Name(), "/")
		if len(segments) < 3 {
			continue
		}

		parent := strings.Join(segments[:len(segments)-1], "/")
		if !declared[parent] {
			t.Errorf("metric %q has no declared parent %q: declare the parent or flatten the name", m.Name(), parent)
		}
	}
}

func TestAggregateMetricsAreTheParentOfTheirParts(t *testing.T) {
	testCases := []struct {
		name   string
		parent Metric
		parts  []Metric
	}{
		{
			name:   "scan_phases_are_children_of_the_whole_scan_duration",
			parent: ScanDuration,
			parts:  []Metric{PortScanDuration, FingerprintDuration, DetectDuration},
		},
		{
			name:   "the_token_breakdown_are_children_of_the_token_total",
			parent: LLMTokens,
			parts: []Metric{
				LLMInputTokens, LLMOutputTokens, LLMThoughtTokens, LLMToolInputTokens,
			},
		},
		{
			name:   "cached_tokens_are_a_child_of_the_input_tokens",
			parent: LLMInputTokens,
			parts:  []Metric{LLMCachedTokens},
		},
		{
			name:   "failed_requests_are_a_child_of_the_request_count",
			parent: HTTPRequests,
			parts:  []Metric{HTTPRequestErrors},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			for _, part := range tc.parts {
				if !strings.HasPrefix(part.Name(), tc.parent.Name()+"/") {
					t.Errorf("metric %q is not a child of %q", part.Name(), tc.parent.Name())
				}
			}
		})
	}
}
