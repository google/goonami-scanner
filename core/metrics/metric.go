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
	"slices"
	"strings"

	"github.com/google/goonami-scanner/core/log"
)

// Metric is the read-only view of a declared metric, common to counters and
// distributions. It lets the registry, the recorders and the collector handle
// any metric uniformly, while recording stays the privilege of the concrete
// types.
//
// The interface is sealed: only Counter and Distribution implement it, so the
// set of metric shapes stays closed and a type switch over it is exhaustive.
type Metric interface {
	// Name returns the name of the metric.
	Name() string

	// Description returns the human readable description of the metric.
	Description() string

	// Unit returns the unit of the values recorded by the metric.
	Unit() Unit

	// LabelKeys returns the label keys the metric accepts.
	LabelKeys() []LabelKey

	base() *metric
}

// metric is what every metric has in common.
type metric struct {
	name        string
	description string
	unit        Unit
	labelKeys   []LabelKey
}

// Name returns the name of the metric.
func (m *metric) Name() string { return m.name }

// Description returns the human readable description of the metric.
func (m *metric) Description() string { return m.description }

// Unit returns the unit of the values recorded by the metric.
func (m *metric) Unit() Unit { return m.unit }

// LabelKeys returns the label keys the metric accepts.
func (m *metric) LabelKeys() []LabelKey { return slices.Clone(m.labelKeys) }

// base implements Metric and seals it to this package.
func (m *metric) base() *metric { return m }

// normalize validates labels against the metric's declared keys, drops the ones
// that do not belong, and returns them deduplicated and sorted so that a series
// key does not depend on argument order.
func (m *metric) normalize(ctx context.Context, labels []Label) []Label {
	normalized := make([]Label, 0, len(labels))
	seen := make(map[LabelKey]bool, len(labels))

	for _, label := range labels {
		if !slices.Contains(m.labelKeys, label.Key) {
			log.DebugContextf(ctx, log.DebugLevelSession, "metric %q does not declare label %q: dropping the label", m.name, label.Key)
			continue
		}

		if seen[label.Key] {
			log.DebugContextf(ctx, log.DebugLevelSession, "metric %q was given label %q twice: keeping the first value", m.name, label.Key)
			continue
		}

		seen[label.Key] = true
		normalized = append(normalized, Label{Key: label.Key, Value: sanitizeValue(label.Value)})
	}

	slices.SortFunc(normalized, func(a, b Label) int { return strings.Compare(string(a.Key), string(b.Key)) })
	return normalized
}

// resolve normalizes labels for recording.
func (m *metric) resolve(ctx context.Context, labels []Label) []Label {
	return m.normalize(ctx, labels)
}

// lookupLabels normalizes labels for a lookup.
func (m *metric) lookupLabels(ctx context.Context, labels []Label) []Label {
	return m.normalize(ctx, labels)
}
