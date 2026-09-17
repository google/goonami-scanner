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
	"strconv"
	"strings"
)

// Stats summarizes the samples of a distribution.
type Stats struct {
	Count int64
	Sum   float64
	Min   float64
	Max   float64
}

// observe folds a sample into the summary.
func (s *Stats) observe(value float64) {
	if s.Count == 0 {
		s.Min = value
		s.Max = value
	} else {
		s.Min = math.Min(s.Min, value)
		s.Max = math.Max(s.Max, value)
	}
	s.Count++
	s.Sum += value
}

// Series is a single time series: one metric with one combination of labels.
type Series struct {
	Metric Metric
	Labels []Label

	value int64
	stats Stats
}

// Value returns the total of a counter series. It is zero for distributions.
func (s *Series) Value() int64 { return s.value }

// Stats returns the summary of a distribution series. It is the zero value for
// counters.
func (s *Series) Stats() Stats { return s.stats }

// compareSeries orders series by metric name, then by label values in declared
// key order. The series map key cannot be used for ordering: it is length
// prefixed for correctness, which does not sort meaningfully.
func compareSeries(a, b *Series) int {
	if diff := strings.Compare(a.Metric.Name(), b.Metric.Name()); diff != 0 {
		return diff
	}

	for i := 0; i < len(a.Labels) && i < len(b.Labels); i++ {
		if diff := strings.Compare(string(a.Labels[i].Key), string(b.Labels[i].Key)); diff != 0 {
			return diff
		}
		if diff := strings.Compare(a.Labels[i].Value, b.Labels[i].Value); diff != 0 {
			return diff
		}
	}
	return len(a.Labels) - len(b.Labels)
}

// seriesKey is the identity of a single time series: a metric name and its
// resolved labels.
func seriesKey(m Metric, labels []Label) string {
	var b strings.Builder
	writeLengthPrefixed(&b, m.Name())
	for _, label := range labels {
		writeLengthPrefixed(&b, string(label.Key))
		writeLengthPrefixed(&b, label.Value)
	}
	return b.String()
}

func writeLengthPrefixed(b *strings.Builder, value string) {
	b.WriteString(strconv.Itoa(len(value)))
	b.WriteByte(':')
	b.WriteString(value)
}
