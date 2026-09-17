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
	"sync"

	"github.com/google/goonami-scanner/core/log"
)

// DefaultMaxSeriesPerMetric bounds how many distinct label combinations a single
// metric may create. The catalog constructors already bound label values, so
// reaching this limit means something is wrong; the cap makes that failure
// degrade a dashboard instead of overwhelming a metrics backend.
const DefaultMaxSeriesPerMetric = 200

// CollectorOption configures a Collector.
type CollectorOption func(*Collector)

// WithMaxSeriesPerMetric overrides the per-metric series cap. A value of zero or
// less disables the cap.
func WithMaxSeriesPerMetric(max int) CollectorOption {
	return func(c *Collector) { c.maxSeriesPerMetric = max }
}

// Collector aggregates observations in memory for the lifetime of a single scan.
//
// Goonami scans one target per process, so aggregating in the scanner and
// writing a summary at exit keeps the output small and lets the downstream
// consumer replay series without reprocessing raw samples.
//
// A Collector is safe for concurrent use and doubles as the test double for
// code that records metrics: see Value and Stats.
type Collector struct {
	mu                 sync.Mutex
	maxSeriesPerMetric int
	series             map[string]*Series
	seriesPerMetric    map[string]int
	dropped            map[string]int64
	capReported        map[string]bool
}

// NewCollector returns an empty Collector.
func NewCollector(options ...CollectorOption) *Collector {
	c := &Collector{
		maxSeriesPerMetric: DefaultMaxSeriesPerMetric,
		series:             make(map[string]*Series),
		seriesPerMetric:    make(map[string]int),
		dropped:            make(map[string]int64),
		capReported:        make(map[string]bool),
	}

	for _, option := range options {
		option(c)
	}
	return c
}

// Add implements Recorder.
func (c *Collector) Add(ctx context.Context, m *Counter, delta int64, labels []Label) {
	c.mu.Lock()
	defer c.mu.Unlock()

	series := c.lookupOrCreate(ctx, m, labels)
	if series == nil {
		return
	}
	series.value += delta
}

// Observe implements Recorder.
func (c *Collector) Observe(ctx context.Context, m *Distribution, value float64, labels []Label) {
	c.mu.Lock()
	defer c.mu.Unlock()

	series := c.lookupOrCreate(ctx, m, labels)
	if series == nil {
		return
	}
	series.stats.observe(value)
}

// lookupOrCreate returns the series for the given metric and labels, creating it
// if needed. It returns nil when the metric has reached its series cap, in which
// case the observation is counted as dropped.
//
// The caller must hold c.mu.
func (c *Collector) lookupOrCreate(ctx context.Context, m Metric, labels []Label) *Series {
	key := seriesKey(m, labels)
	if series, ok := c.series[key]; ok {
		return series
	}

	name := m.Name()
	if c.maxSeriesPerMetric > 0 && c.seriesPerMetric[name] >= c.maxSeriesPerMetric {
		c.dropped[name]++
		if !c.capReported[name] {
			c.capReported[name] = true
			log.ErrorContextf(ctx,
				"metric %q reached its cap of %d series: further label combinations are dropped. This means a label is unbounded and must be fixed",
				name, c.maxSeriesPerMetric)
		}
		return nil
	}

	series := &Series{Metric: m, Labels: slices.Clone(labels)}
	c.series[key] = series
	c.seriesPerMetric[name]++
	return series
}

// Series returns every collected series, ordered by metric name then labels, so
// that output is deterministic.
func (c *Collector) Series() []*Series {
	c.mu.Lock()
	defer c.mu.Unlock()

	all := make([]*Series, 0, len(c.series))
	for _, series := range c.series {
		all = append(all, series)
	}
	slices.SortFunc(all, compareSeries)
	return all
}

// Value returns the total of a counter series, or zero if it was never recorded.
//
// It takes a *Counter rather than any metric, so a test that asks a
// distribution for its total does not compile instead of silently reading zero.
func (c *Collector) Value(ctx context.Context, m *Counter, labels ...Label) int64 {
	c.mu.Lock()
	defer c.mu.Unlock()

	series, ok := c.series[seriesKey(m, m.lookupLabels(ctx, labels))]
	if !ok {
		return 0
	}
	return series.value
}

// Stats returns the summary of a distribution series and whether it exists.
//
// It takes a *Distribution for the same reason Value takes a *Counter.
func (c *Collector) Stats(ctx context.Context, m *Distribution, labels ...Label) (Stats, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	series, ok := c.series[seriesKey(m, m.lookupLabels(ctx, labels))]
	if !ok {
		return Stats{}, false
	}
	return series.Stats(), true
}

// DroppedObservations returns how many observations of a metric were dropped
// because it reached its series cap.
func (c *Collector) DroppedObservations(m Metric) int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.dropped[m.Name()]
}
