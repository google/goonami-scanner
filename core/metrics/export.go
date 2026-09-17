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
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"google.golang.org/protobuf/encoding/prototext"

	smpb "github.com/google/goonami-scanner/core/metrics/scan_metrics_go_proto"
)

var (
	// ErrMarshalMetrics is returned when the metrics cannot be marshaled.
	ErrMarshalMetrics = errors.New("failed to marshal scan metrics")

	// ErrWriteMetrics is returned when the metrics cannot be written to a file.
	ErrWriteMetrics = errors.New("failed to write scan metrics to file")
)

// Export returns the collected series as a proto, ready to be serialized.
func (c *Collector) Export() *smpb.ScanMetrics {
	var series []*smpb.Series
	for _, s := range c.Series() {
		series = append(series, exportSeries(s))
	}

	return smpb.ScanMetrics_builder{
		Series:  series,
		Dropped: c.exportDropped(),
	}.Build()
}

func exportSeries(s *Series) *smpb.Series {
	var labels []*smpb.Label
	for _, label := range s.Labels {
		labels = append(labels, smpb.Label_builder{
			Key:   string(label.Key),
			Value: label.Value,
		}.Build())
	}

	exported := smpb.Series_builder{
		Name:   s.Metric.Name(),
		Labels: labels,
	}.Build()

	// The metric type selects the oneof. The Metric interface is sealed, so
	// these two cases are exhaustive.
	switch s.Metric.(type) {
	case *Counter:
		exported.SetCounter(s.Value())

	case *Distribution:
		stats := s.Stats()
		exported.SetDistribution(smpb.Distribution_builder{
			Count: stats.Count,
			Sum:   stats.Sum,
			Min:   stats.Min,
			Max:   stats.Max,
		}.Build())
	}
	return exported
}

// exportDropped returns the per-metric dropped observation counts, ordered by
// metric name.
func (c *Collector) exportDropped() []*smpb.DroppedSeries {
	c.mu.Lock()
	defer c.mu.Unlock()

	names := make([]string, 0, len(c.dropped))
	for name := range c.dropped {
		names = append(names, name)
	}
	slices.SortFunc(names, strings.Compare)

	var dropped []*smpb.DroppedSeries
	for _, name := range names {
		dropped = append(dropped, smpb.DroppedSeries_builder{
			Metric:       name,
			Observations: c.dropped[name],
		}.Build())
	}
	return dropped
}

// WriteFile serializes the collected metrics as a textproto at path.
func (c *Collector) WriteFile(path string) error {
	options := prototext.MarshalOptions{Multiline: true}
	textproto, err := options.Marshal(c.Export())
	if err != nil {
		return fmt.Errorf("%w: %v", ErrMarshalMetrics, err)
	}

	if err := os.WriteFile(path, textproto, 0644); err != nil {
		return fmt.Errorf("%w: %v", ErrWriteMetrics, err)
	}
	return nil
}
