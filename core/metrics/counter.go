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

	"github.com/google/goonami-scanner/core/log"
)

// Counter is a monotonically increasing total. Counters are created by
// NewCounter at package initialization time and are safe for concurrent use.
type Counter struct {
	metric
}

// NewCounter declares a counter and registers it in the catalog. It panics if
// the name is malformed or already declared, which makes a duplicate or
// misspelled metric a build-time (test) failure rather than a silent runtime
// split of a time series.
func NewCounter(name, description string, labelKeys ...LabelKey) *Counter {
	c := &Counter{metric{
		name:        name,
		description: description,
		unit:        UnitCount,
		labelKeys:   labelKeys,
	}}
	register(c)
	return c
}

// Add increments the counter by delta.
//
// A negative delta is a programming error: it is logged and the observation is
// dropped rather than panicking, because a scanner must not abort a scan over a
// telemetry mistake.
func (c *Counter) Add(ctx context.Context, delta int64, labels ...Label) {
	ctx = log.ContextForModule(ctx, "core/metrics")
	if delta < 0 {
		log.ErrorContextf(ctx, "metric %q is a counter and cannot decrease (delta %d): dropping observation", c.name, delta)
		return
	}

	CurrentRecorder().Add(ctx, c, delta, c.resolve(ctx, labels))
}
