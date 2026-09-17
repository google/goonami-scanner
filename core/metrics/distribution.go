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

// Distribution is a set of samples, folded as they arrive into a count, sum,
// minimum and maximum. Distributions are created by NewDistribution at package
// initialization time and are safe for concurrent use.
type Distribution struct {
	metric
}

// NewDistribution declares a distribution and registers it in the catalog. It
// panics under the same conditions as NewCounter.
func NewDistribution(name, description string, unit Unit, labelKeys ...LabelKey) *Distribution {
	d := &Distribution{metric{
		name:        name,
		description: description,
		unit:        unit,
		labelKeys:   labelKeys,
	}}
	register(d)
	return d
}

// Observe records one sample of the distribution.
func (d *Distribution) Observe(ctx context.Context, value float64, labels ...Label) {
	ctx = log.ContextForModule(ctx, "core/metrics")
	CurrentRecorder().Observe(ctx, d, value, d.resolve(ctx, labels))
}
