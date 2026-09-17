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

// Package metrics provides Goonami's metrics collection interface.
//
// Metrics are declared once, in the catalog, and recorded through the declared
// handles:
//
//	metrics.ModuleErrors.Add(ctx, 1, metrics.Module("webidentity"), metrics.ErrorClass(err))
//	metrics.ModuleDuration.Observe(ctx, elapsed.Seconds(), metrics.Module("webidentity"))
//
// By default the recorder is a no-op, so embedding Goonami as a library costs nothing until a
// recorder is installed with SetRecorder (or through entrypoint.Options).
//
// Values derived from the scan target must never be used as labels. Hostnames,
// URLs, response headers, discovered software versions and raw error strings are
// all attacker-controlled: a hostile target could use them to mint unbounded
// series. Target-scoped detail belongs in the scan results, not here.
//
// This file holds what belongs to the package as a whole: the units, and the
// registry every declaration lands in.
package metrics

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"
)

// Unit of the values recorded by a metric.
type Unit string

const (
	// UnitCount is the unit of dimensionless counts.
	UnitCount Unit = "1"

	// UnitSeconds is the unit of durations.
	UnitSeconds Unit = "s"

	// UnitBytes is the unit of sizes.
	UnitBytes Unit = "By"
)

// metricNameRe is the accepted shape of a metric name: slash separated lowercase
// segments, e.g. "module/duration".
var metricNameRe = regexp.MustCompile(`^[a-z][a-z0-9_]*(/[a-z][a-z0-9_]*)*$`)

var (
	registryMu sync.Mutex
	registry   = make(map[string]Metric)
)

// register adds a metric to the registry, rejecting anything malformed.
//
// Every failure here panics rather than returning an error. Declarations run at
// package initialization time, so a panic is a test failure on a mistake that
// would otherwise only show up as a missing or silently split series in
// production.
func register(m Metric) {
	b := m.base()

	if !metricNameRe.MatchString(b.name) {
		panic(fmt.Sprintf("metrics: invalid metric name %q", b.name))
	}

	if b.description == "" {
		panic(fmt.Sprintf("metrics: metric %q has no description", b.name))
	}

	seen := make(map[LabelKey]bool, len(b.labelKeys))
	for _, key := range b.labelKeys {
		if key == "" {
			panic(fmt.Sprintf("metrics: metric %q declares an empty label key", b.name))
		}
		if seen[key] {
			panic(fmt.Sprintf("metrics: metric %q declares label key %q twice", b.name, key))
		}
		seen[key] = true
	}

	registryMu.Lock()
	defer registryMu.Unlock()
	if _, exists := registry[b.name]; exists {
		panic(fmt.Sprintf("metrics: metric %q declared twice", b.name))
	}
	registry[b.name] = m
}

// Declared returns every declared metric, ordered by name. It exists so that
// tests and documentation tooling can enumerate the catalog.
func Declared() []Metric {
	registryMu.Lock()
	defer registryMu.Unlock()

	all := make([]Metric, 0, len(registry))
	for _, m := range registry {
		all = append(all, m)
	}
	slices.SortFunc(all, func(a, b Metric) int { return strings.Compare(a.Name(), b.Name()) })
	return all
}
