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
	"sync"
)

var (
	recorderMu sync.RWMutex
	recorder   Recorder = NoopRecorder{}
)

// Recorder consumes metric observations. Implementations must be safe for
// concurrent use: the runner fingerprints and detects services in parallel.
//
// Labels passed to a Recorder have already been validated against the metric's
// declared keys, deduplicated, and sorted by key.
type Recorder interface {
	// Add increments a counter by delta.
	Add(ctx context.Context, m *Counter, delta int64, labels []Label)

	// Observe records a single sample of a distribution.
	Observe(ctx context.Context, m *Distribution, value float64, labels []Label)
}

// NoopRecorder discards every observation. It is the default so that library
// users pay nothing for instrumentation they did not ask for.
type NoopRecorder struct{}

// Add implements Recorder and does nothing.
func (NoopRecorder) Add(ctx context.Context, m *Counter, delta int64, labels []Label) {}

// Observe implements Recorder and does nothing.
func (NoopRecorder) Observe(ctx context.Context, m *Distribution, value float64, labels []Label) {}

// SetRecorder installs the recorder that receives every subsequent observation.
// Passing nil restores the no-op recorder.
func SetRecorder(r Recorder) {
	recorderMu.Lock()
	defer recorderMu.Unlock()
	if r == nil {
		r = NoopRecorder{}
	}
	recorder = r
}

// CurrentRecorder returns the installed recorder.
func CurrentRecorder() Recorder {
	recorderMu.RLock()
	defer recorderMu.RUnlock()
	return recorder
}
