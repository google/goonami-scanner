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

package engine

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/google/goonami-scanner/core/log"
)

type mockClient struct {
	responses map[string]*http.Response
	bodies    map[string][]byte
	doFunc    func(req *http.Request) (*http.Response, error)
	callCount int32
}

func (m *mockClient) Do(req *http.Request) (*http.Response, error) {
	atomic.AddInt32(&m.callCount, 1)
	if m.doFunc != nil {
		return m.doFunc(req)
	}
	key := req.Method + " " + req.URL.String()
	if resp, ok := m.responses[key]; ok {
		body := m.bodies[key]
		return &http.Response{
			StatusCode: resp.StatusCode,
			Status:     resp.Status,
			Header:     resp.Header.Clone(),
			Body:       io.NopCloser(strings.NewReader(string(body))),
		}, nil
	}
	return &http.Response{
		StatusCode: http.StatusNotFound,
		Status:     "404 Not Found",
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("not found")),
	}, nil
}

type testDebugLogger struct {
	log.DefaultLogger
	mu      sync.Mutex
	entries []string
}

func (l *testDebugLogger) DebugContextf(ctx context.Context, level log.DebugLevel, format string, args ...any) {
	if l.VerboseLevel >= level {
		l.mu.Lock()
		defer l.mu.Unlock()
		l.entries = append(l.entries, fmt.Sprintf(format, args...))
	}
}
