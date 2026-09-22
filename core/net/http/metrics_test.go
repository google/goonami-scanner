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

package http

import (
	"errors"
	"net/http"
	"testing"

	"github.com/google/goonami-scanner/core/metrics"
)

func TestInstrumentedClientRecordsMetrics(t *testing.T) {
	transportErr := errors.New("connection refused")

	testCases := []struct {
		name           string
		method         string
		client         *fakeClient
		wantErrorClass string
		wantErr        error
	}{
		{
			name:   "when_the_response_is_successful_only_the_request_is_counted",
			method: "GET",
			client: &fakeClient{statusCode: 200},
		},
		{
			name:   "when_the_target_returns_a_server_error_it_is_not_an_error",
			method: "POST",
			client: &fakeClient{statusCode: 503},
		},
		{
			name:   "when_the_response_is_nil_without_error_it_is_not_an_error",
			method: "GET",
			client: &fakeClient{},
		},
		{
			name:           "when_the_transport_fails_the_error_class_is_recorded",
			method:         "GET",
			client:         &fakeClient{err: transportErr},
			wantErrorClass: "other",
			wantErr:        transportErr,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			collector := metrics.NewCollector()
			metrics.SetRecorder(collector)
			t.Cleanup(func() { metrics.SetRecorder(nil) })

			req, err := http.NewRequestWithContext(t.Context(), tc.method, "http://example.com/", nil)
			if err != nil {
				t.Fatalf("http.NewRequestWithContext() error = %v", err)
			}

			client := &metricsClient{wrapped: tc.client}
			if _, err := client.Do(req); !errors.Is(err, tc.wantErr) {
				t.Fatalf("Do() error = %v, want %v", err, tc.wantErr)
			}

			if got := collector.Value(t.Context(), metrics.HTTPRequests); got != 1 {
				t.Errorf("http/requests = %d, want 1", got)
			}

			// A status chosen by the target is not a failure: only a request
			// that never reached a response counts as one.
			var wantErrors int64
			if tc.wantErrorClass != "" {
				wantErrors = 1
				label := metrics.Label{Key: metrics.LabelErrorClass, Value: tc.wantErrorClass}
				if got := collector.Value(t.Context(), metrics.HTTPRequestErrors, label); got != 1 {
					t.Errorf("http/requests/error[%v] = %d, want 1", label, got)
				}
			}
			if got := totalRequestErrors(collector); got != wantErrors {
				t.Errorf("http/requests/error total = %d, want %d", got, wantErrors)
			}
		})
	}
}

func TestInstrumentedClientWhenMultipleRequestsAreAggregated(t *testing.T) {
	collector := metrics.NewCollector()
	metrics.SetRecorder(collector)
	t.Cleanup(func() { metrics.SetRecorder(nil) })

	client := &metricsClient{wrapped: &fakeClient{statusCode: 204}}
	for range 3 {
		req, err := http.NewRequestWithContext(t.Context(), "GET", "http://example.com/", nil)
		if err != nil {
			t.Fatalf("http.NewRequestWithContext() error = %v", err)
		}
		if _, err := client.Do(req); err != nil {
			t.Fatalf("Do() error = %v", err)
		}
	}

	if got := collector.Value(t.Context(), metrics.HTTPRequests); got != 3 {
		t.Errorf("http/requests = %d, want 3", got)
	}
}
