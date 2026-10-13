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

package fakehttp

import (
	"errors"
	"net/http"
	"testing"
)

func TestClientDo(t *testing.T) {
	errFake := errors.New("fake error")

	tests := []struct {
		name       string
		client     *Client
		override   DoFn
		wantNil    bool
		wantStatus int
		wantErr    error
	}{
		{
			name:       "when_status_code_is_configured_returns_response",
			client:     New(http.StatusOK, nil),
			wantStatus: http.StatusOK,
		},
		{
			name:    "when_zero_status_and_nil_error_returns_nil_response",
			client:  New(0, nil),
			wantNil: true,
		},
		{
			name:    "when_error_is_configured_returns_error",
			client:  New(http.StatusOK, errFake),
			wantNil: true,
			wantErr: errFake,
		},
		{
			name: "when_created_with_func_calls_func",
			client: NewWithFunc(func(req *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusCreated, Body: http.NoBody}, nil
			}),
			wantStatus: http.StatusCreated,
		},
		{
			name:   "when_override_do_is_set_calls_override",
			client: New(http.StatusOK, nil),
			override: func(req *http.Request) (*http.Response, error) {
				return nil, errFake
			},
			wantNil: true,
			wantErr: errFake,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.override != nil {
				tc.client.OverrideDo(tc.override)
			}

			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://example.com", nil)
			if err != nil {
				t.Fatalf("http.NewRequestWithContext() unexpected error: %v", err)
			}

			resp, err := tc.client.Do(req)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Do() error = %v, want %v", err, tc.wantErr)
			}
			if tc.wantNil {
				if resp != nil {
					t.Errorf("Do() response = %v, want nil", resp)
				}
			} else {
				if resp == nil {
					t.Fatalf("Do() response = nil, want StatusCode %d", tc.wantStatus)
				}
				if resp.StatusCode != tc.wantStatus {
					t.Errorf("Do() StatusCode = %d, want %d", resp.StatusCode, tc.wantStatus)
				}
			}
			if got := tc.client.Calls(); got != 1 {
				t.Errorf("Calls() = %d, want 1", got)
			}
		})
	}
}
