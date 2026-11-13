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

package cache

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

type mockDoer struct {
	doFunc func(req *http.Request) (*http.Response, error)
}

func (m *mockDoer) Do(req *http.Request) (*http.Response, error) {
	return m.doFunc(req)
}

type errReader struct{}

var (
	errNetwork = errors.New("network down")
	errRead    = errors.New("read error")
)

func (errReader) Read(p []byte) (n int, err error) {
	return 0, errRead
}

func (errReader) Close() error {
	return nil
}

func TestPutAndGet(t *testing.T) {
	c := New(nil)

	testResp := &http.Response{
		StatusCode: 200,
		Status:     "200 OK",
		Header:     http.Header{"Content-Type": []string{"text/html"}},
	}
	testBody := []byte("hello world")

	c.Put("GET", "http://example.com/test", testResp, testBody)

	tests := []struct {
		name       string
		method     string
		url        string
		wantFound  bool
		wantStatus int
		wantBody   []byte
	}{
		{
			name:      "when_key_not_in_cache_returns_false",
			method:    "GET",
			url:       "http://example.com/notfound",
			wantFound: false,
		},
		{
			name:       "when_key_in_cache_returns_entry",
			method:     "GET",
			url:        "http://example.com/test",
			wantFound:  true,
			wantStatus: 200,
			wantBody:   testBody,
		},
		{
			name:       "when_url_has_different_case_normalizes_and_returns_entry",
			method:     "get",
			url:        "HTTP://EXAMPLE.COM/test",
			wantFound:  true,
			wantStatus: 200,
			wantBody:   testBody,
		},
		{
			name:       "when_method_empty_defaults_to_get",
			method:     "",
			url:        "http://example.com/test",
			wantFound:  true,
			wantStatus: 200,
			wantBody:   testBody,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, found := c.Get(tc.method, tc.url)
			if found != tc.wantFound {
				t.Fatalf("Cache.Get(%q, %q) found = %v, want %v", tc.method, tc.url, found, tc.wantFound)
			}
			if tc.wantFound {
				if got.StatusCode != tc.wantStatus {
					t.Errorf("Cache.Get(%q, %q) StatusCode = %d, want %d", tc.method, tc.url, got.StatusCode, tc.wantStatus)
				}
				if diff := cmp.Diff(tc.wantBody, got.Body); diff != "" {
					t.Errorf("Cache.Get(%q, %q) Body mismatch (-want +got):\n%s", tc.method, tc.url, diff)
				}
			}
		})
	}
}

func TestPutWithNilResponse(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		url        string
		body       []byte
		wantStatus int
		wantText   string
	}{
		{
			name:       "when_response_is_nil_defaults_to_200_ok",
			method:     "POST",
			url:        "http://example.com/api",
			body:       []byte("sample"),
			wantStatus: 200,
			wantText:   "200 OK",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := New(nil)
			entry := c.Put(tc.method, tc.url, nil, tc.body)

			if entry.StatusCode != tc.wantStatus {
				t.Errorf("Put(%q, %q, nil, body) StatusCode = %d, want %d", tc.method, tc.url, entry.StatusCode, tc.wantStatus)
			}
			if entry.Status != tc.wantText {
				t.Errorf("Put(%q, %q, nil, body) Status = %q, want %q", tc.method, tc.url, entry.Status, tc.wantText)
			}
			if diff := cmp.Diff(tc.body, entry.Body); diff != "" {
				t.Errorf("Put(%q, %q, nil, body) Body mismatch (-want +got):\n%s", tc.method, tc.url, diff)
			}
		})
	}
}

func TestAll(t *testing.T) {
	type putOp struct {
		method string
		url    string
		body   []byte
	}
	tests := []struct {
		name       string
		ops        []putOp
		wantBodies [][]byte
	}{
		{
			name:       "when_empty_returns_empty_slice",
			wantBodies: nil,
		},
		{
			name: "when_entries_added_returns_entries_in_insertion_order",
			ops: []putOp{
				{method: "GET", url: "http://example.com/1", body: []byte("1")},
				{method: "GET", url: "http://example.com/2", body: []byte("2")},
				{method: "GET", url: "http://example.com/3", body: []byte("3")},
			},
			wantBodies: [][]byte{[]byte("1"), []byte("2"), []byte("3")},
		},
		{
			name: "when_existing_key_overwritten_updates_entry_in_place",
			ops: []putOp{
				{method: "GET", url: "http://example.com/1", body: []byte("old")},
				{method: "GET", url: "http://example.com/2", body: []byte("2")},
				{method: "GET", url: "http://example.com/1", body: []byte("new")},
			},
			wantBodies: [][]byte{[]byte("new"), []byte("2")},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := New(nil)
			for _, op := range tc.ops {
				c.Put(op.method, op.url, nil, op.body)
			}
			all := c.All()
			var gotBodies [][]byte
			for _, entry := range all {
				gotBodies = append(gotBodies, entry.Body)
			}
			if diff := cmp.Diff(tc.wantBodies, gotBodies); diff != "" {
				t.Errorf("Cache.All() bodies mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestFetch(t *testing.T) {
	tests := []struct {
		name      string
		url       string
		req       *http.Request
		nilClient bool
		wantCalls int32
		wantBody  []byte
		wantErr   error
	}{
		{
			name:    "when_request_is_nil_returns_error",
			wantErr: ErrNilRequest,
		},
		{
			name:    "when_request_url_is_nil_returns_error",
			req:     &http.Request{Method: http.MethodGet},
			wantErr: ErrNilRequest,
		},
		{
			name:      "when_no_client_configured_returns_error",
			url:       "http://example.com/unconfigured",
			nilClient: true,
			wantErr:   ErrNoClient,
		},
		{
			name:     "when_already_cached_returns_cached_without_calling_client",
			url:      "http://example.com/cached",
			wantBody: []byte("cached content"),
		},
		{
			name:      "when_not_cached_calls_client_and_stores_in_cache",
			url:       "http://example.com/uncached",
			wantCalls: 1,
			wantBody:  []byte("remote content"),
		},
		{
			name:      "when_client_returns_error_returns_error",
			url:       "http://example.com/error",
			wantCalls: 1,
			wantErr:   errNetwork,
		},
		{
			name:      "when_response_body_read_error_returns_error",
			url:       "http://example.com/bad_body",
			wantCalls: 1,
			wantErr:   errRead,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var callCount int32
			var client HTTPDoer
			if !tc.nilClient {
				client = &mockDoer{
					doFunc: func(req *http.Request) (*http.Response, error) {
						atomic.AddInt32(&callCount, 1)
						if req.URL.Path == "/error" {
							return nil, errNetwork
						}
						if req.URL.Path == "/bad_body" {
							return &http.Response{
								StatusCode: 200,
								Status:     "200 OK",
								Body:       errReader{},
							}, nil
						}
						return &http.Response{
							StatusCode: 200,
							Status:     "200 OK",
							Header:     http.Header{"X-Fetched": []string{"true"}},
							Body:       io.NopCloser(bytes.NewReader([]byte("remote content"))),
						}, nil
					},
				}
			}

			c := New(client, WithMaxBodyBytes(1024*1024))
			c.Put("GET", "http://example.com/cached", nil, []byte("cached content"))

			req := tc.req
			if tc.url != "" {
				var err error
				req, err = http.NewRequestWithContext(t.Context(), http.MethodGet, tc.url, nil)
				if err != nil {
					t.Fatalf("http.NewRequestWithContext(%q) failed: %v", tc.url, err)
				}
			}

			got, err := c.Fetch(t.Context(), req)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Fetch() error = %v, want %v", err, tc.wantErr)
				}
				if currentCalls := atomic.LoadInt32(&callCount); currentCalls != tc.wantCalls {
					t.Errorf("Fetch() callCount = %d, want %d", currentCalls, tc.wantCalls)
				}
				return
			}
			if err != nil {
				t.Fatalf("Fetch() unexpected error: %v", err)
			}
			if diff := cmp.Diff(tc.wantBody, got.Body); diff != "" {
				t.Errorf("Fetch() Body mismatch (-want +got):\n%s", diff)
			}
			if currentCalls := atomic.LoadInt32(&callCount); currentCalls != tc.wantCalls {
				t.Errorf("Fetch() callCount = %d, want %d", currentCalls, tc.wantCalls)
			}
		})
	}
}

func TestFetchSingleflight(t *testing.T) {
	tests := []struct {
		name          string
		numGoroutines int
		wantCalls     int32
		wantBody      string
	}{
		{
			name:          "when_concurrent_requests_share_key_coalesces_into_single_call",
			numGoroutines: 10,
			wantCalls:     1,
			wantBody:      "singleflight response",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var callCount int32
			client := &mockDoer{
				doFunc: func(req *http.Request) (*http.Response, error) {
					atomic.AddInt32(&callCount, 1)
					time.Sleep(50 * time.Millisecond)
					return &http.Response{
						StatusCode: 200,
						Status:     "200 OK",
						Body:       io.NopCloser(bytes.NewReader([]byte(tc.wantBody))),
					}, nil
				},
			}

			c := New(client)
			ctx := t.Context()

			var wg sync.WaitGroup
			wg.Add(tc.numGoroutines)

			for range tc.numGoroutines {
				go func() {
					defer wg.Done()
					req, _ := http.NewRequestWithContext(ctx, "GET", "http://example.com/shared", nil)
					res, err := c.Fetch(ctx, req)
					if err != nil {
						t.Errorf("Fetch() returned unexpected error: %v", err)
						return
					}
					if got := string(res.Body); got != tc.wantBody {
						t.Errorf("Fetch() body = %q, want %q", got, tc.wantBody)
					}
				}()
			}

			wg.Wait()

			if got := atomic.LoadInt32(&callCount); got != tc.wantCalls {
				t.Errorf("Do() callCount = %d, want %d", got, tc.wantCalls)
			}
		})
	}
}
