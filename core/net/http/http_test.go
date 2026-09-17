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
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/metrics"
	"google.golang.org/protobuf/proto"

	cpb "github.com/google/goonami-scanner/core/config/config_go_proto"
)

func TestReadBody(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		maxsize int
		want    []byte
		wantErr error
	}{
		{
			name:    "when_body_is_smaller_than_maxsize_it_is_returned",
			body:    "abc",
			maxsize: 10,
			want:    []byte("abc"),
		},
		{
			name:    "when_body_is_equal_to_maxsize_returns_error",
			body:    "abcdefghij",
			maxsize: 10,
			want:    nil,
			wantErr: ErrPageTooBig,
		},
		{
			name:    "when_body_is_larger_than_maxsize_returns_error",
			body:    "abcdefghijkl",
			maxsize: 10,
			want:    nil,
			wantErr: ErrPageTooBig,
		},
		{
			name:    "when_body_is_empty_returns_eof",
			body:    "",
			maxsize: 10,
			want:    nil,
			wantErr: io.EOF,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := &http.Response{
				Body: io.NopCloser(strings.NewReader(tc.body)),
			}

			actual, err := ReadBody(resp, tc.maxsize)
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("ReadBody() returned error %v, want %v", err, tc.wantErr)
			}

			if tc.wantErr != nil {
				return
			}

			if string(actual) != string(tc.want) {
				t.Errorf("ReadBody() returned %q, expected %q", actual, tc.want)
			}
		})
	}
}

type errorReader struct{}

func (errorReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("read error")
}

func TestReadBody_Error(t *testing.T) {
	resp := &http.Response{
		Body: io.NopCloser(errorReader{}),
	}

	_, err := ReadBody(resp, 10)
	if err == nil {
		t.Errorf("ReadBody() returned no error, want error")
	}
}

func TestRegisterAndNewClient(t *testing.T) {
	cfg := config.Default()
	_, err := NewClient(cfg, DefaultClientOptions())
	if err == nil {
		t.Errorf("NewClient(default) with no simpleclient registered did not return error")
	}

	Register("simpleclient", func(cfg *config.Config, options *ClientOptions) (Client, error) {
		return &fakeClient{}, nil
	})

	client, err := NewClient(cfg, DefaultClientOptions())
	if err != nil {
		t.Fatalf("NewClient(default) returned error: %v", err)
	}
	if client == nil {
		t.Errorf("NewClient(default) returned nil client")
	}

	customCfg := config.FromProto(cpb.Config_builder{
		Globalcfg: cpb.GlobalConfig_builder{
			HttpClient: proto.String("unknown-client"),
		}.Build(),
	}.Build())
	_, err = NewClient(customCfg, DefaultClientOptions())
	if err == nil {
		t.Errorf("NewClient with unknown client did not return error")
	}

	Register("custom", func(cfg *config.Config, options *ClientOptions) (Client, error) {
		return &fakeClient{}, nil
	})
	customCfg = config.FromProto(cpb.Config_builder{
		Globalcfg: cpb.GlobalConfig_builder{
			HttpClient: proto.String("custom"),
		}.Build(),
	}.Build())
	client, err = NewClient(customCfg, DefaultClientOptions())
	if err != nil {
		t.Fatalf("NewClient(custom) returned error: %v", err)
	}
	instrumented, ok := client.(*instrumentedClient)
	if !ok {
		t.Fatalf("NewClient(custom) returned %T, want *instrumentedClient", client)
	}
	if _, ok := instrumented.wrapped.(*fakeClient); !ok {
		t.Errorf("NewClient(custom) wrapped %T, want *fakeClient", instrumented.wrapped)
	}
}

// fakeClient is a Client whose response and error are configurable.
type fakeClient struct {
	statusCode int
	err        error
}

func (f *fakeClient) Do(req *http.Request) (*http.Response, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.statusCode == 0 {
		return nil, nil
	}
	return &http.Response{StatusCode: f.statusCode}, nil
}

func TestOptions_IsAuthorityAllowed(t *testing.T) {
	tests := []struct {
		name               string
		targetURL          string
		allowedAuthorities []string
		want               bool
	}{
		{
			name:               "when_allowed_authorities_empty_returns_true",
			targetURL:          "http://example.com/test",
			allowedAuthorities: nil,
			want:               true,
		},
		{
			name:               "when_exact_match_returns_true",
			targetURL:          "http://example.com:8080/test",
			allowedAuthorities: []string{"example.com:8080"},
			want:               true,
		},
		{
			name:               "when_host_mismatch_returns_false",
			targetURL:          "http://other.com:8080/test",
			allowedAuthorities: []string{"example.com:8080"},
			want:               false,
		},
		{
			name:               "when_port_mismatch_returns_false",
			targetURL:          "http://example.com:9000/test",
			allowedAuthorities: []string{"example.com:8080"},
			want:               false,
		},
		{
			name:               "when_default_http_port_matches_explicit_80",
			targetURL:          "http://example.com/test",
			allowedAuthorities: []string{"example.com:80"},
			want:               true,
		},
		{
			name:               "when_default_https_port_matches_explicit_443",
			targetURL:          "https://example.com/test",
			allowedAuthorities: []string{"example.com:443"},
			want:               true,
		},
		{
			name:               "when_allowed_has_no_port_matches_any_port_on_host",
			targetURL:          "http://example.com:8080/test",
			allowedAuthorities: []string{"example.com"},
			want:               true,
		},
		{
			name:               "when_ipv4_matches",
			targetURL:          "http://127.0.0.1:8080/test",
			allowedAuthorities: []string{"127.0.0.1:8080"},
			want:               true,
		},
		{
			name:               "when_ipv6_matches",
			targetURL:          "http://[::1]:8080/test",
			allowedAuthorities: []string{"[::1]:8080"},
			want:               true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse(tt.targetURL)
			if err != nil {
				t.Fatalf("failed to create url: %v", err)
			}

			opts := &ClientOptions{
				AllowedAuthorities: tt.allowedAuthorities,
			}

			if got := opts.IsAuthorityAllowed(u); got != tt.want {
				t.Errorf("IsAuthorityAllowed(%q) = %v, want %v", u, got, tt.want)
			}
		})
	}
}

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

			client := &instrumentedClient{wrapped: tc.client}
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

	client := &instrumentedClient{wrapped: &fakeClient{statusCode: 204}}
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

// totalRequestErrors sums every http/requests/error series, whatever its error
// class. It is used to assert that no failure at all was recorded, which a
// single lookup cannot prove.
func totalRequestErrors(collector *metrics.Collector) int64 {
	var total int64
	for _, series := range collector.Series() {
		if series.Metric == metrics.HTTPRequestErrors {
			total += series.Value()
		}
	}
	return total
}
