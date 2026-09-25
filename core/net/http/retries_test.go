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
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/metrics"
	"google.golang.org/protobuf/proto"

	cpb "github.com/google/goonami-scanner/core/config/config_go_proto"
)

type clientFunc func(*http.Request) (*http.Response, error)

func (f clientFunc) Do(req *http.Request) (*http.Response, error) { return f(req) }

func TestRetriableClient_Do(t *testing.T) {
	cfg := config.FromProto(cpb.Config_builder{
		Globalcfg: cpb.GlobalConfig_builder{
			HttpClient: proto.String("retry-test"),
		}.Build(),
	}.Build())

	errGetBody := errors.New("get body failed")
	tests := []struct {
		name         string
		method       string
		disableRetry bool
		responses    []int
		retryAfter   string
		getBodyErr   error
		wantAttempts int
		wantStatus   int
		wantErr      error
		wantDuration time.Duration
	}{
		{
			name:         "when_retry_disabled_returns_429_without_retry",
			disableRetry: true,
			responses:    []int{http.StatusTooManyRequests, http.StatusOK},
			wantAttempts: 1,
			wantStatus:   http.StatusTooManyRequests,
		},
		{
			name:         "when_get_request_429_then_200_retries",
			method:       http.MethodGet,
			responses:    []int{http.StatusTooManyRequests, http.StatusOK},
			wantAttempts: 2,
			wantStatus:   http.StatusOK,
			wantDuration: 2 * time.Second,
		},
		{
			name:         "when_429_then_200_retries_and_preserves_post_body",
			responses:    []int{http.StatusTooManyRequests, http.StatusTooManyRequests, http.StatusOK},
			retryAfter:   "1",
			wantAttempts: 3,
			wantStatus:   http.StatusOK,
			wantDuration: 5 * time.Second,
		},
		{
			name:         "when_429_with_http_date_retry_after_retries",
			responses:    []int{http.StatusTooManyRequests, http.StatusOK},
			retryAfter:   "http-date-past",
			wantAttempts: 2,
			wantStatus:   http.StatusOK,
		},
		{
			name:         "when_429_with_excessive_retry_after_aborts_immediately",
			responses:    []int{http.StatusTooManyRequests, http.StatusOK},
			retryAfter:   "60",
			wantAttempts: 1,
			wantErr:      ErrRateLimited,
		},
		{
			name:         "when_429_with_excessive_http_date_retry_after_aborts_immediately",
			responses:    []int{http.StatusTooManyRequests, http.StatusOK},
			retryAfter:   "http-date-future",
			wantAttempts: 1,
			wantErr:      ErrRateLimited,
		},
		{
			name:         "when_429_exceeds_max_attempts_returns_rate_limited_error",
			responses:    []int{http.StatusTooManyRequests, http.StatusTooManyRequests, http.StatusTooManyRequests},
			wantAttempts: 3,
			wantErr:      ErrRateLimited,
			wantDuration: 6 * time.Second,
		},
		{
			name:         "when_get_body_fails_returns_error",
			responses:    []int{http.StatusTooManyRequests, http.StatusOK},
			getBodyErr:   errGetBody,
			wantAttempts: 1,
			wantErr:      errGetBody,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				collector := metrics.NewCollector()
				metrics.SetRecorder(collector)
				t.Cleanup(func() { metrics.SetRecorder(nil) })

				const wantPayload = "user=admin&pass=secret"
				var attempts int
				Register("retry-test", func(*config.Config, *ClientOptions) (Client, error) {
					return clientFunc(func(req *http.Request) (*http.Response, error) {
						attempts++
						if tc.method != http.MethodGet {
							if body, err := io.ReadAll(req.Body); err != nil || string(body) != wantPayload {
								t.Errorf("attempt %d: body = %q (err %v), want %q", attempts, body, err, wantPayload)
							}
						}
						hdr := make(http.Header)
						if attempts == 1 && tc.retryAfter != "" {
							retryAfter := tc.retryAfter
							switch retryAfter {
							case "http-date-past":
								retryAfter = time.Now().Add(-time.Second).UTC().Format(http.TimeFormat)
							case "http-date-future":
								retryAfter = time.Now().Add(time.Hour).UTC().Format(http.TimeFormat)
							}
							hdr.Set("Retry-After", retryAfter)
						}
						return &http.Response{
							StatusCode: tc.responses[attempts-1],
							Header:     hdr,
							Body:       io.NopCloser(strings.NewReader("ok")),
						}, nil
					}), nil
				})

				client, err := NewClient(cfg, &ClientOptions{RetryOnRateLimit: !tc.disableRetry})
				if err != nil {
					t.Fatalf("NewClient() error = %v", err)
				}

				method := tc.method
				var reqBody io.Reader = strings.NewReader(wantPayload)
				if method == http.MethodGet {
					reqBody = nil
				} else if method == "" {
					method = http.MethodPost
				}
				req, err := http.NewRequestWithContext(t.Context(), method, "http://example.com/login", reqBody)
				if err != nil {
					t.Fatalf("http.NewRequestWithContext() error = %v", err)
				}
				if tc.getBodyErr != nil {
					req.GetBody = func() (io.ReadCloser, error) {
						return nil, tc.getBodyErr
					}
				}

				start := time.Now()
				resp, err := client.Do(req)
				if gotDuration := time.Since(start); gotDuration != tc.wantDuration {
					t.Errorf("Do() elapsed = %v, want %v", gotDuration, tc.wantDuration)
				}
				if tc.wantErr != nil {
					if !errors.Is(err, tc.wantErr) {
						t.Fatalf("Do() error = %v, want %v", err, tc.wantErr)
					}
				} else {
					if err != nil {
						t.Fatalf("Do() unexpected error = %v", err)
					}
					defer resp.Body.Close()
					if resp.StatusCode != tc.wantStatus {
						t.Errorf("Do() StatusCode = %d, want %d", resp.StatusCode, tc.wantStatus)
					}
				}

				if attempts != tc.wantAttempts {
					t.Errorf("attempts = %d, want %d", attempts, tc.wantAttempts)
				}
				if got := collector.Value(t.Context(), metrics.HTTPRequests); got != int64(tc.wantAttempts) {
					t.Errorf("http/requests = %d, want %d", got, tc.wantAttempts)
				}
			})
		})
	}
}

func TestRetryDelay(t *testing.T) {
	tests := []struct {
		name          string
		retryAfter    string
		backoff       time.Duration
		maxRetryAfter time.Duration
		wantDelay     time.Duration
		wantErr       error
	}{
		{
			name:          "when_no_header_returns_backoff",
			backoff:       2 * time.Second,
			maxRetryAfter: 30 * time.Second,
			wantDelay:     2 * time.Second,
		},
		{
			name:          "when_backoff_exceeds_max_caps_at_max_retry_after",
			backoff:       60 * time.Second,
			maxRetryAfter: 30 * time.Second,
			wantDelay:     30 * time.Second,
		},
		{
			name:          "when_invalid_header_falls_back_to_capped_backoff",
			retryAfter:    "invalid",
			backoff:       40 * time.Second,
			maxRetryAfter: 30 * time.Second,
			wantDelay:     30 * time.Second,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			hdr := make(http.Header)
			if tc.retryAfter != "" {
				hdr.Set("Retry-After", tc.retryAfter)
			}
			got, err := retryDelay(hdr, tc.backoff, tc.maxRetryAfter)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("retryDelay() error = %v, want %v", err, tc.wantErr)
			}
			if got != tc.wantDelay {
				t.Errorf("retryDelay() = %v, want %v", got, tc.wantDelay)
			}
		})
	}
}
