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
	"strconv"
	"strings"
	"time"

	"github.com/google/goonami-scanner/core/config"
)

// ErrRateLimited is returned when RetryOnRateLimit is enabled and the server responds with
// HTTP 429 Too Many Requests across all retry attempts or with a Retry-After header that
// exceeds the configured maximum.
var ErrRateLimited = errors.New("rate limited by server (HTTP 429)")

// retriableClient wraps a Client and retries HTTP 429 Too Many Requests responses using
// Retry-After headers or exponential backoff up to the configured maximum attempts.
type retriableClient struct {
	wrapped Client
	cfg     *config.Config
}

// Do executes the HTTP request and retries on HTTP 429 Too Many Requests responses.
func (c *retriableClient) Do(req *http.Request) (*http.Response, error) {
	perf := c.cfg.GlobalConfig().GetPerformance()
	maxAttempts := int(perf.GetMaxHttpAttemptsWhenRatelimit())
	maxRetryAfter := time.Duration(perf.GetMaxHttpRetryAfterSeconds()) * time.Second
	backoff := time.Duration(perf.GetHttpRetryInitialBackoffSeconds()) * time.Second

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		resp, err := c.wrapped.Do(req)
		if err != nil || resp.StatusCode != http.StatusTooManyRequests {
			return resp, err
		}
		resp.Body.Close()

		if attempt == maxAttempts {
			break
		}

		if err := resetRequestBody(req); err != nil {
			return nil, err
		}

		sleepDuration, err := retryDelay(resp.Header, backoff, maxRetryAfter)
		if err != nil {
			return nil, err
		}
		time.Sleep(sleepDuration)
		backoff *= 2
	}
	return nil, ErrRateLimited
}

// resetRequestBody closes the consumed request body and replaces it with a fresh reader for retry.
func resetRequestBody(req *http.Request) error {
	if req.GetBody == nil {
		return nil
	}
	if req.Body != nil {
		_ = req.Body.Close()
	}
	body, err := req.GetBody()
	if err != nil {
		return err
	}
	req.Body = body
	return nil
}

// retryDelay returns the duration to wait before the next retry attempt. If a valid
// Retry-After header (seconds or HTTP-date) is present, it is used unless it exceeds
// maxRetryAfter (which returns ErrRateLimited). Otherwise, the current exponential backoff
// duration (capped at maxRetryAfter) is returned.
func retryDelay(headers http.Header, backoff, maxRetryAfter time.Duration) (time.Duration, error) {
	if delay, ok := parseRetryAfter(strings.TrimSpace(headers.Get("Retry-After"))); ok {
		if delay > maxRetryAfter {
			return 0, ErrRateLimited
		}
		return delay, nil
	}
	return min(backoff, maxRetryAfter), nil
}

// parseRetryAfter parses a Retry-After header value formatted either as delta-seconds or an HTTP-date.
func parseRetryAfter(header string) (time.Duration, bool) {
	if header == "" {
		return 0, false
	}
	if sec, err := strconv.Atoi(header); err == nil && sec >= 0 {
		return time.Duration(sec) * time.Second, true
	}
	if retryTime, err := http.ParseTime(header); err == nil {
		return max(0, time.Until(retryTime)), true
	}
	return 0, false
}
