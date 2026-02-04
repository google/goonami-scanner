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

	"github.com/google/goonami-scanner/core/config"

	"golang.org/x/time/rate"
)

var ErrEmptyConfig = errors.New("config is nil")

// RateLimitClient add rate-limiting to an underlying HTTP client.
type RateLimitClient struct {
	client  Client
	limiter *rate.Limiter
}

// NewRateLimitClient creates a new SimpleClient.
func NewRateLimitClient(client Client, cfg *config.Config) (*RateLimitClient, error) {
	if cfg == nil {
		return nil, ErrEmptyConfig
	}

	qps := cfg.GlobalConfig().GetPerformance().GetMaxHttpRequestsPerSecond()
	limiter := rate.NewLimiter(rate.Limit(qps), int(qps))

	// note that if the limit if infinity, a burst value of 0 is ignored.
	if qps == 0 {
		limiter.SetLimit(rate.Inf)
	}

	return &RateLimitClient{
		client:  client,
		limiter: limiter,
	}, nil
}

// Do sends an HTTP request and returns an HTTP response in case of success.
func (c *RateLimitClient) Do(req *http.Request) (*http.Response, error) {
	if err := c.limiter.Wait(req.Context()); err != nil {
		return nil, err
	}

	return c.client.Do(req)
}
