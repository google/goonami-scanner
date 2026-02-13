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
	"net/http"

	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/log"

	"golang.org/x/time/rate"
)

// SimpleClient is a simple HTTP client that uses the standard library client and a rate limiter.
type SimpleClient struct {
	client  *http.Client
	limiter *rate.Limiter
}

// NewSimpleClient creates a new SimpleClient.
func NewSimpleClient(cfg *config.Config) (*SimpleClient, error) {
	if cfg == nil {
		return nil, ErrConfigNil
	}

	qps := cfg.GlobalConfig().GetPerformance().GetMaxHttpRequestsPerSecond()
	limiter := rate.NewLimiter(rate.Limit(qps), int(qps))

	// note that if the limit if infinity, a burst value of 0 is ignored.
	if qps == 0 {
		limiter.SetLimit(rate.Inf)
	}

	return &SimpleClient{
		client:  &http.Client{},
		limiter: limiter,
	}, nil
}

// Do sends an HTTP request and returns an HTTP response in case of success.
func (c *SimpleClient) Do(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	if err := c.limiter.Wait(ctx); err != nil {
		return nil, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		log.DebugContextf(ctx, log.DebugLevelRequest, "%s %q error: %v", req.Method, req.URL.Path, err)
		return resp, err
	}

	log.DebugContextf(ctx, log.DebugLevelRequest, "%s %q status:%d", req.Method, req.URL.Path, resp.StatusCode)
	return resp, err
}
