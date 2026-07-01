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

// Package simpleclient provides a simple HTTP client.
package simpleclient

import (
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/cookiejar"

	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/log"
	goohttp "github.com/google/goonami-scanner/core/net/http"
	"golang.org/x/time/rate"
)

func init() {
	goohttp.Register("simpleclient", newClient)
}

var (
	// ErrConfigNil is returned when the configuration is nil.
	ErrConfigNil = errors.New("config is nil")
)

// SimpleClient is a simple HTTP client that uses the standard library client and a rate limiter.
type SimpleClient struct {
	client  *http.Client
	limiter *rate.Limiter
}

// New creates a new SimpleClient.
func New(cfg *config.Config, options *goohttp.ClientOptions) (*SimpleClient, error) {
	if cfg == nil {
		return nil, ErrConfigNil
	}

	if options == nil {
		options = goohttp.DefaultClientOptions()
	}

	qps := cfg.GlobalConfig().GetPerformance().GetMaxHttpRequestsPerSecond()
	limiter := rate.NewLimiter(rate.Limit(qps), int(qps))

	// note that if the limit if infinity, a burst value of 0 is ignored.
	if qps == 0 {
		limiter.SetLimit(rate.Inf)
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: !options.EnforceTLSCertVerification,
			},
		},
	}

	if options.StoreCookies {
		jar, err := cookiejar.New(nil)
		if err != nil {
			return nil, err
		}
		client.Jar = jar
	}

	if options.DisableFollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	return &SimpleClient{
		client:  client,
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

func newClient(cfg *config.Config, options *goohttp.ClientOptions) (goohttp.Client, error) {
	return New(cfg, options)
}
