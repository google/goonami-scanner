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
	"context"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"

	"github.com/google/goonami-scanner/core/config"
	"golang.org/x/time/rate"
	"google.golang.org/protobuf/proto"

	cpb "github.com/google/goonami-scanner/core/config/config_go_proto"
)

func TestNewSimpleClient(t *testing.T) {
	tests := []struct {
		name      string
		cfg       *config.Config
		wantLimit rate.Limit
		wantBurst int
		wantErr   error
	}{
		{
			name:      "when_config_is_nil_returns_error",
			cfg:       nil,
			wantLimit: 0,
			wantBurst: 0,
			wantErr:   ErrConfigNil,
		},
		{
			name: "when_max_requests_per_second_is_ten_returns_limiter_with_ten_qps",
			cfg: config.FromProto(cpb.Config_builder{
				Globalcfg: cpb.GlobalConfig_builder{
					Performance: cpb.GlobalConfig_Performance_builder{
						MaxHttpRequestsPerSecond: proto.Int32(10),
					}.Build(),
				}.Build(),
			}.Build()),
			wantLimit: 10,
			wantBurst: 10,
			wantErr:   nil,
		},
		{
			name: "when_max_requests_per_second_is_zero_returns_unlimited_limiter",
			cfg: config.FromProto(cpb.Config_builder{
				Globalcfg: cpb.GlobalConfig_builder{
					Performance: cpb.GlobalConfig_Performance_builder{
						MaxHttpRequestsPerSecond: proto.Int32(0),
					}.Build(),
				}.Build(),
			}.Build()),
			wantLimit: rate.Inf,
			wantBurst: 0,
			wantErr:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewSimpleClient(tt.cfg)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("NewSimpleClient() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr != nil {
				return
			}

			if c.limiter.Limit() != tt.wantLimit {
				t.Errorf("NewSimpleClient() limit = %v, wantLimit %v", c.limiter.Limit(), tt.wantLimit)
			}

			if c.limiter.Burst() != tt.wantBurst {
				t.Errorf("NewSimpleClient() burst = %v, wantBurst %v", c.limiter.Burst(), tt.wantBurst)
			}
		})
	}
}

func TestDoWithoutRateLimit(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := config.FromProto(cpb.Config_builder{
		Globalcfg: cpb.GlobalConfig_builder{
			Performance: cpb.GlobalConfig_Performance_builder{
				MaxHttpRequestsPerSecond: proto.Int32(0),
			}.Build(),
		}.Build(),
	}.Build())

	c, err := NewSimpleClient(cfg)
	if err != nil {
		t.Fatalf("NewSimpleClient() failed: %v", err)
	}

	req, err := http.NewRequest("GET", ts.URL, nil)
	if err != nil {
		t.Fatalf("http.NewRequest() failed: %v", err)
	}

	resp, err := c.Do(req)
	if err != nil {
		t.Errorf("Do() failed: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Do() status = %v, want %v", resp.StatusCode, http.StatusOK)
	}
}

func TestDo_ContextCancelled(t *testing.T) {
	cfg := config.FromProto(cpb.Config_builder{
		Globalcfg: cpb.GlobalConfig_builder{
			Performance: cpb.GlobalConfig_Performance_builder{
				MaxHttpRequestsPerSecond: proto.Int32(1),
			}.Build(),
		}.Build(),
	}.Build())

	c, err := NewSimpleClient(cfg)
	if err != nil {
		t.Fatalf("NewSimpleClient() failed: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	req, _ := http.NewRequestWithContext(ctx, "GET", "http://localhost", nil)
	_, err = c.Do(req)

	if err == nil {
		t.Errorf("Do() returned no error, want error")
	}
}

func TestSimpleClient_WithCookieJar(t *testing.T) {
	cfg := config.FromProto(cpb.Config_builder{
		Globalcfg: cpb.GlobalConfig_builder{
			Performance: cpb.GlobalConfig_Performance_builder{
				MaxHttpRequestsPerSecond: proto.Int32(10),
			}.Build(),
		}.Build(),
	}.Build())

	c, err := NewSimpleClient(cfg)
	if err != nil {
		t.Fatalf("NewSimpleClient() failed: %v", err)
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New() failed: %v", err)
	}

	newClient := c.WithCookieJar(jar)

	// Type assertion to access internal fields for testing
	simpleNewClient, ok := newClient.(*SimpleClient)
	if !ok {
		t.Fatalf("WithCookieJar() did not return a *SimpleClient")
	}

	// 1. Verify the exact same limiter pointer is shared
	if simpleNewClient.limiter != c.limiter {
		t.Errorf("WithCookieJar() did not share the limiter pointer")
	}

	// 2. Verify the underlying http.Client is a copy (pointers differ)
	if simpleNewClient.client == c.client {
		t.Errorf("WithCookieJar() did not create a copy of the underlying http.Client")
	}

	// 3. Verify the cookie jar is attached
	if simpleNewClient.client.Jar != jar {
		t.Errorf("WithCookieJar() did not attach the cookie jar")
	}

	// 4. Verify functionality: Cookies are preserved across requests
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/set" {
			http.SetCookie(w, &http.Cookie{Name: "test", Value: "123"})
			return
		}
		if r.URL.Path == "/get" {
			cookie, err := r.Cookie("test")
			if err != nil || cookie.Value != "123" {
				t.Errorf("Cookie 'test=123' not found in request")
			}
			return
		}
	}))
	defer ts.Close()

	reqSet, _ := http.NewRequestWithContext(t.Context(), "GET", ts.URL+"/set", nil)
	_, err = simpleNewClient.Do(reqSet)
	if err != nil {
		t.Fatalf("Do(/set) failed: %v", err)
	}

	reqGet, _ := http.NewRequestWithContext(t.Context(), "GET", ts.URL+"/get", nil)
	_, err = simpleNewClient.Do(reqGet)
	if err != nil {
		t.Fatalf("Do(/get) failed: %v", err)
	}
}
