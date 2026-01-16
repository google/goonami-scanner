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
	"net/http/httptest"
	"testing"

	"github.com/google/goonami-scanner/core/config"
	cpb "github.com/google/goonami-scanner/core/config/config_go_proto"
	"golang.org/x/time/rate"
)

func TestNewSimpleClient(t *testing.T) {
	tests := []struct {
		name      string
		cfg       *config.Config
		wantLimit rate.Limit
		wantBurst int
		wantErr   bool
	}{
		{
			name:      "nil_config_returns_err",
			cfg:       nil,
			wantLimit: 0,
			wantBurst: 0,
			wantErr:   true,
		},
		{
			name: "qps_10_has_limiter_with_10_qps",
			cfg: config.FromProto(cpb.Config_builder{
				Globalcfg: cpb.GlobalConfig_builder{
					Performance: cpb.GlobalConfig_Performance_builder{
						MaxHttpRequestsPerSecond: 10,
					}.Build(),
				}.Build(),
			}.Build()),
			wantLimit: 10,
			wantBurst: 10,
			wantErr:   false,
		},
		{
			name: "qps_0_has_unlimited_limiter",
			cfg: config.FromProto(cpb.Config_builder{
				Globalcfg: cpb.GlobalConfig_builder{
					Performance: cpb.GlobalConfig_Performance_builder{
						MaxHttpRequestsPerSecond: 0,
					}.Build(),
				}.Build(),
			}.Build()),
			wantLimit: rate.Inf,
			wantBurst: 0,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewSimpleClient(tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewSimpleClient() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
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
				MaxHttpRequestsPerSecond: 0,
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
