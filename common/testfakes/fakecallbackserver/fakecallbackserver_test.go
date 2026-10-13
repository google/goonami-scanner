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

package fakecallbackserver

import (
	"io"
	"net/http"
	"testing"
)

func TestServer(t *testing.T) {
	tests := []struct {
		name               string
		enabled            bool
		hasHTTPInteraction bool
		hasDNSInteraction  bool
		secret             string
		wantStatus         int
		wantBody           string
		wantConfigured     bool
	}{
		{
			name:               "when_enabled_with_http_interaction_returns_200_and_json",
			enabled:            true,
			hasHTTPInteraction: true,
			secret:             "sec1",
			wantStatus:         http.StatusOK,
			wantBody:           `{"hasHttpInteraction": true, "hasDnsInteraction": false}`,
			wantConfigured:     true,
		},
		{
			name:              "when_enabled_with_dns_interaction_returns_200_and_json",
			enabled:           true,
			hasDNSInteraction: true,
			secret:            "sec2",
			wantStatus:        http.StatusOK,
			wantBody:          `{"hasHttpInteraction": false, "hasDnsInteraction": true}`,
			wantConfigured:    true,
		},
		{
			name:           "when_enabled_without_interaction_returns_404",
			enabled:        true,
			secret:         "sec3",
			wantStatus:     http.StatusNotFound,
			wantBody:       "not found",
			wantConfigured: true,
		},
		{
			name:               "when_disabled_returns_404_and_empty_config",
			enabled:            false,
			hasHTTPInteraction: true,
			secret:             "sec4",
			wantStatus:         http.StatusNotFound,
			wantBody:           "",
			wantConfigured:     false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := NewServer(tc.enabled, tc.hasHTTPInteraction, tc.hasDNSInteraction)
			defer srv.Close()

			resp, err := http.Get(srv.URL() + "/?secret=" + tc.secret)
			if err != nil {
				t.Fatalf("http.Get() unexpected error: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tc.wantStatus {
				t.Errorf("StatusCode = %d, want %d", resp.StatusCode, tc.wantStatus)
			}
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("io.ReadAll() unexpected error: %v", err)
			}
			if string(body) != tc.wantBody {
				t.Errorf("body = %q, want %q", string(body), tc.wantBody)
			}
			if got := srv.LastSecret(); got != tc.secret {
				t.Errorf("LastSecret() = %q, want %q", got, tc.secret)
			}

			clientsCfg := srv.ClientsConfig()
			gotConfigured := clientsCfg.GetCallbackServer().HasHttpPollConfig()
			if gotConfigured != tc.wantConfigured {
				t.Errorf("HasHttpPollConfig() = %v, want %v", gotConfigured, tc.wantConfigured)
			}
		})
	}
}
