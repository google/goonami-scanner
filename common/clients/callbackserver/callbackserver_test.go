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

package callbackserver

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/goonami-scanner/core/config"
	goohttp "github.com/google/goonami-scanner/core/net/http"

	cpb "github.com/google/goonami-scanner/core/config/config_go_proto"
	cbpb "github.com/google/goonami-scanner/tools/callbackserver/callbackserver_config_go_proto"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		config  *cpb.Config
		wantErr error
	}{
		{
			name: "when_config_has_valid_callback_server_it_succeeds",
			config: cpb.Config_builder{
				Clients: map[string]*cpb.ClientsConfig{
					"all": cpb.ClientsConfig_builder{
						CallbackServer: cbpb.CallbackserverConfig_builder{
							HttpPollConfig: cbpb.EndpointConfig_builder{
								PublicUri: "http://127.0.0.1:8081",
							}.Build(),
							HttpRecordConfig: cbpb.EndpointConfig_builder{
								PublicUri: "http://127.0.0.1:8080",
							}.Build(),
							DnsRecordConfig: cbpb.EndpointConfig_builder{
								PublicUri: "cb.localhost.lan",
							}.Build(),
						}.Build(),
					}.Build(),
				},
			}.Build(),
			wantErr: nil,
		},
		{
			name: "when_config_has_no_callback_server_it_is_created_anyway",
			config: cpb.Config_builder{
				Clients: map[string]*cpb.ClientsConfig{
					"all": cpb.ClientsConfig_builder{}.Build(),
				},
			}.Build(),
			wantErr: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.FromProto(tc.config)
			_, err := new(t.Context(), cfg)
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("New() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestClient_IsCallbackServerEnabled(t *testing.T) {
	tests := []struct {
		name   string
		config *cbpb.CallbackserverConfig
		want   bool
	}{
		{
			name:   "when_config_is_empty_returns_false",
			config: cbpb.CallbackserverConfig_builder{}.Build(),
			want:   false,
		},
		{
			name: "when_all_endpoints_are_provided_returns_true",
			config: cbpb.CallbackserverConfig_builder{
				HttpPollConfig: cbpb.EndpointConfig_builder{
					PublicUri: "http://127.0.0.1:8081",
				}.Build(),
				HttpRecordConfig: cbpb.EndpointConfig_builder{
					PublicUri: "http://127.0.0.1:8080",
				}.Build(),
				DnsRecordConfig: cbpb.EndpointConfig_builder{
					PublicUri: "cb.localhost.lan",
				}.Build(),
			}.Build(),
			want: true,
		},
		{
			name: "when_dns_record_config_is_missing_returns_false",
			config: cbpb.CallbackserverConfig_builder{
				HttpPollConfig: cbpb.EndpointConfig_builder{
					PublicUri: "http://127.0.0.1:8081",
				}.Build(),
				HttpRecordConfig: cbpb.EndpointConfig_builder{
					PublicUri: "http://127.0.0.1:8080",
				}.Build(),
			}.Build(),
			want: false,
		},
		{
			name: "when_http_record_config_is_missing_returns_false",
			config: cbpb.CallbackserverConfig_builder{
				HttpPollConfig: cbpb.EndpointConfig_builder{
					PublicUri: "http://127.0.0.1:8081",
				}.Build(),
				DnsRecordConfig: cbpb.EndpointConfig_builder{
					PublicUri: "cb.localhost.lan",
				}.Build(),
			}.Build(),
			want: false,
		},
		{
			name: "when_http_poll_config_is_missing_returns_false",
			config: cbpb.CallbackserverConfig_builder{
				HttpRecordConfig: cbpb.EndpointConfig_builder{
					PublicUri: "http://127.0.0.1:8080",
				}.Build(),
				DnsRecordConfig: cbpb.EndpointConfig_builder{
					PublicUri: "cb.localhost.lan",
				}.Build(),
			}.Build(),
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := &Client{config: tc.config}
			if got := c.IsCallbackServerEnabled(); got != tc.want {
				t.Errorf("IsCallbackServerEnabled() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestClient_GetHTTPCallbackURI(t *testing.T) {
	tests := []struct {
		name    string
		config  *cbpb.CallbackserverConfig
		secret  string
		want    string
		wantErr error
	}{
		{
			name:    "when_disabled_returns_error",
			config:  cbpb.CallbackserverConfig_builder{}.Build(),
			secret:  "test",
			want:    "",
			wantErr: ErrInvalidConfig,
		},
		{
			name: "when_address_is_ip_returns_http_format",
			config: cbpb.CallbackserverConfig_builder{
				HttpPollConfig: cbpb.EndpointConfig_builder{
					PublicUri: "http://1.2.3.4:8081",
				}.Build(),
				HttpRecordConfig: cbpb.EndpointConfig_builder{
					PublicUri: "http://1.2.3.4:8080",
				}.Build(),
				DnsRecordConfig: cbpb.EndpointConfig_builder{
					PublicUri: "cb.localhost.lan",
				}.Build(),
			}.Build(),
			secret:  "test",
			want:    "http://1.2.3.4:8080/3797bf0afbbfca4a7bbba7602a2b552746876517a7f9b7ce2db0ae7b",
			wantErr: nil,
		},
		{
			name: "when_address_is_domain_returns_http_format",
			config: cbpb.CallbackserverConfig_builder{
				HttpPollConfig: cbpb.EndpointConfig_builder{
					PublicUri: "http://goonami.lan:8081",
				}.Build(),
				HttpRecordConfig: cbpb.EndpointConfig_builder{
					PublicUri: "http://goonami.lan:8080",
				}.Build(),
				DnsRecordConfig: cbpb.EndpointConfig_builder{
					PublicUri: "cb.localhost.lan",
				}.Build(),
			}.Build(),
			secret:  "test",
			want:    "http://goonami.lan:8080/3797bf0afbbfca4a7bbba7602a2b552746876517a7f9b7ce2db0ae7b",
			wantErr: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := &Client{config: tc.config}
			got, err := c.GetHTTPCallbackURI(tc.secret)
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("GetCallbackURI() error = %v, wantErr %v", err, tc.wantErr)
				return
			}

			if tc.wantErr != nil {
				return
			}

			if got != tc.want {
				t.Errorf("GetCallbackURI() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestClient_Interaction(t *testing.T) {
	tests := []struct {
		name           string
		serverResponse string
		status         int
		secret         string
		config         *cbpb.CallbackserverConfig
		want           bool
		wantErr        error
	}{
		{
			name:           "when_interaction_recorded_returns_true",
			serverResponse: `{"hasDnsInteraction": true, "hasHttpInteraction": false}`,
			status:         http.StatusOK,
			secret:         "test_secret",
			want:           true,
			wantErr:        nil,
		},
		{
			name:           "when_no_interaction_recorded_returns_false",
			serverResponse: `{"hasDnsInteraction": false, "hasHttpInteraction": false}`,
			status:         http.StatusOK,
			secret:         "test_secret",
			want:           false,
			wantErr:        nil,
		},
		{
			name:           "when_invalid_json_returns_error",
			serverResponse: `invalid json`,
			status:         http.StatusOK,
			secret:         "test_secret",
			want:           false,
			wantErr:        ErrPollingRequest,
		},
		{
			name:           "when_server_returns_404_returns_false",
			serverResponse: `not found`,
			status:         http.StatusNotFound,
			secret:         "test_secret",
			want:           false,
			wantErr:        nil,
		},
		{
			name:           "when_server_is_disabled_returns_error",
			serverResponse: ``,
			status:         http.StatusOK,
			secret:         "test_secret",
			config:         cbpb.CallbackserverConfig_builder{}.Build(),
			want:           false,
			wantErr:        ErrInvalidConfig,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Get("secret") != tc.secret {
					t.Errorf("expected secret %q, got %q", tc.secret, r.URL.Query().Get("secret"))
				}
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.serverResponse)
			}))
			defer server.Close()

			serverConfig := tc.config
			if serverConfig == nil {
				serverConfig = cbpb.CallbackserverConfig_builder{
					HttpPollConfig: cbpb.EndpointConfig_builder{
						PublicUri: server.URL,
					}.Build(),
					HttpRecordConfig: cbpb.EndpointConfig_builder{
						PublicUri: "http://irrelevant:8080",
					}.Build(),
					DnsRecordConfig: cbpb.EndpointConfig_builder{
						PublicUri: "cb.localhost.lan",
					}.Build(),
				}.Build()
			}

			cfg := config.FromProto(cpb.Config_builder{
				Clients: map[string]*cpb.ClientsConfig{
					"all": cpb.ClientsConfig_builder{
						CallbackServer: serverConfig,
					}.Build(),
				},
			}.Build())
			if err := goohttp.InitializeDefaults(cfg); err != nil {
				t.Fatalf("failed to initialize default HTTP client: %v", err)
			}
			ctx := t.Context()
			client, err := new(ctx, cfg)
			if err != nil {
				t.Fatalf("failed to create callback server client: %v", err)
			}

			got, err := client.HasInteraction(ctx, tc.secret)
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("HasInteraction() error = %v, wantErr %v", err, tc.wantErr)
				return
			}

			if tc.wantErr != nil {
				return
			}

			if got != tc.want {
				t.Errorf("HasInteraction() = %v, want %v", got, tc.want)
			}
		})
	}
}
