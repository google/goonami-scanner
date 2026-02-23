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

	cscpb "github.com/google/goonami-scanner/common/clients/callbackserver/callbackserver_client_config_go_proto"
	"github.com/google/goonami-scanner/core/config"
	cfgpb "github.com/google/goonami-scanner/core/config/config_go_proto"
	goohttp "github.com/google/goonami-scanner/core/net/http"
	"google.golang.org/protobuf/proto"
)

func TestGenerateCBID(t *testing.T) {
	tests := []struct {
		name   string
		secret string
		want   string
	}{
		{
			name:   "when_secret_is_empty_returns_hash_of_empty_string",
			secret: "",
			want:   "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7",
		},
		{
			name:   "when_secret_is_provided_returns_sha3_224_hash",
			secret: "a3d9ed89deadbeef",
			want:   "04041e8898e739ca33a250923e24f59ca41a8373f8cf6a45a1275f3b",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := GenerateCBID(tc.secret)
			if err != nil {
				t.Fatalf("GenerateCBID(%q) unexpected error: %v", tc.secret, err)
			}
			if got != tc.want {
				t.Errorf("GenerateCBID(%q) = %q, want %q", tc.secret, got, tc.want)
			}
		})
	}
}

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		config  *cfgpb.Config
		wantErr error
	}{
		{
			name: "when_config_has_no_callback_server_it_is_created_anyway",
			config: cfgpb.Config_builder{
				Clients: cfgpb.ClientsConfig_builder{}.Build(),
			}.Build(),
			wantErr: nil,
		},
		{
			name: "when_config_has_valid_callback_server_it_succeeds",
			config: cfgpb.Config_builder{
				Clients: cfgpb.ClientsConfig_builder{
					CallbackServer: cscpb.CallbackServerClientConfig_builder{
						CallbackPort: proto.Int32(8080),
					}.Build(),
				}.Build(),
			}.Build(),
			wantErr: nil,
		},
		{
			name: "when_port_is_too_low_it_returns_error",
			config: cfgpb.Config_builder{
				Clients: cfgpb.ClientsConfig_builder{
					CallbackServer: cscpb.CallbackServerClientConfig_builder{
						CallbackPort: proto.Int32(0),
					}.Build(),
				}.Build(),
			}.Build(),
			wantErr: ErrInvalidConfig,
		},
		{
			name: "when_port_is_negative_it_returns_error",
			config: cfgpb.Config_builder{
				Clients: cfgpb.ClientsConfig_builder{
					CallbackServer: cscpb.CallbackServerClientConfig_builder{
						CallbackPort: proto.Int32(-1),
					}.Build(),
				}.Build(),
			}.Build(),
			wantErr: ErrInvalidConfig,
		},
		{
			name: "when_port_is_too_high_it_returns_error",
			config: cfgpb.Config_builder{
				Clients: cfgpb.ClientsConfig_builder{
					CallbackServer: cscpb.CallbackServerClientConfig_builder{
						CallbackPort: proto.Int32(65536),
					}.Build(),
				}.Build(),
			}.Build(),
			wantErr: ErrInvalidConfig,
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
		config *cscpb.CallbackServerClientConfig
		want   bool
	}{
		{
			name:   "when_config_is_empty_returns_false",
			config: cscpb.CallbackServerClientConfig_builder{}.Build(),
			want:   false,
		},
		{
			name: "when_all_fields_are_provided_returns_true",
			config: cscpb.CallbackServerClientConfig_builder{
				CallbackAddress: proto.String("1.2.3.4"),
				CallbackPort:    proto.Int32(80),
				PollingBaseUrl:  proto.String("http://localhost.lan"),
			}.Build(),
			want: true,
		},
		{
			name: "when_address_is_missing_returns_false",
			config: cscpb.CallbackServerClientConfig_builder{
				CallbackPort:   proto.Int32(80),
				PollingBaseUrl: proto.String("http://localhost.lan"),
			}.Build(),
			want: false,
		},
		{
			name: "when_polling_url_is_missing_returns_false",
			config: cscpb.CallbackServerClientConfig_builder{
				CallbackAddress: proto.String("1.2.3.4"),
				CallbackPort:    proto.Int32(80),
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

func TestClient_GetCallbackURI(t *testing.T) {
	tests := []struct {
		name    string
		config  *cscpb.CallbackServerClientConfig
		secret  string
		want    string
		wantErr error
	}{
		{
			name: "when_disabled_returns_error",
			config: cscpb.CallbackServerClientConfig_builder{
				CallbackAddress: proto.String(""),
			}.Build(),
			secret:  "test",
			want:    "",
			wantErr: ErrInvalidConfig,
		},
		{
			name: "when_address_is_ip_returns_path_format",
			config: cscpb.CallbackServerClientConfig_builder{
				CallbackAddress: proto.String("1.2.3.4"),
				CallbackPort:    proto.Int32(8080),
				PollingBaseUrl:  proto.String("http://localhost.lan"),
			}.Build(),
			secret:  "test",
			want:    "http://1.2.3.4:8080/3797bf0afbbfca4a7bbba7602a2b552746876517a7f9b7ce2db0ae7b",
			wantErr: nil,
		},
		{
			name: "when_address_is_domain_returns_subdomain_format",
			config: cscpb.CallbackServerClientConfig_builder{
				CallbackAddress: proto.String("callback.com"),
				CallbackPort:    proto.Int32(80),
				PollingBaseUrl:  proto.String("http://localhost.lan"),
			}.Build(),
			secret:  "test",
			want:    "3797bf0afbbfca4a7bbba7602a2b552746876517a7f9b7ce2db0ae7b.callback.com:80",
			wantErr: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := &Client{config: tc.config}
			got, err := c.GetCallbackURI(tc.secret)
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
		config         *cscpb.CallbackServerClientConfig
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
			config:         cscpb.CallbackServerClientConfig_builder{}.Build(),
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
				serverConfig = cscpb.CallbackServerClientConfig_builder{
					CallbackAddress: proto.String("1.2.3.4"),
					CallbackPort:    proto.Int32(80),
					PollingBaseUrl:  proto.String(server.URL),
				}.Build()
			}

			cfg := config.FromProto(cfgpb.Config_builder{
				Clients: cfgpb.ClientsConfig_builder{
					CallbackServer: serverConfig,
				}.Build(),
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
