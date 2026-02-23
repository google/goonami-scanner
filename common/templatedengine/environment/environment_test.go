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

package environment

import (
	"context"
	"regexp"
	"testing"

	"github.com/google/goonami-scanner/common/clients/callbackserver"
	"github.com/google/goonami-scanner/core/config"
	"google.golang.org/protobuf/proto"

	cscpb "github.com/google/goonami-scanner/common/clients/callbackserver/callbackserver_client_config_go_proto"
	cpb "github.com/google/goonami-scanner/core/config/config_go_proto"
	npb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
)

func TestEnvironment_InitializeFor(t *testing.T) {
	service := nspb.NetworkService_builder{
		NetworkEndpoint: npb.NetworkEndpoint_builder{
			Hostname: npb.Hostname_builder{Name: "example.com"}.Build(),
			Port:     npb.Port_builder{PortNumber: 80}.Build(),
			IpAddress: npb.IpAddress_builder{
				Address: "1.2.3.4",
			}.Build(),
		}.Build(),
		TransportProtocol:    npb.TransportProtocol_TCP,
		SupportedHttpMethods: []string{"GET"},
	}.Build()

	ctx := t.Context()
	if err := callbackserver.Initialize(ctx, config.Default()); err != nil {
		t.Fatalf("Failed to initialize callback server client: %v", err)
	}
	env := New(config.Default())
	env.InitializeFor(ctx, service)

	tests := []struct {
		key      string
		wantVal  string
		wantExpr *regexp.Regexp
	}{
		{key: VarNetServiceHostname, wantVal: "example.com"},
		{key: VarNetServicePort, wantVal: "80"},
		{key: VarNetServiceIP, wantVal: "1.2.3.4"},
		{key: VarNetServiceProtocol, wantVal: "TCP"},
		{key: VarNetServiceBaseURL, wantVal: "http://example.com:80"},
		{key: VarUtilTimestamp, wantExpr: regexp.MustCompile(`^\d+$`)},
	}

	for _, tc := range tests {
		got, ok := env.Get(tc.key)
		if !ok {
			t.Errorf("env.Get(%q) = _, false, want _, true", tc.key)
			continue
		}
		if tc.wantVal != "" && got != tc.wantVal {
			t.Errorf("env.Get(%q) = %q, want %q", tc.key, got, tc.wantVal)
		}
		if tc.wantExpr != nil && !tc.wantExpr.MatchString(got) {
			t.Errorf("env.Get(%q) = %q, doesn't match %v", tc.key, got, tc.wantExpr)
		}
	}
}

func TestEnvironment_InitializeFor_CallbackServer(t *testing.T) {
	service := nspb.NetworkService_builder{
		NetworkEndpoint: npb.NetworkEndpoint_builder{
			Hostname: npb.Hostname_builder{Name: "example.com"}.Build(),
			Port:     npb.Port_builder{PortNumber: 80}.Build(),
			IpAddress: npb.IpAddress_builder{
				Address: "1.2.3.4",
			}.Build(),
		}.Build(),
		TransportProtocol:    npb.TransportProtocol_TCP,
		SupportedHttpMethods: []string{"GET"},
	}.Build()

	tests := []struct {
		name         string
		cbsConfig    *cscpb.CallbackServerClientConfig
		wantVars     map[string]string
		wantPatterns map[string]*regexp.Regexp
	}{
		{
			name: "when_callback_server_is_enabled_with_ip_sets_variables",
			cbsConfig: cscpb.CallbackServerClientConfig_builder{
				CallbackAddress: proto.String("10.0.0.1"),
				CallbackPort:    proto.Int32(8080),
				PollingBaseUrl:  proto.String("http://polling.com"),
			}.Build(),
			wantVars: map[string]string{
				VarCallbackAddress: "10.0.0.1",
				VarCallbackPort:    "8080",
			},
			wantPatterns: map[string]*regexp.Regexp{
				VarCallbackSecret: regexp.MustCompile(`^[a-f0-9]{256}$`),                        // 128 bytes hex encoded
				VarCallbackURI:    regexp.MustCompile(`^http://10\.0\.0\.1:8080/[a-f0-9]{56}$`), // SHA3-224 is 56 hex chars
			},
		},
		{
			name: "when_callback_server_is_enabled_with_domain_sets_variables",
			cbsConfig: cscpb.CallbackServerClientConfig_builder{
				CallbackAddress: proto.String("callback.com"),
				CallbackPort:    proto.Int32(80),
				PollingBaseUrl:  proto.String("http://polling.com"),
			}.Build(),
			wantVars: map[string]string{
				VarCallbackAddress: "callback.com",
				VarCallbackPort:    "80",
			},
			wantPatterns: map[string]*regexp.Regexp{
				VarCallbackSecret: regexp.MustCompile(`^[a-f0-9]{256}$`),
				VarCallbackURI:    regexp.MustCompile(`^[a-f0-9]{56}\.callback\.com:80$`),
			},
		},
		{
			name:      "when_callback_server_is_disabled_does_not_set_variables",
			cbsConfig: &cscpb.CallbackServerClientConfig{},
			wantVars: map[string]string{
				VarCallbackAddress: "",
				VarCallbackPort:    "",
				VarCallbackSecret:  "",
				VarCallbackURI:     "",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.FromProto(cpb.Config_builder{
				Clients: cpb.ClientsConfig_builder{
					CallbackServer: tc.cbsConfig,
				}.Build(),
			}.Build())

			ctx := t.Context()
			if err := callbackserver.Initialize(ctx, cfg); err != nil {
				t.Fatalf("Failed to initialize callback server client: %v", err)
			}

			env := New(cfg)
			err := env.InitializeFor(ctx, service)
			if err != nil {
				t.Fatalf("InitializeFor() failed: %v", err)
			}

			for k, v := range tc.wantVars {
				got, ok := env.Get(k)
				if v == "" {
					if ok {
						t.Errorf("env.Get(%q) = %q, true, want _, false", k, got)
					}
				} else {
					if !ok || got != v {
						t.Errorf("env.Get(%q) = %q, %v, want %q, true", k, got, ok, v)
					}
				}
			}

			for k, p := range tc.wantPatterns {
				got, ok := env.Get(k)
				if !ok {
					t.Errorf("env.Get(%q) = _, false, want _, true", k)
					continue
				}
				if !p.MatchString(got) {
					t.Errorf("env.Get(%q) = %q, doesn't match pattern %v", k, got, p)
				}
			}
		})
	}
}

func TestEnvironment_Substitute(t *testing.T) {
	env := New(config.Default())
	env.Set("var1", "val1")
	env.Set("var2", "val2")

	tests := []struct {
		name     string
		template string
		want     string
	}{
		{
			name:     "when_no_variables_returns_original",
			template: "hello world",
			want:     "hello world",
		},
		{
			name:     "when_single_variable_replaces_it",
			template: "hello {{ var1 }}",
			want:     "hello val1",
		},
		{
			name:     "when_multiple_variables_replaces_them",
			template: "{{ var1 }} and {{ var2 }}",
			want:     "val1 and val2",
		},
		{
			name:     "when_repeated_variable_replaces_all",
			template: "hello {{ var1 }} {{ var1 }}",
			want:     "hello val1 val1",
		},
		{
			name:     "when_variable_not_found_leaves_it",
			template: "hello {{ unknown }}",
			want:     "hello {{ unknown }}",
		},
		{
			name:     "when_malformed_variable_leaves_it",
			template: "hello {{var1}}",
			want:     "hello {{var1}}",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := env.Substitute(context.Background(), tc.template)
			if got != tc.want {
				t.Errorf("Substitute(%q) = %q, want %q", tc.template, got, tc.want)
			}
		})
	}
}

func TestEnvironment_Extract(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		pattern  string
		varname  string
		wantOk   bool
		wantVars map[string]string
	}{
		{
			name:    "when_match_found_extracts_it",
			content: "token: abc-123",
			pattern: `token: ([a-z0-9-]+)`,
			varname: "token",
			wantOk:  true,
			wantVars: map[string]string{
				"token": "abc-123",
			},
		},
		{
			name:    "when_no_match_found_returns_false",
			content: "hello world",
			pattern: `token: ([a-z0-9-]+)`,
			varname: "token",
			wantOk:  false,
			wantVars: map[string]string{
				"token": "",
			},
		},
		{
			name:    "when_invalid_regexp_returns_false",
			content: "hello world",
			pattern: `(`,
			varname: "token",
			wantOk:  false,
			wantVars: map[string]string{
				"token": "",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := New(config.Default())
			gotOk := env.Extract(context.Background(), tc.content, tc.varname, tc.pattern)
			if gotOk != tc.wantOk {
				t.Errorf("Extract() = %v, want %v", gotOk, tc.wantOk)
			}

			for k, v := range tc.wantVars {
				val, ok := env.Get(k)
				if v == "" {
					if ok {
						t.Errorf("env.Get(%q) = %q, true, want _, false", k, val)
					}
				} else {
					if !ok || val != v {
						t.Errorf("env.Get(%q) = %q, %v, want %q, true", k, val, ok, v)
					}
				}
			}
		})
	}
}

func TestEnvironment_SetGet(t *testing.T) {
	env := New(config.Default())
	env.Set("key", "value")
	val, ok := env.Get("key")
	if !ok || val != "value" {
		t.Errorf("Get() = %q, %v, want %q, true", val, ok, "value")
	}

	_, ok = env.Get("unknown")
	if ok {
		t.Errorf("Get(unknown) = _, true, want _, false")
	}
}
