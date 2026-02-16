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

	env := New()
	env.InitializeFor(context.Background(), service)

	tests := []struct {
		key      string
		wantVal  string
		wantExpr *regexp.Regexp
	}{
		{key: "T_NS_HOSTNAME", wantVal: "example.com"},
		{key: "T_NS_PORT", wantVal: "80"},
		{key: "T_NS_IP", wantVal: "1.2.3.4"},
		{key: "T_NS_PROTOCOL", wantVal: "TCP"},
		{key: "T_NS_BASEURL", wantVal: "http://example.com:80"},
		{key: "T_UTL_CURRENT_TIMESTAMP_MS", wantExpr: regexp.MustCompile(`^\d+$`)},
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

func TestEnvironment_Substitute(t *testing.T) {
	env := New()
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
			env := New()
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
	env := New()
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
