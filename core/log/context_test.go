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

package log

import (
	"context"
	"testing"

	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
)

func buildTestContext(ctx context.Context, host string, module string, service *nspb.NetworkService) context.Context {
	switch {
	case service != nil && module != "":
		return ContextForModuleAndService(ctx, module, service)
	case service != nil:
		return ContextForService(ctx, service)
	case host != "" && module != "":
		return ContextForModuleAndHost(ctx, module, host)
	case host != "":
		return ContextForHost(ctx, host)
	case module != "":
		return ContextForModule(ctx, module)
	default:
		return ctx
	}
}

func TestHostFromContext(t *testing.T) {
	testCases := []struct {
		name    string
		host    string
		module  string
		service *nspb.NetworkService
		want    string
	}{
		{
			name: "when_no_host_returns_empty_string",
			want: "",
		},
		{
			name: "when_host_set_directly_returns_host",
			host: "10.0.0.1",
			want: "10.0.0.1",
		},
		{
			name:   "when_module_and_host_set_returns_host",
			host:   "10.0.0.1",
			module: "my-module",
			want:   "10.0.0.1",
		},
		{
			name:   "when_module_only_set_returns_empty_string",
			module: "my-module",
			want:   "",
		},
		{
			name:    "when_host_set_via_service_returns_host",
			service: testService("", "example.com", 80),
			want:    "example.com",
		},
		{
			name:    "when_ip_and_hostname_set_via_service_returns_combined_host",
			service: testService("1.2.3.4", "example.com", 80),
			want:    "1.2.3.4_example.com",
		},
		{
			name:    "when_module_and_service_set_returns_host",
			module:  "my-module",
			service: testService("1.2.3.4", "", 443),
			want:    "1.2.3.4",
		},
		{
			name:    "when_service_missing_host_returns_empty_string",
			service: testService("", "", 8080),
			want:    "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := buildTestContext(t.Context(), tc.host, tc.module, tc.service)
			if got := HostFromContext(ctx); got != tc.want {
				t.Errorf("HostFromContext() = %q, want %q", got, tc.want)
			}
		})
	}
}
