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

package netendpoint

import (
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"

	npb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
)

func TestToHost(t *testing.T) {
	tests := []struct {
		name    string
		input   *npb.NetworkEndpoint
		want    string
		wantErr error
	}{
		{
			name: "when_ipv4_ip_only_returns_ip",
			input: npb.NetworkEndpoint_builder{
				IpAddress: npb.IpAddress_builder{Address: "127.0.0.1", AddressFamily: npb.AddressFamily_IPV4}.Build(),
			}.Build(),
			want: "127.0.0.1",
		},
		{
			name: "when_ipv6_ip_only_returns_ip",
			input: npb.NetworkEndpoint_builder{
				IpAddress: npb.IpAddress_builder{Address: "3ffe::1", AddressFamily: npb.AddressFamily_IPV6}.Build(),
			}.Build(),
			want: "3ffe::1",
		},
		{
			name: "when_ipv4_ip_and_port_returns_ip_without_port",
			input: npb.NetworkEndpoint_builder{
				IpAddress: npb.IpAddress_builder{Address: "127.0.0.1", AddressFamily: npb.AddressFamily_IPV4}.Build(),
				Port:      npb.Port_builder{PortNumber: 80}.Build(),
			}.Build(),
			want: "127.0.0.1",
		},
		{
			name: "when_ipv6_ip_and_port_returns_ip_without_port",
			input: npb.NetworkEndpoint_builder{
				IpAddress: npb.IpAddress_builder{Address: "3ffe::1", AddressFamily: npb.AddressFamily_IPV6}.Build(),
				Port:      npb.Port_builder{PortNumber: 80}.Build(),
			}.Build(),
			want: "3ffe::1",
		},
		{
			name: "when_hostname_and_port_returns_hostname_without_port",
			input: npb.NetworkEndpoint_builder{
				Hostname: npb.Hostname_builder{Name: "example.com"}.Build(),
				Port:     npb.Port_builder{PortNumber: 80}.Build(),
			}.Build(),
			want: "example.com",
		},
		{
			name: "when_ip_hostname_and_port_returns_ip_and_hostname_without_port",
			input: npb.NetworkEndpoint_builder{
				IpAddress: npb.IpAddress_builder{Address: "127.0.0.1", AddressFamily: npb.AddressFamily_IPV4}.Build(),
				Hostname:  npb.Hostname_builder{Name: "example.com"}.Build(),
				Port:      npb.Port_builder{PortNumber: 443}.Build(),
			}.Build(),
			want: "127.0.0.1_example.com",
		},
		{
			name: "when_ipv6_hostname_and_port_returns_ipv6_and_hostname_without_port",
			input: npb.NetworkEndpoint_builder{
				IpAddress: npb.IpAddress_builder{Address: "3ffe::1", AddressFamily: npb.AddressFamily_IPV6}.Build(),
				Hostname:  npb.Hostname_builder{Name: "example.com"}.Build(),
				Port:      npb.Port_builder{PortNumber: 443}.Build(),
			}.Build(),
			want: "3ffe::1_example.com",
		},
		{
			name:    "when_no_ip_and_no_hostname_returns_error",
			input:   &npb.NetworkEndpoint{},
			wantErr: ErrEndpointMissingAddress,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ToHost(tc.input)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("ToHost(%v) returned unexpected error: %v, want %v", tc.input, err, tc.wantErr)
			}
			if tc.wantErr != nil {
				return
			}
			if got != tc.want {
				t.Errorf("ToHost(%v) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestSplitHost(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "when_empty_returns_nil",
			input: "",
			want:  nil,
		},
		{
			name:  "when_ipv4_only_returns_single_element",
			input: "1.2.3.4",
			want:  []string{"1.2.3.4"},
		},
		{
			name:  "when_ipv6_only_returns_single_element",
			input: "3ffe::1",
			want:  []string{"3ffe::1"},
		},
		{
			name:  "when_hostname_only_returns_single_element",
			input: "example.com",
			want:  []string{"example.com"},
		},
		{
			name:  "when_hostname_contains_underscore_does_not_split",
			input: "my_app.internal",
			want:  []string{"my_app.internal"},
		},
		{
			name:  "when_ipv4_and_hostname_splits_into_two_parts",
			input: "1.2.3.4_example.com",
			want:  []string{"1.2.3.4", "example.com"},
		},
		{
			name:  "when_ipv4_and_underscore_hostname_splits_only_after_ip",
			input: "1.2.3.4_my_app.internal",
			want:  []string{"1.2.3.4", "my_app.internal"},
		},
		{
			name:  "when_ipv6_and_hostname_splits_into_two_parts",
			input: "3ffe::1_example.com",
			want:  []string{"3ffe::1", "example.com"},
		},
		{
			name:  "when_ip_with_trailing_underscore_returns_ip_only",
			input: "1.2.3.4_",
			want:  []string{"1.2.3.4"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := SplitHost(tc.input)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("SplitHost(%q) diff (-want +got):\n%s", tc.input, diff)
			}
		})
	}
}
