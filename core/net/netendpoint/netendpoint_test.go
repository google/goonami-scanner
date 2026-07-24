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
	"google.golang.org/protobuf/testing/protocmp"

	npb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
)

func TestNewFromString(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  *npb.NetworkEndpoint
	}{
		{
			name:  "when_input_is_not_an_ip_returns_hostname",
			input: "example.com",
			want: npb.NetworkEndpoint_builder{
				Type:     npb.NetworkEndpoint_HOSTNAME,
				Hostname: npb.Hostname_builder{Name: "example.com"}.Build(),
			}.Build(),
		},
		{
			name:  "when_input_is_ipv4_returns_ip_ipv4",
			input: "127.0.0.1",
			want: npb.NetworkEndpoint_builder{
				Type: npb.NetworkEndpoint_IP,
				IpAddress: npb.IpAddress_builder{
					Address:       "127.0.0.1",
					AddressFamily: npb.AddressFamily_IPV4,
				}.Build(),
			}.Build(),
		},
		{
			name:  "when_input_is_ipv6_returns_ip_ipv6",
			input: "::1",
			want: npb.NetworkEndpoint_builder{
				Type: npb.NetworkEndpoint_IP,
				IpAddress: npb.IpAddress_builder{
					Address:       "::1",
					AddressFamily: npb.AddressFamily_IPV6,
				}.Build(),
			}.Build(),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := FromString(tc.input)
			if diff := cmp.Diff(tc.want, got, protocmp.Transform()); diff != "" {
				t.Errorf("NewFromString(%q) returned diff (-want +got):\n%s", tc.input, diff)
			}
		})
	}
}

func TestToURIAuthority(t *testing.T) {
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
			want:    "127.0.0.1",
			wantErr: nil,
		},
		{
			name: "when_ipv6_ip_only_returns_bracketed_ip",
			input: npb.NetworkEndpoint_builder{
				IpAddress: npb.IpAddress_builder{Address: "3ffe::1", AddressFamily: npb.AddressFamily_IPV6}.Build(),
			}.Build(),
			want:    "[3ffe::1]",
			wantErr: nil,
		},
		{
			name: "when_ipv4_ip_and_port_returns_ip_port",
			input: npb.NetworkEndpoint_builder{
				IpAddress: npb.IpAddress_builder{Address: "127.0.0.1", AddressFamily: npb.AddressFamily_IPV4}.Build(),
				Port:      npb.Port_builder{PortNumber: 80}.Build(),
			}.Build(),
			want:    "127.0.0.1:80",
			wantErr: nil,
		},
		{
			name: "when_ipv6_ip_and_port_returns_bracketed_ip_port",
			input: npb.NetworkEndpoint_builder{
				IpAddress: npb.IpAddress_builder{Address: "3ffe::1", AddressFamily: npb.AddressFamily_IPV6}.Build(),
				Port:      npb.Port_builder{PortNumber: 80}.Build(),
			}.Build(),
			want:    "[3ffe::1]:80",
			wantErr: nil,
		},
		{
			name: "when_hostname_only_returns_hostname",
			input: npb.NetworkEndpoint_builder{
				Hostname: npb.Hostname_builder{Name: "example.com"}.Build(),
			}.Build(),
			want:    "example.com",
			wantErr: nil,
		},
		{
			name: "when_hostname_and_port_returns_hostname_port",
			input: npb.NetworkEndpoint_builder{
				Hostname: npb.Hostname_builder{Name: "example.com"}.Build(),
				Port:     npb.Port_builder{PortNumber: 80}.Build(),
			}.Build(),
			want:    "example.com:80",
			wantErr: nil,
		},
		{
			name: "when_ip_and_hostname_returns_prioritized_hostname",
			input: npb.NetworkEndpoint_builder{
				IpAddress: npb.IpAddress_builder{Address: "127.0.0.1", AddressFamily: npb.AddressFamily_IPV4}.Build(),
				Hostname:  npb.Hostname_builder{Name: "host.com"}.Build(),
			}.Build(),
			want:    "host.com",
			wantErr: nil,
		},
		{
			name: "when_ip_hostname_and_port_returns_prioritized_hostname_port",
			input: npb.NetworkEndpoint_builder{
				IpAddress: npb.IpAddress_builder{Address: "127.0.0.1", AddressFamily: npb.AddressFamily_IPV4}.Build(),
				Hostname:  npb.Hostname_builder{Name: "example.com"}.Build(),
				Port:      npb.Port_builder{PortNumber: 443}.Build(),
			}.Build(),
			want:    "example.com:443",
			wantErr: nil,
		},
		{
			name:    "when_no_ip_and_no_hostname_returns_error",
			input:   npb.NetworkEndpoint_builder{}.Build(),
			wantErr: ErrEndpointMissingAddress,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ToURIAuthority(tc.input)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("ToURIAuthority(%v) returned unexpected error: %v, want: %v", tc.input, err, tc.wantErr)
			}
			if tc.wantErr != nil {
				return
			}
			if got != tc.want {
				t.Errorf("ToURIAuthority(%v) = %q, want: %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestToURIAuthorities(t *testing.T) {
	tests := []struct {
		name    string
		input   *npb.NetworkEndpoint
		want    []string
		wantErr error
	}{
		{
			name: "when_ipv4_ip_only_returns_ip",
			input: npb.NetworkEndpoint_builder{
				IpAddress: npb.IpAddress_builder{Address: "127.0.0.1", AddressFamily: npb.AddressFamily_IPV4}.Build(),
			}.Build(),
			want:    []string{"127.0.0.1"},
			wantErr: nil,
		},
		{
			name: "when_ipv6_ip_only_returns_bracketed_ip",
			input: npb.NetworkEndpoint_builder{
				IpAddress: npb.IpAddress_builder{Address: "3ffe::1", AddressFamily: npb.AddressFamily_IPV6}.Build(),
			}.Build(),
			want:    []string{"[3ffe::1]"},
			wantErr: nil,
		},
		{
			name: "when_ipv4_ip_and_port_returns_ip_port",
			input: npb.NetworkEndpoint_builder{
				IpAddress: npb.IpAddress_builder{Address: "127.0.0.1", AddressFamily: npb.AddressFamily_IPV4}.Build(),
				Port:      npb.Port_builder{PortNumber: 80}.Build(),
			}.Build(),
			want:    []string{"127.0.0.1:80"},
			wantErr: nil,
		},
		{
			name: "when_ipv6_ip_and_port_returns_bracketed_ip_port",
			input: npb.NetworkEndpoint_builder{
				IpAddress: npb.IpAddress_builder{Address: "3ffe::1", AddressFamily: npb.AddressFamily_IPV6}.Build(),
				Port:      npb.Port_builder{PortNumber: 80}.Build(),
			}.Build(),
			want:    []string{"[3ffe::1]:80"},
			wantErr: nil,
		},
		{
			name: "when_hostname_only_returns_hostname",
			input: npb.NetworkEndpoint_builder{
				Hostname: npb.Hostname_builder{Name: "example.com"}.Build(),
			}.Build(),
			want:    []string{"example.com"},
			wantErr: nil,
		},
		{
			name: "when_hostname_and_port_returns_hostname_port",
			input: npb.NetworkEndpoint_builder{
				Hostname: npb.Hostname_builder{Name: "example.com"}.Build(),
				Port:     npb.Port_builder{PortNumber: 80}.Build(),
			}.Build(),
			want:    []string{"example.com:80"},
			wantErr: nil,
		},
		{
			name: "when_ip_and_hostname_returns_both",
			input: npb.NetworkEndpoint_builder{
				IpAddress: npb.IpAddress_builder{Address: "127.0.0.1", AddressFamily: npb.AddressFamily_IPV4}.Build(),
				Hostname:  npb.Hostname_builder{Name: "host.com"}.Build(),
			}.Build(),
			want:    []string{"host.com", "127.0.0.1"},
			wantErr: nil,
		},
		{
			name: "when_ip_hostname_and_port_returns_both_with_port",
			input: npb.NetworkEndpoint_builder{
				IpAddress: npb.IpAddress_builder{Address: "127.0.0.1", AddressFamily: npb.AddressFamily_IPV4}.Build(),
				Hostname:  npb.Hostname_builder{Name: "example.com"}.Build(),
				Port:      npb.Port_builder{PortNumber: 443}.Build(),
			}.Build(),
			want:    []string{"example.com:443", "127.0.0.1:443"},
			wantErr: nil,
		},
		{
			name:    "when_no_ip_and_no_hostname_returns_error",
			input:   npb.NetworkEndpoint_builder{}.Build(),
			wantErr: ErrEndpointMissingAddress,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ToURIAuthorities(tc.input)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("ToURIAuthorities(%v) returned unexpected error: %v, want: %v", tc.input, err, tc.wantErr)
			}
			if tc.wantErr != nil {
				return
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("ToURIAuthorities(%v) returned diff (-want +got):\n%s", tc.input, diff)
			}
		})
	}
}
