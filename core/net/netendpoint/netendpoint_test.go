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
	"github.com/google/goonami-scanner/core/net/iputils"
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

func TestFromTarget(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		want    []*npb.NetworkEndpoint
		wantErr error
	}{
		{
			name:   "when_target_is_ipv4_returns_single_ip_endpoint",
			target: "127.0.0.1",
			want:   []*npb.NetworkEndpoint{FromString("127.0.0.1")},
		},
		{
			name:   "when_target_is_ipv6_returns_single_ipv6_endpoint",
			target: "::1",
			want:   []*npb.NetworkEndpoint{FromString("::1")},
		},
		{
			name:   "when_target_is_hostname_returns_single_hostname_endpoint",
			target: "example.com",
			want:   []*npb.NetworkEndpoint{FromString("example.com")},
		},
		{
			name:   "when_target_is_ipv4_cidr_expands_endpoints",
			target: "192.168.1.0/30",
			want: []*npb.NetworkEndpoint{
				FromString("192.168.1.0"),
				FromString("192.168.1.1"),
				FromString("192.168.1.2"),
				FromString("192.168.1.3"),
			},
		},
		{
			name:   "when_target_is_ipv6_cidr_expands_endpoints",
			target: "2001:db8::/126",
			want: []*npb.NetworkEndpoint{
				FromString("2001:db8::"),
				FromString("2001:db8::1"),
				FromString("2001:db8::2"),
				FromString("2001:db8::3"),
			},
		},
		{
			name:    "when_target_is_cidr_too_large_returns_error",
			target:  "2001:db8::/64",
			wantErr: iputils.ErrCIDRTooLarge,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := FromTarget(tc.target)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("FromTarget(%q) error = %v, want %v", tc.target, err, tc.wantErr)
			}
			if tc.wantErr != nil {
				return
			}
			if diff := cmp.Diff(tc.want, got, protocmp.Transform()); diff != "" {
				t.Errorf("FromTarget(%q) diff (-want +got):\n%s", tc.target, diff)
			}
		})
	}
}

func TestWithPort(t *testing.T) {
	tests := []struct {
		name     string
		endpoint *npb.NetworkEndpoint
		port     uint32
		want     *npb.NetworkEndpoint
		wantErr  error
	}{
		{
			name:     "when_endpoint_is_ip_promotes_to_ip_port",
			endpoint: FromString("127.0.0.1"),
			port:     80,
			want: npb.NetworkEndpoint_builder{
				Type:      npb.NetworkEndpoint_IP_PORT,
				IpAddress: npb.IpAddress_builder{Address: "127.0.0.1", AddressFamily: npb.AddressFamily_IPV4}.Build(),
				Port:      npb.Port_builder{PortNumber: 80}.Build(),
			}.Build(),
		},
		{
			name:     "when_endpoint_is_hostname_promotes_to_hostname_port",
			endpoint: FromString("example.com"),
			port:     8080,
			want: npb.NetworkEndpoint_builder{
				Type:     npb.NetworkEndpoint_HOSTNAME_PORT,
				Hostname: npb.Hostname_builder{Name: "example.com"}.Build(),
				Port:     npb.Port_builder{PortNumber: 8080}.Build(),
			}.Build(),
		},
		{
			name: "when_endpoint_is_ip_hostname_promotes_to_ip_hostname_port",
			endpoint: npb.NetworkEndpoint_builder{
				Type:      npb.NetworkEndpoint_IP_HOSTNAME,
				IpAddress: npb.IpAddress_builder{Address: "127.0.0.1", AddressFamily: npb.AddressFamily_IPV4}.Build(),
				Hostname:  npb.Hostname_builder{Name: "example.com"}.Build(),
			}.Build(),
			port: 443,
			want: npb.NetworkEndpoint_builder{
				Type:      npb.NetworkEndpoint_IP_HOSTNAME_PORT,
				IpAddress: npb.IpAddress_builder{Address: "127.0.0.1", AddressFamily: npb.AddressFamily_IPV4}.Build(),
				Hostname:  npb.Hostname_builder{Name: "example.com"}.Build(),
				Port:      npb.Port_builder{PortNumber: 443}.Build(),
			}.Build(),
		},
		{
			name:     "when_endpoint_type_is_unspecified_returns_error",
			endpoint: &npb.NetworkEndpoint{},
			port:     80,
			wantErr:  ErrInvalidEndpointType,
		},
		{
			name: "when_endpoint_already_has_port_type_returns_error",
			endpoint: npb.NetworkEndpoint_builder{
				Type:      npb.NetworkEndpoint_IP_PORT,
				IpAddress: npb.IpAddress_builder{Address: "127.0.0.1", AddressFamily: npb.AddressFamily_IPV4}.Build(),
				Port:      npb.Port_builder{PortNumber: 80}.Build(),
			}.Build(),
			port:    443,
			wantErr: ErrInvalidEndpointType,
		},
		{
			name:    "when_endpoint_is_nil_returns_error",
			port:    80,
			wantErr: ErrInvalidEndpointType,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := WithPort(tc.endpoint, tc.port)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("WithPort(%v, %d) error = %v, want %v", tc.endpoint, tc.port, err, tc.wantErr)
			}
			if tc.wantErr != nil {
				return
			}
			if diff := cmp.Diff(tc.want, got, protocmp.Transform()); diff != "" {
				t.Errorf("WithPort(%v, %d) diff (-want +got):\n%s", tc.endpoint, tc.port, diff)
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
