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

package iputils

import (
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestIsCIDR(t *testing.T) {
	tests := []struct {
		name string
		cidr string
		want bool
	}{
		{name: "when_ipv4_cidr_returns_true", cidr: "192.168.1.0/24", want: true},
		{name: "when_ipv6_cidr_returns_true", cidr: "2001:db8::/126", want: true},
		{name: "when_single_ip_returns_false", cidr: "192.168.1.1", want: false},
		{name: "when_hostname_returns_false", cidr: "example.com", want: false},
		{name: "when_invalid_mask_returns_false", cidr: "192.168.1.0/33", want: false},
		{name: "when_empty_returns_false", cidr: "", want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := IsCIDR(tc.cidr)
			if got != tc.want {
				t.Errorf("IsCIDR(%q) = %v, want %v", tc.cidr, got, tc.want)
			}
		})
	}
}

func TestIsIPv4CIDR(t *testing.T) {
	tests := []struct {
		name string
		cidr string
		want bool
	}{
		{name: "when_ipv4_cidr_returns_true", cidr: "192.168.1.0/24", want: true},
		{name: "when_ipv6_cidr_returns_false", cidr: "2001:db8::/126", want: false},
		{name: "when_single_ipv4_returns_false", cidr: "192.168.1.1", want: false},
		{name: "when_empty_returns_false", cidr: "", want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := IsIPv4CIDR(tc.cidr)
			if got != tc.want {
				t.Errorf("IsIPv4CIDR(%q) = %v, want %v", tc.cidr, got, tc.want)
			}
		})
	}
}

func TestIsIPv6CIDR(t *testing.T) {
	tests := []struct {
		name string
		cidr string
		want bool
	}{
		{name: "when_ipv4_cidr_returns_false", cidr: "192.168.1.0/24", want: false},
		{name: "when_ipv6_cidr_returns_true", cidr: "2001:db8::/126", want: true},
		{name: "when_single_ipv6_returns_false", cidr: "2001:db8::1", want: false},
		{name: "when_empty_returns_false", cidr: "", want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := IsIPv6CIDR(tc.cidr)
			if got != tc.want {
				t.Errorf("IsIPv6CIDR(%q) = %v, want %v", tc.cidr, got, tc.want)
			}
		})
	}
}

func TestExpandCIDR(t *testing.T) {
	tests := []struct {
		name    string
		cidr    string
		want    []string
		wantErr error
	}{
		{
			name: "when_ipv4_slash_30_returns_four_ips",
			cidr: "192.168.1.0/30",
			want: []string{"192.168.1.0", "192.168.1.1", "192.168.1.2", "192.168.1.3"},
		},
		{
			name: "when_ipv4_unmasked_slash_31_returns_masked_ips",
			cidr: "10.0.0.5/31",
			want: []string{"10.0.0.4", "10.0.0.5"},
		},
		{
			name: "when_ipv6_slash_126_returns_four_ips",
			cidr: "2001:db8::/126",
			want: []string{"2001:db8::", "2001:db8::1", "2001:db8::2", "2001:db8::3"},
		},
		{
			name:    "when_ipv4_slash_8_too_large_returns_error",
			cidr:    "10.0.0.0/8",
			wantErr: ErrCIDRTooLarge,
		},
		{
			name:    "when_ipv6_slash_64_too_large_returns_error",
			cidr:    "2001:db8::/64",
			wantErr: ErrCIDRTooLarge,
		},
		{
			name:    "when_invalid_cidr_returns_error",
			cidr:    "invalid",
			wantErr: ErrInvalidCIDR,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ExpandCIDR(tc.cidr)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("ExpandCIDR(%q) error = %v, want %v", tc.cidr, err, tc.wantErr)
			}
			if tc.wantErr != nil {
				return
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("ExpandCIDR(%q) diff (-want +got):\n%s", tc.cidr, diff)
			}
		})
	}
}

func TestCountCIDR(t *testing.T) {
	tests := []struct {
		name    string
		cidr    string
		want    int
		wantErr error
	}{
		{
			name: "when_ipv4_slash_24_returns_256",
			cidr: "192.168.1.0/24",
			want: 256,
		},
		{
			name: "when_ipv4_slash_32_returns_1",
			cidr: "192.168.1.1/32",
			want: 1,
		},
		{
			name: "when_ipv6_slash_126_returns_4",
			cidr: "2001:db8::/126",
			want: 4,
		},
		{
			name:    "when_ipv6_slash_64_too_large_returns_error",
			cidr:    "2001:db8::/64",
			wantErr: ErrCIDRTooLarge,
		},
		{
			name:    "when_invalid_cidr_returns_error",
			cidr:    "invalid",
			wantErr: ErrInvalidCIDR,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := CountCIDR(tc.cidr)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("CountCIDR(%q) error = %v, want %v", tc.cidr, err, tc.wantErr)
			}
			if tc.wantErr != nil {
				return
			}
			if got != tc.want {
				t.Errorf("CountCIDR(%q) = %d, want %d", tc.cidr, got, tc.want)
			}
		})
	}
}
