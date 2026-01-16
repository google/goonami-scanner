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
	"testing"
)

func TestIsIP(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		want bool
	}{
		{name: "ipv4_loopback_is_ip", ip: "127.0.0.1", want: true},
		{name: "ipv4_private_is_ip", ip: "192.168.1.1", want: true},
		{name: "ipv6_loopback_is_ip", ip: "::1", want: true},
		{name: "ipv6_public_is_ip", ip: "2001:db8::68", want: true},
		{name: "hostname_is_not_ip", ip: "hostname", want: false},
		{name: "empty_is_not_ip", ip: "", want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := IsIP(tc.ip)
			if got != tc.want {
				t.Errorf("IsIP(%q) = %v, want %v", tc.ip, got, tc.want)
			}
		})
	}
}

func TestIsIPv4(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		want bool
	}{
		{name: "ipv4_loopback_is_ipv4", ip: "127.0.0.1", want: true},
		{name: "ipv4_private_is_ipv4", ip: "192.168.1.1", want: true},
		{name: "ipv6_loopback_is_not_ipv4", ip: "::1", want: false},
		{name: "ipv6_public_is_not_ipv4", ip: "2001:db8::68", want: false},
		{name: "hostname_is_not_ipv4", ip: "hostname", want: false},
		{name: "empty_is_not_ipv4", ip: "", want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := IsIPv4(tc.ip)
			if got != tc.want {
				t.Errorf("IsIPv4(%q) = %v, want %v", tc.ip, got, tc.want)
			}
		})
	}
}

func TestIsIPv6(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		want bool
	}{
		{name: "ipv4_loopback_is_not_ipv6", ip: "127.0.0.1", want: false},
		{name: "ipv4_private_is_not_ipv6", ip: "192.168.1.1", want: false},
		{name: "ipv6_loopback_is_ipv6", ip: "::1", want: true},
		{name: "ipv6_public_is_ipv6", ip: "2001:db8::68", want: true},
		{name: "hostname_is_not_ipv6", ip: "hostname", want: false},
		{name: "empty_is_not_ipv6", ip: "", want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := IsIPv6(tc.ip)
			if got != tc.want {
				t.Errorf("IsIPv6(%q) = %v, want %v", tc.ip, got, tc.want)
			}
		})
	}
}
