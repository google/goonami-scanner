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

// Package iputils provides utility functions for working with IP addresses.
package iputils

import (
	"net"
	"net/netip"
)

// IsIP returns true if the input can be parsed as an IP address.
func IsIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

// IsIPv4 returns true if the given IP is an IPv4 address.
func IsIPv4(ip string) bool {
	if addr := net.ParseIP(ip); addr != nil {
		// Note: ParseIP always returns a 16-byte IP address. To check
		// whether it is an IPv4, we have to rely only on To4().
		return addr.To4() != nil
	}

	return false
}

// IsIPv6 returns true if the given IP is an IPv6 address.
func IsIPv6(ip string) bool {
	if addr := net.ParseIP(ip); addr != nil {
		// Note: ParseIP always returns a 16-byte IP address. To check
		// whether it is an IPv6, we have to rely only on To4().
		return addr.To4() == nil
	}

	return false
}

// IsCIDR returns true if the input can be parsed as a CIDR range.
func IsCIDR(cidr string) bool {
	_, err := netip.ParsePrefix(cidr)
	return err == nil
}

// IsIPv4CIDR returns true if the given input is an IPv4 CIDR range.
func IsIPv4CIDR(cidr string) bool {
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return false
	}

	return p.Addr().Is4()
}

// IsIPv6CIDR returns true if the given input is an IPv6 CIDR range.
func IsIPv6CIDR(cidr string) bool {
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return false
	}

	return p.Addr().Is6()
}

// ExpandCIDR expands a CIDR range into a slice of all IP addresses in the range.
func ExpandCIDR(cidr string) ([]string, error) {
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, err
	}

	p = p.Masked()
	var ips []string
	for addr := p.Addr(); p.Contains(addr); addr = addr.Next() {
		ips = append(ips, addr.String())
	}

	return ips, nil
}
