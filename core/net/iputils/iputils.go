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
