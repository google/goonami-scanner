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
	"fmt"
	"net/netip"
)

const (
	// maxExpandHostBits caps in-memory CIDR expansion at 2^20 (1,048,576) addresses.
	maxExpandHostBits = 20

	// maxCountHostBits caps CIDR address counting so 1 << hostBits fits in a positive 64-bit int.
	maxCountHostBits = 61
)

var (
	// ErrInvalidCIDR is returned when the input cannot be parsed as a CIDR range.
	ErrInvalidCIDR = errors.New("invalid CIDR range")

	// ErrCIDRTooLarge is returned when the CIDR range exceeds the supported size bound.
	ErrCIDRTooLarge = errors.New("CIDR range is too large")
)

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
// It returns ErrInvalidCIDR if cidr cannot be parsed, or ErrCIDRTooLarge if the
// prefix exceeds 20 host bits (1,048,576 addresses).
func ExpandCIDR(cidr string) ([]string, error) {
	p, hostBits, err := parseBoundedPrefix(cidr, maxExpandHostBits)
	if err != nil {
		return nil, err
	}

	p = p.Masked()
	ips := make([]string, 0, 1<<hostBits)
	for addr := p.Addr(); p.Contains(addr); addr = addr.Next() {
		ips = append(ips, addr.String())
	}

	return ips, nil
}

// CountCIDR returns the number of IP addresses in a CIDR range without expanding it.
// It returns ErrInvalidCIDR if cidr cannot be parsed, or ErrCIDRTooLarge if the
// address count exceeds a bounded 64-bit integer.
func CountCIDR(cidr string) (int, error) {
	_, hostBits, err := parseBoundedPrefix(cidr, maxCountHostBits)
	if err != nil {
		return 0, err
	}

	return 1 << hostBits, nil
}

func parseBoundedPrefix(cidr string, maxHostBits int) (netip.Prefix, int, error) {
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return netip.Prefix{}, 0, fmt.Errorf("%w: %v", ErrInvalidCIDR, err)
	}

	hostBits := p.Addr().BitLen() - p.Bits()
	if hostBits > maxHostBits {
		return netip.Prefix{}, 0, fmt.Errorf("%w: %q", ErrCIDRTooLarge, cidr)
	}

	return p, hostBits, nil
}
