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
	"fmt"
	"strings"

	"github.com/google/goonami-scanner/core/net/iputils"

	npb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
)

// ToHost converts a NetworkEndpoint to a canonical host string without port.
// When both IP and hostname are present, it returns "<ip>_<hostname>".
// It returns ErrEndpointMissingAddress if neither IP nor hostname is present.
//
// Examples:
//
//   - IP: "127.0.0.1" -> "127.0.0.1" ;; "3ffe::1" -> "3ffe::1"
//   - IP_PORT: "127.0.0.1:80" -> "127.0.0.1" ;; "3ffe::1:80" -> "3ffe::1"
//   - IP_HOSTNAME_PORT: "127.0.0.1:example.com:443" -> "127.0.0.1_example.com"
//   - HOSTNAME_PORT: "example.com:80" -> "example.com"
//   - IP_HOSTNAME: "127.0.0.1:example.com" -> "127.0.0.1_example.com"
//   - HOSTNAME: "example.com" -> "example.com"
func ToHost(endpoint *npb.NetworkEndpoint) (string, error) {
	hasIP := endpoint.HasIpAddress()
	hasHostname := endpoint.HasHostname()

	switch {
	case hasIP && hasHostname:
		return fmt.Sprintf("%s_%s", endpoint.GetIpAddress().GetAddress(), endpoint.GetHostname().GetName()), nil
	case hasIP:
		return endpoint.GetIpAddress().GetAddress(), nil
	case hasHostname:
		return endpoint.GetHostname().GetName(), nil
	default:
		return "", ErrEndpointMissingAddress
	}
}

// SplitHost splits a canonical host string produced by ToHost into its
// component parts: [ip, hostname] for composite "<ip>_<hostname>" values, or
// [host] for single IP/hostname values. Hostnames containing underscores are
// preserved intact because IP addresses never contain "_". It returns nil when
// host is empty.
func SplitHost(host string) []string {
	if host == "" {
		return nil
	}
	if before, after, ok := strings.Cut(host, "_"); ok && iputils.IsIP(before) {
		if after == "" {
			return []string{before}
		}
		return []string{before, after}
	}
	return []string{host}
}
