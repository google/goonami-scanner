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

// Package netendpoint provides utility functions for working with the NetworkEndpoint proto.
package netendpoint

import (
	"errors"
	"fmt"

	"github.com/google/goonami-scanner/core/net/iputils"

	npb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
)

var (
	// ErrEndpointMissingAddress is returned when the network endpoint is missing both hostname and
	// IP address.
	ErrEndpointMissingAddress = errors.New("endpoint has neither a hostname nor an IP address")
)

// FromString creates a NetworkEndpoint from a string. Note that this function does not support
// inputs that contain a port. It assumes the endpoint is a hostname if it fails to be parsed as an
// IP address.
func FromString(endpoint string) *npb.NetworkEndpoint {
	endpointBuilder := &npb.NetworkEndpoint_builder{}

	if !iputils.IsIP(endpoint) {
		endpointBuilder.Type = npb.NetworkEndpoint_HOSTNAME
		endpointBuilder.Hostname = npb.Hostname_builder{
			Name: endpoint,
		}.Build()

		return endpointBuilder.Build()
	}

	endpointBuilder.Type = npb.NetworkEndpoint_IP
	address := npb.IpAddress_builder{
		Address:       endpoint,
		AddressFamily: npb.AddressFamily_IPV4,
	}

	if iputils.IsIPv6(endpoint) {
		address.AddressFamily = npb.AddressFamily_IPV6
	}

	endpointBuilder.IpAddress = address.Build()
	return endpointBuilder.Build()
}

// ToURIAuthority converts a NetworkEndpoint to a URI authority.
// Note that it prioritizes the hostname to allow virtual-host matching of HTTP servers to succeed.
//
// Examples:
//
//   - IP: "127.0.0.1" -> "127.0.0.1" ;; "3ffe::1" -> "[3ffe::1]"
//   - IP_PORT: "127.0.0.1:80" -> "127.0.0.1:80" ;; "3ffe::1:80" -> "[3ffe::1]:80"
//   - IP_HOSTNAME_PORT: "127.0.0.1:example.com:443" -> "example.com:443"
//   - HOSTNAME_PORT: "example.com:80" -> "example.com:80"
//   - IP_HOSTNAME: "127.0.0.1:example.com" -> "example.com"
//   - HOSTNAME: "example.com" -> "example.com"
func ToURIAuthority(endpoint *npb.NetworkEndpoint) (string, error) {
	if endpoint.HasHostname() {
		if endpoint.HasPort() {
			return fmt.Sprintf("%s:%d", endpoint.GetHostname().GetName(), endpoint.GetPort().GetPortNumber()), nil
		}

		return fmt.Sprintf("%s", endpoint.GetHostname().GetName()), nil
	}

	if !endpoint.HasIpAddress() {
		return "", ErrEndpointMissingAddress
	}

	address := endpoint.GetIpAddress().GetAddress()
	if endpoint.GetIpAddress().GetAddressFamily() == npb.AddressFamily_IPV6 {
		address = fmt.Sprintf("[%s]", address)
	}

	if endpoint.HasPort() {
		return fmt.Sprintf("%s:%d", address, endpoint.GetPort().GetPortNumber()), nil
	}

	return fmt.Sprintf("%s", address), nil
}
