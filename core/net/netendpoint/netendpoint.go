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

	// ErrInvalidEndpointType is returned when an endpoint's type cannot be promoted to a port
	// endpoint type.
	ErrInvalidEndpointType = errors.New("invalid network endpoint type")
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

// FromTarget converts a scan target (a CIDR range, IP address, or hostname) into one or more
// NetworkEndpoints without ports. Non-CIDR inputs are converted as a single endpoint via
// FromString; oversized CIDR ranges return an error wrapping iputils.ErrCIDRTooLarge.
func FromTarget(target string) ([]*npb.NetworkEndpoint, error) {
	ips, err := iputils.ExpandCIDR(target)
	if err != nil {
		if errors.Is(err, iputils.ErrInvalidCIDR) {
			return []*npb.NetworkEndpoint{FromString(target)}, nil
		}
		return nil, err
	}

	endpoints := make([]*npb.NetworkEndpoint, 0, len(ips))
	for _, ip := range ips {
		endpoints = append(endpoints, FromString(ip))
	}
	return endpoints, nil
}

// WithPort returns a copy of endpoint with port attached and its endpoint type promoted to the
// corresponding *_PORT variant (IP_PORT, HOSTNAME_PORT, or IP_HOSTNAME_PORT). It returns
// ErrInvalidEndpointType if endpoint does not have type IP, HOSTNAME, or IP_HOSTNAME.
func WithPort(endpoint *npb.NetworkEndpoint, port uint32) (*npb.NetworkEndpoint, error) {
	var portType npb.NetworkEndpoint_Type
	switch endpoint.GetType() {
	case npb.NetworkEndpoint_IP:
		portType = npb.NetworkEndpoint_IP_PORT
	case npb.NetworkEndpoint_HOSTNAME:
		portType = npb.NetworkEndpoint_HOSTNAME_PORT
	case npb.NetworkEndpoint_IP_HOSTNAME:
		portType = npb.NetworkEndpoint_IP_HOSTNAME_PORT
	default:
		return nil, fmt.Errorf("%w: %s", ErrInvalidEndpointType, endpoint.GetType())
	}

	return npb.NetworkEndpoint_builder{
		Type:      portType,
		IpAddress: endpoint.GetIpAddress(),
		Hostname:  endpoint.GetHostname(),
		Port: npb.Port_builder{
			PortNumber: port,
		}.Build(),
	}.Build(), nil
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
	authorities, err := ToURIAuthorities(endpoint)
	if err != nil {
		return "", err
	}

	return authorities[0], nil
}

// ToURIAuthorities converts a NetworkEndpoint to all available URI authorities.
// It returns both the hostname-based and IP-based authorities if both are present in the endpoint.
// It puts the hostname-based authorities first in the list.
// If no authorities are available, it returns an error.
func ToURIAuthorities(endpoint *npb.NetworkEndpoint) ([]string, error) {
	var authorities []string

	if endpoint.HasHostname() {
		if endpoint.HasPort() {
			authorities = append(authorities, fmt.Sprintf("%s:%d", endpoint.GetHostname().GetName(), endpoint.GetPort().GetPortNumber()))
		} else {
			authorities = append(authorities, fmt.Sprintf("%s", endpoint.GetHostname().GetName()))
		}
	}

	if endpoint.HasIpAddress() {
		address := endpoint.GetIpAddress().GetAddress()
		if endpoint.GetIpAddress().GetAddressFamily() == npb.AddressFamily_IPV6 {
			address = fmt.Sprintf("[%s]", address)
		}

		if endpoint.HasPort() {
			authorities = append(authorities, fmt.Sprintf("%s:%d", address, endpoint.GetPort().GetPortNumber()))
		} else {
			authorities = append(authorities, fmt.Sprintf("%s", address))
		}
	}

	if len(authorities) == 0 {
		return nil, ErrEndpointMissingAddress
	}

	return authorities, nil
}
