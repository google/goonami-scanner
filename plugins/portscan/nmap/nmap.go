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

// Package nmap provides a port scanner that uses nmap.
package nmap

import (
	"context"
	"errors"

	"github.com/google/goonami-scanner/common/clients/nmap"
	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/log"
	"github.com/google/goonami-scanner/core/module"

	npb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
	rpb "github.com/google/tsunami-security-scanner/proto/go/reconnaissance_go_proto"
	spb "github.com/google/tsunami-security-scanner/proto/go/software_go_proto"
)

const (
	moduleName = "portscan/nmap"
)

var (
	// ErrNoOutput is returned when the nmap output is nil.
	ErrNoOutput = errors.New("nmap output is nil")

	// ErrInvalidHostsCount is returned when the number of hosts in the nmap output is not 1.
	ErrInvalidHostsCount = errors.New("invalid number of hosts in nmap output")

	// ErrInvalidAddressType is returned when the address type in the nmap output is invalid.
	ErrInvalidAddressType = errors.New("invalid address type in nmap output")

	// ErrNoAddressOrHostname is returned when there are no addresses or hostnames in the nmap output.
	ErrNoAddressOrHostname = errors.New("expected at least one address or hostname in nmap output")
)

type nmapClient interface {
	Run(ctx context.Context, target string) (*nmap.OutputXML, error)
}

// Module implements the portscan.Module interface for nmap.
type Module struct {
	*module.BaseModule
	config *config.Config
	client nmapClient
}

// New creates a new nmap module.
func New(ctx context.Context, config *config.Config) (module.PortScanner, error) {
	return &Module{
		BaseModule: module.NewBaseModule(moduleName),
		config:     config,
		client:     nmap.New(config),
	}, nil
}

// Scan performs a port scan using nmap.
func (m *Module) Scan(ctx context.Context, target string) (*rpb.PortScanningReport, error) {
	results, err := m.client.Run(ctx, target)
	if err != nil {
		return nil, err
	}

	return processResults(ctx, results)
}

func processResults(ctx context.Context, results *nmap.OutputXML) (*rpb.PortScanningReport, error) {
	if results == nil {
		return nil, ErrNoOutput
	}

	// The client currently only supports a single target.
	if len(results.Hosts) != 1 {
		return nil, ErrInvalidHostsCount
	}

	host := results.Hosts[0]
	if host.Status.State != "up" {
		return nil, nil
	}

	endpoint, err := parseNetworkEndpoint(&host)
	if err != nil {
		return nil, err
	}

	result := &rpb.PortScanningReport_builder{
		TargetInfo: rpb.TargetInfo_builder{
			NetworkEndpoints: []*npb.NetworkEndpoint{endpoint},
		}.Build(),
	}

	for _, port := range host.Ports.Ports {
		if port.State.State != "open" {
			continue
		}

		service, err := parseService(ctx, endpoint, &port)
		if err != nil {
			return nil, err
		}

		if service == nil {
			continue
		}

		result.NetworkServices = append(result.NetworkServices, service)
	}

	return result.Build(), nil
}

func parseNetworkEndpoint(host *nmap.Host) (*npb.NetworkEndpoint, error) {
	endpointBuilder := &npb.NetworkEndpoint_builder{}

	if len(host.Hostnames.Hostnames) > 0 && len(host.Addresses) > 0 {
		endpointBuilder.Type = npb.NetworkEndpoint_IP_HOSTNAME
	} else if len(host.Hostnames.Hostnames) > 0 {
		endpointBuilder.Type = npb.NetworkEndpoint_HOSTNAME
	} else if len(host.Addresses) > 0 {
		endpointBuilder.Type = npb.NetworkEndpoint_IP
	} else {
		return nil, ErrNoAddressOrHostname
	}

	if len(host.Addresses) > 0 {
		addr := npb.IpAddress_builder{
			Address: host.Addresses[0].Addr,
		}

		switch host.Addresses[0].AddrType {
		case "ipv4":
			addr.AddressFamily = npb.AddressFamily_IPV4
		case "ipv6":
			addr.AddressFamily = npb.AddressFamily_IPV6
		default:
			return nil, ErrInvalidAddressType
		}

		endpointBuilder.IpAddress = addr.Build()
	}

	if len(host.Hostnames.Hostnames) > 0 {
		endpointBuilder.Hostname = npb.Hostname_builder{
			Name: host.Hostnames.Hostnames[0].Name,
		}.Build()
	}

	return endpointBuilder.Build(), nil
}

func parseService(ctx context.Context, endpoint *npb.NetworkEndpoint, port *nmap.Port) (*nspb.NetworkService, error) {
	portEndpoint := &npb.NetworkEndpoint_builder{
		IpAddress: endpoint.GetIpAddress(),
		Hostname:  endpoint.GetHostname(),
		Port: npb.Port_builder{
			PortNumber: uint32(port.PortID),
		}.Build(),
	}

	// Note: The endpoint is built in parseNetworkEndpoint() and we have only a limited set of
	// possible types.
	switch endpoint.GetType() {
	case npb.NetworkEndpoint_IP:
		portEndpoint.Type = npb.NetworkEndpoint_IP_PORT
	case npb.NetworkEndpoint_HOSTNAME:
		portEndpoint.Type = npb.NetworkEndpoint_HOSTNAME_PORT
	case npb.NetworkEndpoint_IP_HOSTNAME:
		portEndpoint.Type = npb.NetworkEndpoint_IP_HOSTNAME_PORT
	}

	service := &nspb.NetworkService_builder{
		NetworkEndpoint: portEndpoint.Build(),
		ServiceName:     "unknown",
	}

	switch port.Protocol {
	case "tcp":
		service.TransportProtocol = npb.TransportProtocol_TCP
	case "udp":
		service.TransportProtocol = npb.TransportProtocol_UDP
	case "sctp":
		service.TransportProtocol = npb.TransportProtocol_SCTP
	default:
		log.WarnContextf(ctx, "skipping unknown protocol in nmap output: %s", port.Protocol)
		return nil, nil
	}

	if port.Service == nil {
		return service.Build(), nil
	}

	service.ServiceName = port.Service.Name
	service.Cpes = append(service.Cpes, port.Service.CPE...)

	if port.Service.Product != "" {
		service.Software = spb.Software_builder{
			Name: port.Service.Product,
		}.Build()
	}

	if port.Service.Version != "" {
		service.VersionSet = spb.VersionSet_builder{
			Versions: []*spb.Version{
				spb.Version_builder{
					Type:              spb.Version_NORMAL,
					FullVersionString: port.Service.Version,
				}.Build(),
			},
		}.Build()
	}

	for _, script := range port.Scripts {
		if err := parseScripts(ctx, &script, service); err != nil {
			return nil, err
		}
	}

	return service.Build(), nil
}

func parseScripts(ctx context.Context, script *nmap.Script, service *nspb.NetworkService_builder) error {
	switch script.ID {
	case "http-methods":
		return parseScriptHTTPMethods(script, service)
	case "ssl-enum-ciphers":
		return parseScriptSSLCiphers(script, service)
	// silently ignored
	case "http-server-headers", "ssl-cert", "fingerprint-strings":
		return nil
	default:
		log.WarnContextf(ctx, "ignoring unsupported script: %s", script.ID)
		return nil
	}
}

// parseScriptHTTPMethods parses the `http-methods` script output.
func parseScriptHTTPMethods(script *nmap.Script, service *nspb.NetworkService_builder) error {
	for _, table := range script.Tables {
		if table.Key == "Supported Methods" {
			for _, elem := range table.Elems {
				service.SupportedHttpMethods = append(service.SupportedHttpMethods, elem.Value)
			}
		}
	}

	return nil
}

// parseScriptSSLCiphers parses the `ssl-enum-ciphers` script output.
func parseScriptSSLCiphers(script *nmap.Script, service *nspb.NetworkService_builder) error {
	for _, table := range script.Tables {
		service.SupportedSslVersions = append(service.SupportedSslVersions, table.Key)
	}

	return nil
}
