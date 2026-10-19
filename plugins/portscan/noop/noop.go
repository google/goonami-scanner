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

// Package noop provides a port scanner ("ps/noop") that reports all configured
// ports as open without sending network probes. This is useful when open ports
// have already been discovered externally and passed via
// globalcfg.ports_to_scan.
package noop

import (
	"context"
	"errors"

	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/module"
	"github.com/google/goonami-scanner/core/net/netendpoint"

	npb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
	rpb "github.com/google/tsunami-security-scanner/proto/go/reconnaissance_go_proto"
)

const moduleName = "ps/noop"

// ErrNoPortsToScan is returned when globalcfg.ports_to_scan is empty.
// Requiring an explicit port list prevents treating all 65,535 ports as open.
var ErrNoPortsToScan = errors.New("noop port scanner requires ports_to_scan to be configured")

func init() {
	module.RegisterPortScanner(moduleName, New)
}

// Module implements the module.PortScanner interface for ps/noop.
type Module struct {
	*module.BaseModule
	portsToScan []uint32
}

// New returns a new ps/noop port scanner configured with globalcfg.ports_to_scan.
// It returns ErrNoPortsToScan if no ports are configured.
func New(ctx context.Context, config *config.Config) (module.PortScanner, error) {
	portsToScan := config.GlobalConfig().GetPortsToScan()
	if len(portsToScan) == 0 {
		return nil, ErrNoPortsToScan
	}

	return &Module{
		BaseModule:  module.NewBaseModule(moduleName),
		portsToScan: portsToScan,
	}, nil
}

// Scan constructs a PortScanningReport marking every configured port as open on
// target without performing any network I/O.
func (m *Module) Scan(ctx context.Context, target string) (*rpb.PortScanningReport, error) {
	endpoint := netendpoint.FromString(target)
	portType := npb.NetworkEndpoint_IP_PORT
	if endpoint.GetType() == npb.NetworkEndpoint_HOSTNAME {
		portType = npb.NetworkEndpoint_HOSTNAME_PORT
	}

	services := make([]*nspb.NetworkService, 0, len(m.portsToScan))
	for _, port := range m.portsToScan {
		services = append(services, nspb.NetworkService_builder{
			NetworkEndpoint: npb.NetworkEndpoint_builder{
				Type:      portType,
				IpAddress: endpoint.GetIpAddress(),
				Hostname:  endpoint.GetHostname(),
				Port: npb.Port_builder{
					PortNumber: port,
				}.Build(),
			}.Build(),
		}.Build())
	}

	return rpb.PortScanningReport_builder{
		TargetInfo: rpb.TargetInfo_builder{
			NetworkEndpoints: []*npb.NetworkEndpoint{endpoint},
		}.Build(),
		NetworkServices: services,
	}.Build(), nil
}
