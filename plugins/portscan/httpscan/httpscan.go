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

// Package httpscan provides port scanning using only HTTP as a protocol.
// This can prove useful to perform port scanning through HTTP proxies for example.
package httpscan

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"sync"

	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/log"
	"github.com/google/goonami-scanner/core/module"
	goohttp "github.com/google/goonami-scanner/core/net/http"
	"github.com/google/goonami-scanner/core/net/netendpoint"
	"github.com/google/goonami-scanner/core/net/netservice"
	"golang.org/x/sync/errgroup"

	hcpb "github.com/google/goonami-scanner/plugins/portscan/httpscan/httpscan_portscan_config_go_proto"
	npb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
	rpb "github.com/google/tsunami-security-scanner/proto/go/reconnaissance_go_proto"
)

const (
	moduleName = "ps/httpscan"
)

func init() {
	module.RegisterPortScanner(moduleName, New)
}

// DefaultConfig for the module.
// By default, the module considers 400 and 502 as indicating a closed port. It is generally
// recommended not to use the default configuration.
func DefaultConfig() *hcpb.HttpScanPluginConfig {
	return hcpb.HttpScanPluginConfig_builder{
		InvalidExitCodes: []int32{400, 502},
	}.Build()
}

// Module implements the portscan.Module interface for httpscan.
type Module struct {
	*module.BaseModule
	config      *hcpb.HttpScanPluginConfig
	coreConfig  *config.Config
	portsToScan []uint32
}

// New creates a new httpscan module.
func New(ctx context.Context, config *config.Config) (module.PortScanner, error) {
	portsToScan := config.GlobalConfig().GetPortsToScan()

	if len(config.GlobalConfig().GetPortsToScan()) == 0 {
		for i := 1; i <= 65535; i++ {
			portsToScan = append(portsToScan, uint32(i))
		}
	}

	var localConfig *hcpb.HttpScanPluginConfig
	if config.PluginsConfig().HasHttpscan() {
		localConfig = config.PluginsConfig().GetHttpscan()
	} else {
		log.WarnContextf(ctx, "no HTTP scan plugin config found, using default configuration")
		localConfig = DefaultConfig()
	}

	return &Module{
		BaseModule:  module.NewBaseModule(moduleName),
		config:      localConfig,
		coreConfig:  config,
		portsToScan: portsToScan,
	}, nil
}

// Scan performs the port scan.
func (m *Module) Scan(ctx context.Context, target string) (*rpb.PortScanningReport, error) {
	endpoint := netendpoint.FromString(target)
	report := &rpb.PortScanningReport_builder{
		TargetInfo: rpb.TargetInfo_builder{
			NetworkEndpoints: []*npb.NetworkEndpoint{endpoint},
		}.Build(),
	}

	var mut sync.Mutex
	group, grpctx := errgroup.WithContext(ctx)
	group.SetLimit(int(m.coreConfig.GlobalConfig().GetPerformance().GetMaxConcurrency()))

	for _, port := range m.portsToScan {
		if grpctx.Err() != nil {
			return nil, grpctx.Err()
		}

		group.Go(func() error {
			service, err := m.scanPortWorker(grpctx, endpoint, port)
			if err != nil {
				return err
			}

			if service == nil {
				return nil
			}

			mut.Lock()
			defer mut.Unlock()
			report.NetworkServices = append(report.NetworkServices, service)
			return nil
		})
	}

	if err := group.Wait(); err != nil {
		return nil, err
	}

	return report.Build(), nil
}

func (m *Module) scanPortWorker(ctx context.Context, endpoint *npb.NetworkEndpoint, port uint32) (*nspb.NetworkService, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	service := &nspb.NetworkService_builder{
		NetworkEndpoint: npb.NetworkEndpoint_builder{
			Type:      endpoint.GetType(),
			IpAddress: endpoint.GetIpAddress(),
			Hostname:  endpoint.GetHostname(),
			Port: npb.Port_builder{
				PortNumber: port,
			}.Build(),
		}.Build(),
	}

	switch endpoint.GetType() {
	case npb.NetworkEndpoint_IP:
		service.NetworkEndpoint.SetType(npb.NetworkEndpoint_IP_PORT)
	case npb.NetworkEndpoint_HOSTNAME:
		service.NetworkEndpoint.SetType(npb.NetworkEndpoint_HOSTNAME_PORT)
	case npb.NetworkEndpoint_IP_HOSTNAME:
		service.NetworkEndpoint.SetType(npb.NetworkEndpoint_IP_HOSTNAME_PORT)
	default:
		return nil, fmt.Errorf("invalid network endpoint type: %s", endpoint.GetType().String())
	}

	return m.scanPort(ctx, service)
}

func (m *Module) scanPort(ctx context.Context, service *nspb.NetworkService_builder) (*nspb.NetworkService, error) {
	ctx, cancel := context.WithTimeout(ctx, m.coreConfig.TimeoutPerRequest())
	defer cancel()

	webroot, err := netservice.BuildWebRoot(service.Build())
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "GET", webroot, nil)
	if err != nil {
		return nil, err
	}

	// If the request failed, the port is likely closed
	resp, err := goohttp.SharedClient(m.coreConfig).Do(req)
	if err != nil {
		log.DebugContextf(ctx, log.DebugLevelService, "port:%d error decision:closed: %v", service.NetworkEndpoint.GetPort().GetPortNumber(), err)
		return nil, nil
	}
	defer resp.Body.Close()

	if slices.Contains(m.config.GetInvalidExitCodes(), int32(resp.StatusCode)) {
		log.DebugContextf(ctx, log.DebugLevelService, "port:%d status:%d decision:closed", service.NetworkEndpoint.GetPort().GetPortNumber(), resp.StatusCode)
		return nil, nil
	}

	log.DebugContextf(ctx, log.DebugLevelService, "port:%d status:%d decision:open", service.NetworkEndpoint.GetPort().GetPortNumber(), resp.StatusCode)
	service.SupportedHttpMethods = []string{"GET"}
	return service.Build(), nil
}
