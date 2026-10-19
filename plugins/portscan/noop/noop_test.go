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

// Package noop provides unit tests for the noop portscan plugin.
package noop

import (
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/module"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"

	cpb "github.com/google/goonami-scanner/core/config/config_go_proto"
	npb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
	rpb "github.com/google/tsunami-security-scanner/proto/go/reconnaissance_go_proto"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		ports   []uint32
		wantErr error
	}{
		{
			name:  "when_ports_are_configured_registers_and_returns_module",
			ports: []uint32{80, 443},
		},
		{
			name:    "when_no_ports_are_configured_returns_error",
			wantErr: ErrNoPortsToScan,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfgProto := cpb.Config_builder{
				Workflowcfg: cpb.WorkflowConfiguration_builder{
					Portscan: proto.String(moduleName),
				}.Build(),
				Globalcfg: cpb.GlobalConfig_builder{
					PortsToScan: tc.ports,
				}.Build(),
			}.Build()

			m, err := module.GetPortScanner(t.Context(), config.FromProto(cfgProto))
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("GetPortScanner() error = %v, want %v", err, tc.wantErr)
			}
			if tc.wantErr != nil {
				return
			}

			if got := m.Name(); got != moduleName {
				t.Errorf("Name() = %q, want %q", got, moduleName)
			}
		})
	}
}

func TestScan(t *testing.T) {
	tests := []struct {
		name       string
		target     string
		ports      []uint32
		wantReport *rpb.PortScanningReport
	}{
		{
			name:   "when_target_is_ip_returns_ip_port_services",
			target: "127.0.0.1",
			ports:  []uint32{80, 443},
			wantReport: rpb.PortScanningReport_builder{
				TargetInfo: rpb.TargetInfo_builder{
					NetworkEndpoints: []*npb.NetworkEndpoint{
						npb.NetworkEndpoint_builder{
							Type: npb.NetworkEndpoint_IP,
							IpAddress: npb.IpAddress_builder{
								AddressFamily: npb.AddressFamily_IPV4,
								Address:       "127.0.0.1",
							}.Build(),
						}.Build(),
					},
				}.Build(),
				NetworkServices: []*nspb.NetworkService{
					nspb.NetworkService_builder{
						NetworkEndpoint: npb.NetworkEndpoint_builder{
							Type: npb.NetworkEndpoint_IP_PORT,
							IpAddress: npb.IpAddress_builder{
								AddressFamily: npb.AddressFamily_IPV4,
								Address:       "127.0.0.1",
							}.Build(),
							Port: npb.Port_builder{
								PortNumber: 80,
							}.Build(),
						}.Build(),
					}.Build(),
					nspb.NetworkService_builder{
						NetworkEndpoint: npb.NetworkEndpoint_builder{
							Type: npb.NetworkEndpoint_IP_PORT,
							IpAddress: npb.IpAddress_builder{
								AddressFamily: npb.AddressFamily_IPV4,
								Address:       "127.0.0.1",
							}.Build(),
							Port: npb.Port_builder{
								PortNumber: 443,
							}.Build(),
						}.Build(),
					}.Build(),
				},
			}.Build(),
		},
		{
			name:   "when_target_is_hostname_returns_hostname_port_services",
			target: "example.com",
			ports:  []uint32{8080},
			wantReport: rpb.PortScanningReport_builder{
				TargetInfo: rpb.TargetInfo_builder{
					NetworkEndpoints: []*npb.NetworkEndpoint{
						npb.NetworkEndpoint_builder{
							Type: npb.NetworkEndpoint_HOSTNAME,
							Hostname: npb.Hostname_builder{
								Name: "example.com",
							}.Build(),
						}.Build(),
					},
				}.Build(),
				NetworkServices: []*nspb.NetworkService{
					nspb.NetworkService_builder{
						NetworkEndpoint: npb.NetworkEndpoint_builder{
							Type: npb.NetworkEndpoint_HOSTNAME_PORT,
							Hostname: npb.Hostname_builder{
								Name: "example.com",
							}.Build(),
							Port: npb.Port_builder{
								PortNumber: 8080,
							}.Build(),
						}.Build(),
					}.Build(),
				},
			}.Build(),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfgProto := cpb.Config_builder{
				Globalcfg: cpb.GlobalConfig_builder{
					PortsToScan: tc.ports,
				}.Build(),
			}.Build()
			m, err := New(t.Context(), config.FromProto(cfgProto))
			if err != nil {
				t.Fatalf("New() failed: %v", err)
			}

			gotReport, err := m.Scan(t.Context(), tc.target)
			if err != nil {
				t.Fatalf("Scan() returned unexpected error: %v", err)
			}

			if diff := cmp.Diff(tc.wantReport, gotReport, protocmp.Transform()); diff != "" {
				t.Errorf("Scan() report diff (-want +got):\n%s", diff)
			}
		})
	}
}
