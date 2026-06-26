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

// Package httpscan provides unit tests for the httpscan portscan plugin.
package httpscan

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/goonami-scanner/core/config"
	_ "github.com/google/goonami-scanner/core/net/http/simpleclient"
	"github.com/google/goonami-scanner/core/net/netendpoint"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"

	cpb "github.com/google/goonami-scanner/core/config/config_go_proto"
	hcpb "github.com/google/goonami-scanner/plugins/portscan/httpscan/httpscan_portscan_config_go_proto"
	npb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
	rpb "github.com/google/tsunami-security-scanner/proto/go/reconnaissance_go_proto"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name                 string
		cfgProto             *cpb.Config
		wantPortsToScanCount int
		wantInvalidExitCodes []int32
	}{
		{
			name: "when_no_plugins_config_and_no_ports_specified_uses_default_and_all_ports",
			cfgProto: cpb.Config_builder{
				Globalcfg: cpb.GlobalConfig_builder{}.Build(),
			}.Build(),
			wantPortsToScanCount: 65535,
			wantInvalidExitCodes: []int32{400, 502},
		},
		{
			name: "when_plugin_config_provided_and_ports_specified_uses_provided_values",
			cfgProto: cpb.Config_builder{
				Globalcfg: cpb.GlobalConfig_builder{
					PortsToScan: []uint32{80, 443},
				}.Build(),
				Plugins: cpb.PluginsConfig_builder{
					Httpscan: hcpb.HttpScanPluginConfig_builder{
						InvalidExitCodes: []int32{400, 502, 404},
					}.Build(),
				}.Build(),
			}.Build(),
			wantPortsToScanCount: 2,
			wantInvalidExitCodes: []int32{400, 502, 404},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.FromProto(tc.cfgProto)
			m, err := New(t.Context(), cfg)
			if err != nil {
				t.Fatalf("New(%v) returned unexpected error: %v", cfg, err)
			}

			mod, ok := m.(*Module)
			if !ok {
				t.Fatalf("New(%v) did not return a *Module", cfg)
			}

			if len(mod.portsToScan) != tc.wantPortsToScanCount {
				t.Errorf("portsToScan count = %d, want %d", len(mod.portsToScan), tc.wantPortsToScanCount)
			}

			if diff := cmp.Diff(tc.wantInvalidExitCodes, mod.config.GetInvalidExitCodes()); diff != "" {
				t.Errorf("invalid_exit_codes diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestScan(t *testing.T) {
	okServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer okServer.Close()

	invalidCodeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest) // 400 - default closed
	}))
	defer invalidCodeServer.Close()

	sleepServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer sleepServer.Close()

	closedPort := getClosedPort(t)

	tests := []struct {
		name         string
		serverAddr   string
		port         uint32
		timeoutSec   int32
		wantServices bool
	}{
		{
			name:         "when_port_is_open_and_ok_returns_service",
			serverAddr:   okServer.Listener.Addr().String(),
			wantServices: true,
		},
		{
			name:         "when_port_is_open_but_invalid_exit_code_returns_closed",
			serverAddr:   invalidCodeServer.Listener.Addr().String(),
			wantServices: false,
		},
		{
			name:         "when_port_is_closed_returns_no_service",
			serverAddr:   net.JoinHostPort("127.0.0.1", strconv.Itoa(int(closedPort))),
			wantServices: false,
		},
		{
			name:         "when_request_times_out_returns_no_service",
			serverAddr:   sleepServer.Listener.Addr().String(),
			timeoutSec:   1,
			wantServices: false,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			addr, pStr, err := net.SplitHostPort(tc.serverAddr)
			if err != nil {
				t.Fatalf("failed to split host port %q: %v", tc.serverAddr, err)
			}
			port, err := strconv.ParseUint(pStr, 10, 32)
			if err != nil {
				t.Fatalf("failed parsing port %q: %v", pStr, err)
			}

			timeout := int32(5)
			if tc.timeoutSec > 0 {
				timeout = tc.timeoutSec
			}

			cfgProto := cpb.Config_builder{
				Globalcfg: cpb.GlobalConfig_builder{
					PortsToScan: []uint32{uint32(port)},
					Performance: cpb.GlobalConfig_Performance_builder{
						TimeoutPerRequestSeconds: proto.Int32(timeout),
						MaxConcurrency:           proto.Int32(10),
					}.Build(),
				}.Build(),
			}.Build()

			cfg := config.FromProto(cfgProto)
			m, err := New(t.Context(), cfg)
			if err != nil {
				t.Fatalf("New() failed: %v", err)
			}

			gotReport, err := m.Scan(t.Context(), addr)
			if err != nil {
				t.Fatalf("Scan() returned unexpected error: %v", err)
			}

			endpoint := netendpoint.FromString(addr)
			var wantServices []*nspb.NetworkService
			if tc.wantServices {
				wantServices = []*nspb.NetworkService{
					nspb.NetworkService_builder{
						NetworkEndpoint: npb.NetworkEndpoint_builder{
							Type:      npb.NetworkEndpoint_IP_PORT,
							IpAddress: endpoint.GetIpAddress(),
							Port: npb.Port_builder{
								PortNumber: uint32(port),
							}.Build(),
						}.Build(),
						SupportedHttpMethods: []string{"GET"},
					}.Build(),
				}
			}

			wantReport := rpb.PortScanningReport_builder{
				TargetInfo: rpb.TargetInfo_builder{
					NetworkEndpoints: []*npb.NetworkEndpoint{endpoint},
				}.Build(),
				NetworkServices: wantServices,
			}.Build()

			if diff := cmp.Diff(wantReport, gotReport, protocmp.Transform()); diff != "" {
				t.Errorf("Scan() returned unexpected report diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestScan_ContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	cfgProto := cpb.Config_builder{
		Globalcfg: cpb.GlobalConfig_builder{
			PortsToScan: []uint32{80},
		}.Build(),
	}.Build()

	cfg := config.FromProto(cfgProto)
	m, err := New(t.Context(), cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	_, err = m.Scan(ctx, "127.0.0.1")
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Scan() error = %v, want %v", err, context.Canceled)
	}
}

func TestScanPortWorker_ErrorCases(t *testing.T) {
	tests := []struct {
		name     string
		endpoint *npb.NetworkEndpoint
		wantErr  error
	}{
		{
			name: "when_network_endpoint_type_is_unspecified_returns_error",
			endpoint: npb.NetworkEndpoint_builder{
				Type: npb.NetworkEndpoint_TYPE_UNSPECIFIED,
			}.Build(),
			wantErr: errors.New("invalid network endpoint type: TYPE_UNSPECIFIED"),
		},
		{
			name: "when_network_endpoint_has_no_address_returns_build_web_root_error",
			endpoint: npb.NetworkEndpoint_builder{
				Type: npb.NetworkEndpoint_IP,
			}.Build(),
			wantErr: netendpoint.ErrEndpointMissingAddress,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			cfgProto := cpb.Config_builder{
				Globalcfg: cpb.GlobalConfig_builder{
					PortsToScan: []uint32{80},
				}.Build(),
			}.Build()
			cfg := config.FromProto(cfgProto)
			m, err := New(t.Context(), cfg)
			if err != nil {
				t.Fatalf("New() failed: %v", err)
			}

			mod := m.(*Module)
			_, err = mod.scanPortWorker(t.Context(), tc.endpoint, 80)
			if err == nil || err.Error() != tc.wantErr.Error() {
				t.Errorf("scanPortWorker() error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestScanPortWorker_ContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	cfgProto := cpb.Config_builder{
		Globalcfg: cpb.GlobalConfig_builder{
			PortsToScan: []uint32{80},
		}.Build(),
	}.Build()
	cfg := config.FromProto(cfgProto)
	m, err := New(t.Context(), cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	mod := m.(*Module)
	endpoint := netendpoint.FromString("127.0.0.1")
	_, err = mod.scanPortWorker(ctx, endpoint, 80)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("scanPortWorker() error = %v, want %v", err, context.Canceled)
	}
}

func getClosedPort(t *testing.T) uint32 {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer listener.Close()

	_, portStr, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("failed to split host port: %v", err)
	}

	port, err := strconv.ParseUint(portStr, 10, 32)
	if err != nil {
		t.Fatalf("failed to parse port: %v", err)
	}

	return uint32(port)
}
