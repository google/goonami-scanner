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

// Package iswebservice provides a fingerprinter to define if a network service is a web service.
package iswebservice

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
	nepb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
)

func TestFingerprint(t *testing.T) {
	okServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer okServer.Close()
	sleepServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer sleepServer.Close()
	tcpServer := tcpListener(t)
	defer tcpServer.Close()

	tests := []struct {
		name        string
		server      net.Listener
		service     *nspb.NetworkService_builder
		wantMethods []string
	}{
		{
			name:        "when_service_is_web_server_returns_supported_methods",
			server:      okServer.Listener,
			service:     &nspb.NetworkService_builder{ServiceName: "http"},
			wantMethods: []string{"GET"},
		},
		{
			name:   "when_service_is_web_server_with_existing_methods_returns_all_supported_methods",
			server: okServer.Listener,
			service: &nspb.NetworkService_builder{
				ServiceName:          "http",
				SupportedHttpMethods: []string{"POST"},
			},
			wantMethods: []string{"POST", "GET"},
		},
		{
			name:        "when_service_not_http_returns_no_methods",
			server:      tcpServer,
			service:     &nspb.NetworkService_builder{ServiceName: "ssh"},
			wantMethods: nil,
		},
		{
			name:        "when_request_times_out_returns_no_methods",
			server:      sleepServer.Listener,
			service:     &nspb.NetworkService_builder{ServiceName: "http"},
			wantMethods: nil,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.FromProto(cpb.Config_builder{
				Globalcfg: cpb.GlobalConfig_builder{
					Performance: cpb.GlobalConfig_Performance_builder{
						TimeoutPerRequestSeconds: proto.Int32(1),
					}.Build(),
				}.Build(),
			}.Build())

			m, err := New(t.Context(), cfg)
			if err != nil {
				t.Fatalf("New(%v) returned an unexpected error: %v", cfg, err)
			}

			addr, p, err := net.SplitHostPort(tc.server.Addr().String())
			if err != nil {
				t.Fatalf("failed to parse server address %q: %v", tc.server.Addr().String(), err)
			}

			port, err := strconv.ParseUint(p, 10, 32)
			if err != nil {
				t.Fatalf("failed parsing port %q: %v", p, err)
			}

			endpoint := nepb.NetworkEndpoint_builder{
				Type: nepb.NetworkEndpoint_IP_PORT,
				IpAddress: nepb.IpAddress_builder{
					Address:       addr,
					AddressFamily: nepb.AddressFamily_IPV4,
				}.Build(),
				Port: nepb.Port_builder{
					PortNumber: uint32(port),
				}.Build(),
			}.Build()

			tc.service.NetworkEndpoint = endpoint
			service := tc.service.Build()

			gotServices, err := m.Fingerprint(t.Context(), service)
			if err != nil {
				t.Fatalf("Fingerprint(%v) returned an unexpected error: %v", service, err)
			}

			if len(gotServices) != 1 {
				t.Fatalf("Fingerprint(%v) returned an unexpected number of services: %v, want 1", service, len(gotServices))
			}

			got := gotServices[0]
			if diff := cmp.Diff(tc.wantMethods, got.GetSupportedHttpMethods(), protocmp.Transform()); diff != "" {
				t.Errorf("Fingerprint(%v) returned an unexpected diff (-want +got):\n%s", tc.service, diff)
			}
		})
	}
}

func TestFingerprint_ErrorCases(t *testing.T) {
	tests := []struct {
		name    string
		service *nspb.NetworkService
		wantErr error
	}{
		{
			name: "when_network_endpoint_is_invalid_returns_error",
			service: nspb.NetworkService_builder{
				NetworkEndpoint: nepb.NetworkEndpoint_builder{
					Type: nepb.NetworkEndpoint_TYPE_UNSPECIFIED,
				}.Build(),
			}.Build(),
			wantErr: netendpoint.ErrEndpointMissingAddress,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.FromProto(&cpb.Config{})
			m, _ := New(t.Context(), cfg)

			_, err := m.Fingerprint(t.Context(), tc.service)
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("Fingerprint() error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestFingerprint_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	cfg := config.FromProto(&cpb.Config{})
	m, _ := New(t.Context(), cfg)

	service := nspb.NetworkService_builder{
		NetworkEndpoint: nepb.NetworkEndpoint_builder{
			Type: nepb.NetworkEndpoint_IP_PORT,
			IpAddress: nepb.IpAddress_builder{
				Address:       "127.0.0.1",
				AddressFamily: nepb.AddressFamily_IPV4,
			}.Build(),
			Port: nepb.Port_builder{PortNumber: 80}.Build(),
		}.Build(),
	}.Build()

	_, err := m.Fingerprint(ctx, service)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Fingerprint() error = %v, want %v", err, context.Canceled)
	}
}

func tcpListener(t *testing.T) net.Listener {
	t.Helper()

	tcpServer, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start hanging server: %v", err)
	}

	go func() {
		conn, err := tcpServer.Accept()
		if err != nil {
			return
		}

		conn.Write([]byte("SSH"))
		conn.Close()
	}()

	return tcpServer
}
