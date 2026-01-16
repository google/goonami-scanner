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
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/google/goonami-scanner/core/config"
	cpb "github.com/google/goonami-scanner/core/config/config_go_proto"
	goohttp "github.com/google/goonami-scanner/core/net/http"

	"github.com/google/go-cmp/cmp"
	nepb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
	"google.golang.org/protobuf/testing/protocmp"
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
			name:        "service_is_web_server",
			server:      okServer.Listener,
			service:     &nspb.NetworkService_builder{ServiceName: "http"},
			wantMethods: []string{"GET"},
		},
		{
			name:   "service_is_web_server_with_existing_methods",
			server: okServer.Listener,
			service: &nspb.NetworkService_builder{
				ServiceName:          "http",
				SupportedHttpMethods: []string{"POST"},
			},
			wantMethods: []string{"POST", "GET"},
		},
		{
			name:        "service_not_http_no_error",
			server:      tcpServer,
			service:     &nspb.NetworkService_builder{ServiceName: "ssh"},
			wantMethods: nil,
		},
		{
			name:        "request_timed_out_no_error",
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
						TimeoutPerRequestSeconds: 1,
					}.Build(),
				}.Build(),
			}.Build())

			if err := goohttp.InitializeDefaults(cfg); err != nil {
				t.Fatalf("Failed to initialize HTTP client: %v", err)
			}

			m, err := New(cfg)
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

			if err = m.Fingerprint(context.Background(), service); err != nil {
				t.Fatalf("Fingerprint(%v) returned an unexpected error: %v", service, err)
			}

			if diff := cmp.Diff(tc.wantMethods, service.GetSupportedHttpMethods(), protocmp.Transform()); diff != "" {
				t.Errorf("Fingerprint(%v) returned an unexpected diff (-want +got):\n%s", tc.service, diff)
			}
		})
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
