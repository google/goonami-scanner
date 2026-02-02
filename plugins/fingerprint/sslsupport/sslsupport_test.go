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

// Package sslsupport checks if a network service supports SSL.
package sslsupport

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/goonami-scanner/core/config"
	cpb "github.com/google/goonami-scanner/core/config/config_go_proto"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"

	nepb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
)

type dispatchFn func(conn net.Conn)
type listenerFn func(*testing.T, dispatchFn) net.Listener

func TestFingerprint_Connection(t *testing.T) {
	tests := []struct {
		name            string
		server          listenerFn
		dispatch        dispatchFn
		wantSSLVersions []string
	}{
		{
			// note: it seems that the TLS server implementation will not really consider the connection
			// active until some bytes are written. Given that we have tests to ensure the timeout is
			// enforced, we can just make the connection happy here by writing a byte.
			name:            "service_supports_ssl",
			server:          tlsServer,
			dispatch:        func(conn net.Conn) { conn.Write([]byte("\n")) },
			wantSSLVersions: []string{"TLS 1.3"},
		},
		{
			name:     "connection_fails_no_error",
			server:   tlsServer,
			dispatch: func(conn net.Conn) {},
		},
		{
			// note: if timeout are not set correctly, this test will hang. We register a watcher
			// goroutine below to catch this case.
			name:     "connection_timeout",
			server:   hangingServer,
			dispatch: func(_ net.Conn) { time.Sleep(time.Hour * 3) },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := tt.server(t, tt.dispatch)
			defer l.Close()

			parsePort, err := strconv.ParseUint(strings.Split(l.Addr().String(), ":")[1], 10, 32)
			if err != nil {
				t.Fatalf("Failed to parse port: %v", err)
			}
			port := uint32(parsePort)

			service := nspb.NetworkService_builder{
				NetworkEndpoint: nepb.NetworkEndpoint_builder{
					IpAddress: nepb.IpAddress_builder{
						Address:       "127.0.0.1",
						AddressFamily: nepb.AddressFamily_IPV4,
					}.Build(),
					Port: nepb.Port_builder{PortNumber: port}.Build(),
				}.Build(),
			}.Build()

			cfgpb := cpb.Config_builder{
				Globalcfg: cpb.GlobalConfig_builder{
					Performance: cpb.GlobalConfig_Performance_builder{
						TimeoutPerRequestSeconds: 1,
					}.Build(),
				}.Build(),
			}.Build()
			cfg := config.FromProto(cfgpb)
			mod, err := New(cfg)
			if err != nil {
				t.Fatalf("New failed: %v", err)
			}

			// watcher goroutine: tries to catch setup that does not handle timeouts carefully.
			go func() {
				time.Sleep(time.Second * 5)
				log.Fatalf("[watcher] test killed: maybe timeout handling is broken?")
			}()

			gotServices, err := mod.Fingerprint(context.Background(), service)
			if err != nil {
				t.Errorf("Fingerprint() error = %v, want nil", err)
				return
			}

			if len(gotServices) != 1 {
				t.Fatalf("Fingerprint() returned an unexpected number of services: %v, want 1", len(gotServices))
			}

			got := gotServices[0].GetSupportedSslVersions()
			if diff := cmp.Diff(tt.wantSSLVersions, got); diff != "" {
				t.Errorf("Fingerprint() returned diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestFingerprint_Validation(t *testing.T) {
	service := nspb.NetworkService_builder{
		SupportedSslVersions: []string{"TLS12"},
		NetworkEndpoint: nepb.NetworkEndpoint_builder{
			IpAddress: nepb.IpAddress_builder{
				Address:       "127.0.0.1",
				AddressFamily: nepb.AddressFamily_IPV4,
			}.Build(),
			Port: nepb.Port_builder{PortNumber: 8080}.Build(),
		}.Build(),
	}.Build()
	tests := []struct {
		name    string
		service *nspb.NetworkService
		want    *nspb.NetworkService
		wantErr bool
	}{
		{
			name:    "fingerprint_already_done_no_changes",
			service: proto.Clone(service).(*nspb.NetworkService),
			want:    proto.Clone(service).(*nspb.NetworkService),
		},
		{
			name: "invalid_network_endpoint",
			service: nspb.NetworkService_builder{
				NetworkEndpoint: nepb.NetworkEndpoint_builder{
					Type: nepb.NetworkEndpoint_TYPE_UNSPECIFIED,
				}.Build(),
			}.Build(),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.FromProto(cpb.Config_builder{}.Build())
			mod, err := New(cfg)
			if err != nil {
				t.Fatalf("New failed: %v", err)
			}

			gotServices, err := mod.Fingerprint(context.Background(), tt.service)
			if (err != nil) != tt.wantErr {
				t.Errorf("Fingerprint() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			if len(gotServices) != 1 {
				t.Fatalf("Fingerprint() returned an unexpected number of services: %v, want 1", len(gotServices))
			}

			got := gotServices[0]
			if diff := cmp.Diff(tt.want, got, protocmp.Transform()); diff != "" {
				t.Errorf("Fingerprint() returned diff (-want +got):\n%s", diff)
			}
		})
	}
}

func tlsServer(t *testing.T, dispatch dispatchFn) net.Listener {
	t.Helper()
	cert, err := tls.LoadX509KeyPair("testdata/example.crt", "testdata/example.key")
	if err != nil {
		t.Fatalf("Failed to load TLS certificate/key: %v", err)
	}

	cfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	l, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("Failed to start SSL server: %v", err)
	}

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}

			dispatch(conn)
			conn.Close()
		}
	}()

	return l
}

func hangingServer(t *testing.T, dispatch dispatchFn) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start hanging server: %v", err)
	}

	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}

		dispatch(conn)
		conn.Close()
	}()
	return l
}
