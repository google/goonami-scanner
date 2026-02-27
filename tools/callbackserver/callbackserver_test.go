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

package callbackserver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/goonami-scanner/common/callbackserver/cbid"
	"github.com/google/goonami-scanner/common/callbackserver/netutils"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"

	cbpb "github.com/google/goonami-scanner/tools/callbackserver/callbackserver_config_go_proto"
)

func TestConfigFromFile(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		want    *cbpb.CallbackserverConfig
		wantErr error
	}{
		{
			name: "when_valid_config_returns_config",
			path: "testdata/valid_config.textproto",
			want: cbpb.CallbackserverConfig_builder{
				HttpPollConfig: cbpb.EndpointConfig_builder{
					Mode:        cbpb.CallbackEndpointMode_MODE_START_LOCAL_SERVER,
					PublicUri:   "http://127.0.0.1:8081",
					BindAddress: "127.0.0.1",
					BindPort:    8081,
				}.Build(),
				DnsRecordConfig: cbpb.EndpointConfig_builder{
					Mode:      cbpb.CallbackEndpointMode_MODE_USE_REMOTE_SERVER,
					PublicUri: "cb.localhost.lan",
				}.Build(),
				HttpRecordConfig: cbpb.EndpointConfig_builder{
					Mode:        cbpb.CallbackEndpointMode_MODE_START_LOCAL_SERVER,
					PublicUri:   "http://127.0.0.1:8080",
					BindAddress: "127.0.0.1",
					BindPort:    8080,
				}.Build(),
				InteractionTtlSeconds:  proto.Uint32(60),
				CleanupIntervalSeconds: proto.Uint32(10),
			}.Build(),
		},
		{
			name:    "when_file_not_found_returns_error",
			path:    "/path/to/non/existent/file.textproto",
			wantErr: ErrConfigRead,
		},
		{
			name:    "when_invalid_prototext_returns_error",
			path:    "testdata/invalid_prototext.textproto",
			wantErr: ErrConfigUnmarshal,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := ConfigFromFile(context.Background(), tc.path)
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("ConfigFromFile() error = %v, wantErr %v", err, tc.wantErr)
			}

			if tc.wantErr != nil {
				return
			}

			if diff := cmp.Diff(tc.want, cfg, protocmp.Transform()); diff != "" {
				t.Errorf("ConfigFromFile() unexpected diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *cbpb.CallbackserverConfig
		wantErr error
	}{
		{
			name: "when_valid_config_returns_nil",
			cfg: cbpb.CallbackserverConfig_builder{
				HttpPollConfig: cbpb.EndpointConfig_builder{
					Mode: cbpb.CallbackEndpointMode_MODE_START_LOCAL_SERVER,
				}.Build(),
				InteractionTtlSeconds:  proto.Uint32(60),
				CleanupIntervalSeconds: proto.Uint32(10),
			}.Build(),
		},
		{
			name: "when_valid_config_with_remote_server_returns_nil",
			cfg: cbpb.CallbackserverConfig_builder{
				HttpPollConfig: cbpb.EndpointConfig_builder{
					Mode: cbpb.CallbackEndpointMode_MODE_START_LOCAL_SERVER,
				}.Build(),
				HttpRecordConfig: cbpb.EndpointConfig_builder{
					Mode: cbpb.CallbackEndpointMode_MODE_USE_REMOTE_SERVER,
				}.Build(),
				InteractionTtlSeconds:  proto.Uint32(60),
				CleanupIntervalSeconds: proto.Uint32(10),
			}.Build(),
		},
		{
			name: "when_valid_config_with_local_ports_returns_nil",
			cfg: cbpb.CallbackserverConfig_builder{
				HttpPollConfig: cbpb.EndpointConfig_builder{
					Mode: cbpb.CallbackEndpointMode_MODE_START_LOCAL_SERVER,
				}.Build(),
				HttpRecordConfig: cbpb.EndpointConfig_builder{
					Mode:     cbpb.CallbackEndpointMode_MODE_START_LOCAL_SERVER,
					BindPort: 1,
				}.Build(),
				DnsRecordConfig: cbpb.EndpointConfig_builder{
					Mode:     cbpb.CallbackEndpointMode_MODE_START_LOCAL_SERVER,
					BindPort: 65535,
				}.Build(),
				InteractionTtlSeconds:  proto.Uint32(60),
				CleanupIntervalSeconds: proto.Uint32(10),
			}.Build(),
		},
		{
			name: "when_missing_http_poll_config_returns_error",
			cfg: cbpb.CallbackserverConfig_builder{
				InteractionTtlSeconds:  proto.Uint32(60),
				CleanupIntervalSeconds: proto.Uint32(10),
			}.Build(),
			wantErr: ErrInvalidConfig,
		},
		{
			name: "when_invalid_http_record_port_returns_error",
			cfg: cbpb.CallbackserverConfig_builder{
				HttpPollConfig: cbpb.EndpointConfig_builder{
					Mode: cbpb.CallbackEndpointMode_MODE_START_LOCAL_SERVER,
				}.Build(),
				HttpRecordConfig: cbpb.EndpointConfig_builder{
					Mode:     cbpb.CallbackEndpointMode_MODE_START_LOCAL_SERVER,
					BindPort: 0,
				}.Build(),
				InteractionTtlSeconds:  proto.Uint32(60),
				CleanupIntervalSeconds: proto.Uint32(10),
			}.Build(),
			wantErr: ErrInvalidConfig,
		},
		{
			name: "when_invalid_dns_record_port_returns_error",
			cfg: cbpb.CallbackserverConfig_builder{
				HttpPollConfig: cbpb.EndpointConfig_builder{
					Mode: cbpb.CallbackEndpointMode_MODE_START_LOCAL_SERVER,
				}.Build(),
				DnsRecordConfig: cbpb.EndpointConfig_builder{
					Mode:     cbpb.CallbackEndpointMode_MODE_START_LOCAL_SERVER,
					BindPort: 65536,
				}.Build(),
				InteractionTtlSeconds:  proto.Uint32(60),
				CleanupIntervalSeconds: proto.Uint32(10),
			}.Build(),
			wantErr: ErrInvalidConfig,
		},
		{
			name: "when_invalid_interaction_ttl_returns_error",
			cfg: cbpb.CallbackserverConfig_builder{
				HttpPollConfig: cbpb.EndpointConfig_builder{
					Mode: cbpb.CallbackEndpointMode_MODE_START_LOCAL_SERVER,
				}.Build(),
				InteractionTtlSeconds: proto.Uint32(0),
			}.Build(),
			wantErr: ErrInvalidConfig,
		},
		{
			name: "when_invalid_cleanup_interval_returns_error",
			cfg: cbpb.CallbackserverConfig_builder{
				HttpPollConfig: cbpb.EndpointConfig_builder{
					Mode: cbpb.CallbackEndpointMode_MODE_START_LOCAL_SERVER,
				}.Build(),
				CleanupIntervalSeconds: proto.Uint32(0),
			}.Build(),
			wantErr: ErrInvalidConfig,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateConfig(tc.cfg)
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("ValidateConfig() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *cbpb.CallbackserverConfig
		wantErr error
		want    *cbpb.CallbackserverConfig
	}{
		{
			name: "when_valid_config_returns_server",
			cfg: cbpb.CallbackserverConfig_builder{
				HttpPollConfig: cbpb.EndpointConfig_builder{
					Mode: cbpb.CallbackEndpointMode_MODE_START_LOCAL_SERVER,
				}.Build(),
				InteractionTtlSeconds:  proto.Uint32(60),
				CleanupIntervalSeconds: proto.Uint32(10),
			}.Build(),
			want: cbpb.CallbackserverConfig_builder{
				HttpPollConfig: cbpb.EndpointConfig_builder{
					Mode: cbpb.CallbackEndpointMode_MODE_START_LOCAL_SERVER,
				}.Build(),
				InteractionTtlSeconds:  proto.Uint32(60),
				CleanupIntervalSeconds: proto.Uint32(10),
			}.Build(),
		},
		{
			name: "when_invalid_config_returns_error",
			cfg: cbpb.CallbackserverConfig_builder{
				InteractionTtlSeconds:  proto.Uint32(60),
				CleanupIntervalSeconds: proto.Uint32(10),
			}.Build(),
			wantErr: ErrInvalidConfig,
		},
		{
			name: "when_partial_config_uses_defaults",
			cfg: cbpb.CallbackserverConfig_builder{
				HttpPollConfig: cbpb.EndpointConfig_builder{
					Mode: cbpb.CallbackEndpointMode_MODE_START_LOCAL_SERVER,
				}.Build(),
			}.Build(),
			want: cbpb.CallbackserverConfig_builder{
				HttpPollConfig: cbpb.EndpointConfig_builder{
					Mode: cbpb.CallbackEndpointMode_MODE_START_LOCAL_SERVER,
				}.Build(),
				InteractionTtlSeconds:  proto.Uint32(60),
				CleanupIntervalSeconds: proto.Uint32(10),
			}.Build(),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			srv, err := New(ctx, tc.cfg)

			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("New() error = %v, wantErr %v", err, tc.wantErr)
			}

			if tc.wantErr != nil {
				return
			}

			if srv == nil {
				t.Fatal("New() returned nil without error")
			}

			if diff := cmp.Diff(tc.want, srv.cfg, protocmp.Transform()); diff != "" {
				t.Errorf("New() srv.cfg diff (-want +got):\n%s", diff)
			}

			if srv.store == nil {
				t.Error("New() srv.store is nil")
			}
		})
	}
}

func TestServer(t *testing.T) {
	recordPort := getFreePort(t)
	recordURI := fmt.Sprintf("http://127.0.0.1:%d", recordPort)
	pollPort := getFreePort(t)
	pollURI := fmt.Sprintf("http://127.0.0.1:%d", pollPort)

	cfg := cbpb.CallbackserverConfig_builder{
		InteractionTtlSeconds:  proto.Uint32(60),
		CleanupIntervalSeconds: proto.Uint32(10),
		HttpRecordConfig: cbpb.EndpointConfig_builder{
			Mode:        cbpb.CallbackEndpointMode_MODE_START_LOCAL_SERVER,
			BindAddress: "127.0.0.1",
			BindPort:    uint32(recordPort),
		}.Build(),
		HttpPollConfig: cbpb.EndpointConfig_builder{
			Mode:        cbpb.CallbackEndpointMode_MODE_START_LOCAL_SERVER,
			BindAddress: "127.0.0.1",
			BindPort:    uint32(pollPort),
		}.Build(),
		DnsRecordConfig: cbpb.EndpointConfig_builder{
			Mode:      cbpb.CallbackEndpointMode_MODE_USE_REMOTE_SERVER,
			PublicUri: "http://127.0.0.1:53",
		}.Build(),
	}.Build()

	ctx := context.Background()
	srv, err := New(ctx, cfg)
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}

	if srv == nil {
		t.Fatal("New() returned nil server")
	}

	srv.StartRecordingHTTP(ctx)
	srv.StartPolling(ctx)

	// Allow a few milliseconds for the servers to start.
	time.Sleep(200 * time.Millisecond)

	if srv.httpRecordingSrv == nil {
		t.Error("recordingServer is nil after StartRecordingHTTP")
	}

	if srv.httpPollingSrv == nil {
		t.Error("pollingServer is nil after StartPolling")
	}

	// We register an interaction and immediately check its presence.
	httpRegisterInteraction(ctx, t, "test", recordURI)
	httpPollInteraction(ctx, t, "test", pollURI)

	if err := srv.Shutdown(ctx); err != nil {
		t.Errorf("Shutdown() unexpected error: %v", err)
	}
}

func TestServer_RemoteHTTPRecording(t *testing.T) {
	pollPort := getFreePort(t)
	cfg := cbpb.CallbackserverConfig_builder{
		InteractionTtlSeconds:  proto.Uint32(60),
		CleanupIntervalSeconds: proto.Uint32(10),
		HttpRecordConfig: cbpb.EndpointConfig_builder{
			Mode:      cbpb.CallbackEndpointMode_MODE_USE_REMOTE_SERVER,
			PublicUri: "http://127.0.0.1:8080",
		}.Build(),
		HttpPollConfig: cbpb.EndpointConfig_builder{
			Mode:        cbpb.CallbackEndpointMode_MODE_START_LOCAL_SERVER,
			BindAddress: "127.0.0.1",
			BindPort:    uint32(pollPort),
		}.Build(),
		DnsRecordConfig: cbpb.EndpointConfig_builder{
			Mode:      cbpb.CallbackEndpointMode_MODE_USE_REMOTE_SERVER,
			PublicUri: "http://127.0.0.1:53",
		}.Build(),
	}.Build()

	ctx := context.Background()
	srv, err := New(ctx, cfg)
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}

	if srv == nil {
		t.Fatal("New() returned nil server")
	}

	srv.StartRecordingHTTP(ctx)
	srv.StartPolling(ctx)

	// Allow a few milliseconds for the servers to start.
	time.Sleep(200 * time.Millisecond)

	if srv.httpRecordingSrv != nil {
		t.Error("recordingServer is not nil after StartRecordingHTTP")
	}

	if srv.httpPollingSrv == nil {
		t.Error("pollingServer is nil after StartPolling")
	}

	if err := srv.Shutdown(ctx); err != nil {
		t.Errorf("Shutdown() unexpected error: %v", err)
	}
}

func TestServer_RemotePolling(t *testing.T) {
	recordPort := getFreePort(t)

	cfg := cbpb.CallbackserverConfig_builder{
		InteractionTtlSeconds:  proto.Uint32(60),
		CleanupIntervalSeconds: proto.Uint32(10),
		HttpRecordConfig: cbpb.EndpointConfig_builder{
			Mode:        cbpb.CallbackEndpointMode_MODE_START_LOCAL_SERVER,
			BindAddress: "127.0.0.1",
			BindPort:    uint32(recordPort),
		}.Build(),
		HttpPollConfig: cbpb.EndpointConfig_builder{
			Mode:      cbpb.CallbackEndpointMode_MODE_USE_REMOTE_SERVER,
			PublicUri: "http://127.0.0.1:8081",
		}.Build(),
		DnsRecordConfig: cbpb.EndpointConfig_builder{
			Mode:      cbpb.CallbackEndpointMode_MODE_USE_REMOTE_SERVER,
			PublicUri: "http://127.0.0.1:53",
		}.Build(),
	}.Build()

	ctx := context.Background()
	srv, err := New(ctx, cfg)
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}

	if srv == nil {
		t.Fatal("New() returned nil server")
	}

	srv.StartRecordingHTTP(ctx)
	srv.StartPolling(ctx)

	// Allow a few milliseconds for the servers to start.
	time.Sleep(200 * time.Millisecond)

	if srv.httpRecordingSrv == nil {
		t.Error("recordingServer is nil after StartRecordingHTTP")
	}

	if srv.httpPollingSrv != nil {
		t.Error("pollingServer is not nil after StartPolling")
	}

	if err := srv.Shutdown(ctx); err != nil {
		t.Errorf("Shutdown() unexpected error: %v", err)
	}
}

func httpRegisterInteraction(ctx context.Context, t *testing.T, secret, recordURI string) {
	t.Helper()

	cbid, err := cbid.Generate(secret)
	if err != nil {
		t.Fatalf("failed to register interaction: %v", err)
	}

	url := netutils.CallbackURL(recordURI, cbid)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("failed to perform request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("unexpected status code: %v", resp.StatusCode)
	}
}

func httpPollInteraction(ctx context.Context, t *testing.T, secret, pollURI string) {
	t.Helper()

	url := fmt.Sprintf("%s/?secret=%s", pollURI, secret)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("failed to perform request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("unexpected status code: %v", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}

	if string(body) != `{"hasHttpInteraction":true}` {
		t.Errorf("unexpected response body: %v", string(body))
	}
}

func getFreePort(t *testing.T) int {
	t.Helper()
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to resolve tcp addr: %v", err)
	}

	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		t.Fatalf("failed to listen on tcp addr: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}
