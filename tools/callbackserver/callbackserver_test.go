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
	"google.golang.org/protobuf/testing/protocmp"

	ctpb "github.com/google/goonami-scanner/tools/callbackserver/callbackserver_tool_config_go_proto"
)

func TestConfigFromFile(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		want    *ctpb.CallbackserverToolConfig
		wantErr error
	}{
		{
			name: "when_valid_config_returns_config",
			path: "testdata/valid_config.textproto",
			want: (&ctpb.CallbackserverToolConfig_builder{
				RecordConfig: (&ctpb.RecordConfig_builder{
					Address: "127.0.0.1",
					Port:    8080,
				}).Build(),
				PollConfig: (&ctpb.PollConfig_builder{
					Address: "127.0.0.1",
					Port:    8081,
				}).Build(),
				InteractionTtlSeconds:  60,
				CleanupIntervalSeconds: 10,
			}).Build(),
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
		{
			name:    "when_missing_record_config_returns_error",
			path:    "testdata/missing_record_config.textproto",
			wantErr: ErrInvalidConfig,
		},
		{
			name:    "when_missing_poll_config_returns_error",
			path:    "testdata/missing_poll_config.textproto",
			wantErr: ErrInvalidConfig,
		},
		{
			name:    "when_record_port_out_of_range_returns_error",
			path:    "testdata/record_port_out_of_range.textproto",
			wantErr: ErrInvalidConfig,
		},
		{
			name:    "when_poll_port_out_of_range_returns_error",
			path:    "testdata/poll_port_out_of_range.textproto",
			wantErr: ErrInvalidConfig,
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

func TestServer(t *testing.T) {
	recordPort := getFreePort(t)
	pollPort := getFreePort(t)

	cfg := (&ctpb.CallbackserverToolConfig_builder{
		RecordConfig: (&ctpb.RecordConfig_builder{
			Address: "127.0.0.1",
			Port:    uint32(recordPort),
		}).Build(),
		PollConfig: (&ctpb.PollConfig_builder{
			Address: "127.0.0.1",
			Port:    uint32(pollPort),
		}).Build(),
		InteractionTtlSeconds:  60,
		CleanupIntervalSeconds: 10,
	}).Build()

	ctx := context.Background()
	srv := New(ctx, cfg)

	if srv == nil {
		t.Fatal("New() returned nil server")
	}

	srv.StartRecordingHTTP(ctx)
	srv.StartPolling(ctx)

	// Allow a few milliseconds for the servers to start.
	time.Sleep(200 * time.Millisecond)

	if srv.recordingServer == nil {
		t.Error("recordingServer is nil after StartRecordingHTTP")
	}

	if srv.pollingServer == nil {
		t.Error("pollingServer is nil after StartPolling")
	}

	// We register an interaction and immediately check its presence.
	httpRegisterInteraction(ctx, t, "test", "127.0.0.1", recordPort)
	httpPollInteraction(ctx, t, "test", "127.0.0.1", pollPort)

	if err := srv.Shutdown(ctx); err != nil {
		t.Errorf("Shutdown() unexpected error: %v", err)
	}
}

func httpRegisterInteraction(ctx context.Context, t *testing.T, secret, recordHost string, recordPort int) {
	t.Helper()

	cbid, err := cbid.Generate(secret)
	if err != nil {
		t.Fatalf("failed to register interaction: %v", err)
	}

	url := netutils.CallbackURL(recordHost, recordPort, cbid)
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

func httpPollInteraction(ctx context.Context, t *testing.T, secret, pollHost string, pollPort int) {
	t.Helper()

	url := fmt.Sprintf("http://%s:%d/?secret=%s", pollHost, pollPort, secret)
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
