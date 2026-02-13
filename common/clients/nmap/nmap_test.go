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

package nmap

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/goonami-scanner/core/config"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"

	nccpb "github.com/google/goonami-scanner/common/clients/nmap/nmap_client_config_go_proto"
	cpb "github.com/google/goonami-scanner/core/config/config_go_proto"
)

const testdataDir = "testdata"

func loadNmapConfig(t *testing.T, configFile string) *nccpb.NmapClientConfig {
	t.Helper()
	path := filepath.Join(testdataDir, "configs", configFile)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read test config file %q: %v", path, err)
	}
	cfg := &nccpb.NmapClientConfig{}
	if err := prototext.Unmarshal(data, cfg); err != nil {
		t.Fatalf("failed to unmarshal test config file %q: %v", path, err)
	}
	return cfg
}

func TestNew(t *testing.T) {
	testCases := []struct {
		name       string
		nmapConfig *nccpb.NmapClientConfig
		wantConfig *nccpb.NmapClientConfig
	}{
		{
			name:       "when_nmap_config_is_provided_it_is_used",
			nmapConfig: loadNmapConfig(t, "udp.textproto"),
			wantConfig: loadNmapConfig(t, "udp.textproto"),
		},
		{
			name:       "when_nmap_config_is_not_provided_it_uses_default",
			nmapConfig: nil,
			wantConfig: DefaultConfig(),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfgpb := cpb.Config_builder{
				Clients: cpb.ClientsConfig_builder{
					Nmap: tc.nmapConfig,
				}.Build(),
			}.Build()
			cfg := config.FromProto(cfgpb)
			client := New(cfg)
			if diff := cmp.Diff(tc.wantConfig, client.config, cmp.Comparer(proto.Equal)); diff != "" {
				t.Errorf("New() returned unexpected config (-want +got):\n%s", diff)
			}
		})
	}
}

func TestCommandLine(t *testing.T) {
	testCases := []struct {
		name       string
		configFile string
		rateLimit  int32
		ports      []uint32
		userAgent  string
		target     string
		want       []string
		wantErr    error
	}{
		{
			name:       "when_using_default_config_ipv4_returns_correct_args",
			configFile: "default.textproto",
			target:     "127.0.0.1",
			want:       []string{"-oX", "", "-sT", "-T3", "", "-p-", "-Pn", "127.0.0.1"},
			wantErr:    nil,
		},
		{
			name:       "when_using_default_config_ipv6_returns_correct_args",
			configFile: "default.textproto",
			target:     "::1",
			want:       []string{"-oX", "", "-sT", "-T3", "-6", "-p-", "-Pn", "::1"},
			wantErr:    nil,
		},
		{
			name:       "when_using_default_config_with_ports_returns_correct_args",
			configFile: "default.textproto",
			ports:      []uint32{80, 443},
			target:     "127.0.0.1",
			want:       []string{"-oX", "", "-sT", "-T3", "", "-p80,443", "-Pn", "127.0.0.1"},
			wantErr:    nil,
		},
		{
			name:       "when_using_udp_scan_config_returns_correct_args",
			configFile: "udp.textproto",
			target:     "127.0.0.1",
			want:       []string{"-oX", "", "-sU", "-T3", "", "-p-", "-Pn", "127.0.0.1"},
			wantErr:    nil,
		},
		{
			name:       "when_intensity_is_one_returns_correct_args",
			configFile: "intensity_1.textproto",
			target:     "127.0.0.1",
			want:       []string{"-oX", "", "-sT", "-T1", "", "-p-", "-Pn", "127.0.0.1"},
			wantErr:    nil,
		},
		{
			name:       "when_intensity_is_invalid_returns_default_args",
			configFile: "intensity_invalid.textproto",
			target:     "127.0.0.1",
			want:       []string{"-oX", "", "-sT", "-T3", "", "-p-", "-Pn", "127.0.0.1"},
			wantErr:    nil,
		},

		{
			name:       "when_intensity_is_zero_returns_default_args",
			configFile: "intensity_zero.textproto",
			target:     "127.0.0.1",
			want:       []string{"-oX", "", "-sT", "-T3", "", "-p-", "-Pn", "127.0.0.1"},
			wantErr:    nil,
		},
		{
			name:       "when_host_discovery_is_enabled_returns_correct_args",
			configFile: "host_discovery_true.textproto",
			target:     "127.0.0.1",
			want:       []string{"-oX", "", "-sT", "-T3", "", "-p-", "", "127.0.0.1"},
			wantErr:    nil,
		},
		{
			name:       "when_version_detection_is_enabled_returns_correct_args",
			configFile: "version_detection_true.textproto",
			target:     "127.0.0.1",
			want:       []string{"-oX", "", "-sT", "-T3", "", "-p-", "-Pn", "-sV", "127.0.0.1"},
			wantErr:    nil,
		},
		{
			name:       "when_version_intensity_is_invalid_returns_default_version_args",
			configFile: "version_intensity_invalid.textproto",
			target:     "127.0.0.1",
			want:       []string{"-oX", "", "-sT", "-T3", "", "-p-", "-Pn", "-sV", "--version-intensity", "5", "127.0.0.1"},
			wantErr:    nil,
		},
		{
			name:       "when_version_intensity_is_zero_returns_omitted_intensity_args",
			configFile: "version_intensity_zero.textproto",
			target:     "127.0.0.1",
			want:       []string{"-oX", "", "-sT", "-T3", "", "-p-", "-Pn", "-sV", "127.0.0.1"},
			wantErr:    nil,
		},
		{
			name:       "when_http_methods_is_enabled_returns_correct_args",
			configFile: "http_methods_true.textproto",
			target:     "127.0.0.1",
			want:       []string{"-oX", "", "-sT", "-T3", "", "-p-", "-Pn", "--script", "http-methods", "127.0.0.1"},
			wantErr:    nil,
		},
		{
			name:       "when_ssl_is_enabled_returns_correct_args",
			configFile: "ssl_true.textproto",
			target:     "127.0.0.1",
			want:       []string{"-oX", "", "-sT", "-T3", "", "-p-", "-Pn", "--script", "ssl-cert", "--script", "ssl-enum-ciphers", "127.0.0.1"},
			wantErr:    nil,
		},
		{
			name:       "when_user_agent_is_provided_returns_correct_args",
			configFile: "default.textproto",
			userAgent:  "test-agent",
			target:     "127.0.0.1",
			want:       []string{"-oX", "", "-sT", "-T3", "", "-p-", "-Pn", "--script-args", "http.useragent=test-agent", "127.0.0.1"},
			wantErr:    nil,
		},
		{
			name:       "when_rate_limit_is_provided_returns_correct_args",
			configFile: "default.textproto",
			rateLimit:  10,
			target:     "127.0.0.1",
			want:       []string{"-oX", "", "-sT", "--max-rate", "10", "-T3", "", "-p-", "-Pn", "127.0.0.1"},
			wantErr:    nil,
		},
		{
			name:       "when_scan_technique_is_unknown_returns_error",
			configFile: "unknown_scan_technique.textproto",
			target:     "127.0.0.1",
			wantErr:    ErrInvalidTechnique,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			globalCfg := cpb.GlobalConfig_builder{
				PortsToScan: tc.ports,
			}
			if tc.rateLimit != 0 {
				globalCfg.Performance = cpb.GlobalConfig_Performance_builder{
					MaxPacketsPerSecond: proto.Int32(tc.rateLimit),
				}.Build()
			}
			if tc.userAgent != "" {
				globalCfg.UserAgent = proto.String(tc.userAgent)
			}

			cfgpb := cpb.Config_builder{
				Clients: cpb.ClientsConfig_builder{
					Nmap: loadNmapConfig(t, tc.configFile),
				}.Build(),
				Globalcfg: globalCfg.Build(),
			}.Build()
			cfg := config.FromProto(cfgpb)
			client := New(cfg)

			got, err := client.CommandLine(context.Background(), tc.target)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("CommandLine(%q) returned error: %v, wantErr: %v", tc.target, err, tc.wantErr)
			}
			if tc.wantErr != nil {
				return
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("CommandLine(%q) returned unexpected diff (-want +got):\n%s", tc.target, diff)
			}
		})
	}
}
