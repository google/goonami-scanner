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

package config

import (
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"

	ncpb "github.com/google/goonami-scanner/common/clients/nmap/nmap_client_config_go_proto"
	cpb "github.com/google/goonami-scanner/core/config/config_go_proto"
	wfcpb "github.com/google/goonami-scanner/plugins/fingerprint/webidentity/webidentity_fp_config_go_proto"
)

func TestApplyOverrides(t *testing.T) {
	tests := []struct {
		name      string
		overrides []string
		want      func() *Config
		wantErr   error
	}{
		{
			name:      "when_overriding_single_string_field",
			overrides: []string{"globalcfg.user_agent=new-agent"},
			want: func() *Config {
				c := Default()
				c.proto.GetGlobalcfg().SetUserAgent("new-agent")
				return c
			},
			wantErr: nil,
		},
		{
			name:      "when_overriding_nested_int_field",
			overrides: []string{"globalcfg.performance.max_concurrency=10"},
			want: func() *Config {
				c := Default()
				c.proto.GetGlobalcfg().GetPerformance().SetMaxConcurrency(10)
				return c
			},
			wantErr: nil,
		},
		{
			name:      "when_overriding_bool_field",
			overrides: []string{"clients.nmap.enable_host_discovery=true"},
			want: func() *Config {
				c := Default()
				c.proto.SetClients(cpb.ClientsConfig_builder{
					Nmap: ncpb.NmapClientConfig_builder{
						EnableHostDiscovery: proto.Bool(true),
					}.Build(),
				}.Build())
				return c
			},
			wantErr: nil,
		},
		{
			name:      "when_overriding_int64_field",
			overrides: []string{"plugins.webidentity.maximum_file_size_bytes=1024"},
			want: func() *Config {
				c := Default()
				c.proto.SetPlugins(cpb.PluginsConfig_builder{
					Webidentity: wfcpb.WebIdentityFpConfig_builder{
						MaximumFileSizeBytes: proto.Int64(1024),
					}.Build(),
				}.Build())
				return c
			},
			wantErr: nil,
		},
		{
			name:      "when_overriding_repeated_field",
			overrides: []string{"globalcfg.ports_to_scan=80,443"},
			want: func() *Config {
				c := Default()
				c.proto.GetGlobalcfg().SetPortsToScan([]uint32{80, 443})
				return c
			},
			wantErr: nil,
		},
		{
			name:      "when_overriding_repeated_field_again_it_truncates",
			overrides: []string{"globalcfg.ports_to_scan=80,443", "globalcfg.ports_to_scan=22"},
			want: func() *Config {
				c := Default()
				c.proto.GetGlobalcfg().SetPortsToScan([]uint32{22})
				return c
			},
			wantErr: nil,
		},
		{
			name:      "when_using_alias",
			overrides: []string{"ports=8080,8081"},
			want: func() *Config {
				c := Default()
				c.proto.GetGlobalcfg().SetPortsToScan([]uint32{8080, 8081})
				return c
			},
			wantErr: nil,
		},
		{
			name:      "when_using_workflow_alias",
			overrides: []string{"portscan=nmap", "fingerprinters.require=fp1,fp2", "fingerprinters.ignore=fp/private.*"},
			want: func() *Config {
				c := Default()
				c.proto.SetWorkflowcfg(cpb.WorkflowConfiguration_builder{
					Portscan: proto.String("nmap"),
					Fingerprinters: cpb.WorkflowConfiguration_ModuleFilter_builder{
						Require: []string{"fp1", "fp2"},
						Ignore:  []string{"fp/private.*"},
					}.Build(),
				}.Build())
				return c
			},
			wantErr: nil,
		},
		{
			name:      "when_multiple_overrides",
			overrides: []string{"globalcfg.user_agent=agent1", "globalcfg.performance.max_concurrency=2"},
			want: func() *Config {
				c := Default()
				c.proto.GetGlobalcfg().SetUserAgent("agent1")
				c.proto.GetGlobalcfg().GetPerformance().SetMaxConcurrency(2)
				return c
			},
			wantErr: nil,
		},
		{
			name:      "when_no_overrides",
			overrides: []string{},
			want: func() *Config {
				return Default()
			},
			wantErr: nil,
		},
		{
			name:      "when_invalid_format_returns_error",
			overrides: []string{"invalid_format"},
			wantErr:   ErrInvalidOverrideFormat,
		},
		{
			name:      "when_field_not_found_returns_error",
			overrides: []string{"non_existing_field=value"},
			wantErr:   ErrFieldNotFound,
		},
		{
			name:      "when_intermediate_field_not_found_returns_error",
			overrides: []string{"globalcfg.non_existing.field=value"},
			wantErr:   ErrFieldNotFound,
		},
		{
			name:      "when_intermediate_field_is_not_a_message_returns_error",
			overrides: []string{"globalcfg.user_agent.something=value"},
			wantErr:   ErrFieldNotMessage,
		},
		{
			name:      "when_invalid_bool_returns_error",
			overrides: []string{"clients.nmap.enable_host_discovery=not-a-bool"},
			wantErr:   ErrConfigUnmarshal,
		},
		{
			name:      "when_invalid_int32_returns_error",
			overrides: []string{"globalcfg.performance.max_concurrency=not-an-int"},
			wantErr:   ErrConfigUnmarshal,
		},
		{
			name:      "when_int32_overflow_returns_error",
			overrides: []string{"globalcfg.performance.max_concurrency=2147483648"},
			wantErr:   ErrConfigUnmarshal,
		},
		{
			name:      "when_invalid_int64_returns_error",
			overrides: []string{"plugins.webidentity.maximum_file_size_bytes=not-an-int"},
			wantErr:   ErrConfigUnmarshal,
		},
		{
			name:      "when_invalid_uint32_returns_error",
			overrides: []string{"globalcfg.ports_to_scan=not-a-uint"},
			wantErr:   ErrConfigUnmarshal,
		},
		{
			name:      "when_uint32_overflow_returns_error",
			overrides: []string{"globalcfg.ports_to_scan=4294967296"},
			wantErr:   ErrConfigUnmarshal,
		},
		{
			name:      "when_unsupported_field_kind_returns_error",
			overrides: []string{"clients.nmap.scan_technique=CONNECT"},
			wantErr:   ErrUnsupportedFieldKind,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Default()
			err := cfg.ApplyOverrides(t.Context(), tt.overrides)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("ApplyOverrides() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr != nil {
				return
			}

			want := tt.want()
			if diff := cmp.Diff(want.proto, cfg.proto, protocmp.Transform()); diff != "" {
				t.Errorf("ApplyOverrides() produced unexpected config (-want +got):\n%s", diff)
			}
		})
	}
}
