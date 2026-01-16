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
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/goonami-scanner/common/clients/nmap"
	"github.com/google/goonami-scanner/common/testfakes/fakenmap"
	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/module"
	npb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
	rpb "github.com/google/tsunami-security-scanner/proto/go/reconnaissance_go_proto"
	spb "github.com/google/tsunami-security-scanner/proto/go/software_go_proto"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestNew(t *testing.T) {
	config := &config.Config{}
	got, err := New(config)
	if err != nil {
		t.Fatalf("New(%v) failed: %v", config, err)
	}

	if got == nil {
		t.Errorf("New(%v) returned nil", config)
	}
}

func TestScan(t *testing.T) {
	genericNmapErr := errors.New("nmap error")
	testCases := []struct {
		name     string
		client   nmap.Client
		testFile string
		want     *rpb.PortScanningReport
		wantErr  error
	}{
		{
			name:     "endpoint_is_hostname",
			testFile: "endpoint_is_hostname.xml",
			want: rpb.PortScanningReport_builder{
				TargetInfo: rpb.TargetInfo_builder{
					NetworkEndpoints: []*npb.NetworkEndpoint{
						npb.NetworkEndpoint_builder{
							Type:     npb.NetworkEndpoint_HOSTNAME,
							Hostname: npb.Hostname_builder{Name: "localhost"}.Build(),
						}.Build(),
					},
				}.Build(),
			}.Build(),
		},
		{
			name:     "endpoint_is_ip_hostname",
			testFile: "endpoint_is_ip_hostname.xml",
			want: rpb.PortScanningReport_builder{
				TargetInfo: rpb.TargetInfo_builder{
					NetworkEndpoints: []*npb.NetworkEndpoint{
						npb.NetworkEndpoint_builder{
							Type:     npb.NetworkEndpoint_IP_HOSTNAME,
							Hostname: npb.Hostname_builder{Name: "localhost"}.Build(),
							IpAddress: npb.IpAddress_builder{
								Address:       "127.0.0.1",
								AddressFamily: npb.AddressFamily_IPV4,
							}.Build(),
						}.Build(),
					},
				}.Build(),
			}.Build(),
		},
		{
			name:     "endpoint_is_ipv4",
			testFile: "endpoint_is_ipv4.xml",
			want: rpb.PortScanningReport_builder{
				TargetInfo: rpb.TargetInfo_builder{
					NetworkEndpoints: []*npb.NetworkEndpoint{
						npb.NetworkEndpoint_builder{
							Type: npb.NetworkEndpoint_IP,
							IpAddress: npb.IpAddress_builder{
								Address:       "127.0.0.1",
								AddressFamily: npb.AddressFamily_IPV4,
							}.Build(),
						}.Build(),
					},
				}.Build(),
			}.Build(),
		},
		{
			name:     "endpoint_is_ipv6",
			testFile: "endpoint_is_ipv6.xml",
			want: rpb.PortScanningReport_builder{
				TargetInfo: rpb.TargetInfo_builder{
					NetworkEndpoints: []*npb.NetworkEndpoint{
						npb.NetworkEndpoint_builder{
							Type: npb.NetworkEndpoint_IP,
							IpAddress: npb.IpAddress_builder{
								Address:       "::1",
								AddressFamily: npb.AddressFamily_IPV6,
							}.Build(),
						}.Build(),
					},
				}.Build(),
			}.Build(),
		},
		{
			name:     "localhostHttpWithCpe",
			testFile: "localhostHttpWithCpe.xml",
			want: rpb.PortScanningReport_builder{
				TargetInfo: rpb.TargetInfo_builder{
					NetworkEndpoints: []*npb.NetworkEndpoint{
						npb.NetworkEndpoint_builder{
							Type: npb.NetworkEndpoint_IP,
							IpAddress: npb.IpAddress_builder{
								Address:       "127.0.0.1",
								AddressFamily: npb.AddressFamily_IPV4,
							}.Build(),
						}.Build(),
					},
				}.Build(),
				NetworkServices: []*nspb.NetworkService{
					nspb.NetworkService_builder{
						NetworkEndpoint: npb.NetworkEndpoint_builder{
							Type: npb.NetworkEndpoint_IP_PORT,
							IpAddress: npb.IpAddress_builder{
								Address:       "127.0.0.1",
								AddressFamily: npb.AddressFamily_IPV4,
							}.Build(),
							Port: npb.Port_builder{
								PortNumber: 7001,
							}.Build(),
						}.Build(),
						ServiceName:       "http",
						TransportProtocol: npb.TransportProtocol_TCP,
						Cpes:              []string{"cpe:/a:oracle:weblogic_server"},
						Software: spb.Software_builder{
							Name: "Oracle WebLogic admin httpd",
						}.Build(),
					}.Build(),
				},
			}.Build(),
		},
		{
			name:     "localhostHttpsWithSslVersionsAndMethods",
			testFile: "localhostHttpsWithSslVersionsAndMethods.xml",
			want: rpb.PortScanningReport_builder{
				TargetInfo: rpb.TargetInfo_builder{
					NetworkEndpoints: []*npb.NetworkEndpoint{
						npb.NetworkEndpoint_builder{
							Type: npb.NetworkEndpoint_IP,
							IpAddress: npb.IpAddress_builder{
								Address:       "127.0.0.1",
								AddressFamily: npb.AddressFamily_IPV4,
							}.Build(),
						}.Build(),
					},
				}.Build(),
				NetworkServices: []*nspb.NetworkService{
					nspb.NetworkService_builder{
						NetworkEndpoint: npb.NetworkEndpoint_builder{
							Type: npb.NetworkEndpoint_IP_PORT,
							IpAddress: npb.IpAddress_builder{
								Address:       "127.0.0.1",
								AddressFamily: npb.AddressFamily_IPV4,
							}.Build(),
							Port: npb.Port_builder{
								PortNumber: 443,
							}.Build(),
						}.Build(),
						ServiceName:       "http",
						TransportProtocol: npb.TransportProtocol_TCP,
						Cpes:              []string{"cpe:/a:apache:http_server:2.4.56"},
						Software: spb.Software_builder{
							Name: "Apache httpd",
						}.Build(),
						VersionSet: spb.VersionSet_builder{
							Versions: []*spb.Version{
								spb.Version_builder{
									Type:              spb.Version_NORMAL,
									FullVersionString: "2.4.56",
								}.Build(),
							},
						}.Build(),
						SupportedHttpMethods: []string{"POST", "OPTIONS", "HEAD", "GET"},
						SupportedSslVersions: []string{"TLSv1.0", "TLSv1.1", "TLSv1.2"},
					}.Build(),
				},
			}.Build(),
		},
		{
			name:     "service_is_hostname_port_udp",
			testFile: "service_is_hostname_port_udp.xml",
			want: rpb.PortScanningReport_builder{
				TargetInfo: rpb.TargetInfo_builder{
					NetworkEndpoints: []*npb.NetworkEndpoint{
						npb.NetworkEndpoint_builder{
							Type:     npb.NetworkEndpoint_HOSTNAME,
							Hostname: npb.Hostname_builder{Name: "localhost"}.Build(),
						}.Build(),
					},
				}.Build(),
				NetworkServices: []*nspb.NetworkService{
					nspb.NetworkService_builder{
						NetworkEndpoint: npb.NetworkEndpoint_builder{
							Type:     npb.NetworkEndpoint_HOSTNAME_PORT,
							Hostname: npb.Hostname_builder{Name: "localhost"}.Build(),
							Port: npb.Port_builder{
								PortNumber: 80,
							}.Build(),
						}.Build(),
						ServiceName:       "http",
						TransportProtocol: npb.TransportProtocol_UDP,
					}.Build(),
				},
			}.Build(),
		},
		{
			name:     "service_is_ip_hostname_port",
			testFile: "service_is_ip_hostname_port.xml",
			want: rpb.PortScanningReport_builder{
				TargetInfo: rpb.TargetInfo_builder{
					NetworkEndpoints: []*npb.NetworkEndpoint{
						npb.NetworkEndpoint_builder{
							Type:     npb.NetworkEndpoint_IP_HOSTNAME,
							Hostname: npb.Hostname_builder{Name: "localhost"}.Build(),
							IpAddress: npb.IpAddress_builder{
								Address:       "127.0.0.1",
								AddressFamily: npb.AddressFamily_IPV4,
							}.Build(),
						}.Build(),
					},
				}.Build(),
				NetworkServices: []*nspb.NetworkService{
					nspb.NetworkService_builder{
						NetworkEndpoint: npb.NetworkEndpoint_builder{
							Type:     npb.NetworkEndpoint_IP_HOSTNAME_PORT,
							Hostname: npb.Hostname_builder{Name: "localhost"}.Build(),
							IpAddress: npb.IpAddress_builder{
								Address:       "127.0.0.1",
								AddressFamily: npb.AddressFamily_IPV4,
							}.Build(),
							Port: npb.Port_builder{
								PortNumber: 80,
							}.Build(),
						}.Build(),
						ServiceName:       "http",
						TransportProtocol: npb.TransportProtocol_TCP,
					}.Build(),
				},
			}.Build(),
		},
		{
			name:     "service_is_ip_port_tcp",
			testFile: "service_is_ip_port_tcp.xml",
			want: rpb.PortScanningReport_builder{
				TargetInfo: rpb.TargetInfo_builder{
					NetworkEndpoints: []*npb.NetworkEndpoint{
						npb.NetworkEndpoint_builder{
							Type: npb.NetworkEndpoint_IP,
							IpAddress: npb.IpAddress_builder{
								Address:       "127.0.0.1",
								AddressFamily: npb.AddressFamily_IPV4,
							}.Build(),
						}.Build(),
					},
				}.Build(),
				NetworkServices: []*nspb.NetworkService{
					nspb.NetworkService_builder{
						NetworkEndpoint: npb.NetworkEndpoint_builder{
							Type: npb.NetworkEndpoint_IP_PORT,
							IpAddress: npb.IpAddress_builder{
								Address:       "127.0.0.1",
								AddressFamily: npb.AddressFamily_IPV4,
							}.Build(),
							Port: npb.Port_builder{
								PortNumber: 80,
							}.Build(),
						}.Build(),
						ServiceName:       "http",
						TransportProtocol: npb.TransportProtocol_TCP,
					}.Build(),
					nspb.NetworkService_builder{
						NetworkEndpoint: npb.NetworkEndpoint_builder{
							Type: npb.NetworkEndpoint_IP_PORT,
							IpAddress: npb.IpAddress_builder{
								Address:       "127.0.0.1",
								AddressFamily: npb.AddressFamily_IPV4,
							}.Build(),
							Port: npb.Port_builder{
								PortNumber: 9381,
							}.Build(),
						}.Build(),
						ServiceName:       "unknown",
						TransportProtocol: npb.TransportProtocol_TCP,
					}.Build(),
				},
			}.Build(),
		},
		{
			name:     "service_is_unknown_proto_skipped",
			testFile: "service_is_unknown_proto.xml",
			want: rpb.PortScanningReport_builder{
				TargetInfo: rpb.TargetInfo_builder{
					NetworkEndpoints: []*npb.NetworkEndpoint{
						npb.NetworkEndpoint_builder{
							Type: npb.NetworkEndpoint_IP,
							IpAddress: npb.IpAddress_builder{
								Address:       "127.0.0.1",
								AddressFamily: npb.AddressFamily_IPV4,
							}.Build(),
						}.Build(),
					},
				}.Build(),
			}.Build(),
			wantErr: nil,
		},
		{
			name:     "endpoint_is_invalid_ip",
			testFile: "endpoint_is_invalid_ip.xml",
			wantErr:  ErrInvalidAddressType,
		},
		{
			name:     "endpoint_no_hostname_or_ip",
			testFile: "endpoint_no_hostname_or_ip.xml",
			wantErr:  ErrNoAddressOrHostname,
		},
		{
			name:     "host_is_down",
			testFile: "host_is_down.xml",
			want:     nil,
		},
		{
			name:     "multiple_hosts",
			testFile: "multiple_hosts.xml",
			wantErr:  ErrInvalidHostsCount,
		},
		{
			name:    "nmap_error",
			client:  fakenmap.New(nil, genericNmapErr),
			wantErr: genericNmapErr,
		},
		{
			name:    "no_nmap_output",
			client:  fakenmap.New(nil, nil),
			wantErr: ErrNoOutput,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			client := tc.client
			if tc.testFile != "" {
				client, err = fakenmap.FromFile(filepath.Join("testdata", tc.testFile))
				if err != nil {
					t.Fatalf("FromFile(%q) failed: %v", tc.testFile, err)
				}
			}
			m := Module{
				BaseModule: module.NewBaseModule(moduleName),
				client:     client,
			}

			got, err := m.Scan(context.Background(), "target")
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("Scan() error, got: %v, want: %v", err, tc.wantErr)
			}

			if tc.wantErr != nil {
				return
			}

			if diff := cmp.Diff(tc.want, got, protocmp.Transform()); diff != "" {
				t.Errorf("Scan() result mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
