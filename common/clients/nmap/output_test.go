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
	"encoding/xml"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestParseXMLOutput(t *testing.T) {
	testCases := []struct {
		name string
		file string
		want *OutputXML
	}{
		{
			name: "when_parsing_xml_with_closed_ports_returns_parsed_output",
			file: "testdata/nmapxml/closedTelnet.xml",
			want: &OutputXML{
				XMLName:   xml.Name{Space: "", Local: "nmaprun"},
				Args:      "nmap -n -sS -sV -Pn -O -p 23 --script=banner -oX /tmp/o.xml localhost",
				StartStr:  "Tue Jan 21 16:09:39 2020",
				Version:   "7.80",
				Verbose:   Verbose{Level: 0},
				Debugging: Debugging{Level: 0},
				Hosts: []Host{
					{
						Status: Status{State: "up", Reason: "user-set"},
						Addresses: []Address{
							{Addr: "127.0.0.1", AddrType: "ipv4"},
						},
						Hostnames: Hostnames{
							Hostnames: []Hostname{
								{Name: "localhost", Type: "user"},
							},
						},
						Ports: Ports{
							Ports: []Port{
								{
									Protocol: "tcp",
									PortID:   23,
									State:    State{State: "closed", Reason: "reset"},
									Service:  &Service{Name: "telnet"},
								},
							},
						},
						OS: OS{
							PortsUsed: []PortUsed{
								{State: "closed", Proto: "tcp", PortID: 23},
								{State: "closed", Proto: "udp", PortID: 33264},
							},
						},
						Distance: Distance{Value: 0},
					},
				},
				Runstats: Runstats{
					Finished: Finished{
						Time:    1579619381,
						TimeStr: "Tue Jan 21 16:09:41 2020",
						Summary: "Nmap done at Tue Jan 21 16:09:41 2020; 1 IP address (1 host up) scanned in 2.34 seconds",
					},
				},
			},
		},
		{
			name: "when_parsing_xml_with_hostname_and_open_port_without_scripts_returns_parsed_output",
			file: "testdata/nmapxml/localhostHttp.xml",
			want: &OutputXML{
				XMLName:   xml.Name{Space: "", Local: "nmaprun"},
				Args:      "nmap -p 80 -oX - localhost",
				StartStr:  "Tue Aug 25 17:10:59 2020",
				Version:   "7.80",
				Verbose:   Verbose{Level: 0},
				Debugging: Debugging{Level: 0},
				Hosts: []Host{
					{
						Status: Status{State: "up", Reason: "syn-ack"},
						Addresses: []Address{
							{Addr: "127.0.0.1", AddrType: "ipv4"},
						},
						Hostnames: Hostnames{
							Hostnames: []Hostname{
								{Name: "localhost", Type: "user"},
								{Name: "localhost", Type: "PTR"},
							},
						},
						Ports: Ports{
							Ports: []Port{
								{
									Protocol: "tcp",
									PortID:   80,
									State:    State{State: "open", Reason: "syn-ack"},
									Service:  &Service{Name: "http"},
								},
							},
						},
					},
				},
				Runstats: Runstats{
					Finished: Finished{
						Time:    1598368259,
						TimeStr: "Tue Aug 25 17:10:59 2020",
						Summary: "Nmap done at Tue Aug 25 17:10:59 2020; 1 IP address (1 host up) scanned in 0.03 seconds",
					},
				},
			},
		},
		{
			name: "when_parsing_xml_with_hostname_and_open_port_without_ip_returns_parsed_output",
			file: "testdata/nmapxml/localhostHttpHostnameOnly.xml",
			want: &OutputXML{
				XMLName:   xml.Name{Space: "", Local: "nmaprun"},
				Args:      "nmap -p 80 -oX - localhost",
				StartStr:  "Tue Aug 25 17:10:59 2020",
				Version:   "7.80",
				Verbose:   Verbose{Level: 0},
				Debugging: Debugging{Level: 0},
				Hosts: []Host{
					{
						Status: Status{State: "up", Reason: "syn-ack"},
						Hostnames: Hostnames{
							Hostnames: []Hostname{
								{Name: "localhost", Type: "user"},
								{Name: "localhost", Type: "PTR"},
							},
						},
						Ports: Ports{
							Ports: []Port{
								{
									Protocol: "tcp",
									PortID:   80,
									State:    State{State: "open", Reason: "syn-ack"},
									Service:  &Service{Name: "http"},
								},
							},
						},
					},
				},
				Runstats: Runstats{
					Finished: Finished{
						Time:    1598368259,
						TimeStr: "Tue Aug 25 17:10:59 2020",
						Summary: "Nmap done at Tue Aug 25 17:10:59 2020; 1 IP address (1 host up) scanned in 0.03 seconds",
					},
				},
			},
		},
		{
			name: "when_parsing_xml_with_ip_and_open_port_without_scripts_returns_parsed_output",
			file: "testdata/nmapxml/localhostHttpIpOnly.xml",
			want: &OutputXML{
				XMLName:   xml.Name{Space: "", Local: "nmaprun"},
				Args:      "nmap -p 80 -oX - 127.0.0.1",
				StartStr:  "Tue Aug 25 17:10:59 2020",
				Version:   "7.80",
				Verbose:   Verbose{Level: 0},
				Debugging: Debugging{Level: 0},
				Hosts: []Host{
					{
						Status: Status{State: "up", Reason: "syn-ack"},
						Addresses: []Address{
							{Addr: "127.0.0.1", AddrType: "ipv4"},
						},
						Ports: Ports{
							Ports: []Port{
								{
									Protocol: "tcp",
									PortID:   80,
									State:    State{State: "open", Reason: "syn-ack"},
									Service:  &Service{Name: "http"},
								},
							},
						},
					},
				},
				Runstats: Runstats{
					Finished: Finished{
						Time:    1598368259,
						TimeStr: "Tue Aug 25 17:10:59 2020",
						Summary: "Nmap done at Tue Aug 25 17:10:59 2020; 1 IP address (1 host up) scanned in 0.03 seconds",
					},
				},
			},
		},
		{
			name: "when_parsing_xml_with_ip_and_open_port_with_ssl_tunnel_returns_parsed_output",
			file: "testdata/nmapxml/localhostHttpSslTunnel.xml",
			want: &OutputXML{
				XMLName:   xml.Name{Space: "", Local: "nmaprun"},
				Args:      "nmap -p 80 -oX - 127.0.0.1",
				StartStr:  "Tue Aug 25 17:10:59 2020",
				Version:   "7.80",
				Verbose:   Verbose{Level: 0},
				Debugging: Debugging{Level: 0},
				Hosts: []Host{
					{
						Status: Status{State: "up", Reason: "syn-ack"},
						Addresses: []Address{
							{Addr: "127.0.0.1", AddrType: "ipv4"},
						},
						Ports: Ports{
							Ports: []Port{
								{
									Protocol: "tcp",
									PortID:   443,
									State:    State{State: "open", Reason: "syn-ack"},
									Service:  &Service{Name: "http", Tunnel: "ssl"},
								},
							},
						},
					},
				},
				Runstats: Runstats{
					Finished: Finished{
						Time:    1598368259,
						TimeStr: "Tue Aug 25 17:10:59 2020",
						Summary: "Nmap done at Tue Aug 25 17:10:59 2020; 1 IP address (1 host up) scanned in 0.03 seconds",
					},
				},
			},
		},
		{
			name: "when_parsing_xml_with_ip_and_open_port_with_cpe_returns_parsed_output",
			file: "testdata/nmapxml/localhostHttpWithCpe.xml",
			want: &OutputXML{
				XMLName:   xml.Name{Space: "", Local: "nmaprun"},
				Args:      "nmap --unprivileged -Pn -n -sT -sV --version-intensity 5 -T4 --script banner -p 7001 -oX - 127.0.0.1",
				StartStr:  "Tue May 17 11:21:32 2022",
				Version:   "7.92",
				Verbose:   Verbose{Level: 0},
				Debugging: Debugging{Level: 0},
				Hosts: []Host{
					{
						Status: Status{State: "up", Reason: "user-set"},
						Addresses: []Address{
							{Addr: "127.0.0.1", AddrType: "ipv4"},
						},
						Ports: Ports{
							Ports: []Port{
								{
									Protocol: "tcp",
									PortID:   7001,
									State:    State{State: "open", Reason: "syn-ack"},
									Service: &Service{
										Name:    "http",
										Product: "Oracle WebLogic admin httpd",
										CPE:     []string{"cpe:/a:oracle:weblogic_server"},
									},
								},
							},
						},
					},
				},
				Runstats: Runstats{
					Finished: Finished{
						Time:    1652811716,
						TimeStr: "Tue May 17 11:21:56 2022",
						Summary: "Nmap done at Tue May 17 11:21:56 2022; 1 IP address (1 host up) scanned in 24.21 seconds",
					},
				},
			},
		},
		{
			name: "when_parsing_xml_with_ip_and_http_script_without_methods_returns_parsed_output",
			file: "testdata/nmapxml/localhostHttpWithoutMethods.xml",
			want: &OutputXML{
				XMLName:   xml.Name{Space: "", Local: "nmaprun"},
				Args:      "/usr/bin/nmap --unprivileged -Pn -n -sT -p 8090 -sV --version-intensity 5 -T4 --script banner --script ssl-enum-ciphers --script http-methods -oX /tmp/nmap.report 127.0.0.1",
				StartStr:  "Mon Dec 18 13:53:50 2023",
				Version:   "7.94SVN",
				Verbose:   Verbose{Level: 0},
				Debugging: Debugging{Level: 0},
				Hosts: []Host{
					{
						Status: Status{State: "up", Reason: "user-set"},
						Addresses: []Address{
							{Addr: "127.0.0.1", AddrType: "ipv4"},
						},
						Ports: Ports{
							Ports: []Port{
								{
									Protocol: "tcp",
									PortID:   8090,
									State:    State{State: "open", Reason: "syn-ack"},
									Service:  &Service{Name: "opsmessaging"},
									Scripts: []Script{
										{
											ID: "fingerprint-strings",
											Output: `
  GetRequest: 
    HTTP/1.1 302 
    Cache-Control: no-store
    Expires: Thu, 01 Jan 1970 00:00:00 GMT
    X-Confluence-Request-Time: 1702907641931
    Set-Cookie: JSESSIONID=0A6229AEFA367A5518A89C82008D4999; Path=/; HttpOnly
    X-XSS-Protection: 1; mode=block
    X-Content-Type-Options: nosniff
    X-Frame-Options: SAMEORIGIN
    Content-Security-Policy: frame-ancestors 'self'
    Location: http://localhost:8090/login.action?os_destination=%2Findex.action&permissionViolation=true
    Content-Type: text/html;charset=UTF-8
    Content-Language: en-US
    Content-Length: 0
    Date: Mon, 18 Dec 2023 13:54:01 GMT
    Connection: close
  HTTPOptions: 
    HTTP/1.1 200 
    MS-Author-Via: DAV
    Content-Type: text/html;charset=UTF-8
    Content-Length: 0
    Date: Mon, 18 Dec 2023 13:54:01 GMT
    Connection: close
  RTSPRequest: 
    HTTP/1.1 400 
    Content-Type: text/html;charset=utf-8
    Content-Language: en
    Content-Length: 1925
    Date: Mon, 18 Dec 2023 13:54:01 GMT
    Connection: close
    <!doctype html><html lang="en"><head><title>HTTP Status 400 
    Request</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 400 
    Request</h1><hr class="line" /><p><b>Type</b> Exception Report</p><p><b>Message</b> Invalid character found in the HTTP protocol [RTSP&#47;1.00x0d0x0a0x0d0x0a...]</p><p><b>Description</b> The server cannot or will not process the request due to something that is perceived to be a client error (e.g., malformed request syntax, invalid`,
											Elems: []Elem{
												{
													Key:   "GetRequest",
													Value: "\n    HTTP/1.1 302 \n    Cache-Control: no-store\n    Expires: Thu, 01 Jan 1970 00:00:00 GMT\n    X-Confluence-Request-Time: 1702907641931\n    Set-Cookie: JSESSIONID=0A6229AEFA367A5518A89C82008D4999; Path=/; HttpOnly\n    X-XSS-Protection: 1; mode=block\n    X-Content-Type-Options: nosniff\n    X-Frame-Options: SAMEORIGIN\n    Content-Security-Policy: frame-ancestors 'self'\n    Location: http://localhost:8090/login.action?os_destination=%2Findex.action&permissionViolation=true\n    Content-Type: text/html;charset=UTF-8\n    Content-Language: en-US\n    Content-Length: 0\n    Date: Mon, 18 Dec 2023 13:54:01 GMT\n    Connection: close",
												},
												{
													Key:   "HTTPOptions",
													Value: "\n    HTTP/1.1 200 \n    MS-Author-Via: DAV\n    Content-Type: text/html;charset=UTF-8\n    Content-Length: 0\n    Date: Mon, 18 Dec 2023 13:54:01 GMT\n    Connection: close",
												},
												{
													Key:   "RTSPRequest",
													Value: "\n    HTTP/1.1 400 \n    Content-Type: text/html;charset=utf-8\n    Content-Language: en\n    Content-Length: 1925\n    Date: Mon, 18 Dec 2023 13:54:01 GMT\n    Connection: close\n    <!doctype html><html lang=\"en\"><head><title>HTTP Status 400 \n    Request</title><style type=\"text/css\">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 400 \n    Request</h1><hr class=\"line\" /><p><b>Type</b> Exception Report</p><p><b>Message</b> Invalid character found in the HTTP protocol [RTSP&#47;1.00x0d0x0a0x0d0x0a...]</p><p><b>Description</b> The server cannot or will not process the request due to something that is perceived to be a client error (e.g., malformed request syntax, invalid",
												},
											},
										},
									},
								},
							},
						},
					},
				},
				Runstats: Runstats{
					Finished: Finished{
						Time:    1702907652,
						TimeStr: "Mon Dec 18 13:54:12 2023",
						Summary: "Nmap done at Mon Dec 18 13:54:12 2023; 1 IP address (1 host up) scanned in 21.40 seconds",
					},
				},
			},
		},
		{
			name: "when_parsing_xml_with_ip_and_http_script_without_multi_key_string_returns_parsed_output",
			file: "testdata/nmapxml/localhostHttpWithoutMethodsMultiKeyString.xml",
			want: &OutputXML{
				XMLName:   xml.Name{Space: "", Local: "nmaprun"},
				Args:      "/usr/bin/nmap --unprivileged -Pn -n -sT -p 8090 -sV --version-intensity 5 -T4 --script banner --script ssl-enum-ciphers --script http-methods -oX /tmp/nmap16581034243080856388.report 127.0.0.1",
				StartStr:  "Wed Dec 20 13:51:13 2023",
				Version:   "7.94SVN",
				Verbose:   Verbose{Level: 0},
				Debugging: Debugging{Level: 0},
				Hosts: []Host{
					{
						Status: Status{State: "up", Reason: "user-set"},
						Addresses: []Address{
							{Addr: "127.0.0.1", AddrType: "ipv4"},
						},
						Ports: Ports{
							Ports: []Port{
								{
									Protocol: "tcp",
									PortID:   8090,
									State:    State{State: "open", Reason: "syn-ack"},
									Service:  &Service{Name: "opsmessaging"},
									Scripts: []Script{
										{
											ID: "fingerprint-strings",
											Output: `
  GetRequest, HTTPOptions: 
    HTTP/1.1 302 
    Location: http://localhost:8090/bootstrap/selectsetupstep.action
    Content-Type: text/html;charset=UTF-8
    Content-Length: 0
    Date: Wed, 20 Dec 2023 13:51:25 GMT
    Connection: close
  RPCCheck: 
    HTTP/1.1 400 
    Content-Type: text/html;charset=utf-8
    Content-Language: en
    Content-Length: 2259
    Date: Wed, 20 Dec 2023 13:51:25 GMT
    Connection: close
    <!doctype html><html lang="en"><head><title>HTTP Status 400 
    Request</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 400 
    Request</h1><hr class="line" /><p><b>Type</b> Exception Report</p><p><b>Message</b> Invalid character found in method name [0x800x000x00(r0xfe0x1d0x130x000x000x000x000x000x000x000x020x000x010x860xa00x000x010x97|0x000x000x000x000x000x000x000x000x000x000x000x000x000x000x000x000x000x000x000x00...]. HTTP method names must be tokens</p><p
  RTSPRequest: 
    HTTP/1.1 400 
    Content-Type: text/html;charset=utf-8
    Content-Language: en
    Content-Length: 1925
    Date: Wed, 20 Dec 2023 13:51:25 GMT
    Connection: close
    <!doctype html><html lang="en"><head><title>HTTP Status 400 
    Request</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 400 
    Request</h1><hr class="line" /><p><b>Type</b> Exception Report</p><p><b>Message</b> Invalid character found in the HTTP protocol [RTSP&#47;1.00x0d0x0a0x0d0x0a...]</p><p><b>Description</b> The server cannot or will not process the request due to something that is perceived to be a client error (e.g., malformed request syntax, invalid`,
											Elems: []Elem{
												{
													Key:   "GetRequest, HTTPOptions",
													Value: "\n    HTTP/1.1 302 \n    Location: http://localhost:8090/bootstrap/selectsetupstep.action\n    Content-Type: text/html;charset=UTF-8\n    Content-Length: 0\n    Date: Wed, 20 Dec 2023 13:51:25 GMT\n    Connection: close",
												},
												{
													Key:   "RPCCheck",
													Value: "\n    HTTP/1.1 400 \n    Content-Type: text/html;charset=utf-8\n    Content-Language: en\n    Content-Length: 2259\n    Date: Wed, 20 Dec 2023 13:51:25 GMT\n    Connection: close\n    <!doctype html><html lang=\"en\"><head><title>HTTP Status 400 \n    Request</title><style type=\"text/css\">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 400 \n    Request</h1><hr class=\"line\" /><p><b>Type</b> Exception Report</p><p><b>Message</b> Invalid character found in method name [0x800x000x00(r0xfe0x1d0x130x000x000x000x000x000x000x000x020x000x010x860xa00x000x010x97|0x000x000x000x000x000x000x000x000x000x000x000x000x000x000x000x000x000x000x000x00...]. HTTP method names must be tokens</p><p",
												},
												{
													Key:   "RTSPRequest",
													Value: "\n    HTTP/1.1 400 \n    Content-Type: text/html;charset=utf-8\n    Content-Language: en\n    Content-Length: 1925\n    Date: Wed, 20 Dec 2023 13:51:25 GMT\n    Connection: close\n    <!doctype html><html lang=\"en\"><head><title>HTTP Status 400 \n    Request</title><style type=\"text/css\">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 400 \n    Request</h1><hr class=\"line\" /><p><b>Type</b> Exception Report</p><p><b>Message</b> Invalid character found in the HTTP protocol [RTSP&#47;1.00x0d0x0a0x0d0x0a...]</p><p><b>Description</b> The server cannot or will not process the request due to something that is perceived to be a client error (e.g., malformed request syntax, invalid",
												},
											},
										},
									},
								},
							},
						},
					},
				},
				Runstats: Runstats{
					Finished: Finished{
						Time:    1703080295,
						TimeStr: "Wed Dec 20 13:51:35 2023",
						Summary: "Nmap done at Wed Dec 20 13:51:35 2023; 1 IP address (1 host up) scanned in 21.40 seconds",
					},
				},
			},
		},
		{
			name: "when_parsing_xml_with_ip_and_http_scripts_returns_parsed_output",
			file: "testdata/nmapxml/localhostHttpsWithSslVersionsAndMethods.xml",
			want: &OutputXML{
				XMLName:   xml.Name{Space: "", Local: "nmaprun"},
				Args:      "nmap -sT -nvv -p 443 --script http-methods --script ssl-enum-ciphers -sV -oX /tmp/nmap.report.xml 127.0.0.1",
				StartStr:  "Thu Dec 14 15:05:41 2023",
				Version:   "7.80",
				Verbose:   Verbose{Level: 2},
				Debugging: Debugging{Level: 0},
				Hosts: []Host{
					{
						Status: Status{State: "up", Reason: "syn-ack"},
						Addresses: []Address{
							{Addr: "127.0.0.1", AddrType: "ipv4"},
						},
						Ports: Ports{
							Ports: []Port{
								{
									Protocol: "tcp",
									PortID:   443,
									State:    State{State: "open", Reason: "syn-ack"},
									Service: &Service{
										Name:      "http",
										Product:   "Apache httpd",
										Version:   "2.4.56",
										ExtraInfo: "(Debian)",
										Tunnel:    "ssl",
										CPE:       []string{"cpe:/a:apache:http_server:2.4.56"},
									},
									Scripts: []Script{
										{
											ID:     "http-methods",
											Output: "\n  Supported Methods: POST OPTIONS HEAD GET",
											Tables: []Table{
												{
													Key: "Supported Methods",
													Elems: []Elem{
														{Value: "POST"},
														{Value: "OPTIONS"},
														{Value: "HEAD"},
														{Value: "GET"},
													},
												},
											},
										},
										{
											ID:     "http-server-header",
											Output: "Apache/2.4.56 (Debian)",
											Elems: []Elem{
												{Value: "Apache/2.4.56 (Debian)"},
											},
										},
										{
											ID:     "ssl-enum-ciphers",
											Output: "\n  TLSv1.0: \n    ciphers: \n      TLS_DHE_RSA_WITH_AES_128_CBC_SHA (dh 2048) - A\n      TLS_DHE_RSA_WITH_AES_256_CBC_SHA (dh 2048) - A\n      TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA (dh 2048) - A\n      TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA (dh 2048) - A\n      TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (secp256r1) - A\n      TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (secp256r1) - A\n      TLS_RSA_WITH_AES_128_CBC_SHA (rsa 2048) - A\n      TLS_RSA_WITH_AES_256_CBC_SHA (rsa 2048) - A\n      TLS_RSA_WITH_CAMELLIA_128_CBC_SHA (rsa 2048) - A\n      TLS_RSA_WITH_CAMELLIA_256_CBC_SHA (rsa 2048) - A\n    compressors: \n      NULL\n    cipher preference: client\n  TLSv1.1: \n    ciphers: \n      TLS_DHE_RSA_WITH_AES_128_CBC_SHA (dh 2048) - A\n      TLS_DHE_RSA_WITH_AES_256_CBC_SHA (dh 2048) - A\n      TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA (dh 2048) - A\n      TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA (dh 2048) - A\n      TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (secp256r1) - A\n      TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (secp256r1) - A\n      TLS_RSA_WITH_AES_128_CBC_SHA (rsa 2048) - A\n      TLS_RSA_WITH_AES_256_CBC_SHA (rsa 2048) - A\n      TLS_RSA_WITH_CAMELLIA_128_CBC_SHA (rsa 2048) - A\n      TLS_RSA_WITH_CAMELLIA_256_CBC_SHA (rsa 2048) - A\n    compressors: \n      NULL\n    cipher preference: client\n  TLSv1.2: \n    ciphers: \n      TLS_DHE_RSA_WITH_AES_128_CBC_SHA (dh 2048) - A\n      TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 (dh 2048) - A\n      TLS_DHE_RSA_WITH_AES_128_CCM (dh 2048) - A\n      TLS_DHE_RSA_WITH_AES_128_CCM_8 (dh 2048) - A\n      TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 (dh 2048) - A\n      TLS_DHE_RSA_WITH_AES_256_CBC_SHA (dh 2048) - A\n      TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 (dh 2048) - A\n      TLS_DHE_RSA_WITH_AES_256_CCM (dh 2048) - A\n      TLS_DHE_RSA_WITH_AES_256_CCM_8 (dh 2048) - A\n      TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 (dh 2048) - A\n      TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256 (dh 2048) - A\n      TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384 (dh 2048) - A\n      TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA (dh 2048) - A\n      TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 (dh 2048) - A\n      TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA (dh 2048) - A\n      TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 (dh 2048) - A\n      TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (dh 2048) - A\n      TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (secp256r1) - A\n      TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 (secp256r1) - A\n      TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (secp256r1) - A\n      TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (secp256r1) - A\n      TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 (secp256r1) - A\n      TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (secp256r1) - A\n      TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256 (secp256r1) - A\n      TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384 (secp256r1) - A\n      TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 (secp256r1) - A\n      TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384 (secp256r1) - A\n      TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (secp256r1) - A\n      TLS_RSA_WITH_AES_128_CBC_SHA (rsa 2048) - A\n      TLS_RSA_WITH_AES_128_CBC_SHA256 (rsa 2048) - A\n      TLS_RSA_WITH_AES_128_CCM (rsa 2048) - A\n      TLS_RSA_WITH_AES_128_CCM_8 (rsa 2048) - A\n      TLS_RSA_WITH_AES_128_GCM_SHA256 (rsa 2048) - A\n      TLS_RSA_WITH_AES_256_CBC_SHA (rsa 2048) - A\n      TLS_RSA_WITH_AES_256_CBC_SHA256 (rsa 2048) - A\n      TLS_RSA_WITH_AES_256_CCM (rsa 2048) - A\n      TLS_RSA_WITH_AES_256_CCM_8 (rsa 2048) - A\n      TLS_RSA_WITH_AES_256_GCM_SHA384 (rsa 2048) - A\n      TLS_RSA_WITH_ARIA_128_GCM_SHA256 (rsa 2048) - A\n      TLS_RSA_WITH_ARIA_256_GCM_SHA384 (rsa 2048) - A\n      TLS_RSA_WITH_CAMELLIA_128_CBC_SHA (rsa 2048) - A\n      TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256 (rsa 2048) - A\n      TLS_RSA_WITH_CAMELLIA_256_CBC_SHA (rsa 2048) - A\n      TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256 (rsa 2048) - A\n    compressors: \n      NULL\n    cipher preference: client\n  least strength: A",
											Elems: []Elem{
												{Key: "least strength", Value: "A"},
											},
											Tables: []Table{
												{
													Key: "TLSv1.0",
													Elems: []Elem{
														{Key: "cipher preference", Value: "client"},
													},
													Tables: []Table{
														{
															Key: "ciphers",
															Tables: []Table{
																{Elems: []Elem{{Key: "strength", Value: "A"}, {Key: "kex_info", Value: "dh 2048"}, {Key: "name", Value: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA"}}},
																{Elems: []Elem{{Key: "strength", Value: "A"}, {Key: "kex_info", Value: "dh 2048"}, {Key: "name", Value: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA"}}},
																{Elems: []Elem{{Key: "strength", Value: "A"}, {Key: "kex_info", Value: "dh 2048"}, {Key: "name", Value: "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA"}}},
																{Elems: []Elem{{Key: "strength", Value: "A"}, {Key: "kex_info", Value: "dh 2048"}, {Key: "name", Value: "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA"}}},
																{Elems: []Elem{{Key: "strength", Value: "A"}, {Key: "kex_info", Value: "secp256r1"}, {Key: "name", Value: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"}}},
																{Elems: []Elem{{Key: "strength", Value: "A"}, {Key: "kex_info", Value: "secp256r1"}, {Key: "name", Value: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"}}},
																{Elems: []Elem{{Key: "strength", Value: "A"}, {Key: "kex_info", Value: "rsa 2048"}, {Key: "name", Value: "TLS_RSA_WITH_AES_128_CBC_SHA"}}},
																{Elems: []Elem{{Key: "strength", Value: "A"}, {Key: "kex_info", Value: "rsa 2048"}, {Key: "name", Value: "TLS_RSA_WITH_AES_256_CBC_SHA"}}},
																{Elems: []Elem{{Key: "strength", Value: "A"}, {Key: "kex_info", Value: "rsa 2048"}, {Key: "name", Value: "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA"}}},
																{Elems: []Elem{{Key: "strength", Value: "A"}, {Key: "kex_info", Value: "rsa 2048"}, {Key: "name", Value: "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA"}}},
															},
														},
														{
															Key:   "compressors",
															Elems: []Elem{{Value: "NULL"}},
														},
													},
												},
												{
													Key: "TLSv1.1",
													Elems: []Elem{
														{Key: "cipher preference", Value: "client"},
													},
													Tables: []Table{
														{
															Key: "ciphers",
															Tables: []Table{
																{Elems: []Elem{{Key: "strength", Value: "A"}, {Key: "kex_info", Value: "dh 2048"}, {Key: "name", Value: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA"}}},
																{Elems: []Elem{{Key: "strength", Value: "A"}, {Key: "kex_info", Value: "dh 2048"}, {Key: "name", Value: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA"}}},
																{Elems: []Elem{{Key: "strength", Value: "A"}, {Key: "kex_info", Value: "dh 2048"}, {Key: "name", Value: "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA"}}},
																{Elems: []Elem{{Key: "strength", Value: "A"}, {Key: "kex_info", Value: "dh 2048"}, {Key: "name", Value: "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA"}}},
																{Elems: []Elem{{Key: "strength", Value: "A"}, {Key: "kex_info", Value: "secp256r1"}, {Key: "name", Value: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"}}},
																{Elems: []Elem{{Key: "strength", Value: "A"}, {Key: "kex_info", Value: "secp256r1"}, {Key: "name", Value: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"}}},
																{Elems: []Elem{{Key: "strength", Value: "A"}, {Key: "kex_info", Value: "rsa 2048"}, {Key: "name", Value: "TLS_RSA_WITH_AES_128_CBC_SHA"}}},
																{Elems: []Elem{{Key: "strength", Value: "A"}, {Key: "kex_info", Value: "rsa 2048"}, {Key: "name", Value: "TLS_RSA_WITH_AES_256_CBC_SHA"}}},
																{Elems: []Elem{{Key: "strength", Value: "A"}, {Key: "kex_info", Value: "rsa 2048"}, {Key: "name", Value: "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA"}}},
																{Elems: []Elem{{Key: "strength", Value: "A"}, {Key: "kex_info", Value: "rsa 2048"}, {Key: "name", Value: "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA"}}},
															},
														},
														{
															Key:   "compressors",
															Elems: []Elem{{Value: "NULL"}},
														},
													},
												},
												{
													Key: "TLSv1.2",
													Elems: []Elem{
														{Key: "cipher preference", Value: "client"},
													},
													Tables: []Table{
														{
															Key: "ciphers",
															Tables: []Table{
																{Elems: []Elem{{Key: "strength", Value: "A"}, {Key: "kex_info", Value: "dh 2048"}, {Key: "name", Value: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA"}}},
																{Elems: []Elem{{Key: "strength", Value: "A"}, {Key: "kex_info", Value: "dh 2048"}, {Key: "name", Value: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"}}},
																{Elems: []Elem{{Key: "strength", Value: "A"}, {Key: "kex_info", Value: "dh 2048"}, {Key: "name", Value: "TLS_DHE_RSA_WITH_AES_128_CCM"}}},
																{Elems: []Elem{{Key: "strength", Value: "A"}, {Key: "kex_info", Value: "dh 2048"}, {Key: "name", Value: "TLS_DHE_RSA_WITH_AES_128_CCM_8"}}},
																{Elems: []Elem{{Key: "strength", Value: "A"}, {Key: "kex_info", Value: "dh 2048"}, {Key: "name", Value: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"}}},
																{Elems: []Elem{{Key: "strength", Value: "A"}, {Key: "kex_info", Value: "dh 2048"}, {Key: "name", Value: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA"}}},
																{Elems: []Elem{{Key: "strength", Value: "A"}, {Key: "kex_info", Value: "dh 2048"}, {Key: "name", Value: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"}}},
																{Elems: []Elem{{Key: "strength", Value: "A"}, {Key: "kex_info", Value: "dh 2048"}, {Key: "name", Value: "TLS_DHE_RSA_WITH_AES_256_CCM"}}},
																{Elems: []Elem{{Key: "strength", Value: "A"}, {Key: "kex_info", Value: "dh 2048"}, {Key: "name", Value: "TLS_DHE_RSA_WITH_AES_256_CCM_8"}}},
																{Elems: []Elem{{Key: "strength", Value: "A"}, {Key: "kex_info", Value: "dh 2048"}, {Key: "name", Value: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"}}},
																{Elems: []Elem{{Key: "strength", Value: "A"}, {Key: "kex_info", Value: "dh 2048"}, {Key: "name", Value: "TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256"}}},
																{Elems: []Elem{{Key: "strength", Value: "A"}, {Key: "kex_info", Value: "dh 2048"}, {Key: "name", Value: "TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384"}}},
																{Elems: []Elem{{Key: "strength", Value: "A"}, {Key: "kex_info", Value: "dh 2048"}, {Key: "name", Value: "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA"}}},
																{Elems: []Elem{{Key: "strength", Value: "A"}, {Key: "kex_info", Value: "dh 2048"}, {Key: "name", Value: "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256"}}},
																{Elems: []Elem{{Key: "strength", Value: "A"}, {Key: "kex_info", Value: "dh 2048"}, {Key: "name", Value: "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA"}}},
																{Elems: []Elem{{Key: "strength", Value: "A"}, {Key: "kex_info", Value: "dh 2048"}, {Key: "name", Value: "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256"}}},
																{Elems: []Elem{{Key: "strength", Value: "A"}, {Key: "kex_info", Value: "dh 2048"}, {Key: "name", Value: "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256"}}},
																{Elems: []Elem{{Key: "strength", Value: "A"}, {Key: "kex_info", Value: "secp256r1"}, {Key: "name", Value: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"}}},
																{Elems: []Elem{{Key: "strength", Value: "A"}, {Key: "kex_info", Value: "secp256r1"}, {Key: "name", Value: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"}}},
																{Elems: []Elem{{Key: "strength", Value: "A"}, {Key: "kex_info", Value: "secp256r1"}, {Key: "name", Value: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"}}},
																{Elems: []Elem{{Key: "strength", Value: "A"}, {Key: "kex_info", Value: "secp256r1"}, {Key: "name", Value: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"}}},
																{Elems: []Elem{{Key: "strength", Value: "A"}, {Key: "kex_info", Value: "secp256r1"}, {Key: "name", Value: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"}}},
																{Elems: []Elem{{Key: "strength", Value: "A"}, {Key: "kex_info", Value: "secp256r1"}, {Key: "name", Value: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"}}},
																{Elems: []Elem{{Key: "strength", Value: "A"}, {Key: "kex_info", Value: "secp256r1"}, {Key: "name", Value: "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256"}}},
																{Elems: []Elem{{Key: "strength", Value: "A"}, {Key: "kex_info", Value: "secp256r1"}, {Key: "name", Value: "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384"}}},
																{Elems: []Elem{{Key: "strength", Value: "A"}, {Key: "kex_info", Value: "secp256r1"}, {Key: "name", Value: "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256"}}},
																{Elems: []Elem{{Key: "strength", Value: "A"}, {Key: "kex_info", Value: "secp256r1"}, {Key: "name", Value: "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384"}}},
																{Elems: []Elem{{Key: "strength", Value: "A"}, {Key: "kex_info", Value: "secp256r1"}, {Key: "name", Value: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"}}},
																{Elems: []Elem{{Key: "strength", Value: "A"}, {Key: "kex_info", Value: "rsa 2048"}, {Key: "name", Value: "TLS_RSA_WITH_AES_128_CBC_SHA"}}},
																{Elems: []Elem{{Key: "strength", Value: "A"}, {Key: "kex_info", Value: "rsa 2048"}, {Key: "name", Value: "TLS_RSA_WITH_AES_128_CBC_SHA256"}}},
																{Elems: []Elem{{Key: "strength", Value: "A"}, {Key: "kex_info", Value: "rsa 2048"}, {Key: "name", Value: "TLS_RSA_WITH_AES_128_CCM"}}},
																{Elems: []Elem{{Key: "strength", Value: "A"}, {Key: "kex_info", Value: "rsa 2048"}, {Key: "name", Value: "TLS_RSA_WITH_AES_128_CCM_8"}}},
																{Elems: []Elem{{Key: "strength", Value: "A"}, {Key: "kex_info", Value: "rsa 2048"}, {Key: "name", Value: "TLS_RSA_WITH_AES_128_GCM_SHA256"}}},
																{Elems: []Elem{{Key: "strength", Value: "A"}, {Key: "kex_info", Value: "rsa 2048"}, {Key: "name", Value: "TLS_RSA_WITH_AES_256_CBC_SHA"}}},
																{Elems: []Elem{{Key: "strength", Value: "A"}, {Key: "kex_info", Value: "rsa 2048"}, {Key: "name", Value: "TLS_RSA_WITH_AES_256_CBC_SHA256"}}},
																{Elems: []Elem{{Key: "strength", Value: "A"}, {Key: "kex_info", Value: "rsa 2048"}, {Key: "name", Value: "TLS_RSA_WITH_AES_256_CCM"}}},
																{Elems: []Elem{{Key: "strength", Value: "A"}, {Key: "kex_info", Value: "rsa 2048"}, {Key: "name", Value: "TLS_RSA_WITH_AES_256_CCM_8"}}},
																{Elems: []Elem{{Key: "strength", Value: "A"}, {Key: "kex_info", Value: "rsa 2048"}, {Key: "name", Value: "TLS_RSA_WITH_AES_256_GCM_SHA384"}}},
																{Elems: []Elem{{Key: "strength", Value: "A"}, {Key: "kex_info", Value: "rsa 2048"}, {Key: "name", Value: "TLS_RSA_WITH_ARIA_128_GCM_SHA256"}}},
																{Elems: []Elem{{Key: "strength", Value: "A"}, {Key: "kex_info", Value: "rsa 2048"}, {Key: "name", Value: "TLS_RSA_WITH_ARIA_256_GCM_SHA384"}}},
																{Elems: []Elem{{Key: "strength", Value: "A"}, {Key: "kex_info", Value: "rsa 2048"}, {Key: "name", Value: "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA"}}},
																{Elems: []Elem{{Key: "strength", Value: "A"}, {Key: "kex_info", Value: "rsa 2048"}, {Key: "name", Value: "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256"}}},
																{Elems: []Elem{{Key: "strength", Value: "A"}, {Key: "kex_info", Value: "rsa 2048"}, {Key: "name", Value: "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA"}}},
																{Elems: []Elem{{Key: "strength", Value: "A"}, {Key: "kex_info", Value: "rsa 2048"}, {Key: "name", Value: "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256"}}},
															},
														},
														{
															Key:   "compressors",
															Elems: []Elem{{Value: "NULL"}},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
				Runstats: Runstats{
					Finished: Finished{
						Time:    1702566353,
						TimeStr: "Thu Dec 14 15:05:53 2023",
						Summary: "Nmap done at Thu Dec 14 15:05:53 2023; 1 IP address (1 host up) scanned in 12.71 seconds",
					},
				},
			},
		},
		{
			name: "when_parsing_xml_with_ip_and_open_ssh_port_with_script_returns_parsed_output",
			file: "testdata/nmapxml/localhostSsh.xml",
			want: &OutputXML{
				XMLName:   xml.Name{Space: "", Local: "nmaprun"},
				Args:      "nmap -n -sS -sV -Pn -O -p 22 --script=banner -oX /tmp/o.xml localhost",
				StartStr:  "Tue Jan 21 13:27:43 2020",
				Version:   "7.80",
				Verbose:   Verbose{Level: 0},
				Debugging: Debugging{Level: 0},
				Hosts: []Host{
					{
						Status:    Status{State: "up", Reason: "user-set"},
						Addresses: []Address{{Addr: "127.0.0.1", AddrType: "ipv4"}},
						Hostnames: Hostnames{Hostnames: []Hostname{{Name: "localhost", Type: "user"}}},
						Ports: Ports{
							Ports: []Port{
								{
									Protocol: "tcp",
									PortID:   22,
									State:    State{State: "open", Reason: "syn-ack"},
									Service:  &Service{Name: "ssh", ExtraInfo: "protocol 2.0"},
									Scripts: []Script{
										{ID: "banner", Output: "SSH-2.0-OpenSSH_7.9 MDI-2.0"},
										{ID: "fingerprint-strings", Output: "\n  NULL: \n    SSH-2.0-OpenSSH_7.9 MDI-2.0", Elems: []Elem{{Key: "NULL", Value: "\n    SSH-2.0-OpenSSH_7.9 MDI-2.0"}}},
									},
								},
							},
						},
						OS: OS{
							PortsUsed: []PortUsed{
								{State: "open", Proto: "tcp", PortID: 22},
								{State: "closed", Proto: "udp", PortID: 35070},
							},
							OSMatches: []OSMatch{
								{Name: "ASUS RT-N56U WAP (Linux 3.4)", Accuracy: 98},
								{Name: "Linux 3.1", Accuracy: 98},
								{Name: "Linux 3.16", Accuracy: 98},
								{Name: "Linux 3.2", Accuracy: 98},
								{Name: "AXIS 210A or 211 Network Camera (Linux 2.6.17)", Accuracy: 98},
								{Name: "Linux 3.8", Accuracy: 95},
								{Name: "Linux 2.4.26 (Slackware 10.0.0)", Accuracy: 93},
								{Name: "Asus RT-AC66U router (Linux 2.6)", Accuracy: 92},
								{Name: "Asus RT-N10 router or AXIS 211A Network Camera (Linux 2.6)", Accuracy: 92},
								{Name: "Linux 2.6.18", Accuracy: 92},
							},
						},
						Uptime:   Uptime{Seconds: 1216213, Lastboot: "Tue Jan  7 11:37:42 2020"},
						Distance: Distance{Value: 0},
					},
				},
				Runstats: Runstats{
					Finished: Finished{
						Time:    1579609675,
						TimeStr: "Tue Jan 21 13:27:55 2020",
						Summary: "Nmap done at Tue Jan 21 13:27:55 2020; 1 IP address (1 host up) scanned in 11.78 seconds",
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := os.ReadFile(tc.file)
			if err != nil {
				t.Fatalf("Failed to read test data %q: %v", tc.file, err)
			}

			got, err := ParseXMLOutput(data)
			if err != nil {
				t.Fatalf("ParseXMLOutput(%q) returned an unexpected error: %v", tc.file, err)
			}

			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("ParseXMLOutput(%q) returned diff (-want +got):\n%s", tc.file, diff)
			}
		})
	}
}
