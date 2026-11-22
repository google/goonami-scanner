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

package redisunauth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/module"
	"google.golang.org/protobuf/proto"

	cpb "github.com/google/goonami-scanner/core/config/config_go_proto"
	dpb "github.com/google/tsunami-security-scanner/proto/go/detection_go_proto"
	npb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
	vpb "github.com/google/tsunami-security-scanner/proto/go/vulnerability_go_proto"
)

const (
	// Ephemeral localhost self-signed DER certificate and PKCS#8 key for hermetic TLS unit tests.
	testCertDERBase64 = "MIIDCTCCAfGgAwIBAgIUGfm3yjPm9+clDyU5r8uD8R845hIwDQYJKoZIhvcNAQEL" +
		"BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MTExOTE1MTQxNloXDTM2MTEx" +
		"NjE1MTQxNlowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF" +
		"AAOCAQ8AMIIBCgKCAQEAwlProHM8GPeZhlgM1A+88hHLDnzywQ5fYDpJzNtovqLl" +
		"x2qmo8b50dGrqZEUP//K+b/1EIoWsxA6Rl6seczFlsSMan09p5UDf0pVjBQws5hE" +
		"15MIIaR8q7ADknfEEqYqHVAt2l0sB9aZ4gsHGrGVa51aRLTojVeDGHS3gq8P36re" +
		"OTlcIiyXFFhkSUOHstdzNswrsAV2ejSnYJb2HPMdCZWXL/zU4NrWRFxL1Ifp49os" +
		"qsHI2FgHHD8MD4kVZeT8/65FSlrI2+T4eZM8LQMwC/NS+y6lqEgG7UPevdWPGa5A" +
		"8XvieoDqNzQUVN2O6OLcKt5jTk9kPxxCDjtKM44/BQIDAQABo1MwUTAdBgNVHQ4E" +
		"FgQUM8aOutre534O/fOF42dXXnHBiHswHwYDVR0jBBgwFoAUM8aOutre534O/fOF" +
		"42dXXnHBiHswDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAiQzb" +
		"bnLmIpEhq6l1THnGZXJX6LGUWLyPDtdi5K+j/MK2YRzqDRhC8P9wodeupTXQQ5Wz" +
		"QW6KE9/AIdNEEoBIwaVj2ABI5/nZ1+G9mCJ+PAxnAnMvjZF2FhiM3xy1/+EeVHdB" +
		"Ur0HgRJrIYbfJM6yPPKJln6z+8oezmW4MbDbYpDU03oyWyeaS+t+HmJrf8Slc7Wc" +
		"6Wp0x18geng/BngdglI21+eKT02Yc3dV9a1WmRU0K32/o2HTGxiKvT4fBzHzMfpR" +
		"cmT4i6CERnzIwjq1LM6YtRtcZJXIM0WQ3nU/miFGTejC3umSRtN5poI3aoEeU5it" +
		"kJfTnZ+0JGSJLNqXSQ=="

	testKeyDERBase64 = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDCU+ugczwY95mG" +
		"WAzUD7zyEcsOfPLBDl9gOknM22i+ouXHaqajxvnR0aupkRQ//8r5v/UQihazEDpG" +
		"Xqx5zMWWxIxqfT2nlQN/SlWMFDCzmETXkwghpHyrsAOSd8QSpiodUC3aXSwH1pni" +
		"CwcasZVrnVpEtOiNV4MYdLeCrw/fqt45OVwiLJcUWGRJQ4ey13M2zCuwBXZ6NKdg" +
		"lvYc8x0JlZcv/NTg2tZEXEvUh+nj2iyqwcjYWAccPwwPiRVl5Pz/rkVKWsjb5Ph5" +
		"kzwtAzAL81L7LqWoSAbtQ9691Y8ZrkDxe+J6gOo3NBRU3Y7o4twq3mNOT2Q/HEIO" +
		"O0ozjj8FAgMBAAECggEAAOKrjx78oLmbMtyP9J+gLbbZmJ3Nr1tk6GmdWwZu55Ra" +
		"GVcfHkFdOpfnQSperE5sV0gzrpkcQM/WZQawLw05FQhH5fOmPxnXN0tRPwZQv5qE" +
		"gqwOqpghqRF+THN+P/ArjRDAoEnOgNSjxL70c2MvpNPT4hO0RuOzzNM5/GKBe58E" +
		"YD+RnfpehyuPtDj+Q+FFGuRtmvYg/nFwVoBiIIaYowhQasIdXm2047I3e83WNIcp" +
		"Ang+N7GVEpw4U9dESZCcM5g26BtYk5qhKgMQGYpnqmxjp8mbPk1MBexlAdpbwSnY" +
		"edV8+KUisv36wDAHT4h2v87/APP0jbZx5HQIBqvumwKBgQDn1xiqpCpwnSNAxxIK" +
		"MFFiArTfjE2HMY0G2QQ/A90UvVIhsnhnzpGQGVCwVMbUbKyjPs9v4hB2GzY10T7V" +
		"C6e2G0AkhY2zP3BDdPp180iKyK9f0usF6XRUo1oG3SP0kVcqtI9sPPAl9fNHCckH" +
		"806G4wXp5vDRnsHanM9Qc4DP4wKBgQDWlBbOjX/JmuZHjr2rb8adqXcgdtGk+F06" +
		"wJWnOHjQ8G5qPFXI3GbpbLp8YVTFI1NGAxdul3soP4JvyoVj+skfR+bQ6DXNyJK4" +
		"kGFuHtC1/AO6O7XC+S8mK0OWCMTM/9kWOhjHqk2+qxJxOmi8G1njybUCbOG8A5A6" +
		"kdOVgo2Z9wKBgEyREShqB0oh216tYBvVUUtZMXsSzxfzGWxFh8137S/IRrOySWmf" +
		"IxvAAJH7rZ7CNVHEkKWWt3EKE6E6ddHOg5j07v4gzWeBcAYXQBBsRGzxUloHQm81" +
		"ZqH9QOI7boB675q+/w70ISuoSqwPY0Eo7apGl9Fj3+yazdLxLtaXDteZAoGBAI4r" +
		"pEjKm+ZZyUWUH7sc3f3MMG/ECfdBz5OD0iPvWK0nACFHRJdG4LC8J3sNifrsAtqa" +
		"ZcYSe7kZCzVCe8rYeLVPEHFNyYhE4mGC1+r8Y9CP33Be63j5XPHvLGKWAL7KrWz6" +
		"pTx1a/luo1N+HbK0dIRmOpYWyiGmQsNrp0KiM2vVAoGBAKqVaShiSECqyDG3530E" +
		"4IO/9aT+qNkCtMSLMxPagEMQ6D8l4a7xZnrEqjQMVQHd6ObS0x4IRfeCzxFynImy" +
		"9WL+J1JrhrbELRcloiqHNW4diVsZXWSn8y2PiM0QUdRgYC5wy0143z0abg+kQJQy" +
		"E4M46Y6fj7qVgIOgvoCJAC8v"
)

type fakeServerProfile struct {
	infoReply            string
	protectedConfig      string // "", "no", "yes", "local"
	moduleConfig         string // "", "no", "yes", "local"
	dbfilenameReply      string
	syntheticSetReply    string
	moduleLoadexReply    string
	moduleUnloadReply    string
	closeAfterInfo       bool
	closeAfterDbfilename bool
	stallBeforeReply     time.Duration
	failOnAnyConnection  bool
	useTLS               bool
}

type fakeRedisServer struct {
	listener net.Listener
	port     uint32
	wg       sync.WaitGroup
	mu       sync.Mutex
	conns    map[net.Conn]struct{}
	commands [][]string
	accepted int
}

func startFakeRedisServer(t *testing.T, p fakeServerProfile) *fakeRedisServer {
	t.Helper()
	var ln net.Listener
	var err error
	if p.useTLS {
		certDER, errCert := base64.StdEncoding.DecodeString(testCertDERBase64)
		keyDER, errKey := base64.StdEncoding.DecodeString(testKeyDERBase64)
		if errCert != nil || errKey != nil {
			t.Fatalf("failed decoding test cert/key: %v / %v", errCert, errKey)
		}
		privKey, errParse := x509.ParsePKCS8PrivateKey(keyDER)
		if errParse != nil {
			t.Fatalf("failed parsing PKCS8 key: %v", errParse)
		}
		tlsCfg := &tls.Config{
			Certificates: []tls.Certificate{{
				Certificate: [][]byte{certDER},
				PrivateKey:  privKey,
			}},
		}
		ln, err = tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	} else {
		ln, err = net.Listen("tcp", "127.0.0.1:0")
	}
	if err != nil {
		t.Fatalf("failed starting fake Redis listener: %v", err)
	}

	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", ln.Addr().String(), err)
	}
	portNum, err := strconv.ParseUint(portStr, 10, 32)
	if err != nil {
		t.Fatalf("ParseUint(%q): %v", portStr, err)
	}

	srv := &fakeRedisServer{
		listener: ln,
		port:     uint32(portNum),
		conns:    make(map[net.Conn]struct{}),
	}
	srv.wg.Add(1)
	go srv.serve(p)
	t.Cleanup(func() {
		ln.Close()
		srv.mu.Lock()
		for c := range srv.conns {
			c.Close()
		}
		srv.mu.Unlock()
		srv.wg.Wait()
		if p.failOnAnyConnection && srv.acceptedCount() > 0 {
			t.Errorf("unexpected connection attempt (%d) against skipped service", srv.acceptedCount())
		}
		assertSafeCommands(t, srv.recordedCommands())
	})
	return srv
}

func (s *fakeRedisServer) serve(p fakeServerProfile) {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.accepted++
		if p.failOnAnyConnection {
			s.mu.Unlock()
			conn.Close()
			continue
		}
		s.conns[conn] = struct{}{}
		s.wg.Add(1)
		s.mu.Unlock()
		go s.handleConn(conn, p)
	}
}

func (s *fakeRedisServer) handleConn(conn net.Conn, p fakeServerProfile) {
	defer func() {
		s.mu.Lock()
		delete(s.conns, conn)
		s.mu.Unlock()
		conn.Close()
		s.wg.Done()
	}()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	rr := newRespReader(conn)
	for {
		frame, err := rr.readFrame()
		if err != nil {
			return
		}
		if frame.kind != respArray || len(frame.elements) == 0 {
			return
		}
		cmd := make([]string, len(frame.elements))
		for i, el := range frame.elements {
			cmd[i] = el.text
		}
		s.mu.Lock()
		s.commands = append(s.commands, cmd)
		s.mu.Unlock()

		if p.stallBeforeReply > 0 {
			time.Sleep(p.stallBeforeReply)
		}

		upper0 := strings.ToUpper(cmd[0])
		switch {
		case upper0 == "INFO":
			conn.Write([]byte(p.infoReply))
			if p.closeAfterInfo {
				return
			}
		case upper0 == "CONFIG" && len(cmd) == 3 && strings.EqualFold(cmd[1], "GET"):
			val := ""
			if strings.EqualFold(cmd[2], "enable-protected-configs") {
				val = p.protectedConfig
			} else if strings.EqualFold(cmd[2], "enable-module-command") {
				val = p.moduleConfig
			}
			if val == "-NOPERM" {
				conn.Write([]byte("-NOPERM no permissions for config|get\r\n"))
			} else if val == "" {
				conn.Write([]byte("*0\r\n"))
			} else {
				conn.Write(encodeCommand(strings.ToLower(cmd[2]), val))
			}
		case upper0 == "CONFIG" && len(cmd) == 4 && strings.EqualFold(cmd[1], "SET"):
			if strings.EqualFold(cmd[2], "dbfilename") {
				conn.Write([]byte(p.dbfilenameReply))
				if p.closeAfterDbfilename {
					return
				}
			} else {
				conn.Write([]byte(p.syntheticSetReply))
			}
		case upper0 == "MODULE" && len(cmd) >= 2 && strings.EqualFold(cmd[1], "LOADEX"):
			conn.Write([]byte(p.moduleLoadexReply))
		case upper0 == "MODULE" && len(cmd) >= 2 && strings.EqualFold(cmd[1], "UNLOAD"):
			conn.Write([]byte(p.moduleUnloadReply))
		default:
			conn.Write([]byte("-ERR unexpected command\r\n"))
		}
	}
}

func assertSafeCommands(t *testing.T, commands [][]string) {
	t.Helper()
	for _, cmd := range commands {
		upper0 := strings.ToUpper(cmd[0])
		switch upper0 {
		case "SET", "DEL", "FLUSHDB", "FLUSHALL", "SAVE", "BGSAVE", "SLAVEOF", "REPLICAOF":
			t.Errorf("detector sent mutating command %v", cmd)
		case "CONFIG":
			if len(cmd) >= 4 && strings.EqualFold(cmd[1], "SET") {
				if strings.EqualFold(cmd[2], "dbfilename") && cmd[3] != "a/b" {
					t.Errorf("unsafe CONFIG SET dbfilename value %q", cmd[3])
				} else if !strings.EqualFold(cmd[2], "dbfilename") && cmd[2] != probeName {
					t.Errorf("unsafe CONFIG SET key %q", cmd[2])
				}
			}
		case "MODULE":
			if len(cmd) >= 2 && strings.EqualFold(cmd[1], "LOAD") {
				t.Errorf("detector must not invoke MODULE LOAD directly: %v", cmd)
			}
		}
	}
}

func (s *fakeRedisServer) acceptedCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.accepted
}

func (s *fakeRedisServer) recordedCommands() [][]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([][]string, len(s.commands))
	for i, cmd := range s.commands {
		out[i] = slices.Clone(cmd)
	}
	return out
}

func (s *fakeRedisServer) service(name string) *nspb.NetworkService {
	return nspb.NetworkService_builder{
		NetworkEndpoint: npb.NetworkEndpoint_builder{
			Type: npb.NetworkEndpoint_IP_PORT,
			IpAddress: npb.IpAddress_builder{
				Address:       "127.0.0.1",
				AddressFamily: npb.AddressFamily_IPV4,
			}.Build(),
			Port: npb.Port_builder{PortNumber: s.port}.Build(),
		}.Build(),
		ServiceName:       name,
		TransportProtocol: npb.TransportProtocol_TCP,
	}.Build()
}

func bulkReply(s string) string {
	return fmt.Sprintf("$%d\r\n%s\r\n", len(s), s)
}

func TestNewAndAdvisories(t *testing.T) {
	detectors, err := module.AllDetectors(t.Context(), config.Default())
	if err != nil {
		t.Fatalf("AllDetectors() error = %v", err)
	}
	found := false
	for _, d := range detectors {
		if d.Name() == ModuleName {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("detector %q not registered in DefaultRegistry", ModuleName)
	}

	tests := []struct {
		name        string
		cfg         *config.Config
		wantTimeout time.Duration
	}{
		{
			name:        "when_nil_config_uses_default_timeout",
			cfg:         nil,
			wantTimeout: defaultTimeout,
		},
		{
			name: "when_timeout_configured_uses_configured_timeout",
			cfg: config.FromProto(cpb.Config_builder{
				Globalcfg: cpb.GlobalConfig_builder{
					Performance: cpb.GlobalConfig_Performance_builder{
						TimeoutPerRequestSeconds: proto.Int32(2),
					}.Build(),
				}.Build(),
			}.Build()),
			wantTimeout: 2 * time.Second,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mod, err := New(t.Context(), tc.cfg)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			if got := mod.(*Module).timeout; got != tc.wantTimeout {
				t.Errorf("New().timeout = %v, want %v", got, tc.wantTimeout)
			}

			advisories := mod.Advisories()
			if len(advisories) != 2 {
				t.Fatalf("len(Advisories()) = %d, want 2", len(advisories))
			}
			if advisories[0].GetMainId().GetValue() != rceVulnID || advisories[0].GetSeverity() != vpb.Severity_CRITICAL {
				t.Errorf("advisories[0] = (%s, %v), want (%s, CRITICAL)", advisories[0].GetMainId().GetValue(), advisories[0].GetSeverity(), rceVulnID)
			}
			if advisories[1].GetMainId().GetValue() != readWriteVulnID || advisories[1].GetSeverity() != vpb.Severity_HIGH {
				t.Errorf("advisories[1] = (%s, %v), want (%s, HIGH)", advisories[1].GetMainId().GetValue(), advisories[1].GetSeverity(), readWriteVulnID)
			}
		})
	}
}

func TestDetect_Findings(t *testing.T) {
	tests := []struct {
		name               string
		profile            fakeServerProfile
		serviceName        string
		sslVersions        []string
		wantVulnID         string
		wantSeverity       vpb.Severity
		wantDetailContains string
		forbidCommands     []string
	}{
		{
			name: "when_valkey_8_default_protected_configs_returns_high_read_write",
			profile: fakeServerProfile{
				infoReply:       bulkReply("# Server\r\nredis_version:7.2.4\r\nserver_name:valkey\r\nvalkey_version:8.0.13\r\n"),
				protectedConfig: "no",
				moduleConfig:    "no",
			},
			serviceName:        "valkey",
			wantVulnID:         readWriteVulnID,
			wantSeverity:       vpb.Severity_HIGH,
			wantDetailContains: "Engine: valkey 8.0.13",
			forbidCommands:     []string{"CONFIG SET", "MODULE"},
		},
		{
			name: "when_non_default_port_with_static_nmap_service_name_afs3_fileserver_detects_redis",
			profile: fakeServerProfile{
				infoReply:       bulkReply("# Server\r\nredis_version:7.2.17\r\n"),
				protectedConfig: "no",
				moduleConfig:    "no",
			},
			serviceName:        "afs3-fileserver",
			wantVulnID:         readWriteVulnID,
			wantSeverity:       vpb.Severity_HIGH,
			wantDetailContains: "direct OS RCE gates (protected configs and module loading) are locked",
		},
		{
			name: "when_redis_7_enable_protected_configs_yes_returns_critical_rce",
			profile: fakeServerProfile{
				infoReply:       bulkReply("# Server\r\nredis_version:7.2.17\r\n"),
				protectedConfig: "yes",
				dbfilenameReply: "-ERR CONFIG SET failed (possibly related to argument 'dbfilename') - dbfilename can't be a path, just a filename\r\n",
				moduleConfig:    "no",
			},
			serviceName:        "redis",
			wantVulnID:         rceVulnID,
			wantSeverity:       vpb.Severity_CRITICAL,
			wantDetailContains: "CONFIG SET dir/dbfilename permitted",
		},
		{
			name: "when_redis_7_enable_module_command_yes_returns_critical_rce",
			profile: fakeServerProfile{
				infoReply:         bulkReply("# Server\r\nredis_version:7.2.17\r\n"),
				protectedConfig:   "no",
				moduleConfig:      "yes",
				moduleLoadexReply: "-ERR Error loading the extension. Please check the server logs.\r\n",
			},
			serviceName:        "redis",
			wantVulnID:         rceVulnID,
			wantSeverity:       vpb.Severity_CRITICAL,
			wantDetailContains: "MODULE LOADEX permitted",
		},
		{
			name: "when_redis_6_unprotected_defaults_returns_critical_rce",
			profile: fakeServerProfile{
				infoReply:         bulkReply("# Server\r\nredis_version:6.2.24\r\n"),
				protectedConfig:   "",
				dbfilenameReply:   "-ERR Invalid argument 'a/b' for CONFIG SET 'dbfilename' - dbfilename can't be a path, just a filename\r\n",
				moduleConfig:      "",
				moduleLoadexReply: "-ERR Unknown subcommand or wrong number of arguments for 'LOADEX'. Try MODULE HELP.\r\n",
				moduleUnloadReply: "-ERR Error unloading module: no such module with that name\r\n",
			},
			serviceName:        "redis",
			wantVulnID:         rceVulnID,
			wantSeverity:       vpb.Severity_CRITICAL,
			wantDetailContains: "MODULE LOAD/UNLOAD permitted",
		},
		{
			name: "when_managed_redis_6_blocks_dbfilename_and_module_returns_high_read_write",
			profile: fakeServerProfile{
				infoReply:         bulkReply("# Server\r\nredis_version:6.2.14\r\n"),
				protectedConfig:   "",
				dbfilenameReply:   "-ERR Unsupported CONFIG parameter: dbfilename\r\n",
				moduleConfig:      "",
				moduleLoadexReply: "-ERR unknown command 'MODULE'\r\n",
				moduleUnloadReply: "-ERR unknown command 'MODULE'\r\n",
			},
			serviceName:        "redis",
			wantVulnID:         readWriteVulnID,
			wantSeverity:       vpb.Severity_HIGH,
			wantDetailContains: "direct OS RCE gates (protected configs and module loading) are locked",
		},
		{
			name: "when_redis_7_protected_configs_yes_but_acl_blocks_loadex_even_if_unload_allowed_returns_high",
			profile: fakeServerProfile{
				infoReply:         bulkReply("# Server\r\nredis_version:7.4.1\r\n"),
				protectedConfig:   "-NOPERM",
				dbfilenameReply:   "-NOPERM no permissions to run 'config|set'\r\n",
				moduleConfig:      "-NOPERM",
				moduleLoadexReply: "-NOPERM no permissions to run 'module|loadex'\r\n",
				moduleUnloadReply: "-ERR Error unloading module: no such module with that name\r\n",
			},
			serviceName:    "unknown",
			wantVulnID:     readWriteVulnID,
			wantSeverity:   vpb.Severity_HIGH,
			forbidCommands: []string{"MODULE UNLOAD"},
		},
		{
			name: "when_legacy_redis_3_0_5_uses_synthetic_config_set_without_dbfilename_probe",
			profile: fakeServerProfile{
				infoReply:         bulkReply("# Server\r\nredis_version:3.0.5\r\n"),
				protectedConfig:   "",
				syntheticSetReply: "-ERR Unsupported CONFIG parameter: __tsunami_ro_probe__\r\n",
				moduleConfig:      "",
				moduleLoadexReply: "-ERR unknown command 'MODULE'\r\n",
			},
			serviceName:        "redis",
			wantVulnID:         rceVulnID,
			wantSeverity:       vpb.Severity_CRITICAL,
			wantDetailContains: "Engine: redis 3.0.5",
			forbidCommands:     []string{"CONFIG SET dbfilename", "MODULE UNLOAD"},
		},
		{
			name: "when_tls_valkey_service_negotiates_tls_and_preserves_valid_utf8_excerpt",
			profile: fakeServerProfile{
				infoReply:       bulkReply("# Server\r\nvalkey_version:8.0.1\r\npadding:" + strings.Repeat("a", 470) + strings.Repeat("☃", 5) + "\r\n"),
				protectedConfig: "no",
				moduleConfig:    "no",
				useTLS:          true,
			},
			serviceName:  "unknown",
			sslVersions:  []string{"TLSv1.3"},
			wantVulnID:   readWriteVulnID,
			wantSeverity: vpb.Severity_HIGH,
		},
		{
			name: "when_dragonfly_compatible_engine_skips_dbfilename_set_and_returns_high",
			profile: fakeServerProfile{
				infoReply:         bulkReply("# Server\r\nredis_version:7.2.0\r\ndragonfly_version:df-v1.24.0\r\n"),
				protectedConfig:   "",
				moduleConfig:      "",
				moduleLoadexReply: "-ERR unknown command 'MODULE'\r\n",
				moduleUnloadReply: "-ERR unknown command 'MODULE'\r\n",
			},
			serviceName:        "redis",
			wantVulnID:         readWriteVulnID,
			wantSeverity:       vpb.Severity_HIGH,
			wantDetailContains: "runtime CONFIG SET probe skipped for compatibility engine; module loading gate is locked",
			forbidCommands:     []string{"CONFIG SET"},
		},
		{
			name: "when_legacy_redis_2_8_uses_synthetic_config_set_and_returns_critical",
			profile: fakeServerProfile{
				infoReply:         bulkReply("# Server\r\nredis_version:2.8.19\r\n"),
				protectedConfig:   "",
				syntheticSetReply: "-ERR Unsupported CONFIG parameter: __tsunami_ro_probe__\r\n",
				moduleConfig:      "",
				moduleLoadexReply: "-ERR unknown command 'MODULE'\r\n",
				moduleUnloadReply: "-ERR unknown command 'MODULE'\r\n",
			},
			serviceName:        "redis",
			wantVulnID:         rceVulnID,
			wantSeverity:       vpb.Severity_CRITICAL,
			wantDetailContains: "Engine: redis 2.8.19",
		},
		{
			name: "when_socket_closes_after_dbfilename_rce_confirmed_preserves_critical_rce",
			profile: fakeServerProfile{
				infoReply:            bulkReply("# Server\r\nredis_version:7.2.17\r\n"),
				protectedConfig:      "yes",
				dbfilenameReply:      "-ERR dbfilename can't be a path, just a filename\r\n",
				closeAfterDbfilename: true,
			},
			serviceName:        "redis",
			wantVulnID:         rceVulnID,
			wantSeverity:       vpb.Severity_CRITICAL,
			wantDetailContains: "CONFIG SET dir/dbfilename permitted",
		},
		{
			name: "when_custom_server_name_engine_skips_dbfilename_probe_and_returns_high",
			profile: fakeServerProfile{
				infoReply:         bulkReply("# Server\r\nredis_version:7.0.0\r\nserver_name:redict\r\n"),
				protectedConfig:   "",
				moduleConfig:      "",
				moduleLoadexReply: "-ERR unknown command 'MODULE'\r\n",
			},
			serviceName:        "redis",
			wantVulnID:         readWriteVulnID,
			wantSeverity:       vpb.Severity_HIGH,
			wantDetailContains: "runtime CONFIG SET probe skipped for compatibility engine; module loading gate is locked",
			forbidCommands:     []string{"CONFIG SET"},
		},
		{
			name: "when_socket_closes_after_info_server_still_returns_high_read_write",
			profile: fakeServerProfile{
				infoReply:      bulkReply("# Server\r\nredis_version:7.2.17\r\n"),
				closeAfterInfo: true,
			},
			serviceName:        "redis",
			wantVulnID:         readWriteVulnID,
			wantSeverity:       vpb.Severity_HIGH,
			wantDetailContains: "follow-up OS RCE configuration probes were interrupted before completion",
		},
		{
			name: "when_tls_rediss_service_exposed_negotiates_tls_and_returns_finding",
			profile: fakeServerProfile{
				infoReply:       bulkReply("# Server\r\nredis_version:7.2.17\r\n"),
				protectedConfig: "no",
				moduleConfig:    "no",
				useTLS:          true,
			},
			serviceName:  "rediss",
			sslVersions:  []string{"TLSv1.3"},
			wantVulnID:   readWriteVulnID,
			wantSeverity: vpb.Severity_HIGH,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := startFakeRedisServer(t, tc.profile)
			svc := srv.service(tc.serviceName)
			if len(tc.sslVersions) > 0 {
				svc.SetSupportedSslVersions(tc.sslVersions)
			}

			mod, err := New(t.Context(), nil)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			got, err := mod.Detect(t.Context(), svc)
			if err != nil {
				t.Fatalf("Detect() unexpected error = %v", err)
			}
			if len(got.GetDetectionReports()) != 1 {
				t.Fatalf("len(DetectionReports) = %d, want 1", len(got.GetDetectionReports()))
			}
			report := got.GetDetectionReports()[0]
			if report.GetDetectionStatus() != dpb.DetectionStatus_VULNERABILITY_VERIFIED {
				t.Errorf("DetectionStatus = %v, want VULNERABILITY_VERIFIED", report.GetDetectionStatus())
			}
			vuln := report.GetVulnerability()
			if vuln.GetMainId().GetValue() != tc.wantVulnID {
				t.Errorf("MainId.Value = %q, want %q", vuln.GetMainId().GetValue(), tc.wantVulnID)
			}
			if vuln.GetSeverity() != tc.wantSeverity {
				t.Errorf("Severity = %v, want %v", vuln.GetSeverity(), tc.wantSeverity)
			}
			if len(vuln.GetAdditionalDetails()) != 2 {
				t.Fatalf("len(AdditionalDetails) = %d, want 2", len(vuln.GetAdditionalDetails()))
			}
			if tc.wantDetailContains != "" {
				detail := vuln.GetAdditionalDetails()[0].GetTextData().GetText()
				if !strings.Contains(detail, tc.wantDetailContains) {
					t.Errorf("detail = %q, want substring %q", detail, tc.wantDetailContains)
				}
			}
			if excerpt := vuln.GetAdditionalDetails()[1].GetTextData().GetText(); excerpt == "" {
				t.Errorf("AdditionalDetails[1] (INFO server excerpt) is empty")
			}
			if _, err := proto.Marshal(got); err != nil {
				t.Errorf("proto.Marshal(got) error = %v", err)
			}
			recorded := srv.recordedCommands()
			for _, forbidden := range tc.forbidCommands {
				for _, sent := range recorded {
					joined := strings.ToUpper(strings.Join(sent, " "))
					if strings.HasPrefix(joined, forbidden) {
						t.Errorf("unexpected command %q matching forbidden prefix %q", joined, forbidden)
					}
				}
			}
		})
	}
}

func TestDetect_NegativeAndSkipped(t *testing.T) {
	tests := []struct {
		name    string
		timeout time.Duration
		setup   func(t *testing.T) *nspb.NetworkService
	}{
		{
			name: "when_noauth_returned_returns_no_findings",
			setup: func(t *testing.T) *nspb.NetworkService {
				srv := startFakeRedisServer(t, fakeServerProfile{
					infoReply: "-NOAUTH Authentication required.\r\n",
				})
				return srv.service("redis")
			},
		},
		{
			name: "when_simple_string_honeypot_banner_returned_returns_no_findings",
			setup: func(t *testing.T) *nspb.NetworkService {
				srv := startFakeRedisServer(t, fakeServerProfile{
					infoReply: "+OK redis_version:7.2.0\r\n",
				})
				return srv.service("redis")
			},
		},
		{
			name: "when_non_numeric_version_returned_returns_no_findings",
			setup: func(t *testing.T) *nspb.NetworkService {
				srv := startFakeRedisServer(t, fakeServerProfile{
					infoReply: bulkReply("# Server\r\nredis_version:honeypot\r\n"),
				})
				return srv.service("redis")
			},
		},
		{
			name: "when_ssh_banner_returned_on_non_web_port_returns_no_findings",
			setup: func(t *testing.T) *nspb.NetworkService {
				srv := startFakeRedisServer(t, fakeServerProfile{
					infoReply: "SSH-2.0-OpenSSH_9.2p1\r\n",
				})
				return srv.service("ssh")
			},
		},
		{
			name: "when_web_service_passed_skips_without_connecting",
			setup: func(t *testing.T) *nspb.NetworkService {
				srv := startFakeRedisServer(t, fakeServerProfile{failOnAnyConnection: true})
				svc := srv.service("")
				svc.SetSupportedHttpMethods([]string{"GET"})
				return svc
			},
		},
		{
			name: "when_udp_service_passed_skips_without_connecting",
			setup: func(t *testing.T) *nspb.NetworkService {
				srv := startFakeRedisServer(t, fakeServerProfile{failOnAnyConnection: true})
				svc := srv.service("redis")
				svc.SetTransportProtocol(npb.TransportProtocol_UDP)
				return svc
			},
		},
		{
			name: "when_tls_handshake_against_plaintext_server_fails_returns_no_findings",
			setup: func(t *testing.T) *nspb.NetworkService {
				srv := startFakeRedisServer(t, fakeServerProfile{
					infoReply: "+NON_TLS_BANNER\r\n",
				})
				svc := srv.service("unknown")
				svc.SetSupportedSslVersions([]string{"TLSv1.3"})
				return svc
			},
		},
		{
			name:    "when_per_request_timeout_expires_returns_no_findings",
			timeout: 50 * time.Millisecond,
			setup: func(t *testing.T) *nspb.NetworkService {
				srv := startFakeRedisServer(t, fakeServerProfile{
					infoReply:        bulkReply("# Server\r\nredis_version:7.2.0\r\n"),
					stallBeforeReply: 200 * time.Millisecond,
				})
				return srv.service("unknown")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc := tc.setup(t)
			mod, err := New(t.Context(), nil)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			if tc.timeout > 0 {
				mod.(*Module).timeout = tc.timeout
			}
			got, err := mod.Detect(t.Context(), svc)
			if err != nil {
				t.Fatalf("Detect() unexpected error = %v", err)
			}
			if len(got.GetDetectionReports()) != 0 {
				t.Errorf("len(DetectionReports) = %d, want 0", len(got.GetDetectionReports()))
			}
		})
	}
}

func TestDetect_ContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	srv := startFakeRedisServer(t, fakeServerProfile{failOnAnyConnection: true})
	mod, err := New(t.Context(), nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if _, err := mod.Detect(ctx, srv.service("redis")); err == nil {
		t.Fatalf("Detect() with canceled context = nil, want error")
	}
}
