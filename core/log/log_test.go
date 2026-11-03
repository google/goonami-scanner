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

package log

import (
	"bytes"
	"log"
	"os"
	"testing"

	npb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
)

var buf bytes.Buffer

// Entrypoint of the tests, we hijack the output.
func TestMain(m *testing.M) {
	log.SetOutput(&buf)
	exitCode := m.Run()
	buf.Reset()
	os.Exit(exitCode)
}

func TestDefaultLoggerDebugf(t *testing.T) {
	testCases := []struct {
		name       string
		wantToSee  DebugLevel
		logAtLevel DebugLevel
		wantOutput bool
	}{
		{
			name:       "when_configured_level_equals_log_level_it_outputs",
			wantToSee:  DebugLevelSession,
			logAtLevel: DebugLevelSession,
			wantOutput: true,
		},
		{
			name:       "when_configured_level_is_higher_than_log_level_it_outputs",
			wantToSee:  DebugLevelService,
			logAtLevel: DebugLevelSession,
			wantOutput: true,
		},
		{
			name:       "when_configured_level_is_lower_than_log_level_it_does_not_output",
			wantToSee:  DebugLevelSession,
			logAtLevel: DebugLevelRequest,
			wantOutput: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			buf.Reset()
			l := &DefaultLogger{VerboseLevel: tc.wantToSee}
			const msg = "test message"
			l.DebugContextf(t.Context(), tc.logAtLevel, msg)

			if !tc.wantOutput {
				if buf.Len() > 0 {
					t.Errorf("Debug(%d, %v) returned output, want no output", tc.logAtLevel, msg)
				}

				return
			}

			if tc.wantOutput && buf.Len() == 0 {
				t.Errorf("Debug(%d, %v) returned no message, want message", tc.logAtLevel, msg)
			}
		})
	}
}

func TestDefaultLoggerDebug(t *testing.T) {
	testCases := []struct {
		name       string
		wantToSee  DebugLevel
		logAtLevel DebugLevel
		wantOutput bool
	}{
		{
			name:       "when_configured_level_equals_log_level_it_outputs",
			wantToSee:  DebugLevelSession,
			logAtLevel: DebugLevelSession,
			wantOutput: true,
		},
		{
			name:       "when_configured_level_is_higher_than_log_level_it_outputs",
			wantToSee:  DebugLevelService,
			logAtLevel: DebugLevelSession,
			wantOutput: true,
		},
		{
			name:       "when_configured_level_is_lower_than_log_level_it_does_not_output",
			wantToSee:  DebugLevelSession,
			logAtLevel: DebugLevelRequest,
			wantOutput: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			buf.Reset()
			l := &DefaultLogger{VerboseLevel: tc.wantToSee}
			msg := "test message"
			l.DebugContext(t.Context(), tc.logAtLevel, msg)

			if !tc.wantOutput {
				if buf.Len() > 0 {
					t.Errorf("Debug(%d, %v) returned output, want no output", tc.logAtLevel, msg)
				}

				return
			}

			if tc.wantOutput && buf.Len() == 0 {
				t.Errorf("Debug(%d, %v) returned no message, want message", tc.logAtLevel, msg)
			}
		})
	}
}

func testService(ip string, hostname string, port uint32) *nspb.NetworkService {
	ep := npb.NetworkEndpoint_builder{
		Port: npb.Port_builder{PortNumber: port}.Build(),
	}
	if ip != "" {
		ep.IpAddress = npb.IpAddress_builder{
			Address:       ip,
			AddressFamily: npb.AddressFamily_IPV4,
		}.Build()
	}
	if hostname != "" {
		ep.Hostname = npb.Hostname_builder{Name: hostname}.Build()
	}
	return nspb.NetworkService_builder{
		NetworkEndpoint: ep.Build(),
	}.Build()
}

func TestDefaultLoggerPrefix(t *testing.T) {
	testCases := []struct {
		name       string
		host       string
		module     string
		service    *nspb.NetworkService
		msg        string
		wantPrefix string
		isVuln     bool
	}{
		{
			name:       "when_no_metadata_no_prefix",
			msg:        "test",
			wantPrefix: "INFO test",
		},
		{
			name:       "when_host_metadata_host_prefix",
			host:       "1.2.3.4",
			msg:        "test",
			wantPrefix: "INFO [ 1.2.3.4 ] test",
		},
		{
			name:       "when_hostname_with_underscore_logs_single_bracket",
			host:       "my_app.internal",
			msg:        "test",
			wantPrefix: "INFO [ my_app.internal ] test",
		},
		{
			name:       "when_module_and_host_metadata_both_prefix",
			host:       "1.2.3.4",
			module:     "my-module",
			msg:        "test",
			wantPrefix: "INFO [ 1.2.3.4 ] [ my-module ] test",
		},
		{
			name:       "when_module_metadata_module_prefix",
			module:     "my-module",
			msg:        "test",
			wantPrefix: "INFO [ my-module ] test",
		},
		{
			name:       "when_service_metadata_host_and_service_prefix",
			service:    testService("1.2.3.4", "", 80),
			msg:        "test",
			wantPrefix: "INFO [ 1.2.3.4 ] [    80 ] test",
		},
		{
			name:       "when_service_without_host_metadata_port_only_prefix",
			service:    testService("", "", 8080),
			msg:        "test",
			wantPrefix: "INFO [  8080 ] test",
		},
		{
			name:       "when_both_metadata_host_port_and_module_prefix",
			module:     "my-module",
			service:    testService("1.2.3.4", "", 443),
			msg:        "test",
			wantPrefix: "INFO [ 1.2.3.4 ] [   443 ] [ my-module ] test",
		},
		{
			name:       "when_service_has_ip_and_hostname_logs_both_in_separate_brackets",
			module:     "my-module",
			service:    testService("1.2.3.4", "example.com", 443),
			msg:        "test",
			wantPrefix: "INFO [ 1.2.3.4 ] [ example.com ] [   443 ] [ my-module ] test",
		},
		{
			name:       "when_vuln_level_vuln_prefix",
			msg:        "test",
			wantPrefix: "VULN test",
			isVuln:     true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			buf.Reset()
			ctx := buildTestContext(t.Context(), tc.host, tc.module, tc.service)
			l := &DefaultLogger{}
			if tc.isVuln {
				l.VulnContextf(ctx, "%s", tc.msg)
			} else {
				l.InfoContextf(ctx, "%s", tc.msg)
			}

			got := buf.String()
			if !bytes.Contains([]byte(got), []byte(tc.wantPrefix)) {
				t.Errorf("Log output = %q, want it to contain %q", got, tc.wantPrefix)
			}
		})
	}
}

func TestDefaultLoggerColors(t *testing.T) {
	ctx := ContextForModuleAndService(t.Context(), "my-module", testService("1.2.3.4", "", 443))
	buf.Reset()
	l := &DefaultLogger{UseColors: true}
	l.InfoContext(ctx, "test message")

	got := buf.String()
	// INFO is Bold Blue: \033[1;34m
	if !bytes.Contains([]byte(got), []byte("\033[1;34mINFO\033[0m")) {
		t.Errorf("Log output does not contain expected INFO color: %q", got)
	}
	// Host "1.2.3.4" is Purple: \033[0;35m
	// Brackets should NOT be colored.
	if !bytes.Contains([]byte(got), []byte("[ \033[0;35m1.2.3.4\033[0m ]")) {
		t.Errorf("Log output does not contain expected host color with uncolored brackets: %q", got)
	}
	// Port 443 is Green: \033[0;32m
	// Brackets should NOT be colored.
	if !bytes.Contains([]byte(got), []byte("[ \033[0;32m  443\033[0m ]")) {
		t.Errorf("Log output does not contain expected port color with uncolored brackets: %q", got)
	}
	// Module "my-module" is Cyan: \033[0;36m
	// Brackets should NOT be colored.
	if !bytes.Contains([]byte(got), []byte("[ \033[0;36mmy-module\033[0m ]")) {
		t.Errorf("Log output does not contain expected module color with uncolored brackets: %q", got)
	}
}

func TestDefaultLoggerVulnColors(t *testing.T) {
	ctx := t.Context()
	buf.Reset()
	l := &DefaultLogger{UseColors: true}
	l.VulnContext(ctx, "vuln message")

	got := buf.String()
	// VULN level is Bold Green: \033[1;32m
	if !bytes.Contains([]byte(got), []byte("\033[1;32mVULN\033[0m")) {
		t.Errorf("Log output does not contain expected VULN color: %q", got)
	}
	// Message "vuln message" is Bold Green: \033[1;32m
	if !bytes.Contains([]byte(got), []byte("\033[1;32mvuln message\033[0m")) {
		t.Errorf("Log output does not contain expected colored message: %q", got)
	}
}
