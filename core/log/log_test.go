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
	"context"
	"log"
	"os"
	"testing"
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
			l.DebugContextf(context.Background(), tc.logAtLevel, msg)

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
			l.DebugContext(context.Background(), tc.logAtLevel, msg)

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

func TestDefaultLoggerPrefix(t *testing.T) {
	testCases := []struct {
		name       string
		ctx        context.Context
		msg        string
		wantPrefix string
	}{
		{
			name:       "when_no_metadata_no_prefix",
			ctx:        context.Background(),
			msg:        "test",
			wantPrefix: "INFO test",
		},
		{
			name:       "when_module_metadata_module_prefix",
			ctx:        ContextForModule(context.Background(), "my-module"),
			msg:        "test",
			wantPrefix: "INFO [ my-module ] test",
		},
		{
			name:       "when_service_metadata_service_prefix",
			ctx:        ContextForService(context.Background(), 80),
			msg:        "test",
			wantPrefix: "INFO [    80 ] test",
		},
		{
			name:       "when_both_metadata_both_prefix",
			ctx:        ContextForModuleAndService(context.Background(), "my-module", 443),
			msg:        "test",
			wantPrefix: "INFO [   443 ] [ my-module ] test",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			buf.Reset()
			l := &DefaultLogger{}
			l.InfoContextf(tc.ctx, "%s", tc.msg)

			got := buf.String()
			if !bytes.Contains([]byte(got), []byte(tc.wantPrefix)) {
				t.Errorf("Infof() = %q, want it to contain %q", got, tc.wantPrefix)
			}
		})
	}
}
