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
			name:       "configured_level_equals_outputs",
			wantToSee:  DebugLevelSession,
			logAtLevel: DebugLevelSession,
			wantOutput: true,
		},
		{
			name:       "configured_level_higher_outputs",
			wantToSee:  DebugLevelService,
			logAtLevel: DebugLevelSession,
			wantOutput: true,
		},
		{
			name:       "configured_level_lower_no_output",
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
			l.Debugf(tc.logAtLevel, msg)

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
			name:       "configured_level_equals_outputs",
			wantToSee:  DebugLevelSession,
			logAtLevel: DebugLevelSession,
			wantOutput: true,
		},
		{
			name:       "configured_level_higher_outputs",
			wantToSee:  DebugLevelService,
			logAtLevel: DebugLevelSession,
			wantOutput: true,
		},
		{
			name:       "configured_level_lower_no_output",
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
			l.Debug(tc.logAtLevel, msg)

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
