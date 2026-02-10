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

package fakenmap

import (
	"context"
	"errors"
	"path"
	"testing"

	"github.com/google/goonami-scanner/common/clients/nmap"
)

func TestFromFile(t *testing.T) {
	testCases := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{
			name:    "when_file_is_valid_xml_returns_no_error",
			path:    "closedTelnet.xml",
			wantErr: false,
		},
		{
			name:    "when_file_is_invalid_xml_returns_error",
			path:    "invalid.xml",
			wantErr: true,
		},
		{
			name:    "when_file_does_not_exist_returns_error",
			path:    "path/to/nonexistent.xml",
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := FromFile(path.Join("testdata", tc.path))

			if (err != nil) != tc.wantErr {
				t.Errorf("FromFile() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestRun(t *testing.T) {
	testOutput := &nmap.OutputXML{Args: "test"}
	testErr := errors.New("test error")

	testCases := []struct {
		name       string
		wantOutput *nmap.OutputXML
		wantErr    error
	}{
		{
			name:       "when_output_is_provided_without_error_returns_output",
			wantOutput: testOutput,
			wantErr:    nil,
		},
		{
			name:       "when_error_is_provided_without_output_returns_error",
			wantOutput: nil,
			wantErr:    testErr,
		},
		{
			name:       "when_both_output_and_error_are_provided_returns_both",
			wantOutput: testOutput,
			wantErr:    testErr,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			c := New(tc.wantOutput, tc.wantErr)
			gotOutput, gotErr := c.Run(context.Background(), "unused")

			if gotOutput != tc.wantOutput {
				t.Errorf("Run() output = %v, wantOutput %v", gotOutput, tc.wantOutput)
			}
			if gotErr != tc.wantErr {
				t.Errorf("Run() error = %v, wantErr %v", gotErr, tc.wantErr)
			}
		})
	}
}
