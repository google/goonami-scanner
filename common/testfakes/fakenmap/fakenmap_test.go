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
	"os"
	"path"
	"testing"

	"github.com/google/goonami-scanner/common/clients/nmap"
)

func TestFromFile(t *testing.T) {
	testCases := []struct {
		name    string
		path    string
		wantErr error
	}{
		{
			name:    "when_file_is_valid_xml_returns_no_error",
			path:    "closedTelnet.xml",
			wantErr: nil,
		},
		{
			name:    "when_file_is_invalid_xml_returns_error",
			path:    "invalid.xml",
			wantErr: nmap.ErrNmapXMLUnmarshal,
		},
		{
			name:    "when_file_does_not_exist_returns_error",
			path:    "path/to/nonexistent.xml",
			wantErr: os.ErrNotExist,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := FromFile(path.Join("testdata", tc.path))
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("FromFile() error = %v, wantErr %v", err, tc.wantErr)
			}

			if tc.wantErr != nil {
				return
			}
		})
	}
}

func TestRun(t *testing.T) {
	testOutput := &nmap.OutputXML{Args: "test"}

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
			wantErr:    nmap.ErrNmapXMLUnmarshal,
		},
		{
			name:       "when_both_output_and_error_are_provided_returns_both",
			wantOutput: testOutput,
			wantErr:    nmap.ErrNmapXMLUnmarshal,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			c := New(tc.wantOutput, tc.wantErr)
			gotOutput, gotErr := c.Run(context.Background(), "unused")
			if !errors.Is(gotErr, tc.wantErr) {
				t.Errorf("Run() error = %v, wantErr %v", gotErr, tc.wantErr)
			}

			if tc.wantErr != nil {
				return
			}

			if gotOutput != tc.wantOutput {
				t.Errorf("Run() output = %v, wantOutput %v", gotOutput, tc.wantOutput)
			}
		})
	}
}
