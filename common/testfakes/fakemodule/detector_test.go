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

package fakemodule

import (
	"errors"
	"testing"
)

func TestInitFakeVulnDetector(t *testing.T) {
	testCases := []struct {
		name    string
		initErr error
		wantErr bool
	}{
		{
			name:    "no_error_returns_fake",
			initErr: nil,
			wantErr: false,
		},
		{
			name:    "with_error_returns_err",
			initErr: errors.New("init error"),
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			initFn := InitFakeVulnDetector("test", tc.initErr)

			if initFn == nil {
				t.Fatalf("InitFakeVulnDetector() returned nil, want init function")
			}

			detector, err := initFn(nil)
			if tc.wantErr {
				if err == nil {
					t.Errorf("InitFakeVulnDetector() init function returned nil error, want non-nil")
				}

				return
			}

			if err != nil {
				t.Fatalf("InitFakeVulnDetector() init function returned error %v, want nil", err)
			}

			fake, ok := detector.(*FakeVulnDetector)
			if !ok {
				t.Fatalf("InitFakeVulnDetector() returned module of type %T, want *FakeVulnDetector", detector)
			}

			if fake.Name() != "test" {
				t.Errorf("InitFakeVulnDetector() created detector with name %q, want %q", detector.Name(), "test")
			}
		})
	}
}
