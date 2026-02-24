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

package cbid

import (
	"errors"
	"testing"
)

func TestGenerate(t *testing.T) {
	tests := []struct {
		name   string
		secret string
		want   string
	}{
		{
			name:   "when_empty_secret_generates_a_valid_cbid",
			secret: "",
			want:   "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7",
		},
		{
			name:   "when_secret_generates_a_valid_cbid",
			secret: "test_secret",
			want:   "056113bf13f44a3bb49033f04dd8522205f907a0ace19669cbfce486",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := Generate(tt.secret); got != tt.want {
				t.Errorf("Generate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		cbid    string
		wantErr error
	}{
		{
			name: "when_valid_cbid_returns_nil",
			cbid: "056113bf13f44a3bb49033f04dd8522205f907a0ace19669cbfce486",
		},
		{
			name:    "when_invalid_cbid_returns_error",
			cbid:    "invalid_cbid",
			wantErr: ErrInvalidCBID,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := Validate(tt.cbid); !errors.Is(err, tt.wantErr) {
				t.Errorf("Validate() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}
