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

package http

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestReadBody(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		maxsize int
		want    []byte
		wantErr error
	}{
		{
			name:    "body_smaller_than_maxsize_is_returned",
			body:    "abc",
			maxsize: 10,
			want:    []byte("abc"),
		},
		{
			name:    "body_equal_to_maxsize_returns_error",
			body:    "abcdefghij",
			maxsize: 10,
			want:    nil,
			wantErr: ErrPageTooBig,
		},
		{
			name:    "body_larger_than_maxsize_returns_error",
			body:    "abcdefghijkl",
			maxsize: 10,
			want:    nil,
			wantErr: ErrPageTooBig,
		},
		{
			name:    "empty_body_returns_eof",
			body:    "",
			maxsize: 10,
			want:    nil,
			wantErr: io.EOF,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := &http.Response{
				Body: io.NopCloser(strings.NewReader(tc.body)),
			}

			actual, err := ReadBody(resp, tc.maxsize)
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("ReadBody() returned error %v, want %v", err, tc.wantErr)
			}

			if tc.wantErr != nil {
				return
			}

			if string(actual) != string(tc.want) {
				t.Errorf("ReadBody() returned %q, expected %q", actual, tc.want)
			}
		})
	}
}
