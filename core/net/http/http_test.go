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

	"github.com/google/goonami-scanner/core/config"

	cpb "github.com/google/goonami-scanner/core/config/config_go_proto"
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
			name:    "when_body_is_smaller_than_maxsize_it_is_returned",
			body:    "abc",
			maxsize: 10,
			want:    []byte("abc"),
		},
		{
			name:    "when_body_is_equal_to_maxsize_returns_error",
			body:    "abcdefghij",
			maxsize: 10,
			want:    nil,
			wantErr: ErrPageTooBig,
		},
		{
			name:    "when_body_is_larger_than_maxsize_returns_error",
			body:    "abcdefghijkl",
			maxsize: 10,
			want:    nil,
			wantErr: ErrPageTooBig,
		},
		{
			name:    "when_body_is_empty_returns_eof",
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

type errorReader struct{}

func (errorReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("read error")
}

func TestReadBody_Error(t *testing.T) {
	resp := &http.Response{
		Body: io.NopCloser(errorReader{}),
	}

	_, err := ReadBody(resp, 10)
	if err == nil {
		t.Errorf("ReadBody() returned no error, want error")
	}
}

func TestDefaultClient_Panic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("DefaultClient() did not panic")
		}
	}()

	defaultClient = nil
	DefaultClient()
}

func TestSetDefaultClient(t *testing.T) {
	client := &fakeClient{}
	SetDefaultClient(client)

	if DefaultClient() != client {
		t.Errorf("SetDefaultClient() did not set the client")
	}
}

func TestInitializeDefaults(t *testing.T) {
	cfg := config.FromProto(&cpb.Config{})
	if err := InitializeDefaults(cfg); err != nil {
		t.Fatalf("InitializeDefaults() returned error: %v", err)
	}

	if DefaultClient() == nil {
		t.Errorf("InitializeDefaults() did not set the default client")
	}
}

type fakeClient struct{}

func (f *fakeClient) Do(req *http.Request) (*http.Response, error) {
	return nil, nil
}

func (f *fakeClient) WithCookieJar(jar http.CookieJar) Client {
	return f
}
