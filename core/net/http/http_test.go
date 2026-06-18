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
	"google.golang.org/protobuf/proto"

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

func TestRegisterAndNewClient(t *testing.T) {
	cfg := config.Default()
	_, err := NewClient(cfg)
	if err == nil {
		t.Errorf("NewClient(default) with no simpleclient registered did not return error")
	}

	Register("simpleclient", func(cfg *config.Config) (Client, error) {
		return &fakeClient{}, nil
	})

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient(default) returned error: %v", err)
	}
	if client == nil {
		t.Errorf("NewClient(default) returned nil client")
	}

	customCfg := config.FromProto(cpb.Config_builder{
		Globalcfg: cpb.GlobalConfig_builder{
			HttpClient: proto.String("unknown-client"),
		}.Build(),
	}.Build())
	_, err = NewClient(customCfg)
	if err == nil {
		t.Errorf("NewClient with unknown client did not return error")
	}

	Register("custom", func(cfg *config.Config) (Client, error) {
		return &fakeClient{}, nil
	})
	customCfg = config.FromProto(cpb.Config_builder{
		Globalcfg: cpb.GlobalConfig_builder{
			HttpClient: proto.String("custom"),
		}.Build(),
	}.Build())
	client, err = NewClient(customCfg)
	if err != nil {
		t.Fatalf("NewClient(custom) returned error: %v", err)
	}
	if _, ok := client.(*fakeClient); !ok {
		t.Errorf("NewClient(custom) did not return fakeClient")
	}
}

type fakeClient struct{}

func (f *fakeClient) Do(req *http.Request) (*http.Response, error) {
	return nil, nil
}
