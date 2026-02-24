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

package netutils

import (
	"errors"
	"testing"
)

func TestCallbackURL(t *testing.T) {
	tests := []struct {
		name string
		host string
		port int
		cbid string
		want string
	}{
		{
			name: "when_hostname_returns_http_url",
			host: "localhost",
			port: 8080,
			cbid: "abc",
			want: "http://localhost:8080/abc",
		},
		{
			name: "when_ip_returns_http_url",
			host: "127.0.0.1",
			port: 80,
			cbid: "123",
			want: "http://127.0.0.1:80/123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CallbackURL(tt.host, tt.port, tt.cbid); got != tt.want {
				t.Errorf("CallbackURL() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCallbackDomain(t *testing.T) {
	tests := []struct {
		name    string
		domain  string
		cbid    string
		want    string
		wantErr error
	}{
		{
			name:   "when_domain_returns_domain_with_cbid",
			domain: "example.com",
			cbid:   "abc",
			want:   "abc.example.com",
		},
		{
			name:    "when_ip_address_returns_error",
			domain:  "127.0.0.1",
			cbid:    "abc",
			wantErr: ErrInvalidDomain,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CallbackDomain(tt.cbid, tt.domain)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("CallbackDomain() error = %v, want %v", err, tt.wantErr)
			}

			if tt.wantErr != nil {
				return
			}

			if got != tt.want {
				t.Errorf("CallbackDomain() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIdentifierFromURL(t *testing.T) {
	tests := []struct {
		name    string
		httpURL string
		want    string
		wantErr error
	}{
		{
			name:    "when_valid_url_returns_cbid",
			httpURL: "http://localhost:8080/abc",
			want:    "abc",
		},
		{
			name:    "when_valid_path_only_returns_cbid",
			httpURL: "/abc",
			want:    "abc",
		},
		{
			name:    "when_empty_path_returns_error",
			httpURL: "http://localhost:8080/",
			wantErr: ErrInvalidURL,
		},
		{
			name:    "when_multiple_path_segments_returns_error",
			httpURL: "http://localhost:8080/abc/def",
			wantErr: ErrInvalidURL,
		},
		{
			name:    "when_invalid_url_returns_error",
			httpURL: "http://[::1%lo0]:8080/abc",
			wantErr: ErrFailedToParseURL,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := IdentifierFromURL(tt.httpURL)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("IdentifierFromURL() error = %v, want %v", err, tt.wantErr)
			}

			if tt.wantErr != nil {
				return
			}

			if got != tt.want {
				t.Errorf("IdentifierFromURL() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIdentifierFromDomain(t *testing.T) {
	tests := []struct {
		name    string
		domain  string
		want    string
		wantErr error
	}{
		{
			name:   "when_valid_domain_returns_cbid",
			domain: "abc.example.com",
			want:   "abc",
		},
		{
			name:   "when_valid_domain_with_two_parts_returns_cbid",
			domain: "abc.com",
			want:   "abc",
		},
		{
			name:    "when_no_dot_returns_error",
			domain:  "abc",
			wantErr: ErrInvalidDomain,
		},
		{
			name:    "when_empty_first_part_returns_error",
			domain:  ".example.com",
			wantErr: ErrInvalidDomain,
		},
		{
			name:    "when_ip_address_returns_error",
			domain:  "127.0.0.1",
			wantErr: ErrInvalidDomain,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := IdentifierFromDomain(tt.domain)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("IdentifierFromDomain() error = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("IdentifierFromDomain() unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("IdentifierFromDomain() = %v, want %v", got, tt.want)
			}
		})
	}
}
