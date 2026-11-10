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
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
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

func TestResponseCookies(t *testing.T) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New() failed: %v", err)
	}
	u1, _ := url.Parse("http://example.com/login")
	u2, _ := url.Parse("http://example.com/auth/step")
	u3, _ := url.Parse("http://example.com/dashboard")
	jar.SetCookies(u1, []*http.Cookie{
		{Name: "login_tok", Value: "1", Path: "/login"},
		{Name: "admin_tok", Value: "xyz", Path: "/admin"},
		{Name: "sid", Value: "old", Path: "/"},
	})
	jar.SetCookies(u2, []*http.Cookie{{Name: "sso_state", Value: "ok", Path: "/auth"}})
	jar.SetCookies(u3, []*http.Cookie{{Name: "sid", Value: "new", Path: "/"}})

	redirectResp := &http.Response{
		Request: &http.Request{
			URL: u3,
			Response: &http.Response{
				Request: &http.Request{
					URL:      u2,
					Response: &http.Response{Request: &http.Request{URL: u1}},
				},
			},
		},
	}

	tests := []struct {
		name   string
		jar    http.CookieJar
		reqURL *url.URL
		resp   *http.Response
		want   []string
	}{
		{name: "when_jar_is_nil_returns_nil", reqURL: u1, resp: redirectResp},
		{name: "when_urls_and_resp_are_nil_returns_nil", jar: jar},
		{
			name:   "when_multi_hop_redirect_collects_and_deduplicates_across_all_hops",
			jar:    jar,
			reqURL: u1,
			resp:   redirectResp,
			want:   []string{"sid=new", "sso_state=ok", "login_tok=1"},
		},
		{
			name:   "when_response_sets_cookie_for_disjoint_path_collects_cookie",
			jar:    jar,
			reqURL: u1,
			resp: &http.Response{
				Header: http.Header{"Set-Cookie": []string{"admin_tok=xyz; Path=/admin"}},
			},
			want: []string{"login_tok=1", "sid=new", "admin_tok=xyz"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw := ResponseCookies(tc.jar, tc.reqURL, tc.resp)
			if tc.want == nil {
				if raw != nil {
					t.Errorf("ResponseCookies() = %v, want nil", raw)
				}
				return
			}
			var got []string
			for _, c := range raw {
				got = append(got, c.Name+"="+c.Value)
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("ResponseCookies() diff (-want +got):\n%s", diff)
			}
		})
	}
}
