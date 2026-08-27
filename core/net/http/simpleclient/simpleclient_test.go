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

package simpleclient

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/goonami-scanner/core/config"
	goohttp "github.com/google/goonami-scanner/core/net/http"
	"golang.org/x/time/rate"
	"google.golang.org/protobuf/proto"

	cpb "github.com/google/goonami-scanner/core/config/config_go_proto"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name      string
		cfg       *config.Config
		options   *goohttp.ClientOptions
		wantLimit rate.Limit
		wantBurst int
		wantErr   error
	}{
		{
			name:      "when_config_is_nil_returns_error",
			cfg:       nil,
			options:   nil,
			wantLimit: 0,
			wantBurst: 0,
			wantErr:   ErrConfigNil,
		},
		{
			name: "when_max_requests_per_second_is_ten_returns_limiter_with_ten_qps",
			cfg: config.FromProto(cpb.Config_builder{
				Globalcfg: cpb.GlobalConfig_builder{
					Performance: cpb.GlobalConfig_Performance_builder{
						MaxHttpRequestsPerSecond: proto.Int32(10),
					}.Build(),
				}.Build(),
			}.Build()),
			options:   nil,
			wantLimit: 10,
			wantBurst: 10,
			wantErr:   nil,
		},
		{
			name: "when_max_requests_per_second_is_zero_returns_unlimited_limiter",
			cfg: config.FromProto(cpb.Config_builder{
				Globalcfg: cpb.GlobalConfig_builder{
					Performance: cpb.GlobalConfig_Performance_builder{
						MaxHttpRequestsPerSecond: proto.Int32(0),
					}.Build(),
				}.Build(),
			}.Build()),
			options:   nil,
			wantLimit: rate.Inf,
			wantBurst: 0,
			wantErr:   nil,
		},
		{
			name: "when_store_cookies_is_true_sets_cookie_jar",
			cfg: config.FromProto(cpb.Config_builder{
				Globalcfg: cpb.GlobalConfig_builder{
					Performance: cpb.GlobalConfig_Performance_builder{
						MaxHttpRequestsPerSecond: proto.Int32(0),
					}.Build(),
				}.Build(),
			}.Build()),
			options:   &goohttp.ClientOptions{StoreCookies: true},
			wantLimit: rate.Inf,
			wantBurst: 0,
			wantErr:   nil,
		},
		{
			name: "when_store_cookies_is_false_does_not_set_cookie_jar",
			cfg: config.FromProto(cpb.Config_builder{
				Globalcfg: cpb.GlobalConfig_builder{
					Performance: cpb.GlobalConfig_Performance_builder{
						MaxHttpRequestsPerSecond: proto.Int32(0),
					}.Build(),
				}.Build(),
			}.Build()),
			options:   &goohttp.ClientOptions{StoreCookies: false},
			wantLimit: rate.Inf,
			wantBurst: 0,
			wantErr:   nil,
		},
		{
			name: "when_enforce_tls_cert_verification_is_true_insecure_skip_verify_is_false",
			cfg: config.FromProto(cpb.Config_builder{
				Globalcfg: cpb.GlobalConfig_builder{
					Performance: cpb.GlobalConfig_Performance_builder{
						MaxHttpRequestsPerSecond: proto.Int32(0),
					}.Build(),
				}.Build(),
			}.Build()),
			options:   &goohttp.ClientOptions{EnforceTLSCertVerification: true},
			wantLimit: rate.Inf,
			wantBurst: 0,
			wantErr:   nil,
		},
		{
			name: "when_enforce_tls_cert_verification_is_false_insecure_skip_verify_is_true",
			cfg: config.FromProto(cpb.Config_builder{
				Globalcfg: cpb.GlobalConfig_builder{
					Performance: cpb.GlobalConfig_Performance_builder{
						MaxHttpRequestsPerSecond: proto.Int32(0),
					}.Build(),
				}.Build(),
			}.Build()),
			options:   &goohttp.ClientOptions{EnforceTLSCertVerification: false},
			wantLimit: rate.Inf,
			wantBurst: 0,
			wantErr:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := tt.options
			if opts == nil {
				opts = goohttp.DefaultClientOptions()
			}
			c, err := New(tt.cfg, opts)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr != nil {
				return
			}

			if c.limiter.Limit() != tt.wantLimit {
				t.Errorf("New() limit = %v, wantLimit %v", c.limiter.Limit(), tt.wantLimit)
			}

			if c.limiter.Burst() != tt.wantBurst {
				t.Errorf("New() burst = %v, wantBurst %v", c.limiter.Burst(), tt.wantBurst)
			}

			if opts.StoreCookies && c.client.Jar == nil {
				t.Errorf("New() client.Jar is nil, want cookie jar")
			} else if !opts.StoreCookies && c.client.Jar != nil {
				t.Errorf("New() client.Jar is not nil, want no cookie jar")
			}

			transport, ok := c.client.Transport.(*http.Transport)
			if !ok {
				t.Fatalf("New() client.Transport is not an *http.Transport")
			}
			if transport.TLSClientConfig == nil {
				t.Fatalf("New() client.Transport.TLSClientConfig is nil")
			}
			wantInsecureSkipVerify := !opts.EnforceTLSCertVerification
			if transport.TLSClientConfig.InsecureSkipVerify != wantInsecureSkipVerify {
				t.Errorf("New() InsecureSkipVerify = %v, want %v", transport.TLSClientConfig.InsecureSkipVerify, wantInsecureSkipVerify)
			}
		})
	}
}

func TestDoWithoutRateLimit(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := config.FromProto(cpb.Config_builder{
		Globalcfg: cpb.GlobalConfig_builder{
			Performance: cpb.GlobalConfig_Performance_builder{
				MaxHttpRequestsPerSecond: proto.Int32(0),
			}.Build(),
		}.Build(),
	}.Build())

	c, err := New(cfg, goohttp.DefaultClientOptions())
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	req, err := http.NewRequest("GET", ts.URL, nil)
	if err != nil {
		t.Fatalf("http.NewRequest() failed: %v", err)
	}

	resp, err := c.Do(req)
	if err != nil {
		t.Errorf("Do() failed: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Do() status = %v, want %v", resp.StatusCode, http.StatusOK)
	}
}

func TestDo_ContextCancelled(t *testing.T) {
	cfg := config.FromProto(cpb.Config_builder{
		Globalcfg: cpb.GlobalConfig_builder{
			Performance: cpb.GlobalConfig_Performance_builder{
				MaxHttpRequestsPerSecond: proto.Int32(1),
			}.Build(),
		}.Build(),
	}.Build())

	c, err := New(cfg, goohttp.DefaultClientOptions())
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	req, _ := http.NewRequestWithContext(ctx, "GET", "http://localhost", nil)
	_, err = c.Do(req)

	if err == nil {
		t.Errorf("Do() returned no error, want error")
	}
}

func TestDo_StoreCookies(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/set":
			http.SetCookie(w, &http.Cookie{Name: "foo", Value: "bar"})
			w.WriteHeader(http.StatusOK)
		case "/get":
			cookie, err := r.Cookie("foo")
			if err != nil || cookie.Value != "bar" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	tests := []struct {
		name       string
		options    *goohttp.ClientOptions
		wantStatus int
	}{
		{
			name:       "when_store_cookies_is_true_sends_cookies_back",
			options:    &goohttp.ClientOptions{StoreCookies: true},
			wantStatus: http.StatusOK,
		},
		{
			name:       "when_store_cookies_is_false_does_not_send_cookies_back",
			options:    &goohttp.ClientOptions{StoreCookies: false},
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.FromProto(cpb.Config_builder{
				Globalcfg: cpb.GlobalConfig_builder{
					Performance: cpb.GlobalConfig_Performance_builder{
						MaxHttpRequestsPerSecond: proto.Int32(0),
					}.Build(),
				}.Build(),
			}.Build())

			c, err := New(cfg, tt.options)
			if err != nil {
				t.Fatalf("New() failed: %v", err)
			}

			// First request to set the cookie
			setReq, err := http.NewRequest("GET", ts.URL+"/set", nil)
			if err != nil {
				t.Fatalf("http.NewRequest() /set failed: %v", err)
			}
			setResp, err := c.Do(setReq)
			if err != nil {
				t.Fatalf("Do() /set failed: %v", err)
			}
			setResp.Body.Close()
			if setResp.StatusCode != http.StatusOK {
				t.Fatalf("Do() /set status = %d, want %d", setResp.StatusCode, http.StatusOK)
			}

			// Second request to check if cookie is sent back
			getReq, err := http.NewRequest("GET", ts.URL+"/get", nil)
			if err != nil {
				t.Fatalf("http.NewRequest() /get failed: %v", err)
			}
			getResp, err := c.Do(getReq)
			if err != nil {
				t.Fatalf("Do() /get failed: %v", err)
			}
			getResp.Body.Close()

			if getResp.StatusCode != tt.wantStatus {
				t.Errorf("Do() /get status = %d, want %d", getResp.StatusCode, tt.wantStatus)
			}
		})
	}
}

func TestDo_TLSVerification(t *testing.T) {
	// httptest.NewTLSServer starts a server with a self-signed TLS certificate.
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	tests := []struct {
		name    string
		options *goohttp.ClientOptions
		wantErr bool
	}{
		{
			name:    "when_enforce_tls_cert_verification_is_true_returns_error",
			options: &goohttp.ClientOptions{EnforceTLSCertVerification: true},
			wantErr: true,
		},
		{
			name:    "when_enforce_tls_cert_verification_is_false_succeeds",
			options: &goohttp.ClientOptions{EnforceTLSCertVerification: false},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.FromProto(cpb.Config_builder{
				Globalcfg: cpb.GlobalConfig_builder{
					Performance: cpb.GlobalConfig_Performance_builder{
						MaxHttpRequestsPerSecond: proto.Int32(0),
					}.Build(),
				}.Build(),
			}.Build())

			c, err := New(cfg, tt.options)
			if err != nil {
				t.Fatalf("New() failed: %v", err)
			}

			req, err := http.NewRequest("GET", ts.URL, nil)
			if err != nil {
				t.Fatalf("http.NewRequest() failed: %v", err)
			}

			resp, err := c.Do(req)
			if (err != nil) != tt.wantErr {
				t.Errorf("Do() error = %v, wantErr %v", err, tt.wantErr)
			}
			if resp != nil {
				resp.Body.Close()
			}
		})
	}
}

func TestDo_DisableFollowRedirects(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/destination", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	tests := []struct {
		name                   string
		disableFollowRedirects bool
		wantStatus             int
	}{
		{
			name:                   "when_disable_follow_redirects_is_true_returns_redirect_status",
			disableFollowRedirects: true,
			wantStatus:             http.StatusFound,
		},
		{
			name:                   "when_disable_follow_redirects_is_false_returns_ok_status",
			disableFollowRedirects: false,
			wantStatus:             http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.FromProto(cpb.Config_builder{
				Globalcfg: cpb.GlobalConfig_builder{
					Performance: cpb.GlobalConfig_Performance_builder{
						MaxHttpRequestsPerSecond: proto.Int32(0),
					}.Build(),
				}.Build(),
			}.Build())

			opts := &goohttp.ClientOptions{
				DisableFollowRedirects: tt.disableFollowRedirects,
			}
			c, err := New(cfg, opts)
			if err != nil {
				t.Fatalf("New() failed: %v", err)
			}

			req, err := http.NewRequest("GET", ts.URL+"/redirect", nil)
			if err != nil {
				t.Fatalf("http.NewRequest() failed: %v", err)
			}

			resp, err := c.Do(req)
			if err != nil {
				t.Fatalf("Do() failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tt.wantStatus {
				t.Errorf("Do() status = %d, want %d", resp.StatusCode, tt.wantStatus)
			}
		})
	}
}

func TestDo_MaxRedirects(t *testing.T) {
	redirectCount := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectCount++
		http.Redirect(w, r, "/loop", http.StatusFound)
	}))
	defer ts.Close()

	tests := []struct {
		name          string
		maxRedirects  *int32
		expectedCount int
	}{
		{
			name:          "when_default_stops_after_10_redirects",
			maxRedirects:  nil,
			expectedCount: 10,
		},
		{
			name:          "when_custom_max_redirects_stops_after_configured_count",
			maxRedirects:  proto.Int32(3),
			expectedCount: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			redirectCount = 0

			perfBuilder := cpb.GlobalConfig_Performance_builder{
				MaxHttpRequestsPerSecond: proto.Int32(0),
			}
			if tt.maxRedirects != nil {
				perfBuilder.MaxHttpRedirects = tt.maxRedirects
			}

			cfg := config.FromProto(cpb.Config_builder{
				Globalcfg: cpb.GlobalConfig_builder{
					Performance: perfBuilder.Build(),
				}.Build(),
			}.Build())

			c, err := New(cfg, nil)
			if err != nil {
				t.Fatalf("New() failed: %v", err)
			}

			req, err := http.NewRequest("GET", ts.URL+"/loop", nil)
			if err != nil {
				t.Fatalf("http.NewRequest() failed: %v", err)
			}

			resp, err := c.Do(req)
			if err == nil {
				if resp != nil {
					resp.Body.Close()
				}
				t.Fatalf("Do() expected error on redirect loop, got nil")
			}

			if !errors.Is(err, ErrTooManyRedirects) {
				t.Errorf("Do() error = %v, want error matching ErrTooManyRedirects", err)
			}

			if redirectCount != tt.expectedCount {
				t.Errorf("redirectCount = %d, want %d", redirectCount, tt.expectedCount)
			}
		})
	}
}

func TestDo_AllowedAuthorities(t *testing.T) {
	// External server that should not be reached if out-of-scope redirect is not followed
	externalVisited := false
	externalServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		externalVisited = true
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("external content"))
	}))
	defer externalServer.Close()

	// In-scope server that redirects
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redirect_in_scope":
			http.Redirect(w, r, "/destination", http.StatusFound)
		case "/redirect_out_of_scope":
			http.Redirect(w, r, externalServer.URL+"/external", http.StatusFound)
		case "/destination":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("in-scope destination"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer targetServer.Close()

	targetURL, _ := url.Parse(targetServer.URL)
	targetAuthority := targetURL.Host

	tests := []struct {
		name                string
		requestPath         string
		allowedAuthorities  []string
		wantStatus          int
		wantBody            string
		wantExternalVisited bool
	}{
		{
			name:                "when_redirect_in_scope_follows_redirect",
			requestPath:         "/redirect_in_scope",
			allowedAuthorities:  []string{targetAuthority},
			wantStatus:          http.StatusOK,
			wantBody:            "in-scope destination",
			wantExternalVisited: false,
		},
		{
			name:                "when_redirect_out_of_scope_stops_and_returns_redirect_response",
			requestPath:         "/redirect_out_of_scope",
			allowedAuthorities:  []string{targetAuthority},
			wantStatus:          http.StatusFound,
			wantExternalVisited: false,
		},
		{
			name:                "when_allowed_authorities_empty_follows_external_redirect",
			requestPath:         "/redirect_out_of_scope",
			allowedAuthorities:  nil,
			wantStatus:          http.StatusOK,
			wantBody:            "external content",
			wantExternalVisited: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			externalVisited = false

			cfg := config.FromProto(cpb.Config_builder{
				Globalcfg: cpb.GlobalConfig_builder{
					Performance: cpb.GlobalConfig_Performance_builder{
						MaxHttpRequestsPerSecond: proto.Int32(0),
					}.Build(),
				}.Build(),
			}.Build())

			opts := &goohttp.ClientOptions{
				AllowedAuthorities: tt.allowedAuthorities,
			}
			c, err := New(cfg, opts)
			if err != nil {
				t.Fatalf("New() failed: %v", err)
			}

			req, err := http.NewRequest("GET", targetServer.URL+tt.requestPath, nil)
			if err != nil {
				t.Fatalf("http.NewRequest() failed: %v", err)
			}

			resp, err := c.Do(req)
			if err != nil {
				t.Fatalf("Do() failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tt.wantStatus {
				t.Errorf("Do() status = %d, want %d", resp.StatusCode, tt.wantStatus)
			}

			if externalVisited != tt.wantExternalVisited {
				t.Errorf("externalVisited = %v, want %v", externalVisited, tt.wantExternalVisited)
			}

			if tt.wantBody != "" {
				body, _ := io.ReadAll(resp.Body)
				if string(body) != tt.wantBody {
					t.Errorf("Do() body = %q, want %q", string(body), tt.wantBody)
				}
			}
		})
	}
}
