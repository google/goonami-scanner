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

package testrunner

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"

	ftpb "github.com/google/goonami-scanner/plugins/fingerprint/webidentity/fingerprint_test_go_proto"
)

var (
	passiveCrawlSuffixes = []string{
		"/login",
		"/login.html",
		"/wp-login.php",
		".js",
		".css",
		".ico",
		".html",
	}
	passiveCrawlSubstrings = []string{
		"build/",
		"static/",
		"assets/",
	}
)

// mockHTTPClient simulates responses defined in a test case.
type mockHTTPClient struct {
	responses map[string]*ftpb.WebFingerprintTests_MockResponse
}

func (m *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	key := req.URL.String()
	mock, ok := m.responses[key]
	if !ok {
		mock, ok = m.responses[req.URL.Path]
	}

	if !ok {
		return &http.Response{
			StatusCode: http.StatusNotFound,
			Status:     "404 Not Found",
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("404 Not Found")),
			Request:    req,
		}, nil
	}

	return mockToHTTPResponse(mock, req), nil
}

func mockToHTTPResponse(mock *ftpb.WebFingerprintTests_MockResponse, req *http.Request) *http.Response {
	statusCode := int(mock.GetStatusCode())
	if statusCode == 0 {
		statusCode = http.StatusOK
	}

	header := make(http.Header)
	for _, h := range mock.GetHeaders() {
		header.Add(h.GetName(), h.GetValue())
	}

	return &http.Response{
		StatusCode: statusCode,
		Status:     fmt.Sprintf("%d %s", statusCode, http.StatusText(statusCode)),
		Header:     header,
		Body:       io.NopCloser(strings.NewReader(mock.GetBody())),
		Request:    req,
	}
}

func isPassiveCrawlPath(rawURI string) bool {
	parsed, err := url.Parse(rawURI)
	if err != nil {
		return false
	}
	p := parsed.Path
	if p == "" || p == "/" {
		return true
	}
	if slices.ContainsFunc(passiveCrawlSuffixes, func(suffix string) bool {
		return strings.HasSuffix(p, suffix)
	}) {
		return true
	}
	return slices.ContainsFunc(passiveCrawlSubstrings, func(sub string) bool {
		return strings.Contains(p, sub)
	})
}
