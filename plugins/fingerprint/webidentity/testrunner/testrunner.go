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

// Package testrunner executes declarative WebFingerprintTests against WebFingerprint definitions.
package testrunner

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/google/goonami-scanner/plugins/fingerprint/webidentity/cache"
	"github.com/google/goonami-scanner/plugins/fingerprint/webidentity/engine"
	fpb "github.com/google/goonami-scanner/plugins/fingerprint/webidentity/fingerprint_go_proto"
	ftpb "github.com/google/goonami-scanner/plugins/fingerprint/webidentity/fingerprint_test_go_proto"
)

const (
	defaultTestBaseURL = "http://target.test:8080"
)

// RunTestCase executes an individual TestCase against a compiled fingerprint.
func RunTestCase(ctx context.Context, fp *engine.CompiledFingerprint, tc *ftpb.WebFingerprintTests_TestCase) error {
	if fp == nil {
		return errors.New("fingerprint cannot be nil")
	}
	if tc == nil {
		return errors.New("test case cannot be nil")
	}

	c := newSeededTestCache(tc.GetMockResponses())
	eng := engine.New([]*engine.CompiledFingerprint{fp})
	results, err := eng.Run(ctx, c, defaultTestBaseURL)
	if err != nil {
		return fmt.Errorf("engine execution failed: %w", err)
	}

	return verifyExpectedMatches(results, tc.GetExpectedMatches())
}

func newSeededTestCache(mocks []*ftpb.WebFingerprintTests_MockResponse) *cache.Cache {
	mockClient := &mockHTTPClient{
		responses: make(map[string]*ftpb.WebFingerprintTests_MockResponse),
	}
	c := cache.New(mockClient)

	for _, mock := range mocks {
		rawURI := normalizeMockURI(mock.GetUri())
		mockClient.responses[rawURI] = mock
		if parsed, err := url.Parse(rawURI); err == nil {
			mockClient.responses[parsed.Path] = mock
		}

		// If this is a page that a crawler would passively discover, seed it into cache.
		if isPassiveCrawlPath(rawURI) {
			c.Put(http.MethodGet, rawURI, mockToHTTPResponse(mock, nil), []byte(mock.GetBody()))
		}
	}
	return c
}

func normalizeMockURI(rawURI string) string {
	if strings.HasPrefix(rawURI, "http://") || strings.HasPrefix(rawURI, "https://") {
		return rawURI
	}
	if !strings.HasPrefix(rawURI, "/") {
		rawURI = "/" + rawURI
	}
	return defaultTestBaseURL + rawURI
}

func verifyExpectedMatches(got []*engine.IdentificationResult, want []*ftpb.WebFingerprintTests_ExpectedMatch) error {
	if len(got) != len(want) {
		return fmt.Errorf("got %d detections (%+v), want %d", len(got), got, len(want))
	}

	for i, expected := range want {
		res := got[i]
		if res.ApplicationRoot != expected.GetApplicationRootPath() {
			return fmt.Errorf("match %d root mismatch: got %q, want %q", i, res.ApplicationRoot, expected.GetApplicationRootPath())
		}
		for _, wantVer := range expected.GetExpectedVersions() {
			if !slices.Contains(res.Versions, wantVer) {
				return fmt.Errorf("match %d versions = %v, want version %q", i, res.Versions, wantVer)
			}
		}
	}

	return nil
}

// RunSuite runs all test cases in a WebFingerprintTests definition using Go testing.T.
func RunSuite(t *testing.T, fpProto *fpb.WebFingerprint, suite *ftpb.WebFingerprintTests) {
	t.Helper()
	if suite.GetDisabled() {
		t.Skipf("test suite %q is disabled", suite.GetTestedFingerprint())
		return
	}

	fp, err := engine.CompileFingerprint(fpProto)
	if err != nil {
		t.Fatalf("engine.CompileFingerprint(%q) failed: %v", suite.GetTestedFingerprint(), err)
	}

	for _, tc := range suite.GetTests() {
		t.Run(tc.GetName(), func(t *testing.T) {
			if err := RunTestCase(t.Context(), fp, tc); err != nil {
				t.Fatalf("RunTestCase(%q) failed: %v", tc.GetName(), err)
			}
		})
	}
}
