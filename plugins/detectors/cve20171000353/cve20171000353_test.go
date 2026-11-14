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

// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cve20171000353

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/goonami-scanner/core/config"
	_ "github.com/google/goonami-scanner/core/net/http/simpleclient"
	"google.golang.org/protobuf/testing/protocmp"

	dpb "github.com/google/tsunami-security-scanner/proto/go/detection_go_proto"
	npb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
)

func newTestWebService(t *testing.T, srv *httptest.Server) *nspb.NetworkService {
	t.Helper()
	host, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("net.SplitHostPort failed: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("strconv.Atoi failed: %v", err)
	}
	return nspb.NetworkService_builder{
		ServiceName:          "http",
		SupportedHttpMethods: []string{"GET", "POST"},
		NetworkEndpoint: npb.NetworkEndpoint_builder{
			Type: npb.NetworkEndpoint_IP_PORT,
			IpAddress: npb.IpAddress_builder{
				Address:       host,
				AddressFamily: npb.AddressFamily_IPV4,
			}.Build(),
			Port: npb.Port_builder{
				PortNumber: uint32(port),
			}.Build(),
		}.Build(),
	}.Build()
}

func TestAdvisories(t *testing.T) {
	ctx := context.Background()
	cfg := config.Default()
	det, err := New(ctx, cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	advisories := det.Advisories()
	if len(advisories) != 1 {
		t.Fatalf("Advisories() returned %d advisories, want 1", len(advisories))
	}
	if diff := cmp.Diff(baseVulnerability(), advisories[0], protocmp.Transform()); diff != "" {
		t.Errorf("Advisory mismatch (-want +got):\n%s", diff)
	}
}

func TestDetect_WhenVulnerable_ReturnsReport(t *testing.T) {
	var mu sync.Mutex
	type sessionState struct {
		receivedPreamble bool
		done             chan struct{}
	}
	sessions := make(map[string]*sessionState)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/cli" {
			http.NotFound(w, r)
			return
		}

		sessionID := r.Header.Get("Session")
		side := strings.ToLower(r.Header.Get("Side"))

		mu.Lock()
		st, exists := sessions[sessionID]
		if !exists {
			st = &sessionState{done: make(chan struct{})}
			sessions[sessionID] = st
		}
		mu.Unlock()

		if side == "download" {
			select {
			case <-st.done:
				if st.receivedPreamble {
					w.Header().Set("Content-Type", "application/octet-stream")
					w.Header().Set("X-Jenkins", "2.46.1")
					w.WriteHeader(http.StatusOK)
					w.Write([]byte("<===[JENKINS REMOTINGCAPACITY]===>rO0ABXNyABpodWRzb24ucmVtb3RpbmcuQ2FwYWJpbGl0eQAAAAAAAAABAgABSgAEbWFza3hwAAAAAAAAAH4=\x00\x00\x00\x00"))
					return
				}
			case <-time.After(3 * time.Second):
			}
			http.Error(w, "Gateway Timeout", http.StatusGatewayTimeout)
			return
		}

		if side == "upload" {
			body, _ := io.ReadAll(r.Body)
			if strings.Contains(string(body), preambleRemoting) {
				st.receivedPreamble = true
			}
			close(st.done)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
			return
		}

		http.Error(w, "Bad Request", http.StatusBadRequest)
	}))
	defer server.Close()

	ctx := context.Background()
	cfg := config.Default()
	det, err := New(ctx, cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	service := newTestWebService(t, server)
	reports, err := det.Detect(ctx, service)
	if err != nil {
		t.Fatalf("Detect() returned unexpected error: %v", err)
	}

	if reports == nil || len(reports.GetDetectionReports()) != 1 {
		t.Fatalf("Detect() expected 1 report, got %v", reports)
	}

	report := reports.GetDetectionReports()[0]
	if report.GetDetectionStatus() != dpb.DetectionStatus_VULNERABILITY_VERIFIED {
		t.Errorf("DetectionStatus got %v, want VULNERABILITY_VERIFIED", report.GetDetectionStatus())
	}
	if diff := cmp.Diff(baseVulnerability(), report.GetVulnerability(), protocmp.Transform()); diff != "" {
		t.Errorf("Vulnerability mismatch (-want +got):\n%s", diff)
	}
}

func TestDetect_WhenPatched_ReturnsNil(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/cli" {
			w.Header().Set("X-Jenkins", "2.46.2")
			w.Header().Set("X-Jenkins-CLI2-Port", "50000")
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Remoting over HTTP CLI is disabled in this version of Jenkins.\n"))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	ctx := context.Background()
	cfg := config.Default()
	det, err := New(ctx, cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	service := newTestWebService(t, server)
	reports, err := det.Detect(ctx, service)
	if err != nil {
		t.Fatalf("Detect() returned unexpected error: %v", err)
	}

	if reports != nil && len(reports.GetDetectionReports()) > 0 {
		t.Errorf("Detect() on patched server expected nil, got %v", reports)
	}
}

func TestDetect_WhenNotJenkins_ReturnsNil(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer server.Close()

	ctx := context.Background()
	cfg := config.Default()
	det, err := New(ctx, cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	service := newTestWebService(t, server)
	reports, err := det.Detect(ctx, service)
	if err != nil {
		t.Fatalf("Detect() returned unexpected error: %v", err)
	}

	if reports != nil && len(reports.GetDetectionReports()) > 0 {
		t.Errorf("Detect() on non-Jenkins server expected nil, got %v", reports)
	}
}

func TestDetect_WhenEchoServer_ReturnsNil(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "text/plain")
		io.Copy(w, r.Body)
	}))
	defer server.Close()

	ctx := context.Background()
	cfg := config.Default()
	det, err := New(ctx, cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	service := newTestWebService(t, server)
	reports, err := det.Detect(ctx, service)
	if err != nil {
		t.Fatalf("Detect() returned unexpected error: %v", err)
	}

	if reports != nil && len(reports.GetDetectionReports()) > 0 {
		t.Errorf("Detect() on echo server expected nil, got %v", reports)
	}
}
