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

package cve2026111497

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/module"
	goohttp "github.com/google/goonami-scanner/core/net/http"
	_ "github.com/google/goonami-scanner/core/net/http/simpleclient"
	"google.golang.org/protobuf/testing/protocmp"

	cpb "github.com/google/goonami-scanner/core/config/config_go_proto"
	dpb "github.com/google/tsunami-security-scanner/proto/go/detection_go_proto"
	npb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
	vpb "github.com/google/tsunami-security-scanner/proto/go/vulnerability_go_proto"
)

func useCompactProbeForTest(t *testing.T) {
	t.Helper()
	orig := probeMiddleZeroLen
	probeMiddleZeroLen = 64
	t.Cleanup(func() {
		probeMiddleZeroLen = orig
	})
}

func isProbePayload(body []byte) bool {
	if len(body) != len(probeHeader)+probeMiddleZeroLen+len(probeTail) {
		return false
	}
	if !bytes.HasPrefix(body, probeHeader) || !bytes.HasSuffix(body, probeTail) {
		return false
	}
	middle := body[len(probeHeader) : len(probeHeader)+probeMiddleZeroLen]
	for _, b := range middle {
		if b != 0 {
			return false
		}
	}
	return true
}

func closeRawConn(w http.ResponseWriter) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		return
	}
	conn, _, err := hj.Hijack()
	if err == nil {
		_ = conn.Close()
	}
}

func newWebServiceForTest(t *testing.T, ts *httptest.Server) *nspb.NetworkService {
	t.Helper()
	host, portStr, err := net.SplitHostPort(ts.Listener.Addr().String())
	if err != nil {
		t.Fatalf("net.SplitHostPort(%q) failed: %v", ts.Listener.Addr().String(), err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("strconv.Atoi(%q) failed: %v", portStr, err)
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

func TestRegistrationAndAdvisories(t *testing.T) {
	ctx := t.Context()
	cfg := config.FromProto(&cpb.Config{})

	allDetectors, err := module.AllDetectors(ctx, cfg)
	if err != nil {
		t.Fatalf("module.AllDetectors() error = %v", err)
	}
	found := false
	for _, d := range allDetectors {
		if d.Name() == moduleName {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("detector %q not found in module.AllDetectors()", moduleName)
	}

	det, err := New(ctx, cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	got := det.Advisories()
	want := []*vpb.Vulnerability{baseVulnerability()}
	if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
		t.Errorf("Advisories() diff (-want +got):\n%s", diff)
	}

	if !bytes.HasPrefix(invalidBrotliControl, []byte("Vtsunami_brotli_invalid_control_")) {
		t.Errorf("invalidBrotliControl missing prefix: %q", invalidBrotliControl)
	}

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("mustDecodeHex(\"zz\") did not panic")
		}
	}()
	_ = mustDecodeHex("zz")
}

func TestDetect_NonWebServiceAndInvalidInputs(t *testing.T) {
	useCompactProbeForTest(t)
	ctx := t.Context()
	cfg := config.FromProto(&cpb.Config{})
	det, err := New(ctx, cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	sshService := nspb.NetworkService_builder{
		ServiceName: "ssh",
		NetworkEndpoint: npb.NetworkEndpoint_builder{
			Type: npb.NetworkEndpoint_IP_PORT,
			IpAddress: npb.IpAddress_builder{
				Address:       "127.0.0.1",
				AddressFamily: npb.AddressFamily_IPV4,
			}.Build(),
			Port: npb.Port_builder{
				PortNumber: 22,
			}.Build(),
		}.Build(),
	}.Build()
	if reports, err := det.Detect(ctx, sshService); err != nil || reports != nil {
		t.Errorf("Detect(ssh) = (%v, %v), want (nil, nil)", reports, err)
	}

	missingEndpointWebService := nspb.NetworkService_builder{
		ServiceName:          "http",
		SupportedHttpMethods: []string{"POST"},
	}.Build()
	if reports, err := det.Detect(ctx, missingEndpointWebService); err != nil || reports != nil {
		t.Errorf("Detect(missingEndpoint) = (%v, %v), want (nil, nil)", reports, err)
	}

	nilCfgDet, err := New(ctx, nil)
	if err != nil {
		t.Fatalf("New(nil) error = %v", err)
	}
	validEndpointWebService := nspb.NetworkService_builder{
		ServiceName:          "http",
		SupportedHttpMethods: []string{"POST"},
		NetworkEndpoint: npb.NetworkEndpoint_builder{
			Type: npb.NetworkEndpoint_IP_PORT,
			IpAddress: npb.IpAddress_builder{
				Address:       "127.0.0.1",
				AddressFamily: npb.AddressFamily_IPV4,
			}.Build(),
			Port: npb.Port_builder{
				PortNumber: 80,
			}.Build(),
		}.Build(),
	}.Build()
	if _, err := nilCfgDet.Detect(ctx, validEndpointWebService); err == nil {
		t.Errorf("Detect() with nil config succeeded, want error")
	}
}

func TestDetect_VulnerableBrotliServerWithCanaryReflection_ReportsVulnerability(t *testing.T) {
	useCompactProbeForTest(t)
	var totalReqs atomic.Int32
	var newConns atomic.Int32

	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqNum := totalReqs.Add(1)
		if r.Header.Get("Content-Type") != "application/json" ||
			r.Header.Get("Accept") != "application/json, text/event-stream, text/plain, */*" {
			w.WriteHeader(http.StatusUnsupportedMediaType)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// Post-probe canary control order is validFirst (request #4 valid, request #5 invalid).
		if (reqNum == 4 && !bytes.Equal(body, validBrotliControl)) ||
			(reqNum == 5 && !bytes.Equal(body, invalidBrotliControl)) {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if r.Header.Get("Content-Encoding") != "br" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid raw json"}`))
			return
		}
		if bytes.Equal(body, validBrotliControl) || isProbePayload(body) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"echo":"` + decompressedCanary + `"}`))
			return
		}
		if bytes.Equal(body, invalidBrotliControl) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"BrotliDecompress failed"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	ts.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			newConns.Add(1)
		}
	}
	ts.Start()
	defer ts.Close()

	ctx := t.Context()
	cfg := config.FromProto(&cpb.Config{})
	det, err := New(ctx, cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	reports, err := det.Detect(ctx, newWebServiceForTest(t, ts))
	if err != nil {
		t.Fatalf("Detect() unexpected error = %v", err)
	}
	if reports == nil || len(reports.GetDetectionReports()) != 1 {
		t.Fatalf("Detect() reports = %v, want 1 report", reports)
	}
	gotReport := reports.GetDetectionReports()[0]
	if gotReport.GetDetectionStatus() != dpb.DetectionStatus_VULNERABILITY_VERIFIED {
		t.Errorf("DetectionStatus = %v, want VULNERABILITY_VERIFIED", gotReport.GetDetectionStatus())
	}
	if gotReport.GetVulnerability().GetMainId().GetValue() != "CVE-2026-111497" {
		t.Errorf("MainId.Value = %q, want %q", gotReport.GetVulnerability().GetMainId().GetValue(), "CVE-2026-111497")
	}
	details := gotReport.GetVulnerability().GetAdditionalDetails()
	if len(details) != 1 || details[0].GetTextData().GetText() == "" {
		t.Errorf("AdditionalDetails = %v, want 1 non-empty detail", details)
	}
	if got := totalReqs.Load(); got != 6 {
		t.Errorf("totalReqs = %d, want 6 (Step 1..5 with 1 post-probe canary control pair)", got)
	}
	if got := newConns.Load(); got != 1 {
		t.Errorf("newConns = %d, want 1 (resp.Body.Close() must allow keep-alive reuse)", got)
	}
}

func TestDetect_VulnerableBrotliServerStatusOnlyDifferential_OnRedirectingCandidatePath_ReportsVulnerability(t *testing.T) {
	useCompactProbeForTest(t)
	var rootReqs atomic.Int32

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			rootReqs.Add(1)
			w.WriteHeader(http.StatusUnsupportedMediaType)
			return
		}
		if r.URL.Path != "/graphql" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if r.Header.Get("Content-Encoding") != "br" {
			w.WriteHeader(http.StatusUnsupportedMediaType)
			return
		}
		if bytes.Equal(body, validBrotliControl) || isProbePayload(body) {
			w.Header().Set("Location", "/redirect-trap")
			w.WriteHeader(http.StatusFound)
			return
		}
		if bytes.Equal(body, invalidBrotliControl) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNotImplemented)
	}))
	defer ts.Close()

	ctx := t.Context()
	cfg := config.FromProto(&cpb.Config{})
	det, err := New(ctx, cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	reports, err := det.Detect(ctx, newWebServiceForTest(t, ts))
	if err != nil {
		t.Fatalf("Detect() unexpected error = %v", err)
	}
	if reports == nil || len(reports.GetDetectionReports()) != 1 {
		t.Fatalf("Detect() reports = %v, want 1 report on /graphql", reports)
	}
	if got := rootReqs.Load(); got != 1 {
		t.Errorf("rootReqs = %d, want 1 (Step 1 415 status must skip Step 2)", got)
	}
}

func TestDetect_PatchedBrotliServerRejectingProbe_StopsAfterMaxProbes(t *testing.T) {
	useCompactProbeForTest(t)
	var probesReceived atomic.Int32

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if r.Header.Get("Content-Encoding") != "br" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if isProbePayload(body) {
			probesReceived.Add(1)
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH"}`))
			return
		}
		if bytes.Equal(body, validBrotliControl) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"echo":"` + decompressedCanary + `"}`))
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer ts.Close()

	ctx := t.Context()
	cfg := config.FromProto(&cpb.Config{})
	det, err := New(ctx, cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	reports, err := det.Detect(ctx, newWebServiceForTest(t, ts))
	if err != nil {
		t.Fatalf("Detect() unexpected error = %v", err)
	}
	if reports != nil && len(reports.GetDetectionReports()) > 0 {
		t.Errorf("Detect() reports = %v, want nil for patched server", reports)
	}
	if got := int(probesReceived.Load()); got != maxProbesPerService {
		t.Errorf("probesReceived = %d, want %d (maxProbesPerService)", got, maxProbesPerService)
	}
}

func TestDetect_Step1IOErrorCircuitBreaker(t *testing.T) {
	useCompactProbeForTest(t)

	t.Run("stops_after_max_consecutive_step1_io_errors", func(t *testing.T) {
		var reqs atomic.Int32
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			reqs.Add(1)
			closeRawConn(w)
		}))
		defer ts.Close()

		det, err := New(t.Context(), config.FromProto(&cpb.Config{}))
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		reports, err := det.Detect(t.Context(), newWebServiceForTest(t, ts))
		if err != nil {
			t.Fatalf("Detect() unexpected error = %v", err)
		}
		if reports != nil {
			t.Errorf("Detect() = %v, want nil", reports)
		}
		if got := int(reqs.Load()); got != maxConsecutiveStep1IOErrors {
			t.Errorf("reqs = %d, want %d (maxConsecutiveStep1IOErrors)", got, maxConsecutiveStep1IOErrors)
		}
	})

	t.Run("resets_consecutive_io_error_counter_after_http_response", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/", "/api", "/api/v1":
				closeRawConn(w)
				return
			case "/graphql":
				w.WriteHeader(http.StatusUnsupportedMediaType)
				return
			case "/api/graphql":
				body, _ := io.ReadAll(r.Body)
				if r.Header.Get("Content-Encoding") == "br" &&
					(bytes.Equal(body, validBrotliControl) || isProbePayload(body)) {
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(decompressedCanary))
					return
				}
				w.WriteHeader(http.StatusBadRequest)
				return
			default:
				w.WriteHeader(http.StatusUnsupportedMediaType)
			}
		}))
		defer ts.Close()

		det, err := New(t.Context(), config.FromProto(&cpb.Config{}))
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		reports, err := det.Detect(t.Context(), newWebServiceForTest(t, ts))
		if err != nil {
			t.Fatalf("Detect() unexpected error = %v", err)
		}
		if reports == nil || len(reports.GetDetectionReports()) != 1 {
			t.Fatalf("Detect() reports = %v, want 1 report on /api/graphql", reports)
		}
	})
}

func TestDetect_NegativeDifferentialAndErrorPaths_DoesNotReport(t *testing.T) {
	useCompactProbeForTest(t)

	tests := []struct {
		name           string
		wantProbesSent int32
		handler        func(reqNum int32, w http.ResponseWriter, r *http.Request, body []byte)
	}{
		{
			name:           "server_ignoring_content_encoding_br",
			wantProbesSent: 0,
			handler: func(_ int32, w http.ResponseWriter, _ *http.Request, _ []byte) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"status":"ok"}`))
			},
		},
		{
			name:           "step2_connection_drop_skips_probe",
			wantProbesSent: 0,
			handler: func(_ int32, w http.ResponseWriter, _ *http.Request, body []byte) {
				if bytes.Equal(body, invalidBrotliControl) {
					closeRawConn(w)
					return
				}
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(decompressedCanary))
			},
		},
		{
			name:           "alternating_status_server_rejected_by_pre_probe_invalid_first_control",
			wantProbesSent: 0,
			handler: func(reqNum int32, w http.ResponseWriter, _ *http.Request, _ []byte) {
				if reqNum%2 == 1 {
					w.WriteHeader(http.StatusOK)
					return
				}
				w.WriteHeader(http.StatusBadRequest)
			},
		},
		{
			name:           "pre_probe_valid_control_failure_rejects_before_probe",
			wantProbesSent: 0,
			handler: func(reqNum int32, w http.ResponseWriter, _ *http.Request, body []byte) {
				// Req 1 (valid) -> 200, Req 2 (invalid) -> 400, Req 3 (invalid) -> 400, Req 4 (valid) -> 400.
				if reqNum == 1 && bytes.Equal(body, validBrotliControl) {
					w.WriteHeader(http.StatusOK)
					return
				}
				w.WriteHeader(http.StatusBadRequest)
			},
		},
		{
			name:           "step3_probe_connection_drop",
			wantProbesSent: int32(maxProbesPerService),
			handler: func(_ int32, w http.ResponseWriter, _ *http.Request, body []byte) {
				if isProbePayload(body) {
					closeRawConn(w)
					return
				}
				if bytes.Equal(body, validBrotliControl) {
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(decompressedCanary))
					return
				}
				w.WriteHeader(http.StatusBadRequest)
			},
		},
		{
			name:           "post_probe_valid_control_fails_in_canary_mode",
			wantProbesSent: int32(maxProbesPerService),
			handler: func(reqNum int32, w http.ResponseWriter, _ *http.Request, body []byte) {
				// Req 1 (valid) -> 200+canary, Req 2 (invalid) -> 400, Req 3 (probe) -> 200+canary,
				// Req 4 (post-probe valid) -> 500.
				if reqNum == 4 {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				if bytes.Equal(body, validBrotliControl) || isProbePayload(body) {
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(decompressedCanary))
					return
				}
				w.WriteHeader(http.StatusBadRequest)
			},
		},
		{
			name:           "post_probe_invalid_control_reflects_canary",
			wantProbesSent: int32(maxProbesPerService),
			handler: func(reqNum int32, w http.ResponseWriter, _ *http.Request, body []byte) {
				// Req 1 (valid) -> 200+canary, Req 2 (invalid) -> 400, Req 3 (probe) -> 200+canary,
				// Req 4 (post-probe valid) -> 200+canary, Req 5 (post-probe invalid) -> 400+canary.
				if reqNum == 5 {
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(decompressedCanary))
					return
				}
				if bytes.Equal(body, validBrotliControl) || isProbePayload(body) {
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(decompressedCanary))
					return
				}
				w.WriteHeader(http.StatusBadRequest)
			},
		},
		{
			name:           "unencoded_baseline_reflects_canary",
			wantProbesSent: int32(maxProbesPerService),
			handler: func(_ int32, w http.ResponseWriter, _ *http.Request, body []byte) {
				// Even when Content-Encoding: br is omitted, server reflects the canary.
				if bytes.Equal(body, validBrotliControl) || isProbePayload(body) {
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(decompressedCanary))
					return
				}
				w.WriteHeader(http.StatusBadRequest)
			},
		},
		{
			name:           "unencoded_baseline_accepts_status_200_in_status_diff_mode",
			wantProbesSent: int32(maxProbesPerService),
			handler: func(_ int32, w http.ResponseWriter, _ *http.Request, body []byte) {
				// Even when Content-Encoding: br is omitted, server returns 200 OK for validBrotliControl.
				if bytes.Equal(body, validBrotliControl) || isProbePayload(body) {
					w.WriteHeader(http.StatusOK)
					return
				}
				w.WriteHeader(http.StatusBadRequest)
			},
		},
		{
			name:           "unencoded_baseline_connection_drop",
			wantProbesSent: int32(maxProbesPerService),
			handler: func(_ int32, w http.ResponseWriter, r *http.Request, body []byte) {
				if r.Header.Get("Content-Encoding") != "br" {
					closeRawConn(w)
					return
				}
				if bytes.Equal(body, validBrotliControl) || isProbePayload(body) {
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(decompressedCanary))
					return
				}
				w.WriteHeader(http.StatusBadRequest)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var reqCount atomic.Int32
			var probeCount atomic.Int32
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/" && r.URL.Path != "/graphql" {
					w.WriteHeader(http.StatusUnsupportedMediaType)
					return
				}
				body, _ := io.ReadAll(r.Body)
				if isProbePayload(body) {
					probeCount.Add(1)
				}
				n := reqCount.Add(1)
				tc.handler(n, w, r, body)
			}))
			defer ts.Close()

			det, err := New(t.Context(), config.FromProto(&cpb.Config{}))
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			reports, err := det.Detect(t.Context(), newWebServiceForTest(t, ts))
			if err != nil {
				t.Fatalf("Detect() unexpected error = %v", err)
			}
			if reports != nil && len(reports.GetDetectionReports()) > 0 {
				t.Errorf("Detect() = %v, want no reports", reports)
			}
			if got := probeCount.Load(); got != tc.wantProbesSent {
				t.Errorf("probeCount = %d, want %d", got, tc.wantProbesSent)
			}
		})
	}
}

func TestSendPostRequestAndStatusHelpers(t *testing.T) {
	ctx := t.Context()
	cfg := config.FromProto(&cpb.Config{})
	client, err := goohttp.NewClient(cfg, goohttp.DefaultClientOptions())
	if err != nil {
		t.Fatalf("goohttp.NewClient() error = %v", err)
	}

	if _, err := sendPostRequest(ctx, client, "://invalid-url", []byte("{}"), true); err == nil {
		t.Errorf("sendPostRequest(invalid-url) succeeded, want error")
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "1024")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("short"))
		closeRawConn(w)
	}))
	defer ts.Close()

	if _, err := sendPostRequest(ctx, client, ts.URL, []byte("{}"), false); err == nil {
		t.Errorf("sendPostRequest(truncated body) succeeded, want error")
	}

	acceptedCodes := []int{
		http.StatusOK,
		http.StatusCreated,
		http.StatusFound,
		http.StatusSeeOther,
		http.StatusTemporaryRedirect,
		http.StatusPermanentRedirect,
		http.StatusUnauthorized,
		http.StatusForbidden,
		http.StatusNotFound,
		http.StatusMethodNotAllowed,
		http.StatusNotAcceptable,
	}
	for _, code := range acceptedCodes {
		if !isPostDecompressionStatus(code) {
			t.Errorf("isPostDecompressionStatus(%d) = false, want true", code)
		}
	}
	if isPostDecompressionStatus(http.StatusUnsupportedMediaType) {
		t.Errorf("isPostDecompressionStatus(415) = true, want false")
	}

	failureCodes := []int{
		http.StatusBadRequest,
		http.StatusUnprocessableEntity,
		http.StatusInternalServerError,
	}
	for _, code := range failureCodes {
		if !isDecompressionFailureStatus(code) {
			t.Errorf("isDecompressionFailureStatus(%d) = false, want true", code)
		}
		if !isUnencodedRejectionStatus(code) {
			t.Errorf("isUnencodedRejectionStatus(%d) = false, want true", code)
		}
	}
	if !isUnencodedRejectionStatus(http.StatusUnsupportedMediaType) {
		t.Errorf("isUnencodedRejectionStatus(415) = false, want true")
	}
	if isUnencodedRejectionStatus(http.StatusOK) {
		t.Errorf("isUnencodedRejectionStatus(200) = true, want false")
	}
}
