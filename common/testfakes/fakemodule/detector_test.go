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

package fakemodule

import (
	"context"
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/testing/protocmp"

	dpb "github.com/google/tsunami-security-scanner/proto/go/detection_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
	vulnpb "github.com/google/tsunami-security-scanner/proto/go/vulnerability_go_proto"
)

func TestFakeDetectFnNoFindings(t *testing.T) {
	if _, err := FakeDetectFnNoFindings(t.Context(), nil); err != nil {
		t.Errorf("FakeDetectFnNoFindings() = %v, want nil", err)
	}
}

func TestFakeDetectFnErrors(t *testing.T) {
	if _, err := FakeDetectFnErrors(t.Context(), nil); err != ErrFakeDetectGeneric {
		t.Errorf("FakeDetectFnErrors() = %v, want %v", err, ErrFakeDetectGeneric)
	}
}

func TestNewFakeVulnDetector(t *testing.T) {
	fake := NewFakeVulnDetector("test", FakeDetectFnNoFindings)
	if fake.Name() != "test" {
		t.Errorf("NewFakeVulnDetector() created fake with name %q, want %q", fake.Name(), "test")
	}

	if fake.CountCalls() != 0 {
		t.Errorf("NewFakeVulnDetector() created fake with %d calls, want 0", fake.CountCalls())
	}
}

func TestFakeVulnDetectorCountCalls(t *testing.T) {
	fake := NewFakeVulnDetector("test", FakeDetectFnNoFindings)
	if fake.CountCalls() != 0 {
		t.Errorf("CountCalls() = %d, want 0", fake.CountCalls())
	}

	fake.Detect(t.Context(), nil)
	if fake.CountCalls() != 1 {
		t.Errorf("CountCalls() = %d, want 1", fake.CountCalls())
	}
}

func TestFakeVulnDetectorAdvisories(t *testing.T) {
	wantAdv := []*vulnpb.Vulnerability{
		vulnpb.Vulnerability_builder{Title: "vuln1"}.Build(),
	}

	tests := []struct {
		name string
		fake *FakeVulnDetector
		want []*vulnpb.Vulnerability
	}{
		{
			name: "when_constructed_without_advisories_returns_nil",
			fake: NewFakeVulnDetector("test", FakeDetectFnNoFindings),
			want: nil,
		},
		{
			name: "when_constructed_with_advisories_returns_configured_advisories",
			fake: NewFakeVulnDetectorWithAdvisories("test", wantAdv, FakeDetectFnNoFindings),
			want: wantAdv,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.fake.Advisories()
			if diff := cmp.Diff(tc.want, got, protocmp.Transform()); diff != "" {
				t.Errorf("Advisories() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestFakeVulnDetectorDetect(t *testing.T) {
	tests := []struct {
		name     string
		detectFn FakeDetectFn
		wantErr  error
		want     *dpb.DetectionReportList
	}{
		{
			name: "when_detection_succeeds_returns_report",
			detectFn: func(ctx context.Context, svc *nspb.NetworkService) (*dpb.DetectionReportList, error) {
				return dpb.DetectionReportList_builder{
					DetectionReports: []*dpb.DetectionReport{
						dpb.DetectionReport_builder{
							Vulnerability: vulnpb.Vulnerability_builder{
								Title: "test-vuln",
							}.Build(),
						}.Build(),
					},
				}.Build(), nil
			},
			want: dpb.DetectionReportList_builder{
				DetectionReports: []*dpb.DetectionReport{
					dpb.DetectionReport_builder{
						Vulnerability: vulnpb.Vulnerability_builder{
							Title: "test-vuln",
						}.Build(),
					}.Build(),
				},
			}.Build(),
		},
		{
			name: "when_detection_errors_it_propagates_error",
			detectFn: func(ctx context.Context, svc *nspb.NetworkService) (*dpb.DetectionReportList, error) {
				return nil, ErrFakeDetectGeneric
			},
			wantErr: ErrFakeDetectGeneric,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fake := NewFakeVulnDetector("test", tc.detectFn)
			svc := nspb.NetworkService_builder{
				ServiceName: "original",
			}.Build()
			got, err := fake.Detect(t.Context(), svc)
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("Detect() error = %v, want %v", err, tc.wantErr)
			}

			if tc.wantErr != nil {
				return
			}

			if fake.CountCalls() != 1 {
				t.Errorf("Detect() call count = %d, want 1", fake.CountCalls())
			}

			if diff := cmp.Diff(tc.want, got, protocmp.Transform()); diff != "" {
				t.Errorf("Detect() diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestInitFakeVulnDetector(t *testing.T) {
	errInit := errors.New("init error")
	testCases := []struct {
		name     string
		initErr  error
		override FakeDetectFn
		wantErr  error
	}{
		{
			name:    "when_init_has_no_error_it_returns_fake",
			initErr: nil,
			wantErr: nil,
		},
		{
			name:    "when_init_has_error_it_returns_error",
			initErr: errInit,
			wantErr: errInit,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			initFn := InitFakeVulnDetector("test", tc.initErr, tc.override)

			if initFn == nil {
				t.Fatalf("InitFakeVulnDetector() returned nil, want init function")
			}

			detector, err := initFn(t.Context(), nil)
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("InitFakeVulnDetector() init function returned error %v, want %v", err, tc.wantErr)
			}
			if tc.wantErr != nil {
				return
			}

			fake, ok := detector.(*FakeVulnDetector)
			if !ok {
				t.Fatalf("InitFakeVulnDetector() returned module of type %T, want *FakeVulnDetector", detector)
			}

			if fake.Name() != "test" {
				t.Errorf("InitFakeVulnDetector() created detector with name %q, want %q", detector.Name(), "test")
			}
		})
	}
}

func TestInitFakeVulnDetectorWithAdvisories(t *testing.T) {
	errInit := errors.New("init error")
	wantAdv := []*vulnpb.Vulnerability{
		vulnpb.Vulnerability_builder{Title: "vuln-adv"}.Build(),
	}

	testCases := []struct {
		name     string
		initErr  error
		adv      []*vulnpb.Vulnerability
		wantErr  error
		wantName string
	}{
		{
			name:     "when_init_has_no_error_returns_fake_with_advisories",
			initErr:  nil,
			adv:      wantAdv,
			wantErr:  nil,
			wantName: "test-adv",
		},
		{
			name:     "when_init_has_error_returns_error",
			initErr:  errInit,
			adv:      wantAdv,
			wantErr:  errInit,
			wantName: "test-adv",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			initFn := InitFakeVulnDetectorWithAdvisories(tc.wantName, tc.initErr, tc.adv, FakeDetectFnNoFindings)
			if initFn == nil {
				t.Fatalf("InitFakeVulnDetectorWithAdvisories() returned nil, want init function")
			}

			detector, err := initFn(t.Context(), nil)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("init function returned error %v, want %v", err, tc.wantErr)
			}
			if tc.wantErr != nil {
				return
			}

			fake, ok := detector.(*FakeVulnDetector)
			if !ok {
				t.Fatalf("detector is of type %T, want *FakeVulnDetector", detector)
			}
			if fake.Name() != tc.wantName {
				t.Errorf("detector name = %q, want %q", fake.Name(), tc.wantName)
			}
			if diff := cmp.Diff(tc.adv, fake.Advisories(), protocmp.Transform()); diff != "" {
				t.Errorf("Advisories() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
