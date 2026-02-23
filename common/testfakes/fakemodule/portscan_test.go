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
	npb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
	rpb "github.com/google/tsunami-security-scanner/proto/go/reconnaissance_go_proto"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestFakePortScanFnDoNothing(t *testing.T) {
	report, err := FakePortScanFnDoNothing(t.Context(), "irrelevant")
	if report != nil || err != nil {
		t.Errorf("FakePortScanFnDoNothing() = %v, %v, want nil, nil", report, err)
	}
}

func TestFakePortScanFnErrors(t *testing.T) {
	report, err := FakePortScanFnErrors(t.Context(), "irrelevant")
	if report != nil || err != ErrFakePortScanGeneric {
		t.Errorf("FakePortScanFnErrors() = %v, %v, want nil, %v", report, err, ErrFakePortScanGeneric)
	}
}

func TestNewFakePortScanner(t *testing.T) {
	fake := NewFakePortScanner("test", FakePortScanFnDoNothing)
	if fake.Name() != "test" {
		t.Errorf("NewFakePortScanner() created fake with name %q, want %q", fake.Name(), "test")
	}

	if fake.CountCalls() != 0 {
		t.Errorf("NewFakePortScanner() created fake with %d calls, want 0", fake.CountCalls())
	}
}

func TestFakePortScannerCountCalls(t *testing.T) {
	fake := NewFakePortScanner("test", FakePortScanFnDoNothing)
	if fake.CountCalls() != 0 {
		t.Errorf("CountCalls() = %d, want 0", fake.CountCalls())
	}
	fake.Scan(t.Context(), "irrelevant")
	if fake.CountCalls() != 1 {
		t.Errorf("CountCalls() = %d, want 1", fake.CountCalls())
	}
}

func TestFakePortScannerScan(t *testing.T) {
	testReport := rpb.PortScanningReport_builder{
		TargetInfo: rpb.TargetInfo_builder{
			NetworkEndpoints: []*npb.NetworkEndpoint{
				npb.NetworkEndpoint_builder{
					IpAddress: npb.IpAddress_builder{
						Address:       "1.2.3.4",
						AddressFamily: npb.AddressFamily_IPV4,
					}.Build(),
					Port: npb.Port_builder{
						PortNumber: 80,
					}.Build(),
				}.Build(),
			},
		}.Build(),
		NetworkServices: []*nspb.NetworkService{
			nspb.NetworkService_builder{
				ServiceName: "http",
			}.Build(),
		},
	}.Build()

	tests := []struct {
		name       string
		scanFn     FakePortScanFn
		wantReport *rpb.PortScanningReport
		wantErr    error
	}{
		{
			name: "when_scan_succeeds_it_increases_call_count",
			scanFn: func(ctx context.Context, target string) (*rpb.PortScanningReport, error) {
				return nil, nil
			},
		},
		{
			name: "when_scan_succeeds_it_returns_report",
			scanFn: func(ctx context.Context, target string) (*rpb.PortScanningReport, error) {
				return testReport, nil
			},
			wantReport: testReport,
		},
		{
			name: "when_scan_errors_it_propagates_error",
			scanFn: func(ctx context.Context, target string) (*rpb.PortScanningReport, error) {
				return nil, ErrFakePortScanGeneric
			},
			wantErr: ErrFakePortScanGeneric,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fake := NewFakePortScanner("test", tc.scanFn)
			report, err := fake.Scan(t.Context(), "irrelevant")
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("Scan() error = %v, want %v", err, tc.wantErr)
			}

			if tc.wantErr == nil {
				return
			}

			if fake.CountCalls() != 1 {
				t.Errorf("Scan() call count = %d, want 1", fake.CountCalls())
			}

			if diff := cmp.Diff(tc.wantReport, report, protocmp.Transform()); diff != "" {
				t.Errorf("Scan() report diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestInitFakePortScanner(t *testing.T) {
	errInit := errors.New("init error")
	testCases := []struct {
		name    string
		initErr error
		wantErr error
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
			initFn := InitFakePortScanner("test", tc.initErr, FakePortScanFnDoNothing)
			if initFn == nil {
				t.Fatalf("InitFakePortScanner() returned nil")
			}

			m, err := initFn(t.Context(), nil)
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("InitFakePortScanner() error = %v, want %v", err, tc.wantErr)
			}
			if tc.wantErr != nil {
				return
			}

			fake, ok := m.(*FakePortScanner)
			if !ok {
				t.Fatalf("InitFakePortScanner() returned module of type %T, want *FakePortScanner", m)
			}

			if fake.Name() != "test" {
				t.Errorf("InitFakePortScanner() created fake with name %q, want %q", fake.Name(), "test")
			}

			if fake.override == nil {
				t.Errorf("InitFakePortScanner() created fake with nil override")
			}
		})
	}
}
