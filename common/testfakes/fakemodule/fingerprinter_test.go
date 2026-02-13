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
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestFakeFingerprintFnDoNothing(t *testing.T) {
	if _, err := FakeFingerprintFnDoNothing(context.Background(), nil); err != nil {
		t.Errorf("FakeFingerprintFnDoNothing() = %v, want nil", err)
	}
}

func TestFakeFingerprintFnErrors(t *testing.T) {
	if _, err := FakeFingerprintFnErrors(context.Background(), nil); err != ErrFakeFingerprintGeneric {
		t.Errorf("FakeFingerprintFnErrors() = %v, want %v", err, ErrFakeFingerprintGeneric)
	}
}

func TestNewFakeFingerprinter(t *testing.T) {
	fake := NewFakeFingerprinter("test", FakeFingerprintFnDoNothing)
	if fake.Name() != "test" {
		t.Errorf("NewFakeFingerprinter() created fake with name %q, want %q", fake.Name(), "test")
	}

	if fake.CountCalls() != 0 {
		t.Errorf("NewFakeFingerprinter() created fake with %d calls, want 0", fake.CountCalls())
	}
}

func TestFakeFingerprinterCountCalls(t *testing.T) {
	fake := NewFakeFingerprinter("test", FakeFingerprintFnDoNothing)
	if fake.CountCalls() != 0 {
		t.Errorf("CountCalls() = %d, want 0", fake.CountCalls())
	}

	fake.Fingerprint(context.Background(), nil)
	if fake.CountCalls() != 1 {
		t.Errorf("CountCalls() = %d, want 1", fake.CountCalls())
	}
}

func TestFakeFingerprinterFingerprint(t *testing.T) {
	tests := []struct {
		name    string
		scanFn  FakeFingerprintFn
		wantErr error
		wantSvc *nspb.NetworkService
	}{
		{
			name: "when_fingerprinting_succeeds_returns_modified_service",
			scanFn: func(ctx context.Context, svc *nspb.NetworkService) ([]*nspb.NetworkService, error) {
				svc.SetServiceName("modified")
				return []*nspb.NetworkService{svc}, nil
			},
			wantSvc: nspb.NetworkService_builder{
				ServiceName: "modified",
			}.Build(),
		},
		{
			name: "when_fingerprinting_errors_it_propagates_error",
			scanFn: func(ctx context.Context, svc *nspb.NetworkService) ([]*nspb.NetworkService, error) {
				return nil, ErrFakeFingerprintGeneric
			},
			wantErr: ErrFakeFingerprintGeneric,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fake := NewFakeFingerprinter("test", tc.scanFn)
			svc := nspb.NetworkService_builder{
				ServiceName: "original",
			}.Build()
			gotServices, err := fake.Fingerprint(context.Background(), svc)
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("Fingerprint() error = %v, want %v", err, tc.wantErr)
			}

			if tc.wantErr != nil {
				return
			}

			if len(gotServices) != 1 {
				t.Fatalf("Fingerprint() returned an unexpected number of services: %v, want 1", len(gotServices))
			}

			if fake.CountCalls() != 1 {
				t.Errorf("Fingerprint() call count = %d, want 1", fake.CountCalls())
			}

			got := gotServices[0]
			if diff := cmp.Diff(tc.wantSvc, got, protocmp.Transform()); diff != "" {
				t.Errorf("Fingerprint() service diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestInitFakeFingerprinter(t *testing.T) {
	testCases := []struct {
		name    string
		initErr error
		wantErr bool
	}{
		{
			name:    "when_init_has_no_error_it_returns_fake",
			initErr: nil,
			wantErr: false,
		},
		{
			name:    "when_init_has_error_it_returns_error",
			initErr: errors.New("init error"),
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			initFn := InitFakeFingerprinter("test", tc.initErr, FakeFingerprintFnDoNothing)
			if initFn == nil {
				t.Fatalf("InitFakeFingerprinter() returned nil")
			}

			fingerprinter, err := initFn(context.Background(), nil)
			if tc.wantErr {
				if err == nil {
					t.Errorf("InitFakeFingerprinter() init function returned nil error, want non-nil")
				}
				return
			}
			if err != nil {
				t.Errorf("InitFakeFingerprinter() returned error %v, want nil", err)
			}

			fake, ok := fingerprinter.(*FakeFingerprinter)
			if !ok {
				t.Fatalf("InitFakeFingerprinter() returned module of type %T, want *FakeFingerprinter", fingerprinter)
			}

			if fake.Name() != "test" {
				t.Errorf("InitFakeFingerprinter() created fake with name %q, want %q", fingerprinter.Name(), "test")
			}

			if fake.override == nil {
				t.Errorf("InitFakeFingerprinter() created fake with nil override")
			}
		})
	}
}
