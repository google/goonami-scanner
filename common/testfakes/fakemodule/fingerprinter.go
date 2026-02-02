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
	"sync"

	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/module"

	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
)

// FakeFingerprintFn is the function that overrides the Fingerprint() of the fake fingerprinter.
type FakeFingerprintFn func(ctx context.Context, svc *nspb.NetworkService) ([]*nspb.NetworkService, error)

// FakeFingerprintFnDoNothing is a fake fingerprinting function that does nothing.
func FakeFingerprintFnDoNothing(ctx context.Context, svc *nspb.NetworkService) ([]*nspb.NetworkService, error) {
	return []*nspb.NetworkService{svc}, nil
}

// ErrFakeFingerprintGeneric is a generic fake fingerprinting error.
var ErrFakeFingerprintGeneric = errors.New("generic fake fingerprinting error")

// FakeFingerprintFnErrors is a fake fingerprinting function that errors out.
func FakeFingerprintFnErrors(ctx context.Context, svc *nspb.NetworkService) ([]*nspb.NetworkService, error) {
	return nil, ErrFakeFingerprintGeneric
}

// FakeFingerprinter is a test double for module.Fingerprinter.
type FakeFingerprinter struct {
	*module.BaseModule
	override  FakeFingerprintFn
	mut       sync.Mutex
	scanCalls int
}

// NewFakeFingerprinter creates a new FakeFingerprinter.
func NewFakeFingerprinter(name string, override FakeFingerprintFn) *FakeFingerprinter {
	return &FakeFingerprinter{
		BaseModule: module.NewBaseModule(name),
		override:   override,
	}
}

// CountCalls returns the number of times the Fingerprint method was called.
func (m *FakeFingerprinter) CountCalls() int {
	m.mut.Lock()
	defer m.mut.Unlock()
	return m.scanCalls
}

// Fingerprint the service using the registered override function.
func (m *FakeFingerprinter) Fingerprint(ctx context.Context, svc *nspb.NetworkService) ([]*nspb.NetworkService, error) {
	m.mut.Lock()
	m.scanCalls++
	m.mut.Unlock()

	return m.override(ctx, svc)
}

// InitFakeFingerprinter return an init function for the FakeFingerprinter. If err is provided, the
// init function will immediately return it.
func InitFakeFingerprinter(name string, err error, override FakeFingerprintFn) module.InitFingerprinterFn {
	return func(c *config.Config) (module.Fingerprinter, error) {
		if err != nil {
			return nil, err
		}

		return NewFakeFingerprinter(name, override), nil
	}
}
